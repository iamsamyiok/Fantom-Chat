#include "MessageStore.h"
#include <QSqlQuery>
#include <QSqlError>
#include <QVariant>
#include <QDebug>
#include <QSettings>
#include <QDir>
#include <QDateTime>
#include <QFileInfo>
#include <sodium.h>

// O1: 主密钥长度与算法常量
// crypto_secretbox 用 Xsalsa20-Poly1305（libsodium 默认），密钥 32 字节，nonce 24 字节
static constexpr int MASTER_KEY_LEN = crypto_secretbox_KEYBYTES;
static constexpr int NONCE_LEN     = crypto_secretbox_NONCEBYTES;
static constexpr int MAC_LEN        = crypto_secretbox_MACBYTES;

MessageStore::MessageStore(QObject* parent)
    : QObject(parent) {}

MessageStore::~MessageStore()
{
    close();
}

bool MessageStore::open(const QString& dbPath)
{
    if (!m_enabled) return false;

    // 确保目录存在
    QDir().mkpath(QFileInfo(dbPath).absolutePath());

    m_db = QSqlDatabase::addDatabase("QSQLITE", "fantomchat_store");
    m_db.setDatabaseName(dbPath);
    if (!m_db.open()) {
        qWarning() << "MessageStore: cannot open DB" << dbPath << ":" << m_db.lastError().text();
        return false;
    }

    // 创建表
    QSqlQuery q(m_db);
    bool ok = true;
    ok &= q.exec(
        "CREATE TABLE IF NOT EXISTS messages ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  chat_id TEXT NOT NULL,"
        "  sender TEXT NOT NULL,"             // 消息来源 clientID
        "  ciphertext BLOB NOT NULL,"         // 加密后的消息体（含 nonce 前缀）
        "  is_incoming INTEGER NOT NULL,"     // 0/1
        "  timestamp INTEGER NOT NULL"        // 毫秒级 UTC
        ")");
    ok &= q.exec(
        "CREATE INDEX IF NOT EXISTS idx_messages_chat_ts ON messages(chat_id, timestamp)");
    if (!ok) {
        qWarning() << "MessageStore: cannot create schema:" << q.lastError().text();
        return false;
    }

    // 加载或生成主密钥
    return loadOrCreateMasterKey(dbPath);
}

void MessageStore::close()
{
    if (m_db.isOpen()) {
        m_db.close();
        // 注意：不调用 removeDatabase，因为可能在主进程退出时调用
    }
    // 清空内存中的密钥
    sodium_memzero(m_masterKey.data(), m_masterKey.size());
    m_masterKey.clear();
}

bool MessageStore::loadOrCreateMasterKey(const QString& dbPath)
{
    // 主密钥存放于 QSettings（与 DB 同目录，可后续加密码保护）
    QSettings settings;
    QByteArray stored = settings.value("store/masterKey").toByteArray();

    if (stored.size() == MASTER_KEY_LEN) {
        m_masterKey = stored;
        return true;
    }

    // 生成新密钥
    m_masterKey.resize(MASTER_KEY_LEN);
    if (sodium_init() < 0) {
        qWarning() << "MessageStore: libsodium init failed";
        return false;
    }
    randombytes_buf(m_masterKey.data(), MASTER_KEY_LEN);

    // 保存（base64 编码以兼容 QSettings）
    settings.setValue("store/masterKey", m_masterKey.toBase64());
    qDebug() << "MessageStore: generated new master key for" << dbPath;
    return true;
}

QByteArray MessageStore::encryptMessage(const QByteArray& plain) const
{
    if (m_masterKey.isEmpty()) {
        qWarning() << "MessageStore: master key not loaded, cannot encrypt";
        return QByteArray();
    }

    // 生成 nonce
    QByteArray nonce(NONCE_LEN, Qt::Uninitialized);
    randombytes_buf(nonce.data(), NONCE_LEN);

    // 加密
    QByteArray cipher(MAC_LEN + plain.size(), Qt::Uninitialized);
    if (crypto_secretbox_easy(
            reinterpret_cast<unsigned char*>(cipher.data()),
            reinterpret_cast<const unsigned char*>(plain.constData()), plain.size(),
            reinterpret_cast<const unsigned char*>(nonce.constData()),
            reinterpret_cast<const unsigned char*>(m_masterKey.constData())) != 0) {
        qWarning() << "MessageStore: encrypt failed";
        return QByteArray();
    }

    // 输出格式：nonce || ciphertext
    return nonce + cipher;
}

QByteArray MessageStore::decryptMessage(const QByteArray& blob) const
{
    if (m_masterKey.isEmpty()) {
        qWarning() << "MessageStore: master key not loaded, cannot decrypt";
        return QByteArray();
    }
    if (blob.size() < NONCE_LEN + MAC_LEN) {
        qWarning() << "MessageStore: blob too short";
        return QByteArray();
    }

    QByteArray nonce = blob.left(NONCE_LEN);
    QByteArray cipher = blob.mid(NONCE_LEN);

    QByteArray plain(cipher.size() - MAC_LEN, Qt::Uninitialized);
    if (crypto_secretbox_open_easy(
            reinterpret_cast<unsigned char*>(plain.data()),
            reinterpret_cast<const unsigned char*>(cipher.constData()), cipher.size(),
            reinterpret_cast<const unsigned char*>(nonce.constData()),
            reinterpret_cast<const unsigned char*>(m_masterKey.constData())) != 0) {
        qWarning() << "MessageStore: decrypt failed (MAC mismatch)";
        return QByteArray();
    }
    return plain;
}

bool MessageStore::saveMessage(const QString& chatId, const Message& message)
{
    if (!m_enabled || !m_db.isOpen()) return false;

    QByteArray plain = message.message.toUtf8();
    QByteArray cipher = encryptMessage(plain);
    if (cipher.isEmpty()) return false;

    QSqlQuery q(m_db);
    q.prepare(
        "INSERT INTO messages (chat_id, sender, ciphertext, is_incoming, timestamp) "
        "VALUES (?, ?, ?, ?, ?)");
    q.addBindValue(chatId);
    q.addBindValue(message.clientID);
    q.addBindValue(cipher);
    q.addBindValue(message.isIncoming ? 1 : 0);
    q.addBindValue(QDateTime::currentDateTimeUtc().toMSecsSinceEpoch());

    if (!q.exec()) {
        qWarning() << "MessageStore: insert failed:" << q.lastError().text();
        return false;
    }
    return true;
}

QList<Message> MessageStore::loadMessages(const QString& chatId, int limit) const
{
    QList<Message> result;
    if (!m_enabled || !m_db.isOpen()) return result;

    QSqlQuery q(m_db);
    if (limit > 0) {
        q.prepare("SELECT sender, ciphertext, is_incoming, timestamp FROM messages "
                  "WHERE chat_id = ? ORDER BY timestamp ASC LIMIT ?");
        q.addBindValue(chatId);
        q.addBindValue(limit);
    } else {
        q.prepare("SELECT sender, ciphertext, is_incoming, timestamp FROM messages "
                  "WHERE chat_id = ? ORDER BY timestamp ASC");
        q.addBindValue(chatId);
    }

    if (!q.exec()) {
        qWarning() << "MessageStore: load failed:" << q.lastError().text();
        return result;
    }

    while (q.next()) {
        Message m;
        m.clientID   = q.value(0).toString();
        QByteArray cipher = q.value(1).toByteArray();
        m.isIncoming = q.value(2).toInt() == 1;
        QByteArray plain = decryptMessage(cipher);
        m.message = QString::fromUtf8(plain);
        result.append(m);
    }
    return result;
}

QHash<QString, Message> MessageStore::loadLatestMessagesForAllChats() const
{
    QHash<QString, Message> result;
    if (!m_enabled || !m_db.isOpen()) return result;

    QSqlQuery q(m_db);
    if (!q.exec("SELECT m.chat_id, m.sender, m.ciphertext, m.is_incoming, m.timestamp "
                "FROM messages m "
                "JOIN (SELECT chat_id, MAX(timestamp) AS max_ts FROM messages GROUP BY chat_id) latest "
                "ON m.chat_id = latest.chat_id AND m.timestamp = latest.max_ts")) {
        qWarning() << "MessageStore: load latest failed:" << q.lastError().text();
        return result;
    }

    while (q.next()) {
        QString chatId = q.value(0).toString();
        Message m;
        m.clientID   = q.value(1).toString();
        QByteArray cipher = q.value(2).toByteArray();
        m.isIncoming = q.value(3).toInt() == 1;
        QByteArray plain = decryptMessage(cipher);
        m.message = QString::fromUtf8(plain);
        result.insert(chatId, m);
    }
    return result;
}

bool MessageStore::clearChat(const QString& chatId)
{
    if (!m_enabled || !m_db.isOpen()) return false;
    QSqlQuery q(m_db);
    q.prepare("DELETE FROM messages WHERE chat_id = ?");
    q.addBindValue(chatId);
    return q.exec();
}

bool MessageStore::clearAll()
{
    if (!m_enabled || !m_db.isOpen()) return false;
    QSqlQuery q(m_db);
    return q.exec("DELETE FROM messages");
}
