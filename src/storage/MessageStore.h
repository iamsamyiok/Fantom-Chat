#ifndef MESSAGESTORE_H
#define MESSAGESTORE_H

#include <QObject>
#include <QString>
#include <QList>
#include <QByteArray>
#include <QSqlDatabase>
#include "../utils/Structures.h"

// O1: 消息持久化层
// 解决 v1.0 FAQ 中 "v1.0 stores state in RAM only; restarting clears sessions" 硬伤
// 使用 SQLite 存储消息历史，每条消息用 libsodium crypto_secretbox 加密后再写盘
// 主密钥（masterKey）从随机生成后保存到 QSettings（后续可加密码保护）
class MessageStore : public QObject
{
    Q_OBJECT
public:
    explicit MessageStore(QObject* parent = nullptr);
    ~MessageStore();

    // 初始化存储：打开/创建数据库，加载或生成主密钥
    // dbPath: 数据库文件路径
    // 返回 true 表示成功
    bool open(const QString& dbPath);

    // 关闭数据库
    void close();

    // 保存一条消息（自动加密）
    // chatId: 聊天会话 ID
    // message: 消息结构（含 clientID, message, isIncoming）
    // 返回 true 表示成功
    bool saveMessage(const QString& chatId, const Message& message);

    // 加载某 chat 的全部历史消息（自动解密）
    // chatId: 聊天会话 ID
    // limit: 最多返回多少条（0 表示全部）
    QList<Message> loadMessages(const QString& chatId, int limit = 0) const;

    // 加载所有 chat 的最新一条消息（用于侧边栏联系人列表）
    // 返回 chatId -> Message 的映射
    QHash<QString, Message> loadLatestMessagesForAllChats() const;

    // 删除某 chat 的全部历史
    bool clearChat(const QString& chatId);

    // 删除所有历史
    bool clearAll();

    // 是否启用持久化（默认启用；可在配置中关闭）
    bool isEnabled() const { return m_enabled; }
    void setEnabled(bool enabled) { m_enabled = enabled; }

private:
    QSqlDatabase m_db;
    QByteArray m_masterKey; // 用于加密消息的对称密钥（crypto_secretbox）
    bool m_enabled = true;

    // 加载或生成主密钥
    bool loadOrCreateMasterKey(const QString& dbPath);

    // 加密/解密单条消息
    QByteArray encryptMessage(const QByteArray& plain) const;
    QByteArray decryptMessage(const QByteArray& cipher) const;
};

#endif // MESSAGESTORE_H
