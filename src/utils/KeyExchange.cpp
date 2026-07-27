#include "KeyExchange.h"

#include <QCryptographicHash>
#include <QStringList>
#include <cstring>
#include <sodium.h>

QString KeyExchange::exportPublicKey(const QByteArray& publicKey) {
    return QString::fromLatin1(HEADER) +
           QString::fromUtf8(publicKey.toBase64());
}

QByteArray KeyExchange::importPublicKey(const QString& text) {
    QString cleaned = stripCommentsAndWhitespace(text);
    if (cleaned.isEmpty()) {
        return {};
    }

    QByteArray raw;
    if (cleaned.startsWith(QLatin1String(HEADER))) {
        // 标准格式：FANTOM-PUBKEY-V1:<base64>
        QString b64 = cleaned.mid(strlen(HEADER));
        raw = QByteArray::fromBase64(b64.trimmed().toUtf8());
    } else {
        // 兼容：纯 base64 字符串
        // 检查只包含 base64 字母表（含可能的 = 填充）
        QString candidate = cleaned.trimmed();
        static const QString kBase64Chars =
            QStringLiteral("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=");
        bool isBase64 = true;
        for (const QChar& ch : candidate) {
            if (!kBase64Chars.contains(ch)) {
                isBase64 = false;
                break;
            }
        }
        if (!isBase64 || candidate.length() < 4) {
            return {};
        }
        raw = QByteArray::fromBase64(candidate.toUtf8());
    }

    if (!isValidPublicKeyLength(raw)) {
        return {};
    }
    return raw;
}

QString KeyExchange::computeFingerprint(const QByteArray& publicKey, int bytes) {
    if (bytes <= 0) bytes = 16;
    if (bytes > 32) bytes = 32;  // SHA-256 最多 32 字节

    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(publicKey);
    QByteArray digest = hash.result().left(bytes);

    // 转大写 hex，按 4 字符分组
    QString hex = QString::fromLatin1(digest.toHex()).toUpper();
    QStringList groups;
    for (int i = 0; i < hex.length(); i += 4) {
        groups << hex.mid(i, 4);
    }
    return groups.join(' ');
}

bool KeyExchange::isValidPublicKeyLength(const QByteArray& publicKey) {
    // libsodium X25519 公钥长度 = crypto_kx_PUBLICKEYBYTES（通常 32 字节）
    return publicKey.size() == static_cast<int>(crypto_kx_PUBLICKEYBYTES);
}

QString KeyExchange::stripCommentsAndWhitespace(const QString& text) {
    QStringList out;
    const QStringList lines = text.split('\n', Qt::SkipEmptyParts);
    for (const QString& rawLine : lines) {
        QString line = rawLine.trimmed();
        if (line.isEmpty()) continue;
        if (line.startsWith('#') || line.startsWith("//")) continue;
        out << line;
    }
    return out.join(QString());
}
