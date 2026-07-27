#include "SafetyNumber.h"

#include <QCryptographicHash>
#include <QStringList>
#include <limits>

// O17: Safety Number 实现
//
// 25 字节随机数据 → 12 组 5 位十进制
// 每 2 字节（16 位）mod 100000 → 0..99999，格式化为 5 位
// 25 字节 = 12 组 × 2 字节 + 1 字节，最后一字节丢弃

namespace {
constexpr int DIGEST_BYTES_USED = 25;          // SHA-256 取前 25 字节
constexpr quint64 DEC_MOD = 100000ULL;          // 每组模数
}

QString SafetyNumber::compute(const QByteArray& localPublicKey,
                                const QByteArray& remotePublicKey) {
    if (localPublicKey.isEmpty() || remotePublicKey.isEmpty()) {
        return {};
    }

    // 按字典序排序拼接，保证双向稳定
    QString localHex = toComparableHex(localPublicKey);
    QString remoteHex = toComparableHex(remotePublicKey);

    QByteArray concat;
    if (localHex <= remoteHex) {
        concat = localHex.toUtf8() + remoteHex.toUtf8();
    } else {
        concat = remoteHex.toUtf8() + localHex.toUtf8();
    }

    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(concat);
    QByteArray digest = hash.result().left(DIGEST_BYTES_USED);
    if (digest.size() < DIGEST_BYTES_USED) {
        return {};
    }

    QStringList groups;
    for (int i = 0; i < GROUP_COUNT; ++i) {
        // 取 2 字节为大端 16 位
        quint16 val = (static_cast<quint16>(static_cast<quint8>(digest.at(i * 2))) << 8)
                    | static_cast<quint8>(digest.at(i * 2 + 1));
        // mod 100000 → 0..99999
        quint64 group = static_cast<quint64>(val) % DEC_MOD;
        // 格式化为 5 位，前导 0
        groups << QString("%1").arg(group, GROUP_DIGITS, 10, QChar('0'));
    }
    return groups.join(' ');
}

QString SafetyNumber::formatForDisplay(const QString& safetyNumber) {
    if (safetyNumber.isEmpty()) {
        return SafetyNumber::compute({}, {});
    }
    return QStringLiteral("Safety Number: ") + safetyNumber;
}

bool SafetyNumber::isValidFormat(const QString& input) {
    if (input.isEmpty()) return false;

    // 统计纯数字字符数（允许任意空格分隔）
    int digitCount = 0;
    for (const QChar& ch : input) {
        if (ch.isDigit()) {
            ++digitCount;
        } else if (ch.isSpace()) {
            continue;
        } else {
            return false;  // 非数字非空格
        }
    }
    return digitCount == TOTAL_DIGITS;
}

QString SafetyNumber::normalize(const QString& input) {
    // 去除所有空白与分隔符
    QString digits;
    digits.reserve(input.length());
    for (const QChar& ch : input) {
        if (ch.isDigit()) {
            digits.append(ch);
        }
    }

    // 不足 60 位：补前导 0（用户可能省略前导 0）
    if (digits.length() < TOTAL_DIGITS) {
        digits = digits.rightJustified(TOTAL_DIGITS, '0');
    } else if (digits.length() > TOTAL_DIGITS) {
        // 多于 60 位：截断（用户可能多粘了一段）
        digits = digits.left(TOTAL_DIGITS);
    }

    // 按 5 位分组
    QStringList groups;
    for (int i = 0; i < GROUP_COUNT; ++i) {
        groups << digits.mid(i * GROUP_DIGITS, GROUP_DIGITS);
    }
    return groups.join(' ');
}

bool SafetyNumber::equals(const QString& a, const QString& b) {
    if (a.isEmpty() || b.isEmpty()) return false;
    return normalize(a) == normalize(b);
}

QString SafetyNumber::toComparableHex(const QByteArray& key) {
    return QString::fromLatin1(key.toHex()).toLower();
}
