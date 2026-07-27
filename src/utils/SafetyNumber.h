#pragma once
#ifndef SAFETYNUMBER_H
#define SAFETYNUMBER_H

#include <QString>
#include <QByteArray>

// O17: Safety Number（安全码）- 身份验证机制
//
// 灵感来自 Signal 的 "Safety Number"：用户在带外通道（电话、当面）口头核对
// 一段十进制数字串，确认两端公钥未被中间人替换。
//
// 设计要点：
// 1. 双向稳定：safetyNumber(localPub, remotePub) == safetyNumber(remotePub, localPub)
//    —— 拼接时按字典序排序，避免顺序依赖
// 2. 可读性强：30 组 5 位十进制（共 150 位），用户可分段核对
//    Signal 标准是 60 位（12 组 5 位），这里采用相同的 12 组 5 位以兼容用户习惯
// 3. 派生算法：SHA-256(sortedHex(localPub) || sortedHex(remotePub))，
//    取前 25 字节，每 2 字节编码为 5 位十进制（mod 100000），共 12 组
//    （最后 1 字节丢弃，正好凑 12 组）
// 4. 与 KeyExchange::computeFingerprint 互补：指纹是单方公钥的标识，
//    Safety Number 是双方公钥的"会话指纹"
class SafetyNumber {
public:
    // 计算两端公钥的 Safety Number，返回 12 组 5 位十进制，空格分隔
    // 形如："12345 67890 13579 24680 ..."
    // 任一公钥为空或长度非法时返回空串
    static QString compute(const QByteArray& localPublicKey,
                           const QByteArray& remotePublicKey);

    // 返回 Safety Number 的简短描述（用于 UI 显示）
    // 形如："Safety Number: 12345 67890 ..."
    static QString formatForDisplay(const QString& safetyNumber);

    // 校验用户输入的 Safety Number 是否格式合法
    // - 长度：12 组 × 5 位
    // - 字符：每组 5 位纯数字（允许前导 0）
    // - 分隔：空格（任意数量）或无分隔
    static bool isValidFormat(const QString& input);

    // 规范化用户输入：去除多余空白、补齐前导 0、补分隔
    // 输入可能是 "12345 67890..." 也可能是 "1234567890..."
    static QString normalize(const QString& input);

    // 比较：忽略空格数量与大小写的相等性
    static bool equals(const QString& a, const QString& b);

private:
    static constexpr int GROUP_COUNT = 12;
    static constexpr int GROUP_DIGITS = 5;
    static constexpr int TOTAL_DIGITS = GROUP_COUNT * GROUP_DIGITS; // 60

    // 把公钥转为 hex（小写），便于字典序排序
    static QString toComparableHex(const QByteArray& key);
};

#endif // SAFETYNUMBER_H
