#pragma once
#ifndef KEYEXCHANGE_H
#define KEYEXCHANGE_H

#include <QString>
#include <QByteArray>

// F5: base64 编码层 - 密钥外带交换
//
// 在 Fantom-Chat 现有协议内，握手时已经用 base64 传 public key。
// 这个工具类是面向"用户在带外通道（邮件、IM、二维码）交换密钥"的格式化封装：
//
// - exportPublicKey(rawBytes) -> "FANTOM-PUBKEY-V1:AAAA..."
// - importPublicKey(text)     -> rawBytes（解析、校验格式、返回）
// - computeFingerprint(bytes) -> "AB12 CD34 ..." 的可读指纹（SHA-256 取前 16 字节）
//
// 设计原则：
// - 纯函数，无副作用，便于单元测试（与 O6 协同）
// - 容忍空白与多余前后缀，方便从邮件粘贴
class KeyExchange {
public:
    static constexpr const char* HEADER = "FANTOM-PUBKEY-V1:";

    // 导出公钥为可粘贴文本
    static QString exportPublicKey(const QByteArray& publicKey);

    // 从文本导入公钥。返回空 QByteArray 表示解析失败
    // - 自动剥离首尾空白、注释行、行号前缀
    // - 必须以 HEADER 开头 OR 是纯 base64 字符串（向后兼容）
    static QByteArray importPublicKey(const QString& text);

    // 计算 SHA-256 取前 N 字节的可读指纹，默认 16 字节（128 位），按 4 字符分组
    static QString computeFingerprint(const QByteArray& publicKey, int bytes = 16);

    // 校验导入的公钥长度是否符合 libsodium X25519 公钥长度
    static bool isValidPublicKeyLength(const QByteArray& publicKey);

private:
    // 去除注释行（以 # 或 // 开头）和行尾空白
    static QString stripCommentsAndWhitespace(const QString& text);
};

#endif // KEYEXCHANGE_H
