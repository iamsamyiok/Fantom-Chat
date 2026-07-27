#pragma once
#ifndef PROTOCOL_HANDSHAKECODEC_H
#define PROTOCOL_HANDSHAKECODEC_H

#include <QByteArray>
#include <QString>
#include "../utils/ProtocolVersion.h"

// O8: 协议层与网络层解耦
// HandshakeCodec 把握手协议文本行（HANDSHAKE / HANDSHAKE_ACK / HANDSHAKE_NACK）
// 与结构化数据互转，便于未来 Relay / WebSocket 通道复用同一握手逻辑
//
// 当前协议：
//   客户端 -> 服务端: HANDSHAKE <pubkey_b64> <client_ts_ms> <proto_ver> <min_compat_ver>\n
//   服务端 -> 客户端: HANDSHAKE_ACK <pubkey_b64> <server_ts_ms> <proto_ver> <min_compat_ver>\n
//                     HANDSHAKE_NACK <reason>\n  （版本不兼容时）
//   兼容旧版：HANDSHAKE <pubkey_b64> / HANDSHAKE_ACK <pubkey_b64>（无时间戳无版本）
namespace Protocol {

struct HandshakeInit {
    QByteArray publicKey;        // 解码后的原始公钥字节
    QString publicKeyBase64;     // base64 文本（保留原样便于 echo）
    qint64 clientTimestampMs = 0;
    quint32 protoVersion = 0;
    quint32 minCompatVersion = 0;
    bool hasTimestamp = false;
    bool hasVersion = false;
    bool valid = false;
};

struct HandshakeAck {
    QByteArray publicKey;
    QString publicKeyBase64;
    qint64 serverTimestampMs = 0;
    quint32 protoVersion = 0;
    quint32 minCompatVersion = 0;
    bool hasTimestamp = false;
    bool hasVersion = false;
    bool valid = false;
};

namespace HandshakeCodec {

// 构造客户端发送的握手行
QString buildInit(const QByteArray& publicKey, qint64 clientTsMs);
QString buildInit(const QByteArray& publicKey, qint64 clientTsMs,
                  quint32 protoVer, quint32 minCompatVer);

// 解析客户端发送的握手行
HandshakeInit parseInit(const QString& line);

// 构造服务端 ACK 行
QString buildAck(const QByteArray& publicKey, qint64 serverTsMs);
QString buildAck(const QByteArray& publicKey, qint64 serverTsMs,
                 quint32 protoVer, quint32 minCompatVer);

// 解析服务端 ACK 行
HandshakeAck parseAck(const QString& line);

// 构造服务端 NACK 行
QString buildNack(const QString& reason);

// 解析 NACK 行（返回原因；空字符串表示非 NACK 行）
QString parseNack(const QString& line);

} // namespace HandshakeCodec
} // namespace Protocol

#endif // PROTOCOL_HANDSHAKECODEC_H
