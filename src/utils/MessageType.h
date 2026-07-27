#ifndef MESSAGETYPE_H
#define MESSAGETYPE_H

#include <QtGlobal>
#include <QByteArray>

// O9 + F3: 消息类型与文件传输协议
// 在原 composedMessage 之前加 1 字节类型标记，加密后传输
// 设计原则：保留原文本路径不变，新增文件路径旁路
//
// composedMessage 旧格式：[selfHost]\0[encryptedPayload]
// composedMessage 新格式：[typeByte][selfHost]\0[encryptedPayload]
//
// encryptedPayload 解密后内容（按 type 区分）：
//   TYPE_TEXT          : 原始文本（UTF-8）
//   TYPE_FILE_HEADER   : file_id(16B 随机) + filename_len(2B) + filename + size(8B)
//   TYPE_FILE_CHUNK    : file_id(16B) + offset(8B) + chunk_len(4B) + chunk_data
//   TYPE_FILE_END      : file_id(16B)

namespace MsgType {
    enum Type : quint8 {
        TEXT          = 0x00, // 普通文本消息（向后兼容旧版）
        FILE_HEADER   = 0x01, // 文件元数据
        FILE_CHUNK    = 0x02, // 文件数据块
        FILE_END      = 0x03, // 文件传输结束
        CONTROL       = 0xFF, // 控制消息（保留）
    };
}

// 消息类型工具函数
namespace MsgCodec {

// 在原始 composedMessage 前加 1 字节类型
// 原: selfHost\0 + encrypted
// 新: type + selfHost\0 + encrypted
inline QByteArray wrapWithType(quint8 type, const QByteArray& composed) {
    QByteArray result;
    result.reserve(1 + composed.size());
    result.append(static_cast<char>(type));
    result.append(composed);
    return result;
}

// 从 frame 中解析出 type 字节，剩余为原 composedMessage
inline quint8 unwrapType(const QByteArray& frame, QByteArray* restOut = nullptr) {
    if (frame.isEmpty()) return MsgType::TEXT; // 兼容旧版无类型字节
    quint8 type = static_cast<quint8>(frame[0]);
    if (restOut) *restOut = frame.mid(1);
    return type;
}

// 文件传输默认分片大小（加密前），单包最大 64KB - 1 - 头开销
constexpr int FILE_CHUNK_SIZE = 32 * 1024; // 32KB

// 文件 ID 长度（随机生成的 16 字节）
constexpr int FILE_ID_LEN = 16;

// 编码 FILE_HEADER 载荷（加密前）
// file_id: 16 字节
// filename: UTF-8 字符串
// size: 文件总大小
inline QByteArray encodeFileHeader(const QByteArray& fileId,
                                   const QString& filename,
                                   qint64 size) {
    QByteArray fn = filename.toUtf8();
    if (fn.size() > 65535) fn = fn.left(65535); // 截断保护

    QByteArray payload;
    payload.reserve(FILE_ID_LEN + 2 + fn.size() + 8);
    payload.append(fileId);
    // 2 字节大端 filename_len
    quint16 fnLen = static_cast<quint16>(fn.size());
    payload.append(static_cast<char>((fnLen >> 8) & 0xFF));
    payload.append(static_cast<char>(fnLen & 0xFF));
    payload.append(fn);
    // 8 字节大端 size
    for (int i = 7; i >= 0; --i) {
        payload.append(static_cast<char>((size >> (i * 8)) & 0xFF));
    }
    return payload;
}

// 解码 FILE_HEADER 载荷
struct FileHeader {
    QByteArray fileId;
    QString filename;
    qint64 size = 0;
    bool valid = false;
};

inline FileHeader decodeFileHeader(const QByteArray& payload) {
    FileHeader h;
    if (payload.size() < FILE_ID_LEN + 2 + 8) return h;
    h.fileId = payload.left(FILE_ID_LEN);
    int p = FILE_ID_LEN;
    quint16 fnLen = (static_cast<quint8>(payload[p]) << 8) | static_cast<quint8>(payload[p + 1]);
    p += 2;
    if (payload.size() < p + fnLen + 8) return h;
    h.filename = QString::fromUtf8(payload.mid(p, fnLen));
    p += fnLen;
    h.size = 0;
    for (int i = 0; i < 8; ++i) {
        h.size = (h.size << 8) | static_cast<quint8>(payload[p + i]);
    }
    h.valid = true;
    return h;
}

// 编码 FILE_CHUNK 载荷
inline QByteArray encodeFileChunk(const QByteArray& fileId,
                                   qint64 offset,
                                   const QByteArray& chunk) {
    QByteArray payload;
    payload.reserve(FILE_ID_LEN + 8 + 4 + chunk.size());
    payload.append(fileId);
    for (int i = 7; i >= 0; --i) {
        payload.append(static_cast<char>((offset >> (i * 8)) & 0xFF));
    }
    quint32 cl = static_cast<quint32>(chunk.size());
    for (int i = 3; i >= 0; --i) {
        payload.append(static_cast<char>((cl >> (i * 8)) & 0xFF));
    }
    payload.append(chunk);
    return payload;
}

// 解码 FILE_CHUNK 载荷
struct FileChunk {
    QByteArray fileId;
    qint64 offset = 0;
    QByteArray data;
    bool valid = false;
};

inline FileChunk decodeFileChunk(const QByteArray& payload) {
    FileChunk c;
    if (payload.size() < FILE_ID_LEN + 8 + 4) return c;
    c.fileId = payload.left(FILE_ID_LEN);
    int p = FILE_ID_LEN;
    c.offset = 0;
    for (int i = 0; i < 8; ++i) {
        c.offset = (c.offset << 8) | static_cast<quint8>(payload[p + i]);
    }
    p += 8;
    quint32 cl = 0;
    for (int i = 0; i < 4; ++i) {
        cl = (cl << 8) | static_cast<quint8>(payload[p + i]);
    }
    p += 4;
    if (payload.size() < p + static_cast<int>(cl)) return c;
    c.data = payload.mid(p, cl);
    c.valid = true;
    return c;
}

// 编码 FILE_END 载荷（仅 file_id）
inline QByteArray encodeFileEnd(const QByteArray& fileId) {
    return fileId;
}

} // namespace MsgCodec

#endif // MESSAGETYPE_H
