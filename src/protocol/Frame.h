#pragma once
#ifndef PROTOCOL_FRAME_H
#define PROTOCOL_FRAME_H

#include <QByteArray>
#include <QtGlobal>

// O8: 协议层与网络层解耦
// Frame 抽象：应用层面对的最小协议单元
//
// 一个 Frame = [1 字节 type][N 字节 payload]
// 网络层只需负责把 Frame 的字节流（length-prefix 在 FrameReader/Writer 处理）
// 透传到对端，不再关心 type 与 payload 的语义
//
// 当前协议中 composedMessage 的 [selfHost]\0 + encrypted 被视为 payload 的 outer layer
// 由调用方自行决定是否再分包（如 sendTypedFrame 已实现的 type + selfHost + encrypted）
namespace Protocol {

struct Frame {
    quint8 type = 0;
    QByteArray payload; // 已包含 selfHost\0 + encrypted（向后兼容现有调用）

    Frame() = default;
    Frame(quint8 t, QByteArray p) : type(t), payload(std::move(p)) {}

    // 序列化为可发送字节：type + payload
    QByteArray serialize() const;

    // 反序列化：从字节流（不含 length-prefix）解析出 Frame
    // 成功返回 true；空数据或异常返回 false 并保持 frame 不变
    static bool deserialize(const QByteArray& bytes, Frame& outFrame);
};

} // namespace Protocol

#endif // PROTOCOL_FRAME_H
