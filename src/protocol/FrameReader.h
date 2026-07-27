#pragma once
#ifndef PROTOCOL_FRAMEREADER_H
#define PROTOCOL_FRAMEREADER_H

#include <QByteArray>
#include <QObject>
#include <functional>

// O8: 协议层与网络层解耦
// FrameReader 处理 length-prefix 流式字节，回调完整 Frame。
//
// 网络层只需：
//   reader.feed(socket->readAll());
// FrameReader 内部维护半包缓冲，长度足够时回调。
//
// 协议：4 字节大端 length + 1 字节 type + N 字节 payload
//      length 仅覆盖 type + payload（不含 length-prefix 自身）
//
// 设计为无信号版本（避免 QObject 继承），调用方传入回调
class FrameReader {
public:
    // 接收到完整帧时调用此回调
    using FrameCallback = std::function<void(quint8 type, const QByteArray& payload)>;

    explicit FrameReader(FrameCallback cb = nullptr);

    // 喂入新字节，回调可能触发多次
    void feed(const QByteArray& data);

    // 重置内部缓冲（连接关闭时调用）
    void reset();

    // 当前缓冲长度（用于调试 / 单元测试）
    int bufferedBytes() const { return m_buffer.size(); }

private:
    FrameCallback m_callback;
    QByteArray m_buffer;
};

#endif // PROTOCOL_FRAMEREADER_H
