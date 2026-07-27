#include "FrameReader.h"

#include <QDebug>
#include <QtEndian>

FrameReader::FrameReader(FrameCallback cb) : m_callback(std::move(cb)) {}

void FrameReader::feed(const QByteArray& data) {
    if (data.isEmpty()) return;
    m_buffer.append(data);

    while (true) {
        if (m_buffer.size() < 4) {
            // 长度前缀尚未读全
            return;
        }
        quint32 len = qFromBigEndian<quint32>(
            reinterpret_cast<const uchar*>(m_buffer.constData()));
        // len 包含 1 字节 type + payload
        constexpr quint32 kMaxFrame = 16 * 1024 * 1024; // 16MB 上限防恶意包
        if (len < 1) {
            qWarning() << "FrameReader: invalid frame length" << len << "resetting";
            m_buffer.clear();
            return;
        }
        if (len > kMaxFrame) {
            qWarning() << "FrameReader: frame too large" << len << "resetting";
            m_buffer.clear();
            return;
        }
        if (m_buffer.size() < 4 + static_cast<int>(len)) {
            // 整帧尚未读全
            return;
        }
        QByteArray frame = m_buffer.mid(4, len);
        m_buffer.remove(0, 4 + len);

        if (frame.isEmpty()) continue;
        quint8 type = static_cast<quint8>(frame[0]);
        QByteArray payload = frame.mid(1);
        if (m_callback) m_callback(type, payload);
    }
}

void FrameReader::reset() {
    m_buffer.clear();
}
