#include "Frame.h"

namespace Protocol {

QByteArray Frame::serialize() const {
    QByteArray result;
    result.reserve(1 + payload.size());
    result.append(static_cast<char>(type));
    result.append(payload);
    return result;
}

bool Frame::deserialize(const QByteArray& bytes, Frame& outFrame) {
    if (bytes.isEmpty()) return false;
    outFrame.type = static_cast<quint8>(bytes[0]);
    outFrame.payload = bytes.mid(1);
    return true;
}

} // namespace Protocol
