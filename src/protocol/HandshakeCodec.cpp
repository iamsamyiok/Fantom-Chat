#include "HandshakeCodec.h"

#include <QStringList>
#include <cstring>

namespace Protocol {

namespace HandshakeCodec {

static constexpr const char* kInitPrefix = "HANDSHAKE ";
static constexpr const char* kAckPrefix = "HANDSHAKE_ACK ";
static constexpr const char* kNackPrefix = "HANDSHAKE_NACK ";

// ---- 客户端 -> 服务端 ----

QString buildInit(const QByteArray& publicKey, qint64 clientTsMs) {
    return buildInit(publicKey, clientTsMs,
                     ProtoVer::CURRENT, ProtoVer::MIN_COMPAT);
}

QString buildInit(const QByteArray& publicKey, qint64 clientTsMs,
                  quint32 protoVer, quint32 minCompatVer) {
    return QString::fromLatin1(kInitPrefix) +
           QString::fromUtf8(publicKey.toBase64()) + ' ' +
           QString::number(clientTsMs) + ' ' +
           QString::number(protoVer, 16) + ' ' +
           QString::number(minCompatVer, 16);
}

HandshakeInit parseInit(const QString& line) {
    HandshakeInit hs;
    QString trimmed = line.trimmed();
    if (!trimmed.startsWith(QLatin1String(kInitPrefix))) {
        return hs;
    }
    QStringList parts = trimmed.split(' ', Qt::SkipEmptyParts);
    if (parts.size() < 2) return hs;

    hs.publicKeyBase64 = parts[1];
    hs.publicKey = QByteArray::fromBase64(hs.publicKeyBase64.toUtf8());

    if (parts.size() >= 3) {
        bool ok = false;
        qint64 ts = parts[2].toLongLong(&ok);
        if (ok) {
            hs.clientTimestampMs = ts;
            hs.hasTimestamp = true;
        }
    }
    if (parts.size() >= 5) {
        bool ok1 = false, ok2 = false;
        quint32 cur = parts[3].toUInt(&ok1, 16);
        quint32 minc = parts[4].toUInt(&ok2, 16);
        if (ok1 && ok2) {
            hs.protoVersion = cur;
            hs.minCompatVersion = minc;
            hs.hasVersion = true;
        }
    }
    hs.valid = !hs.publicKey.isEmpty();
    return hs;
}

// ---- 服务端 -> 客户端 ----

QString buildAck(const QByteArray& publicKey, qint64 serverTsMs) {
    return buildAck(publicKey, serverTsMs,
                    ProtoVer::CURRENT, ProtoVer::MIN_COMPAT);
}

QString buildAck(const QByteArray& publicKey, qint64 serverTsMs,
                  quint32 protoVer, quint32 minCompatVer) {
    return QString::fromLatin1(kAckPrefix) +
           QString::fromUtf8(publicKey.toBase64()) + ' ' +
           QString::number(serverTsMs) + ' ' +
           QString::number(protoVer, 16) + ' ' +
           QString::number(minCompatVer, 16);
}

HandshakeAck parseAck(const QString& line) {
    HandshakeAck hs;
    QString trimmed = line.trimmed();
    if (!trimmed.startsWith(QLatin1String(kAckPrefix))) {
        return hs;
    }
    QStringList parts = trimmed.split(' ', Qt::SkipEmptyParts);
    if (parts.size() < 2) return hs;

    hs.publicKeyBase64 = parts[1];
    hs.publicKey = QByteArray::fromBase64(hs.publicKeyBase64.toUtf8());

    if (parts.size() >= 3) {
        bool ok = false;
        qint64 ts = parts[2].toLongLong(&ok);
        if (ok) {
            hs.serverTimestampMs = ts;
            hs.hasTimestamp = true;
        }
    }
    if (parts.size() >= 5) {
        bool ok1 = false, ok2 = false;
        quint32 cur = parts[3].toUInt(&ok1, 16);
        quint32 minc = parts[4].toUInt(&ok2, 16);
        if (ok1 && ok2) {
            hs.protoVersion = cur;
            hs.minCompatVersion = minc;
            hs.hasVersion = true;
        }
    }
    hs.valid = !hs.publicKey.isEmpty();
    return hs;
}

QString buildNack(const QString& reason) {
    return QString::fromLatin1(kNackPrefix) + reason;
}

QString parseNack(const QString& line) {
    QString trimmed = line.trimmed();
    if (!trimmed.startsWith(QLatin1String(kNackPrefix))) {
        return QString();
    }
    return trimmed.mid(strlen(kNackPrefix)).trimmed();
}

} // namespace HandshakeCodec
} // namespace Protocol
