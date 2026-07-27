#include "ClockSync.h"
#include <QDateTime>

ClockSync& ClockSync::instance()
{
    static ClockSync instance;
    return instance;
}

void ClockSync::setOffset(const QString& clientID, qint64 offsetMs)
{
    QMutexLocker locker(&m_mutex);
    PeerClockOffset& entry = m_offsets[clientID];
    entry.offsetMs = offsetMs;
    entry.valid = true;
    entry.warned = false;
}

qint64 ClockSync::offset(const QString& clientID) const
{
    QMutexLocker locker(&m_mutex);
    auto it = m_offsets.constFind(clientID);
    if (it == m_offsets.constEnd()) return 0;
    return it.value().offsetMs;
}

bool ClockSync::isWithinTolerance(const QString& clientID) const
{
    QMutexLocker locker(&m_mutex);
    auto it = m_offsets.constFind(clientID);
    if (it == m_offsets.constEnd()) return true; // 未协商过视为容忍
    return qAbs(it.value().offsetMs) <= CLOCK_SYNC_TOLERANCE_MS;
}

bool ClockSync::hasOffset(const QString& clientID) const
{
    QMutexLocker locker(&m_mutex);
    return m_offsets.contains(clientID);
}

void ClockSync::clear(const QString& clientID)
{
    QMutexLocker locker(&m_mutex);
    m_offsets.remove(clientID);
}

qint64 ClockSync::computeOffset(qint64 clientSendTs, qint64 localRecvTs)
{
    // 简化模型：忽略网络传输延迟
    // offset = clientTs - localTs
    // 若 offset > 0，说明对端时钟超前本地
    return clientSendTs - localRecvTs;
}

qint64 ClockSync::nowMs()
{
    return QDateTime::currentDateTimeUtc().toMSecsSinceEpoch();
}
