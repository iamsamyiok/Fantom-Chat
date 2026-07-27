#ifndef CLOCKSYNC_H
#define CLOCKSYNC_H

#include <QHash>
#include <QString>
#include <QMutex>
#include <QtGlobal>

// 容忍的时钟偏差阈值（毫秒）。偏差超过此值会发出警告但仍允许通信。
// 5 分钟 = 300000 ms，符合 RFC 5280 的 Kerberos 容忍值
constexpr qint64 CLOCK_SYNC_TOLERANCE_MS = 300 * 1000LL;

// 单 peer 时钟偏移记录
struct PeerClockOffset {
    qint64 offsetMs = 0;        // 远端时间 - 本地时间（毫秒）
    bool   valid     = false;   // 是否已协商
    bool   warned    = false;   // 是否已发过警告
};

// 全局时钟同步管理（线程安全单例）
// 解决 v1.0 的 FAQ 中"Handshake fails: time is in sync"的硬伤
class ClockSync {
public:
    static ClockSync& instance();

    // 记录某 peer 的时钟偏移
    void setOffset(const QString& clientID, qint64 offsetMs);

    // 获取某 peer 的时钟偏移（未协商过返回 0）
    qint64 offset(const QString& clientID) const;

    // 判断偏差是否在容忍范围内
    bool isWithinTolerance(const QString& clientID) const;

    // 是否已协商过
    bool hasOffset(const QString& clientID) const;

    // 清除某 peer 的偏移记录（连接断开时调用）
    void clear(const QString& clientID);

    // 根据本地时间和对端握手时戳计算偏移
    // clientSendTs: 对端发送握手时的时间戳
    // localRecvTs:  本端收到时的时间戳
    // 返回值: 远端时间 - 本地时间（毫秒）
    static qint64 computeOffset(qint64 clientSendTs, qint64 localRecvTs);

    // 获取本地当前时间戳（毫秒，UTC，自 epoch 起）
    static qint64 nowMs();

private:
    ClockSync() = default;
    ClockSync(const ClockSync&) = delete;
    ClockSync& operator=(const ClockSync&) = delete;

    mutable QMutex m_mutex;
    QHash<QString, PeerClockOffset> m_offsets;
};

#endif // CLOCKSYNC_H
