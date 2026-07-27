#ifndef PEERDISCOVERY_H
#define PEERDISCOVERY_H

#include <QObject>
#include <QUdpSocket>
#include <QHostAddress>
#include <QTimer>
#include <QHash>
#include <QDateTime>
#include <QMutex>
#include <QSet>

// O2: 局域网内 IPv6 peer 自动发现
// 用 IPv6 多播 ff02::1（all-nodes）实现零配置邻居发现，无外部依赖
// 协议：周期性广播 "FANTOMCHAT_PRESENT <ipv6_addr> <port>\n" 到多播组
// 收到其他实例广播后，通过 peerFound 信号通知 UI
// 同时支持全局 IPv6（GUA, 2000::/3）与 link-local（fe80::/10）

struct DiscoveredPeer {
    QString address;       // 不含 zone id 的纯 IPv6 地址
    int port = 0;
    qint64 lastSeenMs = 0; // 最近一次收到该 peer 广播的时间
};

class PeerDiscovery : public QObject
{
    Q_OBJECT
public:
    explicit PeerDiscovery(QObject* parent = nullptr);
    ~PeerDiscovery();

    // 启动发现服务
    // selfAddr: 自己的 IPv6 地址（用于过滤掉自身广播）
    // selfPort: 自己的服务端口
    bool start(const QHostAddress& selfAddr, int selfPort);

    // 停止发现服务
    void stop();

    // 当前已知 peer 列表（自动剔除超过 60s 未广播的）
    QList<DiscoveredPeer> knownPeers() const;

    // 是否在运行
    bool isRunning() const { return m_running; }

signals:
    // 发现新 peer 或 peer 信息更新
    void peerFound(const QString& address, int port);
    // peer 失联（超过 TTL 未收到广播）
    void peerLost(const QString& address, int port);

private slots:
    void onReadyRead();
    void onBroadcastTick();
    void onCleanupTick();

private:
    QUdpSocket* m_socket = nullptr;
    QTimer m_broadcastTimer;
    QTimer m_cleanupTimer;
    QHostAddress m_selfAddr;
    int m_selfPort = 0;
    bool m_running = false;

    // address:port -> DiscoveredPeer
    mutable QMutex m_peersMutex;
    QHash<QString, DiscoveredPeer> m_peers;

    // 已知超时阈值（毫秒）
    static constexpr qint64 PEER_TTL_MS = 60 * 1000; // 60s
    static constexpr int BROADCAST_INTERVAL_MS = 10 * 1000; // 10s
    static constexpr int CLEANUP_INTERVAL_MS = 15 * 1000; // 15s
    static constexpr quint16 DISCOVERY_PORT = 31489;
    static constexpr const char* MULTICAST_ADDR = "ff02::1"; // IPv6 all-nodes
    static constexpr const char* PROTO_MAGIC = "FANTOMCHAT_PRESENT";
};

#endif // PEERDISCOVERY_H
