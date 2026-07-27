#include "PeerDiscovery.h"
#include <QDebug>
#include <QNetworkInterface>

PeerDiscovery::PeerDiscovery(QObject* parent)
    : QObject(parent)
{
    m_broadcastTimer.setInterval(BROADCAST_INTERVAL_MS);
    m_cleanupTimer.setInterval(CLEANUP_INTERVAL_MS);
    connect(&m_broadcastTimer, &QTimer::timeout, this, &PeerDiscovery::onBroadcastTick);
    connect(&m_cleanupTimer, &QTimer::timeout, this, &PeerDiscovery::onCleanupTick);
}

PeerDiscovery::~PeerDiscovery()
{
    stop();
}

bool PeerDiscovery::start(const QHostAddress& selfAddr, int selfPort)
{
    if (m_running) return true;

    m_selfAddr = selfAddr;
    m_selfPort = selfPort;

    m_socket = new QUdpSocket(this);
    // 绑定到所有 IPv6 接口的发现端口
    if (!m_socket->bind(QHostAddress::AnyIPv6, DISCOVERY_PORT,
                         QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint)) {
        qWarning() << "PeerDiscovery: cannot bind UDP port" << DISCOVERY_PORT
                   << ":" << m_socket->errorString();
        delete m_socket;
        m_socket = nullptr;
        return false;
    }

    // 加入多播组 ff02::1，对每个非 loopback 的 IPv6 接口都加入
    QHostAddress multicast(MULTICAST_ADDR);
    bool joinedAny = false;
    for (const QNetworkInterface& iface : QNetworkInterface::allInterfaces()) {
        if (!(iface.flags() & QNetworkInterface::IsUp) ||
            !(iface.flags() & QNetworkInterface::IsRunning) ||
             (iface.flags() & QNetworkInterface::IsLoopBack)) {
            continue;
        }
        if (m_socket->joinMulticastGroup(multicast, iface)) {
            joinedAny = true;
            qDebug() << "PeerDiscovery: joined multicast on interface" << iface.name();
        }
    }
    if (!joinedAny) {
        // 退一步：不指定接口加入
        if (!m_socket->joinMulticastGroup(multicast)) {
            qWarning() << "PeerDiscovery: cannot join multicast group, only send works";
        }
    }

    connect(m_socket, &QUdpSocket::readyRead, this, &PeerDiscovery::onReadyRead);

    m_running = true;
    m_broadcastTimer.start();
    m_cleanupTimer.start();

    // 立即广播一次
    onBroadcastTick();

    qDebug() << "PeerDiscovery: started, self =" << m_selfAddr.toString() << ":" << m_selfPort;
    return true;
}

void PeerDiscovery::stop()
{
    if (!m_running) return;
    m_broadcastTimer.stop();
    m_cleanupTimer.stop();
    if (m_socket) {
        m_socket->deleteLater();
        m_socket = nullptr;
    }
    QMutexLocker locker(&m_peersMutex);
    m_peers.clear();
    m_running = false;
}

void PeerDiscovery::onReadyRead()
{
    while (m_socket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(m_socket->pendingDatagramSize());
        QHostAddress senderAddr;
        quint16 senderPort = 0;
        qint64 n = m_socket->readDatagram(datagram.data(), datagram.size(),
                                           &senderAddr, &senderPort);
        if (n <= 0) continue;

        QString line = QString::fromUtf8(datagram).trimmed();
        // 期望格式：FANTOMCHAT_PRESENT <ipv6_addr> <port>\n
        if (!line.startsWith(QLatin1String(PROTO_MAGIC))) continue;

        QStringList parts = line.split(' ', Qt::SkipEmptyParts);
        if (parts.size() < 3) continue;

        QString peerAddr = parts[1];
        int peerPort = parts[2].toInt();
        if (peerPort <= 0) continue;

        // 过滤掉自身（避免回环）
        if (peerAddr == m_selfAddr.toString() && peerPort == m_selfPort) {
            continue;
        }

        QString key = QString("%1:%2").arg(peerAddr).arg(peerPort);
        bool isNew = false;
        {
            QMutexLocker locker(&m_peersMutex);
            auto it = m_peers.find(key);
            if (it == m_peers.end()) {
                DiscoveredPeer p;
                p.address = peerAddr;
                p.port = peerPort;
                p.lastSeenMs = QDateTime::currentMSecsSinceEpoch();
                m_peers.insert(key, p);
                isNew = true;
            } else {
                it.value().lastSeenMs = QDateTime::currentMSecsSinceEpoch();
            }
        }
        if (isNew) {
            qDebug() << "PeerDiscovery: found new peer" << peerAddr << ":" << peerPort;
            emit peerFound(peerAddr, peerPort);
        }
    }
}

void PeerDiscovery::onBroadcastTick()
{
    if (!m_socket) return;

    QString msg = QString("%1 %2 %3\n")
        .arg(QLatin1String(PROTO_MAGIC))
        .arg(m_selfAddr.toString())
        .arg(m_selfPort);

    QByteArray payload = msg.toUtf8();
    QHostAddress multicast(MULTICAST_ADDR);

    qint64 sent = m_socket->writeDatagram(payload, multicast, DISCOVERY_PORT);
    if (sent < 0) {
        qWarning() << "PeerDiscovery: broadcast failed:" << m_socket->errorString();
    }
}

void PeerDiscovery::onCleanupTick()
{
    qint64 now = QDateTime::currentMSecsSinceEpoch();
    QList<DiscoveredPeer> expired;
    {
        QMutexLocker locker(&m_peersMutex);
        auto it = m_peers.begin();
        while (it != m_peers.end()) {
            if (now - it.value().lastSeenMs > PEER_TTL_MS) {
                expired.append(it.value());
                it = m_peers.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (const DiscoveredPeer& p : expired) {
        qDebug() << "PeerDiscovery: peer expired" << p.address << ":" << p.port;
        emit peerLost(p.address, p.port);
    }
}

QList<DiscoveredPeer> PeerDiscovery::knownPeers() const
{
    QMutexLocker locker(&m_peersMutex);
    return m_peers.values();
}
