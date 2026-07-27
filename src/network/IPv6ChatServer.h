#ifndef IPV6CHATSERVER_H
#define IPV6CHATSERVER_H

#include "../utils/Structures.h"
#include "../encrypting/interfaces/ICryptoKeyPair.h"
#include "../encrypting/interfaces/ICryptoSession.h"
#include "../encrypting/interfaces/IRatchetSession.h"
#include "../encrypting/interfaces/ICryptoBackend.h"
#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>
#include <QMutex>
#include <QVector>
#include <QMap>


class IPv6ChatServer : public QObject {
    Q_OBJECT

private:
    QTcpServer *server;
    QMutex clientsMutex;
    QString myClientID;
    QHostAddress addr;
    int port;
    QMap<QString, PeerConnection> clients;
    QMap<QTcpSocket*, QByteArray> socketBuffers;
    QSet<QTcpSocket*> handshakedSockets;

    QMap<QTcpSocket*, ICryptoKeyPair*> serverKeys;
    // 非 Ratchet 会话（旧版本对端使用）
    QMap<QTcpSocket*, ICryptoSession*> sessions;
    // O16: Ratchet 会话（双方协议版本 >= v1.2.0 时使用，拥有权归属本类）
    // 注意：ratchetSessions[socket] 与 sessions[socket] 互斥，同一 socket 至多一个
    QMap<QTcpSocket*, IRatchetSession*> ratchetSessions;
    // O16: DH 旋转是否已完成（true 表示此后可正常解密用户消息）
    QMap<QTcpSocket*, bool> ratchetReady;
    // O17: 保存每个 clientID 对应的远端公钥，供 Safety Number 计算
    QMap<QString, QByteArray> peerPublicKeys;
    QMutex peerKeysMutex;

    void processMessage(QTcpSocket* socket, QByteArray& buffer);
    QString updateClientZoneID(QString rawClientID);

    // O16: 按 socket 取实际生效的会话（Ratchet 或普通）
    ICryptoSession* sessionFor(QTcpSocket* socket) const;

public:
    std::shared_ptr<ICryptoBackend> cryptoBackend;

    explicit IPv6ChatServer(QHostAddress addr, int port, QObject* parent = nullptr);
    ~IPv6ChatServer();

    // O17: 获取本端长期公钥（用于 Safety Number 显示）
    // 注意：每个连接的临时密钥对是动态生成的，这里返回最后一次握手时本端用的公钥
    QByteArray localPublicKey() const;

    // O17: 按 clientID 取远端公钥。返回空 QByteArray 表示未知 / 已断开
    QByteArray peerPublicKey(const QString& clientID) const;

public slots:
    void run();
    void onNewConnection();
    void onReadyRead();
    void onClientDisconnected();
    void stopServer();

signals:
    void messageArrived(const QString& clientID, const QByteArray& message);

    // O9+F3: 文件传输相关信号
    void fileHeaderArrived(const QString& clientID, const QByteArray& fileId,
                            const QString& filename, qint64 size);
    void fileChunkArrived(const QString& clientID, const QByteArray& fileId,
                           qint64 offset, const QByteArray& chunk);
    void fileEndArrived(const QString& clientID, const QByteArray& fileId);

    void clientConnected(const QString& clientID);
    void clientDisconnected(const QString& clientID);

    // O11: 错误信号，携带本地化错误消息（用于 UI 展示）
    void handshakeError(const QString& localizedMessage);
    void decryptionError(const QString& localizedMessage);
};
#endif // IPV6CHATSERVER_H
