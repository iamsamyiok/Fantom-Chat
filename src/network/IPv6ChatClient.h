#ifndef IPV6CHATCLIENT_H
#define IPV6CHATCLIENT_H

#include "../utils/Structures.h"
#include "../encrypting/interfaces/ICryptoKeyPair.h"
#include "../encrypting/interfaces/ICryptoSession.h"
#include "../encrypting/interfaces/IRatchetSession.h"
#include "../encrypting/interfaces/ICryptoBackend.h"
#include <QMap>
#include <QMutex>
#include <QObject>
#include <QTcpSocket>

class IPv6ChatClient : public QObject {
    Q_OBJECT

public:
    std::shared_ptr<ICryptoBackend> cryptoBackend;

    explicit IPv6ChatClient(QObject* parent = nullptr);
    void connectToPeer(const QString& address, int port);
    void sendMessage(const QString& selfHost, const QString& clientID, const QByteArray& message);

    // O9+F3: 文件传输 API
    // sendFileHeader 发送文件元数据
    void sendFileHeader(const QString& selfHost, const QString& clientID,
                       const QByteArray& fileId, const QString& filename, qint64 size);
    // sendFileChunk 发送文件数据块（调用方按 chunk 循环调用）
    void sendFileChunk(const QString& selfHost, const QString& clientID,
                       const QByteArray& fileId, qint64 offset, const QByteArray& chunk);
    // sendFileEnd 通知文件传输结束
    void sendFileEnd(const QString& selfHost, const QString& clientID,
                     const QByteArray& fileId);

    // O17: Safety Number 支持访问器
    // 获取指定 clientID 对应的远端公钥（握手成功后可用）
    QByteArray peerPublicKey(const QString& clientID) const;
    // 获取本端最后一次握手时使用的公钥（用于 Safety Number 显示）
    QByteArray localPublicKey() const;

private slots:
    void onConnected();
    void onDisconnected();
    void onReadyRead();
    void onSocketError(QAbstractSocket::SocketError);

private:
    QMutex connectionsMutex;
    QMap<QString, PeerConnection> connections;
    QHash<QTcpSocket*, bool> handshakeStatus;

    QHash<QTcpSocket*, ICryptoKeyPair*> clientKeys;
    // 非 Ratchet 会话（旧版本对端使用）
    QHash<QTcpSocket*, ICryptoSession*> sessions;
    // O16: Ratchet 会话（双方协议版本 >= v1.2.0 时使用，拥有权归属本类）
    // 注意：ratchetSessions[socket] 与 sessions[socket] 互斥，同一 socket 至多一个
    QHash<QTcpSocket*, IRatchetSession*> ratchetSessions;
    // O16: DH 旋转是否已完成（true 表示此后可双向收发用户消息）
    QHash<QTcpSocket*, bool> ratchetReady;
    // O16+: 自上次 DH 旋转以来发送的消息计数，用于触发周期性再旋转
    // 达到 RATCHET_ROTATE_EVERY 条消息时，下一条发送前先 prepareRatchetStep
    QHash<QTcpSocket*, quint32> messagesSinceRotation;

    // O17: 保存每个 clientID 对应的远端公钥（mutex 与 connectionsMutex 复用）
    QMap<QString, QByteArray> peerPublicKeys;

    // O16: 按 socket 取实际生效的会话（Ratchet 或普通）
    ICryptoSession* sessionFor(QTcpSocket* socket) const;

    // O16+: 周期性 DH 旋转阈值（每 100 条消息触发一次再旋转，增强后向保密）
    static constexpr quint32 RATCHET_ROTATE_EVERY = 100;

    // O9+F3: 内部辅助，发送带类型标记的加密帧
    void sendTypedFrame(const QString& selfHost, const QString& clientID,
                        quint8 type, const QByteArray& payload);

signals:
    void peerConnected(const QString& clientID);
    void peerDisconnected(const QString& clientID);
    void messageSent(const QString& clientID, const QByteArray& message);

    // O11: 握手/加密错误信号，携带本地化错误消息
    // MainWindow 可连接此信号，向用户展示翻译后的错误提示
    void handshakeError(const QString& localizedMessage);
};

#endif // IPV6CHATCLIENT_H
