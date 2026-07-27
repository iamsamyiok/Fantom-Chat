#include "IPv6ChatClient.h"
#include "../encrypting/interfaces/ICryptoError.h"
#include "../utils/ClockSync.h"
#include "../utils/ProtocolVersion.h"
#include "../utils/MessageType.h"
#include "../utils/RatchetWire.h"
#include <QDebug>
#ifdef Q_OS_WIN
#include <winsock2.h>
#endif

// O16: 取实际生效的会话（Ratchet 优先，否则回退到普通会话）
ICryptoSession* IPv6ChatClient::sessionFor(QTcpSocket* socket) const {
    auto it = ratchetSessions.find(socket);
    if (it != ratchetSessions.end()) return it.value();
    return sessions.value(socket, nullptr);
}

IPv6ChatClient::IPv6ChatClient(QObject* parent) : QObject(parent) {}

void IPv6ChatClient::connectToPeer(const QString& address, int port) {
    // Ability to connect to the peer by its address and port
    // UPD: Remmeber, each client - one socket
    QString clientID = QString("%1:%2")
        .arg(address)
        .arg(port);
    if (connections.contains(clientID)){
        qDebug() << "Client: Already connected to peer" << clientID;
        return;
    }

    QTcpSocket* socket = new QTcpSocket(this);
    connect(socket, &QTcpSocket::connected, this, &IPv6ChatClient::onConnected);
    connect(socket, &QTcpSocket::disconnected, this, &IPv6ChatClient::onDisconnected);
    connect(socket, &QTcpSocket::readyRead, this, &IPv6ChatClient::onReadyRead);
    connect(socket, &QTcpSocket::errorOccurred, this, &IPv6ChatClient::onSocketError);

    socket->setProperty("clientID", clientID);
    socket->connectToHost(QHostAddress(address), port);
}

void IPv6ChatClient::onSocketError(QAbstractSocket::SocketError)
{
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket) return;

    QString clientID = socket->property("clientID").toString();
    qDebug() << "Client: couldn't connect to the server" << clientID;

    if (!clientID.isEmpty()) {
        QMutexLocker locker(&connectionsMutex);
        qDebug() << "Client: Disconnected from peer" << clientID;
        connections.remove(clientID);
    }

    handshakeStatus.remove(socket);
    socket->deleteLater();
    return;
}

void IPv6ChatClient::onConnected() {
    qDebug() << "Client: Connected to server";

    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket) return;

    QString clientID = socket->property("clientID").toString();

    {
        QMutexLocker locker(&connectionsMutex);
        connections.insert(clientID, {clientID, socket});
    }

    // Handshake
    qDebug() << "Client: Sending handshake";

    // Generate pair for this connection
    auto keyPair = cryptoBackend->generateKeyPair();
    clientKeys.insert(socket, keyPair);

    // Encode public key to Base64
    QString publicKeyBase64 = clientKeys[socket]->publicKey().toBase64();

    // O3: 握手协议加入时间戳，解决"handshake fails: time is in sync"硬伤
    // O4: 加入协议版本字段，semver 兼容判定
    // 新格式：HANDSHAKE <pubkey> <client_ts_ms> <proto_ver> <min_compat_ver>\n
    qint64 clientTs = ClockSync::nowMs();
    QString handashakeMessage = QString("HANDSHAKE %1 %2 %3 %4\n")
        .arg(publicKeyBase64)
        .arg(clientTs)
        .arg(ProtoVer::CURRENT, 0, 16)
        .arg(ProtoVer::MIN_COMPAT, 0, 16);

    socket->write(handashakeMessage.toUtf8());
    qDebug() << "Client: Sent handshake with public key, timestamp" << clientTs
             << "and protocol version" << ProtoVer::toString(ProtoVer::CURRENT);
}

void IPv6ChatClient::onReadyRead()
{
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket) return;

    QByteArray data = socket->readAll();
    QString line = QString::fromUtf8(data).trimmed();

    try{
        if (line.startsWith("HANDSHAKE_ACK ")) {
            // O3: 解析新格式 HANDSHAKE_ACK <pubkey> <server_ts_ms> <proto_ver> <min_compat_ver>
            // 兼容旧格式 HANDSHAKE_ACK <pubkey>（无时间戳无版本）
            QStringList parts = line.split(' ', Qt::SkipEmptyParts);
            if (parts.size() < 2) {
                qDebug() << "Client: Malformed HANDSHAKE_ACK";
                socket->disconnectFromHost();
                return;
            }

            QString peerPublicKeyBase64 = parts[1];
            QByteArray peerPublicKey = QByteArray::fromBase64(peerPublicKeyBase64.toUtf8());
            QString clientID = socket->property("clientID").toString();

            // O4: 版本兼容性判定（先做，决定走 Ratchet 还是普通路径）
            bool useRatchet = false;
            if (parts.size() >= 5) {
                bool ok1 = false, ok2 = false;
                quint32 remoteCurrent  = parts[3].toUInt(&ok1, 16);
                quint32 remoteMinCompat = parts[4].toUInt(&ok2, 16);
                if (ok1 && ok2) {
                    if (!ProtoVer::isCompatibleWith(remoteCurrent, remoteMinCompat)) {
                        qWarning() << "Client: Protocol incompatible with peer" << clientID
                                   << "- local" << ProtoVer::toString(ProtoVer::CURRENT)
                                   << "(min compat" << ProtoVer::toString(ProtoVer::MIN_COMPAT) << ")"
                                   << "vs remote" << ProtoVer::toString(remoteCurrent)
                                   << "(min compat" << ProtoVer::toString(remoteMinCompat) << ")"
                                   << "- please upgrade to a compatible version.";
                        socket->disconnectFromHost();
                        return;
                    }
                    // O16: 双方协议版本都 >= v1.2.0 才启用 Ratchet
                    useRatchet = ProtoVer::supportsRatchet(remoteCurrent);
                    qDebug() << "Client: Protocol version compatible with peer"
                             << ProtoVer::toString(ProtoVer::CURRENT)
                             << "<->" << ProtoVer::toString(remoteCurrent)
                             << (useRatchet ? "(Ratchet enabled)" : "(Ratchet disabled)");
                } else {
                    qDebug() << "Client: Cannot parse remote protocol version, treating as legacy";
                }
            } else {
                qDebug() << "Client: Peer" << clientID
                         << "uses legacy protocol (no version field), proceeding in compat mode";
            }

            // O3: 时间偏移协商
            if (parts.size() >= 3) {
                bool ok = false;
                qint64 serverTs = parts[2].toLongLong(&ok);
                if (ok) {
                    qint64 localRecvTs = ClockSync::nowMs();
                    qint64 offset = ClockSync::computeOffset(serverTs, localRecvTs);
                    ClockSync::instance().setOffset(clientID, offset);

                    if (!ClockSync::instance().isWithinTolerance(clientID)) {
                        qWarning() << "Client: Clock skew with" << clientID
                                   << "is" << offset << "ms (exceeds"
                                   << CLOCK_SYNC_TOLERANCE_MS << "ms)."
                                   << "Communication continues but time-dependent features may misbehave.";
                    } else {
                        qDebug() << "Client: Clock offset with" << clientID << "=" << offset << "ms";
                    }
                } else {
                    qDebug() << "Client: Cannot parse server timestamp, skipping clock sync";
                }
            } else {
                // 旧版服务端，无时间戳，视为无偏移
                ClockSync::instance().setOffset(clientID, 0);
            }

            // O17: 保存 peer 公钥，供 Safety Number 计算
            {
                QMutexLocker locker(&connectionsMutex);
                peerPublicKeys.insert(clientID, peerPublicKey);
            }

            // O16: 根据协议版本选择会话类型
            auto keyPair = clientKeys[socket];
            if (useRatchet) {
                auto ratchetSession = cryptoBackend->createRatchetSession(*keyPair, peerPublicKey);
                if (!ratchetSession) {
                    // 后端不支持 Ratchet，回退到普通会话（向后兼容）
                    qWarning() << "Client: Backend does not support Ratchet, falling back to regular session";
                    auto session = cryptoBackend->createSession(*keyPair, peerPublicKey);
                    sessions.insert(socket, session);
                } else {
                    ratchetSessions.insert(socket, ratchetSession);
                    // 客户端作为 ratchet-initiator：调用 prepareRatchetStep 生成新公钥，
                    // 此操作将本端切到 post-rotation chain；旧 rootKey 立即丢弃（实现 PFS）
                    QByteArray newPub = ratchetSession->prepareRatchetStep();
                    // 通过 wire 明文发送给对端（服务端将调用 applyPeerRatchetKey）
                    // 公钥本身不敏感，MITM 风险与 HANDSHAKE 相同，由 Safety Number 缓解
                    socket->write(RatchetWire::encode(newPub));
                    ratchetReady.insert(socket, true);
                    qDebug() << "Client: Ratchet session established and rotated (sendCounter="
                             << ratchetSession->sendCounter() << ")";
                }
            } else {
                auto session = cryptoBackend->createSession(*keyPair, peerPublicKey);
                sessions.insert(socket, session);
            }

            qDebug() << "Client: Handshake complete. Session keys established.";
            handshakeStatus[socket] = true;

            // Emiting to return clientID outside the thread
            emit peerConnected(socket->property("clientID").toString());
        } else if (line.startsWith("HANDSHAKE_NACK ")) {
            // O4: 服务端拒绝握手（版本不兼容）
            QString reason = line.section(' ', 1);
            qWarning() << "Client: Handshake rejected by peer:" << reason
                       << "- please upgrade your client.";
            socket->disconnectFromHost();
        } else {
            qDebug() << "Client: Unexpected response during handshake.";
            socket->disconnectFromHost();
        }
    } catch (const ICryptoError& ex) {
        // O11: 日志记录原始消息，对用户可见场景使用本地化消息
        qWarning() << "Client: Failed to perform handshake:" << ex.message()
                   << "| user-facing:" << ex.localizedMessage();
        emit handshakeError(ex.localizedMessage());
        socket->disconnectFromHost();
    }

    // Only handshake may be read here.
    disconnect(socket, &QTcpSocket::readyRead, this, &IPv6ChatClient::onReadyRead);
}

void IPv6ChatClient::onDisconnected() {
    auto* socket = qobject_cast<QTcpSocket*>(sender());
    QString deadPeer = socket->property("clientID").toString();

    if (!deadPeer.isEmpty()) {
        QMutexLocker locker(&connectionsMutex);
        qDebug() << "Client: Disconnected from peer" << deadPeer;
        connections.remove(deadPeer);
        // O17: 清理 peer 公钥缓存
        peerPublicKeys.remove(deadPeer);
        // O3: 清除时钟偏移记录
        ClockSync::instance().clear(deadPeer);
    }

    handshakeStatus.remove(socket);
    delete clientKeys[socket];
    clientKeys.remove(socket);
    // O16: 清理会话（ratchetSessions 与 sessions 互斥，二者至多一个非空）
    delete ratchetSessions[socket];
    ratchetSessions.remove(socket);
    ratchetReady.remove(socket);
    messagesSinceRotation.remove(socket);
    delete sessions[socket];
    sessions.remove(socket);
    socket->deleteLater();
    emit peerDisconnected(deadPeer);
}

// 私有辅助：发送一个带类型标记的加密帧
// 内部封装 length-prefix + type + selfHost\0 + encrypted(payload)
void IPv6ChatClient::sendTypedFrame(const QString& selfHost, const QString& clientID,
                                     quint8 type, const QByteArray& payload) {
    if (!connections.contains(clientID)) {
        qDebug() << "Client: No connection to peer" << clientID;
        emit peerDisconnected(clientID);
        return;
    }

    QTcpSocket* socket = connections[clientID].socket;
    if (!handshakeStatus.value(socket, false)) {
        qDebug() << "Client: Can't send, handshake not complete for" << clientID;
        return;
    }

    // O16: 若使用 Ratchet 但 DH 旋转尚未完成，拒绝发送
    // （post-rotation sendChain 与对端 pre-rotation recvChain 不匹配会导致解密失败）
    if (ratchetSessions.contains(socket) && !ratchetReady.value(socket, false)) {
        qDebug() << "Client: Can't send, ratchet not ready for" << clientID;
        return;
    }

    // O16+: 周期性 DH 再旋转
    // 达到阈值时，下一条消息发送前先 prepareRatchetStep 并发送 RATCHET_PUBKEY 行
    // TCP 保序保证：对端先收到 RATCHET_PUBKEY 并 applyPeerRatchetKey，再解密这条消息
    // 旋转后旧 rootKey/chainKey 立即丢弃 → 进一步增强后向保密
    if (ratchetSessions.contains(socket)) {
        quint32& count = messagesSinceRotation[socket];
        if (count >= RATCHET_ROTATE_EVERY) {
            try {
                QByteArray newPub = ratchetSessions[socket]->prepareRatchetStep();
                socket->write(RatchetWire::encode(newPub));
                count = 0;
                qDebug() << "Client: Periodic ratchet rotation triggered for" << clientID
                         << "(sendCounter=" << ratchetSessions[socket]->sendCounter() << ")";
            } catch (const ICryptoError& ex) {
                qWarning() << "Client: Periodic ratchet rotation failed:" << ex.message()
                           << "| user-facing:" << ex.localizedMessage();
                emit handshakeError(ex.localizedMessage());
                return;
            }
        }
    }

    auto session = sessionFor(socket);
    if (!session){
        qDebug() << "Client: No crypto session found for" << clientID;
        return;
    }

    QByteArray encrypted;
    try{
        encrypted = session->encrypt(payload);
    } catch (const ICryptoError& ex){
        // O11: 日志记录原始消息，对用户可见场景使用本地化消息
        qWarning() << "Client: cannot encrypt payload:" << ex.message()
                   << "| user-facing:" << ex.localizedMessage();
        emit handshakeError(ex.localizedMessage());
        return;
    }

    // O9+F3: composedMessage = type + selfHost\0 + encrypted
    QByteArray composed = MsgCodec::wrapWithType(
        type, selfHost.toUtf8() + '\0' + encrypted);

    QByteArray lengthPrefix;
    QDataStream stream(&lengthPrefix, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);
    stream << static_cast<quint32>(composed.size());

    composed = lengthPrefix + composed;

    socket->write(composed);
    if (socket->waitForBytesWritten(3000)){
        qDebug() << "Client: frame sent (type=" << type << ")";
    }else{
        qDebug() << "Client: frame to" << clientID << "not sent";
    }

    // O16+: 累计本条已成功发送的消息，用于触发周期性再旋转
    if (ratchetSessions.contains(socket)) {
        ++messagesSinceRotation[socket];
    }
}

void IPv6ChatClient::sendMessage(const QString& selfHost, const QString& clientID, const QByteArray& message) {
    // O9+F3: 走统一的 typed frame 路径，类型为 TEXT
    sendTypedFrame(selfHost, clientID, MsgType::TEXT, message);
    emit messageSent(clientID, message);
}

// O9+F3: 发送文件
// 实际发送由调用方按 chunk 调用 sendFileChunk
void IPv6ChatClient::sendFileHeader(const QString& selfHost, const QString& clientID,
                                     const QByteArray& fileId,
                                     const QString& filename,
                                     qint64 size) {
    QByteArray payload = MsgCodec::encodeFileHeader(fileId, filename, size);
    sendTypedFrame(selfHost, clientID, MsgType::FILE_HEADER, payload);
}

void IPv6ChatClient::sendFileChunk(const QString& selfHost, const QString& clientID,
                                    const QByteArray& fileId,
                                    qint64 offset,
                                    const QByteArray& chunk) {
    QByteArray payload = MsgCodec::encodeFileChunk(fileId, offset, chunk);
    sendTypedFrame(selfHost, clientID, MsgType::FILE_CHUNK, payload);
}

void IPv6ChatClient::sendFileEnd(const QString& selfHost, const QString& clientID,
                                  const QByteArray& fileId) {
    QByteArray payload = MsgCodec::encodeFileEnd(fileId);
    sendTypedFrame(selfHost, clientID, MsgType::FILE_END, payload);
}

// O17: Safety Number 支持访问器
QByteArray IPv6ChatClient::peerPublicKey(const QString& clientID) const {
    QMutexLocker locker(const_cast<QMutex*>(&connectionsMutex));
    return peerPublicKeys.value(clientID);
}

QByteArray IPv6ChatClient::localPublicKey() const {
    QMutexLocker locker(const_cast<QMutex*>(&connectionsMutex));
    if (clientKeys.isEmpty()) return {};
    return clientKeys.values().last()->publicKey();
}

