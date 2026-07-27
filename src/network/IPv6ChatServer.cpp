#include "IPv6ChatServer.h"
#include "../utils/ProtocolUtils.h"
#include "../utils/ClockSync.h"
#include "../utils/ProtocolVersion.h"
#include "../utils/MessageType.h"
#include "../utils/RatchetWire.h"
#include "../encrypting/interfaces/ICryptoError.h"
#include <QDebug>
#include <QTcpServer>

// O16: 取实际生效的会话（Ratchet 优先，否则回退到普通会话）
ICryptoSession* IPv6ChatServer::sessionFor(QTcpSocket* socket) const {
    auto it = ratchetSessions.find(socket);
    if (it != ratchetSessions.end()) return it.value();
    return sessions.value(socket, nullptr);
}

IPv6ChatServer::IPv6ChatServer(QHostAddress addr, int port, QObject* parent)
    : QObject(parent), server(nullptr), addr(addr), port(port) {}

IPv6ChatServer::~IPv6ChatServer() {
    stopServer();
    qDebug() << "Server: Killed server.";
}

void IPv6ChatServer::run() {
    // Server initiating and strating to listen the port on self Thread
    if (server) return;
    server = new QTcpServer(this);
    connect(server, &QTcpServer::newConnection, this, &IPv6ChatServer::onNewConnection);

    // Garbage: QHostAddress::AnyIPv6
    if (!server->listen(this->addr, port)) {
        qCritical() << "Server: failed to start: " << server->errorString();
        return;
    }

    qDebug() << "Server: started on address: " << "["+ this->addr.toString() + "]:" + QString::number(port);
}

void IPv6ChatServer::onNewConnection() {
    // New client connected
    // Each connected client will be appended to the list of client connections from server side
    // TODO: parse list of connected clients as address book list as available to send message
    QTcpSocket* socket = server->nextPendingConnection();
    if (!socket) return;

    QString clientID = QString("%1:%2")
       .arg(socket->peerAddress().toString())
       .arg(socket->peerPort());

    socket->setProperty("clientID", clientID);

    QMutexLocker locker(&clientsMutex);
    for (auto client : clients) {
        if (stripPort(client.clientID) == stripPort(clientID)) {
            if (client.socket->state() == QAbstractSocket::UnconnectedState) {
                clients.remove(client.clientID);
                break;
            } else {
                socket->disconnectFromHost();
                return;
            }
        }
    }

    clients.insert(clientID, {clientID, socket});

    connect(socket, &QTcpSocket::readyRead, this, &IPv6ChatServer::onReadyRead, Qt::QueuedConnection);
    connect(socket, &QTcpSocket::disconnected, this, &IPv6ChatServer::onClientDisconnected);

    qDebug() << "Server: New client connected: " << clientID;

    emit clientConnected(clientID);
}

void IPv6ChatServer::onReadyRead() {
    // Read message incoming from client
    // Any message from client will be get and separated by its id
    qDebug() << "Server: ready read starts";
    QTcpSocket* senderClient = qobject_cast<QTcpSocket*>(sender());
    if (!senderClient) return;

    QByteArray& buffer = socketBuffers[senderClient];
    buffer.append(senderClient->readAll());

    bool isHandshaked = handshakedSockets.contains(senderClient);

    if (!isHandshaked && !buffer.startsWith("HANDSHAKE ")){
        qDebug() << "Server: Got message before handshake, disconnecting.";
        senderClient->disconnectFromHost();
        return;
    }

    // Handshaking first
    if (!isHandshaked){
        const int maxHandshakeLineSize = 2048;
        if (buffer.size() > maxHandshakeLineSize) {
            qWarning() << "Server: Handshake line too long, disconnecting.";
            senderClient->disconnectFromHost();
            return;
        }

        int endIndex = buffer.indexOf('\n');
        if (endIndex == -1) return; // Waiting for full line

        QByteArray line = buffer.left(endIndex).trimmed();
        buffer.remove(0, endIndex + 1);

        QString lineStr = QString::fromUtf8(line);

        // O3: 解析新格式 HANDSHAKE <pubkey> <client_ts_ms> <proto_ver> <min_compat_ver>
        // 兼容旧格式 HANDSHAKE <pubkey>（无时间戳无版本）
        QStringList parts = lineStr.split(' ', Qt::SkipEmptyParts);
        if (parts.size() < 2) {
            qDebug() << "Server: Malformed HANDSHAKE line, disconnecting.";
            senderClient->disconnectFromHost();
            return;
        }

        QString peerPublicKeyBase64 = parts[1];
        QByteArray peerPublicKey = QByteArray::fromBase64(peerPublicKeyBase64.toUtf8());

        // O4: 版本兼容性判定
        // 如果客户端带版本字段，先判定；不兼容则返回 HANDSHAKE_NACK 并断开
        // O16: 同时判定是否启用 Ratchet（双方协议版本都 >= v1.2.0）
        bool useRatchet = false;
        if (parts.size() >= 5) {
            bool ok1 = false, ok2 = false;
            quint32 remoteCurrent  = parts[3].toUInt(&ok1, 16);
            quint32 remoteMinCompat = parts[4].toUInt(&ok2, 16);
            if (ok1 && ok2) {
                if (!ProtoVer::isCompatibleWith(remoteCurrent, remoteMinCompat)) {
                    qWarning() << "Server: Protocol incompatible with client"
                               << senderClient->property("clientID").toString()
                               << "- local" << ProtoVer::toString(ProtoVer::CURRENT)
                               << "(min compat" << ProtoVer::toString(ProtoVer::MIN_COMPAT) << ")"
                               << "vs remote" << ProtoVer::toString(remoteCurrent)
                               << "(min compat" << ProtoVer::toString(remoteMinCompat) << ")";
                    QString nack = QString("HANDSHAKE_NACK incompatible_version local=%1 remote=%2\n")
                        .arg(ProtoVer::toString(ProtoVer::CURRENT))
                        .arg(ProtoVer::toString(remoteCurrent));
                    senderClient->write(nack.toUtf8());
                    senderClient->disconnectFromHost();
                    return;
                }
                // O16: 双方协议版本都 >= v1.2.0 才启用 Ratchet
                useRatchet = ProtoVer::supportsRatchet(remoteCurrent);
                qDebug() << "Server: Protocol version compatible with client"
                         << ProtoVer::toString(ProtoVer::CURRENT)
                         << "<->" << ProtoVer::toString(remoteCurrent)
                         << (useRatchet ? "(Ratchet enabled)" : "(Ratchet disabled)");
            } else {
                qDebug() << "Server: Cannot parse client protocol version, treating as legacy";
            }
        } else {
            qDebug() << "Server: Client uses legacy protocol (no version field), proceeding in compat mode";
        }

        try{
            // Generate keys and session from server side
            auto keyPair = cryptoBackend->generateKeyPair();
            serverKeys[senderClient] = keyPair;

            // O16: 根据协议版本选择会话类型
            //   useRatchet=true: 创建 IRatchetSession（pre-rotation 状态），等待 RATCHET_PUBKEY
            //   useRatchet=false: 创建普通 ICryptoSession（向后兼容）
            if (useRatchet) {
                auto ratchetSession = cryptoBackend->createRatchetSession(*serverKeys[senderClient], peerPublicKey);
                if (!ratchetSession) {
                    // 后端不支持 Ratchet，回退到普通会话
                    qWarning() << "Server: Backend does not support Ratchet, falling back to regular session";
                    auto session = cryptoBackend->createSession(*serverKeys[senderClient], peerPublicKey);
                    sessions[senderClient] = session;
                } else {
                    ratchetSessions[senderClient] = ratchetSession;
                    // ratchetReady 保持 false，等待客户端发送 RATCHET_PUBKEY
                    ratchetReady[senderClient] = false;
                    qDebug() << "Server: Ratchet session created, awaiting RATCHET_PUBKEY from client";
                }
            } else {
                auto session = cryptoBackend->createSession(*serverKeys[senderClient], peerPublicKey);
                sessions[senderClient] = session;
            }

            // O17: 保存 peer 公钥，供 Safety Number 计算
            {
                QString clientID = senderClient->property("clientID").toString();
                QMutexLocker locker(&peerKeysMutex);
                peerPublicKeys.insert(clientID, peerPublicKey);
            }

            // O3: 计算时钟偏移（如果客户端带时间戳）
            QString clientID = senderClient->property("clientID").toString();
            if (parts.size() >= 3) {
                bool ok = false;
                qint64 clientTs = parts[2].toLongLong(&ok);
                if (ok) {
                    qint64 localRecvTs = ClockSync::nowMs();
                    qint64 offset = ClockSync::computeOffset(clientTs, localRecvTs);
                    ClockSync::instance().setOffset(clientID, offset);

                    if (!ClockSync::instance().isWithinTolerance(clientID)) {
                        qWarning() << "Server: Clock skew with" << clientID
                                    << "is" << offset << "ms (exceeds"
                                    << CLOCK_SYNC_TOLERANCE_MS << "ms)."
                                    << "Communication continues but time-dependent features may misbehave.";
                    } else {
                        qDebug() << "Server: Clock offset with" << clientID << "=" << offset << "ms";
                    }
                } else {
                    qDebug() << "Server: Cannot parse client timestamp, skipping clock sync";
                }
            } else {
                // 旧版客户端，无时间戳，视为无偏移
                ClockSync::instance().setOffset(clientID, 0);
            }

            // O3 + O4: 响应中附带服务端时间戳与版本字段
            // 新格式：HANDSHAKE_ACK <pubkey> <server_ts_ms> <proto_ver> <min_compat_ver>\n
            QString serverPublicKeyBase64 = serverKeys[senderClient]->publicKey().toBase64();
            qint64 serverTs = ClockSync::nowMs();
            QString ackMessage = QString("HANDSHAKE_ACK %1 %2 %3 %4\n")
                .arg(serverPublicKeyBase64)
                .arg(serverTs)
                .arg(ProtoVer::CURRENT, 0, 16)
                .arg(ProtoVer::MIN_COMPAT, 0, 16);
            senderClient->write(ackMessage.toUtf8());

            handshakedSockets.insert(senderClient);
        } catch (const ICryptoError& ex) {
            // O11: 日志记录原始消息，对用户可见场景使用本地化消息
            qWarning() << "Server: Failed handshake:" << ex.message()
                       << "| user-facing:" << ex.localizedMessage();
            emit handshakeError(ex.localizedMessage());
            senderClient->disconnectFromHost();
        }

        return;
    }

    // O16: 握手后，若该 socket 使用 Ratchet，先消费所有 RATCHET_PUBKEY 行
    //   - 首次旋转：ratchetReady 由 false 变 true
    //   - 周期性再旋转（O16+）：ratchetReady 已 true，再次 applyPeerRatchetKey
    // 二进制帧首字节是 length-prefix 的高字节（小消息为 0x00），
    // "RATCHET_PUBKEY" 首字节是 'R'=0x52，二者绝不冲突，可安全区分
    if (ratchetSessions.contains(senderClient)) {
        while (buffer.startsWith(RatchetWire::PREFIX)) {
            QByteArray newPub;
            if (!RatchetWire::tryDecode(buffer, newPub)) {
                if (buffer.indexOf('\n') == -1) {
                    return; // 行未完整，等待更多数据
                }
                // 已有 \n 但解析失败（长度不对等）→ 协议违规
                qWarning() << "Server: Malformed RATCHET_PUBKEY from"
                           << senderClient->property("clientID").toString();
                senderClient->disconnectFromHost();
                return;
            }
            try {
                ratchetSessions[senderClient]->applyPeerRatchetKey(newPub);
                ratchetReady[senderClient] = true;
                qDebug() << "Server: Ratchet rotation applied with"
                         << senderClient->property("clientID").toString()
                         << "(recvCounter=" << ratchetSessions[senderClient]->recvCounter() << ")";
            } catch (const ICryptoError& ex) {
                qWarning() << "Server: Ratchet rotation failed:" << ex.message()
                           << "| user-facing:" << ex.localizedMessage();
                emit handshakeError(ex.localizedMessage());
                senderClient->disconnectFromHost();
                return;
            }
        }

        // 首次旋转尚未完成时，绝不允许走二进制帧路径（chain 不匹配会导致解密失败）
        if (!ratchetReady.value(senderClient, false)) {
            // buffer 不以 RATCHET_PUBKEY 开头，但又没旋转过 → 用户消息提前到达
            qWarning() << "Server: Expected RATCHET_PUBKEY but got non-matching data from"
                       << senderClient->property("clientID").toString();
            senderClient->disconnectFromHost();
            return;
        }
    }

    // If handshaked, move on
    processMessage(senderClient, buffer);
}

void IPv6ChatServer::processMessage(QTcpSocket* socket, QByteArray& buffer)
{
    const int maxMessageSize = 64 * 1024;

    // We have to ensure, that we get full message and determine client as one for this message
    while (buffer.size() >= 4) {
        quint32 msgLen = readUInt32(buffer.left(4));
        if (buffer.size() < 4 + msgLen) break;

        if (msgLen > maxMessageSize) {
            qDebug() << "Server: Message too large (" << msgLen << " bytes), dropping.";
            socket->disconnectFromHost();
            return;
        }

        QByteArray fullMessage = buffer.mid(4, msgLen);
        buffer.remove(0, 4 + msgLen);

        // O9+F3: 解析类型字节
        // 兼容旧版（无 type 字节）：第一字节若是 selfHost 首字符（IPv6 数字/字母/冒号），
        // 直接走旧路径；否则按新版解析
        quint8 type = MsgType::TEXT;
        QByteArray rest = fullMessage;
        if (!fullMessage.isEmpty()) {
            quint8 firstByte = static_cast<quint8>(fullMessage[0]);
            if (firstByte == MsgType::TEXT ||
                firstByte == MsgType::FILE_HEADER ||
                firstByte == MsgType::FILE_CHUNK ||
                firstByte == MsgType::FILE_TRANSFER_END ||
                firstByte == MsgType::CONTROL) {
                type = firstByte;
                rest = fullMessage.mid(1);
            }
            // 否则视为旧版无 type 字节，rest = fullMessage
        }

        int sepIndex = rest.indexOf('\0');
        if (sepIndex == -1) continue;

        QString clientID = this->updateClientZoneID(QString::fromUtf8(rest.left(sepIndex)));
        QByteArray encryptedPayload = rest.mid(sepIndex + 1);

        if (!handshakedSockets.contains(socket)) {
            qDebug() << "Server: Message from unverified clientID " << clientID << ", dropping.";
            socket->disconnectFromHost();
            return;
        }

        // O16: 取实际生效的会话（Ratchet 优先，否则回退到普通会话）
        auto session = sessionFor(socket);
        if (!session) {
            qDebug() << "Server: No crypto session found for socket";
            continue;
        }

        QByteArray payload;
        try{
            payload = session->decrypt(encryptedPayload);
        } catch (const ICryptoError& ex){
            // O11: 日志记录原始消息，对用户可见场景使用本地化消息
            qWarning() << "Server: cannot decrypt payload:" << ex.message()
                       << "| user-facing:" << ex.localizedMessage();
            emit decryptionError(ex.localizedMessage());
            continue;
        }

        // O9+F3: 按类型分发信号
        switch (type) {
            case MsgType::TEXT: {
                qDebug() << "Server: Received text from" << clientID << ":" << payload;
                emit messageArrived(clientID, payload);
                break;
            }
            case MsgType::FILE_HEADER: {
                MsgCodec::FileHeader h = MsgCodec::decodeFileHeader(payload);
                if (h.valid) {
                    qDebug() << "Server: Received file header from" << clientID
                             << "name=" << h.filename << "size=" << h.size;
                    emit fileHeaderArrived(clientID, h.fileId, h.filename, h.size);
                }
                break;
            }
            case MsgType::FILE_CHUNK: {
                MsgCodec::FileChunk c = MsgCodec::decodeFileChunk(payload);
                if (c.valid) {
                    emit fileChunkArrived(clientID, c.fileId, c.offset, c.data);
                }
                break;
            }
            case MsgType::FILE_TRANSFER_END: {
                if (payload.size() >= MsgCodec::FILE_ID_LEN) {
                    emit fileEndArrived(clientID, payload.left(MsgCodec::FILE_ID_LEN));
                }
                break;
            }
            default:
                qDebug() << "Server: Unknown message type" << type << "from" << clientID;
        }
    }
}

QString IPv6ChatServer::updateClientZoneID(QString rawClientID)
{

    QString serverAddress = this->addr.toString();
    QString zoneID;
    int percentIndex = serverAddress.indexOf('%');
    if (percentIndex != -1)
        zoneID = serverAddress.mid(percentIndex + 1);

    QString clientPort = rawClientID.section(':', -1);
    QString clientID = stripPort(rawClientID);
    return zoneID.isEmpty()
               ? clientID + ":" + clientPort
               : clientID + "%" + zoneID + ":" + clientPort;
}

void IPv6ChatServer::onClientDisconnected() {
    // Client disconnected
    // On disconnection each client, we have to ensure socket delete
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket) return;

    QString disconnectedID;
    QMutexLocker locker(&clientsMutex);
    auto client = std::find_if(clients.begin(), clients.end(), [&](const PeerConnection& c){
        return c.socket == socket;
    });
    if (client != clients.end()) {
        qDebug() << "Disconnected:" << client.value().clientID;
        disconnectedID = client.value().clientID;
        clients.erase(client);
    }

    delete sessions[socket];
    sessions.remove(socket);
    // O16: 清理 Ratchet 会话和状态（与 sessions 互斥，至多一个非空）
    delete ratchetSessions[socket];
    ratchetSessions.remove(socket);
    ratchetReady.remove(socket);
    delete serverKeys[socket];
    serverKeys.remove(socket);
    handshakedSockets.remove(socket);
    socketBuffers.remove(socket);

    // O17: 清理 peer 公钥缓存
    if (!disconnectedID.isEmpty()) {
        QMutexLocker pkLocker(&peerKeysMutex);
        peerPublicKeys.remove(disconnectedID);
    }

    // O3: 清除时钟偏移记录
    if (!disconnectedID.isEmpty()) {
        ClockSync::instance().clear(disconnectedID);
    }

    emit clientDisconnected(disconnectedID);

    socket->deleteLater();
}

void IPv6ChatServer::stopServer() {
    // Server stopping
    // Kill the server and clear clients list, not forgetting to disconnect each
    if (server) {
        server->close();
    }
    QMutexLocker locker(&clientsMutex);
    for (const PeerConnection& client : clients.values()) {
        client.socket->disconnectFromHost();
    }
    clients.clear();
}

// O17: Safety Number 支持访问器
QByteArray IPv6ChatServer::localPublicKey() const {
    // Server 端每次握手都生成临时密钥对，没有"全局长期密钥"概念
    // 这里返回最后一次握手生成的公钥，足以支持 Safety Number 显示
    // （Safety Number 是会话级别的，只在单次连接期间有效）
    if (serverKeys.isEmpty()) return {};
    return serverKeys.last()->publicKey();
}

QByteArray IPv6ChatServer::peerPublicKey(const QString& clientID) const {
    QMutexLocker locker(const_cast<QMutex*>(&peerKeysMutex));
    return peerPublicKeys.value(clientID);
}
