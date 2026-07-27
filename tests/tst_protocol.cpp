// tst_protocol.cpp - 测试协议层 (O8) 的 Frame / FrameReader / HandshakeCodec
#include <QtTest>
#include <QByteArray>
#include <QString>

#include "Frame.h"
#include "FrameReader.h"
#include "HandshakeCodec.h"
#include "ProtocolVersion.h"

class TestProtocol : public QObject {
    Q_OBJECT
private slots:
    void testFrameRoundTrip();
    void testFrameDeserializeEmpty();
    void testFrameReaderSingleFrame();
    void testFrameReaderMultipleFrames();
    void testFrameReaderPartialThenComplete();
    void testFrameReaderRejectsHuge();
    void testHandshakeInitRoundTrip();
    void testHandshakeAckRoundTrip();
    void testHandshakeNackRoundTrip();
    void testHandshakeLegacyFormat();
    void testProtocolVersionCompat();
    void testSupportsRatchet();
};

void TestProtocol::testFrameRoundTrip() {
    Protocol::Frame in(0x05, QByteArray("hello world"));
    QByteArray serialized = in.serialize();
    Protocol::Frame out;
    QVERIFY(Protocol::Frame::deserialize(serialized, out));
    QCOMPARE(out.type, quint8(0x05));
    QCOMPARE(out.payload, QByteArray("hello world"));
}

void TestProtocol::testFrameDeserializeEmpty() {
    Protocol::Frame out;
    QVERIFY(!Protocol::Frame::deserialize(QByteArray(), out));
}

void TestProtocol::testFrameReaderSingleFrame() {
    // length-prefix (4 bytes big-endian) + type + payload
    QByteArray frame = Protocol::Frame(0x07, QByteArray("payload-1")).serialize();
    QByteArray packet;
    quint32 len = frame.size();
    for (int i = 3; i >= 0; --i) {
        packet.append(static_cast<char>((len >> (i * 8)) & 0xFF));
    }
    packet.append(frame);

    int calls = 0;
    quint8 gotType = 0;
    QByteArray gotPayload;
    FrameReader reader([&](quint8 type, const QByteArray& payload){
        ++calls; gotType = type; gotPayload = payload;
    });
    reader.feed(packet);
    QCOMPARE(calls, 1);
    QCOMPARE(gotType, quint8(0x07));
    QCOMPARE(gotPayload, QByteArray("payload-1"));
}

void TestProtocol::testFrameReaderMultipleFrames() {
    QByteArray packet;
    auto appendFrame = [&](const Protocol::Frame& f){
        QByteArray s = f.serialize();
        quint32 len = s.size();
        for (int i = 3; i >= 0; --i) {
            packet.append(static_cast<char>((len >> (i * 8)) & 0xFF));
        }
        packet.append(s);
    };
    appendFrame(Protocol::Frame(0x01, QByteArray("a")));
    appendFrame(Protocol::Frame(0x02, QByteArray("bb")));
    appendFrame(Protocol::Frame(0x03, QByteArray("ccc")));

    int calls = 0;
    QStringList payloads;
    FrameReader reader([&](quint8, const QByteArray& payload){
        ++calls; payloads << QString::fromUtf8(payload);
    });
    reader.feed(packet);
    QCOMPARE(calls, 3);
    QCOMPARE(payloads, QStringList({"a", "bb", "ccc"}));
}

void TestProtocol::testFrameReaderPartialThenComplete() {
    QByteArray frame = Protocol::Frame(0x09, QByteArray("split-frame")).serialize();
    QByteArray packet;
    quint32 len = frame.size();
    for (int i = 3; i >= 0; --i) {
        packet.append(static_cast<char>((len >> (i * 8)) & 0xFF));
    }
    packet.append(frame);

    int calls = 0;
    QByteArray gotPayload;
    FrameReader reader([&](quint8, const QByteArray& payload){
        ++calls; gotPayload = payload;
    });
    // 先喂一半
    reader.feed(packet.left(packet.size() / 2));
    QCOMPARE(calls, 0);
    // 再喂剩余
    reader.feed(packet.mid(packet.size() / 2));
    QCOMPARE(calls, 1);
    QCOMPARE(gotPayload, QByteArray("split-frame"));
}

void TestProtocol::testFrameReaderRejectsHuge() {
    QByteArray packet;
    // 构造一个声称 100MB 的长度
    quint32 huge = 100u * 1024u * 1024u;
    for (int i = 3; i >= 0; --i) {
        packet.append(static_cast<char>((huge >> (i * 8)) & 0xFF));
    }
    packet.append(QByteArray("dummy"));

    int calls = 0;
    FrameReader reader([&](quint8, const QByteArray&){
        ++calls;
    });
    reader.feed(packet);
    QCOMPARE(calls, 0);
    QCOMPARE(reader.bufferedBytes(), 0); // 应已 reset
}

void TestProtocol::testHandshakeInitRoundTrip() {
    QByteArray pubKey(32, '\x42');  // 32 字节测试公钥
    qint64 ts = 1234567890;
    QString line = Protocol::HandshakeCodec::buildInit(pubKey, ts);
    QVERIFY(line.startsWith("HANDSHAKE "));

    Protocol::HandshakeInit parsed = Protocol::HandshakeCodec::parseInit(line);
    QVERIFY(parsed.valid);
    QCOMPARE(parsed.publicKey, pubKey);
    QVERIFY(parsed.hasTimestamp);
    QCOMPARE(parsed.clientTimestampMs, ts);
    QVERIFY(parsed.hasVersion);
    QCOMPARE(parsed.protoVersion, ProtoVer::CURRENT);
    QCOMPARE(parsed.minCompatVersion, ProtoVer::MIN_COMPAT);
}

void TestProtocol::testHandshakeAckRoundTrip() {
    QByteArray pubKey(32, '\x99');
    qint64 ts = 9876543210LL;
    QString line = Protocol::HandshakeCodec::buildAck(pubKey, ts);
    QVERIFY(line.startsWith("HANDSHAKE_ACK "));

    Protocol::HandshakeAck parsed = Protocol::HandshakeCodec::parseAck(line);
    QVERIFY(parsed.valid);
    QCOMPARE(parsed.publicKey, pubKey);
    QCOMPARE(parsed.serverTimestampMs, ts);
    QVERIFY(parsed.hasVersion);
}

void TestProtocol::testHandshakeNackRoundTrip() {
    QString reason = "incompatible version";
    QString line = Protocol::HandshakeCodec::buildNack(reason);
    QVERIFY(line.startsWith("HANDSHAKE_NACK "));
    QString parsed = Protocol::HandshakeCodec::parseNack(line);
    QCOMPARE(parsed, reason);

    // 非 NACK 行应返回空
    QCOMPARE(Protocol::HandshakeCodec::parseNack("HANDSHAKE foo"), QString());
}

void TestProtocol::testHandshakeLegacyFormat() {
    // 兼容旧版：仅 HANDSHAKE <pubkey>，无时间戳无版本
    QByteArray pubKey(32, '\xAA');
    QString line = QString("HANDSHAKE %1")
                       .arg(QString::fromUtf8(pubKey.toBase64()));

    Protocol::HandshakeInit parsed = Protocol::HandshakeCodec::parseInit(line);
    QVERIFY(parsed.valid);
    QCOMPARE(parsed.publicKey, pubKey);
    QVERIFY(!parsed.hasTimestamp);
    QVERIFY(!parsed.hasVersion);
}

void TestProtocol::testProtocolVersionCompat() {
    // 当前版本与自身兼容
    QVERIFY(ProtoVer::isCompatibleWith(ProtoVer::CURRENT, ProtoVer::MIN_COMPAT));
    // 远端 major 不同（v2.0.0）应拒绝
    QVERIFY(!ProtoVer::isCompatibleWith(0x020000, ProtoVer::MIN_COMPAT));
    // 远端版本太旧（v0.x）应拒绝
    QVERIFY(!ProtoVer::isCompatibleWith(0x00FF00, 0x00FF00));
}

void TestProtocol::testSupportsRatchet() {
    // O16: 当前版本应当 >= RATCHET_FEATURE_VERSION（即本端支持 Ratchet）
    QVERIFY(ProtoVer::CURRENT >= ProtoVer::RATCHET_FEATURE_VERSION);

    // 双方都是当前版本 → 启用 Ratchet
    QVERIFY(ProtoVer::supportsRatchet(ProtoVer::CURRENT));

    // 远端刚好等于 RATCHET_FEATURE_VERSION → 启用（边界值）
    QVERIFY(ProtoVer::supportsRatchet(ProtoVer::RATCHET_FEATURE_VERSION));

    // 远端 v1.1.0 (低于 RATCHET_FEATURE_VERSION) → 不启用，回退普通会话
    QVERIFY(!ProtoVer::supportsRatchet(0x010100));

    // 远端 v1.0.0 → 不启用
    QVERIFY(!ProtoVer::supportsRatchet(0x010000));

    // 远端假想 v1.3.0（高于本端）→ 仍然启用（向后兼容 Ratchet 特性）
    QVERIFY(ProtoVer::supportsRatchet(0x010300));
}

int runProtocolTests(int argc, char** argv) {
    char* args[] = { argv[0], const_cast<char*>("-o"), const_cast<char*>("-,txt") };
    int newArgc = sizeof(args) / sizeof(args[0]);
    return QTest::qExec(new TestProtocol(), newArgc, args);
}

#include "tst_protocol.moc"
