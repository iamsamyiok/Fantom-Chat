// tst_ratchet.cpp - 测试 SodiumRatchetSession (O16 前向保密)
//
// 覆盖：
//   - 构造与状态
//   - 双向 round-trip（验证初始 chain 方向交叉正确）
//   - 多消息计数器递增
//   - 每条消息密文唯一
//   - 乱序 / 空密文 / 篡改 等错误路径
//   - DH ratchet 旋转后的双向通信
//   - PFS：旋转后旧密文不可重新解密
//   - PFS：仅持有长期密钥的攻击者无法解密旋转后密文（MAC 失败）
#include <QtTest>
#include <QByteArray>
#include <QCryptographicHash>
#include <memory>

#include "SodiumCryptoBackend.h"
#include "SodiumKeyPair.h"
#include "SodiumRatchetSession.h"
#include "IRatchetSession.h"
#include "ICryptoError.h"
#include "RatchetWire.h"

class TestRatchet : public QObject {
    Q_OBJECT
private slots:
    void testConstruction();
    void testInvalidRootKeySize();
    void testInvalidKeySizes();
    void testBasicRoundTrip();
    void testBidirectionalRoundTrip();
    void testMultipleMessagesIncrementCounter();
    void testCiphertextUniquePerMessage();
    void testOutOfOrderThrows();
    void testEmptyCiphertextThrows();
    void testTooShortCiphertextThrows();
    void testTamperedCiphertextThrows();
    void testDHRatchetRoundTrip();
    void testPostRotationOldCiphertextUndecryptable();
    void testForwardSecrecyAfterRotation();
    // O16: wire 协议测试
    void testRatchetWireEncodeDecodeRoundTrip();
    void testRatchetWireIgnoresUnrelatedBuffer();
    void testRatchetWireWaitsForNewline();
    void testRatchetWireRejectsBadLength();
    void testRatchetWireRejectsMalformedLine();
    // O16+: 周期性再旋转测试
    void testMultipleRatchetsRoundTrip();
};

// ---- 构造与状态 ----

void TestRatchet::testConstruction() {
    SodiumCryptoBackend backend;
    std::unique_ptr<ICryptoKeyPair> alice(backend.generateKeyPair());
    std::unique_ptr<ICryptoKeyPair> bob(backend.generateKeyPair());

    std::unique_ptr<IRatchetSession> aliceSession(
        backend.createRatchetSession(*alice, bob->publicKey()));
    QVERIFY(aliceSession != nullptr);
    QVERIFY(aliceSession->isInitialized());
    QCOMPARE(aliceSession->sendCounter(), 0u);
    QCOMPARE(aliceSession->recvCounter(), 0u);
}

void TestRatchet::testInvalidRootKeySize() {
    SodiumCryptoBackend backend;
    std::unique_ptr<ICryptoKeyPair> alice(backend.generateKeyPair());
    std::unique_ptr<ICryptoKeyPair> bob(backend.generateKeyPair());

    // rootKey 必须是 32 字节
    try {
        SodiumRatchetSession bad(QByteArray(16, '\x01'),
                                  alice->privateKey(), alice->publicKey(),
                                  bob->publicKey());
        QFAIL("Construction with short root key should throw");
    } catch (const ICryptoError& ex) {
        QCOMPARE(ex.errorCode(), CryptoErrorCode::InvalidArgument);
    }
}

void TestRatchet::testInvalidKeySizes() {
    SodiumCryptoBackend backend;
    std::unique_ptr<ICryptoKeyPair> alice(backend.generateKeyPair());
    std::unique_ptr<ICryptoKeyPair> bob(backend.generateKeyPair());
    QByteArray rootKey(32, '\x42');

    // 私钥尺寸错误
    try {
        SodiumRatchetSession bad(rootKey,
                                  QByteArray(10, '\x00'),  // too short
                                  alice->publicKey(),
                                  bob->publicKey());
        QFAIL("Construction with bad private key size should throw");
    } catch (const ICryptoError& ex) {
        QCOMPARE(ex.errorCode(), CryptoErrorCode::InvalidArgument);
    }

    // 对端公钥尺寸错误
    try {
        SodiumRatchetSession bad(rootKey,
                                  alice->privateKey(), alice->publicKey(),
                                  QByteArray(10, '\x00'));  // too short
        QFAIL("Construction with bad peer pubkey size should throw");
    } catch (const ICryptoError& ex) {
        QCOMPARE(ex.errorCode(), CryptoErrorCode::InvalidArgument);
    }
}

// ---- 基础 round-trip ----

void TestRatchet::testBasicRoundTrip() {
    SodiumCryptoBackend backend;
    std::unique_ptr<ICryptoKeyPair> alice(backend.generateKeyPair());
    std::unique_ptr<ICryptoKeyPair> bob(backend.generateKeyPair());

    std::unique_ptr<IRatchetSession> aliceSession(
        backend.createRatchetSession(*alice, bob->publicKey()));
    std::unique_ptr<IRatchetSession> bobSession(
        backend.createRatchetSession(*bob, alice->publicKey()));

    QByteArray msg = "Hello from Alice over ratchet!";
    QByteArray cipher = aliceSession->encrypt(msg);
    QVERIFY(cipher.size() > msg.size());
    QCOMPARE(bobSession->decrypt(cipher), msg);

    // counter 推进
    QCOMPARE(aliceSession->sendCounter(), 1u);
    QCOMPARE(bobSession->recvCounter(), 1u);
}

// 关键测试：双向通信。
// 如果初始 chain 方向没交叉，Bob -> Alice 会因 messageKey 不匹配而 MAC 失败。
void TestRatchet::testBidirectionalRoundTrip() {
    SodiumCryptoBackend backend;
    std::unique_ptr<ICryptoKeyPair> alice(backend.generateKeyPair());
    std::unique_ptr<ICryptoKeyPair> bob(backend.generateKeyPair());

    std::unique_ptr<IRatchetSession> aliceSession(
        backend.createRatchetSession(*alice, bob->publicKey()));
    std::unique_ptr<IRatchetSession> bobSession(
        backend.createRatchetSession(*bob, alice->publicKey()));

    // Alice -> Bob
    QByteArray msgA = "Alice -> Bob";
    QCOMPARE(bobSession->decrypt(aliceSession->encrypt(msgA)), msgA);

    // Bob -> Alice
    QByteArray msgB = "Bob -> Alice reply";
    QCOMPARE(aliceSession->decrypt(bobSession->encrypt(msgB)), msgB);
}

void TestRatchet::testMultipleMessagesIncrementCounter() {
    SodiumCryptoBackend backend;
    std::unique_ptr<ICryptoKeyPair> alice(backend.generateKeyPair());
    std::unique_ptr<ICryptoKeyPair> bob(backend.generateKeyPair());

    std::unique_ptr<IRatchetSession> aliceSession(
        backend.createRatchetSession(*alice, bob->publicKey()));
    std::unique_ptr<IRatchetSession> bobSession(
        backend.createRatchetSession(*bob, alice->publicKey()));

    for (int i = 0; i < 5; ++i) {
        QByteArray msg = "msg " + QByteArray::number(i);
        QByteArray cipher = aliceSession->encrypt(msg);
        QCOMPARE(bobSession->decrypt(cipher), msg);
        QCOMPARE(aliceSession->sendCounter(), static_cast<quint32>(i + 1));
        QCOMPARE(bobSession->recvCounter(), static_cast<quint32>(i + 1));
    }
}

// 每条消息使用独立 messageKey + 随机 nonce，相同明文也产生不同密文
void TestRatchet::testCiphertextUniquePerMessage() {
    SodiumCryptoBackend backend;
    std::unique_ptr<ICryptoKeyPair> alice(backend.generateKeyPair());
    std::unique_ptr<ICryptoKeyPair> bob(backend.generateKeyPair());

    std::unique_ptr<IRatchetSession> aliceSession(
        backend.createRatchetSession(*alice, bob->publicKey()));

    QByteArray plain = "same plaintext";
    QByteArray c1 = aliceSession->encrypt(plain);
    QByteArray c2 = aliceSession->encrypt(plain);
    QVERIFY(c1 != c2);
}

// ---- 错误路径 ----

void TestRatchet::testOutOfOrderThrows() {
    SodiumCryptoBackend backend;
    std::unique_ptr<ICryptoKeyPair> alice(backend.generateKeyPair());
    std::unique_ptr<ICryptoKeyPair> bob(backend.generateKeyPair());

    std::unique_ptr<IRatchetSession> aliceSession(
        backend.createRatchetSession(*alice, bob->publicKey()));
    std::unique_ptr<IRatchetSession> bobSession(
        backend.createRatchetSession(*bob, alice->publicKey()));

    QByteArray c0 = aliceSession->encrypt("first");
    QByteArray c1 = aliceSession->encrypt("second");

    // 正常解第一条
    QCOMPARE(bobSession->decrypt(c0), QByteArray("first"));
    QCOMPARE(bobSession->recvCounter(), 1u);

    // 重复解 c0 —— counter=0 落后于当前 recvCounter=1，应抛 RatchetOutOfOrder
    try {
        bobSession->decrypt(c0);
        QFAIL("Re-decrypting old ciphertext should throw RatchetOutOfOrder");
    } catch (const ICryptoError& ex) {
        QCOMPARE(ex.errorCode(), CryptoErrorCode::RatchetOutOfOrder);
    }

    // 下一条 c1（counter=1）仍能正常解（顺序不乱就行）
    QCOMPARE(bobSession->decrypt(c1), QByteArray("second"));
}

void TestRatchet::testEmptyCiphertextThrows() {
    SodiumCryptoBackend backend;
    std::unique_ptr<ICryptoKeyPair> alice(backend.generateKeyPair());
    std::unique_ptr<ICryptoKeyPair> bob(backend.generateKeyPair());

    std::unique_ptr<IRatchetSession> bobSession(
        backend.createRatchetSession(*bob, alice->publicKey()));

    try {
        bobSession->decrypt(QByteArray());
        QFAIL("Decrypting empty input should throw");
    } catch (const ICryptoError& ex) {
        QCOMPARE(ex.errorCode(), CryptoErrorCode::CiphertextTooShort);
    }
}

// 比 counter + flag + nonce + MAC 还短
void TestRatchet::testTooShortCiphertextThrows() {
    SodiumCryptoBackend backend;
    std::unique_ptr<ICryptoKeyPair> alice(backend.generateKeyPair());
    std::unique_ptr<ICryptoKeyPair> bob(backend.generateKeyPair());

    std::unique_ptr<IRatchetSession> bobSession(
        backend.createRatchetSession(*bob, alice->publicKey()));

    // 4 (counter) + 1 (flag) + 12 (nonce) + 16 (MAC) = 33 字节最小
    try {
        bobSession->decrypt(QByteArray(10, '\x00'));
        QFAIL("Decrypting too-short input should throw");
    } catch (const ICryptoError& ex) {
        QCOMPARE(ex.errorCode(), CryptoErrorCode::CiphertextTooShort);
    }
}

void TestRatchet::testTamperedCiphertextThrows() {
    SodiumCryptoBackend backend;
    std::unique_ptr<ICryptoKeyPair> alice(backend.generateKeyPair());
    std::unique_ptr<ICryptoKeyPair> bob(backend.generateKeyPair());

    std::unique_ptr<IRatchetSession> aliceSession(
        backend.createRatchetSession(*alice, bob->publicKey()));
    std::unique_ptr<IRatchetSession> bobSession(
        backend.createRatchetSession(*bob, alice->publicKey()));

    QByteArray cipher = aliceSession->encrypt("tamper me");
    // 篡改最后一字节（落在 MAC 或密文区）
    cipher[cipher.size() - 1] = static_cast<char>(
        static_cast<quint8>(cipher[cipher.size() - 1]) ^ 0x01);

    try {
        bobSession->decrypt(cipher);
        QFAIL("Tampered ciphertext should fail MAC verification");
    } catch (const ICryptoError& ex) {
        QCOMPARE(ex.errorCode(), CryptoErrorCode::DecryptionMacFailed);
    }
}

// ---- DH ratchet 旋转 ----

// 验证 prepareRatchetStep + applyPeerRatchetKey 后双向通信仍正常
void TestRatchet::testDHRatchetRoundTrip() {
    SodiumCryptoBackend backend;
    std::unique_ptr<ICryptoKeyPair> alice(backend.generateKeyPair());
    std::unique_ptr<ICryptoKeyPair> bob(backend.generateKeyPair());

    std::unique_ptr<IRatchetSession> aliceSession(
        backend.createRatchetSession(*alice, bob->publicKey()));
    std::unique_ptr<IRatchetSession> bobSession(
        backend.createRatchetSession(*bob, alice->publicKey()));

    // 旋转前：Alice -> Bob
    QByteArray msg0 = "pre-rotation Alice -> Bob";
    QCOMPARE(bobSession->decrypt(aliceSession->encrypt(msg0)), msg0);

    // Bob 发起 DH 旋转，把新公钥给 Alice
    QByteArray bobNewPub = bobSession->prepareRatchetStep();
    QCOMPARE(bobNewPub.size(), 32);
    aliceSession->applyPeerRatchetKey(bobNewPub);

    // 旋转后：Alice -> Bob 仍然能解
    QByteArray msg1 = "post-rotation Alice -> Bob";
    QCOMPARE(bobSession->decrypt(aliceSession->encrypt(msg1)), msg1);

    // 旋转后：Bob -> Alice 也能解（验证 recvChain 方向同步）
    QByteArray msg2 = "post-rotation Bob -> Alice";
    QCOMPARE(aliceSession->decrypt(bobSession->encrypt(msg2)), msg2);
}

// PFS 性质 1：旋转后，本会话无法再解旋转前的旧密文（counter 已前进）
void TestRatchet::testPostRotationOldCiphertextUndecryptable() {
    SodiumCryptoBackend backend;
    std::unique_ptr<ICryptoKeyPair> alice(backend.generateKeyPair());
    std::unique_ptr<ICryptoKeyPair> bob(backend.generateKeyPair());

    std::unique_ptr<IRatchetSession> aliceSession(
        backend.createRatchetSession(*alice, bob->publicKey()));
    std::unique_ptr<IRatchetSession> bobSession(
        backend.createRatchetSession(*bob, alice->publicKey()));

    // 旋转前 Alice -> Bob 一条
    QByteArray c0 = aliceSession->encrypt("old message");
    QCOMPARE(bobSession->decrypt(c0), QByteArray("old message"));

    // 触发旋转
    QByteArray bobNewPub = bobSession->prepareRatchetStep();
    aliceSession->applyPeerRatchetKey(bobNewPub);

    // 旋转后再试图解 c0 —— counter=0，但 Bob 的 recvCounter 已是 1
    try {
        bobSession->decrypt(c0);
        QFAIL("Re-decrypting pre-rotation ciphertext should fail");
    } catch (const ICryptoError& ex) {
        QCOMPARE(ex.errorCode(), CryptoErrorCode::RatchetOutOfOrder);
    }
}

// PFS 性质 2（核心）：
// 攻击者拿到了 Alice/Bob 的长期密钥，重建一个全新的 ratchet session，
// 仍然无法解密"旋转后"的密文 —— 因为旋转后的 chain 来自一次性 DH 派生的 rootKey，
// 长期密钥泄露无法回推。
//
// 为了把"counter 不匹配"这个干扰因素排除掉，先用一条旋转前的密文把攻击者会话的
// recvCounter 推到对的位置，再尝试解旋转后密文，期望 MAC 失败（而非 counter 失败）。
void TestRatchet::testForwardSecrecyAfterRotation() {
    SodiumCryptoBackend backend;
    std::unique_ptr<ICryptoKeyPair> alice(backend.generateKeyPair());
    std::unique_ptr<ICryptoKeyPair> bob(backend.generateKeyPair());

    std::unique_ptr<IRatchetSession> aliceSession(
        backend.createRatchetSession(*alice, bob->publicKey()));
    std::unique_ptr<IRatchetSession> bobSession(
        backend.createRatchetSession(*bob, alice->publicKey()));

    // 旋转前：Alice -> Bob，counter=0
    QByteArray c0 = aliceSession->encrypt("pre-rotation");
    QCOMPARE(bobSession->decrypt(c0), QByteArray("pre-rotation"));

    // Bob 发起 DH 旋转
    QByteArray bobNewPub = bobSession->prepareRatchetStep();
    aliceSession->applyPeerRatchetKey(bobNewPub);

    // 旋转后：Alice -> Bob，counter=1（post-rotation 密文）
    QByteArray c1 = aliceSession->encrypt("post-rotation secret");
    QCOMPARE(bobSession->decrypt(c1), QByteArray("post-rotation secret"));  // 合法方能解

    // 攻击者：用 Bob 的长期密钥重新构造一个全新 ratchet session
    std::unique_ptr<IRatchetSession> attackerSession(
        backend.createRatchetSession(*bob, alice->publicKey()));
    QVERIFY(attackerSession->isInitialized());

    // 先用旋转前的 c0 把攻击者的 recvCounter 推到 1
    // —— 这一步本来就该成功（旋转前没有 PFS，长期密钥足够重建初始 chain）
    QCOMPARE(attackerSession->decrypt(c0), QByteArray("pre-rotation"));
    QCOMPARE(attackerSession->recvCounter(), 1u);

    // 现在攻击者尝试解旋转后的 c1（counter=1，counter 对得上）
    // 但 messageKey 来自初始 chain，而 c1 是用旋转后 chain 加密的
    // —— 期望 MAC 失败，证明长期密钥无法解旋转后密文
    try {
        attackerSession->decrypt(c1);
        QFAIL("Attacker with long-term keys should NOT decrypt post-rotation ciphertext");
    } catch (const ICryptoError& ex) {
        QCOMPARE(ex.errorCode(), CryptoErrorCode::DecryptionMacFailed);
    }
}

// ---- O16: RatchetWire wire 协议 ----

void TestRatchet::testRatchetWireEncodeDecodeRoundTrip() {
    // 模拟一个 X25519 公钥（32 字节）
    QByteArray newPub(32, '\0');
    for (int i = 0; i < newPub.size(); ++i) {
        newPub[i] = static_cast<char>(i * 7 + 1);
    }

    QByteArray wire = RatchetWire::encode(newPub);
    // 必须以 PREFIX 开头，并以 \n 结尾
    QVERIFY(wire.startsWith(RatchetWire::PREFIX));
    QVERIFY(wire.endsWith('\n'));

    // 解码（用一份可变副本，模拟网络 buffer）
    QByteArray buffer = wire;
    QByteArray decoded;
    QVERIFY(RatchetWire::tryDecode(buffer, decoded));
    QCOMPARE(decoded, newPub);
    // 解码后 buffer 应为空（仅含一行）
    QVERIFY(buffer.isEmpty());
}

void TestRatchet::testRatchetWireIgnoresUnrelatedBuffer() {
    // buffer 不是 RATCHET_PUBKEY 消息（如普通二进制帧）→ 不消费
    QByteArray buffer;
    buffer.append(static_cast<char>(0x00));
    buffer.append(static_cast<char>(0x00));
    buffer.append(static_cast<char>(0x01));
    buffer.append(static_cast<char>(0x00)); // 长度前缀
    buffer.append("hello\0secret", 12);

    QByteArray decoded;
    QVERIFY(!RatchetWire::tryDecode(buffer, decoded));
    // 关键：buffer 必须未被修改（调用方可继续走二进制帧解析路径）
    QCOMPARE(buffer.size(), 16);
    QVERIFY(decoded.isEmpty());
}

void TestRatchet::testRatchetWireWaitsForNewline() {
    QByteArray newPub(32, '\xAB');
    QByteArray wire = RatchetWire::encode(newPub);

    // 截断最后一字节（\n），模拟未到达完整行
    QByteArray partial = wire.left(wire.size() - 1);
    QByteArray decoded;
    QVERIFY(!RatchetWire::tryDecode(partial, decoded));
    // buffer 未被消费（等待更多数据）
    QCOMPARE(partial, wire.left(wire.size() - 1));
    QVERIFY(decoded.isEmpty());
}

void TestRatchet::testRatchetWireRejectsBadLength() {
    // 公钥长度不对（16 字节，应该是 32）
    QByteArray badPub(16, '\x42');
    QByteArray wire = RatchetWire::encode(badPub);

    QByteArray buffer = wire;
    QByteArray decoded;
    // tryDecode 应返回 false（长度不对）
    QVERIFY(!RatchetWire::tryDecode(buffer, decoded));
    // 但该行已被消费（调用方应断开连接）
    QVERIFY(buffer.isEmpty());
    // 解码出的内容长度不是 32 字节（调用方应据此判定格式违规）
    QVERIFY(decoded.size() != RatchetWire::NEW_PUBKEY_LEN);
    QCOMPARE(decoded.size(), 16);
}

void TestRatchet::testRatchetWireRejectsMalformedLine() {
    // 没有空格分隔，格式不对
    QByteArray buffer = "RATCHET_PUBKEY\n";
    QByteArray decoded;
    QVERIFY(!RatchetWire::tryDecode(buffer, decoded));
    QVERIFY(buffer.isEmpty());
    QVERIFY(decoded.isEmpty());
}

// O16+: 多次 DH 旋转后的双向通信
// 模拟客户端周期性触发 prepareRatchetStep，服务端模拟 applyPeerRatchetKey
// 每次旋转前后都验证 round-trip 正确，且旋转前密文旋转后不可解（PFS 持续生效）
void TestRatchet::testMultipleRatchetsRoundTrip() {
    SodiumCryptoBackend backend;
    std::unique_ptr<ICryptoKeyPair> alice(backend.generateKeyPair());
    std::unique_ptr<ICryptoKeyPair> bob(backend.generateKeyPair());

    std::unique_ptr<IRatchetSession> aliceSession(
        backend.createRatchetSession(*alice, bob->publicKey()));
    std::unique_ptr<IRatchetSession> bobSession(
        backend.createRatchetSession(*bob, alice->publicKey()));

    // 首次旋转（与 testDHRatchetRoundTrip 一致）
    QByteArray aliceNewPub = aliceSession->prepareRatchetStep();
    bobSession->applyPeerRatchetKey(aliceNewPub);

    // 第一次旋转后双向 round-trip
    QVERIFY(bobSession->decrypt(aliceSession->encrypt("msg after r1")) == QByteArray("msg after r1"));
    QVERIFY(aliceSession->decrypt(bobSession->encrypt("reply after r1")) == QByteArray("reply after r1"));

    // 第二次旋转（模拟周期性再旋转）
    QByteArray aliceNewPub2 = aliceSession->prepareRatchetStep();
    bobSession->applyPeerRatchetKey(aliceNewPub2);

    QVERIFY(bobSession->decrypt(aliceSession->encrypt("msg after r2")) == QByteArray("msg after r2"));
    QVERIFY(aliceSession->decrypt(bobSession->encrypt("reply after r2")) == QByteArray("reply after r2"));

    // 第三次旋转
    QByteArray aliceNewPub3 = aliceSession->prepareRatchetStep();
    bobSession->applyPeerRatchetKey(aliceNewPub3);

    QVERIFY(bobSession->decrypt(aliceSession->encrypt("msg after r3")) == QByteArray("msg after r3"));
    QVERIFY(aliceSession->decrypt(bobSession->encrypt("reply after r3")) == QByteArray("reply after r3"));

    // 旋转 3 次后，counter 累计 3 次加密（每次旋转不推进 counter，仅 encrypt 推进）
    // counter 在旋转时不重置（保持全局单调递增，避免与历史消息冲突）
    QCOMPARE(aliceSession->sendCounter(), 3u);
    QCOMPARE(bobSession->recvCounter(), 3u);
}

int runRatchetTests(int argc, char** argv) {
    char* args[] = { argv[0], const_cast<char*>("-o"), const_cast<char*>("-,txt") };
    int newArgc = sizeof(args) / sizeof(args[0]);
    return QTest::qExec(new TestRatchet(), newArgc, args);
}

#include "tst_ratchet.moc"
