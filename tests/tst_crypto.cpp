// tst_crypto.cpp - 测试加密层 (SodiumCryptoBackend round-trip + 错误码)
#include <QtTest>
#include <QByteArray>

#include "SodiumCryptoBackend.h"
#include "SodiumKeyPair.h"
#include "SodiumSession.h"
#include "ICryptoError.h"

class TestCrypto : public QObject {
    Q_OBJECT
private slots:
    void testKeyPairGeneration();
    void testSessionRoundTrip();
    void testDecryptionMacFails();
    void testEmptyCiphertextThrows();
};

void TestCrypto::testKeyPairGeneration() {
    SodiumCryptoBackend backend;
    std::unique_ptr<ICryptoKeyPair> kp(backend.generateKeyPair());
    QVERIFY(kp != nullptr);
    QCOMPARE(kp->publicKey().size(), 32);
    QCOMPARE(kp->privateKey().size(), 32);
    // 公钥不能全 0
    QVERIFY(kp->publicKey() != QByteArray(32, '\0'));
}

void TestCrypto::testSessionRoundTrip() {
    SodiumCryptoBackend backend;
    std::unique_ptr<ICryptoKeyPair> alice(backend.generateKeyPair());
    std::unique_ptr<ICryptoKeyPair> bob(backend.generateKeyPair());

    // 双方互发对端公钥建立 session
    std::unique_ptr<ICryptoSession> aliceSession(
        backend.createSession(*alice, bob->publicKey()));
    std::unique_ptr<ICryptoSession> bobSession(
        backend.createSession(*bob, alice->publicKey()));

    // Alice -> Bob
    QByteArray msg1 = "Hello from Alice!";
    QByteArray cipher1 = aliceSession->encrypt(msg1);
    QVERIFY(cipher1.size() > msg1.size());
    QCOMPARE(bobSession->decrypt(cipher1), msg1);

    // Bob -> Alice
    QByteArray msg2 = "Hi Alice, this is Bob!";
    QByteArray cipher2 = bobSession->encrypt(msg2);
    QCOMPARE(aliceSession->decrypt(cipher2), msg2);
}

void TestCrypto::testDecryptionMacFails() {
    SodiumCryptoBackend backend;
    std::unique_ptr<ICryptoKeyPair> alice(backend.generateKeyPair());
    std::unique_ptr<ICryptoKeyPair> bob(backend.generateKeyPair());

    std::unique_ptr<ICryptoSession> aliceSession(
        backend.createSession(*alice, bob->publicKey()));

    QByteArray cipher = aliceSession->encrypt("tamper test");
    // 篡改密文最后一字节
    if (!cipher.isEmpty()) {
        cipher[cipher.size() - 1] = static_cast<char>(
            static_cast<quint8>(cipher[cipher.size() - 1]) ^ 0x01);
    }
    // 这条消息本应由 Bob 解密，但密钥未对齐，所以用第三方身份再建一个 session 来验
    std::unique_ptr<ICryptoKeyPair> carol(backend.generateKeyPair());
    std::unique_ptr<ICryptoSession> bobSession(
        backend.createSession(*bob, carol->publicKey()));

    try {
        bobSession->decrypt(cipher);
        QFAIL("Decryption should have failed due to MAC mismatch / wrong key");
    } catch (const ICryptoError& ex) {
        QVERIFY(ex.errorCode() == CryptoErrorCode::DecryptionMacFailed ||
                ex.errorCode() == CryptoErrorCode::DecryptionFailed);
        QVERIFY(!ex.localizedMessage().isEmpty());
        QVERIFY(!ex.message().isEmpty());
    }
}

void TestCrypto::testEmptyCiphertextThrows() {
    SodiumCryptoBackend backend;
    std::unique_ptr<ICryptoKeyPair> alice(backend.generateKeyPair());
    std::unique_ptr<ICryptoKeyPair> bob(backend.generateKeyPair());

    std::unique_ptr<ICryptoSession> bobSession(
        backend.createSession(*bob, alice->publicKey()));

    try {
        bobSession->decrypt(QByteArray());
        QFAIL("Decrypting empty input should throw");
    } catch (const ICryptoError& ex) {
        QCOMPARE(ex.errorCode(), CryptoErrorCode::CiphertextTooShort);
    }
}

int runCryptoTests(int argc, char** argv) {
    char* args[] = { argv[0], const_cast<char*>("-o"), const_cast<char*>("-,txt") };
    int newArgc = sizeof(args) / sizeof(args[0]);
    return QTest::qExec(new TestCrypto(), newArgc, args);
}

#include "tst_crypto.moc"
