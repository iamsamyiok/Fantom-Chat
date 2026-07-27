// tst_keyexchange.cpp - 测试 KeyExchange (F5 base64 编码层)
#include <QtTest>
#include <QByteArray>
#include <QString>

#include "KeyExchange.h"

class TestKeyExchange : public QObject {
    Q_OBJECT
private slots:
    void testExportImportRoundTrip();
    void testImportFromPlainBase64();
    void testImportInvalidReturnsEmpty();
    void testImportStripsComments();
    void testFingerprintFormat();
    void testFingerprintStable();
};

void TestKeyExchange::testExportImportRoundTrip() {
    QByteArray pubKey(32, '\x33');
    QString exported = KeyExchange::exportPublicKey(pubKey);
    QVERIFY(exported.startsWith("FANTOM-PUBKEY-V1:"));

    QByteArray imported = KeyExchange::importPublicKey(exported);
    QCOMPARE(imported, pubKey);
}

void TestKeyExchange::testImportFromPlainBase64() {
    QByteArray pubKey(32, '\x55');
    QString b64 = QString::fromUtf8(pubKey.toBase64());
    QByteArray imported = KeyExchange::importPublicKey(b64);
    QCOMPARE(imported, pubKey);
}

void TestKeyExchange::testImportInvalidReturnsEmpty() {
    // 长度不对
    QCOMPARE(KeyExchange::importPublicKey("not a key"), QByteArray());
    QCOMPARE(KeyExchange::importPublicKey(""), QByteArray());
    // 正确 base64 但长度不对
    QByteArray tooShort(10, '\x01');
    QString exported = QString::fromUtf8(tooShort.toBase64());
    QCOMPARE(KeyExchange::importPublicKey(exported), QByteArray());
}

void TestKeyExchange::testImportStripsComments() {
    QByteArray pubKey(32, '\x77');
    QString b64 = QString::fromUtf8(pubKey.toBase64());
    // 在前后加注释与换行
    QString text = "# This is a Fantom public key\n"
                   "// share with peer out-of-band\n"
                   + b64 + "\n";
    QCOMPARE(KeyExchange::importPublicKey(text), pubKey);
}

void TestKeyExchange::testFingerprintFormat() {
    QByteArray pubKey(32, '\x42');
    QString fp = KeyExchange::computeFingerprint(pubKey);
    // 默认 16 字节 -> 32 hex 字符，按 4 字符分组，共 8 组
    QStringList groups = fp.split(' ');
    QCOMPARE(groups.size(), 8);
    for (const QString& g : groups) {
        QCOMPARE(g.length(), 4);
        // 全大写 hex
        for (const QChar& ch : g) {
            QVERIFY(ch.isUpper() || ch.isDigit());
        }
    }
}

void TestKeyExchange::testFingerprintStable() {
    QByteArray pubKey(32, '\x42');
    QString fp1 = KeyExchange::computeFingerprint(pubKey);
    QString fp2 = KeyExchange::computeFingerprint(pubKey);
    QCOMPARE(fp1, fp2);

    // 不同公钥应产生不同指纹
    QByteArray pubKey2(32, '\x43');
    QString fp3 = KeyExchange::computeFingerprint(pubKey2);
    QVERIFY(fp1 != fp3);
}

int runKeyExchangeTests(int argc, char** argv) {
    char* args[] = { argv[0], const_cast<char*>("-o"), const_cast<char*>("-,txt") };
    int newArgc = sizeof(args) / sizeof(args[0]);
    return QTest::qExec(new TestKeyExchange(), newArgc, args);
}

#include "tst_keyexchange.moc"
