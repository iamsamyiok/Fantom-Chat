// tst_safetynumber.cpp - 测试 SafetyNumber (O17 身份验证机制)
#include <QtTest>
#include <QByteArray>
#include <QString>
#include <QStringList>

#include "SafetyNumber.h"

class TestSafetyNumber : public QObject {
    Q_OBJECT
private slots:
    void testEmptyKeysReturnEmpty();
    void testStableForSameKeys();
    void testCommutativeBetweenTwoParties();
    void testDifferentKeysGiveDifferentSN();
    void testFormatShape();
    void testIsValidFormat();
    void testNormalize();
    void testEquals();
};

void TestSafetyNumber::testEmptyKeysReturnEmpty() {
    QVERIFY(SafetyNumber::compute(QByteArray(), QByteArray(32, 'a')).isEmpty());
    QVERIFY(SafetyNumber::compute(QByteArray(32, 'a'), QByteArray()).isEmpty());
}

void TestSafetyNumber::testStableForSameKeys() {
    QByteArray local(32, '\x11');
    QByteArray remote(32, '\x22');
    QString sn1 = SafetyNumber::compute(local, remote);
    QString sn2 = SafetyNumber::compute(local, remote);
    QCOMPARE(sn1, sn2);
}

// 双向稳定性：A 算 B 与 B 算 A 结果相同
void TestSafetyNumber::testCommutativeBetweenTwoParties() {
    QByteArray pubA(32, '\x33');
    QByteArray pubB(32, '\x44');
    QString snFromA = SafetyNumber::compute(pubA, pubB);
    QString snFromB = SafetyNumber::compute(pubB, pubA);
    QCOMPARE(snFromA, snFromB);
}

void TestSafetyNumber::testDifferentKeysGiveDifferentSN() {
    QByteArray local(32, '\x11');
    QByteArray remote1(32, '\x22');
    QByteArray remote2(32, '\x33');
    QString sn1 = SafetyNumber::compute(local, remote1);
    QString sn2 = SafetyNumber::compute(local, remote2);
    QVERIFY(sn1 != sn2);
}

// 格式：12 组 5 位十进制，空格分隔
void TestSafetyNumber::testFormatShape() {
    QString sn = SafetyNumber::compute(QByteArray(32, '\x11'), QByteArray(32, '\x22'));
    QStringList groups = sn.split(' ');
    QCOMPARE(groups.size(), 12);
    for (const QString& g : groups) {
        QCOMPARE(g.length(), 5);
        for (const QChar& ch : g) {
            QVERIFY(ch.isDigit());
        }
    }
}

void TestSafetyNumber::testIsValidFormat() {
    QString valid = "12345 67890 13579 24680 11111 22222 33333 44444 55555 66666 77777 88888";
    QVERIFY(SafetyNumber::isValidFormat(valid));

    // 缺一组
    QVERIFY(!SafetyNumber::isValidFormat("12345 67890"));
    // 含非数字
    QVERIFY(!SafetyNumber::isValidFormat("12x45 67890 13579 24680 11111 22222 33333 44444 55555 66666 77777 88888"));
    // 空串
    QVERIFY(!SafetyNumber::isValidFormat(""));
}

void TestSafetyNumber::testNormalize() {
    // 用户漏了空格（60 位连续数字）—— a 去掉所有空格
    QString spaced = "12345 67890 13579 24680 11111 22222 33333 44444 55555 66666 77777 88888";
    QString compact = spaced;
    compact.remove(' ');
    QString norm = SafetyNumber::normalize(compact);
    QVERIFY(SafetyNumber::isValidFormat(norm));

    // 用户多了空格
    QString input2 = "12345    67890  13579  24680  11111  22222  33333  44444  55555  66666  77777  88888";
    QString norm2 = SafetyNumber::normalize(input2);
    QVERIFY(SafetyNumber::isValidFormat(norm2));
}

void TestSafetyNumber::testEquals() {
    QString a = "12345 67890 13579 24680 11111 22222 33333 44444 55555 66666 77777 88888";
    QString b = "12345  67890  13579  24680  11111  22222  33333  44444  55555  66666  77777  88888";
    QVERIFY(SafetyNumber::equals(a, b));

    // 无空格分隔（紧凑形式 = a 去掉空格）
    QString c = a;
    c.remove(' ');
    QVERIFY(SafetyNumber::equals(a, c));

    // 真不一致
    QString d = "99999 67890 13579 24680 11111 22222 33333 44444 55555 66666 77777 88888";
    QVERIFY(!SafetyNumber::equals(a, d));
}

int runSafetyNumberTests(int argc, char** argv) {
    char* args[] = { argv[0], const_cast<char*>("-o"), const_cast<char*>("-,txt") };
    int newArgc = sizeof(args) / sizeof(args[0]);
    return QTest::qExec(new TestSafetyNumber(), newArgc, args);
}

#include "tst_safetynumber.moc"
