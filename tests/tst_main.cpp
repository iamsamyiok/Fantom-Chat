// tst_main.cpp - 测试主入口
// 多个 Test 类放在不同文件中，每个 Test 类有 Q_OBJECT，因此需要 moc
// 这里用 #include "tst_xxx.moc" 在 main 中链接 moc 生成代码
//
// 简化方案：把所有 test class 定义放在头文件里，main 文件 include 之
// 但 Qt 的 Q_OBJECT + 多文件比较麻烦，所以采用经典的"每个 .cpp 顶部 #include 该 cpp 的 moc"

#include <QTest>
#include <QCoreApplication>

// 各测试类前向声明
class TestProtocol;
class TestCrypto;
class TestKeyExchange;
class TestSafetyNumber;
class TestRatchet;

// 在每个 tst_*.cpp 中各自定义 test class，并通过 QTEST_MAIN_EXPORT 宏导出 run 函数
// 这里使用简化的 "extern run function" 风格

extern int runProtocolTests(int argc, char** argv);
extern int runCryptoTests(int argc, char** argv);
extern int runKeyExchangeTests(int argc, char** argv);
extern int runSafetyNumberTests(int argc, char** argv);
extern int runRatchetTests(int argc, char** argv);

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);

    int failures = 0;
    failures += runProtocolTests(argc, argv);
    failures += runCryptoTests(argc, argv);
    failures += runKeyExchangeTests(argc, argv);
    failures += runSafetyNumberTests(argc, argv);
    failures += runRatchetTests(argc, argv);

    if (failures == 0) {
        qDebug("\n========== All tests passed ==========");
    } else {
        qDebug("\n========== %d test(s) failed ==========", failures);
    }
    return failures == 0 ? 0 : 1;
}
