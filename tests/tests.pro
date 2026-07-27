# tests/tests.pro
# O6: 单元测试 - Qt Test 框架
# 单一可执行文件 FantomChatTests，内部按模块组织
#
# 构建：
#   cd tests && qmake6 tests.pro && make
# 运行：
#   ./FantomChatTests

QT += testlib core network
QT -= gui

TARGET = FantomChatTests
TEMPLATE = app
CONFIG += c++20 console testcase
CONFIG -= app_bundle

include(tests.pri)

SOURCES += \
    tst_main.cpp \
    tst_protocol.cpp \
    tst_crypto.cpp \
    tst_keyexchange.cpp \
    tst_safetynumber.cpp \
    tst_ratchet.cpp
