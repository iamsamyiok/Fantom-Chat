# tests/tests.pri - 共享的测试构建配置
# 由 tests.pro include，统一引用 fantom-chat 源码

FANTOM_ROOT = $$PWD/..

# 包含 fantom-chat 源码目录
INCLUDEPATH += \
    $$FANTOM_ROOT \
    $$FANTOM_ROOT/src/encrypting/interfaces \
    $$FANTOM_ROOT/src/encrypting/sodium/backends \
    $$FANTOM_ROOT/src/encrypting/sodium/key_pairs \
    $$FANTOM_ROOT/src/encrypting/sodium/sessions \
    $$FANTOM_ROOT/src/encrypting/sodium/errors \
    $$FANTOM_ROOT/src/utils \
    $$FANTOM_ROOT/src/network \
    $$FANTOM_ROOT/src/storage \
    $$FANTOM_ROOT/src/protocol \
    $$FANTOM_ROOT/src/models

# 引用 fantom-chat 的关键源文件（仅可移植部分，不引入 Qt UI 代码）
SOURCES += \
    $$FANTOM_ROOT/src/encrypting/sodium/backends/SodiumCryptoBackend.cpp \
    $$FANTOM_ROOT/src/encrypting/sodium/key_pairs/SodiumKeyPair.cpp \
    $$FANTOM_ROOT/src/encrypting/sodium/sessions/SodiumSession.cpp \
    $$FANTOM_ROOT/src/encrypting/sodium/sessions/SodiumRatchetSession.cpp \
    $$FANTOM_ROOT/src/utils/ClockSync.cpp \
    $$FANTOM_ROOT/src/utils/KeyExchange.cpp \
    $$FANTOM_ROOT/src/utils/SafetyNumber.cpp \
    $$FANTOM_ROOT/src/protocol/Frame.cpp \
    $$FANTOM_ROOT/src/protocol/FrameReader.cpp \
    $$FANTOM_ROOT/src/protocol/HandshakeCodec.cpp

# 依赖
unix:!macx {
    LIBS += -lsodium -lz
}
macx {
    SODIUM_ROOT = /opt/homebrew/opt/libsodium
    INCLUDEPATH += $$SODIUM_ROOT/include
    LIBS += -L$$SODIUM_ROOT/lib -lsodium
}
win32 {
    SODIUM_ROOT = C:/msys64/ucrt64
    INCLUDEPATH += $$SODIUM_ROOT/include
    LIBS += -L$$SODIUM_ROOT/lib -lsodium
}
