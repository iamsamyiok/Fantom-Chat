QT += core widgets network sql

TARGET = FantomChat
TEMPLATE = app

CONFIG += c++20

SOURCES += \
    src/encrypting/sodium/backends/SodiumCryptoBackend.cpp \
    src/encrypting/sodium/key_pairs/SodiumKeyPair.cpp \
    src/encrypting/sodium/sessions/SodiumSession.cpp \
    src/encrypting/sodium/sessions/SodiumRatchetSession.cpp \
    src/models/ContactListModel.cpp \
    src/network/IPv6ChatClient.cpp \
    src/network/IPv6ChatServer.cpp \
    src/network/PeerDiscovery.cpp \
    src/models/MessageListModel.cpp \
    src/ui/contacts/delegates/ContactsDelegate.cpp \
    src/utils/ClockSync.cpp \
    src/storage/MessageStore.cpp \
    src/utils/Requests.cpp \
    src/utils/FirewallHelper.cpp \
    src/utils/KeyExchange.cpp \
    src/utils/SafetyNumber.cpp \
    src/protocol/Frame.cpp \
    src/protocol/FrameReader.cpp \
    src/protocol/HandshakeCodec.cpp \
    main.cpp \
    src/ui/main_window/mainwindow.cpp \
    src/ui/chat/delegates/ChatMessageDelegate.cpp \
    src/ui/contacts/delegates/ContactsDelegate.cpp
HEADERS += \
    src/encrypting/interfaces/CryptoErrorCode.h \
    src/encrypting/interfaces/ICryptoError.h \
    src/encrypting/interfaces/IRatchetSession.h \
    src/encrypting/sodium/backends/SodiumCryptoBackend.h \
    src/encrypting/interfaces/ICryptoBackend.h \
    src/encrypting/interfaces/ICryptoKeyPair.h \
    src/encrypting/interfaces/ICryptoSession.h \
    src/encrypting/sodium/errors/SodiumCryptoError.h \
    src/encrypting/sodium/key_pairs/SodiumKeyPair.h \
    src/encrypting/sodium/sessions/SodiumSession.h \
    src/encrypting/sodium/sessions/SodiumRatchetSession.h \
    src/models/ContactListModel.h \
    src/network/IPv6ChatClient.h \
    src/network/IPv6ChatServer.h \
    src/network/PeerDiscovery.h \
    src/models/MessageListModel.h \
    src/storage/MessageStore.h \
    src/utils/ClockSync.h \
    src/utils/FirewallHelper.h \
    src/utils/KeyExchange.h \
    src/utils/SafetyNumber.h \
    src/protocol/Frame.h \
    src/protocol/FrameReader.h \
    src/protocol/HandshakeCodec.h \
    src/utils/MessageType.h \
    src/utils/ProtocolUtils.h \
    src/utils/ProtocolVersion.h \
    src/utils/Requests.h \
    src/utils/Structures.h \
    src/ui/main_window/mainwindow.h

FORMS += \
    assets/templates/mainwindow.ui

TRANSLATIONS = \
    translations/en.ts \
    translations/ru.ts \
    translations/zh.ts

win32 {
    OPENSSL_ROOT = C:/msys64/ucrt64
    ZLIB_ROOT = C:/msys64/ucrt64
    CURL_ROOT = C:/msys64/ucrt64
    SODIUM_ROOT = C:/msys64/ucrt64

    # Connect OpenSSL
    INCLUDEPATH += $$OPENSSL_ROOT/include
    LIBS += -L$$OPENSSL_ROOT/lib -lssl -lcrypto
    # Connect CURL
    INCLUDEPATH += $$CURL_ROOT/include
    LIBS += -L$$CURL_ROOT/lib -lcurl -lws2_32 -lwsock32 -lcrypt32
    # set needed DLLs
    # 注意: 不在 QMAKE_POST_LINK 中调用 copy_dlls.bat
    # 原因: mingw32-make 在 msys2 环境下用 /usr/bin/sh (bash) 执行 QMAKE_POST_LINK,
    # 而 copy_dlls.bat 是 Windows .bat 文件, 必须通过 cmd /c 调用.
    # 但 cmd /c 在 cmd.exe 与 bash 下的引号/路径转义规则不同, 无法用同一语法兼容两者.
    # 解决方案:
    #   - CI: Build 步骤在 mingw32-make 之后显式调用 cmd //c copy_dlls.bat (已配置)
    #   - 本地开发: 构建完成后手动运行 win32/copy_dlls.bat <build_dir>
    #   - CI Package 步骤还有直接从 MSYS2 bin/ 复制 DLL 的兜底逻辑

    # Connect Zlib
    INCLUDEPATH += $$ZLIB_ROOT/include
    # 用 -lz 让链接器自动选择 libz.a (static) 或 libz.dll.a (import)
    # 避免硬编码静态库路径在不同 MSYS2 版本下找不到文件
    LIBS += -L$$ZLIB_ROOT/lib -lz

    # Connect libsodium
    INCLUDEPATH += $$SODIUM_ROOT/include
    LIBS += -L$$SODIUM_ROOT/lib -lsodium
}

macx {
    SODIUM_ROOT = /opt/homebrew/opt/libsodium
    ZLIB_ROOT = /opt/homebrew/opt/zlib
    CONFIG += app_bundle
    LIBS += -lcurl
    # Connect Zlib
    INCLUDEPATH += $$ZLIB_ROOT/include
    # 用 -lz 让链接器自动选择 libz.a (static) 或 libz.dylib (dynamic)
    LIBS += -L$$ZLIB_ROOT/lib -lz

    # Connect libsodium
    INCLUDEPATH += $$SODIUM_ROOT/include
    LIBS += -L$$SODIUM_ROOT/lib -lsodium
}

unix:!macx {
    LIBS += -lcurl -lsodium -lz
}

# Set path for installation
target.path = $$[QT_INSTALL_BINS]
INSTALLS += target

CONFIG+=fontAwesomeFree
include(dependencies/QtAwesome/QtAwesome.pri)

DISTFILES += \
    .gitignore \
    LICENSE.md \
    README.md \
    TESTING_NOTES.md \
    assets/styles/general.qss \
    copy_dlls.bat \
    assets/images/app_icon.rc \
    assets/styles/mainwindow.qss \
    third_party_licenses/FontAwesome-LICENSE.md \
    third_party_licenses/Qt-LICENSE.md

RESOURCES += \
    resources.qrc

# Icon
RC_FILE = assets/images/app_icon.rc

