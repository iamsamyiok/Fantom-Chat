# F8: 加密层独立构建 —— 把 src/encrypting 抽成可独立构建/复用的静态库
#
# 目标：
#   - 与 Qt UI 解耦，便于单元测试与复用
#   - 与 O7（多 backend）协同：后续可在此处聚合 OpenSSL/Botan 后端
#   - 与 O8（协议层解耦）协同：网络层只依赖此 lib 的接口，不依赖具体 backend
#
# 依赖：
#   - Qt6::Core (QByteArray / QMutex / QCryptographicHash / QString)
#   - libsodium (X25519 / ChaCha20-Poly1305 / HMAC-SHA256 / crypto_kx)
#
# 独立构建：
#   cmake -S src/encrypting -B build/crypto -DCMAKE_BUILD_TYPE=Release
#   cmake --build build/crypto -j
#
# 作为子目录（未来顶层 CMakeLists.txt）：
#   add_subdirectory(src/encrypting)
#   target_link_libraries(my_target PRIVATE fantomcrypto)
#
# 该层不依赖 utils/、network/、protocol/、ui/ —— 依赖边界已验证。
cmake_minimum_required(VERSION 3.16)
project(fantomcrypto LANGUAGES CXX VERSION 1.0.0 DESCRIPTION "Fantom-Chat crypto layer (libsodium backend + Double Ratchet)")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---- Qt6 ----
find_package(Qt6 6.2 QUIET COMPONENTS Core)
if(NOT Qt6_FOUND)
    message(FATAL_ERROR "Qt6::Core not found. Install qt6-base-dev (Linux) / qt@6 (macOS) / mingw-w64-ucrt-x86_64-qt6-base (MSYS2).")
endif()

# ---- libsodium ----
# 优先 pkg-config（Linux/macOS Homebrew/MSYS2 都带 .pc），否则回退 find_library
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(SODIUM IMPORTED_TARGET libsodium)
endif()
if(NOT SODIUM_FOUND)
    find_path(SODIUM_INCLUDE_DIR sodium.h)
    find_library(SODIUM_LIBRARY NAMES sodium)
    if(SODIUM_INCLUDE_DIR AND SODIUM_LIBRARY)
        set(SODIUM_FOUND TRUE)
        add_library(SODIUM::sodium UNKNOWN IMPORTED)
        set_target_properties(SODIUM::sodium PROPERTIES
            IMPORTED_LOCATION "${SODIUM_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}")
    endif()
endif()
if(NOT SODIUM_FOUND)
    message(FATAL_ERROR "libsodium not found. Install libsodium-dev (Linux) / libsodium (macOS) / mingw-w64-ucrt-x86_64-libsodium (MSYS2).")
endif()

# ---- 源文件 ----
set(FANTOM_CRYPTO_SOURCES
    sodium/backends/SodiumCryptoBackend.cpp
    sodium/key_pairs/SodiumKeyPair.cpp
    sodium/sessions/SodiumSession.cpp
    sodium/sessions/SodiumRatchetSession.cpp
)

set(FANTOM_CRYPTO_HEADERS
    interfaces/ICryptoBackend.h
    interfaces/ICryptoError.h
    interfaces/ICryptoKeyPair.h
    interfaces/ICryptoSession.h
    interfaces/IRatchetSession.h
    interfaces/CryptoErrorCode.h
    sodium/backends/SodiumCryptoBackend.h
    sodium/key_pairs/SodiumKeyPair.h
    sodium/sessions/SodiumSession.h
    sodium/sessions/SodiumRatchetSession.h
    sodium/errors/SodiumCryptoError.h
)

# ---- 静态库 ----
add_library(fantomcrypto STATIC ${FANTOM_CRYPTO_SOURCES} ${FANTOM_CRYPTO_HEADERS})
add_library(Fantom::Crypto ALIAS fantomcrypto)

target_include_directories(fantomcrypto
    PUBLIC
        # 用 BUILD_INTERFACE 包裹源树路径：构建期可见，不泄露到 install 后的
        # INTERFACE_INCLUDE_DIRECTORIES（避免出现宿主绝对路径）
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/interfaces>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/sodium/backends>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/sodium/key_pairs>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/sodium/sessions>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/sodium/errors>
        # install 后消费者从 ${includedir}/fantomcrypto 取头文件
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/fantomcrypto>
)

target_link_libraries(fantomcrypto
    PUBLIC
        Qt6::Core
)

if(TARGET PkgConfig::SODIUM)
    target_link_libraries(fantomcrypto PUBLIC PkgConfig::SODIUM)
else()
    target_link_libraries(fantomcrypto PUBLIC SODIUM::sodium)
endif()

# Windows 静态链接 libsodium 时需要 ws2_32/iphlapi（sodium 的 randombytes 系统源）
if(WIN32)
    target_link_libraries(fantomcrypto PUBLIC ws2_32 iphlapi)
endif()

# 警告级别
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(fantomcrypto PRIVATE -Wall -Wextra)
endif()

# ---- 安装规则（可选，便于作为系统库消费）----
include(GNUInstallDirs)
install(TARGETS fantomcrypto
    EXPORT FantomCryptoTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY interfaces/ sodium/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/fantomcrypto
    FILES_MATCHING PATTERN "*.h")

install(EXPORT FantomCryptoTargets
    FILE FantomCryptoTargets.cmake
    NAMESPACE Fantom::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/FantomCrypto)

# 生成版本化 config 文件，便于 find_package(FantomCrypto)
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/FantomCryptoConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/FantomCryptoConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/FantomCryptoConfig.cmake"
    @ONLY)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/FantomCryptoConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/FantomCryptoConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/FantomCrypto)
