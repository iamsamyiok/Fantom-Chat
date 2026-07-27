#ifndef PROTOCOLVERSION_H
#define PROTOCOLVERSION_H

#include <QtGlobal>
#include <QString>

// O4: 协议版本管理
// 版本号编码：高 16 位 = major，中 8 位 = minor，低 8 位 = patch
// 例如：v1.0.0 = 0x010000, v1.1.0 = 0x010100, v1.2.0 = 0x010200, v2.0.0 = 0x020000
namespace ProtoVer {

// 当前协议版本
constexpr quint32 CURRENT  = 0x010200; // v1.2.0（本次升级后）
constexpr quint32 MIN_COMPAT = 0x010000; // 仍兼容 v1.0.0（O3 之前）

// O16: Ratchet (前向保密) 特性引入的协议版本
// 双方协议版本都 >= 此值时，握手后改用 IRatchetSession 进行通信
constexpr quint32 RATCHET_FEATURE_VERSION = 0x010200;

// 将版本号格式化为字符串（"1.2.0"）
inline QString toString(quint32 v) {
    int major = (v >> 16) & 0xFF;
    int minor = (v >> 8) & 0xFF;
    int patch = v & 0xFF;
    return QString("%1.%2.%3").arg(major).arg(minor).arg(patch);
}

// 判定本端能否与远端通信
// 兼容规则：major 必须相同；本端 MIN_COMPAT <= 远端 <= 本端 CURRENT
// 也要求远端声明它兼容本端的版本
inline bool isCompatibleWith(quint32 remoteCurrent, quint32 remoteMinCompat) {
    int myMajor    = (CURRENT >> 16) & 0xFF;
    int remoteMajor = (remoteCurrent >> 16) & 0xFF;
    if (myMajor != remoteMajor) return false;
    // 我能接受远端的最低版本必须 <= 远端实际版本
    if (MIN_COMPAT > remoteCurrent) return false;
    // 远端能接受的最低版本必须 <= 我实际版本
    if (remoteMinCompat > CURRENT) return false;
    return true;
}

// O16: 判定远端是否支持 Ratchet (前向保密) 特性
// 双方都 >= RATCHET_FEATURE_VERSION 才算支持
inline bool supportsRatchet(quint32 remoteCurrent) {
    return (CURRENT >= RATCHET_FEATURE_VERSION) && (remoteCurrent >= RATCHET_FEATURE_VERSION);
}

} // namespace ProtoVer

#endif // PROTOCOLVERSION_H
