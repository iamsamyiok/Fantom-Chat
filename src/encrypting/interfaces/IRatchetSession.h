#ifndef IRATCHETSESSION_H
#define IRATCHETSESSION_H

#include "ICryptoSession.h"
#include <QByteArray>

// O16: 轻量 Double Ratchet 接口
//
// 在 ICryptoSession 之上扩展，提供：
// 1. 每条消息使用 KDF chain 派生独立 message key（message-key ratchet）
// 2. 调用方驱动的 DH rotation（DH ratchet）—— 替换 rootKey，丢弃旧值
//    实现"前向保密"：长期密钥泄露后无法解密 ratchet 前的历史消息
//
// 轻量版与完整 Signal Double Ratchet 的区别：
// - 不实现 message keys 的延迟缓存（仅保留当前 message key，前一条立即丢弃）
//   —— 不支持 out-of-order 容忍，要求消息严格按序到达
// - 不实现 skipped message keys 缓存
// - DH rotation 由调用方（上层协议）驱动
//
// 协议层集成约定（上层 server/client 在调用方实现）：
// - 每条消息的密文前缀 4 字节大端 counter（由 encrypt 自动写入）
// - DH rotation 时，调用方先调用 prepareRatchetStep() 拿到本端新公钥，
//   通过协议消息发给对端；对端收到后调用 applyPeerRatchetKey(pub)
//   触发双方同步推进 rootKey
class IRatchetSession : public ICryptoSession {
public:
    // 触发一次 DH rotation
    // 返回本端新公钥，调用方需要把它通过协议消息发给对端
    // 调用后本端 rootKey 已被替换，旧 rootKey 被丢弃（实现 PFS）
    virtual QByteArray prepareRatchetStep() = 0;

    // 接收对端发来的新公钥，触发本地 DH rotation
    // 调用后本端 rootKey 已被替换
    virtual void applyPeerRatchetKey(const QByteArray& peerNewPublicKey) = 0;

    // 当前 ratchet 状态是否已初始化（可以加解密）
    virtual bool isInitialized() const = 0;

    // 当前发送 / 接收 counter（用于调试与上层日志）
    virtual quint32 sendCounter() const = 0;
    virtual quint32 recvCounter() const = 0;
};

#endif // IRATCHETSESSION_H
