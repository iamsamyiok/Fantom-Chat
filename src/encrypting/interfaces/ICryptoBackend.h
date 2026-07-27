#ifndef ICRYPTOBACKEND_H
#define ICRYPTOBACKEND_H

#include "ICryptoKeyPair.h"
#include "ICryptoSession.h"

// O16: 前向声明，避免循环 include
class IRatchetSession;

class ICryptoBackend {
public:
    virtual ICryptoKeyPair* generateKeyPair() = 0;
    virtual ICryptoSession* createSession(
        const ICryptoKeyPair& selfKey, const QByteArray& peerPublicKey
    ) = 0;

    // O16: 创建支持前向保密的 Ratchet 会话
    // 返回 IRatchetSession*（拥有权转移给调用方），调用方负责 delete
    // 默认实现返回 nullptr —— 后端不实现 ratchet 时调用方应回退到普通 session
    virtual IRatchetSession* createRatchetSession(
        const ICryptoKeyPair& selfKey, const QByteArray& peerPublicKey
    ) { Q_UNUSED(selfKey) Q_UNUSED(peerPublicKey) return nullptr; }

    virtual std::shared_ptr<ICryptoBackend> clone() const = 0;
    virtual ~ICryptoBackend() {}
};

#endif // ICRYPTOBACKEND_H
