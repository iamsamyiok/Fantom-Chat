#pragma once

#ifndef SODIUMCRYPTOBACKEND_H
#define SODIUMCRYPTOBACKEND_H

#include "../../interfaces/ICryptoBackend.h"
#include "../../interfaces/IRatchetSession.h"
#include <sodium.h>
#include <QCryptographicHash>

class SodiumCryptoBackend : public ICryptoBackend
{
public:
    ICryptoKeyPair* generateKeyPair() override;
    ICryptoSession* createSession(
        const ICryptoKeyPair& selfKey, const QByteArray& peerPublicKey
    ) override;

    // O16: 创建支持前向保密的 Ratchet 会话
    IRatchetSession* createRatchetSession(
        const ICryptoKeyPair& selfKey, const QByteArray& peerPublicKey
    ) override;

    std::shared_ptr<ICryptoBackend> clone() const override;
};

#endif // SODIUMCRYPTOBACKEND_H
