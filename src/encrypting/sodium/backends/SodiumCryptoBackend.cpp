#include "SodiumCryptoBackend.h"
#include "../errors/SodiumCryptoError.h"
#include "../key_pairs/SodiumKeyPair.h"
#include "../sessions/SodiumSession.h"
#include "../sessions/SodiumRatchetSession.h"

ICryptoKeyPair* SodiumCryptoBackend::generateKeyPair()
{
    QByteArray public_key(crypto_kx_PUBLICKEYBYTES, Qt::Uninitialized);
    QByteArray private_key(crypto_kx_SECRETKEYBYTES, Qt::Uninitialized);

    crypto_kx_keypair(
        reinterpret_cast<unsigned char*>(public_key.data()),
        reinterpret_cast<unsigned char*>(private_key.data())
    );
    return new SodiumKeyPair(public_key, private_key);
}

ICryptoSession* SodiumCryptoBackend::createSession(
    const ICryptoKeyPair& selfKey,
    const QByteArray& peerPublicKey
)
{
    const QByteArray selfPublicKey = selfKey.publicKey();
    const QByteArray selfPrivateKey = selfKey.privateKey();

    unsigned char rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx[crypto_kx_SESSIONKEYBYTES];

    // Hashing session keys to ensure protection and hash sum consistence to prevent MITM attack
    QByteArray selfHash = QCryptographicHash::hash(selfPublicKey, QCryptographicHash::Sha256);
    QByteArray peerHash = QCryptographicHash::hash(peerPublicKey, QCryptographicHash::Sha256);

    // Determine role according to their hash sums to prevent key duplication for both sides
    // Helps us generate different async pair of keys for encrypting/decrypting
    bool isClient = (selfHash < peerHash);

    int result = isClient
                     ? crypto_kx_client_session_keys(rx, tx,
                                                    reinterpret_cast<const unsigned char*>(selfPublicKey.constData()),
                                                    reinterpret_cast<const unsigned char*>(selfPrivateKey.constData()),
                                                     reinterpret_cast<const unsigned char*>(peerPublicKey.constData()))
                     : crypto_kx_server_session_keys(rx, tx,
                                                     reinterpret_cast<const unsigned char*>(selfPublicKey.constData()),
                                                     reinterpret_cast<const unsigned char*>(selfPrivateKey.constData()),
                                                     reinterpret_cast<const unsigned char*>(peerPublicKey.constData()));

    if (result != 0){
        throw SodiumCryptoError("Failed to derive session keys with crypto_kx_*_session_keys.",
                                CryptoErrorCode::SessionKeyDerivationFailed);
    }

    return new SodiumSession(
        QByteArray(reinterpret_cast<const char*>(tx), crypto_kx_SESSIONKEYBYTES),
        QByteArray(reinterpret_cast<const char*>(rx), crypto_kx_SESSIONKEYBYTES)
    );
}

std::shared_ptr<ICryptoBackend> SodiumCryptoBackend::clone() const {
    return std::make_shared<SodiumCryptoBackend>(*this);
}

// O16: 创建支持前向保密的 Ratchet 会话
IRatchetSession* SodiumCryptoBackend::createRatchetSession(
    const ICryptoKeyPair& selfKey, const QByteArray& peerPublicKey
) {
    // 用双方公钥做 SHA-256 派生初始 rootKey
    // 这与 createSession 的"hash 双方公钥判定角色"思路一致
    QByteArray selfHash = QCryptographicHash::hash(selfKey.publicKey(), QCryptographicHash::Sha256);
    QByteArray peerHash = QCryptographicHash::hash(peerPublicKey, QCryptographicHash::Sha256);

    // rootKey = SHA256(selfHash || peerHash)（顺序由字典序决定，保证双方一致）
    QByteArray concat = (selfHash < peerHash)
        ? (selfHash + peerHash)
        : (peerHash + selfHash);
    QByteArray rootKey = QCryptographicHash::hash(concat, QCryptographicHash::Sha256);

    return new SodiumRatchetSession(
        rootKey,
        selfKey.privateKey(),
        selfKey.publicKey(),
        peerPublicKey
    );
}
