#include "SodiumRatchetSession.h"
#include "../errors/SodiumCryptoError.h"
#include <QCryptographicHash>
#include <sodium.h>
#include <cstring>

// O16: SodiumRatchetSession 实现

namespace {
// libsodium 常量
constexpr int AEAD_KEY_BYTES = 32;     // crypto_aead_chacha20poly1305_ietf_KEYBYTES
constexpr int AEAD_NONCE_BYTES = 12;   // crypto_aead_chacha20poly1305_ietf_NPUBBYTES
constexpr int AEAD_MAC_BYTES = 16;     // crypto_aead_chacha20poly1305_ietf_ABYTES
constexpr int X25519_PUBKEY_BYTES = 32; // crypto_scalarmult_curve25519_BYTES
constexpr int X25519_PRIVKEY_BYTES = 32; // crypto_scalarmult_curve25519_SCALARBYTES
} // namespace

SodiumRatchetSession::SodiumRatchetSession(
    const QByteArray& initialRootKey,
    const QByteArray& selfPrivateKey,
    const QByteArray& selfPublicKey,
    const QByteArray& peerPublicKey)
    : m_rootKey(initialRootKey),
      m_selfPrivateKey(selfPrivateKey),
      m_selfPublicKey(selfPublicKey),
      m_peerPublicKey(peerPublicKey)
{
    if (m_rootKey.size() != ROOT_KEY_LEN) {
        throw SodiumCryptoError("Ratchet: initial root key must be 32 bytes",
                                CryptoErrorCode::InvalidArgument);
    }
    if (m_selfPrivateKey.size() != X25519_PRIVKEY_BYTES ||
        m_selfPublicKey.size() != X25519_PUBKEY_BYTES ||
        m_peerPublicKey.size() != X25519_PUBKEY_BYTES) {
        throw SodiumCryptoError("Ratchet: invalid DH key sizes",
                                CryptoErrorCode::InvalidArgument);
    }

    // 用初始 rootKey 派生 send/recv chain key
    // 关键：双方必须用对称的 chain 方向 —— Alice 的 sendChain == Bob 的 recvChain
    // 通过公钥哈希字典序判定角色（与 createSession 的 isClient 一致）：
    //   isInitiator = (selfHash < peerHash)
    //   initiator:  sendChain <- "send",  recvChain <- "recv"
    //   responder:  sendChain <- "recv",  recvChain <- "send"
    // 这样 initiator 的 sendChain (info="send") 与 responder 的 recvChain (info="send") 一致
    QByteArray selfHash = QCryptographicHash::hash(selfPublicKey, QCryptographicHash::Sha256);
    QByteArray peerHash = QCryptographicHash::hash(peerPublicKey, QCryptographicHash::Sha256);
    bool isInitiator = (selfHash < peerHash);

    if (isInitiator) {
        m_sendChainKey = hkdfExpand(m_rootKey, "fantom-ratchet-send", CHAIN_KEY_LEN);
        m_recvChainKey = hkdfExpand(m_rootKey, "fantom-ratchet-recv", CHAIN_KEY_LEN);
    } else {
        m_sendChainKey = hkdfExpand(m_rootKey, "fantom-ratchet-recv", CHAIN_KEY_LEN);
        m_recvChainKey = hkdfExpand(m_rootKey, "fantom-ratchet-send", CHAIN_KEY_LEN);
    }
    m_initialized = true;
}

SodiumRatchetSession::~SodiumRatchetSession()
{
    // 显式清零敏感内存
    sodium_memzero(m_rootKey.data(), m_rootKey.size());
    sodium_memzero(m_sendChainKey.data(), m_sendChainKey.size());
    sodium_memzero(m_recvChainKey.data(), m_recvChainKey.size());
    sodium_memzero(m_selfPrivateKey.data(), m_selfPrivateKey.size());
}

// ---- KDF ----

QByteArray SodiumRatchetSession::hmacSha256(const QByteArray& key, const QByteArray& data) {
    // 用 libsodium 的 crypto_auth_hmacsha256 实现
    constexpr int OUT_LEN = 32; // crypto_auth_hmacsha256_BYTES
    QByteArray out(OUT_LEN, Qt::Uninitialized);
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state,
        reinterpret_cast<const unsigned char*>(key.constData()),
        static_cast<unsigned long long>(key.size()));
    crypto_auth_hmacsha256_update(&state,
        reinterpret_cast<const unsigned char*>(data.constData()),
        static_cast<unsigned long long>(data.size()));
    crypto_auth_hmacsha256_final(&state,
        reinterpret_cast<unsigned char*>(out.data()));
    return out;
}

QByteArray SodiumRatchetSession::hkdfExtract(const QByteArray& salt, const QByteArray& ikm) {
    // HKDF-Extract = HMAC-SHA256(salt, ikm)
    QByteArray effectiveSalt = salt.isEmpty() ? QByteArray(32, '\0') : salt;
    return hmacSha256(effectiveSalt, ikm);
}

QByteArray SodiumRatchetSession::hkdfExpand(const QByteArray& prk, const QByteArray& info, int length) {
    // HKDF-Expand = HMAC(prk, info || 0x01) 截断到 length 字节
    QByteArray input = info + QByteArray(1, '\x01');
    QByteArray t = hmacSha256(prk, input);
    if (t.size() < length) {
        // 不应该发生（HMAC-SHA256 输出 32 字节），但防御性处理
        t = t.leftJustified(length, '\0');
    }
    return t.left(length);
}

// ---- chain 推进 ----

QByteArray SodiumRatchetSession::advanceSendChain() const {
    // messageKey = HMAC(sendChainKey, 0x01)
    // nextChainKey = HMAC(sendChainKey, 0x02)
    QByteArray messageKey = hmacSha256(m_sendChainKey, QByteArray(1, '\x01'));
    m_sendChainKey = hmacSha256(m_sendChainKey, QByteArray(1, '\x02'));
    quint32 c = m_sendCounter++;
    Q_UNUSED(c);
    return messageKey;
}

QByteArray SodiumRatchetSession::advanceRecvChainTo(quint32 targetCounter) const {
    // 严格按序：必须 targetCounter == m_recvCounter
    if (targetCounter != m_recvCounter) {
        throw SodiumCryptoError(
            "Ratchet: message out of order",
            CryptoErrorCode::RatchetOutOfOrder);
    }
    QByteArray messageKey = hmacSha256(m_recvChainKey, QByteArray(1, '\x01'));
    m_recvChainKey = hmacSha256(m_recvChainKey, QByteArray(1, '\x02'));
    ++m_recvCounter;
    return messageKey;
}

// ---- AEAD ----

QByteArray SodiumRatchetSession::aeadEncrypt(const QByteArray& key,
                                                const QByteArray& nonce,
                                                const QByteArray& plain) {
    if (key.size() != AEAD_KEY_BYTES) {
        throw SodiumCryptoError("Ratchet AEAD: invalid key size",
                                CryptoErrorCode::InvalidArgument);
    }
    if (nonce.size() != AEAD_NONCE_BYTES) {
        throw SodiumCryptoError("Ratchet AEAD: invalid nonce size",
                                CryptoErrorCode::InvalidArgument);
    }

    QByteArray cipher(AEAD_MAC_BYTES + plain.size(), Qt::Uninitialized);
    unsigned long long cipherLen = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            reinterpret_cast<unsigned char*>(cipher.data()), &cipherLen,
            reinterpret_cast<const unsigned char*>(plain.constData()),
            static_cast<unsigned long long>(plain.size()),
            nullptr, 0,  // no additional data
            nullptr,
            reinterpret_cast<const unsigned char*>(nonce.constData()),
            reinterpret_cast<const unsigned char*>(key.constData())) != 0) {
        throw SodiumCryptoError("Ratchet AEAD: encryption failed",
                                CryptoErrorCode::EncryptionFailed);
    }
    cipher.resize(static_cast<int>(cipherLen));
    return cipher;
}

QByteArray SodiumRatchetSession::aeadDecrypt(const QByteArray& key,
                                                const QByteArray& nonce,
                                                const QByteArray& cipher) {
    if (key.size() != AEAD_KEY_BYTES) {
        throw SodiumCryptoError("Ratchet AEAD: invalid key size",
                                CryptoErrorCode::InvalidArgument);
    }
    if (nonce.size() != AEAD_NONCE_BYTES) {
        throw SodiumCryptoError("Ratchet AEAD: invalid nonce size",
                                CryptoErrorCode::InvalidArgument);
    }

    if (cipher.size() < AEAD_MAC_BYTES) {
        throw SodiumCryptoError("Ratchet AEAD: ciphertext too short",
                                CryptoErrorCode::CiphertextTooShort);
    }

    QByteArray plain(cipher.size() - AEAD_MAC_BYTES, Qt::Uninitialized);
    unsigned long long plainLen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(plain.data()), &plainLen,
            nullptr,
            reinterpret_cast<const unsigned char*>(cipher.constData()),
            static_cast<unsigned long long>(cipher.size()),
            nullptr, 0,
            reinterpret_cast<const unsigned char*>(nonce.constData()),
            reinterpret_cast<const unsigned char*>(key.constData())) != 0) {
        throw SodiumCryptoError("Ratchet AEAD: MAC verification failed",
                                CryptoErrorCode::DecryptionMacFailed);
    }
    plain.resize(static_cast<int>(plainLen));
    return plain;
}

// ---- DH rotation ----

void SodiumRatchetSession::doRatchet(const QByteArray& newSelfPriv,
                                       const QByteArray& newSelfPub,
                                       const QByteArray& newPeerPub,
                                       bool isInitiator) {
    // DH: shared = X25519(newSelfPriv, newPeerPub)
    QByteArray shared(X25519_PUBKEY_BYTES, Qt::Uninitialized);
    if (crypto_scalarmult_curve25519(
            reinterpret_cast<unsigned char*>(shared.data()),
            reinterpret_cast<const unsigned char*>(newSelfPriv.constData()),
            reinterpret_cast<const unsigned char*>(newPeerPub.constData())) != 0) {
        throw SodiumCryptoError("Ratchet: X25519 DH derivation failed",
                                CryptoErrorCode::RatchetStepFailed);
    }

    // newRoot = HKDF-Extract(salt=oldRoot, ikm=shared)
    QByteArray newRoot = hkdfExtract(m_rootKey, shared);

    // 立即销毁旧的 rootKey 和 chainKey（实现 PFS 的关键）
    sodium_memzero(m_rootKey.data(), m_rootKey.size());
    sodium_memzero(m_sendChainKey.data(), m_sendChainKey.size());
    sodium_memzero(m_recvChainKey.data(), m_recvChainKey.size());
    sodium_memzero(shared.data(), shared.size());

    m_rootKey = newRoot;
    m_selfPrivateKey = newSelfPriv;
    m_selfPublicKey = newSelfPub;
    m_peerPublicKey = newPeerPub;

    // 派生新的 send/recv chain
    // 发起方与接收方 chain 方向相反，确保双方 send 对应对方 recv
    if (isInitiator) {
        m_sendChainKey = hkdfExpand(m_rootKey, "fantom-ratchet-send-v2", CHAIN_KEY_LEN);
        m_recvChainKey = hkdfExpand(m_rootKey, "fantom-ratchet-recv-v2", CHAIN_KEY_LEN);
    } else {
        m_sendChainKey = hkdfExpand(m_rootKey, "fantom-ratchet-recv-v2", CHAIN_KEY_LEN);
        m_recvChainKey = hkdfExpand(m_rootKey, "fantom-ratchet-send-v2", CHAIN_KEY_LEN);
    }

    // counter 不重置——保持全局单调递增
    // （避免与历史消息 counter 冲突）
}

QByteArray SodiumRatchetSession::prepareRatchetStep() {
    QMutexLocker locker(&m_mutex);

    // 生成新的 DH 密钥对（X25519，与 crypto_scalarmult_curve25519 兼容）
    QByteArray newPub(X25519_PUBKEY_BYTES, Qt::Uninitialized);
    QByteArray newPriv(X25519_PRIVKEY_BYTES, Qt::Uninitialized);
    if (crypto_box_keypair(
            reinterpret_cast<unsigned char*>(newPub.data()),
            reinterpret_cast<unsigned char*>(newPriv.data())) != 0) {
        throw SodiumCryptoError("Ratchet: failed to generate new DH keypair",
                                CryptoErrorCode::RatchetStepFailed);
    }

    // 用本端新私钥与对端当前公钥做 DH，得到新 rootKey（这一步把旧 rootKey 丢弃）
    // 这里 isInitiator = true（我们是发起方）
    doRatchet(newPriv, newPub, m_peerPublicKey, true);

    return newPub;
}

void SodiumRatchetSession::applyPeerRatchetKey(const QByteArray& peerNewPublicKey) {
    QMutexLocker locker(&m_mutex);

    if (peerNewPublicKey.size() != X25519_PUBKEY_BYTES) {
        throw SodiumCryptoError("Ratchet: invalid peer pubkey size",
                                CryptoErrorCode::InvalidArgument);
    }

    // 用本端当前密钥与对端新公钥做 DH
    // 注意：我们不需要生成新的本端密钥，因为 DH rotation 是单边的
    //   发起方更换密钥，接收方用现有密钥接收
    //   这是 Signal 的"被动方不换密钥"的简化
    // isInitiator = false
    doRatchet(m_selfPrivateKey, m_selfPublicKey, peerNewPublicKey, false);
}

// ---- ICryptoSession ----

QByteArray SodiumRatchetSession::encrypt(const QByteArray& plainText) const {
    QMutexLocker locker(&m_mutex);

    if (!m_initialized) {
        throw SodiumCryptoError("Ratchet: session not initialized",
                                CryptoErrorCode::RatchetNotInitialized);
    }

    // 推进 send chain，得到本条消息的 messageKey
    QByteArray messageKey = advanceSendChain();

    // 生成随机 nonce
    QByteArray nonce(AEAD_NONCE_BYTES, Qt::Uninitialized);
    randombytes_buf(nonce.data(), AEAD_NONCE_BYTES);

    // 加密
    QByteArray cipher = aeadEncrypt(messageKey, nonce, plainText);

    // 销毁 messageKey（PFS 关键）
    sodium_memzero(messageKey.data(), messageKey.size());

    // 组装输出：[counter(4B, big-endian)] [ratchet_flag(1B, 0x00)] [nonce(12B)] [cipher]
    QByteArray output;
    output.reserve(COUNTER_LEN + RATCHET_FLAG_LEN + AEAD_NONCE_BYTES + cipher.size());

    // counter
    quint32 c = m_sendCounter - 1; // advanceSendChain 已自增
    for (int i = 3; i >= 0; --i) {
        output.append(static_cast<char>((c >> (i * 8)) & 0xFF));
    }
    // ratchet flag = 0（普通消息，不旋转；prepareRatchetStep 是单独调用）
    output.append(static_cast<char>(0x00));
    // nonce
    output.append(nonce);
    // cipher
    output.append(cipher);

    return output;
}

QByteArray SodiumRatchetSession::decrypt(const QByteArray& cipherText) const {
    QMutexLocker locker(&m_mutex);

    if (!m_initialized) {
        throw SodiumCryptoError("Ratchet: session not initialized",
                                CryptoErrorCode::RatchetNotInitialized);
    }

    // 最小长度：counter + flag + nonce + MAC
    constexpr int MIN_LEN = COUNTER_LEN + RATCHET_FLAG_LEN + AEAD_NONCE_BYTES + AEAD_MAC_BYTES;
    if (cipherText.size() < MIN_LEN) {
        throw SodiumCryptoError("Ratchet: ciphertext too short",
                                CryptoErrorCode::CiphertextTooShort);
    }

    // 解析 counter
    quint32 counter = 0;
    for (int i = 0; i < 4; ++i) {
        counter = (counter << 8) | static_cast<quint8>(cipherText[i]);
    }

    // 解析 ratchet flag
    quint8 flag = static_cast<quint8>(cipherText[COUNTER_LEN]);
    if (flag != 0x00) {
        // 当前实现：flag 只支持 0（prepareRatchetStep 不通过 encrypt 触发）
        // 上层协议负责单独发送 ratchet 公钥消息
        throw SodiumCryptoError("Ratchet: unsupported ratchet flag",
                                CryptoErrorCode::InvalidArgument);
    }

    // 解析 nonce 和 cipher
    int offset = COUNTER_LEN + RATCHET_FLAG_LEN;
    QByteArray nonce = cipherText.mid(offset, AEAD_NONCE_BYTES);
    QByteArray cipher = cipherText.mid(offset + AEAD_NONCE_BYTES);

    // 推进 recv chain 到对应 counter
    QByteArray messageKey = advanceRecvChainTo(counter);

    // 解密
    QByteArray plain;
    try {
        plain = aeadDecrypt(messageKey, nonce, cipher);
    } catch (...) {
        sodium_memzero(messageKey.data(), messageKey.size());
        throw;
    }

    // 销毁 messageKey
    sodium_memzero(messageKey.data(), messageKey.size());

    return plain;
}

// ---- 访问器 ----

bool SodiumRatchetSession::isInitialized() const {
    QMutexLocker locker(&m_mutex);
    return m_initialized;
}

quint32 SodiumRatchetSession::sendCounter() const {
    QMutexLocker locker(&m_mutex);
    return m_sendCounter;
}

quint32 SodiumRatchetSession::recvCounter() const {
    QMutexLocker locker(&m_mutex);
    return m_recvCounter;
}
