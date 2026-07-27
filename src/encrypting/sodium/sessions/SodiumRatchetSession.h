#ifndef SODIUMRATCHETSESSION_H
#define SODIUMRATCHETSESSION_H

#include "../../interfaces/IRatchetSession.h"
#include <QByteArray>
#include <QMutex>

// O16: 基于 libsodium 的轻量 Double Ratchet 实现
//
// 状态：
//   m_rootKey       —— 持续 KDF chain 的根，每次 DH rotation 后被替换
//   m_sendChainKey  —— 发送链 KDF key，每条消息推进一次
//   m_recvChainKey  —— 接收链 KDF key，每条消息推进一次
//   m_sendCounter   —— 发送计数器（单调递增，附在密文前缀）
//   m_recvCounter   —— 接收计数器
//   m_selfKeyPair   —— 本端 DH 密钥对（每次 prepareRatchetStep 时刷新）
//   m_peerPublicKey  —— 对端当前 DH 公钥
//
// KDF 设计（基于 HMAC-SHA256，键控不同字节以区分用途）：
//   nextChainKey = HMAC-SHA256(chainKey, 0x02)
//   messageKey   = HMAC-SHA256(chainKey, 0x01)
//   下一轮 chainKey 用 nextChainKey，messageKey 用于本条消息加解密后丢弃
//
// DH rotation 设计（X25519）：
//   newRootKey = HKDF(oldRootKey || X25519(selfPriv, peerPub))
//   newSendChain = HMAC-SHA256(newRootKey, "send")
//   newRecvChain = HMAC-SHA256(newRootKey, "recv")
//
// 密文格式（在 ICryptoSession::encrypt 的输出中）：
//   [counter(4B, big-endian)] [ratchet_flag(1B)] [ratchet_pubkey?(32B)] [nonce(24B)] [ciphertext+MAC]
//
//   ratchet_flag = 0x01 表示本条消息触发了一次 prepareRatchetStep
//                  0x00 普通消息（不旋转）
//
// 安全保证：
//   - 每条消息使用独立 messageKey，加密后立即从内存丢弃
//   - DH rotation 后，旧 rootKey / chainKey 立即从内存丢弃
//   - 长期密钥泄露（m_selfKeyPair.privateKey）不能解密 ratchet 前的消息：
//     因为那些消息用的是已被丢弃的 messageKey（由旧 chainKey 派生），
//     而 chainKey 由旧 rootKey 派生，旧 rootKey 在 rotation 后被丢弃
class SodiumRatchetSession : public IRatchetSession
{
public:
    // 从初始握手派生的 tx/rx key 创建 ratchet session
    // initialRootKey 由调用方提供（一般 = SHA256(txKey || rxKey)）
    // selfKeyPair 由调用方提供（一般 = 握手时用的 keypair）
    // peerPublicKey 由调用方提供（一般 = 握手时拿到的对端 pubkey）
    SodiumRatchetSession(const QByteArray& initialRootKey,
                          const QByteArray& selfPrivateKey,
                          const QByteArray& selfPublicKey,
                          const QByteArray& peerPublicKey);

    ~SodiumRatchetSession() override;

    // ICryptoSession 接口实现
    // 注意：虽然是 const 方法，但内部通过 mutable 修改 ratchet 状态
    QByteArray encrypt(const QByteArray& plainText) const override;
    QByteArray decrypt(const QByteArray& cipherText) const override;

    // IRatchetSession 接口实现
    QByteArray prepareRatchetStep() override;
    void applyPeerRatchetKey(const QByteArray& peerNewPublicKey) override;
    bool isInitialized() const override;
    quint32 sendCounter() const override;
    quint32 recvCounter() const override;

private:
    // KDF 工具
    static QByteArray hmacSha256(const QByteArray& key, const QByteArray& data);
    static QByteArray hkdfExtract(const QByteArray& salt, const QByteArray& ikm);
    static QByteArray hkdfExpand(const QByteArray& prk, const QByteArray& info, int length);

    // 推进 send chain，返回当前 message key
    QByteArray advanceSendChain() const;

    // 推进 recv chain 到指定 counter，返回对应 message key
    // 若 counter 落后于当前 recvCounter，抛出 RatchetOutOfOrder
    QByteArray advanceRecvChainTo(quint32 targetCounter) const;

    // 触发 DH rotation（双方同步）
    //   newSelfPriv / newSelfPub: 本端新一轮 DH 私钥/公钥
    //   newPeerPub: 对端新一轮 DH 公钥
    //   isInitiator: 本端是否为 DH rotation 发起方
    //                （决定 send/recv chain 方向）
    void doRatchet(const QByteArray& newSelfPriv,
                    const QByteArray& newSelfPub,
                    const QByteArray& newPeerPub,
                    bool isInitiator);

    // 用 message key 加密 / 解密 payload（AEAD: ChaCha20-Poly1305）
    static QByteArray aeadEncrypt(const QByteArray& key,
                                   const QByteArray& nonce,
                                   const QByteArray& plain);
    static QByteArray aeadDecrypt(const QByteArray& key,
                                   const QByteArray& nonce,
                                   const QByteArray& cipher);

    mutable QMutex m_mutex;

    // 所有状态都用 mutable，以便在 const encrypt/decrypt 中修改
    mutable QByteArray m_rootKey;
    mutable QByteArray m_sendChainKey;
    mutable QByteArray m_recvChainKey;
    mutable quint32 m_sendCounter = 0;
    mutable quint32 m_recvCounter = 0;

    mutable QByteArray m_selfPrivateKey;
    mutable QByteArray m_selfPublicKey;
    mutable QByteArray m_peerPublicKey;

    mutable bool m_initialized = false;

    // 常量
    static constexpr int ROOT_KEY_LEN = 32;
    static constexpr int CHAIN_KEY_LEN = 32;
    static constexpr int MESSAGE_KEY_LEN = 32;
    static constexpr int NONCE_LEN = 24;  // crypto_aead_chacha20poly1305_ietf_NPUBBYTES
    static constexpr int COUNTER_LEN = 4;
    static constexpr int RATCHET_FLAG_LEN = 1;
    static constexpr int RATCHET_PUBKEY_LEN = 32;
};

#endif // SODIUMRATCHETSESSION_H
