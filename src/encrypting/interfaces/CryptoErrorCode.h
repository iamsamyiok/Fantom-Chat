#pragma once
#ifndef CRYPTOERRORCODE_H
#define CRYPTOERRORCODE_H

#include <QString>
#include <QCoreApplication>

// O11: 错误信息本地化
// 定义统一的加密层错误码，并提供本地化字符串映射
// 抛出异常时仍可附带原始英文消息（用于日志），UI 显示时统一走 errorCode -> tr() 映射
enum class CryptoErrorCode {
    Unknown = 0,
    // 密钥派生 / 会话密钥
    SessionKeyDerivationFailed,
    // 加解密
    EncryptionFailed,
    CiphertextTooShort,
    DecryptionMacFailed,
    DecryptionFailed,
    // 密钥对
    InvalidPublicKey,
    InvalidSecretKey,
    KeyPairGenerationFailed,
    // 通用
    BackendNotInitialized,
    InvalidArgument,
    // O16: Ratchet / 前向保密
    RatchetOutOfOrder,        // 收到的消息 counter 落后太多或乱序，无法解密
    RatchetStepFailed,         // DH ratchet 推进失败
    RatchetMessageKeyMissing,  // 找不到对应 counter 的消息密钥（已丢弃）
    RatchetNotInitialized      // Ratchet 状态未初始化
};

namespace CryptoErrorLocalizer {
    // 调用方需在 QObject 上下文里使用，确保 tr() 正确翻译
    // 此处用 QCoreApplication::translate 以便从非 QObject 上下文也能调用
    inline QString toString(CryptoErrorCode code) {
        switch (code) {
            case CryptoErrorCode::SessionKeyDerivationFailed:
                return QCoreApplication::translate("CryptoError",
                    "Failed to derive session keys from peer public key. "
                    "The peer's key may be malformed or invalid.");
            case CryptoErrorCode::EncryptionFailed:
                return QCoreApplication::translate("CryptoError",
                    "Failed to encrypt the message. "
                    "The session state may be corrupted.");
            case CryptoErrorCode::CiphertextTooShort:
                return QCoreApplication::translate("CryptoError",
                    "Received ciphertext is too short to be valid "
                    "(missing nonce or authentication tag).");
            case CryptoErrorCode::DecryptionMacFailed:
                return QCoreApplication::translate("CryptoError",
                    "Message authentication failed. "
                    "The message may have been tampered with or the key is wrong.");
            case CryptoErrorCode::DecryptionFailed:
                return QCoreApplication::translate("CryptoError",
                    "Failed to decrypt the message.");
            case CryptoErrorCode::InvalidPublicKey:
                return QCoreApplication::translate("CryptoError",
                    "The peer's public key is invalid.");
            case CryptoErrorCode::InvalidSecretKey:
                return QCoreApplication::translate("CryptoError",
                    "The local secret key is invalid.");
            case CryptoErrorCode::KeyPairGenerationFailed:
                return QCoreApplication::translate("CryptoError",
                    "Failed to generate a cryptographic key pair.");
            case CryptoErrorCode::BackendNotInitialized:
                return QCoreApplication::translate("CryptoError",
                    "The cryptography backend is not initialized.");
            case CryptoErrorCode::InvalidArgument:
                return QCoreApplication::translate("CryptoError",
                    "Invalid argument passed to a cryptography function.");
            case CryptoErrorCode::RatchetOutOfOrder:
                return QCoreApplication::translate("CryptoError",
                    "Received a message out of order. "
                    "The ratchet cannot rewind to recover the message key.");
            case CryptoErrorCode::RatchetStepFailed:
                return QCoreApplication::translate("CryptoError",
                    "Failed to advance the ratchet state (DH derivation failed).");
            case CryptoErrorCode::RatchetMessageKeyMissing:
                return QCoreApplication::translate("CryptoError",
                    "The message key for this counter has already been discarded. "
                    "The message cannot be decrypted.");
            case CryptoErrorCode::RatchetNotInitialized:
                return QCoreApplication::translate("CryptoError",
                    "The ratchet session has not been initialized.");
            case CryptoErrorCode::Unknown:
            default:
                return QCoreApplication::translate("CryptoError",
                    "An unknown cryptographic error occurred.");
        }
    }
}

#endif // CRYPTOERRORCODE_H
