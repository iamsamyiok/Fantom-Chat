#ifndef ICRYPTOERROR_H
#define ICRYPTOERROR_H

#include <QString>
#include "CryptoErrorCode.h"

// O11: 错误信息本地化
// ICryptoError 现在携带一个稳定错误码 (CryptoErrorCode)
// - message() 保留原始英文消息（用于日志与调试）
// - localizedMessage() 返回基于错误码的本地化字符串（用于 UI 展示）
class ICryptoError : public std::runtime_error {
public:
    explicit ICryptoError(const std::string& message,
                          CryptoErrorCode code = CryptoErrorCode::Unknown)
        : std::runtime_error(message), m_code(code) {}

    virtual ~ICryptoError() = default;

    // 原始英文消息（用于日志）
    virtual QString message() const = 0;

    // 错误码
    CryptoErrorCode errorCode() const { return m_code; }

    // 本地化消息（用于 UI）
    virtual QString localizedMessage() const {
        return CryptoErrorLocalizer::toString(m_code);
    }

private:
    CryptoErrorCode m_code;
};

#endif // ICRYPTOERROR_H
