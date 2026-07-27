#ifndef RATCHETWIRE_H
#define RATCHETWIRE_H

#include <QString>
#include <QByteArray>

// O16: Ratchet DH rotation 公钥的 wire 协议
//
// 握手成功后，ratchet-initiator (TCP 客户端) 调用 prepareRatchetStep 得到新公钥，
// 通过此 wire 消息明文发送给 ratchet-responder (TCP 服务端)
// 服务端收到后调用 applyPeerRatchetKey 完成双方同步旋转
//
// 与 HANDSHAKE 一样，此消息以文本行形式发送（\n 结尾），不经过加密层
// 公钥本身不是秘密；MITM 威胁与 HANDSHAKE 相同，由 Safety Number (O17) 缓解
//
// 流程：
//   client: HANDSHAKE_ACK 收到 -> 创建 IRatchetSession -> prepareRatchetStep -> 发送 RATCHET_PUBKEY 行
//   server: 收到 RATCHET_PUBKEY 行 -> 创建 IRatchetSession（已就绪）-> applyPeerRatchetKey
//   双方此后进入 post-rotation chain，可双向收发用户消息
namespace RatchetWire {

constexpr const char* PREFIX = "RATCHET_PUBKEY";
constexpr int NEW_PUBKEY_LEN = 32; // X25519 公钥长度

// 编码 RATCHET_PUBKEY 行：RATCHET_PUBKEY <base64>\n
inline QByteArray encode(const QByteArray& newPublicKey) {
    return QString("%1 %2\n")
        .arg(QString::fromLatin1(PREFIX))
        .arg(QString::fromUtf8(newPublicKey.toBase64()))
        .toUtf8();
}

// 尝试从 buffer 开头解析一条 RATCHET_PUBKEY 行
// - 若 buffer 不是以 PREFIX 开头：返回 false，不修改 buffer（继续走二进制帧路径）
// - 若是 PREFIX 开头但 \n 未到达：返回 false，不修改 buffer（等待更多数据）
// - 若解析成功：从 buffer 移除该行，newPublicKeyOut 输出 32B 公钥，返回 true
// - 若解析失败（行格式不对/长度不对）：从 buffer 移除该行，返回 false（调用方应断开）
inline bool tryDecode(QByteArray& buffer, QByteArray& newPublicKeyOut) {
    if (!buffer.startsWith(PREFIX)) return false;
    int endIndex = buffer.indexOf('\n');
    if (endIndex == -1) return false; // 等待完整行

    QByteArray line = buffer.left(endIndex).trimmed();
    buffer.remove(0, endIndex + 1);

    int space = line.indexOf(' ');
    if (space == -1) {
        newPublicKeyOut.clear();
        return false;
    }
    QByteArray b64 = line.mid(space + 1).trimmed();
    newPublicKeyOut = QByteArray::fromBase64(b64);
    return newPublicKeyOut.size() == NEW_PUBKEY_LEN;
}

} // namespace RatchetWire

#endif // RATCHETWIRE_H
