#pragma once
#ifndef FIREWALLHELPER_H
#define FIREWALLHELPER_H

#include <QObject>
#include <QString>

// P3-O15: 防火墙引导工具
// 检测系统防火墙状态、提示用户添加防火墙规则、验证端口可达性
//
// 设计目标：
// - 跨平台（Windows / Linux / macOS）
// - 不可执行需要 root / UAC 提权的命令时给出友好提示
// - 不阻塞 UI：调用方在主线程发起检测，结果通过信号回调
class FirewallHelper : public QObject {
    Q_OBJECT
public:
    enum class FirewallState {
        Unknown,        // 检测失败或平台不支持
        Enabled,        // 防火墙开启
        Disabled,       // 防火墙关闭（无需任何规则）
        NotManaged      // 防火墙开启但非本工具可管理（如 nftables / iptables 直接配置）
    };
    Q_ENUM(FirewallState)

    enum class Platform {
        Windows,
        Linux_Ufw,
        Linux_Firewalld,
        Linux_NotManaged,
        MacOs,
        Other
    };

    struct PortCheckResult {
        bool locallyReachable = false;   // 自连接 + QTcpServer 验证
        bool externallyReachable = false; // 简单的外部回环探测（best-effort）
        QString detail;
    };

    explicit FirewallHelper(QObject* parent = nullptr);

    // 检测当前平台
    static Platform detectPlatform();

    // 同步检测防火墙状态（阻塞，建议在非 UI 线程调用）
    FirewallState detectFirewallState(Platform platform) const;

    // 检测端口可达性（同步，自连接方式）
    // 在本机尝试 QTcpServer::listen 自连接，验证端口确实能 bind
    PortCheckResult checkPortReachable(int port) const;

    // 异步检测入口（在工作线程执行，结果通过信号返回）
    void detectAsync(int serverPort);

    // 异步添加防火墙规则（需要 root / UAC）
    // 返回 false 表示命令已发起但需要提权（具体行为由系统决定）
    bool requestAddRule(int port, const QString& ruleName);

signals:
    // detectAsync 完成后发射
    void detectionFinished(FirewallHelper::Platform platform,
                            FirewallHelper::FirewallState state,
                            FirewallHelper::PortCheckResult portResult,
                            int serverPort);

private:
    // Windows: netsh advfirewall firewall add rule ...
    bool addRuleWindows(int port, const QString& ruleName);
    // Linux UFW: ufw allow <port>/tcp
    bool addRuleUfw(int port, const QString& ruleName);
    // Linux firewalld: firewall-cmd --add-port=<port>/tcp --permanent
    bool addRuleFirewalld(int port, const QString& ruleName);
};

#endif // FIREWALLHELPER_H
