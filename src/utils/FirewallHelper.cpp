#include "FirewallHelper.h"

#include <QCoreApplication>
#include <QProcess>
#include <QTcpServer>
#include <QHostAddress>
#include <QThread>
#include <QFileInfo>
#include <QStandardPaths>
#include <QDebug>

FirewallHelper::FirewallHelper(QObject* parent) : QObject(parent) {}

FirewallHelper::Platform FirewallHelper::detectPlatform() {
#ifdef Q_OS_WIN
    return Platform::Windows;
#elif defined(Q_OS_MAC)
    return Platform::MacOs;
#elif defined(Q_OS_LINUX)
    // UFW 优先于 firewalld
    if (QStandardPaths::findExecutable("ufw") != QString()) {
        return Platform::Linux_Ufw;
    }
    if (QStandardPaths::findExecutable("firewall-cmd") != QString()) {
        return Platform::Linux_Firewalld;
    }
    return Platform::Linux_NotManaged;
#else
    return Platform::Other;
#endif
}

FirewallHelper::FirewallState FirewallHelper::detectFirewallState(Platform platform) const {
    switch (platform) {
        case Platform::Windows: {
            // netsh advfirewall show allprofiles state
            // 输出每行形如 "State                                 ON" / "OFF"
            QProcess p;
            p.setProgram("netsh");
            p.setArguments({"advfirewall", "show", "allprofiles", "state"});
            p.start();
            if (!p.waitForFinished(5000)) {
                qWarning() << "FirewallHelper: netsh timeout";
                return FirewallState::Unknown;
            }
            QString out = QString::fromUtf8(p.readAllStandardOutput());
            // 至少一个 profile 为 ON 即视为启用
            if (out.contains("ON", Qt::CaseInsensitive)) {
                return FirewallState::Enabled;
            }
            if (out.contains("OFF", Qt::CaseInsensitive)) {
                return FirewallState::Disabled;
            }
            return FirewallState::Unknown;
        }
        case Platform::Linux_Ufw: {
            // sudo ufw status 不需要 root 即可查询（ufw status 是只读）
            QProcess p;
            p.setProgram("ufw");
            p.setArguments({"status"});
            p.start();
            if (!p.waitForFinished(5000)) {
                qWarning() << "FirewallHelper: ufw status timeout";
                return FirewallState::Unknown;
            }
            QString out = QString::fromUtf8(p.readAllStandardOutput());
            if (out.contains("Status: active", Qt::CaseInsensitive)) {
                return FirewallState::Enabled;
            }
            if (out.contains("Status: inactive", Qt::CaseInsensitive)) {
                return FirewallState::Disabled;
            }
            // 可能因为非 root 而权限拒绝
            if (p.exitCode() != 0) {
                qWarning() << "FirewallHelper: ufw status exit" << p.exitCode()
                           << p.readAllStandardError();
                return FirewallState::Unknown;
            }
            return FirewallState::Unknown;
        }
        case Platform::Linux_Firewalld: {
            // firewall-cmd --state，需要 firewalld 服务在运行
            QProcess p;
            p.setProgram("firewall-cmd");
            p.setArguments({"--state"});
            p.start();
            if (!p.waitForFinished(5000)) {
                return FirewallState::Unknown;
            }
            QString out = QString::fromUtf8(p.readAllStandardOutput()).trimmed();
            if (out.compare("running", Qt::CaseInsensitive) == 0) {
                return FirewallState::Enabled;
            }
            if (out.compare("not running", Qt::CaseInsensitive) == 0) {
                return FirewallState::Disabled;
            }
            return FirewallState::Unknown;
        }
        case Platform::Linux_NotManaged:
            // 不可管理，让 UI 给出通用提示
            return FirewallState::NotManaged;
        case Platform::MacOs: {
            // pfctl -s info | grep "Status"
            QProcess p;
            p.setProgram("pfctl");
            p.setArguments({"-s", "info"});
            p.start();
            if (!p.waitForFinished(5000)) {
                return FirewallState::Unknown;
            }
            QString out = QString::fromUtf8(p.readAllStandardOutput());
            if (out.contains("Status: Enabled", Qt::CaseInsensitive)) {
                return FirewallState::Enabled;
            }
            if (out.contains("Status: Disabled", Qt::CaseInsensitive)) {
                return FirewallState::Disabled;
            }
            return FirewallState::Unknown;
        }
        case Platform::Other:
            return FirewallState::NotManaged;
    }
    return FirewallState::Unknown;
}

FirewallHelper::PortCheckResult FirewallHelper::checkPortReachable(int port) const {
    PortCheckResult result;
    // 自连接 + QTcpServer::listen 验证
    QTcpServer server;
    bool ok = false;
    // 优先 IPv6 any
    ok = server.listen(QHostAddress::AnyIPv6, port);
    if (!ok) {
        // 退回 IPv4 any
        ok = server.listen(QHostAddress::Any, port);
    }
    if (!ok) {
        result.locallyReachable = false;
        result.detail = server.errorString();
        return result;
    }
    result.locallyReachable = true;
    // 验证 serverPort() 真实生效（端口 0 时由系统分配）
    int actualPort = server.serverPort();
    result.detail = QString("Listening on port %1 (requested %2)").arg(actualPort).arg(port);
    server.close();
    return result;
}

void FirewallHelper::detectAsync(int serverPort) {
    // 通过 QtConcurrent 或 QThread 跑在后台
    QThread* worker = QThread::create([this, serverPort]() {
        Platform p = detectPlatform();
        FirewallState s = detectFirewallState(p);
        PortCheckResult pr = checkPortReachable(serverPort);
        emit detectionFinished(p, s, pr, serverPort);
    });
    worker->setParent(this);
    connect(worker, &QThread::finished, worker, &QObject::deleteLater);
    worker->start();
}

bool FirewallHelper::requestAddRule(int port, const QString& ruleName) {
    Platform p = detectPlatform();
    switch (p) {
        case Platform::Windows:
            return addRuleWindows(port, ruleName);
        case Platform::Linux_Ufw:
            return addRuleUfw(port, ruleName);
        case Platform::Linux_Firewalld:
            return addRuleFirewalld(port, ruleName);
        case Platform::Linux_NotManaged:
        case Platform::MacOs:
        case Platform::Other:
        default:
            qWarning() << "FirewallHelper: cannot auto-add rule on platform" << static_cast<int>(p);
            return false;
    }
}

bool FirewallHelper::addRuleWindows(int port, const QString& ruleName) {
    // netsh advfirewall firewall add rule name="FantomChat TCP <port>" dir=in action=allow protocol=TCP localport=<port>
    QProcess* p = new QProcess(this);
    p->setProgram("netsh");
    QStringList args = {"advfirewall", "firewall", "add", "rule",
                       QString("name=%1").arg(ruleName),
                       "dir=in", "action=allow", "protocol=TCP",
                       QString("localport=%1").arg(port)};
    p->setArguments(args);
    // 注意：通常需要 UAC 提权，这里用 startDetached 让系统弹出提权对话框由父进程决定
    // 实际生产中应通过 Qt 的 QProcess::startDetached，或调用 ShellExecuteW 带 "runas" 动词
    bool ok = p->startDetached();
    if (!ok) {
        qWarning() << "FirewallHelper: failed to start netsh (need UAC?)";
        return false;
    }
    return true;
}

bool FirewallHelper::addRuleUfw(int port, const QString& ruleName) {
    Q_UNUSED(ruleName);
    // sudo ufw allow <port>/tcp
    // 使用 pkexec 提权，避免硬编码 sudo（避免终端密码问题）
    QProcess* p = new QProcess(this);
    QString pkexec = QStandardPaths::findExecutable("pkexec");
    if (pkexec.isEmpty()) {
        qWarning() << "FirewallHelper: pkexec not found, falling back to ufw without privilege";
        p->setProgram("ufw");
        p->setArguments({"allow", QString("%1/tcp").arg(port)});
    } else {
        p->setProgram(pkexec);
        p->setArguments({"ufw", "allow", QString("%1/tcp").arg(port)});
    }
    bool ok = p->startDetached();
    if (!ok) {
        qWarning() << "FirewallHelper: failed to start ufw";
        return false;
    }
    return true;
}

bool FirewallHelper::addRuleFirewalld(int port, const QString& ruleName) {
    Q_UNUSED(ruleName);
    // sudo firewall-cmd --add-port=<port>/tcp --permanent && firewall-cmd --reload
    QProcess* p = new QProcess(this);
    QString pkexec = QStandardPaths::findExecutable("pkexec");
    if (pkexec.isEmpty()) {
        p->setProgram("firewall-cmd");
        p->setArguments({"--add-port", QString("%1/tcp").arg(port), "--permanent"});
    } else {
        p->setProgram(pkexec);
        p->setArguments({"firewall-cmd", "--add-port", QString("%1/tcp").arg(port), "--permanent"});
    }
    bool ok = p->startDetached();
    if (!ok) {
        qWarning() << "FirewallHelper: failed to start firewall-cmd";
        return false;
    }
    return true;
}
