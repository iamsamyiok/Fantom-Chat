#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "../../network/IPv6ChatClient.h"
#include "../../network/IPv6ChatServer.h"
#include "../../network/PeerDiscovery.h"
#include "../../models/MessageListModel.h"
#include "../../models/ContactListModel.h"
#include "../../storage/MessageStore.h"
#include "../../utils/Requests.h"
#include "../../utils/FirewallHelper.h"

#include <QMainWindow>
#include <QSettings>
#include <QGridLayout>
#include <QTranslator>
#include <memory>

const int DEFAULT_SERVER_PORT = 31488;

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void PastInit();
    void UploadConfig();
    void HideSidebarElements(QGridLayout *ipGrid, QGridLayout *startServerGrid);
    void ShowSidebarElements(QGridLayout *ipGrid, QGridLayout *startServerGrid);
    void InitServer(int serverPort = DEFAULT_SERVER_PORT);
    void InitClient();

    void switchLanguage(const QString &langCode);

protected:
    void showEvent(QShowEvent *event) override;

private:
    Ui::MainWindow *ui;
    QSettings *settings;
    IPv6ChatServer *socketServer;
    QThread *socketServerThread;
    IPv6ChatClient *socketClient;
    QThread *clientSocketsThread;
    QHostAddress selfHostAddress;
    QString stringSelfHostAddress;
    Requests *request;
    QString currentChatID;
    QTranslator* translator = nullptr;

    QMap<QString, QList<Message>> messages;

    bool isCurrentChatClientOnline = false;

    MessageListModel* currentMessageModel = nullptr;
    ContactListModel* currentContactModel = nullptr;

    // Client list connected to server (for UI purpose)
    QSet<QString> connectedClients;

    std::shared_ptr<ICryptoBackend> baseCrypto;

    // O1: 消息持久化层（SQLite + libsodium 加密）
    std::unique_ptr<MessageStore> messageStore;

    // O2: 局域网内 IPv6 peer 自动发现
    std::unique_ptr<PeerDiscovery> peerDiscovery;

    // O15: 防火墙引导
    FirewallHelper* firewallHelper = nullptr;

    void initializeTranslatingTexts();

    void applyStyleSheet(QString langCode);
    void openChatPage(const QString& chatID, const QString& clientID);
    void setUpMessagesForChatInRAM(const QString& chatID);
    QString getLocalIPv6Address();
    void showToolTipOnPosition(QWidget* widget, QString text);

    // O15: 首次启动防火墙引导
    void startFirewallGuidance(int serverPort);

    // O17: 显示当前会话的 Safety Number
    // 在 chatID 对应的连接中，计算两端公钥的 Safety Number 并展示给用户
    void showSafetyNumber(const QString& chatID, const QString& clientID);

    // O17: 查找指定 clientID 对应的 peer 公钥
    // 优先从客户端侧查找（用户主动连接的对端）；找不到再从服务端侧查找
    QByteArray lookupPeerPublicKey(const QString& clientID);

    // O17: 查找本端公钥
    QByteArray lookupLocalPublicKey();

private slots:
    void on_splitter_splitterMoved(int pos, int index);
    void on_start_server_button_clicked();
    void on_port_input_textChanged();
    void on_write_to_button_clicked();
    void on_port_input_returnPressed();
    void on_client_address_input_returnPressed();
    void on_client_port_input_returnPressed();
    void on_send_message_button_clicked();
    void on_copy_server_button_clicked();
    void onContactClicked(const QModelIndex& index);

    // O17: 联系人列表右键菜单 - 显示 Safety Number
    void onShowSafetyNumberAction();

    // Client
    void onPeerConnected(const QString& clientID);
    void onPeerDisconnected(const QString& clientID);
    void onMessageSent(const QString& clientID, const QByteArray& message);

    // Server
    void onServerClientConnected(const QString& clientID);
    void onServerClientDisconnected(const QString& clientID);
    void onMessageArrived(const QString& clientID, const QByteArray& message);

    // O15: 防火墙检测完成回调
    void onFirewallDetectionFinished(FirewallHelper::Platform platform,
                                      FirewallHelper::FirewallState state,
                                      FirewallHelper::PortCheckResult portResult,
                                      int serverPort);
};
#endif // MAINWINDOW_H
