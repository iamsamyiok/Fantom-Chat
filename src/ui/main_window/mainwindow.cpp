#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "../../src/font-awesome/AwesomeGlobal.h"
#include "../../utils/Requests.h"
#include "../../utils/ProtocolUtils.h"
#include "../../utils/SafetyNumber.h"
#include "../../utils/KeyExchange.h"
#include "../../encrypting/sodium/backends/SodiumCryptoBackend.h"

#include <curl/curl.h>

#include <QFont>
#include <QDebug>
#include <QString>
#include <QSettings>
#include <QMetaObject>
#include <QMessageBox>
#include <QPushButton>
#include <QFile>
#include <QToolTip>
#include <QTimer>
#include <QClipboard>
#include <QFontDatabase>
#include <QButtonGroup>
#include <QShortcut>
#include <QKeySequence>
#include <QMenu>
#include <QAction>
#include <QInputDialog>
#include <QStandardPaths>
#include <QDir>

#include "../chat/delegates/ChatMessageDelegate.cpp"
#include "../contacts/delegates/ContactsDelegate.cpp"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , settings(new QSettings("config.ini", QSettings::IniFormat))
    , socketServer(nullptr)
    , socketServerThread(new QThread(this))
    , socketClient(nullptr)
    , clientSocketsThread(new QThread(this))
    , request(new Requests)
{
    ui->setupUi(this);

    ui->splitter->setStretchFactor(0, 1);
    ui->splitter->setStretchFactor(1, 1);

    QVariantMap iconOptions;
    iconOptions.insert("color", QColor("#e0e0e0"));
    iconOptions.insert("color-active", QColor("#e0e0e0"));

    ui->port_input->setText(QString::number(DEFAULT_SERVER_PORT));
    ui->write_to_button->setEnabled(false);

    ui->chat_stacked_widget->setCurrentIndex(1);

    ui->send_message_button->setIcon(awesome->icon(fa::fa_solid, fa::fa_paper_plane, iconOptions));
    ui->copy_server_button->setIcon(awesome->icon(fa::fa_solid, fa::fa_copy, iconOptions));
    ui->copy_server_button->setToolTip("Copy to clipboard");

    ui->chat_list->setItemDelegate(new ChatMessageDelegate(ui->chat_list));
    ui->chat_list->setWordWrap(true);
    ui->chat_list->setUniformItemSizes(false);
    ui->chat_list->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    ui->chat_list->setSpacing(10);

    ui->contacts_list_view->setItemDelegate(new ContactsDelegate(ui->contacts_list_view));
    ui->contacts_list_view->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    ui->contacts_list_view->setUniformItemSizes(true);
    // For hovering
    ui->contacts_list_view->setMouseTracking(true);
    ui->contacts_list_view->viewport()->setCursor(Qt::PointingHandCursor);

    // Set contacts model
    currentContactModel = new ContactListModel(this);
    ui->contacts_list_view->setModel(currentContactModel);
    ui->contacts_list_view->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->contacts_list_view->setSelectionBehavior(QAbstractItemView::SelectRows);

    connect(ui->contacts_list_view, &QListView::clicked, this, &MainWindow::onContactClicked);

    // O17: 联系人列表右键菜单 - 提供"显示 Safety Number"入口
    ui->contacts_list_view->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->contacts_list_view, &QWidget::customContextMenuRequested,
            this, [this](const QPoint& pos){
        QModelIndex index = ui->contacts_list_view->indexAt(pos);
        if (!index.isValid()) return;

        QMenu menu(this);
        QAction* safetyAction = menu.addAction(tr("Show Safety Number..."));
        safetyAction->setData(index);
        connect(safetyAction, &QAction::triggered, this, &MainWindow::onShowSafetyNumberAction);
        menu.exec(ui->contacts_list_view->viewport()->mapToGlobal(pos));
    });

    QVector<Contact> contacts;
    currentContactModel->setContacts(contacts);

    // locale buttons
    QButtonGroup* localeGroup = new QButtonGroup(this);
    localeGroup->addButton(ui->en_locale, 0);
    localeGroup->addButton(ui->ru_locale, 1);
    localeGroup->addButton(ui->zh_locale, 2);

    connect(localeGroup, &QButtonGroup::idClicked, this, [=, this](int id){
        switch (id) {
            case 0: switchLanguage("en"); break;
            case 1: switchLanguage("ru"); break;
            case 2: switchLanguage("zh"); break;
        }
    });

    ui->en_locale->setIcon(QIcon(":/assets/images/en_flag.png"));
    ui->ru_locale->setIcon(QIcon(":/assets/images/ru_flag.png"));
    ui->zh_locale->setIcon(QIcon(":/assets/images/zh_flag.png"));

    QSize iconSize(32, 32);
    ui->en_locale->setIconSize(iconSize);
    ui->ru_locale->setIconSize(iconSize);
    ui->zh_locale->setIconSize(iconSize);

    // Initializing cryptography
    baseCrypto = std::make_shared<SodiumCryptoBackend>();

    // O1: 初始化消息持久化层
    // 数据库存放在用户配置目录下的 fantomchat 子目录
    messageStore = std::make_unique<MessageStore>(this);
    QString configDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (configDir.isEmpty()) {
        // Linux/Windows 退回方案
        configDir = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/fantomchat";
    }
    QDir().mkpath(configDir);
    QString dbPath = configDir + "/messages.db";
    if (messageStore->open(dbPath)) {
        qDebug() << "MessageStore: opened at" << dbPath;
    } else {
        qWarning() << "MessageStore: failed to open" << dbPath << ", falling back to RAM-only mode";
        messageStore->setEnabled(false);
    }

    QIcon windowIcon(":/assets/images/logo.png");
    this->setWindowIcon(windowIcon);
    this->showMaximized();
    this->UploadConfig();
}

MainWindow::~MainWindow()
{
    QVariantList sizes;
    for (int& size : ui->splitter->sizes()) {
        sizes.append(size);
    }

    settings->setValue("splitterSizes", sizes);
    settings->sync();

    // To ensure that it will be destroyed in the same thread it is located, we gonna use deleteLater
    // No need to invoke here, server stops in the destructor (deleteLater calls it)
    if (socketServerThread && socketServerThread->isRunning()) {
        socketServerThread->quit();
        socketServerThread->wait();
    }

    if (clientSocketsThread && clientSocketsThread->isRunning()) {
        clientSocketsThread->quit();
        clientSocketsThread->wait();
    }

    if (socketServer){
        socketServer->deleteLater();
        socketServer = nullptr;
    }

    if (socketClient){
        socketClient->deleteLater();
        socketClient = nullptr;
    }

    delete socketServerThread;
    socketServerThread = nullptr;

    delete clientSocketsThread;
    clientSocketsThread = nullptr;

    delete settings;
    delete ui;
}


void MainWindow::initializeTranslatingTexts()
{
    ui->your_ip_label->setText(tr("Your address:"));
    ui->port_warning->setText(tr("Please, do not change port if you are not sure what are you doing."));
    ui->start_server_button->setText(tr("Start server"));
    ui->port_input->setPlaceholderText(tr("Your local port, use any from 30000 to 65535"));
    ui->write_to_button->setText(tr("Write to"));
    ui->client_address_input->setPlaceholderText(tr("Peer address"));
    ui->client_port_input->setPlaceholderText(tr("Peer port"));
    ui->status_label->setText(tr("Server status"));
    ui->welcome_text->setHtml(tr(R"(
        <b>Welcome!</b><br><br>

        To use this app, you must:<br>
        <ul>
          <li><b>Remember:</b> trust no one</li>
          <li><b>Understand:</b> the peer you're connecting to is recorded</li>
          <li><b>Know:</b> only your chat is secure</li>
        </ul>

        <p>
            To start chatting, you need <b>full IPv6 support</b> on your router.<br>
            If it's not available — contact your ISP.<br><br>

            Messages are <b>not stored</b>, nothing is stored — everything lives <b>only in your RAM</b>.
        </p>

        <p>
            Exchange copied addresses and the port where you started your server — using the <b>“Start Server”</b> button.<br>
            Once you receive your peer's address, insert their <b>IP and port</b> into the appropriate fields before clicking <b>“Write to”</b>.<br>
            Click the button. <b>Start chatting.</b>
        </p>
    )"));
    ui->ip_text->setText(this->stringSelfHostAddress);
}


// On show, after initing all of the UI, run internal configurations
void MainWindow::showEvent(QShowEvent *event)
{
    QMainWindow::showEvent(event);
    static bool initialized = false;
    if (!initialized) {
        initialized = true;
        PastInit();
    }
}


// Past init complex handler
void MainWindow::PastInit(){
    QString protocolName = "";
    if (!QCoreApplication::instance()->property("local_network").toBool()){
        QString externalIP = request->get("https://api64.ipify.org", true);
        QHostAddress addr;

        if (!addr.setAddress(externalIP)) {
            QMessageBox::warning(this, "Error", tr("Invalid IP address received: ") + externalIP);
            return;
        }
        if (addr.protocol() != QAbstractSocket::IPv6Protocol){
            QMessageBox::warning(this, "Error", tr("Your connection does not provide IPv6 address. Connection is unavailable."));
            // return;
        }
        if (addr.protocol() == QAbstractSocket::IPv4Protocol){
            protocolName = "/IPv4";
        } else if(addr.setAddress(externalIP) && addr.protocol() == QAbstractSocket::IPv6Protocol){
            protocolName = "/IPv6";
        }
        this->stringSelfHostAddress = externalIP + protocolName;
        this->selfHostAddress = addr;
    } else {
        QString address = getLocalIPv6Address();
        qDebug() << "Local IPv6 IP: " << address;
        protocolName = "/IPv6";
        this->selfHostAddress = QHostAddress(address);
        this->stringSelfHostAddress = address + protocolName;
    }
    // Initializing translator
    QSettings settings("config.ini", QSettings::IniFormat);
    QString langCode = settings.value("language", "en").toString();
    switchLanguage(langCode);

    // Set CTRL+Enter handler on messaage field
    auto shortcutReturn = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_Return), ui->send_message_input);
    shortcutReturn->setContext(Qt::WidgetShortcut); // Only for this widget (QTextEdit)

    auto shortcutEnter = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_Enter), ui->send_message_input);
    shortcutEnter->setContext(Qt::WidgetShortcut); // For numpad enter

    connect(shortcutReturn, &QShortcut::activated, this, [this]{
        this->on_send_message_button_clicked();
    });
    connect(shortcutEnter, &QShortcut::activated, this, [this]{
        this->on_send_message_button_clicked();
    });
}

QString MainWindow::getLocalIPv6Address()
{
    const auto interfaces = QNetworkInterface::allInterfaces();

    for (const QNetworkInterface& iface : interfaces) {
        qDebug() << iface.type();
        if (!(iface.flags() & QNetworkInterface::IsUp) ||
            !(iface.flags() & QNetworkInterface::IsRunning) ||
            (iface.flags() & QNetworkInterface::IsLoopBack)) {
            continue;
        }

#ifdef Q_OS_WIN
    if (
        iface.type() != QNetworkInterface::Ethernet &&
        iface.type() != QNetworkInterface::Wifi
        )
        continue;
    QString name = iface.humanReadableName();

    if (name.contains("vEthernet", Qt::CaseInsensitive) ||
        name.contains("VMware", Qt::CaseInsensitive) ||
        name.contains("Virtual", Qt::CaseInsensitive) ||
        name.contains("TAP", Qt::CaseInsensitive))
        continue;
#elif defined(Q_OS_LINUX)
        const QString ifname = iface.name();  // "eth0", "enp3s0", "wlp2s0", "lo", "virbr0", "docker0" ...

        if (ifname.startsWith("lo") ||              // loopback
            ifname.startsWith("virbr") ||           // libvirt bridge
            ifname.startsWith("docker") ||          // docker bridge
            ifname.startsWith("tun") ||             // TUN/TAP
            ifname.startsWith("tap") ||
            ifname.startsWith("veth") ||            // virtual ethernet
            ifname.startsWith("br-") ||             // docker compose bridge
            ifname.startsWith("vmnet") ||           // VMware
            ifname.contains("virtual", Qt::CaseInsensitive))
            continue;
#elif defined(Q_OS_MAC)
    // en0 is base active interface, en1, en2... are additional for ethernet cabel/thunderbolt connection
    if (!iface.name().startsWith("en"))
        continue;
#endif

        int ifaceIndex = iface.index();

        for (const QNetworkAddressEntry& entry : iface.addressEntries()) {
            QHostAddress ip = entry.ip();

            if (ip.protocol() != QAbstractSocket::IPv6Protocol || ip.isLoopback())
                continue;
            if (!ip.toString().startsWith("fe80"))
                continue;

            QString addr = ip.toString().section('%', 0, 0);

#ifdef Q_OS_LINUX
            addr += '%' + iface.name();
#else
            addr += '%' + QString::number(ifaceIndex);
#endif

            return addr;
        }
    }

    return "";
}


// Initial configurations
void MainWindow::InitServer(int serverPort)
{
    // Move server to Thread
    socketServer = new IPv6ChatServer(this->selfHostAddress, serverPort);
    socketServer->moveToThread(socketServerThread);

    connect(socketServer, &IPv6ChatServer::messageArrived, this, &MainWindow::onMessageArrived);
    connect(socketServer, &IPv6ChatServer::clientDisconnected, this, &MainWindow::onServerClientDisconnected);
    connect(socketServer, &IPv6ChatServer::clientConnected, this, &MainWindow::onServerClientConnected);
    // O11: 加密/握手错误以本地化形式提示用户
    connect(socketServer, &IPv6ChatServer::handshakeError, this, [this](const QString& msg){
        QMessageBox::warning(this, tr("Handshake error"), msg);
    });
    connect(socketServer, &IPv6ChatServer::decryptionError, this, [this](const QString& msg){
        qWarning() << "Server decryption error:" << msg;
        // 解密错误一般为单条消息损坏，不打扰用户，仅在状态栏提示
        // 这里以 warning 形式记录，可由 MainWindow 进一步加 status bar
    });

    socketServer->cryptoBackend = baseCrypto->clone();

    socketServerThread->start();

    // Run server into the thread by invoking
    QMetaObject::invokeMethod(socketServer, [=, this]{
        socketServer->run();
    }, Qt::QueuedConnection);

    // O2: 同时启动 IPv6 多播 peer 自动发现
    peerDiscovery = std::make_unique<PeerDiscovery>(this);
    connect(peerDiscovery.get(), &PeerDiscovery::peerFound,
            this, [](const QString& address, int port){
        qDebug() << "Discovery: found peer" << address << ":" << port
                 << "- use address to connect manually";
    });
    connect(peerDiscovery.get(), &PeerDiscovery::peerLost,
            this, [](const QString& address, int port){
        qDebug() << "Discovery: peer lost" << address << ":" << port;
    });
    if (!peerDiscovery->start(this->selfHostAddress, serverPort)) {
        qWarning() << "Discovery: failed to start, only manual connection available";
    }

    if (socketServerThread->isRunning()){
        ui->start_server_button->setDisabled(true);
        ui->port_input->setReadOnly(true);
    }

    // O15: 启动后异步检测防火墙状态
    startFirewallGuidance(serverPort);
}

void MainWindow::InitClient()
{
    clientSocketsThread->start();

    QMetaObject::invokeMethod(clientSocketsThread, [this](){
        socketClient = new IPv6ChatClient();
        socketClient->cryptoBackend = this->baseCrypto->clone();
        connect(socketClient, &IPv6ChatClient::peerConnected, this, &MainWindow::onPeerConnected);
        connect(socketClient, &IPv6ChatClient::peerDisconnected, this, &MainWindow::onPeerDisconnected);
        connect(socketClient, &IPv6ChatClient::messageSent, this, &MainWindow::onMessageSent);
        // O11: 加密/握手错误以本地化形式提示用户
        connect(socketClient, &IPv6ChatClient::handshakeError, this, [this](const QString& msg){
            QMessageBox::warning(this, tr("Connection error"), msg);
        });
    }, Qt::QueuedConnection);
}

void MainWindow::UploadConfig()
{
    QVariantList  splitterSizes = settings->value("splitterSizes", QVariant::fromValue(ui->splitter->sizes())).toList();
    QList<int> sizes;
    for (QVariant& size : splitterSizes) {
        sizes.append(size.toInt());
    }
    ui->splitter->setSizes(sizes);
    if (sizes[0] < 150){
        QGridLayout *ipGrid = qobject_cast<QGridLayout*>(ui->ip_panel->layout());
        QGridLayout *startServerGrid = qobject_cast<QGridLayout*>(ui->start_server_panel->layout());
        this->HideSidebarElements(ipGrid, startServerGrid);
    }
}

void MainWindow::switchLanguage(const QString &langCode)
{
    if (translator) {
        qApp->removeTranslator(translator);
        delete translator;
        translator = nullptr;
    }

    translator = new QTranslator(this);
    qDebug() << "Trying to load translation file:" << ":/translations/" + langCode + ".qm";
    if (translator->load(":/translations/" + langCode + ".qm")) {
        qDebug() << "Loaded translation";
        qApp->installTranslator(translator);
        ui->retranslateUi(this);

        // O10: 删除 Sindarin 后不再需要加载 Tengwar 字体，统一使用系统字体
        qApp->setFont(QFont("Segoe UI, Roboto"));

        settings->setValue("language", langCode);
        settings->sync();
    }else{
        qDebug() << "Failed to load translation";
    }
    qDebug() << "Language chosen: " << langCode;
    this->applyStyleSheet(langCode);
    this->initializeTranslatingTexts();
}

void MainWindow::applyStyleSheet(QString langCode)
{
    QFile file(":/assets/styles/mainwindow.qss");
    if (!file.open(QFile::ReadOnly | QFile::Text)) {
        qDebug() << "Failed to load stylesheet";
        return;
    }

    qDebug() << "Stylesheet loaded";

    QString style = QString::fromUtf8(file.readAll());
    file.close();

    // O10: 删除 Sindarin 后统一使用系统默认字体
    QString fontName = "\"Segoe UI\", \"Roboto\", sans-serif";
    style.replace("{{font}}", fontName);

    qApp->setStyleSheet(style);
}

// Chat pages changing handler
void MainWindow::openChatPage(const QString& chatID, const QString& clientID)
{
    // Clear: previous chat models from RAM
    if (chatID != currentChatID){
        if (currentMessageModel){
            ui->chat_list->setModel(nullptr);
            delete currentMessageModel;
            currentMessageModel = nullptr;
        }

        QVariantMap iconOptions;
        if (connectedClients.contains(chatID)) {
            iconOptions.insert("color-disabled", QColor("#03da5a"));
            isCurrentChatClientOnline = true;
            ui->status_text->setIcon(awesome->icon(fa::fa_solid, fa::fa_check, iconOptions));
            ui->status_text->setText(tr("Online"));
        } else {
            iconOptions.insert("color-disabled", QColor("#d32f2f"));
            isCurrentChatClientOnline = false;
            ui->status_text->setIcon(awesome->icon(fa::fa_solid, fa::fa_times, iconOptions));
            ui->status_text->setText(tr("Offline"));
        }

        currentChatID = chatID;
        ui->clientID_text->setText(clientID);

        // Set up messages in RAM for all chats (to store them as in DB)
        setUpMessagesForChatInRAM(chatID);

        currentContactModel->setActive(chatID);
        // 0 for chat page, initital is 1 (just in case)
        if(ui->chat_stacked_widget->currentIndex()){
            ui->chat_stacked_widget->setCurrentIndex(0);
        }
    }
}

void MainWindow::setUpMessagesForChatInRAM(const QString& chatID)
{
    if (!messages.contains(chatID)) {
        messages[chatID] = QList<Message>();
    }

    // O1: 若该 chat 尚未加载过，从持久化层加载历史消息
    // 注意：messages[chatID] 一旦非空说明本会话已加载过，避免重复加载
    if (messages[chatID].isEmpty() && messageStore && messageStore->isEnabled()) {
        QList<Message> loaded = messageStore->loadMessages(chatID);
        if (!loaded.isEmpty()) {
            messages[chatID] = loaded;
            qDebug() << "MessageStore: loaded" << loaded.size() << "messages for chat" << chatID;
        }
    }

    currentMessageModel = new MessageListModel(this);
    if (messages.contains(chatID))
        currentMessageModel->setMessages(messages[chatID]);

    ui->chat_list->setModel(currentMessageModel);
}

// Custom emited thread Signals

// Client
void MainWindow::onPeerConnected(const QString& clientID)
{
    QMessageBox::information(this, "INFO", tr("Connected to the peer: ") + clientID);

    // Save clientID to use later in DB/File/Cache.
    QString chatID = makeChatID(selfHostAddress.toString(), stripPort(clientID));
    openChatPage(chatID, clientID);
}

void MainWindow::onPeerDisconnected(const QString& clientID)
{
    QMessageBox::warning(this, "WARNING", tr("No connection to peer: ") + clientID);
}

void MainWindow::onMessageSent(const QString& clientID, const QByteArray& message)
{
    qDebug() << "Message sent: " << message << clientID;
    QString chatID = makeChatID(selfHostAddress.toString(), stripPort(clientID));
    Message msg{clientID, QString::fromUtf8(message), false};
    messages[chatID].append(msg);

    // O1: 持久化到 SQLite（加密后写盘）
    if (messageStore && messageStore->isEnabled()) {
        messageStore->saveMessage(chatID, msg);
    }

    currentContactModel->onNewMessage(chatID, clientID, message);

    if (currentMessageModel)
        currentMessageModel->addMessage({clientID, QString::fromUtf8(message), false});

    ui->send_message_input->clear();

    ui->chat_list->scrollToBottom();
    currentContactModel->setActive(chatID);
}

//Server
void MainWindow::onMessageArrived(const QString& clientID, const QByteArray& message)
{
    qDebug() << "Message arrived: " << message << clientID;
    QString chatID = makeChatID(selfHostAddress.toString(), stripPort(clientID));
    Message msg{clientID, QString::fromUtf8(message), true};
    messages[chatID].append(msg);

    // O1: 持久化到 SQLite（加密后写盘）
    if (messageStore && messageStore->isEnabled()) {
        messageStore->saveMessage(chatID, msg);
    }

    currentContactModel->onNewMessage(chatID, clientID, message);

    if (chatID == currentChatID){
        if (currentMessageModel)
            currentMessageModel->addMessage({clientID, QString::fromUtf8(message), true});

        ui->chat_list->scrollToBottom();
        currentContactModel->setActive(chatID);
    }
}

void MainWindow::onServerClientConnected(const QString& clientID)
{
    QString chatID = makeChatID(selfHostAddress.toString() , stripPort(clientID));
    if (chatID == currentChatID){
        QVariantMap iconOptions;
        iconOptions.insert("color-disabled", QColor("#03da5a"));
        isCurrentChatClientOnline = true;
        ui->status_text->setIcon(awesome->icon(fa::fa_solid, fa::fa_check, iconOptions));
        ui->status_text->setText(tr("Online"));
    }
    connectedClients.insert(chatID);
}

void MainWindow::onServerClientDisconnected(const QString& clientID)
{
    QString chatID = makeChatID(selfHostAddress.toString(), stripPort(clientID));
    connectedClients.remove(chatID);
    if (chatID == currentChatID){
        QVariantMap iconOptions;
        iconOptions.insert("color-disabled", QColor("#d32f2f"));
        isCurrentChatClientOnline = false;
        ui->status_text->setIcon(awesome->icon(fa::fa_solid, fa::fa_times, iconOptions));
        ui->status_text->setText(tr("Offline"));
        QString message = tr("Peer is disconnected, if peer will be active again, just push the button \"Write to\" using actual port.");
        messages[chatID].append({tr("System"), message, true});
        currentMessageModel->addMessage({tr("System"), message, true});
    }
}

// Classic UI slot signals
void MainWindow::on_start_server_button_clicked()
{
    bool isValid = true;
    int port = ui->port_input->text().toInt(&isValid);

    if(30000 > port || port > 65535){
        isValid = false;
    }

    if(!isValid){
        ui->port_input->setStyleSheet("border: 1px solid #dc3545");
        QMessageBox::warning(this, "Error", tr("Provide port in range of 30000-65535"));
        return;
    }

    InitServer(port);
    InitClient();
    ui->write_to_button->setEnabled(true);
}

void MainWindow::on_port_input_textChanged()
{
    ui->port_input->setStyleSheet("border: 1px solid white");
}

void MainWindow::on_write_to_button_clicked()
{
    bool isValid = true;
    int port = ui->client_port_input->text().toInt(&isValid);

    if(30000 > port || port > 65535){
        isValid = false;
    }

    if(!isValid){
        QMessageBox::warning(this, "Error", tr("Provide port in range of 30000-65535"));
        return;
    }

    QHostAddress clientAddress;
    QString clientIP = ui->client_address_input->text();

    if (clientIP.trimmed().isEmpty()) {
        QMessageBox::warning(this, "Error", tr("Client IP cannot be empty"));
        return;
    }
    if (!clientAddress.setAddress(clientIP)) {
        QMessageBox::warning(this, "Error", tr("Invalid IP address received: ") + clientIP);
        return;
    }
    if (clientAddress.protocol() != QAbstractSocket::IPv6Protocol){
        QMessageBox::warning(this, "Error", tr("Address is not IPv6 address. Connection is unavailable."));
        return;
    }

    QMetaObject::invokeMethod(clientSocketsThread, [this, clientAddress, port](){
        socketClient->connectToPeer(clientAddress.toString(), port);
    }, Qt::QueuedConnection);
}

void MainWindow::on_port_input_returnPressed()
{
    on_start_server_button_clicked();
}

void MainWindow::on_client_address_input_returnPressed()
{
    on_write_to_button_clicked();
}

void MainWindow::on_client_port_input_returnPressed()
{
    on_write_to_button_clicked();
}

void MainWindow::on_send_message_button_clicked()
{
    QString message = ui->send_message_input->toPlainText();
    if (message.trimmed().isEmpty()){
        ui->send_message_input->setFocus();
        return;
    }

    QString clientID = ui->clientID_text->text();
    QString selfHost = selfHostAddress.toString() + ":" + ui->port_input->text();
    QMetaObject::invokeMethod(clientSocketsThread, [this, selfHost, clientID, message](){
        socketClient->sendMessage(selfHost, clientID, message.toUtf8());
    }, Qt::QueuedConnection);
}

// UI handlers
void MainWindow::on_splitter_splitterMoved(int pos, int index)
{
    int sidebarWidth = ui->sidebar->width();
    QGridLayout *ipGrid = qobject_cast<QGridLayout*>(ui->ip_panel->layout());
    QGridLayout *startServerGrid = qobject_cast<QGridLayout*>(ui->start_server_panel->layout());
    if (sidebarWidth < 150){
        this->HideSidebarElements(ipGrid, startServerGrid);
    }else{
        this->ShowSidebarElements(ipGrid, startServerGrid);
    }
}

void MainWindow::HideSidebarElements(QGridLayout *ipGrid, QGridLayout *startServerGrid)
{
    ui->your_ip_label->setVisible(false);
    ui->port_input->setVisible(false);
    ui->port_warning->setVisible(false);
    ui->client_port_input->setVisible(false);
    ui->client_address_input->setVisible(false);
    ui->write_to_button->setVisible(false);
    ipGrid->setColumnStretch(0, 1);
    ipGrid->update();
    startServerGrid->setColumnStretch(1, 0);
    startServerGrid->update();

}

void MainWindow::ShowSidebarElements(QGridLayout *ipGrid, QGridLayout *startServerGrid)
{
    ui->your_ip_label->setVisible(true);
    ui->port_input->setVisible(true);
    ui->port_warning->setVisible(true);
    ui->client_port_input->setVisible(true);
    ui->client_address_input->setVisible(true);
    ui->write_to_button->setVisible(true);
    ipGrid->setColumnStretch(1, 6);
    ipGrid->update();
    startServerGrid->setColumnStretch(1, 6);
    startServerGrid->update();
}

void MainWindow::on_copy_server_button_clicked()
{
    QClipboard *clipboard = QGuiApplication::clipboard();
    clipboard->setText(ui->ip_text->text().replace("/IPv6", "").replace("/IPv4", ""));

    showToolTipOnPosition(
        ui->copy_server_button,
        tr("Copied to clipboard")
    );
}

void MainWindow::onContactClicked(const QModelIndex& index)
{
    if (!index.isValid())
        return;

    QString clientID = index.data(ContactListModel::ClientIDRole).toString();
    QString chatID = index.data(ContactListModel::ChatIDRole).toString();
    openChatPage(chatID, clientID);
}

// O17: 右键菜单触发，从触发它的 QAction 中拿到 index 然后显示 Safety Number
void MainWindow::onShowSafetyNumberAction()
{
    QAction* action = qobject_cast<QAction*>(sender());
    if (!action) return;
    QModelIndex index = action->data().toModelIndex();
    if (!index.isValid()) return;

    QString clientID = index.data(ContactListModel::ClientIDRole).toString();
    QString chatID = index.data(ContactListModel::ChatIDRole).toString();
    showSafetyNumber(chatID, clientID);
}

// O17: 查找指定 clientID 的 peer 公钥
// 客户端侧（用户主动连出去的连接）优先；找不到再查服务端侧（对端连入的连接）
QByteArray MainWindow::lookupPeerPublicKey(const QString& clientID)
{
    if (socketClient) {
        QByteArray pk = socketClient->peerPublicKey(clientID);
        if (!pk.isEmpty()) return pk;
    }
    if (socketServer) {
        return socketServer->peerPublicKey(clientID);
    }
    return {};
}

// O17: 查找本端公钥。优先服务端（被连接方）的临时密钥对
QByteArray MainWindow::lookupLocalPublicKey()
{
    if (socketServer) {
        QByteArray pk = socketServer->localPublicKey();
        if (!pk.isEmpty()) return pk;
    }
    if (socketClient) {
        return socketClient->localPublicKey();
    }
    return {};
}

// O17: 弹出对话框显示两端公钥派生的 Safety Number，并允许用户输入对端告知的 Safety Number 比对
void MainWindow::showSafetyNumber(const QString& chatID, const QString& clientID)
{
    QByteArray localPK = lookupLocalPublicKey();
    QByteArray remotePK = lookupPeerPublicKey(clientID);

    if (localPK.isEmpty() || remotePK.isEmpty()) {
        QMessageBox::information(this, tr("Safety Number"),
            tr("Safety Number is not available yet.\n\n"
               "Please establish an encrypted session with this peer first "
               "(complete a handshake)."));
        return;
    }

    QString sn = SafetyNumber::compute(localPK, remotePK);
    if (sn.isEmpty()) {
        QMessageBox::warning(this, tr("Safety Number"),
            tr("Failed to compute Safety Number."));
        return;
    }

    QString localFingerprint = KeyExchange::computeFingerprint(localPK);
    QString remoteFingerprint = KeyExchange::computeFingerprint(remotePK);

    QString details = QString(
        "<b>%1</b><br>"
        "<code style='font-size:14pt; letter-spacing:2px;'>%2</code>"
        "<br><br>"
        "<small>%3</small><br>"
        "<code>%4</code><br><br>"
        "<small>%5</small><br>"
        "<code>%6</code>"
    ).arg(tr("Your Safety Number with this peer is:"))
     .arg(sn)
     .arg(tr("Your key fingerprint:"))
     .arg(localFingerprint)
     .arg(tr("Peer key fingerprint:"))
     .arg(remoteFingerprint);

    QMessageBox box(this);
    box.setWindowTitle(tr("Safety Number"));
    box.setText(details);
    box.setTextFormat(Qt::RichText);
    box.setStandardButtons(QMessageBox::Ok);
    box.setDefaultButton(QMessageBox::Ok);

    // 加一个"验证"按钮，让用户输入对方告知的 SN 进行比对
    QPushButton* verifyBtn = box.addButton(tr("Verify..."), QMessageBox::ActionRole);
    box.exec();

    if (box.clickedButton() == verifyBtn) {
        bool ok = false;
        QString userSn = QInputDialog::getText(
            this, tr("Verify Safety Number"),
            tr("Enter the Safety Number as read out by the peer:"),
            QLineEdit::Normal, QString(), &ok);
        if (ok && !userSn.isEmpty()) {
            if (SafetyNumber::equals(userSn, sn)) {
                QMessageBox::information(this, tr("Verify Safety Number"),
                    tr("✅ Safety Numbers match.\n"
                       "Your communication is end-to-end encrypted and not "
                       "intercepted by a third party."));
            } else {
                QMessageBox::warning(this, tr("Verify Safety Number"),
                    tr("⚠️ Safety Numbers do NOT match.\n"
                       "Your communication may be intercepted.\n"
                       "Please verify the channel you used to exchange "
                       "Safety Numbers is trustworthy."));
            }
        }
    }
}

void MainWindow::showToolTipOnPosition(QWidget* widget, QString text)
{
    QPoint globalPos = widget->mapToGlobal(QPoint(widget->width() / 2, 0));
    QToolTip::showText(globalPos, text, widget);

    QTimer::singleShot(1500, []() {
        QToolTip::hideText();
    });
}

// O15: 防火墙引导
// 在服务端启动后异步检测防火墙状态，若发现防火墙启用且端口不可达，
// 弹出友好对话框提示用户一键添加防火墙规则。
void MainWindow::startFirewallGuidance(int serverPort)
{
    if (!firewallHelper) {
        firewallHelper = new FirewallHelper(this);
        connect(firewallHelper, &FirewallHelper::detectionFinished,
                this, &MainWindow::onFirewallDetectionFinished,
                Qt::QueuedConnection);
    }
    firewallHelper->detectAsync(serverPort);
}

void MainWindow::onFirewallDetectionFinished(FirewallHelper::Platform platform,
                                              FirewallHelper::FirewallState state,
                                              FirewallHelper::PortCheckResult portResult,
                                              int serverPort)
{
    QString platformName;
    switch (platform) {
        case FirewallHelper::Platform::Windows:        platformName = "Windows"; break;
        case FirewallHelper::Platform::Linux_Ufw:      platformName = "Linux (UFW)"; break;
        case FirewallHelper::Platform::Linux_Firewalld:platformName = "Linux (firewalld)"; break;
        case FirewallHelper::Platform::Linux_NotManaged:platformName = "Linux (unmanaged firewall)"; break;
        case FirewallHelper::Platform::MacOs:          platformName = "macOS"; break;
        default:                                       platformName = "Unknown"; break;
    }

    qDebug() << "FirewallHelper: platform=" << platformName
             << " state=" << static_cast<int>(state)
             << " portReachable=" << portResult.locallyReachable
             << " detail=" << portResult.detail;

    // 端口本身可达，无需任何提示
    if (portResult.locallyReachable && state != FirewallHelper::FirewallState::Enabled) {
        qDebug() << "FirewallHelper: port reachable, no guidance needed";
        return;
    }

    // 防火墙关闭或端口可达：不弹窗
    if (state == FirewallHelper::FirewallState::Disabled ||
        state == FirewallHelper::FirewallState::Unknown) {
        if (portResult.locallyReachable) {
            return;
        }
    }

    // 端口不可达 OR 防火墙启用：弹出引导
    QString title = tr("Firewall Configuration Required");
    QString body;
    QString addBtnText;

    if (state == FirewallHelper::FirewallState::Enabled && !portResult.locallyReachable) {
        body = tr(
            "Your system firewall (%1) appears to be enabled and the server port %2 "
            "could not be bound locally.<br><br>"
            "Would you like to add an inbound firewall rule for TCP port %2? "
            "This typically requires administrator privileges."
        ).arg(platformName).arg(serverPort);
        addBtnText = tr("Add firewall rule");
    } else if (state == FirewallHelper::FirewallState::Enabled) {
        body = tr(
            "Your system firewall (%1) is enabled. Fantom-Chat may need an inbound "
            "rule for TCP port %2 to accept incoming peer connections.<br><br>"
            "Would you like to add the rule now? This typically requires administrator privileges."
        ).arg(platformName).arg(serverPort);
        addBtnText = tr("Add firewall rule");
    } else if (state == FirewallHelper::FirewallState::NotManaged) {
        body = tr(
            "Your system appears to use an unmanaged firewall (e.g. raw iptables/nftables). "
            "Fantom-Chat cannot add rules automatically.<br><br>"
            "Please manually allow inbound TCP port %1 for IPv6 traffic."
        ).arg(serverPort);
        addBtnText = tr("OK");
    } else if (!portResult.locallyReachable) {
        body = tr(
            "Server port %1 could not be bound locally: %2.<br><br>"
            "Please check whether another process is using this port, "
            "or pick a different port in the range 30000-65535."
        ).arg(serverPort).arg(portResult.detail);
        addBtnText = tr("OK");
    } else {
        return;
    }

    QMessageBox box(this);
    box.setWindowTitle(title);
    box.setTextFormat(Qt::RichText);
    box.setText(body);
    box.setIcon(QMessageBox::Warning);

    QPushButton* addBtn = nullptr;
    box.addButton(tr("Skip"), QMessageBox::RejectRole);
    addBtn = box.addButton(addBtnText, QMessageBox::AcceptRole);
    box.setDefaultButton(addBtn);
    box.exec();

    if (box.clickedButton() == addBtn &&
        (state == FirewallHelper::FirewallState::Enabled ||
         state == FirewallHelper::FirewallState::NotManaged)) {
        // 仅在防火墙启用且本工具可管理时尝试自动添加
        if (state == FirewallHelper::FirewallState::Enabled) {
            QString ruleName = QString("FantomChat TCP %1").arg(serverPort);
            bool dispatched = firewallHelper->requestAddRule(serverPort, ruleName);
            if (dispatched) {
                QMessageBox::information(this, tr("Firewall"),
                    tr("Firewall rule request has been dispatched. "
                       "If a privilege elevation prompt appears, please approve it. "
                       "After adding the rule, you may need to restart the server."));
            } else {
                QMessageBox::warning(this, tr("Firewall"),
                    tr("Failed to dispatch firewall rule request. "
                       "Please add the rule manually:<br>"
                       "Windows: <code>netsh advfirewall firewall add rule name=\"FantomChat\" "
                       "dir=in action=allow protocol=TCP localport=%1</code><br>"
                       "Linux (ufw): <code>sudo ufw allow %1/tcp</code><br>"
                       "Linux (firewalld): <code>sudo firewall-cmd --add-port=%1/tcp --permanent</code>")
                    .arg(serverPort));
            }
        }
    }
}

