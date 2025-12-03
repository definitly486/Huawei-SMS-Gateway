#include "mainwindow.h"
#include <QApplication>
#include <QScreen>
#include <QMessageBox>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <ctime>
#include <cstring>
#include <cstdlib>

// ---------------------------------------------------------------------------
// СТАТИЧЕСКИЕ ПЕРЕМЕННЫЕ (один экземпляр на весь процесс)
// ---------------------------------------------------------------------------
CURL                *MainWindow::ch       = nullptr;
CURLcode             MainWindow::res      = CURLE_OK;
struct curl_slist   *MainWindow::headers  = nullptr;
int                  MainWindow::ContLen  = 0;
char                 MainWindow::SessionID[1024] = {0};
char                 MainWindow::Buff[BuffSize]  = {0};
char                 MainWindow::Token[36][64]   = {{0}};
MainWindow::MemoryStruct MainWindow::chunk = {Buff, 0};

// ---------------------------------------------------------------------------
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ---------------------------------------------------------------------------
char *MainWindow::bin2hex(unsigned char *s, long L)
{
    static char hex[4096];
    long i, l = 0;
    for (i = 0; i < L; i++) l += sprintf(&hex[l], "%02x", s[i]);
    hex[l] = 0;
    return hex;
}

char *MainWindow::hex2bin(char *s)
{
    static char bin[2048];
    unsigned int v, l = 0;
    while (*s) {
        sscanf(s, "%2x", &v);
        bin[l++] = (char)v;
        s += 2;
    }
    bin[l] = 0;
    return bin;
}

// ---------------------------------------------------------------------------
// CALLBACKS CURL
// ---------------------------------------------------------------------------
size_t MainWindow::WriteHeaderCallback(void *contents, size_t size, size_t nmemb, void */*userp*/)
{
    char *p = (char*)contents;
    size_t len = size * nmemb;

    if (len > 15 && !memcmp(p, "Content-Length:", 15))
        ContLen = atoi(p + 15);
    else if (len > 11 && !memcmp(p, "Set-Cookie:", 11))
        snprintf(SessionID, sizeof(SessionID), "%.*s", (int)(len - 13), p + 12);
    else if (len > 27 && !memcmp(p, "__RequestVerificationToken:", 27)) {
        char *t = strtok(p + 27, "#");
        for (int i = 0; t && i < 36; i++) {
            snprintf(Token[i], sizeof(Token[i]), "__RequestVerificationToken:%s", t);
            t = strtok(nullptr, "#");
        }
    }
    return len;
}

size_t MainWindow::WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    MemoryStruct *mem = (MemoryStruct*)userp;

    if (mem->size + realsize >= BuffSize) return 0;          // защита от переполнения
    memcpy(mem->memory + mem->size, contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

// ---------------------------------------------------------------------------
// HTTP-ЗАПРОСЫ
// ---------------------------------------------------------------------------
int MainWindow::GET(const char *Url)
{
    char url[256];
    snprintf(url, sizeof(url), "%s%s", MODEM, Url);
    curl_easy_setopt(ch, CURLOPT_URL, url);
    curl_easy_setopt(ch, CURLOPT_COOKIE, SessionID);
    curl_easy_setopt(ch, CURLOPT_POST, 0L);
    chunk.size = 0;
    res = curl_easy_perform(ch);
    return (res == CURLE_OK);
}

int MainWindow::POST(const char *post, const char *Url)
{
    char url[256];
    snprintf(url, sizeof(url), "%s%s", MODEM, Url);
    curl_easy_setopt(ch, CURLOPT_URL, url);
    curl_easy_setopt(ch, CURLOPT_POSTFIELDS, post);
    curl_easy_setopt(ch, CURLOPT_COOKIE, SessionID);

    headers = nullptr;
    headers = curl_slist_append(headers, Token[0]);
    headers = curl_slist_append(headers, "Connection: keep-alive");
    curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);

    chunk.size = 0;
    res = curl_easy_perform(ch);

    curl_slist_free_all(headers);
    curl_easy_setopt(ch, CURLOPT_HTTPHEADER, nullptr);
    return (res == CURLE_OK);
}

int MainWindow::SesTokInfo()
{
    if (!GET("/api/webserver/SesTokInfo")) return 0;
    char *s = strstr(Buff, "<SesInfo>"), *e = strstr(Buff, "</SesInfo>");
    if (!s || !e) return 0;
    snprintf(SessionID, sizeof(SessionID), "%.*s", (int)(e - s - 9), s + 9);

    s = strstr(Buff, "<TokInfo>"); e = strstr(Buff, "</TokInfo>");
    if (!s || !e) return 0;
    snprintf(Token[0], sizeof(Token[0]), "__RequestVerificationToken:%.*s", (int)(e - s - 9), s + 9);
    return 1;
}

// ---------------------------------------------------------------------------
// АВТОРИЗАЦИЯ (SCRAM)
// ---------------------------------------------------------------------------
int MainWindow::login(const char *user, const char *password)
{
    unsigned int outlen;
    unsigned char salt[32], saltedPwd[32], clientKey[32], storedKey[32],
                  clientProof[32], signature[32];
    char post[2048], authMsg[2048], servernonce[256];

    curl_global_init(CURL_GLOBAL_ALL);
    ch = curl_easy_init();
    curl_easy_setopt(ch, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION,  WriteMemoryCallback);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA,      (void*)&chunk);
    curl_easy_setopt(ch, CURLOPT_TIMEOUT,       8L);
    curl_easy_setopt(ch, CURLOPT_CONNECTTIMEOUT,8L);
    curl_easy_setopt(ch, CURLOPT_HTTP_VERSION,  CURL_HTTP_VERSION_1_1);

    if (!SesTokInfo()) return 0;

    // firstNonce
    unsigned char firstNonce[32];
    SHA256_CTX ctx;
    time_t t = time(nullptr);
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (unsigned char*)ctime(&t), 26);
    SHA256_Update(&ctx, (unsigned char*)&ts, sizeof(ts));
    SHA256_Final(firstNonce, &ctx);

    snprintf(post, sizeof(post),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<request><username>%s</username><firstnonce>%s</firstnonce><mode>1</mode></request>",
        user, bin2hex(firstNonce, 32));

    if (!POST(post, "/api/user/challenge_login")) return 0;

    // salt
    char *p = strstr(Buff, "<salt>"); char *q = strstr(Buff, "</salt>");
    if (!p || !q) return 0;
    memcpy(salt, hex2bin(strncpy(post, p+6, q-p-6)), 32);

    // servernonce
    p = strstr(Buff, "<servernonce>"); q = strstr(Buff, "</servernonce>");
    if (!p || !q) return 0;
    strncpy(servernonce, p+13, q-p-13); servernonce[q-p-13] = 0;

    // authMsg
    int alen = snprintf(authMsg, sizeof(authMsg), "%s,%s,%s",
                        bin2hex(firstNonce,32), servernonce, servernonce);

    // SaltedPassword
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, 32, 100,
                      EVP_sha256(), 32, saltedPwd);

    // ClientKey → StoredKey
    HMAC(EVP_sha256(), "Client Key", 10, saltedPwd, 32, clientKey, &outlen);
    SHA256(clientKey, 32, storedKey);

    // Signature
    HMAC(EVP_sha256(), authMsg, alen, storedKey, 32, signature, &outlen);

    // ClientProof
    for (int i = 0; i < 32; i++) clientProof[i] = clientKey[i] ^ signature[i];

    // final request
    snprintf(post, sizeof(post),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<request><clientproof>%s</clientproof><finalnonce>%s</finalnonce></request>",
        bin2hex(clientProof,32), servernonce);

    if (!POST(post, "/api/user/authentication_login")) return 0;
    if (!GET("/api/user/state-login")) return 0;
    return (strstr(Buff, "<State>0</State>") != nullptr);
}

int MainWindow::logout()
{
    const char *post = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><Logout>1</Logout></request>";
    POST(post, "/api/user/logout");
    if (ch) { curl_easy_cleanup(ch); ch = nullptr; }
    curl_global_cleanup();
    return 1;
}

// ---------------------------------------------------------------------------
// SMS
// ---------------------------------------------------------------------------
char* MainWindow::ListSmsIn()
{
    const char *post =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<request><PageIndex>1</PageIndex><ReadCount>50</ReadCount>"
        "<BoxType>1</BoxType><SortType>0</SortType><Ascending>0</Ascending>"
        "<UnreadPreferred>0</UnreadPreferred></request>";

    if (!POST(post, "/api/sms/sms-list")) return nullptr;
    return Buff;
}

bool MainWindow::DeleteSms(int smsIndex)
{
    char post[256];
    snprintf(post, sizeof(post),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<request><Index>%d</Index></request>", smsIndex);

    if (!POST(post, "/api/sms/delete-sms")) return false;
    return (strstr(Buff, "<response>OK</response>") != nullptr);
}

bool MainWindow::DeleteAllSms()
{
    char *data = ListSmsIn();
    if (!data) return false;

    XMLDocument doc;
    if (doc.Parse(data) != XML_SUCCESS) return false;

    XMLElement *messages = doc.FirstChildElement("response")
                                ->FirstChildElement("Messages");
    if (!messages) return true;   // уже пусто

    std::vector<int> idxs;
    for (XMLElement *msg = messages->FirstChildElement("Message"); msg; msg = msg->NextSiblingElement("Message")) {
        XMLElement *idxEl = msg->FirstChildElement("Index");
        if (idxEl && idxEl->GetText()) idxs.push_back(atoi(idxEl->GetText()));
    }

    bool allOk = true;
    for (int i : idxs)
        if (!DeleteSms(i)) allOk = false;

    return allOk;
}

QString MainWindow::parseSmsXml(const char *xmlData)
{
    QString result;
    XMLDocument doc;
    if (doc.Parse(xmlData) != XML_SUCCESS) return "Ошибка парсинга XML";

    XMLElement *resp = doc.FirstChildElement("response");
    if (!resp) return "Нет <response>";

    XMLElement *msgs = resp->FirstChildElement("Messages");
    if (!msgs || !msgs->FirstChildElement("Message"))
        return "Входящих SMS нет";

    for (XMLElement *m = msgs->FirstChildElement("Message"); m; m = m->NextSiblingElement("Message")) {
        const char *phone = m->FirstChildElement("Phone")   ? m->FirstChildElement("Phone")->GetText()   : "неизвестно";
        const char *date  = m->FirstChildElement("Date")    ? m->FirstChildElement("Date")->GetText()    : "";
        const char *text  = m->FirstChildElement("Content") ? m->FirstChildElement("Content")->GetText() : "";

        result += QString("От: %1\nДата: %2\n%3\n\n")
                     .arg(phone).arg(date).arg(text);
    }
    return result.trimmed();
}

// ---------------------------------------------------------------------------
// GUI
// ---------------------------------------------------------------------------
MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent)
{
    setWindowTitle("Huawei SMS Gateway");
    setWindowIcon(QIcon(":/resources/resources/sms.png"));

    QWidget *central = new QWidget(this);
    QVBoxLayout *vlay = new QVBoxLayout(central);

    // SMS-текст
    textSms = new QTextEdit;
    textSms->setReadOnly(true);
    textSms->setFont(QFont("Consolas", 10));
    textSms->setPlaceholderText("Список SMS появится здесь...");

    // Кнопки
    btnGetSms       = new QPushButton("Получить SMS");
    btnDeleteAll    = new QPushButton("Удалить все SMS");
    btnRefreshToken = new QPushButton("Переподключиться");

    // Стили
    btnGetSms->setStyleSheet(
        "QPushButton { background:#4CAF50; color:white; font-weight:bold; border-radius:8px; padding:12px; }"
        "QPushButton:pressed { background:#45a049; }");
    btnDeleteAll->setStyleSheet(
        "QPushButton { background:#f44336; color:white; font-weight:bold; border-radius:8px; padding:12px; }"
        "QPushButton:pressed { background:#d32f2f; }");
    btnRefreshToken->setStyleSheet(
        "QPushButton { background:#2196F3; color:white; font-weight:bold; border-radius:8px; padding:12px; }"
        "QPushButton:pressed { background:#1976D2; }");

    // Статус
    labelStatus = new QLabel("Готов");
    labelStatus->setAlignment(Qt::AlignCenter);
    labelStatus->setStyleSheet("color:#777; font-style:italic; padding:8px;");

    // Горизонтальная строка кнопок
    QHBoxLayout *btnLay = new QHBoxLayout;
    btnLay->addWidget(btnGetSms);
    btnLay->addWidget(btnDeleteAll);
    btnLay->addWidget(btnRefreshToken);

    vlay->addWidget(textSms);
    vlay->addLayout(btnLay);
    vlay->addWidget(labelStatus);
    vlay->setContentsMargins(20,20,20,20);
    vlay->setSpacing(15);

    setCentralWidget(central);
    resize(860, 680);

    // Центрируем окно
    QRect scr = QGuiApplication::primaryScreen()->availableGeometry();
    move((scr.width()  - width())  / 2,
         (scr.height() - height()) / 2);

    // Сигналы
    connect(btnGetSms,       &QPushButton::clicked, this, &MainWindow::on_btnGetSms_clicked);
    connect(btnDeleteAll,    &QPushButton::clicked, this, &MainWindow::on_btnDeleteAll_clicked);
    connect(btnRefreshToken, &QPushButton::clicked, this, &MainWindow::on_btnRefreshToken_clicked);
}

MainWindow::~MainWindow() { logout(); }

// ---------------------------------------------------------------------------
// СЛОТЫ
// ---------------------------------------------------------------------------
void MainWindow::on_btnGetSms_clicked()
{
    labelStatus->setText("Вход в модем...");
    btnGetSms->setEnabled(false);
    textSms->clear();

    system("doas service ipfw stop 2>/dev/null || true");

    if (login("admin", "admin")) {
        char *data = ListSmsIn();
        if (data) {
            textSms->setText(parseSmsXml(data));
            labelStatus->setText("SMS получены");
        } else {
            textSms->setText("Не удалось получить список SMS");
            labelStatus->setText("Ошибка получения SMS");
        }
    } else {
        textSms->setText("Ошибка авторизации!\nПроверьте подключение к модему.");
        labelStatus->setText("Не удалось войти");
    }

    system("doas service ipfw start 2>/dev/null || true");
    btnGetSms->setEnabled(true);
}

void MainWindow::on_btnDeleteAll_clicked()
{
    auto r = QMessageBox::question(this, "Удаление",
        "Удалить ВСЕ входящие SMS?\n\nЭто действие необратимо!", QMessageBox::Yes|QMessageBox::No);
    if (r != QMessageBox::Yes) return;

    btnDeleteAll->setEnabled(false);
    btnDeleteAll->setText("Удаление...");
    labelStatus->setText("Удаление сообщений...");

    bool ok = DeleteAllSms();

    btnDeleteAll->setText("Удалить все SMS");
    btnDeleteAll->setEnabled(true);

    if (ok) {
        textSms->setText("Все SMS успешно удалены.");
        labelStatus->setText("Готово — всё удалено");
    } else {
        QMessageBox::warning(this, "Ошибка", "Не все сообщения удалось удалить.");
        labelStatus->setText("Ошибка удаления");
    }

    on_btnGetSms_clicked();   // обновляем список
}

void MainWindow::on_btnRefreshToken_clicked()
{
    labelStatus->setText("Переподключение...");
    logout();
    if (login("admin", "admin"))
        labelStatus->setText("Переподключено успешно");
    else
        labelStatus->setText("Ошибка переподключения");
}