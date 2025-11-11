#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <ctime>
#include <cstring>
#include <QScreen> 

CURL *MainWindow::ch = nullptr;
CURLcode MainWindow::res;
struct curl_slist *MainWindow::headers = nullptr;
int MainWindow::ContLen = 0;
char MainWindow::SessionID[1024] = {0};
char MainWindow::Buff[BuffSize];
char MainWindow::Token[36][34+27] = {{0}};
MainWindow::MemoryStruct MainWindow::chunk = {Buff, 0};

// ---------- Конвертация ----------
char *MainWindow::bin2hex(unsigned char *s, long L)
{
    static char hex[2048];
    long i, l = 0;
    for (i = 0; i < L; i++) l += sprintf(&hex[l], "%02x", 0xFF & (*(s + i)));
    hex[l] = 0;
    return hex;
}

char *MainWindow::hex2bin(char *s)
{
    static char bin[2048];
    unsigned int i, e, l = 0, L = strlen(s);
    for (i = 0; i < L; i += 2) { sscanf(s + i, "%02x", &e); bin[l++] = (char)e; }
    bin[l] = 0;
    return bin;
}

// ---------- Колбэки ----------
size_t MainWindow::WriteHeaderCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    char *p = (char *)contents;
    size_t realsize = size * nmemb;

    if (!memcmp(p, "Content-Length:", 15)) ContLen = atoi(p + 15);
    else if (!memcmp(p, "Set-Cookie:", 11))
        sprintf(SessionID, "%*.*s", (int)(realsize - 2 - 11), (int)(realsize - 2 - 11), (p + 11));
    else if (!memcmp(p, "__RequestVerificationToken:", 27))
    {
        int i; char *t;
        t = strtok(p + 27, "#");
        for (i = 0; t && i < 36; i++)
        {
            sprintf(Token[i], "__RequestVerificationToken:%32.32s", t);
            t = strtok(NULL, "#");
        }
    }

    return realsize;
}

size_t MainWindow::WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    MemoryStruct *mem = (MemoryStruct *)userp;

    if ((mem->size + realsize) >= BuffSize) return realsize;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

// ---------- Запросы ----------
int MainWindow::GET(char *Url)
{
    char URL[128];
    sprintf(URL, MODEM "%s", Url);
    curl_easy_setopt(ch, CURLOPT_URL, URL);
    curl_easy_setopt(ch, CURLOPT_COOKIE, SessionID);
    curl_easy_setopt(ch, CURLOPT_POST, 0);
    chunk.size = 0;
    res = curl_easy_perform(ch);
    if (res != CURLE_OK) return 0;
    return 1;
}

int MainWindow::POST(char *post, char *Url)
{
    char URL[128];
    sprintf(URL, MODEM "%s", Url);
    curl_easy_setopt(ch, CURLOPT_URL, URL);
    curl_easy_setopt(ch, CURLOPT_POST, 1);
    curl_easy_setopt(ch, CURLOPT_POSTFIELDS, post);
    curl_easy_setopt(ch, CURLOPT_COOKIE, SessionID);
    headers = nullptr;
    headers = curl_slist_append(headers, Token[0]);
    headers = curl_slist_append(headers, "Connection: keep-alive");
    curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);
    chunk.size = 0;
    res = curl_easy_perform(ch);
    if (res != CURLE_OK) return 0;
    curl_slist_free_all(headers);
    curl_easy_setopt(ch, CURLOPT_HTTPHEADER, nullptr);
    return 1;
}

int MainWindow::SesTokInfo()
{
    char *i, *f;
    if (!GET("/api/webserver/SesTokInfo")) return 0;

    i = strstr(Buff, "<SesInfo>");
    f = strstr(Buff, "</SesInfo>");
    if (!i || !f) return 0;
    sprintf(SessionID, "%*.*s", (int)(f - i - 9), (int)(f - i - 9), i + 9);

    i = strstr(Buff, "<TokInfo>");
    f = strstr(Buff, "</TokInfo>");
    if (!i || !f) return 0;
    sprintf(Token[0], "__RequestVerificationToken:%*.*s", (int)(f - i - 9), (int)(f - i - 9), i + 9);
    return 1;
}

// ---------- SCRAM login ----------
int MainWindow::login(char *user, char *password)
{
    unsigned int j;
    unsigned char firstNonce[SHA256_DIGEST_LENGTH],
        salt[SHA256_DIGEST_LENGTH],
        saltPassword[SHA256_DIGEST_LENGTH],
        storedkey[SHA256_DIGEST_LENGTH],
        clientproof[SHA256_DIGEST_LENGTH],
        clientKey[SHA256_DIGEST_LENGTH],
        signature[SHA256_DIGEST_LENGTH];
    char authMsg[2048];
    char servernonce[1024];
    char post[2048];
    time_t rawtime = time(nullptr);
    struct timespec TT;
    SHA256_CTX ctx;

    memset(Token, 0, sizeof(Token));

    curl_global_init(CURL_GLOBAL_ALL);
    ch = curl_easy_init();
    curl_easy_setopt(ch, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(ch, CURLOPT_CONNECTTIMEOUT, 5);
    curl_easy_setopt(ch, CURLOPT_TIMEOUT, 5);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

    if (!SesTokInfo()) return 0;

    clock_gettime(CLOCK_MONOTONIC, &TT);
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, ctime(&rawtime), SHA256_DIGEST_LENGTH);
    SHA256_Update(&ctx, bin2hex((unsigned char *)&TT, sizeof(TT)), SHA256_DIGEST_LENGTH);
    SHA256_Final(firstNonce, &ctx);

    sprintf(post,
            "<?xml version='1.0' encoding='UTF-8'?>\n"
            "<request>\n"
            "<username>%s</username>\n"
            "<firstnonce>%s</firstnonce>\n"
            "<mode>1</mode>\n"
            "</request>",
            user, bin2hex(firstNonce, SHA256_DIGEST_LENGTH));

    if (!POST(post, "/api/user/challenge_login")) return 0;

    char *i = strstr(Buff, "<salt>");
    char *f = strstr(Buff, "</salt>");
    if (!i || !f) return 0;
    sprintf(post, "%*.*s", (int)(f - i - 6), (int)(f - i - 6), i + 6);
    memcpy(salt, hex2bin(post), SHA256_DIGEST_LENGTH);

    i = strstr(Buff, "<servernonce>");
    f = strstr(Buff, "</servernonce>");
    if (!i || !f) return 0;
    sprintf(servernonce, "%*.*s", (int)(f - i - 13), (int)(f - i - 13), i + 13);

    unsigned int La = sprintf(authMsg, "%s,%s,%s", bin2hex(firstNonce, SHA256_DIGEST_LENGTH), servernonce, servernonce);

    PKCS5_PBKDF2_HMAC(password, strlen(password), (const unsigned char *)salt, SHA256_DIGEST_LENGTH, 100, EVP_sha256(), SHA256_DIGEST_LENGTH, saltPassword);
    HMAC(EVP_sha256(), (const unsigned char *)"Client Key", 10, saltPassword, SHA256_DIGEST_LENGTH, clientKey, &j);
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, clientKey, SHA256_DIGEST_LENGTH);
    SHA256_Final(storedkey, &ctx);
    HMAC(EVP_sha256(), (const unsigned char *)authMsg, La, storedkey, SHA256_DIGEST_LENGTH, signature, &j);
    for (j = 0; j < SHA256_DIGEST_LENGTH; j++) clientproof[j] = clientKey[j] ^ signature[j];

    sprintf(post,
            "<?xml version='1.0' encoding='UTF-8'?>\n"
            "<request>\n"
            "<clientproof>%s</clientproof>\n"
            "<finalnonce>%s</finalnonce>\n"
            "</request>\n",
            bin2hex(clientproof, SHA256_DIGEST_LENGTH), servernonce);

    if (!POST(post, "/api/user/authentication_login")) return 0;
    if (!GET("/api/user/state-login")) return 0;
    if (!strstr(Buff, "<State>0</State>")) return 0;
    return 1;
}

int MainWindow::logout()
{
    char *post =
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<request>\n"
        "<Logout>1</Logout>\n"
        "</request>\n";

    if (!POST(post, "/api/user/logout")) return 0;
    curl_easy_cleanup(ch);
    curl_global_cleanup();
    ch = nullptr;
    if (!strstr(Buff, "<response>OK</response>")) return 0;
    return 1;
}

char *MainWindow::ListSmsIn()
{
    char post[] =
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<request>\n"
        "<PageIndex>1</PageIndex>\n"
        "<ReadCount>20</ReadCount>\n"
        "<BoxType>1</BoxType>\n"
        "<SortType>0</SortType>\n"
        "<Ascending>0</Ascending>\n"
        "<UnreadPreferred>0</UnreadPreferred>\n"
        "</request>";

    if (!POST(post, "/api/sms/sms-list")) return nullptr;
    return Buff;
}

QString MainWindow::parseSmsXml(const char *xmlData)
{
    QString result;
    XMLDocument doc;

    // Парсим XML данные
    if (doc.Parse(xmlData) != XML_SUCCESS) {
        return "Ошибка парсинга XML.\n";
    }

    XMLElement *response = doc.FirstChildElement("response");
    if (!response) return "Нет тегов <response> в XML.\n";

    XMLElement *messages = response->FirstChildElement("Messages");
    if (!messages) return "Нет входящих сообщений.\n";

    XMLElement *sms = messages->FirstChildElement("Message");
    while (sms) {
        const char *phone = sms->FirstChildElement("Phone") ? sms->FirstChildElement("Phone")->GetText() : "Неизвестно";
        const char *date = sms->FirstChildElement("Date") ? sms->FirstChildElement("Date")->GetText() : "";
        const char *content = sms->FirstChildElement("Content") ? sms->FirstChildElement("Content")->GetText() : "";

        // Формируем строку результата
        result += QString("📱 От: %1\n🕓 Дата: %2\n💬 Сообщение:\n%3\n\n")
                      .arg(phone)
                      .arg(date)
                      .arg(content);

        sms = sms->NextSiblingElement("Message");  // Переход к следующему сообщению
    }

    if (result.isEmpty()) result = "Нет входящих SMS.";
    return result;
}


// ---------- GUI ----------
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(nullptr)
{
    // Устанавливаем иконку
    setWindowIcon(QIcon(":/resources/resources/sms.png"));  // Убедитесь, что путь правильный

    QWidget *w = new QWidget;
    QVBoxLayout *lay = new QVBoxLayout(w);

    // Убираем поля для ввода логина и пароля
    // lineUser = new QLineEdit; lineUser->setPlaceholderText("Username");
    // linePass = new QLineEdit; linePass->setPlaceholderText("Password"); linePass->setEchoMode(QLineEdit::Password);

    btnLogin = new QPushButton("Login");
    textSms = new QTextEdit; textSms->setPlaceholderText("SMS list will appear here...");

    lay->addWidget(btnLogin);
    lay->addWidget(textSms);

    setCentralWidget(w);
    QRect screenGeometry = QGuiApplication::primaryScreen()->availableGeometry();
    int x = (screenGeometry.width() - width()) / 2;
    int y = (screenGeometry.height() - height()) / 2;
    move(x, y);
    connect(btnLogin, &QPushButton::clicked, this, &MainWindow::on_pushButton_clicked);
}

MainWindow::~MainWindow() {}

void MainWindow::on_pushButton_clicked()
{
    QByteArray u = "admin";  // Логин всегда "admin"
    QByteArray p = "admin";  // Пароль всегда "admin"

    system("doas service ipfw stop");

    if (login(u.data(), p.data())) {
        // Remove the success message box
        // QMessageBox::information(this, "Login", "Успешный вход!");
        
        char *sms = ListSmsIn();
        if (sms) {
            // Парсим XML и отображаем SMS
            QString parsedMessages = parseSmsXml(sms);
            textSms->setText(parsedMessages);
        } else {
            QMessageBox::warning(this, "Ошибка", "Не удалось получить SMS.");
        }
    } else {
        QMessageBox::critical(this, "Ошибка", "Ошибка входа. Проверьте логин/пароль.");
    }

    system("doas service ipfw start");
}
