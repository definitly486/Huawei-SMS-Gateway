#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPushButton>
#include <QTextEdit>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>

// Необходимые библиотеки
#include <curl/curl.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <tinyxml2.h>

using namespace tinyxml2;

#define MODEM       "http://192.168.8.1"   // Обязательно с http:// !
#define BuffSize    16384                  // Чуть больше, на всякий случай

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    // Парсинг и работа с SMS
    QString parseSmsXml(const char *xmlData);
    bool    DeleteSms(int smsIndex);
    bool    DeleteAllSms();            // Удаляет все входящие

private slots:
    void on_btnGetSms_clicked();
    void on_btnDeleteAll_clicked();
    void on_btnRefreshToken_clicked();

private:
    // === Виджеты ===
    QTextEdit   *textSms;
    QPushButton *btnGetSms;
    QPushButton *btnDeleteAll;
    QPushButton *btnRefreshToken;
    QLabel      *labelStatus;

    // === Сетевые переменные (статические, как у тебя было) ===
    static CURL              *ch;
    static CURLcode           res;
    static struct curl_slist *headers;
    static int                ContLen;
    static char               SessionID[1024];
    static char               Buff[BuffSize];
    static char               Token[36][64];
    
    typedef struct { char *memory; size_t size; } MemoryStruct;
    static MemoryStruct chunk;

    // === Вспомогательные функции ===
    static char*  bin2hex(unsigned char *s, long L);
    static char*  hex2bin(char *s);

    // === Callbacks для libcurl ===
    static size_t WriteHeaderCallback(void *contents, size_t size, size_t nmemb, void *userp);
    static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);

    // === HTTP-запросы ===
    static int  GET(const char *Url);
    static int  POST(const char *post, const char *Url);
    static int  SesTokInfo();

    // === Авторизация ===
    static int  login(const char *user, const char *password);
    static int  logout();

    // === Работа с SMS ===
    static char* ListSmsIn();
};

#endif // MAINWINDOW_H