#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMessageBox>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

#include <curl/curl.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <tinyxml2.h>

using namespace tinyxml2;

#define MODEM "192.168.8.1"  // адрес вашего роутера
#define BuffSize 10240

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
     QString parseSmsXml(const char *xmlData);


private slots:
    void on_pushButton_clicked();

private:
    Ui::MainWindow *ui;

    // виджеты
    QLineEdit *lineUser;
    QLineEdit *linePass;
    QTextEdit *textSms;
    QPushButton *btnLogin;

    // --- сетевые переменные ---
    static CURL *ch;
    static CURLcode res;
    static struct curl_slist *headers;
    static int ContLen;
    static char SessionID[1024];
    static char Buff[BuffSize];
    static char Token[36][34+27];

    typedef struct { char *memory; size_t size; } MemoryStruct;
    static MemoryStruct chunk;

    // --- функции ---
    static char *bin2hex(unsigned char *s, long L);
    static char *hex2bin(char *s);
    static size_t WriteHeaderCallback(void *contents, size_t size, size_t nmemb, void *userp);
    static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
    static int GET(char *Url);
    static int POST(char *post, char *Url);
    static int SesTokInfo();
    static int login(char *user, char *password);
    static int logout();
    static char *ListSmsIn();
};

#endif // MAINWINDOW_H
