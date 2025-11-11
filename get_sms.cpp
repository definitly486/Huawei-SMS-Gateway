// clang++  -L/usr/local/lib    ./get_sms.cpp -lcurl -lssl -lcrypto -lstdc++  -ltinyxml2   -w -std=c++17 -o get_sms 
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include </usr/local/include/curl/curl.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <memory>
#include </usr/local/include/tinyxml2.h> // Добавляем tinyxml2 для удобной обработки XML

using namespace tinyxml2;

#define FALSE 0
#define TRUE  1

#define MODEM "192.168.8.1"  // Адрес вашего роутера

static CURL     *ch;
static CURLcode res;
static struct curl_slist *headers=NULL;

static int  ContLen=0;
static char SessionID[1024]={0};

#define BuffSize 10240

static  char Buff[BuffSize];
typedef struct {  char *memory;  size_t size; }MemoryStruct;
static  MemoryStruct chunk = {Buff, 0};

static  char Token[36][34+27] = {{0}};
#define sTok sizeof(Token[0])
#define nTok (sizeof(Token)/sTok)

// Функция конвертации бинарных данных в HEX
static  char *bin2hex(unsigned char *s, long L)
{
    static  char hex[2048];
    long i,l=0;
    for (i=0; i<L; i++) l+=sprintf(&hex[l], "%02x", 0xFF & (*(s+i)));
    hex[l]=0;
    return hex;
}

// Конвертация строки HEX обратно в байтовый массив
static  char *hex2bin( char *s)
{
    static  char bin[2048];
    unsigned int i,e,l=0,L=strlen(s);
    for (i=0; i<L; i+=2) { sscanf(s+i, "%02x",&e); bin[l++]=(char)e; }
    bin[l]=0;
    return bin;
}

// Обработчик HTTP-заголовков
static size_t WriteHeaderCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
   char *p=(char *)contents;
   size_t realsize = size * nmemb;

   if (!memcmp(p, "Content-Length:", 15))               ContLen=atoi(p+15); else
   if (!memcmp(p, "Set-Cookie:", 11))                   sprintf(SessionID,  "%*.*s", realsize-2-11, realsize-2-11, (p+11)); else
   if (!memcmp(p, "__RequestVerificationToken:", 27))
   {   int  i; char *t;
       t=strtok(p+27, "#");
       for (i=0;t && i<nTok;i++) { sprintf(Token[i], "__RequestVerificationToken:%32.32s", t); t=strtok(NULL, "#"); }
   }

  return realsize;
}

// Обработчик тела HTTP-запросов
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  MemoryStruct *mem = ( MemoryStruct *)userp;

  if ((mem->size+realsize) >= BuffSize) return realsize; // ! too much data !

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
  return realsize;
}

// Выполнение простого GET-запроса
static int GET(char *Url)
{
    char URL[128];
    sprintf (URL, MODEM "%s", Url);
    curl_easy_setopt(ch, CURLOPT_URL, URL);
    curl_easy_setopt(ch, CURLOPT_COOKIE, SessionID);
    curl_easy_setopt(ch, CURLOPT_POST, 0);
    chunk.size = 0;
    res = curl_easy_perform(ch);
    if (res != CURLE_OK) return FALSE;
    return TRUE;
}

// Выполнение POST-запроса
static int POST(char *post, char *Url)
{
    char URL[128];
    sprintf (URL, MODEM "%s", Url);
    curl_easy_setopt(ch, CURLOPT_URL, URL);
    curl_easy_setopt(ch, CURLOPT_POST, 1);
    curl_easy_setopt(ch, CURLOPT_POSTFIELDS, post);
    curl_easy_setopt(ch, CURLOPT_COOKIE, SessionID);
    headers=NULL;
    headers = curl_slist_append(headers, Token[0]);
    headers = curl_slist_append(headers, "Connection: keep-alive");
    curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);
    chunk.size = 0;
    res = curl_easy_perform(ch);
    if (res != CURLE_OK)  return FALSE;
    curl_slist_free_all(headers);
    curl_easy_setopt(ch, CURLOPT_HTTPHEADER, NULL);
    return TRUE;
}

// Получение токенов сессии и аутентификации
static int SesTokInfo()
{
    char *i,*f;

    if (!GET("/api/webserver/SesTokInfo")) return FALSE;

    i=strstr(Buff,"<SesInfo>"); f=strstr(Buff,"</SesInfo>");
    if (!i || !f) return FALSE;
    sprintf(SessionID, "%*.*s", f-i-9, f-i-9, i+9);
    i=strstr(Buff,"<TokInfo>"); f=strstr(Buff,"</TokInfo>");
    if (!i || !f) return FALSE;
    sprintf(Token[0], "__RequestVerificationToken:%*.*s", f-i-9, f-i-9, i+9);
    return TRUE;
}

// Логин через механизм SCRAM
int login(char *user, char *password)
{
    char *i, *f;
    unsigned int La,j;
    unsigned char   firstNonce  [SHA256_DIGEST_LENGTH],
                    salt        [SHA256_DIGEST_LENGTH],
                    saltPassword[SHA256_DIGEST_LENGTH],
                    storedkey   [SHA256_DIGEST_LENGTH],
                    clientproof [SHA256_DIGEST_LENGTH],
                    clientKey   [SHA256_DIGEST_LENGTH],
                    signature   [SHA256_DIGEST_LENGTH];
    char authMsg    [2048];
    char servernonce[1024];
    char post       [2048];
    time_t rawtime = time(NULL);
    struct timespec TT;
    SHA256_CTX ctx;

    memset(Token, 0, sizeof(Token));

    curl_global_init(CURL_GLOBAL_ALL);
    ch = curl_easy_init();
    curl_easy_setopt(ch, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION,  WriteMemoryCallback);
    curl_easy_setopt(ch, CURLOPT_CONNECTTIMEOUT, 5);
    curl_easy_setopt(ch, CURLOPT_TIMEOUT,        5);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

    if (!SesTokInfo()) return FALSE;

    clock_gettime(CLOCK_MONOTONIC, &TT);
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, ctime(&rawtime),                          SHA256_DIGEST_LENGTH);
    SHA256_Update(&ctx, bin2hex((unsigned char*)&TT,sizeof(TT)), SHA256_DIGEST_LENGTH);
    SHA256_Final(firstNonce, &ctx);

    sprintf(post,
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<request>\n"
        "<username>%s</username>\n"
        "<firstnonce>%s</firstnonce>\n"
        "<mode>1</mode>\n"
        "</request>",
        user, bin2hex(firstNonce, SHA256_DIGEST_LENGTH));

    if (!POST(post, "/api/user/challenge_login")) return FALSE;

    i=strstr(Buff,"<salt>"); f=strstr(Buff,"</salt>");
    if (!i || !f) return FALSE;
    sprintf(post, "%*.*s", f-i-6, f-i-6, i+6); memcpy(salt, hex2bin(post), SHA256_DIGEST_LENGTH);

    i=strstr(Buff,"<servernonce>"); f=strstr(Buff,"</servernonce>");
    if (!i || !f) return FALSE;
    sprintf(servernonce, "%*.*s", f-i-13, f-i-13, i+13);

    La=sprintf(authMsg, "%s,%s,%s", bin2hex(firstNonce, SHA256_DIGEST_LENGTH), servernonce, servernonce);

    PKCS5_PBKDF2_HMAC(password, strlen(password), (const unsigned char*)salt, SHA256_DIGEST_LENGTH, 100, EVP_sha256(), SHA256_DIGEST_LENGTH, saltPassword);
    HMAC(EVP_sha256(), (const unsigned char *)"Client Key", 10, saltPassword, SHA256_DIGEST_LENGTH, clientKey, &j);
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, clientKey, SHA256_DIGEST_LENGTH);
    SHA256_Final(storedkey, &ctx);
    HMAC(EVP_sha256(), (const unsigned char *)authMsg, La, storedkey, SHA256_DIGEST_LENGTH, signature, &j);
    for (j=0;j<SHA256_DIGEST_LENGTH; j++) clientproof[j] = clientKey[j] ^ signature[j];

    sprintf (
        post,
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<request>\n"
        "<clientproof>%s</clientproof>\n"
        "<finalnonce>%s</finalnonce>\n"
        "</request>\n",
        bin2hex(clientproof, SHA256_DIGEST_LENGTH), servernonce);

    if (!POST(post, "/api/user/authentication_login")) return FALSE;
    if (!GET("/api/user/state-login")) return FALSE;
    if (!strstr(Buff, "<State>0</State>")) return FALSE;
    return TRUE;
}

// Разлогинивание
static int logout ()
{
    char *post =
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<request>\n"
        "<Logout>1</Logout>\n"
        "</request>\n";

    if (!POST(post, "/api/user/logout")) return FALSE;
    curl_easy_cleanup(ch);
    curl_global_cleanup();
    ch=NULL;

    if (!strstr(Buff, "<response>OK</response>")) return FALSE;
    return TRUE;
}

// Получение входящих SMS
static char * ListSmsIn()
{
    char post[]=
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<request>\n"
        "<PageIndex>1</PageIndex>\n"
        "<ReadCount>20</ReadCount>\n"
        "<BoxType>1</BoxType>\n" // Тип коробки: 1 — входящие SMS
        "<SortType>0</SortType>\n"
        "<Ascending>0</Ascending>\n"
        "<UnreadPreferred>0</UnreadPreferred>\n"
        "</request>";

    if (!POST(post, "/api/sms/sms-list")) return FALSE;
    return Buff;
}

// Основная программа
int main(int argc, char* argv[])
{
    if (!login("admin", "admin")) { printf("Ошибка входа!\n"); return 0; }
    printf("Авторизация успешна.\n");

    const char *smsResult = ListSmsIn();
    if (!smsResult) { printf("Ошибка при получении SMS.\n"); return 0; }
    
    // Парсим полученные SMS с использованием tinyxml2
    XMLDocument doc;
    XMLError err = doc.Parse(smsResult);
    if (err != XML_SUCCESS) { printf("Ошибка парсинга XML: %d\n", err); return 0; }

    // Извлекаем список SMS
    auto rootElement = doc.FirstChildElement("response");
    if (!rootElement) { printf("Нет элемента 'response'.\n"); return 0; }

    auto messagesNode = rootElement->FirstChildElement("Messages");
    if (!messagesNode) { printf("Нет элементов 'Messages'.\n"); return 0; }

    auto messageNodes = messagesNode->FirstChildElement("Message");
    if (!messageNodes) { printf("Нет ни одной SMS.\n"); return 0; }

    printf("\nСписок входящих SMS:\n");
    while(messageNodes)
    {
        auto contentNode = messageNodes->FirstChildElement("Content");
        auto phoneNumberNode = messageNodes->FirstChildElement("Phone");
        
        if(contentNode && phoneNumberNode)
        {
            printf("От кого: %s\nСообщение: %s\n", phoneNumberNode->GetText(), contentNode->GetText());
        }
        messageNodes = messageNodes->NextSiblingElement("Message");
    }

    if (!logout()) { printf("Ошибка выхода.\n"); return 0; }
    printf("\nВыход выполнен успешно.\n");
    return 0;
}