#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_clicked()
{

    system("doas service ipfw stop");

    // Очищаем содержимое текстового поля
    ui->textEdit->clear();

    // Настраиваем процесс
    m_process.setProgram("get_sms");     // Имя программы
    m_process.setArguments(QStringList()); // Аргументы (оставляем пустой список)

    // Читаем стандартный вывод
    QObject::connect(&m_process, &QProcess::readyReadStandardOutput,
                     [&]()
                     {
                         // Чтение данных из стандартного потока вывода
                         auto data = m_process.readAllStandardOutput().trimmed();
                         ui->textEdit->append(data); // Выводим полученные данные в TextEdit
                     });

    // Стартуем процесс
    m_process.start();

    system("doas service ipfw start");

}

