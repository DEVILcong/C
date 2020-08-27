#include "widget.h"
#include "ui_widget.h"

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
    this->connection = nullptr;
    this->timer = nullptr;

    connect(ui->pushButton, SIGNAL(clicked()), this, SLOT(doQuery()));
}

Widget::~Widget()
{
    delete ui;

    if(this->connection != nullptr)
        delete this->connection;
    if(this->timer != nullptr)
        delete this->timer;
}

void Widget::doQuery(void){
    if(this->connection == nullptr)
        this->create_connection();

    float balance = 0;
    float power_all = 0;
    int category = 0;

    QString buildingID = ui->comboBox->currentText();
    QString roomID = ui->lineEdit->text();

    if(buildingID == "--选择楼栋--"){
        QMessageBox::critical(this, "ERROR", "请选择楼栋");
        return;
    }

    if(roomID.length() > 5){
        QMessageBox::critical(this, "ERROR", "请正确输入房间号");
        return;
    }

    for(int i = 0; i < roomID.length(); ++i){
        if(roomID[i] < QChar('0') || roomID > QChar('9')){
            QMessageBox::critical(this, "ERROR", "请正确输入房间号");
            return;
        }
    }

    if(ui->radioButton->isChecked())
        category = 0;
    else if(ui->radioButton_2->isChecked())
        category = 1;

    QByteArray build = buildingID.toUtf8();
    QByteArray room = roomID.toLatin1();


    this->connection->getPowerBalance(build.data(), room.data(), category, &balance, &power_all);

    if(balance < 0){
        switch(int(balance)){
            case(-1):
                QMessageBox::critical(this, "ERROR", "无法进入查询初始页面");
            break;
            case(-2):
                QMessageBox::critical(this, "ERROR", "无法创建curl");
            break;
            case(-3):
                QMessageBox::critical(this, "ERROR", "无法找到对应寝室");
            break;
            case(-4):
                QMessageBox::critical(this, "ERROR", "无法获取网页信息");
            break;
            case(-5):
                QMessageBox::critical(this, "ERROR", "正则解析错误");
            break;
            case(-6):
                QMessageBox::critical(this, "ERROR", "无法找到对应信息");
            break;
        }
        return;
    }

    ui->lcdNumber->display(balance);
    ui->lcdNumber_2->display(power_all);
}

void Widget::handleTimeOut(){
    this->close_connection();

    delete this->timer;
}

void Widget::create_connection(){
    if(this->connection != nullptr)
        this->close_connection();

    this->connection = new SchoolTools(false);

    if(this->timer != nullptr)
        delete this->timer;

    this->timer = new QTimer();
    this->timer->start(5*60*1000);    //5min

    connect(this->timer, SIGNAL(timeout()), this, SLOT(handleTimeOut()));
}

void Widget::close_connection(){
    delete this->connection;
    this->connection = nullptr;
}

