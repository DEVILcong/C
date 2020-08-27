#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <school_tools.hpp>
#include <QMessageBox>
#include <QTimer>
#include <QPushButton>

QT_BEGIN_NAMESPACE
namespace Ui { class Widget; }
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

public:
    Widget(QWidget *parent = nullptr);
    ~Widget();

public slots:
    void doQuery(void);
    void handleTimeOut(void);

private:
    SchoolTools* connection;
    Ui::Widget *ui;
    QTimer* timer;

    void create_connection(void);
    void close_connection(void);
};
#endif // WIDGET_H
