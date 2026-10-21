// Qt Widgets Wayland client: raster QPainter creates normal wl_shm buffers.
#include <QApplication>
#include <QColor>
#include <QPainter>
#include <QPaintEvent>
#include <QWidget>

class ShmClient : public QWidget {
protected:
    void paintEvent(QPaintEvent *) override {
        QPainter painter(this);
        painter.fillRect(rect(), QColor(37, 169, 83));
    }
};

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    ShmClient widget;
    widget.setAttribute(Qt::WA_OpaquePaintEvent);
    widget.setWindowFlags(Qt::Window | Qt::FramelessWindowHint);
    widget.setFixedSize(96, 96);
    widget.show();
    return app.exec();
}
