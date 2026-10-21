// Off-device scenegraph contract test for Watch3's planned wl_shm fallback.
// This exercises QImage -> QSGSimpleTextureNode -> Qt Quick software pixels,
// the same primitive used by QtWayland's pinned QWaylandQuickItem.
// It does NOT launch AsteroidOS or establish a Wayland connection.
#include <QColor>
#include <QElapsedTimer>
#include <QGuiApplication>
#include <QImage>
#include <QQuickItem>
#include <QQuickWindow>
#include <QSGRendererInterface>
#include <QSGSimpleTextureNode>
#include <QTimer>
#include <QtGlobal>
#include <cstdio>

class SharedMemoryLikeItem final : public QQuickItem {
public:
    explicit SharedMemoryLikeItem(QQuickItem *parent = nullptr) : QQuickItem(parent) {
        setFlag(ItemHasContents, true);
    }

protected:
    QSGNode *updatePaintNode(QSGNode *oldNode, UpdatePaintNodeData *) override {
        auto *node = static_cast<QSGSimpleTextureNode *>(oldNode);
        if (!node) {
            node = new QSGSimpleTextureNode;
            node->setOwnsTexture(true);
        }

        // A deterministic CPU-only pixel buffer simulating wl_shm contents.
        QImage buffer(48, 48, QImage::Format_ARGB32_Premultiplied);
        buffer.fill(QColor(37, 169, 83));
        if (!node->texture())
            node->setTexture(window()->createTextureFromImage(buffer));
        node->setRect(boundingRect());
        return node;
    }
};

int main(int argc, char **argv) {
    QGuiApplication app(argc, argv);
    QQuickWindow view;
    view.setWidth(128);
    view.setHeight(128);
    view.setColor(QColor(10, 20, 30));

    auto *item = new SharedMemoryLikeItem(view.contentItem());
    item->setWidth(96);
    item->setHeight(96);
    item->setX(16);
    item->setY(16);

    QElapsedTimer elapsed;
    elapsed.start();
    QTimer poll;
    poll.setInterval(100);
    QObject::connect(&poll, &QTimer::timeout, [&] {
        if (view.rendererInterface()->graphicsApi() != QSGRendererInterface::Software) {
            std::fprintf(stderr, "FAIL: renderer is not Qt Quick software\n");
            app.exit(2);
            return;
        }
        const QImage image = view.grabWindow();
        if (!image.isNull() && image.width() >= 64 && image.height() >= 64) {
            const QColor c = image.pixelColor(64, 64);
            if (c.red() == 37 && c.green() == 169 && c.blue() == 83) {
                std::puts("PASS: Qt Quick software rendered CPU-memory pixels through QSGSimpleTextureNode");
                std::puts("NOT TESTED: actual QtWayland compositor, wl_shm round-trip, target Qt 6.11.3, /dev/fb0");
                app.quit();
                return;
            }
        }
        if (elapsed.elapsed() > 7000) {
            std::fprintf(stderr, "FAIL: expected software pixels not observed in scenegraph capture\n");
            app.exit(3);
        }
    });

    view.show();
    poll.start();
    return app.exec();
}
