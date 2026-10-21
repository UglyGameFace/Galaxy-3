// Host-only proof: real Wayland client buffer is wl_shm AND compositor paints it.
#include <QColor>
#include <QGuiApplication>
#include <QImage>
#include <QQmlApplicationEngine>
#include <QPointer>
#include <QQuickWindow>
#include <QSGRendererInterface>
#include <QTimer>
#include <QUrl>
#include <QWaylandBufferRef>
#include <QWaylandCompositor>
#include <QWaylandOutput>
#include <QWaylandSurface>
#include <QWaylandView>
#include <cstdio>

static bool expectedGreen(const QColor &c)
{
    return c.red() == 37 && c.green() == 169 && c.blue() == 83;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        std::fprintf(stderr, "FAIL[usage]: expected path to compositor.qml\n");
        return 64;
    }
    QGuiApplication app(argc, argv);
    QQmlApplicationEngine engine;
    engine.load(QUrl::fromLocalFile(QString::fromLocal8Bit(argv[1])));
    if (engine.rootObjects().isEmpty()) {
        std::fprintf(stderr, "FAIL[qml]: compositor QML failed to load\n");
        return 2;
    }
    auto *compositor = qobject_cast<QWaylandCompositor *>(engine.rootObjects().first());
    if (!compositor) {
        std::fprintf(stderr, "FAIL[qml]: root object is not QWaylandCompositor\n");
        return 2;
    }
    QList<QPointer<QWaylandSurface>> surfaces;
    QObject::connect(compositor, &QWaylandCompositor::surfaceCreated, &app,
                     [&](QWaylandSurface *surface) {
        surfaces.append(QPointer<QWaylandSurface>(surface));
        std::puts("EVENT: Wayland surface created");
        std::fflush(stdout);
    });

    bool shmSeen = false;
    bool shmPixelsSeen = false;
    QTimer timer;
    timer.setInterval(100);
    QObject::connect(&timer, &QTimer::timeout, &app, [&] {
        auto *output = compositor->defaultOutput();
        auto *window = output ? qobject_cast<QQuickWindow *>(output->window()) : nullptr;
        if (!window)
            return;
        for (const auto &surface : surfaces) {
            if (!surface)
                continue;
            for (auto *view : surface->views()) {
                QWaylandBufferRef buffer = view->currentBuffer();
                if (!buffer.hasContent() || !buffer.isSharedMemory())
                    continue;
                if (!shmSeen) {
                    shmSeen = true;
                    std::puts("PASS[protocol]: compositor received actual wl_shm buffer");
                    std::fflush(stdout);
                }
                const QImage pixels = buffer.image();
                if (!pixels.isNull() &&
                    expectedGreen(pixels.pixelColor(pixels.width() / 2, pixels.height() / 2)))
                    shmPixelsSeen = true;
            }
        }
        if (!shmPixelsSeen)
            return;
        if (window->rendererInterface()->graphicsApi() != QSGRendererInterface::Software) {
            std::fprintf(stderr, "FAIL[backend]: compositor is not Qt Quick software\n");
            app.exit(3);
            return;
        }
        const QImage rendered = window->grabWindow();
        if (rendered.isNull() || rendered.width() < 100 || rendered.height() < 100)
            return;
        // Server surface item is at (24,24), the 96x96 QWidget fills it.
        if (expectedGreen(rendered.pixelColor(64, 64))) {
            std::puts("PASS[pixels]: compositor output contains the Wayland client's green pixels");
            std::puts("NOT TESTED: target ARM64 Qt 6.11.3 compositor, /dev/fb0, watch boot");
            std::fflush(stdout);
            app.quit();
        }
    });
    timer.start();
    QTimer::singleShot(12000, &app, [&] {
        std::fprintf(stderr,
                     "FAIL[timeout]: received-shm=%d correct-shm-pixels=%d; "
                     "no verified compositor pixel frame\n",
                     int(shmSeen), int(shmPixelsSeen));
        app.exit(4);
    });
    return app.exec();
}
