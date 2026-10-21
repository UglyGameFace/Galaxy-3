// Based on the actual QtWayland 6.2.4 minimal-qml example, narrowed to XDG.
import QtQuick
import QtQuick.Window
import QtWayland.Compositor
import QtWayland.Compositor.XdgShell

WaylandCompositor {
    id: server
    socketName: "watch3-shm-0"
    useHardwareIntegrationExtension: false

    WaylandOutput {
        sizeFollowsWindow: true
        window: Window {
            width: 160
            height: 160
            visible: true
            color: "#0c1420"

            Repeater {
                model: shellSurfaces
                ShellSurfaceItem {
                    x: 24
                    y: 24
                    shellSurface: modelData
                    onSurfaceDestroyed: shellSurfaces.remove(index)
                }
            }
        }
    }

    XdgShell {
        onToplevelCreated: shellSurfaces.append({shellSurface: xdgSurface})
    }
    ListModel { id: shellSurfaces }
}
