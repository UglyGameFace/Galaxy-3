// SPDX-License-Identifier: MIT
// Galaxy Watch3 AsteroidOS enhancements: Signal. High-contrast amber sport face.
import QtQuick
import Nemo.Mce

Item {
    id: face
    anchors.fill: parent
    readonly property real diameter: Math.min(width, height)
    readonly property bool dimmed: displayAmbient || nightstand
    readonly property color accent: "#FFC36B"
    MceBatteryLevel { id: battery }

    Rectangle { anchors.fill: parent; color: "#0E0D0B" }
    Item {
        id: safe
        width: face.diameter * 0.80
        height: width
        anchors.centerIn: parent
        Rectangle {
            x: safe.width * 0.19
            y: safe.height * 0.12
            width: safe.width * 0.12
            height: Math.max(2, safe.height * 0.012)
            color: face.dimmed ? "#746046" : face.accent
        }
        Text {
            x: safe.width * 0.36
            y: safe.height * 0.09
            text: "SIGNAL"
            color: face.dimmed ? "#8A7961" : face.accent
            font.pixelSize: safe.height * 0.073
            font.weight: Font.DemiBold
            renderType: Text.NativeRendering
        }
        Text {
            id: time
            anchors.horizontalCenter: parent.horizontalCenter
            y: safe.height * 0.32
            text: wallClock.time.toLocaleString(
                Qt.locale(), use12H.value ? "h:mm" : "HH:mm")
            color: face.dimmed ? "#C2AA87" : "#FFF0D9"
            font.family: "Noto Sans"
            font.weight: Font.Bold
            font.pixelSize: safe.height * (use12H.value ? 0.235 : 0.255)
            renderType: Text.NativeRendering
        }
        Text {
            anchors.horizontalCenter: parent.horizontalCenter
            y: safe.height * 0.65
            text: wallClock.time.toLocaleString(Qt.locale(), "ddd d MMM").toUpperCase()
            color: face.dimmed ? "#89775D" : "#FFC36B"
            font.pixelSize: safe.height * 0.080
            renderType: Text.NativeRendering
        }
        Rectangle {
            anchors.horizontalCenter: parent.horizontalCenter
            y: safe.height * 0.81
            width: safe.width * 0.58
            height: safe.height * 0.012
            color: "#51402B"
            visible: !face.dimmed
            Rectangle {
                width: parent.width * Math.max(0, Math.min(1, battery.percent / 100))
                height: parent.height
                color: face.accent
            }
        }
        Text {
            anchors.horizontalCenter: parent.horizontalCenter
            y: safe.height * 0.86
            visible: !face.dimmed
            text: "BAT " + battery.percent + "%"
            color: "#D9B27B"
            font.pixelSize: safe.height * 0.060
            renderType: Text.NativeRendering
        }
    }
    Component.onCompleted: {
        burnInProtectionManager.widthOffset = Qt.binding(
            function() { return face.diameter * 0.16 })
        burnInProtectionManager.heightOffset = Qt.binding(
            function() { return face.diameter * 0.16 })
    }
}
