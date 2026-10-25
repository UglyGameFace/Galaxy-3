// SPDX-License-Identifier: MIT
// Galaxy Watch3 AsteroidOS enhancements: Focus. Minimal monochrome face.
import QtQuick
import Nemo.Mce

Item {
    id: face
    anchors.fill: parent
    readonly property real diameter: Math.min(width, height)
    readonly property string currentTime: wallClock.time.toLocaleString(
        Qt.locale(), use12H.value ? "h:mm AP" : "HH:mm")
    readonly property bool dimmed: displayAmbient || nightstand
    MceBatteryLevel { id: battery }

    Rectangle { anchors.fill: parent; color: "#050505" }
    Item {
        id: safe
        width: face.diameter * 0.80
        height: width
        anchors.centerIn: parent
        Text {
            y: safe.height * 0.14
            anchors.horizontalCenter: parent.horizontalCenter
            text: wallClock.time.toLocaleString(Qt.locale(), "dddd").toUpperCase()
            color: face.dimmed ? "#6A6A6A" : "#B3B3B3"
            font.pixelSize: safe.height * 0.072
            font.letterSpacing: safe.width * 0.013
            renderType: Text.NativeRendering
        }
        Text {
            anchors.centerIn: parent
            text: face.currentTime
            color: face.dimmed ? "#B5B5B5" : "#FFFFFF"
            font.family: "Noto Sans"
            font.weight: Font.Light
            font.pixelSize: safe.height * (use12H.value ? 0.245 : 0.25)
            renderType: Text.NativeRendering
        }
        Rectangle {
            x: safe.width * 0.18
            width: safe.width * 0.64
            height: Math.max(1, safe.height * 0.006)
            y: safe.height * 0.65
            color: face.dimmed ? "#424242" : "#686868"
        }
        Text {
            y: safe.height * 0.72
            anchors.horizontalCenter: parent.horizontalCenter
            text: wallClock.time.toLocaleString(Qt.locale(), "d MMM yyyy")
            color: face.dimmed ? "#828282" : "#DDDDDD"
            font.pixelSize: safe.height * 0.075
            renderType: Text.NativeRendering
        }
        Text {
            y: safe.height * 0.85
            anchors.horizontalCenter: parent.horizontalCenter
            visible: !face.dimmed
            text: battery.percent + "%"
            color: "#999999"
            font.pixelSize: safe.height * 0.065
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
