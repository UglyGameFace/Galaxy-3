// SPDX-License-Identifier: MIT
// UgLy|OS edition for Galaxy Watch3: Orbit. Round-screen-safe, software Qt.
// Existing watchface Settings discovers .qml files automatically.
import QtQuick
import Nemo.Mce
import Nemo.Configuration

Item {
    id: face
    anchors.fill: parent
    readonly property real diameter: Math.min(width, height)
    // Shared optional appearance preference; original/unknown retains legacy colors.
    readonly property string accentChoice: ["emerald", "ice", "violet", "ember", "rose"].indexOf(uglyOsAccent.value) >= 0
                                            ? uglyOsAccent.value : "original"
    readonly property bool themed: accentChoice !== "original"
    readonly property color accent: accentChoice === "emerald" ? "#44E8A3"
                                  : accentChoice === "ice" ? "#80D9FF"
                                  : accentChoice === "violet" ? "#BE9BFF"
                                  : accentChoice === "ember" ? "#FFBE72"
                                  : accentChoice === "rose" ? "#FF95C8"
                                  : "#6EED9A"
    ConfigurationValue {
        id: uglyOsAccent
        key: "/desktop/uglyos/appearance/accent"
        defaultValue: "original"
    }
    readonly property bool ambient: displayAmbient
    readonly property bool dimmed: ambient || nightstand
    readonly property string currentTime: wallClock.time.toLocaleString(
        Qt.locale(), use12H.value ? "h:mm AP" : "HH:mm")
    readonly property string currentDate: wallClock.time.toLocaleString(
        Qt.locale(), "ddd, d MMM")

    MceBatteryLevel { id: battery }
    Rectangle { anchors.fill: parent; color: "#050C09" }

    Item {
        id: safe
        width: face.diameter * 0.80
        height: width
        anchors.centerIn: parent

        Text {
            anchors.horizontalCenter: parent.horizontalCenter
            y: safe.height * 0.13
            text: "UgLy|OS"
            color: face.dimmed ? "#76867D" : face.accent
            font.family: "Noto Sans"
            font.pixelSize: safe.height * 0.073
            font.letterSpacing: safe.width * 0.012
            renderType: Text.NativeRendering
        }
        Text {
            id: clock
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.verticalCenter: parent.verticalCenter
            text: face.currentTime
            color: face.dimmed ? "#A4B0AA" : "#F1FFF7"
            font.family: "Noto Sans"
            font.weight: Font.DemiBold
            font.pixelSize: safe.height * (use12H.value ? 0.225 : 0.24)
            renderType: Text.NativeRendering
        }
        Text {
            anchors.horizontalCenter: parent.horizontalCenter
            y: safe.height * 0.65
            text: face.currentDate
            color: face.dimmed ? "#84938A" : "#B9D8C4"
            font.pixelSize: safe.height * 0.082
            renderType: Text.NativeRendering
        }
        Rectangle {
            id: track
            width: safe.width * 0.55
            height: Math.max(2, safe.height * 0.017)
            radius: height / 2
            anchors.horizontalCenter: parent.horizontalCenter
            y: safe.height * 0.82
            color: "#34483B"
            visible: !face.dimmed
            Rectangle {
                width: parent.width * Math.max(0, Math.min(1, battery.percent / 100))
                height: parent.height
                radius: parent.radius
                color: face.accent
            }
        }
        Text {
            anchors.horizontalCenter: parent.horizontalCenter
            y: safe.height * 0.86
            visible: !face.dimmed
            text: battery.percent + "% BATTERY"
            color: "#A8BEAE"
            font.pixelSize: safe.height * 0.055
            renderType: Text.NativeRendering
        }
    }
    // Preserve AsteroidOS's existing AOD OLED burn-in protection behavior.
    Component.onCompleted: {
        burnInProtectionManager.widthOffset = Qt.binding(
            function() { return face.diameter * 0.16 })
        burnInProtectionManager.heightOffset = Qt.binding(
            function() { return face.diameter * 0.16 })
    }
}
