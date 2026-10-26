// SPDX-License-Identifier: MIT
// UgLy|OS R08 offline SOLO face. Only clock/battery + user-initiated actions.
// NO network/daemon, idle animation, hardware-dependent fitness or wakeup timer.
import QtQuick
import Nemo.Mce
import Nemo.Configuration

Item {
    id: face
    anchors.fill: parent
    readonly property real diameter: Math.min(width, height)
    readonly property int questCompleted: dial.completed
    readonly property string accentChoice:
        ["emerald", "ice", "violet", "ember", "rose"].indexOf(uglyOsAccent.value) >= 0
        ? uglyOsAccent.value : "original"
    readonly property color accent: accentChoice === "emerald" ? "#44E8A3"
        : accentChoice === "ice" ? "#80D9FF"
        : accentChoice === "violet" ? "#BE9BFF"
        : accentChoice === "ember" ? "#FFBE72"
        : accentChoice === "rose" ? "#FF95C8" : "#75EAC0"
    readonly property bool dimmed: displayAmbient || nightstand
    readonly property string currentTime: wallClock.time.toLocaleString(
        Qt.locale(), use12H.value ? "h:mm AP" : "HH:mm")
    readonly property string currentDate: wallClock.time.toLocaleString(
        Qt.locale(), "ddd d MMM")
    ConfigurationValue {
        id: uglyOsAccent
        key: "/desktop/uglyos/appearance/accent"
        defaultValue: "original"
    }
    MceBatteryLevel { id: battery }
    Rectangle { anchors.fill: parent; color: "#000000" }
    Item {
        id: dial
        anchors.centerIn: parent
        width: face.diameter * 0.80
        height: width

        readonly property string day: wallClock.time.toLocaleString(Qt.locale(), "yyyy-MM-dd")
        readonly property bool currentDay: progress.value.indexOf(day + "|") === 0
        readonly property int completed: currentDay
             ? Math.max(0, Math.min(3, Number(progress.value.split("|")[1]) || 0))
             : 0
        readonly property var quests: ["STRETCH", "WATER BREAK", "MOVE A LITTLE"]
        function finishQuest() {
            if (face.dimmed || completed >= 3)
                return
            progress.value = day + "|" + (completed + 1)
        }
        ConfigurationValue {
            id: progress
            key: "/desktop/uglyos/solo/daily-checkpoint"
            defaultValue: ""
        }
        Text {
            anchors.horizontalCenter: parent.horizontalCenter
            y: dial.height * 0.105
            text: "SOLO  /  ARCADE"
            color: face.dimmed ? "#666E69" : face.accent
            font.weight: Font.Bold
            font.letterSpacing: 1
            font.pixelSize: dial.height * 0.068
            renderType: Text.NativeRendering
        }
        Item {
            id: questCard
            objectName: "uglyos-solo-quest-card"
            anchors.horizontalCenter: parent.horizontalCenter
            y: dial.height * 0.745
            width: dial.width * 0.80
            height: dial.height * 0.125
            visible: !face.dimmed
            Rectangle {
                anchors.fill: parent
                radius: height * 0.25
                color: "#0F2118"
                border.color: face.accent
                border.width: 1
            }
            Text {
                anchors.centerIn: parent
                width: parent.width * 0.91
                horizontalAlignment: Text.AlignHCenter
                elide: Text.ElideRight
                text: dial.completed === 3 ? "DAILY CLEAR  3/3"
                    : (dial.completed + 1) + "/3  " + dial.quests[dial.completed] + "  ✓"
                color: "#E2FCEB"
                font.pixelSize: Math.max(11, questCard.height * 0.36)
                renderType: Text.NativeRendering
            }
            MouseArea {
                anchors.fill: parent
                enabled: !face.dimmed && dial.completed < 3
                onClicked: dial.finishQuest()
            }
        }

        Text {
            anchors.horizontalCenter: parent.horizontalCenter
            y: dial.height * 0.365
            text: face.currentTime
            color: face.dimmed ? "#969F99" : "#FAFFF9"
            font.family: "Noto Sans"
            font.weight: Font.DemiBold
            font.pixelSize: dial.height * (use12H.value ? 0.205 : 0.225)
            renderType: Text.NativeRendering
        }
        Text {
            anchors.horizontalCenter: parent.horizontalCenter
            y: dial.height * 0.605
            text: face.currentDate
            color: face.dimmed ? "#777E77" : "#B7DBBD"
            font.pixelSize: dial.height * 0.074
            renderType: Text.NativeRendering
        }
        Text {
            anchors.horizontalCenter: parent.horizontalCenter
            y: dial.height * 0.90
            visible: !face.dimmed
            text: "BAT " + battery.percent + "%"
            color: face.accent
            font.pixelSize: dial.height * 0.060
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
