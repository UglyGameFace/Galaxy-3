// SPDX-License-Identifier: MIT
// UgLy|OS Stoner Lounge | R08: cozy 420-inspired lounge with press-only haze.
import QtQuick
import Nemo.Configuration
import org.asteroid.controls

ListView {
    id: appsView
    anchors.fill: parent
    clip: true
    spacing: Math.max(3, height * 0.012)
    cacheBuffer: height * 0.5
    boundsBehavior: Flickable.StopAtBounds
    model: launcherModel
    property bool fakePressed: false
    property real rowHeight: Math.max(52, height * 0.18)

    ConfigurationValue {
        id: effectsSetting
        key: "/desktop/uglyos/appearance/effects"
        defaultValue: "subtle"
    }
    readonly property bool effectsEnabled: effectsSetting.value === "subtle"

    header: Item {
        width: appsView.width
        height: appsView.height * 0.145
        Text {
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.bottom: parent.bottom
            anchors.bottomMargin: parent.height * 0.12
            text: "420  /  LOUNGE"
            color: "#A8F0BD"
            font.pixelSize: Math.max(13, appsView.height * 0.064)
            font.weight: Font.DemiBold
            font.letterSpacing: 1.5
            renderType: Text.NativeRendering
        }
    }
    footer: Item { width: appsView.width; height: appsView.height * 0.13 }

    delegate: MouseArea {
        objectName: "uglyos-app-item-" + index
        id: row
        x: (appsView.width - width) / 2
        width: appsView.width * 0.79
        height: appsView.rowHeight
        enabled: !appsView.dragging
        onClicked: model.object.launchApplication()

        Rectangle {
            anchors.fill: parent
            radius: height * 0.26
            color: row.pressed ? "#225A3C" : "#10291F"
            border.color: row.pressed ? "#B3FFD0" : "#386D54"
            border.width: 1
            Behavior on color {
                enabled: appsView.effectsEnabled
                ColorAnimation { duration: 95 }
            }
        }
        Rectangle {
            id: emblem
            width: row.height * 0.66
            height: width
            radius: width / 2
            anchors.verticalCenter: parent.verticalCenter
            anchors.left: parent.left
            anchors.leftMargin: row.height * 0.12
            color: "#1B4531"
            border.color: "#7CCDA0"
            border.width: 1
            Icon {
                anchors.centerIn: parent
                width: parent.width * 0.64
                height: width
                name: model.object.iconId === "" ? "ios-help" : model.object.iconId
                color: "#C0F3CD"
            }
        }
        Text {
            anchors.left: emblem.right
            anchors.leftMargin: row.height * 0.13
            anchors.right: parent.right
            anchors.rightMargin: row.height * 0.12
            anchors.verticalCenter: parent.verticalCenter
            text: model.object.title + localeManager.changesObserver
            color: row.pressed ? "#FFFFFF" : "#E4F9E9"
            font.pixelSize: Math.max(11, appsView.height * 0.051)
            font.weight: Font.Medium
            elide: Text.ElideRight
            renderType: Text.NativeRendering
        }
    }
    Connections {
        target: grid
        function onCurrentVerticalPosChanged() {
            if (grid.currentVerticalPos === 0)
                appsView.positionViewAtBeginning()
        }
    }
    onAtYBeginningChanged: {
        if (grid.currentHorizontalPos === 0 && grid.currentVerticalPos === 1) {
            forbidTop = !atYBeginning
            grid.changeAllowedDirections()
        }
    }
    Component.onCompleted: {
        launcherColorOverride = true
        toLeftAllowed = false
        toRightAllowed = false
        toBottomAllowed = Qt.binding(function() { return !atYBeginning })
        toTopAllowed = Qt.binding(function() { return !atYEnd })
        forbidTop = !atYBeginning
        forbidBottom = false
        forbidLeft = false
        forbidRight = false
        // Initial selector/grid positioning must show header and full first tile.
        // Runs ONCE after component layout, never as an animation or timer.
        Qt.callLater(function() { appsView.positionViewAtBeginning() })
    }
}
