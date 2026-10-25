// SPDX-License-Identifier: MIT
// UgLy|OS Gamer Arcade | R08: neon high contrast with touch-only micro-effects.
import QtQuick
import Nemo.Configuration
import org.asteroid.controls

GridView {
    id: appsView
    anchors.fill: parent
    clip: true
    model: launcherModel
    cellWidth: width / 2
    cellHeight: Math.max(65, height * 0.265)
    flow: GridView.FlowLeftToRight
    snapMode: GridView.SnapToRow
    cacheBuffer: height * 0.5
    boundsBehavior: Flickable.StopAtBounds
    property bool fakePressed: false

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
            text: "UGLY  //  ARCADE"
            color: "#8CE8FF"
            font.pixelSize: Math.max(13, appsView.height * 0.061)
            font.weight: Font.Bold
            font.letterSpacing: 1
            renderType: Text.NativeRendering
        }
    }
    footer: Item { width: appsView.width; height: appsView.height * 0.13 }

    delegate: MouseArea {
        objectName: "uglyos-app-item-" + index
        id: tile
        width: appsView.cellWidth
        height: appsView.cellHeight
        enabled: !appsView.dragging
        onClicked: model.object.launchApplication()

        Rectangle {
            id: frame
            width: parent.width * 0.66
            height: width
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.top: parent.top
            anchors.topMargin: parent.height * 0.06
            radius: width * 0.20
            color: tile.pressed ? "#1B4A69" : "#111C34"
            border.color: tile.pressed ? "#A5F4FF" : "#4A74C8"
            border.width: 2
            Behavior on color {
                enabled: appsView.effectsEnabled
                ColorAnimation { duration: 85 }
            }
            Rectangle {
                width: parent.width * 0.68
                height: Math.max(2, parent.height * 0.045)
                color: "#7CD9F3"
                anchors.top: parent.top
                anchors.horizontalCenter: parent.horizontalCenter
                opacity: tile.pressed ? 1 : 0.55
            }
            Icon {
                anchors.centerIn: parent
                width: parent.width * 0.53
                height: width
                name: model.object.iconId === "" ? "ios-help" : model.object.iconId
                color: "#CDEEFF"
            }
        }
        Text {
            anchors.top: frame.bottom
            anchors.topMargin: Math.max(2, tile.height * 0.03)
            anchors.horizontalCenter: parent.horizontalCenter
            width: tile.width * 0.82
            text: model.object.title + localeManager.changesObserver
            font.pixelSize: Math.max(10, appsView.height * 0.041)
            font.weight: Font.DemiBold
            horizontalAlignment: Text.AlignHCenter
            elide: Text.ElideRight
            maximumLineCount: 1
            color: "#E1EDFF"
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
    }
}
