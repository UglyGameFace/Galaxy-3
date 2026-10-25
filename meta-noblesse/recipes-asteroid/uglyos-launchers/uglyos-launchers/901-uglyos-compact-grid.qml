// SPDX-License-Identifier: MIT
// UgLy|OS Compact Grid: readable, 2-column virtualized launcher, no shaders.
import QtQuick
import Nemo.Configuration
import org.asteroid.controls

Item {
    id: uglyLauncherRoot
    anchors.fill: parent
    property alias currentIndex: appsView.currentIndex
    property alias count: appsView.count
    property bool fakePressed: false

    Rectangle {
        anchors.fill: parent
        color: "#090E19"
    }
    Text {
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: parent.top
        anchors.topMargin: parent.height * 0.065
        width: parent.width * 0.83
        horizontalAlignment: Text.AlignHCenter
        text: "UGLY  /  GRID"
        color: "#83D4FF"
        font.pixelSize: Math.max(12, parent.height * 0.049)
        font.weight: Font.Bold
        font.letterSpacing: 1
        elide: Text.ElideRight
        renderType: Text.NativeRendering
    }
    GridView {
        id: appsView
        anchors.fill: parent
        anchors.topMargin: uglyLauncherRoot.height * 0.18
        anchors.bottomMargin: uglyLauncherRoot.height * 0.08
        anchors.leftMargin: uglyLauncherRoot.width * 0.03
        anchors.rightMargin: uglyLauncherRoot.width * 0.03
        clip: true
        cellWidth: width / 2
        cellHeight: Math.max(64, height * 0.265)
        cacheBuffer: height * 0.55
        flow: GridView.FlowLeftToRight
        snapMode: GridView.SnapToRow
        boundsBehavior: Flickable.StopAtBounds
        model: launcherModel
        property bool fakePressed: false

        ConfigurationValue {
            id: uglyOsAccent
            key: "/desktop/uglyos/appearance/accent"
            defaultValue: "original"
        }
        readonly property color accent: uglyOsAccent.value === "ice" ? "#80D9FF"
                                      : uglyOsAccent.value === "violet" ? "#BE9BFF"
                                      : uglyOsAccent.value === "ember" ? "#FFBE72"
                                      : uglyOsAccent.value === "rose" ? "#FF95C8"
                                      : "#6EED9A"


        delegate: MouseArea {
            objectName: "uglyos-app-item-" + index
            id: appTile
            width: appsView.cellWidth
            height: appsView.cellHeight
            enabled: !appsView.dragging
            onClicked: model.object.launchApplication()

            Rectangle {
                id: disk
                anchors.horizontalCenter: parent.horizontalCenter
                anchors.top: parent.top
                anchors.topMargin: parent.height * 0.08
                width: parent.width * 0.51
                height: width
                radius: width / 2
                color: appTile.pressed ? "#234936" : "#172920"
                border.width: 1
                border.color: appTile.pressed ? appsView.accent : "#34483B"
                Icon {
                    anchors.centerIn: parent
                    width: disk.width * 0.57
                    height: width
                    name: model.object.iconId === "" ? "ios-help" : model.object.iconId
                    color: appsView.accent
                }
            }
            Text {
                anchors.top: disk.bottom
                anchors.topMargin: Math.max(2, parent.height * 0.035)
                anchors.horizontalCenter: parent.horizontalCenter
                width: parent.width * 0.82
                horizontalAlignment: Text.AlignHCenter
                maximumLineCount: 1
                elide: Text.ElideRight
                color: "#F0F8F2"
                text: model.object.title + localeManager.changesObserver
                font.pixelSize: Math.max(10, appsView.height * 0.043)
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

}
