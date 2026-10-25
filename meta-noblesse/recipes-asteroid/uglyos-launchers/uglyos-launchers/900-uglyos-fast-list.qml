// SPDX-License-Identifier: MIT
// UgLy|OS Fast List: one-tap native app navigation without costly effects.
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
        color: "#07110C"
    }
    Text {
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: parent.top
        anchors.topMargin: parent.height * 0.065
        width: parent.width * 0.83
        horizontalAlignment: Text.AlignHCenter
        text: "UGLY  /  FAST"
        color: "#74EEAA"
        font.pixelSize: Math.max(12, parent.height * 0.049)
        font.weight: Font.Bold
        font.letterSpacing: 1
        elide: Text.ElideRight
        renderType: Text.NativeRendering
    }
    ListView {
        id: appsView
        anchors.fill: parent
        anchors.topMargin: uglyLauncherRoot.height * 0.18
        anchors.bottomMargin: uglyLauncherRoot.height * 0.08
        anchors.leftMargin: uglyLauncherRoot.width * 0.03
        anchors.rightMargin: uglyLauncherRoot.width * 0.03
        clip: true
        spacing: Math.max(2, height * 0.008)
        cacheBuffer: height * 0.55
        boundsBehavior: Flickable.StopAtBounds
        model: launcherModel
        property bool fakePressed: false
        property real cellHeight: Math.max(48, height * 0.18)

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
            id: appRow
            width: appsView.width * 0.80
            x: (appsView.width - width) / 2
            height: appsView.cellHeight
            enabled: !appsView.dragging
            onClicked: model.object.launchApplication()

            Rectangle {
                anchors.fill: parent
                radius: height * 0.21
                color: appRow.pressed ? "#22392C" : "#101813"
                border.color: appRow.pressed ? appsView.accent : "#29362E"
                border.width: 1
            }
            Rectangle {
                anchors.left: parent.left
                anchors.leftMargin: parent.height * 0.14
                anchors.verticalCenter: parent.verticalCenter
                width: parent.height * 0.59
                height: width
                radius: width / 2
                color: "#253B2E"
                Icon {
                    anchors.centerIn: parent
                    width: parent.width * 0.67
                    height: width
                    name: model.object.iconId === "" ? "ios-help" : model.object.iconId
                    color: appsView.accent
                }
            }
            Text {
                anchors.left: parent.left
                anchors.leftMargin: appRow.height * 0.88
                anchors.right: parent.right
                anchors.rightMargin: appRow.height * 0.13
                anchors.verticalCenter: parent.verticalCenter
                color: appRow.pressed ? appsView.accent : "#EAF4EC"
                text: model.object.title + localeManager.changesObserver
                elide: Text.ElideRight
                font.pixelSize: Math.max(11, appsView.height * 0.053)
                font.weight: Font.Medium
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
