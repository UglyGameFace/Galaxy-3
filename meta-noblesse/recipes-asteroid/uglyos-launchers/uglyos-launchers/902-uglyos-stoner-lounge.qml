// SPDX-License-Identifier: MIT
// UgLy|OS Stoner Lounge | R08: cozy 420-inspired lounge with press-only haze.
import QtQuick
import Nemo.Configuration
import "uglyos-favorites.js" as Pins
import org.asteroid.controls

Item {
    id: uglyLauncherRoot
    anchors.fill: parent
    property alias currentIndex: appsView.currentIndex
    property alias count: appsView.count
    property bool fakePressed: false
    // Pinned list contains only real installed LauncherItem QObject instances.
    // Stable freedesktop file IDs, never translated titles or raw Exec strings.
    property var pinnedApps: []
    property int pinnedCount: pinnedApps.length
    property int pinnedIndex: 0
    function refreshPins() {
        pinnedApps = Pins.resolve(launcherModel, favoriteSetting.value)
        if (pinnedIndex >= pinnedApps.length)
            pinnedIndex = 0
    }
    function togglePin(item) {
        var id = Pins.appID(item)
        if (!id)
            return
        favoriteSetting.value = Pins.toggle(favoriteSetting.value, item)
        refreshPins()
    }
    function cyclePin(delta) {
        if (pinnedApps.length)
            pinnedIndex = (pinnedIndex + delta + pinnedApps.length) % pinnedApps.length
    }
    function launchPin() {
        if (pinnedIndex < pinnedApps.length && pinnedApps[pinnedIndex])
            pinnedApps[pinnedIndex].launchApplication()
    }
    onCountChanged: Qt.callLater(refreshPins)

    ConfigurationValue {
        id: favoriteSetting
        key: "/desktop/uglyos/launcher/favorites"
        defaultValue: "[]"
        onValueChanged: Qt.callLater(uglyLauncherRoot.refreshPins)
    }
    property bool firstAppPositioned: false
    function positionFirstApp() {
        if (firstAppPositioned || appsView.count < 1 || appsView.height < 1)
            return
        appsView.currentIndex = 0
        appsView.positionViewAtIndex(0, ListView.Beginning)
        firstAppPositioned = true
    }
    readonly property bool effectsEnabled: appsView.effectsEnabled

    // One compact quick-launch dock, always above the virtualized app list.
    // Unset favorites yield guidance instead of blank / broken app buttons.
    Item {
        id: favoriteDock
        objectName: "uglyos-favorites-dock"
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: parent.top
        anchors.topMargin: parent.height * 0.115
        width: parent.width * 0.78
        height: Math.max(24, parent.height * 0.075)
        z: 3
        Rectangle {
            anchors.fill: parent
            color: "#16251D"
            border.color: "#476A53"
            border.width: 1
            radius: height / 2
        }
        Text {
            anchors.centerIn: parent
            width: parent.width * 0.60
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
            text: uglyLauncherRoot.pinnedApps.length
                  ? "\u2605 " + uglyLauncherRoot.pinnedApps[uglyLauncherRoot.pinnedIndex].title
                  : "Hold app to pin"
            elide: Text.ElideRight
            color: "#D8F6E3"
            font.pixelSize: Math.max(10, parent.height * 0.43)
            renderType: Text.NativeRendering
        }
        Text {
            text: "\u2039"
            visible: uglyLauncherRoot.pinnedApps.length > 1
            anchors.left: parent.left
            anchors.leftMargin: parent.width * 0.09
            anchors.verticalCenter: parent.verticalCenter
            color: "#A5ECC0"
            font.pixelSize: parent.height * 0.75
        }
        Text {
            text: "\u203a"
            visible: uglyLauncherRoot.pinnedApps.length > 1
            anchors.right: parent.right
            anchors.rightMargin: parent.width * 0.09
            anchors.verticalCenter: parent.verticalCenter
            color: "#A5ECC0"
            font.pixelSize: parent.height * 0.75
        }
        MouseArea {
            width: parent.width * 0.20
            height: parent.height
            anchors.left: parent.left
            enabled: uglyLauncherRoot.pinnedApps.length > 1
            onClicked: uglyLauncherRoot.cyclePin(-1)
        }
        MouseArea {
            width: parent.width * 0.20
            height: parent.height
            anchors.right: parent.right
            enabled: uglyLauncherRoot.pinnedApps.length > 1
            onClicked: uglyLauncherRoot.cyclePin(1)
        }
        MouseArea {
            id: launchPinned
            objectName: "uglyos-launch-favorite"
            width: parent.width * 0.60
            height: parent.height
            anchors.centerIn: parent
            enabled: uglyLauncherRoot.pinnedApps.length > 0
            onClicked: uglyLauncherRoot.launchPin()
        }
    }

    Rectangle {
        anchors.fill: parent
        color: "#08160F"
    }
    Text {
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: parent.top
        anchors.topMargin: parent.height * 0.065
        width: parent.width * 0.83
        horizontalAlignment: Text.AlignHCenter
        text: "420  /  LOUNGE"
        color: "#A8F0BD"
        font.pixelSize: Math.max(12, parent.height * 0.049)
        font.weight: Font.Bold
        font.letterSpacing: 1
        elide: Text.ElideRight
        renderType: Text.NativeRendering
    }
    ListView {
        id: appsView
        objectName: "uglyos-apps-view"
        anchors.fill: parent
        anchors.topMargin: uglyLauncherRoot.height * 0.225
        anchors.bottomMargin: uglyLauncherRoot.height * 0.08
        anchors.leftMargin: uglyLauncherRoot.width * 0.03
        anchors.rightMargin: uglyLauncherRoot.width * 0.03
        clip: true
        onCountChanged: Qt.callLater(uglyLauncherRoot.positionFirstApp)
        onHeightChanged: Qt.callLater(uglyLauncherRoot.positionFirstApp)
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


        delegate: MouseArea {
            objectName: "uglyos-app-item-" + index
            id: row
            x: (appsView.width - width) / 2
            width: appsView.width * 0.79
            height: appsView.rowHeight
            enabled: !appsView.dragging
            property bool heldToPin: false
            onPressed: heldToPin = false
            onPressAndHold: {
                if (!appsView.dragging) {
                    heldToPin = true
                    uglyLauncherRoot.togglePin(model.object)
                }
            }
            onClicked: {
                if (!heldToPin)
                    model.object.launchApplication()
            }

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
            Qt.callLater(uglyLauncherRoot.positionFirstApp)
            Qt.callLater(uglyLauncherRoot.refreshPins)
        }
    }

}
