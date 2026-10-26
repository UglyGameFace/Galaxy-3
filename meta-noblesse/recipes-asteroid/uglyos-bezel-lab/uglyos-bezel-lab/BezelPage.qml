// SPDX-License-Identifier: MIT
// Native watch-side interaction preview. The physical evdev -> Qt wheel
// binding has NOT been verified on the SM-R840X. No system-wide interception.
import QtQuick
import Nemo.Configuration
import "BezelEngine.js" as Bezel

Item {
    id: root
    objectName: "uglyos-bezel-lab"
    focus: true
    property var snapshot: Bezel.makeState()
    property bool hardwareWheelVerified: false
    property bool actualButtonCombosVerified: false
    property bool companionConnected: false
    property bool hapticsVerified: false

    ConfigurationValue {
        id: storedGestures
        key: "/desktop/uglyos/bezel/local-gestures"
        defaultValue: "[]"
    }
    ConfigurationValue {
        id: directionPreference
        key: "/desktop/uglyos/bezel/invert-direction"
        defaultValue: false
    }
    function send(event) {
        const previous = snapshot
        snapshot = Bezel.apply(previous, event)
        if (JSON.stringify(previous.gestures) !== JSON.stringify(snapshot.gestures))
            storedGestures.value = JSON.stringify(snapshot.gestures)
    }
    function detents(delta) {
        if (!Number.isInteger(delta) || delta === 0 || Math.abs(delta) > 8) return
        send({kind:"rotate", steps: (directionPreference.value === true ? -delta : delta),
              ms: Date.now()})
    }
    function showTarget() {
        var next = Bezel.LOCAL_ACTIONS
        var current = next.indexOf(snapshot.gestureTarget)
        send({kind:"target",value:next[(current + 1) % next.length]})
    }
    function confirm() { send({kind:"choose"}) }
    function goBack() { send({kind:"back"}) }

    Component.onCompleted: {
        try {
            var saved = JSON.parse(storedGestures.value)
            snapshot = Bezel.loadGestures(snapshot, saved)
        } catch (error) {
            // Corrupt settings never execute unrecognized action bindings.
            snapshot = Bezel.makeState()
        }
    }

    // Qt wheel works for host synthetic input. Whether the pinned Watch3
    // tizen_detent node is routed into Qt/libinput remains unverified.
    WheelHandler {
        id: wheelAdapter
        objectName: "uglyos-bezel-wheel-adapter"
        target: null
        onWheel: (event) => {
            var steps = Math.round(event.angleDelta.y / 120)
            if (steps !== 0 && Math.abs(steps) <= 8) root.detents(steps)
        }
    }
    Keys.onPressed: (event) => {
        if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter ||
            event.key === Qt.Key_Select) {
            confirm()
            event.accepted = true
        } else if (event.key === Qt.Key_Escape || event.key === Qt.Key_Back) {
            goBack()
            event.accepted = true
        }
    }

    Rectangle {
        anchors.fill: parent
        color: "#06110B"
    }
    Rectangle {
        anchors.centerIn: parent
        width: parent.width * 0.89
        height: width
        radius: width / 2
        color: "transparent"
        border.width: Math.max(2, width * 0.009)
        border.color: "#36734E"
    }
    Rectangle {
        anchors.centerIn: parent
        width: parent.width * 0.77
        height: width
        radius: width / 2
        color: "#0B2318"
        border.width: 1
        border.color: "#2F7047"
    }
    Text {
        id: heading
        objectName: "uglyos-bezel-title"
        anchors.top: parent.top
        anchors.topMargin: parent.height * 0.10
        anchors.horizontalCenter: parent.horizontalCenter
        width: parent.width * 0.72
        text: "UgLy|OS  BEZEL"
        horizontalAlignment: Text.AlignHCenter
        font.pixelSize: Math.max(12, parent.height * 0.052)
        color: "#D1FFDF"
        font.bold: true
        elide: Text.ElideRight
        renderType: Text.NativeRendering
    }
    Text {
        anchors.top: heading.bottom
        anchors.topMargin: parent.height * 0.015
        width: parent.width * 0.66
        anchors.horizontalCenter: parent.horizontalCenter
        text: root.snapshot.page.toUpperCase() + " • " + root.snapshot.context.toUpperCase()
        color: "#82B99A"
        font.pixelSize: Math.max(10, parent.height * 0.035)
        horizontalAlignment: Text.AlignHCenter
        elide: Text.ElideRight
    }

    Text {
        objectName: "uglyos-bezel-selection"
        anchors.centerIn: parent
        anchors.verticalCenterOffset: -parent.height * 0.02
        width: parent.width * 0.72
        wrapMode: Text.WordWrap
        maximumLineCount: 3
        horizontalAlignment: Text.AlignHCenter
        font.bold: true
        font.pixelSize: Math.max(16, parent.height * 0.060)
        color: "#ECFFF3"
        text: {
            const s = root.snapshot
            if (s.gestureArmed) return s.lastResult
            if (s.page === "ring") return Bezel.LOCAL_ACTIONS[s.focus].toUpperCase()
            if (s.page === "precision") return s.dial + " / 100"
            if (s.page === "keyboard") return Bezel.CHARACTERS[s.keyboardIndex] === " "
                ? "SPACE" : Bezel.CHARACTERS[s.keyboardIndex]
            if (s.page === "timeline") return Math.floor(s.timelineSeconds / 60)
                + "m " + (s.timelineSeconds % 60) + "s"
            if (s.page === "game") return "SLOT " + (s.gameSlot + 1) + " / 24"
            if (s.page === "gestures") return s.gestures.length + " SAVED"
            return "LOCAL ONLY"
        }
        renderType: Text.NativeRendering
    }
    Text {
        id: detail
        objectName: "uglyos-bezel-status"
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.verticalCenter: parent.verticalCenter
        anchors.verticalCenterOffset: parent.height * 0.115
        width: parent.width * 0.74
        horizontalAlignment: Text.AlignHCenter
        wrapMode: Text.WordWrap
        maximumLineCount: 3
        font.pixelSize: Math.max(10, parent.height * 0.036)
        color: "#A9D6B9"
        text: root.snapshot.page === "keyboard" ? root.snapshot.keyboardText :
              root.snapshot.page === "gestures" ?
              ("Target: " + root.snapshot.gestureTarget + " • " + root.snapshot.lastResult) :
              root.snapshot.page === "features" ?
              "Phone actions, haptics and OS-wide controls need adapters" :
              root.snapshot.lastResult
    }
    // Touch controls are debug/accessibility fallback, not proof that
    // the physical buttons or bezel have been mapped to Qt on hardware.
    Row {
        id: actions
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.bottom: parent.bottom
        anchors.bottomMargin: parent.height * 0.115
        spacing: Math.max(5, parent.width * 0.012)
        Repeater {
            model: ["‹", "OK", "›", "BACK"]
            delegate: Rectangle {
                objectName: "uglyos-bezel-action-" + index
                width: Math.max(40, root.width * (index === 3 ? 0.20 : 0.17))
                height: Math.max(30, root.height * 0.105)
                radius: height / 2
                color: "#1C5033"
                border.color: "#7AC796"
                Text {
                    anchors.centerIn: parent
                    text: modelData
                    color: "white"
                    font.bold: true
                    font.pixelSize: Math.max(10, parent.height * 0.37)
                }
                MouseArea {
                    anchors.fill: parent
                    onClicked: {
                        if (index === 0) root.detents(-1)
                        else if (index === 1) root.confirm()
                        else if (index === 2) root.detents(1)
                        else root.goBack()
                    }
                }
            }
        }
    }
    Row {
        id: secondaryControls
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.bottom: actions.top
        anchors.bottomMargin: root.height * 0.017
        spacing: Math.max(5, root.width * 0.015)
        Repeater {
            model: root.snapshot.page === "gestures" ?
                   ["RECORD", "RUN", "TARGET"] : ["MODE", "INVERT"]
            delegate: Rectangle {
                objectName: "uglyos-bezel-secondary-" + index
                width: root.width * (root.snapshot.page === "gestures" ? 0.22 : 0.31)
                height: root.height * 0.075
                radius: height / 2
                color: "#18402A"
                border.color: "#4F9770"
                Text {
                    anchors.centerIn: parent
                    text: modelData
                    color: "#E8FFEF"
                    font.pixelSize: Math.max(10,parent.height * 0.38)
                }
                MouseArea {
                    anchors.fill: parent
                    onClicked: {
                        if (root.snapshot.page === "gestures") {
                            if (index === 0)
                                root.send(root.snapshot.gestureArmed ?
                                          {kind:"cancel"} : {kind:"arm",record:true})
                            else if (index === 1)
                                root.send({kind:"arm",record:false})
                            else root.showTarget()
                        } else if (index === 0) {
                            const contexts = Bezel.CONTEXTS
                            const pos = contexts.indexOf(root.snapshot.context)
                            root.send({kind:"context",value:contexts[(pos+1)%contexts.length]})
                        } else {
                            directionPreference.value = directionPreference.value !== true
                            root.send({kind:"context",value:root.snapshot.context})
                        }
                    }
                }
            }
        }
    }
    // No live remote command dispatch, fake notifications, continuous
    // animation, unverified haptic or kernel input permission requests.
}
