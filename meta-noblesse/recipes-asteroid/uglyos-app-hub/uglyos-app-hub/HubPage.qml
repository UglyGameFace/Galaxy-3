// SPDX-License-Identifier: MIT
// Native, OFFLINE UgLy|OS app catalog. This page never installs packages.
import QtQuick
import "HubCatalog.js" as Catalog

Item {
    id: hub
    objectName: "uglyos-app-hub"
    property var groups: ["all", "native-watch", "phone-bridge", "unsupported"]
    property var groupTitles: ["ALL", "WATCH", "PHONE", "LIMITS"]
    property int groupIndex: 0
    property var rows: Catalog.entries
    property int selected: -1
    property bool detailsOpen: selected >= 0
    property bool installEnabled: false

    function filterGroup(delta) {
        groupIndex = (groupIndex + delta + groups.length) % groups.length
        selected = -1
        updateRows()
    }
    function updateRows() {
        var group = groups[groupIndex]
        var next = []
        for (var i = 0; i < Catalog.entries.length; i++) {
            var record = Catalog.entries[i]
            if (group === "all" || record.kind === group)
                next.push(record)
        }
        rows = next
        list.positionViewAtBeginning()
    }
    function openDetails(index) {
        if (index >= 0 && index < rows.length)
            selected = index
    }
    function closeDetails() { selected = -1 }

    Rectangle { anchors.fill: parent; color: "#07130C" }

    Text {
        id: heading
        objectName: "uglyos-app-hub-title"
        anchors.top: parent.top
        anchors.topMargin: parent.height * 0.075
        anchors.horizontalCenter: parent.horizontalCenter
        width: parent.width * 0.80
        text: "UgLy|OS  APP HUB"
        color: "#A4F3BE"
        font.pixelSize: Math.max(12, parent.height * 0.052)
        font.bold: true
        elide: Text.ElideRight
        horizontalAlignment: Text.AlignHCenter
        renderType: Text.NativeRendering
    }
    Item {
        id: tabs
        anchors.top: heading.bottom
        anchors.topMargin: hub.height * 0.035
        anchors.horizontalCenter: parent.horizontalCenter
        width: parent.width * 0.78
        height: Math.max(36, hub.height * 0.11)
        z: 3
        Rectangle {
            anchors.fill: parent
            radius: height / 2
            color: "#13281C"
            border.color: "#508D66"
        }
        Text {
            anchors.centerIn: parent
            width: parent.width * 0.56
            text: hub.groupTitles[hub.groupIndex]
            color: "#F1FFF4"
            font.pixelSize: Math.max(12, parent.height * 0.39)
            horizontalAlignment: Text.AlignHCenter
            font.bold: true
            elide: Text.ElideRight
        }
        Text {
            anchors.left: parent.left
            anchors.leftMargin: parent.width * 0.08
            anchors.verticalCenter: parent.verticalCenter
            text: "\u2039"
            color: "#B4F4C9"
            font.pixelSize: parent.height * 0.82
        }
        Text {
            anchors.right: parent.right
            anchors.rightMargin: parent.width * 0.08
            anchors.verticalCenter: parent.verticalCenter
            text: "\u203a"
            color: "#B4F4C9"
            font.pixelSize: parent.height * 0.82
        }
        MouseArea {
            objectName: "uglyos-hub-prev-filter"
            anchors.left: parent.left
            width: parent.width * 0.23
            height: parent.height
            onClicked: hub.filterGroup(-1)
        }
        MouseArea {
            objectName: "uglyos-hub-next-filter"
            anchors.right: parent.right
            width: parent.width * 0.23
            height: parent.height
            onClicked: hub.filterGroup(1)
        }
    }
    Text {
        id: note
        anchors.top: tabs.bottom
        anchors.topMargin: hub.height * 0.018
        anchors.horizontalCenter: parent.horizontalCenter
        text: hub.rows.length + " ENTRIES  \u2022  BROWSE ONLY"
        color: "#8EB89E"
        font.pixelSize: Math.max(9, hub.height * 0.032)
    }
    ListView {
        id: list
        objectName: "uglyos-hub-list"
        anchors.fill: parent
        anchors.topMargin: hub.height * 0.315
        anchors.bottomMargin: hub.height * 0.085
        anchors.leftMargin: hub.width * 0.07
        anchors.rightMargin: hub.width * 0.07
        clip: true
        cacheBuffer: height * 0.38
        boundsBehavior: Flickable.StopAtBounds
        spacing: Math.max(5, height * 0.018)
        model: hub.rows
        delegate: MouseArea {
            id: tile
            objectName: "uglyos-hub-card-" + index
            width: list.width
            height: Math.max(62, list.height * 0.30)
            enabled: !list.dragging
            onClicked: hub.openDetails(index)
            Rectangle {
                anchors.fill: parent
                radius: Math.max(13, height * 0.21)
                color: tile.pressed ? "#1F4630" : "#10271A"
                border.color: tile.pressed ? "#A0E6B8" : "#385943"
            }
            Text {
                anchors.top: parent.top
                anchors.topMargin: parent.height * 0.21
                anchors.left: parent.left
                anchors.leftMargin: parent.width * 0.085
                anchors.right: parent.right
                anchors.rightMargin: parent.width * 0.085
                text: modelData.name
                color: "#F0FFF2"
                font.pixelSize: Math.max(12, parent.height * 0.235)
                font.bold: true
                elide: Text.ElideRight
                renderType: Text.NativeRendering
            }
            Text {
                anchors.bottom: parent.bottom
                anchors.bottomMargin: parent.height * 0.20
                anchors.left: parent.left
                anchors.leftMargin: parent.width * 0.085
                anchors.right: parent.right
                anchors.rightMargin: parent.width * 0.085
                text: modelData.category + "  |  " +
                      (modelData.kind === "native-watch" ? "ASTEROID" :
                       modelData.kind === "phone-bridge" ? "PHONE" : "UNSUPPORTED")
                color: "#9FCEAF"
                font.pixelSize: Math.max(10, parent.height * 0.165)
                elide: Text.ElideRight
            }
        }
    }
    // A read-only detail sheet: no Install, link-opening, package manager,
    // network, telephony or privilege escalation hooks.
    Rectangle {
        id: sheet
        objectName: "uglyos-hub-details"
        anchors.fill: parent
        visible: hub.detailsOpen
        z: 6
        color: "#091710"
        property var record: hub.detailsOpen ? hub.rows[hub.selected] : null
        Text {
            id: detailsTitle
            anchors.top: parent.top
            anchors.topMargin: parent.height * 0.17
            anchors.horizontalCenter: parent.horizontalCenter
            width: parent.width * 0.72
            text: sheet.record ? sheet.record.name : ""
            color: "#C6F4D3"
            font.bold: true
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
            font.pixelSize: Math.max(15, parent.height * 0.053)
        }
        Flickable {
            id: textArea
            anchors.top: detailsTitle.bottom
            anchors.topMargin: parent.height * 0.035
            anchors.bottom: close.top
            anchors.bottomMargin: parent.height * 0.028
            anchors.left: parent.left
            anchors.leftMargin: parent.width * 0.17
            anchors.right: parent.right
            anchors.rightMargin: parent.width * 0.17
            contentHeight: detailText.implicitHeight
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            Text {
                id: detailText
                width: textArea.width
                wrapMode: Text.WordWrap
                text: sheet.record
                      ? sheet.record.summary + "\n\nStatus: " +
                        sheet.record.state.replace(/-/g, " ") +
                        "\n\nInstallation unavailable"
                      : ""
                color: "#D6EADB"
                font.pixelSize: Math.max(11, hub.height * 0.041)
                lineHeight: 1.15
                renderType: Text.NativeRendering
            }
        }
        Rectangle {
            id: close
            objectName: "uglyos-hub-close"
            anchors.bottom: parent.bottom
            anchors.bottomMargin: parent.height * 0.10
            anchors.horizontalCenter: parent.horizontalCenter
            width: parent.width * 0.52
            height: Math.max(38, parent.height * 0.12)
            radius: height / 2
            color: "#246744"
            Text {
                anchors.centerIn: parent
                text: "BACK"
                color: "#F0FFF4"
                font.pixelSize: Math.max(12, parent.height * 0.41)
                font.bold: true
            }
            MouseArea {
                anchors.fill: parent
                onClicked: hub.closeDetails()
            }
        }
    }
    Component.onCompleted: updateRows()
}
