// HOST ONLY: simulated icon for visual tests, not a device icon resource.
import QtQuick
Item {
    property string name: ""
    property color color: "#BFE9D0"
    Rectangle {
        anchors.fill: parent
        color: "transparent"
        border.color: parent.color
        border.width: Math.max(1, width * 0.065)
        radius: width * 0.23
    }
    Text {
        anchors.centerIn: parent
        color: parent.color
        text: parent.parent.name.indexOf("calendar") >= 0 ? "D" :
              parent.parent.name.indexOf("settings") >= 0 ? "S" :
              parent.parent.name.indexOf("music") >= 0 ? "M" :
              parent.parent.name.indexOf("timer") >= 0 ? "T" :
              parent.parent.name.indexOf("alarm") >= 0 ? "A" : "+"
        font.pixelSize: Math.max(10, parent.width * 0.44)
    }
}
