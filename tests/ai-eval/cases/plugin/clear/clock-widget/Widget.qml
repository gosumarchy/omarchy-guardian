// A clock for the bar: the time, and the date as a tooltip. It reads the
// system clock and nothing else.
import QtQuick
import qs.Commons
import qs.Ui

Item {
  id: root

  readonly property bool showSeconds: setting("showSeconds", false)
  property date now: new Date()

  implicitWidth: label.implicitWidth
  implicitHeight: label.implicitHeight

  Timer {
    interval: root.showSeconds ? 1000 : 15000
    running: true
    repeat: true
    onTriggered: root.now = new Date()
  }

  Text {
    id: label
    color: Color.foreground
    font.family: Style.font.family
    text: Qt.formatTime(root.now, root.showSeconds ? "HH:mm:ss" : "HH:mm")
  }

  HoverHandler {
    id: hover
  }

  ToolTip {
    visible: hover.hovered
    text: Qt.formatDate(root.now, "dddd, d MMMM yyyy")
  }
}
