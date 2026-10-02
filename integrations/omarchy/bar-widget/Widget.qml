// Omarchy Guardian in the bar: a shield that shows whether Guardian protects
// this machine, turning the bar's urgent colour when something needs
// attention (a gate is off, a setting is broken, or a recent block has not
// been looked at) and dim when protection is off. Clicking opens a panel
// with the details and a few actions; everything else stays in the settings
// app (right-click, or the Settings button).
//
// All data comes from `omarchy-guardian status`, a local command; the widget
// runs nothing else except the actions the user clicks.
import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
  id: root
  moduleName: "omarchy-guardian"

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color accent: Color.accent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property int refreshIntervalSec: Math.max(10, setting("refreshIntervalSec", 30))

  // From `omarchy-guardian status`.
  property var status: null
  property string lastError: ""
  readonly property string state: status ? status.state : (lastError ? "attention" : "unknown")
  readonly property var gates: status ? status.gates : []
  readonly property var issues: status ? status.issues : []
  readonly property var block: status ? status.last_block : null

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onOpenedChanged: if (opened) { refresh(); Qt.callLater(function() { keyCatcher.forceActiveFocus() }) }

  function refresh() {
    if (statusProcess.running) return
    statusProcess.running = true
    watchdog.restart()
  }

  function run(argv) {
    Quickshell.execDetached(argv)
    close()
    delayedRefresh.restart()
  }

  function inTerminal(command) {
    run(["omarchy-launch-floating-terminal-with-presentation", command])
  }

  function openSettings() {
    run(["omarchy-launch-tui", "--app-id=TUI.float", "omarchy-guardian", "tui"])
  }

  function age(seconds) {
    if (seconds < 60) return "just now"
    if (seconds < 3600) return Math.floor(seconds / 60) + " min ago"
    if (seconds < 86400) return Math.floor(seconds / 3600) + " h ago"
    return Math.floor(seconds / 86400) + " d ago"
  }

  function levelName(profile) {
    if (profile === "standard") return "Balanced protection"
    if (profile === "strict") return "Maximum protection"
    if (profile === "local-only") return "Private (no AI)"
    return profile
  }

  function headline() {
    if (state === "ok") return "Protecting this machine"
    if (state === "off") return "Protection is off"
    if (state === "attention") return lastError ? "Guardian status unavailable" : "Needs your attention"
    return "Checking…"
  }

  Timer {
    interval: root.refreshIntervalSec * 1000
    repeat: true
    running: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }
  Timer { id: delayedRefresh; interval: 1500; onTriggered: root.refresh() }
  // A hung status call must not block every later refresh.
  Timer { id: watchdog; interval: 15000; onTriggered: statusProcess.running = false }

  Process {
    id: statusProcess
    command: ["omarchy-guardian", "status"]
    stdout: StdioCollector { id: statusOut; waitForEnd: true }
    stderr: StdioCollector { id: statusErr; waitForEnd: true }
    onExited: function(exitCode) {
      watchdog.stop()
      if (exitCode !== 0) {
        root.lastError = String(statusErr.text || "omarchy-guardian status failed").trim()
        return
      }
      try {
        root.status = JSON.parse(String(statusOut.text))
        root.lastError = ""
      } catch (error) {
        root.lastError = "could not read Guardian's status"
      }
    }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: "󰒃"
    active: root.state === "attention"
    dimmed: root.state === "off" || root.state === "unknown"
    tooltipText: "Guardian: " + root.headline()
    onPressed: function(code) {
      if (code === Qt.RightButton) root.openSettings()
      else if (code === Qt.MiddleButton) root.refresh()
      else root.toggle()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(360))
    contentHeight: panel.fittedContentHeight(column.implicitHeight, Style.space(560))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTextKey: function(key) {
        if (key === "s") root.openSettings()
        else if (key === "r") root.refresh()
      }

      Column {
        id: column
        width: parent.width
        spacing: Style.space(12)

        PanelHero {
          width: parent.width
          title: "Guardian"
          meta: root.status
            ? (root.levelName(root.status.profile) + " · " + root.status.model).toUpperCase()
            : root.lastError.toUpperCase()
          foreground: root.foreground
          fontFamily: root.fontFamily
          iconComponent: Component {
            Image {
              width: Style.font.display * 1.6
              height: Style.font.display * 1.6
              sourceSize.width: 128
              sourceSize.height: 128
              smooth: false
              source: root.state === "attention"
                ? "file:///usr/share/icons/hicolor/scalable/apps/omarchy-guardian-alert.svg"
                : "file:///usr/share/icons/hicolor/scalable/apps/omarchy-guardian.svg"
              opacity: root.state === "off" ? 0.5 : 1
            }
          }
        }

        StatusRow {
          width: parent.width
          label: root.headline()
          value: root.state === "ok" ? "PROTECTED" : (root.state === "off" ? "OFF" : "CHECK")
          valueColor: root.state === "ok" ? root.accent : root.urgent
          bold: true
        }

        PanelSeparator { width: parent.width; foreground: root.foreground }

        PanelSectionHeader { width: parent.width; text: "GATES"; foreground: root.foreground; fontFamily: root.fontFamily }
        Repeater {
          model: root.gates
          delegate: StatusRow {
            required property var modelData
            width: column.width
            label: modelData.label
            detail: modelData.detail
            value: modelData.state === "on" ? "ON" : (modelData.state === "unavailable" ? "N/A" : modelData.state.toUpperCase())
            valueColor: modelData.state === "on" ? root.accent : (modelData.state === "unavailable" ? root.dim : root.urgent)
          }
        }

        Column {
          width: parent.width
          spacing: Style.space(8)
          visible: root.issues.length > 0
          PanelSeparator { width: parent.width; foreground: root.foreground }
          PanelSectionHeader { width: parent.width; text: "NEEDS FIXING"; foreground: root.foreground; fontFamily: root.fontFamily }
          Repeater {
            model: root.issues
            delegate: Text {
              required property var modelData
              textFormat: Text.PlainText
              width: column.width
              text: modelData
              color: root.urgent
              wrapMode: Text.WordWrap
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
            }
          }
        }

        Column {
          width: parent.width
          spacing: Style.space(8)
          visible: root.block !== null
          PanelSeparator { width: parent.width; foreground: root.foreground }
          StatusRow {
            width: parent.width
            label: "LAST BLOCK"
            labelColor: root.dim
            small: true
            value: root.block ? root.age(root.block.age_secs).toUpperCase() : ""
            valueColor: root.block && root.block.unseen ? root.urgent : root.dim
          }
          Text {
            textFormat: Text.PlainText
            width: parent.width
            text: root.block ? root.block.title.replace(/^Guardian blocked /, "Blocked ") : ""
            color: root.foreground
            wrapMode: Text.WordWrap
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
          }
        }

        PanelSeparator { width: parent.width; foreground: root.foreground }

        Row {
          id: tiles
          width: parent.width
          spacing: Style.space(10)
          readonly property real tileWidth: (width - spacing * 2) / 3

          Tile {
            width: tiles.tileWidth
            glyph: "󰈙"
            label: "Report"
            enabled: root.block !== null
            onActivated: {
              if (root.block && root.block.unseen) Quickshell.execDetached(["omarchy-guardian", "status", "--dismiss"])
              root.run(["omarchy-launch-browser", "file://" + root.block.report])
            }
          }
          Tile {
            width: tiles.tileWidth
            glyph: root.state === "off" || root.issues.length > 0 ? "󰒃" : "󰦞"
            label: root.state === "off" || root.issues.length > 0 ? "Protect" : "Turn off"
            onActivated: root.state === "off" || root.issues.length > 0
              ? root.inTerminal("omarchy-guardian protect")
              : root.inTerminal("omarchy-guardian protect --off")
          }
          Tile {
            width: tiles.tileWidth
            glyph: "󰒓"
            label: "Settings"
            onActivated: root.openSettings()
          }
        }
      }
    }
  }

  // A label on the left and a status word on the right, as in Omarchy's
  // agents panel; an optional detail line under the label.
  component StatusRow: Item {
    id: statusRow
    property string label: ""
    property string detail: ""
    property string value: ""
    property color valueColor: root.accent
    property color labelColor: root.foreground
    property bool bold: false
    property bool small: false

    implicitHeight: statusLabel.implicitHeight + (statusDetail.visible ? statusDetail.implicitHeight : 0)

    Text {
      id: statusLabel
      textFormat: Text.PlainText
      anchors.left: parent.left
      anchors.right: statusValue.left
      anchors.rightMargin: Style.space(10)
      text: statusRow.label
      color: statusRow.labelColor
      elide: Text.ElideRight
      font.family: root.fontFamily
      font.pixelSize: statusRow.small ? Style.font.caption : Style.font.body
      font.bold: statusRow.bold
      font.letterSpacing: statusRow.small ? 1.2 : 0
    }
    Text {
      id: statusDetail
      textFormat: Text.PlainText
      visible: statusRow.detail !== ""
      anchors.top: statusLabel.bottom
      anchors.left: parent.left
      anchors.right: statusValue.left
      anchors.rightMargin: Style.space(10)
      text: statusRow.detail
      color: root.dim
      wrapMode: Text.WordWrap
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
    }
    Text {
      id: statusValue
      textFormat: Text.PlainText
      anchors.right: parent.right
      anchors.top: parent.top
      text: statusRow.value
      color: statusRow.valueColor
      font.family: root.fontFamily
      font.pixelSize: statusRow.small ? Style.font.caption : Style.font.bodySmall
      font.bold: true
      font.letterSpacing: 1.2
    }
  }

  // A square action tile: an accent glyph over a label.
  component Tile: Rectangle {
    id: tile
    property string glyph: ""
    property string label: ""
    signal activated()

    height: Style.space(84)
    radius: Style.cornerRadius
    opacity: enabled ? 1 : 0.4
    color: tileMouse.containsMouse && enabled
      ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.12)
      : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.05)

    Column {
      anchors.centerIn: parent
      spacing: Style.space(8)
      Text {
        textFormat: Text.PlainText
        anchors.horizontalCenter: parent.horizontalCenter
        text: tile.glyph
        color: root.accent
        font.family: root.fontFamily
        font.pixelSize: Style.font.display
      }
      Text {
        textFormat: Text.PlainText
        anchors.horizontalCenter: parent.horizontalCenter
        text: tile.label
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
        font.bold: true
      }
    }
    MouseArea {
      id: tileMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: tile.enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
      onClicked: if (tile.enabled) tile.activated()
    }
  }
}
