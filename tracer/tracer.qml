import QtQuick 2.1
import QtQuick.Controls 1.0
import QtQuick.Window 2.0

ApplicationWindow {
    title: qsTr("Tracer")
    width: 640
    height: 480

    menuBar: MenuBar {
        Menu {
            title: qsTr("File")
            MenuItem {
                text: qsTr("Exit")
                onTriggered: Qt.quit();
            }
        }
    }

    Text {
        anchors.top: parent.top
        anchors.right: parent.right
        anchors.topMargin: 10
        anchors.rightMargin: 10
        text: application.tracer.state
        font.pixelSize: 12
    }

    GroupBox {
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.topMargin: 10
        anchors.leftMargin: 10
        enabled: application.tracer.state === 'detached'

        Column {
            Label {
                id: processLabel
                text: "Process to trace"
            }

            ComboBox {
                id: process
                width: 159
                height: 26
                model: application.processList
                textRole: 'name'
                currentIndex: application.process
                onCurrentIndexChanged: application.process = process.currentIndex
            }

            Label {
                id: triggerLabel
                text: "TCP port use as trigger"
            }

            TextField {
                id: trigger
                width: 43
                height: 20
                font.pixelSize: 12
                text: application.triggerPort
                onTextChanged: application.triggerPort = parseInt(trigger.text, 10)
            }

            Button {
                id: attach
                text: qsTr("Attach")
                onClicked: {
                    application.tracer.attach(application.processList.get(process.currentIndex), application.triggerPort)
                }
            }
        }
    }
}
