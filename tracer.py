import frida
import os
import sys
from PyQt5.QtCore import (pyqtProperty, pyqtSignal, pyqtSlot, QAbstractListModel, QModelIndex, QObject, QSettings, Qt, QVariant)
from PyQt5.QtGui import QGuiApplication
from PyQt5.QtQml import (qmlRegisterType, QQmlApplicationEngine)

class Process(QObject):
    def __init__(self, device, pid, name, parent=None):
        super(Process, self).__init__(parent)

        self.device = device
        self._pid = pid
        self._name = name

    @pyqtProperty(int)
    def pid(self):
        return self._pid

    @pyqtProperty(str)
    def name(self):
        return self._name

class ProcessList(QAbstractListModel):
    ProcessRole = Qt.UserRole + 1

    _roles = {Qt.DisplayRole: 'name', ProcessRole: 'process'}

    def __init__(self, device, parent=None):
        super(ProcessList, self).__init__(parent)

        self.processes = []
        for process in sorted(device.enumerate_processes(), key=lambda p: p.name.lower()):
            self.processes.append(Process(device, process.pid, process.name, self))

    @pyqtSlot(int, result=Process)
    def get(self, row):
        return self.data(self.index(row, 0), self.ProcessRole)

    def rowCount(self, parent=QModelIndex()):
        return len(self.processes)

    def data(self, index, role=Qt.DisplayRole):
        try:
            process = self.processes[index.row()]
        except IndexError:
            return QVariant()
        if role == Qt.DisplayRole:
            return process.name
        elif role == self.ProcessRole:
            return process
        return QVariant()

    def roleNames(self):
        return self._roles

class Tracer(QObject):
    def __init__(self, parent=None):
        super(Tracer, self).__init__(parent)

        self._state = 'detached'

    stateChanged = pyqtSignal()

    @pyqtProperty(str, notify=stateChanged)
    def state(self):
        return self._state

    @state.setter
    def state(self, state):
        if state != self._state:
            self._state = state
            self.stateChanged.emit()

    @pyqtSlot(Process)
    def attach(self, process):
        if self.state != 'detached':
            raise Exception('invalid state')
        print "Attaching to pid %d" % process.pid
        self.state = 'attaching'

class Application(QGuiApplication):
    def __init__(self, argv):
        super(Application, self).__init__(argv)

        self.setOrganizationName("Frida")
        self.setOrganizationDomain("boblycat.org")
        self.setApplicationName("Tracer")

        qmlRegisterType(Process, 'Frida', 1, 0, 'Process')
        qmlRegisterType(ProcessList, 'Frida', 1, 0, 'ProcessList')
        qmlRegisterType(Tracer, 'Frida', 1, 0, 'Tracer')

        self._tracer = Tracer(self)
        localSystem = [device for device in frida.get_device_manager().enumerate_devices() if device.type == 'local'][0]
        self._processList = ProcessList(localSystem, self)
        self._process = 0
        self._triggerPort = 80

        self._settings = QSettings()

        self._loadSettings()

    tracerChanged = pyqtSignal()
    processListChanged = pyqtSignal()
    processChanged = pyqtSignal()
    triggerPortChanged = pyqtSignal()

    def _loadSettings(self):
        processName = self._settings.value('processName')
        for i, process, in enumerate(self._processList.processes):
            if process.name == processName:
                self._process = i
                break

        self._triggerPort = self._settings.value('triggerPort', self._triggerPort)

    @pyqtProperty(Tracer, notify=tracerChanged)
    def tracer(self):
        return self._tracer

    @pyqtProperty(ProcessList, notify=processListChanged)
    def processList(self):
        return self._processList

    @pyqtProperty(int, notify=processChanged)
    def process(self):
        return self._process

    @process.setter
    def process(self, process):
        if process != self._process:
            self._process = process
            self._settings.setValue('processName', self._processList.get(process).name)

    @pyqtProperty(int, notify=triggerPortChanged)
    def triggerPort(self):
        return self._triggerPort

    @triggerPort.setter
    def triggerPort(self, triggerPort):
        if triggerPort != self._triggerPort:
            self._triggerPort = triggerPort
            self._settings.setValue('triggerPort', triggerPort)


if __name__ == '__main__':
    application = Application(sys.argv)
    appdir = os.path.dirname(os.path.abspath(__file__))

    engine = QQmlApplicationEngine()

    context = engine.rootContext()
    context.setContextProperty('application', application)

    engine.load(os.path.join(appdir, "tracer.qml"))
    engine.setOutputWarningsToStandardError(True)

    window = engine.rootObjects()[0]
    window.show()

    application.exec_()
