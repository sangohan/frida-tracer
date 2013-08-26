import frida
import os
from PyQt5.QtCore import pyqtProperty, pyqtSignal, QSettings
from PyQt5.QtGui import QGuiApplication
from PyQt5.QtQml import qmlRegisterType, QQmlApplicationEngine

from .process import Process, ProcessList
from .tracer import Tracer

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

        self._engine = QQmlApplicationEngine()
        self._engine.setOutputWarningsToStandardError(True)
        self._engine.rootContext().setContextProperty('application', self)
        appdir = os.path.dirname(os.path.abspath(__file__))
        self._engine.load(os.path.join(appdir, "tracer.qml"))

    tracerChanged = pyqtSignal()
    processListChanged = pyqtSignal()
    processChanged = pyqtSignal()
    triggerPortChanged = pyqtSignal()

    def run(self):
        window = self._engine.rootObjects()[0]
        window.show()
        self.exec_()

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
