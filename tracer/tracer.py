from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from .process import Process

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
