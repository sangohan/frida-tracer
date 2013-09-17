from frida import Device
from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QThread

from .process import Process

class Tracer(QObject):
    def __init__(self, parent=None):
        super(Tracer, self).__init__(parent)

        self._state = 'detached'
        self._workerThread = QThread()
        self._worker = Worker()
        self._worker.moveToThread(self._workerThread)
        self._workerThread.finished.connect(self._worker.deleteLater)
        self._attach.connect(self._worker.attach)
        self._worker.attachCompleted.connect(self._onAttachCompleted)
        self._workerThread.start()

    stateChanged = pyqtSignal()
    _attach = pyqtSignal(Process, int)

    def dispose(self):
        self._workerThread.quit()
        self._workerThread.wait()

    @pyqtProperty(str, notify=stateChanged)
    def state(self):
        return self._state

    @state.setter
    def state(self, state):
        if state != self._state:
            self._state = state
            self.stateChanged.emit()

    @pyqtSlot(Process, int)
    def attach(self, process, triggerPort):
        if self.state != 'detached':
            raise Exception('invalid state')
        self.state = 'attaching'
        self._attach.emit(process, triggerPort)

    @pyqtSlot(str)
    def _onAttachCompleted(self, error):
        print error
        if not error:
            self.state = 'attached'
        else:
            self.state = 'detached'

TRACER_SCRIPT_TEMPLATE = """
Stalker.trustThreshold = 2000;
Stalker.queueCapacity = 1000000;
Stalker.queueDrainInterval = 50;

var modules = [];
Process.enumerateModules({
    onMatch: function onMatch(name, address, path) {
        modules.push({ name: name, address: "0x" + address.toString(16) });
    },
    onComplete: function onComplete() {
        send({ name: '+sync', from: "/process/modules", payload: { items: modules } });
        modules = null;
    }
});

var stalkedThreadId = null;
var interceptReadFunction = function interceptReadFunction(functionName) {
    Interceptor.attach(Module.findExportByName('libSystem.B.dylib', functionName), {
        onEnter: function(args) {
            this.fd = args[0].toInt32();
        },
        onLeave: function (retval) {
            var fd = this.fd;
            if (Socket.type(fd) === 'tcp') {
                var address = Socket.peerAddress(fd);
                if (address !== null && address.port === %(triggerPort)d) {
                    send({ name: '+add', from: "/interceptor/functions", payload: { items: [{ name: functionName }] } });
                    if (stalkedThreadId === null) {
                        stalkedThreadId = Process.getCurrentThreadId();
                        Stalker.follow({
                            onReceive: function onReceive(events) {
                                send({ name: '+add', from: "/stalker/events", payload: { items: events } });
                            }
                        });
                    }
                }
            }
        }
    });
}
interceptReadFunction('recv');
interceptReadFunction('read$UNIX2003');
interceptReadFunction('readv$UNIX2003');
"""

class Worker(QObject):
    attachCompleted = pyqtSignal(str)

    def __init__(self, parent=None):
        super(Worker, self).__init__(parent)

        self._process = None
        self._script = None

    @pyqtSlot(Process, int)
    def attach(self, process, triggerPort):
        try:
            self._process = process.device.attach(process.pid)
            self._script = self._process._session.create_script(TRACER_SCRIPT_TEMPLATE % {
                'triggerPort': triggerPort
            })
            self._script.on('message', self._onMessage)
            self._script.load()
            self.attachCompleted.emit(None)
        except Exception, e:
            self._script = None
            if self._process is not None:
                try:
                    self._process.detach()
                except:
                    pass
                self._process = None
            self.attachCompleted.emit(str(e))

    def _onMessage(self, message, data):
        print "_onMessage message:", message

