import frida
import signal
import sys
from PyQt5.QtCore import QCoreApplication

from tracer.process import ProcessList
from tracer.tracer import Tracer

if __name__ == '__main__':
    application = QCoreApplication(sys.argv)
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    localSystem = [device for device in frida.get_device_manager().enumerate_devices() if device.type == 'local'][0]
    processName = sys.argv[1]
    triggerPort = int(sys.argv[2])
    processList = ProcessList(localSystem)
    target = None
    for process in processList.processes:
        if process.name == processName:
            target = process
            break
    if target is None:
        print >> sys.stderr, "No such process"
        sys.exit(1)
    tracer = Tracer()
    tracer.attach(target, triggerPort)

    application.exec_()
