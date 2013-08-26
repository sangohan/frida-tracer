from PyQt5.QtCore import pyqtProperty, pyqtSlot, QAbstractListModel, QModelIndex, Qt, QObject

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
