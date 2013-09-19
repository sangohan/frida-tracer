import bisect
import collections
import struct

def enum(**enums):
    return type('Enum', (), enums)

class Module:
    def __init__(self, name, address, size):
        self.name = name
        self.address = address
        self.size = size

    def __repr__(self):
        return "%s <0x%x to 0x%x>" % (self.name, self.address, self.address + self.size - 1)

class Function:
    def __init__(self, module, name, address):
        self.module = module
        self.name = name
        self.address = address

    def __repr__(self):
        return self.module.name + "::" + self.name

class Resolver:
    def __init__(self):
        self.modules = collections.OrderedDict()
        self.functions = {}

    def sync(self, modules):
        parsedModules = []
        self.functions = {}
        for moduleData in modules:
            module = Module(moduleData['name'], int(moduleData['address'], 16), moduleData['size'])
            parsedModules.append(module)
            for export in moduleData['exports']:
                func = Function(module, export['name'], int(export['address'], 16))
                self.functions[func.address] = func
        parsedModules.sort(key=lambda m: m.address)
        self.modules = collections.OrderedDict()
        for module in parsedModules:
            self.modules[module.address] = module

    def moduleAt(self, address):
        keys = self.modules.keys()
        i = bisect.bisect_right(keys, address)
        assert i
        module = self.modules[keys[i - 1]]
        if address >= module.address + module.size:
            return None
        return module

    def functionAt(self, address):
        return self.functions.get(address)

class Processor:
    State = enum(CREATED=1, READY=2)

    def __init__(self):
        self.state = Processor.State.CREATED
        self.resolver = Resolver()
        self.pending = []

    def push(self, message, data):
        if message['type'] == 'send':
            stanza = message['payload']
            sender = stanza['from']
            name = stanza['name']
            if sender == "/stalker/events" and name == '+add':
                self.pending.append(data)
                self._processPending()
            elif sender == "/interceptor/functions" and name == '+add':
                pass
            elif sender == "/process/modules" and name == '+sync':
                self._onProcessModulesReceived(stanza['payload']['items'])
            else:
                print message
        else:
            print message

    def _onProcessModulesReceived(self, modules):
        if self.state == Processor.State.CREATED:
            self.state = Processor.State.READY
            self.resolver.sync(modules)
            self._processPending()

    def _processPending(self):
        if self.state == Processor.State.READY:
            for data in self.pending:
                for offset in range(0, len(data), 16):
                    [t, location, target, depth] = struct.unpack("IIII", data[offset:offset + 16])
                    function = self.resolver.functionAt(target)
                    if function is not None:
                        print "%s" % function
                    else:
                        module = self.resolver.moduleAt(target)
                        if module is not None:
                            print "%s+%d" % (module.name, target - module.address)
                        else:
                            print "0x%x" % target
            self.pending = []


if __name__ == '__main__':
    import cPickle as pickle
    import sys

    processor = Processor()
    messages = open(sys.argv[1], 'rb')
    while True:
        try:
            [message, data] = pickle.load(messages)
            processor.push(message, data)
        except EOFError:
            break
