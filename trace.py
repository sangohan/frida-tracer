import frida
import struct
import threading

TRACER_SCRIPT_TEMPLATE = """
Stalker.trustThreshold = 2000;
Stalker.queueCapacity = 1000000;
Stalker.queueDrainInterval = 50;

var initialize = function initialize() {
    sendModules(function () {
        interceptReadFunction('recv');
        interceptReadFunction('read$UNIX2003');
        interceptReadFunction('readv$UNIX2003');
    });
};

var sendModules = function sendModules(callback) {
    var modules = [];
    Process.enumerateModules({
        onMatch: function onMatch(name, address, size, path) {
            modules.push({ name: name, address: "0x" + address.toString(16), size: size, exports: [] });
        },
        onComplete: function onComplete() {
            var process = function process(pending) {
                if (pending.length === 0) {
                    send({ name: '+sync', from: "/process/modules", payload: { items: modules } });
                    callback();
                    return;
                }
                var module = pending.shift();
                var exports = module.exports;
                setTimeout(function enumerateExports() {
                    Module.enumerateExports(module.name, {
                        onMatch: function onMatch(name, address) {
                            exports.push({
                                name: name,
                                address: "0x" + address.toString(16)
                            });
                        },
                        onComplete: function onComplete() {
                            process(pending);
                        }
                    });
                }, 0);
            };
            process(modules.slice(0));
        }
    });
};

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
                if (address !== null && address.port === %(trigger_port)d) {
                    send({ name: '+add', from: "/interceptor/functions", payload: { items: [{ name: functionName }] } });
                    if (stalkedThreadId === null) {
                        stalkedThreadId = Process.getCurrentThreadId();
                        Stalker.follow(stalkedThreadId, {
                            events: {
                                call: true
                            },
                            onReceive: function onReceive(events) {
                                send({ name: '+add', from: "/stalker/events", payload: { size: events.length } }, events);
                            }
                        });
                    }
                }
            }
        }
    });
}

setTimeout(initialize, 0);
"""

events = open('events.csv', 'w')

class Capture(object):
    def __init__(self, pid, trigger_port):
        super(Capture, self).__init__()
        self._pid = pid
        self._trigger_port = trigger_port
        self._session = None
        self._script = None
        self._on_stop = []

    def dispose(self):
        self.stop()
        if self._session is not None:
            self._session.detach()
            self._session = None

    def start(self):
        self.stop()
        if self._session is None:
            self._session = frida.attach(self._pid)
            self._session.on('detached', self._on_detached)
        self._script = self._session._session.create_script(TRACER_SCRIPT_TEMPLATE % {
            'trigger_port': self._trigger_port
        })
        self._script.on('message', self._on_message)
        self._script.load()

    def stop(self):
        if self._script is None:
            return
        self._script.unload()
        self._script = None

    def on(self, signal, callback):
        if signal == 'stop':
            self._on_stop.append(callback)
        else:
            raise NotImplementedError("unsupported signal")

    def _on_detached(self):
        self._session = None
        self._script = None
        for callback in self._on_stop:
            try:
                callback()
            except Exception, e:
                print "Uh oh:", e
        self._on_stop = []

    def _on_message(self, message, data):
        if message['type'] == 'send':
            stanza = message['payload']
            if stanza['from'] == "/stalker/events" and stanza['name'] == '+add':
                for offset in range(0, len(data), 16):
                    [t, location, target, depth] = struct.unpack("IIII", data[offset:offset + 16])
                    events.write("0x%x,0x%x,%d\n" % (location, target, depth))
                events.flush()
            elif stanza['from'] == "/process/modules" and stanza['name'] == '+sync':
                print "Got modules!"
                try:
                    with open('modules.csv', 'w') as modules:
                        with open('exports.csv', 'w') as exports:
                            for module in stanza['payload']['items']:
                                print "Module:", module
                                print "l=", len(module['exports'])
                                modules.write("%s,%s,%d\n" % (module['name'], module['address'], module['size']))
                                for export in module['exports']:
                                    exports.write("%s,%s,%s\n" % (module['name'], export['name'], export['address']))
                except Exception, e:
                    print "Oops:", e
            elif stanza['from'] == "/interceptor/functions" and stanza['name'] == '+add':
                pass
            else:
                print "stanza: name=%s from=%s" % (stanza['name'], stanza['from'])
        else:
            print "message:", message


if __name__ == '__main__':
    import sys

    class Application(object):
        def __init__(self, pid, trigger_port):
            self._stop = threading.Event()
            self._capture = Capture(pid, trigger_port)
            self._capture.on('stop', self._on_stop)

        def dispose(self):
            self._capture.dispose()

        def run(self):
            keyboard_handler = KeyboardHandler(self._stop)
            keyboard_handler.start()
            self._capture.start()
            self._stop.wait()
            self._capture.stop()

        def _on_stop(self):
            self._stop.set()

    class KeyboardHandler(threading.Thread):
        def __init__(self, stop):
            super(KeyboardHandler, self).__init__()
            self.daemon = True
            self._stop = stop

        def run(self):
            try:
                raw_input()
                self._stop.set()
                while True:
                    raw_input()
            except KeyboardInterrupt:
                events.close()
                sys.exit(1)

    pid = sys.argv[1]
    trigger_port = int(sys.argv[2])

    app = Application(pid, trigger_port)
    try:
        app.run()
    except KeyboardInterrupt:
        events.close()
        sys.exit(0)
    app.dispose()
    events.close()
    sys.exit(0)
