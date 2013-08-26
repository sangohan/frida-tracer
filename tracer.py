import sys

from tracer.application import Application

if __name__ == '__main__':
    application = Application(sys.argv)
    application.run()
