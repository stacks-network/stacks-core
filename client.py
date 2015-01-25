from twisted.internet import reactor
from txjsonrpc.web.jsonrpc import Proxy

def printValue(value):
    print "Result: %s" % str(value)

def printError(error):
    print 'error', error

def shutDown(data):
    print "Shutting down reactor..."
    reactor.stop()

proxy = Proxy('http://127.0.0.1:8314/')

d = proxy.callRemote('hello')
d.addCallback(printValue).addErrback(printError).addBoth(shutDown)
reactor.run()