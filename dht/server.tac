from twisted.application import service, internet
from twisted.python.log import ILogObserver
from twisted.internet import reactor, task

import sys 
import os
sys.path.append(os.path.dirname(__file__))

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

from kademlia.network import Server
from kademlia import log

from storage import OpennameStorage
from config import DHT_PORT

application = service.Application("kademlia")
application.setComponent(ILogObserver, log.FileLogObserver(sys.stdout, log.INFO).emit)

if os.path.isfile('cache.pickle'):
    kserver = Server.loadState('cache.pickle')
else:
    kserver = Server(storage=OpennameStorage())
    kserver.bootstrap([("1.2.3.4", DHT_PORT)])
kserver.saveStateRegularly('cache.pickle', 10)

server = internet.UDPServer(DHT_PORT, kserver.protocol)
server.setServiceParent(application)