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

from storage import BlockStorage, hostname_to_ip, DEFAULT_DHT_SERVERS, DHT_SERVER_PORT
# from plugin import DEFAULT_DHT_SERVERS, DHT_SERVER_PORT

application = service.Application("kademlia")
application.setComponent(ILogObserver, log.FileLogObserver(sys.stdout, log.INFO).emit)

kserver = Server(storage=BlockStorage())
bootstrap_servers = hostname_to_ip(DEFAULT_DHT_SERVERS)
kserver.bootstrap(bootstrap_servers)

server = internet.UDPServer(DHT_SERVER_PORT, kserver.protocol)
server.setServiceParent(application)