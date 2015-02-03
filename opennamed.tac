"""
    Opennamed tac (config) file used by Twisted for launching the server
    ~~~~~
    :copyright: (c) 2014 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

#hack around absolute paths
import os
import sys
current_dir =  os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, current_dir)

from txjsonrpc.netstring import jsonrpc
from twisted.application import service, internet
from twisted.internet.task import LoopingCall

from kademlia.network import Server

from dht.storage import OpennameStorage, hostname_to_ip
from opennamelib.config import DEFAULT_DHT_SERVERS, DHT_SERVER_PORT, OPENNAMED_PORT

dht_server = Server(storage=OpennameStorage())
bootstrap_servers = hostname_to_ip(DEFAULT_DHT_SERVERS)
dht_server.bootstrap(bootstrap_servers)

from opennamed import OpennamedRPC, reindex_blockchain
from opennamelib.config import REINDEX_FREQUENCY

lc = LoopingCall(reindex_blockchain)
lc.start(REINDEX_FREQUENCY)

application = service.Application("opennamed")

factory_openname = jsonrpc.RPCFactory(OpennamedRPC(dht_server))

server_openname = internet.TCPServer(OPENNAMED_PORT, factory_openname)
server_openname.setServiceParent(application)

server_dht = internet.UDPServer(DHT_SERVER_PORT, dht_server.protocol)
server_dht.setServiceParent(application)