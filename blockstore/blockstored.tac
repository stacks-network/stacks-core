"""
    Blockstored tac (config) file used by Twisted for launching the server
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

from dht.storage import BlockStorage, hostname_to_ip
from lib.config import DEFAULT_DHT_SERVERS, DHT_SERVER_PORT, BLOCKSTORED_PORT

dht_server = Server(storage=BlockStorage())
bootstrap_servers = hostname_to_ip(DEFAULT_DHT_SERVERS)
dht_server.bootstrap(bootstrap_servers)

from blockstored import BlockstoredRPC, reindex_blockchain
from lib.config import REINDEX_FREQUENCY

application = service.Application("blockstored")

factory_blockstore = jsonrpc.RPCFactory(BlockstoredRPC(dht_server))

server_blockstore = internet.TCPServer(BLOCKSTORED_PORT, factory_blockstore)
server_blockstore.setServiceParent(application)

server_dht = internet.UDPServer(DHT_SERVER_PORT, dht_server.protocol)
server_dht.setServiceParent(application)

lc = LoopingCall(reindex_blockchain)
lc.start(REINDEX_FREQUENCY)