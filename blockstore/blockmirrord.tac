"""
    Blockmirrord tac (config) file used by Twisted for launching the server
    ~~~~~
    :copyright: (c) 2015 by Openname.org
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

from lib.config import BLOCKMIRRORD_PORT

from blockmirrord import BlockmirrordRPC, refresh_mirror
from lib.config import REINDEX_FREQUENCY

application = service.Application("blockmirrord")

factory_blockmirror = jsonrpc.RPCFactory(BlockmirrordRPC())

server_blockstore = internet.TCPServer(BLOCKMIRRORD_PORT, factory_blockstore)

lc = LoopingCall(refresh_mirror)
lc.start(REINDEX_FREQUENCY)
