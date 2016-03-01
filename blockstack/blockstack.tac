#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack

    Blockstack is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
"""

#hack around absolute paths
import os
import sys
current_dir =  os.path.abspath(os.path.dirname(__file__) + "/..")
sys.path.insert(0, current_dir)

from txjsonrpc.netstring import jsonrpc
from twisted.application import service, internet
from twisted.internet.task import LoopingCall

application = service.Application("blockstackd")

# ------------
# blockstack 
# ------------
# from blockstackd import BlockstackdRPC, reindex_blockchain
import blockstack
from blockstack.blockstackd import BlockstackdRPC
from blockstack.lib.config import REINDEX_FREQUENCY, RPC_SERVER_PORT

factory_blockstack = jsonrpc.RPCFactory(BlockstackdRPC(), maxLength=8192)

server_blockstack = internet.TCPServer(RPC_SERVER_PORT, factory_blockstack)
server_blockstack.setServiceParent(application)

# -----------
# DHT 
# -----------
from kademlia.network import Server
from blockstack.dht.storage import BlockStorage, hostname_to_ip
from blockstack.lib import nameset as blockstack_state_engine

import virtualchain
import blockstack

if os.getenv("BLOCKSTACK_TEST") == "1":
    
    import blockstack.tests.mock_bitcoind as mock_bitcoind

    working_dir = os.environ.get('BLOCKSTACK_TEST_WORKING_DIR', None)
    worker_env = mock_bitcoind.make_worker_env( mock_bitcoind, os.getenv("MOCK_BITCOIND_SAVE_PATH") )
    worker_env['BLOCKSTACK_TEST'] = "1"

    if working_dir is not None:
        blockstack_state_engine.working_dir = working_dir 

    virtualchain.setup_virtualchain( impl=blockstack_state_engine, bitcoind_connection_factory=mock_bitcoind.connect_mock_bitcoind, index_worker_env=worker_env )
    
else:
    virtualchain.setup_virtualchain( impl=blockstack_state_engine )

dht_opts = blockstack.lib.config.default_dht_opts()

if not dht_opts['disable']:
   
   # start up Kademlia node
   dht_servers = dht_opts['servers']
   dht_port = dht_opts['port']

   dht_server = Server(storage=BlockStorage())
   bootstrap_servers = hostname_to_ip(dht_servers)
   dht_server.bootstrap(bootstrap_servers)

   server_dht = internet.UDPServer(dht_port, dht_server.protocol)
   server_dht.setServiceParent(application)

