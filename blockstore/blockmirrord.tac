#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstore

    Blockstore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore. If not, see <http://www.gnu.org/licenses/>.
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
