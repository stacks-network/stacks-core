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