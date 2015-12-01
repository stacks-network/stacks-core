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

from twisted.internet import reactor
from twisted.python import log

from kademlia.network import Server

import sys
import pybitcoin
import json

log.startLogging(sys.stdout)

#key = 'u/muneeb'
#value = "temp"

value = '{"name": "Muneeb Ali Khan"}'
key = pybitcoin.hash.hex_hash160(value)

print key
print value

hold_display = None

from storage import BlockStorage


def done(result):
    print "Key result: ", result
    print "Found: ", hold_display
    reactor.stop()


def get_key(result, server):
    global key, value

    server.get(key).addCallback(done)


def set_key(found, server):
    global key, value, hold_display

    hold_display = found
    server.set(key, value).addCallback(get_key, server)

server = Server(storage=BlockStorage())
server.listen(8467)

server.bootstrap([("127.0.0.1", 8468)]).addCallback(set_key, server)

reactor.run()
