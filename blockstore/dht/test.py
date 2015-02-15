#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

from twisted.internet import reactor
from twisted.python import log

from kademlia.network import Server

import sys
import coinkit
import json

log.startLogging(sys.stdout)

#key = 'u/muneeb'
#value = "temp"

value = '{"name": "Muneeb Ali Khan"}'
key = coinkit.hex_hash160(value)

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
