#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Opennamed
    ~~~~~
    :copyright: (c) 2014 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

from twisted.internet import reactor
from twisted.python import log

from kademlia.network import Server

import sys
import coinkit
import json

from storage import OpennameStorage


class dht_node(object):

    def __init__(self):
        self.reply = {}

    def get_key(self, key):

        self.reply['key'] = key

        server = Server(storage=OpennameStorage())
        server.listen(8467)

        def inner_done(result):
            self.reply['value'] = result
            reactor.stop()

        def inner_get(found):

            server.get(key).addCallback(inner_done)

        server.bootstrap([("127.0.0.1", 8468)]).addCallback(inner_get)
        reactor.run()

        return self.reply

    def set_key(self, key, value):

        server = Server(storage=OpennameStorage())
        server.listen(8467)

        try:
            test_value = json.loads(value)
        except:
            self.reply['error'] = "value not JSON, not storing"
            return self.reply

        hash = coinkit.hex_hash160(value)
        test_key = hash

        if key != test_key:
            self.reply['error'] = "hash(value) doesn't match, not storing"
            return self.reply

        def inner_done(result):
            global reply
            self.reply['success'] = result
            reactor.stop()

        def inner_set(found):

            server.set(key, value).addCallback(inner_done)

        server.bootstrap([("127.0.0.1", 8468)]).addCallback(inner_set)
        reactor.run()

        return self.reply

# -----------------------------------
if __name__ == '__main__':

    log.startLogging(sys.stdout)

    #key = 'u/muneeb'
    #value = "temp"

    value = '{"name": "Muneeb Ali Khan"}'
    key = coinkit.hex_hash160(value)

    print key
    print value

    node = dht_node()

    #print node.set_key(key, value)
    print node.get_key(key)
