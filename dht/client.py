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
import os
import coinkit
import json
import ast
import socket

from storage import OpennameStorage

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

from config import DHT_CLIENT_PORT, DEFAULT_DHT_SERVERS


def hostname_to_ip(servers):
    """ Given (hostname, port) return (ip_address, port)
    """

    reply = []

    for server, port in servers:
        ip_address = socket.gethostbyname(server)
        reply.append((ip_address, port))

    return reply


class dht_client(object):

    def __init__(self):
        self.reply = {}

        self.client = Server(storage=OpennameStorage())
        self.client.listen(DHT_CLIENT_PORT)

    def get_key(self, key):

        self.reply['key'] = key

        def inner_done(result):
            value = json.loads(json.dumps(result))
            try:
                value = ast.literal_eval(value)
            except:
                pass

            self.reply['value'] = value
            reactor.stop()

        def inner_get(found):

            self.client.get(key).addCallback(inner_done)

        servers = hostname_to_ip(DEFAULT_DHT_SERVERS)

        self.client.bootstrap(servers).addCallback(inner_get)

        reactor.run()

        return self.reply

    def set_key(self, key, value):

        try:
            test_value = json.loads(json.dumps(value))
        except:
            self.reply['error'] = "value not JSON, not storing"
            return self.reply

        hash = coinkit.hex_hash160(value)
        test_key = hash

        if key != test_key:
            self.reply['error'] = "hash(value) doesn't match, not storing"
            return self.reply

        self.reply['key'] = hash

        def inner_done(result):
            global reply
            self.reply['success'] = result
            reactor.stop()

        def inner_set(found):

            self.client.set(key, value).addCallback(inner_done)

        servers = hostname_to_ip(DEFAULT_DHT_SERVERS)

        self.client.bootstrap(servers).addCallback(inner_set)
        reactor.run()

        return self.reply

# -----------------------------------
if __name__ == '__main__':

    log.startLogging(sys.stdout)

    #key = 'u/muneeb'
    #value = "temp"

    value = '{"name": "Muneeb Ali"}'
    key = coinkit.hex_hash160(value)

    print key
    print value

    client = dht_client()

    #print client.set_key(key, value)
    print client.get_key(key)
