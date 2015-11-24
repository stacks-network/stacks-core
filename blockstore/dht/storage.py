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

import time
from itertools import izip
from itertools import imap
from itertools import takewhile
import operator
from collections import OrderedDict

from zope.interface import implements
from zope.interface import Interface

from kademlia.storage import IStorage
from kademlia.log import Logger
from kademlia.utils import digest

import sys
import json
import pybitcoin
import os
import socket

# Hack around absolute paths
# current_dir = os.path.abspath(os.path.dirname(__file__))
# parent_dir = os.path.abspath(current_dir + "/../")

# sys.path.insert(0, parent_dir)

# from .plugin import STORAGE_TTL
# 3 years
STORAGE_TTL = 3 * 60 * 60 * 24 * 365

DHT_SERVER_PORT = 6265  # blockstored default to port 6264

DEFAULT_DHT_SERVERS = [('dht.openname.org', DHT_SERVER_PORT),
                       ('dht.onename.com', DHT_SERVER_PORT),
                       ('dht.halfmoonlabs.com', DHT_SERVER_PORT),
                       ('127.0.0.1', DHT_SERVER_PORT)]


class BlockStorage(object):
    implements(IStorage)

    """ BlockStorage has following properties:
        a) is content-addressable (all keys must be hash(value))
        b) high TTL (effectively the keys don't expire)
        c) stores only valid JSON values
    """

    def __init__(self, ttl=STORAGE_TTL):
        """
        By default, max age is three years.
        """
        self.data = OrderedDict()
        self.ttl = ttl
        self.log = Logger(system=self)

    def __setitem__(self, key, value):

        try:
            test_value = json.loads(value)
        except:
            self.log.info("value not JSON, not storing")
            return

        hash = pybitcoin.hash.hex_hash160(value)
        test_key = digest(hash)

        if key != test_key:
            self.log.info("hash(value) doesn't match, not storing")
            return

        if key in self.data:
            del self.data[key]

        self.data[key] = (time.time(), value)
        self.cull()

    def cull(self):
        for k, v in self.iteritemsOlderThan(self.ttl):
            self.data.popitem(first=True)

    def get(self, key, default=None):
        self.cull()
        if key in self.data:
            value = self[key]
            hash = pybitcoin.hash.hex_hash160(value)

            test_key = digest(hash)

            if key != test_key:
                self.log.info("hash(value) doesn't match, ignoring value")
                return default

            return self[key]

        return default

    def __getitem__(self, key):
        self.cull()
        return self.data[key][1]

    def __iter__(self):
        self.cull()
        return iter(self.data)

    def __repr__(self):
        self.cull()
        return repr(self.data)

    def iteritemsOlderThan(self, secondsOld):
        minBirthday = time.time() - secondsOld
        zipped = self._tripleIterable()
        matches = takewhile(lambda r: minBirthday >= r[1], zipped)
        return imap(operator.itemgetter(0, 2), matches)

    def _tripleIterable(self):
        ikeys = self.data.iterkeys()
        ibirthday = imap(operator.itemgetter(0), self.data.itervalues())
        ivalues = imap(operator.itemgetter(1), self.data.itervalues())
        return izip(ikeys, ibirthday, ivalues)

    def iteritems(self):
        self.cull()
        ikeys = self.data.iterkeys()
        ivalues = imap(operator.itemgetter(1), self.data.itervalues())
        return izip(ikeys, ivalues)


# ---------------------------------
def hostname_to_ip(servers):
    """ Given (hostname, port) return (ip_address, port)
    """

    reply = []

    for server, port in servers:
        ip_address = socket.gethostbyname(server)
        reply.append((ip_address, port))

    return reply
