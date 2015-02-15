#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
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
import coinkit
import os
import socket

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

from lib.config import STORAGE_TTL


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

        hash = coinkit.hex_hash160(value)
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
            hash = coinkit.hex_hash160(value)

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
