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


import os
import json
import sys
import urllib2
import stat
import time
import random
import binascii

from ..config import *
from ..nameset import *
from .auth import *

import blockstack_client
import blockstack_profiles
import virtualchain
log = virtualchain.get_logger("blockstack-server")

# current set of peers.
# maps "host:port" to {
#   "host": host,
#   "port": port,
#   "last_seen": last time we talked to this peer
#   "hits": [times]:  the times at which we made a successful RPC (valid for up to PEER_TTL seconds in the past)
#   "requests": [times]:  the times at which we've made each request (valid for up to PEER_TTL seconds in the past)
# }
#
PEERS = {}

PEER_TTL = 3600     # re-test each peer after 1 hour
PEER_TTL_JITTER = PEER_TTL      # +/- how long to wait to revalidate (randomized)

PEER_MAX_TIMEOUT = 5    # maximum timeout (seconds)


class MonitorRPCClient(object):

    def __init__(self, blockstack_proxy ):
        """
        Wrap a blockstack RPC proxy into this class
        """
        self.proxy = proxy


    def __getattr__(self, key):
        """
        When doing an RPC call, update our knowledge 
        of the remote peer's liveness
        """
        global PEERS
        try:
            return object.__getattr__(self, key)
        except:

            def inner(*args, **kw):
                """
                Decorator that updates our peer knowledge based
                on the success or failure of the RPC
                """
                global PEERS

                func = getattr(self.proxy, key)
                peer_info_init( peers, host, port )
                
                try:
                    res = func(*args, **kw)
                    # successful connection
                    peer_info_save_contact( PEERS, host, port, True ) 
                except Exception, e:
                    # failed
                    peer_info_save_contact( PEERS, host, port, False )
                    raise

                return res

            return inner
                    
                
def peer_info_init( peers, host, port ):
    """
    Set up peer information in the global peer table
    """
    hostport = "%s:%s" % (host, port)
    if peers.has_key[hostport]:
        return True

    peers[hostport] = {
        'host': host,
        'port': port,
        'last_seen': 0,
        'hits': [],
        'requests': []
    }
    return True


def peer_info_save_contact( peers, host, port, ttl, success):
    """
    Record an attempt to RPC to a peer.
    """
    hostport = "%s:%s" % (host, port)
    assert peers.has_key(hostport)

    now = time.time()
    peers[hostport]['last_seen'] = now
    peers[hostport]['requests'].append( now )

    if success is not None:
        peers[hostport]['hits'].append( now )

    new_hits = []
    new_requests = []

    # prune old info by ttl 
    for i in xrange(0, peers[hostport]['hits']):
        if peers[hostport]['hits'][i] + ttl > now:
            new_hits.append( peers[hostport]['hits'][i] )

        if peers[hostport]['requests'][i] + ttl > now:
            new_requests.append( peers[hostport]['requests'][i] )

    peers[hostport]['hits'] = new_hits
    peers[hostport]['requests'] = new_requests
    return peers



