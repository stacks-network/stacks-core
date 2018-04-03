#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack-client.

    Blockstack-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack-client. If not, see <http://www.gnu.org/licenses/>.
"""

from .blockchain_client import BlockchainClient

from xmlrpclib import ServerProxy, Transport
from defusedxml import xmlrpc
import httplib
import json

# prevent the usual XML attacks
xmlrpc.monkey_patch()

class BlockstackCoreUTXOClient( BlockchainClient ):
    def __init__(self, server, port):
        self.type = "blockstack_utxo"
        self.server = server
        self.port = port

    def get_unspents(self, address):
        return get_unspents( address, self )

    def broadcast_transaction(self, txdata ):
        return broadcast_transaction( txdata, self )


# TODO: make into its own module
# https://seattle.poly.edu/browser/seattle/trunk/demokit/timeout_xmlrpclib.py?rev=692
class TimeoutHTTPConnection(httplib.HTTPConnection):
    def connect(self):
        httplib.HTTPConnection.connect(self)
        self.sock.settimeout(self.timeout)


class TimeoutHTTP(httplib.HTTP):
    _connection_class = TimeoutHTTPConnection

    def set_timeout(self, timeout):
        self._conn.timeout = timeout

    def getresponse(self, **kw):
        return self._conn.getresponse(**kw)


class TimeoutTransport(Transport):
    def __init__(self, *l, **kw):
        self.timeout = kw.get('timeout', 10)
        if 'timeout' in kw.keys():
            del kw['timeout']

        Transport.__init__(self, *l, **kw)

    def make_connection(self, host):
        conn = TimeoutHTTP(host)
        conn.set_timeout(self.timeout)
        return conn

class TimeoutServerProxy(ServerProxy):
    def __init__(self, uri, *l, **kw):
        kw['transport'] = TimeoutTransport(timeout=kw.get('timeout',10), use_datetime=kw.get('use_datetime', 0))
        if 'timeout' in kw.keys():
            del kw['timeout']
        
        ServerProxy.__init__(self, uri, *l, **kw)


class BlockstackCoreRPCClient(object):
    """
    RPC client for the blockstack server
    """
    def __init__(self, server, port, timeout=30, min_confirmations=None ):
        self.srv = TimeoutServerProxy( "http://%s:%s" % (server, port), timeout=timeout, allow_none=True )
        self.server = server
        self.port = port
        self.min_confirmations = min_confirmations

    def __getattr__(self, key):
        try:
            return object.__getattr__(self, key)
        except AttributeError:
            def inner(*args, **kw):
                func = getattr(self.srv, key)
                res = func(*args, **kw)
                if res is not None:
                    # lol jsonrpc within xmlrpc
                    res = json.loads(res)
                return res
            return inner


def get_unspents( address, client=BlockstackCoreUTXOClient("localhost", 6264) ):
    """
    Get unspent outputs from a Blockstack server.
    """
    proxy = BlockstackCoreRPCClient( client.server, client.port )
    unspents = proxy.get_unspents( address )
    return unspents


def broadcast_transaction( txdata, client ):
    """
    Send a transaction through a Blockstack server
    """
    if not isinstance(client, BlockstackCoreUTXOClient):
        raise Exception("Not a Blockstack UTXO client")

    proxy = BlockstackCoreRPCClient( client.server, client.port )
    res = proxy.broadcast_transaction( txdata )
    return res

