#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack-utxo
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
"""

from pybitcoin.services import BlockchainClient

from xmlrpclib import ServerProxy, Transport
from defusedxml import xmlrpc
import httplib
import json

# prevent the usual XML attacks
xmlrpc.monkey_patch()

class BlockstackUTXOClient( BlockchainClient ):
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


class BlockstackRPCClient(object):
    """
    RPC client for the blockstack server
    """
    def __init__(self, server, port, timeout=30 ):
        self.srv = TimeoutServerProxy( "http://%s:%s" % (server, port), timeout=timeout, allow_none=True )
        self.server = server
        self.port = port

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


def get_unspents( address, client=BlockstackUTXOClient("localhost", 6264) ):
    """
    Get unspent outputs from a Blockstack server.
    TODO: authenticate the server
    """
    proxy = BlockstackRPCClient( client.server, client.port )
    unspents = proxy.get_unspents( address )
    return unspents


def broadcast_transaction( txdata, client ):
    """
    Send a transaction through a Blockstack server
    TODO: authenticate the server
    """
    if not isinstance(client, BlockstackUTXOClient):
        raise Exception("Not a Blockstack UTXO client")

    proxy = BlockstackRPCClient( client.server, client.port )
    res = proxy.broadcast_transaction( txdata )
    return res

