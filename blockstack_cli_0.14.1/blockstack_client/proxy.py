#!/usr/bin/env python
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

import argparse
import sys
import json
import traceback
import types
import socket
import uuid
import os
import importlib
import pprint
import random
import time
import copy
import blockstack_profiles
import blockstack_zones
import urllib
from xmlrpclib import ServerProxy, Transport
from defusedxml import xmlrpc
import httplib

# prevent the usual XML attacks
xmlrpc.monkey_patch()

import user as user_db
import storage

import pybitcoin
import bitcoin
import binascii
from utilitybelt import is_hex

import config
from config import get_logger, DEBUG, MAX_RPC_LEN, find_missing, BLOCKSTACKD_SERVER, \
    BLOCKSTACKD_PORT, BLOCKSTACK_METADATA_DIR, BLOCKSTACK_DEFAULT_STORAGE_DRIVERS, \
    FIRST_BLOCK_MAINNET, NAME_OPCODES, OPFIELDS, CONFIG_DIR, SPV_HEADERS_PATH, BLOCKCHAIN_ID_MAGIC, \
    NAME_PREORDER, NAME_REGISTRATION, NAME_UPDATE, NAME_TRANSFER, NAMESPACE_PREORDER, NAME_IMPORT, \
    USER_ZONEFILE_TTL, CONFIG_PATH

log = get_logger("blockstack-client")

# borrowed with gratitude from Justin Cappos
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


# default API endpoint proxy to blockstackd
default_proxy = None

class BlockstackRPCClient(object):
    """
    RPC client for the blockstack server
    """
    def __init__(self, server, port, max_rpc_len=MAX_RPC_LEN, timeout=config.DEFAULT_TIMEOUT ):
        self.srv = TimeoutServerProxy( "http://%s:%s" % (server, port), timeout=timeout, allow_none=True )
        self.server = server
        self.port = port

    def __getattr__(self, key):
        try:
            return object.__getattr__(self, key)
        except AttributeError:
            log.debug("RPC http://%s:%s %s" % (self.server, self.port, key))
            def inner(*args, **kw):
                func = getattr(self.srv, key)
                res = func(*args, **kw)
                if res is not None:
                    # lol jsonrpc within xmlrpc
                    res = json.loads(res)
                return res
            return inner


def get_default_proxy(config_path=CONFIG_PATH):
    """
    Get the default API proxy to blockstack.
    """
    global default_proxy
    if default_proxy is None:

        import client

        if os.environ.get("BLOCKSTACK_CLIENT_TEST_ALTERNATIVE_CONFIG", None) == "1":
            # feature test: make sure alternative config paths get propagated
            if config_path.startswith("/home"):
                print config_path
                traceback.print_stack()
                sys.exit(0)

        # load     
        conf = config.get_config(config_path)
        assert conf is not None, "Failed to get config from '%s'" % config_path
        blockstack_server = conf['server']
        blockstack_port = conf['port']

        log.debug("Default proxy to %s:%s" % (blockstack_server, blockstack_port))
        proxy = client.session(conf=conf, server_host=blockstack_server, server_port=blockstack_port)

        return proxy

    else:
        return default_proxy


def set_default_proxy(proxy):
    """
    Set the default API proxy
    """
    global default_proxy
    default_proxy = proxy


def json_traceback():
    exception_data = traceback.format_exc().splitlines()
    return {
        "error": exception_data[-1],
        "traceback": exception_data
    }


def getinfo(proxy=None):
    """
    getinfo
    """

    resp = {}

    if proxy is None:
        proxy = get_default_proxy()

    try:
        resp = proxy.getinfo()
        if type(resp) == list:
            if len(resp) == 0:
                resp = {'error': 'No data returned'}
            else:
                resp = resp[0]

    except Exception as e:
        resp = json_traceback()

    return resp


def ping(proxy=None):
    """
    ping
    """

    resp = {}

    if proxy is None:
        proxy = get_default_proxy()

    try:
        resp = proxy.ping()
        if type(resp) == list:
            if len(resp) == 0:
                resp = {'error': 'No data returned'}
            else:
                resp = resp[0]

    except Exception as e:
        resp['error'] = str(e)

    return resp


def get_name_cost(name, proxy=None):
    """
    name_cost
    """
    if proxy is None:
        proxy = get_default_proxy()

    resp = proxy.get_name_cost(name)
    if type(resp) == list:
        if len(resp) == 0:
            resp = {'error': 'No data returned'}
        else:
            resp = resp[0]

    return resp


def get_namespace_cost(namespace_id, proxy=None):
    """
    namespace_cost
    """
    if proxy is None:
        proxy = get_default_proxy()

    resp = proxy.get_namespace_cost(namespace_id)
    if type(resp) == list:
        if len(resp) == 0:
            resp = {'error': 'No data returned'}
        else:
            resp = resp[0]

    return resp


def get_all_names(offset, count, proxy=None):
    """
    get all names
    """
    if proxy is None:
        proxy = get_default_proxy()

    return proxy.get_all_names(offset, count)


def get_names_in_namespace(namespace_id, offset, count, proxy=None):
    """
    Get names in a namespace
    """
    if proxy is None:
        proxy = get_default_proxy()

    return proxy.get_names_in_namespace(namespace_id, offset, count)


def get_names_owned_by_address(address, proxy=None):
    """
    Get the names owned by an address.
    Only works for p2pkh scripts.
    """
    if proxy is None:
        proxy = get_default_proxy()

    return proxy.get_names_owned_by_address(address)


def get_consensus_at(block_height, proxy=None):
    """
    Get consensus at a block
    """
    if proxy is None:
        proxy = get_default_proxy()

    resp = proxy.get_consensus_at(block_height)
    if type(resp) == list:
        if len(resp) == 0:
            resp = {'error': 'No data returned'}
        else:
            resp = resp[0]

    return resp


def get_consensus_hashes(block_heights, proxy=None):
    """
    Get consensus hashes for a list of blocks
    NOTE: returns {block_height (int): consensus_hash (str)}
    (coerces the key to an int)
    """
    if proxy is None:
        proxy = get_default_proxy()

    resp = proxy.get_consensus_hashes(block_heights)
    if type(resp) == list:
        if len(resp) == 0:
            resp = {'error': 'No data returned'}
        else:
            resp = resp[0]

    if 'error' in resp:
        return resp

    else:
        if type(resp) != dict:
            return {'error': 'Invalid data: expected dict'}

        ret = {}
        for h in resp.keys():
            try:
                hint = int(h)
                ret[hint] = resp[h]
            except:
                return {'error': 'Invalid data: expected int'}
            
        return ret


def get_consensus_range(block_id_start, block_id_end, proxy=None):
    """
    Get a range of consensus hashes.  The range is inclusive.
    """
    if proxy is None:
        proxy = get_default_proxy()

    resp = proxy.get_consensus_range(block_id_start, block_id_end)
    return resp


def get_nameops_at(block_id, proxy=None):
    """
    Get the set of records as they were at a particular block.
    """
    if proxy is None:
        proxy = get_default_proxy()

    resp = proxy.get_nameops_at(block_id)
    return resp


def get_nameops_hash_at(block_id, proxy=None):
    """
    Get the hash of a set of records as they were at a particular block.
    """
    if proxy is None:
        proxy = get_default_proxy()

    resp = proxy.get_nameops_hash_at(block_id)
    if type(resp) == list:
        if len(resp) == 0:
            resp = {'error': 'No data returned'}
        else:
            resp = resp[0]

    return resp


def get_name_blockchain_record(name, proxy=None):
    """
    get_name_blockchain_record
    """

    if proxy is None:
        proxy = get_default_proxy()

    resp = proxy.get_name_blockchain_record(name)
    if type(resp) == list:
        if len(resp) == 0:
            resp = {'error': 'No data returned'}
        else:
            resp = resp[0]

    return resp


def get_namespace_blockchain_record(namespace_id, proxy=None):
    """
    get_namespace_blockchain_record
    """

    if proxy is None:
        proxy = get_default_proxy()

    ret = proxy.get_namespace_blockchain_record(namespace_id)
    if type(ret) == list:
        if len(ret) == 0:
            ret = {'error': 'No data returned'}
            return ret
        else:
            ret = ret[0]

    if ret is not None:
        # this isn't needed
        if 'opcode' in ret:
            del ret['opcode']

    return ret


def is_name_registered(fqu, proxy=None):
    """
    Return True if @fqu registered on blockchain
    """

    if proxy is None:
        proxy = get_default_proxy()

    blockchain_record = get_name_blockchain_record( fqu, proxy=proxy )
    if 'error' in blockchain_record:
        log.debug("Failed to read blockchain record for %s" % fqu)
        return False

    if blockchain_record.has_key('revoked') and blockchain_record['revoked']:
        return False

    if "first_registered" in blockchain_record:
        return True
    else:
        return False


def has_zonefile_hash(fqu, proxy=None ):
    """
    Return True if @fqu has a zonefile hash on the blockchain
    """
    
    if proxy is None:
        proxy = get_default_proxy()

    blockchain_record = get_name_blockchain_record(fqu, proxy=proxy )
    if 'error' in blockchain_record:
        log.debug("Failed to read blockchain record for %s" % fqu)
        return False

    if 'value_hash' in blockchain_record and blockchain_record['value_hash'] is not None:
        return True
    else:
        return False


def is_zonefile_current(fqu, zonefile_json, proxy=None):
    """ 
    Return True if hash(@zonefile_json) published on blockchain
    """

    from .storage import hash_zonefile

    if proxy is None:
        proxy = get_default_proxy()

    blockchain_record = get_name_blockchain_record( fqu, proxy=proxy )
    if 'error' in blockchain_record:
        log.debug("Failed to read blockchain record for %s" % fqu)
        return False

    zonefile_hash = hash_zonefile(zonefile_json)

    if 'value_hash' in blockchain_record and blockchain_record['value_hash'] == zonefile_hash:
        # if hash of profile is in correct
        return True

    return False


def is_name_owner(fqu, address, proxy=None):
    """
    return True if @btc_address owns @fqu
    """

    if proxy is None:
        proxy = get_default_proxy()

    blockchain_record = get_name_blockchain_record( fqu, proxy=proxy )
    if 'error' in blockchain_record:
        log.debug("Failed to read blockchain record for %s" % fqu)
        return False

    if 'address' in blockchain_record and blockchain_record['address'] == address:
        return True
    else:
        return False


