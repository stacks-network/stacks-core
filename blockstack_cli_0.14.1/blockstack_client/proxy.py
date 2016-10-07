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

import json
import traceback
import os
import random
from xmlrpclib import ServerProxy, Transport
from defusedxml import xmlrpc
import httplib

# prevent the usual XML attacks
xmlrpc.MAX_DATA = 10 * 1024 * 1024  # 10MiB
xmlrpc.monkey_patch()

import storage

import config
from config import get_logger, MAX_RPC_LEN, CONFIG_PATH, BLOCKSTACK_TEST


log = get_logger('blockstack-client')

BLOCKSTACK_CLIENT_TEST_ALTERNATIVE_CONFIG = os.environ.get('BLOCKSTACK_CLIENT_TEST_ALTERNATIVE_CONFIG', None)


class TimeoutHTTPConnection(httplib.HTTPConnection):
    """
    borrowed with gratitude from Justin Cappos
    https://seattle.poly.edu/browser/seattle/trunk/demokit/timeout_xmlrpclib.py?rev=692
    """
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
        self.timeout = kw.pop('timeout', 10)
        Transport.__init__(self, *l, **kw)

    def make_connection(self, host):
        conn = TimeoutHTTP(host)
        conn.set_timeout(self.timeout)

        return conn


class TimeoutServerProxy(ServerProxy):
    def __init__(self, uri, *l, **kw):
        timeout = kw.pop('timeout', 10)
        use_datetime = kw.get('use_datetime', 0)
        kw['transport'] = TimeoutTransport(timeout=timeout, use_datetime=use_datetime)
        ServerProxy.__init__(self, uri, *l, **kw)


# default API endpoint proxy to blockstackd
default_proxy = None


class BlockstackRPCClient(object):

    """
    RPC client for the blockstack server
    """

    def __init__(self, server, port, max_rpc_len=MAX_RPC_LEN, timeout=config.DEFAULT_TIMEOUT, debug_timeline=False, **kw):
        self.url = 'http://{}:{}'.format(server, port)
        self.srv = TimeoutServerProxy(self.url, timeout=timeout, allow_none=True)
        self.server = server
        self.port = port
        self.debug_timeline = debug_timeline

    def __getattr__(self, key):
        try:
            return object.__getattr__(self, key)
        except AttributeError:
            r = -1  # random ID to match in logs
            if self.debug_timeline:
                r = random.randint(0, 2 ** 16)
                log.debug('RPC({}) begin {} {}'.format(r, self.url, key))

            def inner(*args, **kw):
                func = getattr(self.srv, key)
                res = func(*args, **kw)
                if res is not None:
                    # lol jsonrpc within xmlrpc
                    try:
                        res = json.loads(res)
                    except (ValueError, TypeError):
                        if BLOCKSTACK_TEST is not None:
                            log.debug('Server replied invalid JSON: {}'.format(res))

                        log.error('Server replied invalid JSON')
                        res = {'error': 'Server replied invalid JSON'}

                if self.debug_timeline:
                    log.debug('RPC({}) end {} {}'.format(r, self.url, key))

                return res

            return inner


def get_default_proxy(config_path=CONFIG_PATH):
    """
    Get the default API proxy to blockstack.
    """
    global default_proxy
    if default_proxy is not None:
        return default_proxy

    import client

    if BLOCKSTACK_CLIENT_TEST_ALTERNATIVE_CONFIG is not None:
        # feature test: make sure alternative config paths get propagated
        if config_path.startswith('/home'):
            print(config_path)
            traceback.print_stack()
            os.abort()

    # load
    conf = config.get_config(config_path)
    assert conf is not None, 'Failed to get config from "{}"'.format(config_path)

    blockstack_server, blockstack_port = conf['server'], conf['port']

    log.debug('Default proxy to {}:{}'.format(blockstack_server, blockstack_port))
    proxy = client.session(conf=conf, server_host=blockstack_server, server_port=blockstack_port)

    return proxy


def set_default_proxy(proxy):
    """
    Set the default API proxy
    """
    global default_proxy
    default_proxy = proxy


def json_traceback():
    exception_data = traceback.format_exc().splitlines()
    return {
        'error': exception_data[-1],
        'traceback': exception_data
    }


def getinfo(proxy=None):
    """
    getinfo
    """

    resp = {}

    proxy = get_default_proxy() if proxy is None else proxy

    try:
        resp = proxy.getinfo()
        if isinstance(resp, list):
            resp = resp[0] if resp else {'error': 'No data returned'}
    except Exception:
        resp = json_traceback()

    return resp


def ping(proxy=None):
    """
    ping
    """

    resp = {}

    proxy = get_default_proxy() if proxy is None else proxy

    try:
        resp = proxy.ping()
        if isinstance(resp, list):
            resp = resp[0] if resp else {'error': 'No data returned'}
    except Exception as e:
        resp['error'] = str(e)

    return resp


def get_name_cost(name, proxy=None):
    """
    name_cost
    """
    proxy = get_default_proxy() if proxy is None else proxy

    resp = proxy.get_name_cost(name)
    if isinstance(resp, list):
        resp = resp[0] if resp else {'error': 'No data returned'}

    return resp


def get_namespace_cost(namespace_id, proxy=None):
    """
    namespace_cost
    """
    proxy = get_default_proxy() if proxy is None else proxy

    resp = proxy.get_namespace_cost(namespace_id)
    if isinstance(resp, list):
        resp = resp[0] if resp else {'error': 'No data returned'}

    return resp


def get_all_names(offset, count, proxy=None):
    """
    get all names
    """
    proxy = get_default_proxy() if proxy is None else proxy

    return proxy.get_all_names(offset, count)


def get_names_in_namespace(namespace_id, offset, count, proxy=None):
    """
    Get names in a namespace
    """
    proxy = get_default_proxy() if proxy is None else proxy

    return proxy.get_names_in_namespace(namespace_id, offset, count)


def get_names_owned_by_address(address, proxy=None):
    """
    Get the names owned by an address.
    Only works for p2pkh scripts.
    """
    proxy = get_default_proxy() if proxy is None else proxy

    return proxy.get_names_owned_by_address(address)


def get_consensus_at(block_height, proxy=None):
    """
    Get consensus at a block
    """
    proxy = get_default_proxy() if proxy is None else proxy

    resp = proxy.get_consensus_at(block_height)
    if isinstance(resp, list):
        resp = resp[0] if resp else {'error': 'No data returned'}

    return resp


def get_consensus_hashes(block_heights, proxy=None):
    """
    Get consensus hashes for a list of blocks
    NOTE: returns {block_height (int): consensus_hash (str)}
    (coerces the key to an int)
    """
    proxy = get_default_proxy() if proxy is None else proxy

    resp = proxy.get_consensus_hashes(block_heights)
    if isinstance(resp, list):
        resp = resp[0] if resp else {'error': 'No data returned'}

    if 'error' in resp:
        return resp

    if not isinstance(resp, dict):
        return {'error': 'Invalid data: expected dict'}

    try:
        return {int(k): v for k, v in resp.items()}
    except ValueError:
        return {'error': 'Invalid data: expected int'}


def get_consensus_range(block_id_start, block_id_end, proxy=None):
    """
    Get a range of consensus hashes.  The range is inclusive.
    """
    proxy = get_default_proxy() if proxy is None else proxy

    resp = proxy.get_consensus_range(block_id_start, block_id_end)

    return resp


def get_name_blockchain_history(name, start_block, end_block, proxy=None):
    """
    Get the name's historical blockchain records
    """
    proxy = get_default_proxy() if proxy is None else proxy

    resp = proxy.get_name_blockchain_history(name, start_block, end_block)

    return resp


def get_records_at(block_id, proxy=None):
    """
    Get the set of records as they were at a particular block.
    """
    proxy = get_default_proxy() if proxy is None else proxy

    resp = proxy.get_records_at(block_id)

    return resp


def get_records_hash_at(block_id, proxy=None):
    """
    Get the hash of a set of records as they were at a particular block.
    """
    proxy = get_default_proxy() if proxy is None else proxy

    resp = proxy.get_records_hash_at(block_id)
    if isinstance(resp, list):
        resp = resp[0] if resp else {'error': 'No data returned'}

    return resp


def get_name_blockchain_record(name, proxy=None):
    """
    get_name_blockchain_record
    """

    proxy = get_default_proxy() if proxy is None else proxy

    resp = proxy.get_name_blockchain_record(name)
    if isinstance(resp, list):
        resp = resp[0] if resp else {'error': 'No data returned'}

    return resp


def get_namespace_blockchain_record(namespace_id, proxy=None):
    """
    get_namespace_blockchain_record
    """

    proxy = get_default_proxy() if proxy is None else proxy

    resp = proxy.get_namespace_blockchain_record(namespace_id)
    if isinstance(resp, list):
        resp = resp[0] if resp else {'error': 'No data returned'}

    if resp is not None:
        # this isn't needed
        resp.pop('opcode', None)

    return resp


def is_name_registered(fqu, proxy=None):
    """
    Return True if @fqu registered on blockchain
    """

    proxy = get_default_proxy() if proxy is None else proxy

    blockchain_record = get_name_blockchain_record(fqu, proxy=proxy)
    if 'error' in blockchain_record:
        log.debug('Failed to read blockchain record for {}'.format(fqu))
        return False

    if blockchain_record.get('revoked', None) is not None:
        return False

    return 'first_registered' in blockchain_record


def has_zonefile_hash(fqu, proxy=None):
    """
    Return True if @fqu has a zonefile hash on the blockchain
    """

    proxy = get_default_proxy() if proxy is None else proxy

    blockchain_record = get_name_blockchain_record(fqu, proxy=proxy)
    if 'error' in blockchain_record:
        log.debug('Failed to read blockchain record for {}'.format(fqu))
        return False

    return blockchain_record.get('value_hash', None) is not None


def is_zonefile_current(fqu, zonefile_json, proxy=None):
    """
    Return True if hash(@zonefile_json) published on blockchain
    """

    proxy = get_default_proxy() if proxy is None else proxy

    zonefile_hash = storage.hash_zonefile(zonefile_json)

    return is_zonefile_hash_current(fqu, zonefile_hash, proxy=proxy)


def is_zonefile_hash_current(fqu, zonefile_hash, proxy=None):
    """
    Return True if hash(@zonefile_json) published on blockchain
    """

    proxy = get_default_proxy() if proxy is None else proxy

    blockchain_record = get_name_blockchain_record(fqu, proxy=proxy)
    if 'error' in blockchain_record:
        log.debug('Failed to read blockchain record for {}'.format(fqu))
        return False

    return zonefile_hash == blockchain_record.get('value_hash', '')


def is_name_owner(fqu, address, proxy=None):
    """
    return True if @btc_address owns @fqu
    """

    proxy = get_default_proxy() if proxy is None else proxy

    blockchain_record = get_name_blockchain_record(fqu, proxy=proxy)
    if 'error' in blockchain_record:
        log.debug('Failed to read blockchain record for {}'.format(fqu))
        return False

    return address == blockchain_record.get('address', '')
