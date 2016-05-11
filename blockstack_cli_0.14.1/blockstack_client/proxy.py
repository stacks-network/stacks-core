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
import zone_file
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

log = get_logger()

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


def get_namespace_reveal_blockchain_record(namespace_id, proxy=None):
    """
    Get a revealed (but not readied) namespace's information
    """
    if proxy is None:
        proxy = get_default_proxy()

    ret = proxy.get_namespace_reveal_blockchain_record(namespace_id)
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


def preorder(name, privatekey, register_addr=None, proxy=None, tx_only=False):
    """
    preorder.
    Generate a private key to derive a change address for the register,
    if one is not given already.
    """

    register_privkey_wif = None

    if register_addr is None:
        privkey = pybitcoin.BitcoinPrivateKey()
        pubkey = privkey.public_key()

        register_addr = pubkey.address()

        register_privkey_wif = privkey.to_wif()
        print register_privkey_wif
        print register_addr

    # make sure the reveal address is *not* the address of this private key
    privkey = pybitcoin.BitcoinPrivateKey(privatekey)
    if register_addr == privkey.public_key().address():
        return {"error": "Register address derived from private key"}

    resp = {}

    if proxy is None:
        proxy = get_default_proxy()

    try:
        if tx_only:

            # get unsigned preorder
            resp = proxy.preorder_tx(name, privatekey, register_addr)

        else:
            # send preorder
            resp = proxy.preorder(name, privatekey, register_addr)

    except Exception as e:
        resp['error'] = str(e)

    if 'error' in resp:
        return resp

    # give the client back the key to the addr we used
    if register_privkey_wif is not None:
        resp['register_privatekey'] = register_privkey_wif

    return resp


def preorder_subsidized(name, register_addr, subsidy_key, proxy=None):
    """
    preorder a name, but subsidize it with the given subsidy_key.
    Return a SIGHASH_ANYONECANPAY transaction, where the client must sign each
    input originating from register_addr
    """
    resp = {}

    if proxy is None:
        proxy = get_default_proxy()

    try:
        # get preorder tx
        resp = proxy.preorder_tx_subsidized(name, register_addr, subsidy_key)

    except Exception as e:
        resp['error'] = str(e)

    return resp


def register(name, privatekey, register_addr, proxy=None, tx_only=False):
    """
    register
    """

    resp = {}

    if proxy is None:
        proxy = get_default_proxy()

    try:
        if tx_only:

            # get unsigned preorder
            resp = proxy.register_tx(name, privatekey, register_addr)

        else:
            # send preorder
            resp = proxy.register(name, privatekey, register_addr)

    except Exception as e:
        resp['error'] = str(e)

    return resp



def register_subsidized(name, public_key, register_addr, subsidy_key, proxy=None):
    """
    make a transaction that will register a name, but subsidize it with the given subsidy_key.
    Return a SIGHASH_ANYONECANPAY transaction, where the client must sign each
    input originating from register_addr
    """
    resp = {}

    if proxy is None:
        proxy = get_default_proxy()

    try:
        # get register tx
        resp = proxy.register_tx_subsidized(name, public_key, register_addr, subsidy_key)

    except Exception as e:
        resp['error'] = str(e)

    return resp


def update(name, user_zonefile_json_or_hash, privatekey, txid=None, proxy=None, tx_only=False, public_key=None, subsidy_key=None):
    """
    Low-level update.

    Update a name record.  Send a new transaction that attaches the given zonefile JSON (or a hash of it) to the name.

    Optionally supply a txid.  The reason for doing so is to try to replicate user
    data to new storage systems, or to recover from a transient error encountered
    earlier.
    """

    import profile 

    # sanity check
    if privatekey is None and public_key is None:
        return {'error': 'Missing public and private key'}

    if proxy is None:
        proxy = get_default_proxy()

    user_zonefile_hash = None
    user_zonefile = None

    # 160-bit hex string?
    if len(user_zonefile_json_or_hash) == 40 and len(user_zonefile_json_or_hash.translate(None, "0123456789ABCDEFabcdef")) == 0:

        user_zonefile_hash = user_zonefile_json_or_hash.lower()
    else:
        
        # user zonefile. verify that it's wellformed
        try:
            if type(user_zonefile_json_or_hash) in [str, unicode]:
                user_zonefile = json.loads(user_zonefile_json_or_hash)
            else:
                user_zonefile = copy.deepcopy(user_zonefile_json_or_hash)

            assert user_db.is_user_zonefile( user_zonefile )
        except Exception, e:
            log.exception(e)
            return {'error': 'User profile is unparseable JSON or unparseable hash'}

        user_zonefile_txt = zone_file.make_zone_file( user_zonefile, origin=name, ttl=USER_ZONEFILE_TTL )
        user_zonefile_hash = storage.get_name_zonefile_hash( user_zonefile_txt )

    # must be blockchain data for this user
    blockchain_result = get_name_blockchain_record( name, proxy=proxy )
    if blockchain_result is None:
        return {'error': 'No such user'}
    
    if 'error' in blockchain_result:
        return blockchain_result

    if tx_only:

        result = None

        # only want a transaction 
        if privatekey is None and public_key is not None and subsidy_key is not None:
            result = proxy.update_tx_subsidized( name, user_zonefile_hash, public_key, subsidy_key )

        if privatekey is not None:
            result = proxy.update_tx( name, user_zonefile_hash, privatekey )

        if result is not None:
            return result

    if txid is None:

        # send a new transaction 
        result = proxy.update( name, user_zonefile_hash, privatekey )
        if result is None:
            return {'error': 'No response from server'}
        
        if 'error' in result:
            return result

        if 'transaction_hash' not in result:
            # failed
            print result
            result['error'] = 'No transaction hash returned'
            return result

        txid = result['transaction_hash']

    else:
        # embed the txid into the result nevertheless
        result['transaction_hash'] = txid 

    # store the zonefile, if given
    if user_zonefile is not None:
        rc, new_hash = profile.store_name_zonefile( name, user_zonefile, txid )
        if not rc:
            result['error'] = 'Failed to store user zonefile'
            return result

    # success!
    result['status'] = True
    result['value_hash'] = user_zonefile_hash
    return result


def update_subsidized(name, user_zonefile_json_or_hash, public_key, subsidy_key, txid=None, proxy=None):
    """
    update_subsidized
    """
    return update(name, user_zonefile_json_or_hash, None, txid=txid, public_key=public_key, subsidy_key=subsidy_key, tx_only=True, proxy=proxy)


def transfer(name, address, keep_data, privatekey, proxy=None, tx_only=False):
    """
    transfer
    """

    if proxy is None:
        proxy = get_default_proxy()

    if tx_only:
        return proxy.transfer_tx(name, address, keep_data, privatekey)

    else:
        return proxy.transfer(name, address, keep_data, privatekey)


def transfer_subsidized(name, address, keep_data, public_key, subsidy_key, proxy=None):
    """
    transfer_subsidized
    """
    if proxy is None:
        proxy = get_default_proxy()
    return proxy.transfer_tx_subsidized(name, address, keep_data, public_key, subsidy_key)


def renew(name, privatekey, proxy=None, tx_only=False):
    """
    renew
    """

    if proxy is None:
        proxy = get_default_proxy()

    if tx_only:
        return proxy.renew_tx(name, privatekey)

    else:
        return proxy.renew(name, privatekey)


def renew_subsidized(name, public_key, subsidy_key, proxy=None):
    """
    renew_subsidized
    """

    if proxy is None:
        proxy = get_default_proxy()

    return proxy.renew_tx_subsidized(name, public_key, subsidy_key)


def revoke(name, privatekey, proxy=None, tx_only=False):
    """
    revoke
    """

    if proxy is None:
        proxy = get_default_proxy()

    if tx_only:
        return proxy.revoke_tx(name, privatekey)

    else:
        return proxy.revoke(name, privatekey)


def revoke_subsidized(name, public_key, subsidy_key, proxy=None):
    """
    revoke_subsidized
    """
    if proxy is None:
        proxy = get_default_proxy()

    return proxy.revoke_tx_subsidized(name, public_key, subsidy_key)


def send_subsidized(privatekey, subsidized_tx, proxy=None):
    """
    send_subsidized
    """
    if proxy is None:
        proxy = get_default_proxy()

    return proxy.send_subsidized(privatekey, subsidized_tx)


def name_import(name, address, update_hash, privatekey, proxy=None):
    """
    name import
    """

    if proxy is None:
        proxy = get_default_proxy()

    return proxy.name_import(name, address, update_hash, privatekey)


def namespace_preorder(namespace_id, privatekey, reveal_addr=None, proxy=None):
    """
    namespace preorder
    Generate a register change address private key, if not given
    """

    if proxy is None:
        proxy = get_default_proxy()

    reveal_privkey_wif = None

    if reveal_addr is None:
        privkey = pybitcoin.BitcoinPrivateKey()
        pubkey = privkey.public_key()
        reveal_addr = pubkey.address()

        reveal_privkey_wif = privkey.to_wif()
        print reveal_privkey_wif
        print reveal_addr

    # make sure the reveal address is *not* the address of this private key
    privkey = pybitcoin.BitcoinPrivateKey(privatekey)
    if reveal_addr == privkey.public_key().address():
        return {"error": "Reveal address derived from private key"}

    result = proxy.namespace_preorder(namespace_id, reveal_addr, privatekey)

    if 'error' in result:
        return result

    if reveal_privkey_wif is not None:
        result['reveal_privatekey'] = reveal_privkey_wif

    return result


def namespace_reveal(namespace_id, reveal_addr, lifetime, coeff, base_cost,
                     bucket_exponents, nonalpha_discount, no_vowel_discount,
                     privatekey, proxy=None):
    """
    namesapce_reveal
    """

    if proxy is None:
        proxy = get_default_proxy()

    return proxy.namespace_reveal(namespace_id, reveal_addr, lifetime, coeff,
                                  base_cost, bucket_exponents, nonalpha_discount,
                                  no_vowel_discount, privatekey)


def namespace_ready(namespace_id, privatekey, proxy=None):
    """
    namespace_ready
    """

    if proxy is None:
        proxy = get_default_proxy()

    return proxy.namespace_ready(namespace_id, privatekey)


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

    from .profile import hash_zonefile

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


