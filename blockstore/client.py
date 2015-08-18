#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore-client
    ~~~~~
    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

    This file is part of Blockstore-client.

    Blockstore-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstore-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore-client.  If not, see <http://www.gnu.org/licenses/>.
"""

import argparse
import sys
import json
import traceback
import types
import socket
import uuid

from . import parsing, schemas, storage
from . import user as user_db

import pybitcoin
import pybitcointools
import binascii

from .config import log, DEBUG, MAX_RPC_LEN

# default API endpoint proxy to blockstored
default_proxy = None

# ancillary storage providers
STORAGE_IMPL = None


class BlockstoreRPCClient(object):
    """
    Not-quite-JSONRPC client for Blockstore.

    Blockstore's not-quite-JSONRPC server expects a raw Netstring that encodes
    a JSON object with a "method" string and an "args" list.  It will ignore
    "id" and "version", and will not accept keyword arguments.  It also does
    not guarantee that the "result" and "error" keywords will be present.
    """

    def __init__(self, server, port, max_rpc_len=MAX_RPC_LEN):
        self.server = server
        self.port = port
        self.sock = None
        self.max_rpc_len = max_rpc_len

    def __getattr__(self, key):
        try:
            return object.__getattr__(self, key)
        except AttributeError:
            return self.dispatch(key)

    def socket():
        return self.sock

    def default(self, *args):
        self.params = args
        return self.request()

    def dispatch(self, key):
        self.method = key
        return self.default

    def ensure_connected(self):
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            self.sock.connect((self.server, self.port))

        return True

    def request(self):

        self.ensure_connected()
        request_id = str(uuid.uuid4())
        parameters = {
            'id': request_id,
            'method': self.method,
            'params': self.params,
            'version': '2.0'
        }

        data = json.dumps(parameters)
        data_netstring = str(len(data)) + ":" + data + ","

        # send request
        self.sock.sendall(data_netstring)

        # get response: expect comma-ending netstring
        # get the length first
        len_buf = ""

        while True:
            c = self.sock.recv(1)
            if len(c) == 0:
                # connection closed
                self.sock.close()
                raise Exception("Server closed remote connection")

            c = c[0]

            if c == ':':
                break
            else:
                len_buf += c
                buf_len = 0

                # ensure it's an int
                try:
                    buf_len = int(len_buf)
                except Exception, e:
                    # invalid
                    self.sock.close()
                    raise Exception("Invalid response: invalid netstring length")

                # ensure it's not too big
                if buf_len >= self.max_rpc_len:
                    self.sock.close()
                    raise Exception("Invalid response: message too big")

        # receive message
        response = self.sock.recv(buf_len+1)

        # ensure that the message is terminated with a comma
        if response[-1] != ',':
            self.sock.close()
            raise Exception("Invalid response: invalid netstring termination")

        # trim ','
        response = response[:-1]

        # parse the response
        try:
            result = json.loads(response)
        except Exception, e:

            # try to clean up
            self.sock.close()
            raise Exception("Invalid response: not a JSON string")

        return result


def session(server_host, server_port, username=None, password=None,
            set_global=True):
    """
    Create a JSONRPC API proxy to blockstore
    """

    global default_proxy
    proxy = BlockstoreRPCClient(server_host, server_port)

    if default_proxy is None and set_global:
        default_proxy = proxy

    return proxy


def get_default_proxy():
    """
    Get the default API proxy to blockstore.
    """
    global default_proxy

    return default_proxy


def register_storage(storage_impl):
    """
    Register a storage implementation.
    """
    rc = storage.register_storage(storage_impl)
    if rc:
        rc = storage_impl.storage_init()
        
    return rc


def load_user(record_hash):
    """
    Load a user record from the storage implementation with the given hex string hash,
    The user record hash should have been loaded from the blockchain, and thereby be the
    authentic hash.

    Return the user record on success
    Return None on error
    """

    user_json = storage.get_immutable_data(record_hash)
    if user_json is None:
        log.error("Failed to load user record '%s'" % record_hash)
        return None

    # verify integrity
    user_record_hash = storage.get_data_hash(user_json)
    if user_record_hash != record_hash:
        log.error("Profile hash mismatch: expected '%s', got '%s'" % record_hash, user_record_hash)
        return None

    user = user_db.parse_user(user_json)
    return user


def get_user_record(name, create=False):
    """
    Given the name of the user, look up the user's record hash,
    and then get the record itself from storage.

    Returns a dict that contains the record,
    or a dict with "error" defined and a message.
    """

    # find name record first
    name_record = lookup(name)
    if len(name_record) == 0:
        return {"error": "No such name"}

    name_record = name_record[0]
    if name_record is None:
        # failed to look up 
        return {'error': "No such name"}
    
    if 'error' in name_record:

        # failed to look up
        return name_record

    # sanity check
    if 'value_hash' not in name_record:

        return {"error": "Name has no user record hash defined"}

    # is there a user record loaded?
    if name_record['value_hash'] in [None, "null", ""]:

        # no user data
        if not create:
            return {"error": "No user data"}
        else:
            # make an empty one and return that
            user_resp = user_db.make_empty_user(name, name_record)
            return user_resp

    # get record
    user_record_hash = name_record['value_hash']
    user_resp = load_user(user_record_hash)

    if user_resp is None:

      # no user record data
      return {"error": "User data could not be loaded from storage"}

    return user_resp


def store_user_record(user, txid):
    """
    Store JSON user record data to the immutable storage providers, synchronously.

    Return (True, hash(user)) on success
    Return (False, hash(user)) on failure
    """

    username = user_db.name(user)

    # serialize
    user_json = None
    try:
        user_json = user_db.serialize_user(user)
    except Exception, e:
        log.error("Failed to serialize '%s'" % user)
        return False

    data_hash = storage.get_data_hash(user_json)
    result = storage.put_immutable_data(user_json, txid, replication_strategy=storage.REPLICATE_ALL)

    rc = None
    if result is None:
        rc = False
    else:
        rc = True

    return (rc, data_hash)


def remove_user_record(user, txid):
    """
    Delete JSON user record data from immutable storage providers, synchronously.

    Return (True, hash(user)) on success
    Return (False, hash(user)) on error
    """

    username = user_db.name(user)

    # serialize
    user_json = None
    try:
        user_json = user_db.serialize_user(user)
    except Exception, e:
        log.error("Failed to serialize '%s'" % user)
        return False

    data_hash = storage.get_data_hash(user_json)
    result = storage.delete_immutable_data(data_hash, txid)

    rc = None
    if result is None:
        rc = False
    else:
        rc = True

    return (rc, data_hash)


def getinfo(proxy=None):
    """
    getinfo
    """

    resp = {}

    if proxy is None:
        proxy = get_default_proxy()

    try:
        resp = proxy.getinfo()
    except Exception as e:
        resp['error'] = str(e)

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
    except Exception as e:
        resp['error'] = str(e)

    return resp


def lookup(name, proxy=None):
    """
    lookup
    """

    if proxy is None:
        proxy = get_default_proxy()

    return proxy.lookup(name)


def preorder(name, privatekey, proxy=None):
    """
    preorder
    """

    resp = {}

    if proxy is None:
        proxy = get_default_proxy()

    try:
        resp = proxy.preorder(name, privatekey)
    except Exception as e:
        resp['error'] = str(e)

    return resp


def register(name, privatekey, proxy=None):
    """
    register
    """

    if proxy is None:
        proxy = get_default_proxy()

    return proxy.register(name, privatekey)


def update(name, user_json_or_hash, privatekey, txid=None, proxy=None):
    """
    update

    Optionally supply a txid.  The reason for doing so is to try to replicate user
    data to new storage systems, or to recover from a transient error encountered
    earlier.
    """

    if proxy is None:
        proxy = get_default_proxy()

    user_record_hash = None
    user_data = None

    # 160-bit hex string?
    if len(user_json_or_hash) == 40 and len(user_json_or_hash.translate(None, "0123456789ABCDEFabcdef")) == 0:

        user_record_hash = user_json_or_hash.lower()
    else:

        # user record json.  hash it
        user_data = user_db.parse_user(user_json_or_hash)
        if user_data is None:
            return {'error': 'Invalid user record JSON'}

        user_record_hash = pybitcoin.hash.hex_hash160(user_db.serialize_user(user_data))

    # go get the current user record 
    current_user_record = get_user_record( name )
    if current_user_record is None:
        return {'error': 'No such user'}
    
    if current_user_record.has_key('error'):
        # some other error 
        return current_user_record

    result = {}
    
    old_hash = pybitcoin.hash.hex_hash160(user_db.serialize_user(user_data))

    # no transaction: go put one
    if txid is None:
        
        result = proxy.update(name, user_record_hash, privatekey)
        result = result[0]

        if 'error' in result:
            # failed
            return result

        if 'transaction_hash' not in result:
            # failed
            result['error'] = "No transaction hash given"
            return result

        txid = result['transaction_hash']

    else:

        # embed the txid into the result nevertheless
        result['transaction_hash'] = txid

    # store new user data
    rc = True
    new_data_hash = None
    if user_data is not None:
        rc, new_data_hash = store_user_record(user_data, txid)
    
    else:
        # was already a hash
        new_data_hash = user_json_or_hash
    
    if not rc:
        result['error'] = "Failed to store updated user record."
        return result 
    
    result['status'] = True
    result['value_hash'] = new_data_hash
    result['transaction_hash'] = txid

    return result


def transfer(name, address, keep_data, privatekey, proxy=None):
    """
    transfer
    """

    if proxy is None:
        proxy = get_default_proxy()

    return proxy.transfer(name, address, keep_data, privatekey)


def renew(name, privatekey, proxy=None):
    """
    renew
    """

    if proxy is None:
        proxy = get_default_proxy()

    return proxy.renew(name, privatekey)


def revoke(name, privatekey, proxy=None):
    """
    revoke
    """

    if proxy is None:
        proxy = get_default_proxy()

    return proxy.revoke(name, privatekey)


def namespace_preorder(namespace_id, privatekey, proxy=None):
    """
    namespace preorder
    """

    if proxy is None:
        proxy = get_default_proxy()

    return proxy.namespace_preorder(namespace_id, privatekey)


def namespace_reveal(namespace_id, lifetime, base_name_cost, cost_decay_rate,
                     privatekey, proxy=None):
    """
    namesapce_reveal
    """

    if proxy is None:
        proxy = get_default_proxy()

    return proxy.namespace_reveal(namespace_id, lifetime, base_name_cost,
                                  cost_decay_rate, privatekey)


def namespace_ready(namespace_id, privatekey, proxy=None):
    """
    namespace_ready
    """

    if proxy is None:
        proxy = get_default_proxy()

    return proxy.namespace_ready(namespace_id, privatekey)


def get_immutable(name, data_key):
    """
    get_immutable
    """

    user = get_user_record(name)
    if 'error' in user:

        # no user data
        return {'error': "Unable to load user record: %s" % user['error']}

    if not user_db.has_immutable_data(user, data_key):

        # no data
        return {'error': 'Profile has no such immutable data'}

    data = storage.get_immutable_data(data_key)
    if data is None:

        # no data
        return {'error': 'No immutable data found'}

    return {'data': data}


def get_mutable(name, data_id, nonce_min=None, nonce_max=None, nonce_check=None):
    """
    get_mutable
    """

    user = get_user_record(name)
    if 'error' in user:

        # no user data
        return {'error': "Unable to load user record: %s" % user['error']}

    # find the mutable data ID
    data_route = user_db.get_mutable_data_route(user, data_id)
    if data_route is None:

        # no data
        return {'error': 'No such route'}

    # go and fetch the data
    data = storage.get_mutable_data(data_route, nonce_min=nonce_min,
                                    nonce_max=nonce_max,
                                    nonce_check=nonce_check)
    if data is None:

        # no data
        return {'error': 'No mutable data found'}

    # include the route
    data['route'] = data_route
    return data


def put_immutable(name, data, privatekey, txid=None, proxy=None):
    """
    put_immutable

    Optionally include a txid from the user record update, in order to retry a failed 
    data replication (in which case, this txid corresponds to the succeeded name 
    update operation).  This is to avoid needing to pay for each replication retry.
    """

    if proxy is None:
        global default_proxy
        proxy = default_proxy

    # need to put the transaction ID into the data record we put
    user = get_user_record(name, create=True)
    if 'error' in user:

        # no user data
        return {'error': "Unable to load user record: %s" % user['error']}

    data_hash = storage.get_data_hash( data )
    rc = user_db.add_immutable_data(user, data_hash)
    if not rc:
        return {'error': 'Invalid hash'}

    user_json = user_db.serialize_user(user)
    if user_json is None:
        raise Exception("BUG: failed to serialize user record")
    
    value_hash = None 
    
    if txid is None:

        # haven't updated the user record yet.  Do so now.
        # put the new user record hash
        update_result = update(name, user_json, privatekey, proxy=proxy)
        if 'error' in update_result:

            # failed to replicate user record
            # NOTE: result will have the txid in it; pass it as txid to try again!
            return update_result

        txid = update_result['transaction_hash']
        value_hash = update_result['value_hash']

    result = {
        'data_hash': data_hash,
        'transaction_hash': txid
    }

    # propagate update() data
    if value_hash is not None:
        result['value_hash'] = value_hash
    
    # replicate the data
    rc = storage.put_immutable_data(data, txid)
    if not rc:
        result['error'] = 'Failed to store immutable data'
        return result

    else:
        result['status'] = True
        return result


def put_mutable(name, data_id, data_text, privatekey, proxy=None, create=True,
                txid=None, nonce=None, make_nonce=None,
                replication_strategy=storage.REPLICATE_ALL):
    """
    put_mutable

    ** Consistency **

    nonce, if given, is the nonce to include in the data.
    make_nonce, if given, is a callback that takes the data_id and data_text and generates a nonce to be included in the data record uploaded.
    If nonce is not given, but make_nonce is, then make_nonce will be used to generate the nonce.
    If neither nonce nor make_nonce are given, the mutable data (if it already exists) is fetched, and the nonce is calculated as existing['nonce'] + 1.

    ** Durability ** 

    replication_strategy defines how rigorous blockstore is when it comes to replicating data to its storage providers.
    If set to REPLICATE_ALL (the default), then this method only succeeds if we successfully replicate to *every* storage provider.
    If set to REPLICATE_ANY, then this method succeeds if we successfully replicate to one storage provider.
    Storage providers are contacted in the order they are registered.
    """

    if proxy is None:
        proxy = get_default_proxy()

    result = {}
    user = get_user_record(name, create=create)
    if 'error' in user:

        return {'error': "Unable to load user record: %s" % user['error']}

    route = None
    exists = True
    old_hash = None
    cur_hash = None

    # do we have a route for this data yet?
    if not user_db.has_mutable_data_route(user, data_id):

        if not create:
            # won't create; expect it to exist
            return {'error': 'No such route'}

        # need to put one
        urls = storage.make_mutable_urls(data_id)
        if len(urls) == 0:
            return {"error": "No routes constructed"}

        writer_pubkey = pybitcointools.privkey_to_pubkey(privatekey)

        route = storage.mutable_data_route(data_id, urls,
                                           writer_pubkey=writer_pubkey)

        user_db.add_mutable_data_route(user, route)

        user_json = user_db.serialize_user(user)
        
        # update the user record with the new route
        update_result = update(name, user_json, privatekey, txid=txid, proxy=proxy)
        if 'error' in update_result:

            # update failed; caller should try again
            return update_result

        txid = update_result['transaction_hash']
        cur_hash = update_result['value_hash']
        
        exists = False

    else:

        route = user_db.get_mutable_data_route(user, data_id)
        if route is None:

            return {"error": "No such route"}

    if nonce is None:

        # need a nonce
        if make_nonce is not None:
            nonce = make_nonce(data_id, data_text)

        if exists:

            existing_data = get_mutable(name, data_id)
            if existing_data is None:

                result['error'] = "No nonce calculated"
                result['transaction_hash'] = txid
                return result

            nonce = existing_data['nonce']
            nonce += 1

        else:
            nonce = 1

    # upload the data
    data = storage.mutable_data(data_id, data_text, nonce, privkey=privatekey)
    if data is None:
        return {"error": "Failed to generate data record"}

    data_json = parsing.json_stable_serialize(data)

    store_rc = storage.put_mutable_data( data, privatekey )
    if not store_rc:
        result['error'] = "Failed to store mutable data"

    else:
        result['status'] = True

    result['transaction_hash'] = txid
    
    if cur_hash:
        # propagate 
        result['value_hash'] = cur_hash
        
    return result


def delete_immutable(name, data_key, privatekey, proxy=None, txid=None):
    """
    delete_immutable
    """

    if proxy is None:
        proxy = get_default_proxy()

    result = {}
    user = get_user_record(name)
    if 'error' in user:

        # no user data
        return {'error': "Unable to load user record: %s" % user['error']}

    # does the user record have this data?
    if not user_db.has_immutable_data(user, data_key):

        # already deleted
        return {'status': True}

    # remove hash from the user record and update it
    user_db.remove_immutable_data(user, data_key)

    user_json = user_db.serialize_user(user)

    update_result = update(name, user_json, privatekey, txid=txid, proxy=proxy)
    if 'error' in update_result:

        # update failed; caller should try again
        return update_result

    txid = update_result['transaction_hash']

    # remove the data itself data
    delete_result = storage.delete_immutable_data(data_key, txid)
    if delete_result:

        result['status'] = True

    else:

        # be sure to give back the update transaction hash, so this call can be retried
        result['error'] = 'Failed to delete immutable data'

    result['transaction_hash'] = txid
    result['value_hash'] = update_result['value_hash']
    
    return result


def delete_mutable(name, data_id, privatekey, proxy=default_proxy, txid=None,
                   route=None):
    """
    delete_mutable
    """

    if proxy is None:
        proxy = get_default_proxy()

    result = {}
    user = get_user_record(name)
    if 'error' in user:

        # no user data
        return {'error': "Unable to load user record: %s" % user['error']}

    # does the user have a route to this data?
    if not user_db.has_mutable_data_route(user, data_id) and txid is None:

        # nope--we're good
        return {'status': True}

    # blow away the data
    storage_rc = storage.delete_mutable_data(data_id, privatekey)
    if not storage_rc:
        result['error'] = "Failed to delete mutable data"
        return result

    # remove the route from the user record
    user_db.remove_mutable_data_route(user, data_id)
    user_json = user_db.serialize_user(user)

    # update the user record
    update_status = update(name, user_json, privatekey, txid=txid,
                           proxy=proxy)
    
    if 'error' in update_status:

        # failed; caller should try again
        return update_status

    if txid is None:
        txid = update_status['transaction_hash']

    # blow away the route
    if route is None:
        route = user_db.get_mutable_data_route(user, data_id)

    route_hash = storage.get_mutable_data_route_hash(route)
    storage_rc = storage.delete_immutable_data(route_hash, txid)
    if not storage_rc:

        result['error'] = "Failed to delete immutable data route"
        result['route'] = route

    else:
        result['status'] = True
        result['transaction_hash'] = txid 
        result['value_hash'] = update_status['value_hash']
    

    return result
