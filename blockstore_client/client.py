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
    along with Blockstore-client. If not, see <http://www.gnu.org/licenses/>.
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

from . import parsing, schemas, storage, drivers, config
from . import user as user_db

import pybitcoin
import bitcoin as pybitcointools
import binascii

from config import log, DEBUG, MAX_RPC_LEN, find_missing, BLOCKSTORED_SERVER, \
    BLOCKSTORED_PORT, BLOCKSTORE_METADATA_DIR, BLOCKSTORE_DEFAULT_STORAGE_DRIVERS

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
        try:
            self.sock.sendall(data_netstring)
        except Exception, e:
            self.sock.close()
            self.sock = None
            raise e

        # get response: expect comma-ending netstring
        # get the length first
        len_buf = ""
        
        while True:
            c = self.sock.recv(1)
            if len(c) == 0:
                # connection closed
                self.sock.close()
                self.sock = None
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
                    self.sock = None
                    raise Exception("Invalid response: invalid netstring length")

                # ensure it's not too big
                if buf_len >= self.max_rpc_len:
                    self.sock.close()
                    self.sock = None
                    raise Exception("Invalid response: message too big")

        # receive message
        num_received = 0
        response = ""
        
        while num_received < buf_len+1:
            buf = self.sock.recv( 4096 )
            num_received += len(buf)
            response += buf

        # ensure that the message is terminated with a comma
        if response[-1] != ',':
            self.sock.close()
            self.sock = None
            raise Exception("Invalid response: invalid netstring termination")

        # trim ','
        response = response[:-1]

        # parse the response
        try:
            result = json.loads(response)
        except Exception, e:

            # try to clean up
            self.sock.close()
            self.sock = None
            raise Exception("Invalid response: not a JSON string")

        return result


def session(conf=None, server_host=BLOCKSTORED_SERVER, server_port=BLOCKSTORED_PORT,
            username=None, password=None, storage_drivers=BLOCKSTORE_DEFAULT_STORAGE_DRIVERS,
            metadata_dir=BLOCKSTORE_METADATA_DIR, set_global=True):
    
    """
    Create a blockstore session: 
    * validate the configuration
    * load all storage drivers 
    * initialize all storage drivers
    * load an API proxy to blockstore
    
    Returns the API proxy object.
    """
    
    global default_proxy
    proxy = BlockstoreRPCClient(server_host, server_port)

    if default_proxy is None and set_global:
        default_proxy = proxy
      
    if conf is not None:
        
        missing = find_missing( conf )
        if len(missing) > 0:
            log.error("Missing blockstore configuration fields: %s" % (", ".join(missing)))
            sys.exit(1)
            
        server_host = conf['server']
        server_port = conf['port']
        storage_drivers = conf['storage_drivers']
        metadata_dir = conf['metadata']
    
    if storage_drivers is None:
        log.error("No storage driver(s) defined in the config file.  Please set 'storage=' to a comma-separated list of %s" % ", ".join(drivers.DRIVERS))
        sys.exit(1)

    # load all storage drivers
    for storage_driver in storage_drivers.split(","):
        storage_impl = load_storage( storage_driver )
        if storage_impl is None:
            log.error("Failed to load storage driver '%s'" % (storage_driver))
            sys.exit(1)

        rc = register_storage( storage_impl )
        if not rc:
            log.error("Failed to initialize storage driver '%s'" % (storage_driver))
            sys.exit(1)
    
    return proxy


def get_default_proxy():
    """
    Get the default API proxy to blockstore.
    """
    global default_proxy

    return default_proxy


def load_storage( module_name ):
    """
    Load a storage implementation, given its module name.
    Valid options can be found in blockstore.drivers.DRIVERS
    """

    if module_name not in drivers.DRIVERS:
        raise Exception("Unrecognized storage driver.  Valid options are %s" % (", ".join(drivers.DRIVERS)))

    try:
        storage_impl = importlib.import_module("blockstore_client.drivers.%s" % module_name)
    except ImportError, ie:
        raise Exception("Failed to import blockstore.drivers.%s.  Please verify that it is accessible via your PYTHONPATH" % module_name)

    return storage_impl


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


def lookup( name ):
    return get_name_record( name )


def get_name_record(name, create_if_absent=False):
    """
    Given the name of the user, look up the user's record hash,
    and then get the record itself from storage.

    Returns a dict that contains the record,
    or a dict with "error" defined and a message.
    """

    # find name record first
    name_record = get_name_blockchain_record(name)
    if len(name_record) == 0:
        return {"error": "No such name"}
   
    if 'error' in name_record:
        return name_record 
    
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
        if not create_if_absent:
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


def store_name_record(user, txid):
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
    result = storage.put_immutable_data(user_json, txid )

    rc = None
    if result is None:
        rc = False
    else:
        rc = True

    return (rc, data_hash)


def remove_name_record(user, txid):
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


def get_name_cost( name, proxy=None ):
    """
    name_cost
    """
    if proxy is None:
        proxy = get_default_proxy()

    return proxy.get_name_cost(name)


def get_namespace_cost( namespace_id, proxy=None ):
    """
    namespace_cost
    """
    if proxy is None:
        proxy = get_default_proxy()

    return proxy.get_namespace_cost(namespace_id)


def get_all_names( offset, count, proxy=None ):
    """
    get all names
    """
    if proxy is None:
        proxy = get_default_proxy()
    
    return proxy.get_all_names( offset, count )


def get_names_in_namespace( namespace_id, offset, count, proxy=None ):
    """
    Get names in a namespace 
    """
    if proxy is None:
        proxy = get_default_proxy()
        
    return proxy.get_names_in_namespace( namespace_id, offset, count )


def get_consensus_at( block_id, proxy=None ):
    """
    Get consensus at a block 
    """
    if proxy is None:
        proxy = get_default_proxy()
    
    return proxy.get_consensus_at( block_id )

def get_name_blockchain_record(name, proxy=None):
    """
    get_name_blockchain_record
    """

    if proxy is None:
        proxy = get_default_proxy()

    return proxy.get_name_blockchain_record(name)


def get_namespace_blockchain_record( namespace_id, proxy=None ):
    """
    get_namespace_blockchain_record
    """

    if proxy is None:
        proxy = get_default_proxy()

    ret = proxy.get_namespace_blockchain_record(namespace_id)
    if ret is not None:
        # this isn't needed
        if 'opcode' in ret[0]:
            del ret[0]['opcode']

    return ret


def preorder(name, privatekey, register_addr=None, proxy=None, tx_only=False ):
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
    privkey = pybitcoin.BitcoinPrivateKey( privatekey )
    if register_addr == privkey.public_key().address():
        return {"error": "Register address derived from private key"}

    resp = {}

    if proxy is None:
        proxy = get_default_proxy()

    try:
        if tx_only:
            
            # get unsigned preorder
            resp = proxy.preorder_tx( name, privatekey, register_addr )
            
        else:
            # send preorder
            resp = proxy.preorder(name, privatekey, register_addr)
            
    except Exception as e:
        resp['error'] = str(e)

    if 'error' in resp:
        return resp

    # give the client back the key to the addr we used
    if register_privkey_wif is not None:
        resp[0]['register_privatekey'] = register_privkey_wif

    return resp


def preorder_subsidized( name, public_key, register_addr, subsidy_key, proxy=None ):
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
        resp = proxy.preorder_tx_subsidized( name, public_key, register_addr, subsidy_key )
        
    except Exception as e:
        resp['error'] = str(e)
    
    return resp


def register(name, privatekey, register_addr, proxy=None, tx_only=False ):
    """
    register
    """

    if proxy is None:
        proxy = get_default_proxy()

    try:
        if tx_only:
            
            # get unsigned preorder
            resp = proxy.register_tx( name, privatekey, register_addr )
            
        else:
            # send preorder
            resp = proxy.register(name, privatekey, register_addr)
            
    except Exception as e:
        resp['error'] = str(e)

    return resp



def register_subsidized( name, public_key, register_addr, subsidy_key, proxy=None ):
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
        resp = proxy.register_tx_subsidized( name, public_key, register_addr, subsidy_key )
        
    except Exception as e:
        resp['error'] = str(e)
    
    return resp


def update(name, user_json_or_hash, privatekey, txid=None, proxy=None, tx_only=False, public_key=None, subsidy_key=None):
    """
    update

    Optionally supply a txid.  The reason for doing so is to try to replicate user
    data to new storage systems, or to recover from a transient error encountered
    earlier.
    """
    
    # sanity check 
    if privatekey is None and public_key is None:
        return {'error': 'Missing public and private key'}
    
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
    current_user_record = get_name_record( name, create_if_absent=True )
    if current_user_record is None:
        return {'error': 'No such user'}

    if current_user_record.has_key('error'):
        # some other error
        return current_user_record

    result = {}

    old_hash = pybitcoin.hash.hex_hash160(user_db.serialize_user(user_data))
    
    # only want transaction?
    if tx_only:
        
        if privatekey is None and public_key is not None and subsidy_key is not None:
            return proxy.update_tx_subsidized( name, user_record_hash, public_key, subsidy_key )
        
        else:
            return proxy.update_tx( name, user_record_hash, privatekey )
            
    
    # no transaction: go put one
    if txid is None:
        
        if tx_only:
            result = proxy.update_tx( name, user_record_hash, privatekey )
            return result 
        
        else:
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
        rc, new_data_hash = store_name_record(user_data, txid)

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


def update_subsidized( name, user_json_or_hash, public_key, subsidy_key, txid=None ):
    """
    update_subsidized
    """
    return update( name, user_json_or_hash, None, txid=txid, public_key=public_key, subsidy_key=subsidy_key, tx_only=True )


def transfer(name, address, keep_data, privatekey, proxy=None, tx_only=False):
    """
    transfer
    """

    if proxy is None:
        proxy = get_default_proxy()

    if tx_only:
        return proxy.transfer_tx( name, address, keep_data, privatekey )
    
    else:
        return proxy.transfer(name, address, keep_data, privatekey)


def transfer_subsidized( name, address, keep_data, public_key, subsidy_key, proxy=None ):
    """
    transfer_subsidized
    """
    if proxy is None:
        proxy = get_default_proxy()

    return proxy.transfer_tx_subsidized( name, address, keep_data, public_key, subsidy_key )


def renew(name, privatekey, proxy=None, tx_only=False):
    """
    renew
    """

    if proxy is None:
        proxy = get_default_proxy()

    if tx_only:
        return proxy.renew_tx( name, privatekey )
    
    else:
        return proxy.renew(name, privatekey)


def renew_subsidized( name, public_key, subsidy_key, proxy=None ):
    """
    renew_subsidized
    """
    
    if proxy is None:
        proxy = get_default_proxy()

    return proxy.renew_tx_subsidized( name, public_key, subsidy_key )


def revoke(name, privatekey, proxy=None, tx_only=False):
    """
    revoke
    """

    if proxy is None:
        proxy = get_default_proxy()

    if tx_only:
        return proxy.revoke_tx( name, privatekey )
    
    else:
        return proxy.revoke(name, privatekey)
    
    
def revoke_subsidized( name, public_key, subsidy_key, proxy=None ):
    """
    revoke_subsidized
    """
    if proxy is None:
        proxy = get_default_proxy()

    return proxy.revoke_tx_subsidized( name, public_key, subsidy_key )


def send_subsidized( privatekey, subsidized_tx, proxy=None ):
    """
    send_subsidized
    """
    if proxy is None:
        proxy = get_default_proxy()
        
    return proxy.send_subsidized( privatekey, subsidized_tx )


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
    privkey = pybitcoin.BitcoinPrivateKey( privatekey )
    if reveal_addr == privkey.public_key().address():
        return {"error": "Reveal address derived from private key"}

    result = proxy.namespace_preorder(namespace_id, reveal_addr, privatekey )

    if 'error' in result:
        return result

    if reveal_privkey_wif is not None:
        result[0]['reveal_privatekey'] = reveal_privkey_wif

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
                                  no_vowel_discount, privatekey )


def namespace_ready(namespace_id, privatekey, proxy=None):
    """
    namespace_ready
    """

    if proxy is None:
        proxy = get_default_proxy()

    return proxy.namespace_ready(namespace_id, privatekey)


def load_mutable_data_version( conf, name, data_id, try_remote=True ):
    """
    Get the version field of a piece of mutable data.
    Check the local cache first, and if we need to,
    fetch the data itself from mutable storage
    """

    # try to get the current, locally-cached version
    if conf is None:
        conf = config.get_config()

    metadata_dir = None
    if conf is not None:

        metadata_dir = conf.get('metadata', None)
        if metadata_dir is not None and os.path.isdir( metadata_dir ):

            # find the version file for this data
            serialized_data_id = data_id.replace("/", "\x2f").replace('\0', "\\0")
            version_file_path = os.path.join( metadata_dir, serialized_data_id + ".ver")

            if os.path.exists( version_file_path ):

                ver = None
                try:
                    with open( version_file_path, "r" ) as f:
                        ver_txt = f.read()
                        ver = int( ver_txt.strip() )

                    # success!
                    return ver

                except ValueError, ve:
                    # not an int
                    log.warn("Not an integer: '%s'" % version_file_path )

                except Exception, e:
                    # can't read
                    log.warn("Failed to read '%s': %s" % (version_file_path))

    if not try_remote:
        if conf is None:
            log.warning("No config found; cannot load version for '%s'" % data_id)

        elif metadata_dir is None:
            log.warning("No metadata directory found; cannot load version for '%s'" % data_id)

        return None

    # if we got here, then we need to fetch remotely
    existing_data = get_mutable(name, data_id)
    if existing_data is None:

        # nope
        return None

    if existing_data.has_key('error'):

        # nope
        return None

    ver = existing_data['ver']
    return ver


def store_mutable_data_version( conf, data_id, ver ):
    """
    Locally store the version of a piece of mutable data,
    so we can ensure that its version is incremented on
    subsequent puts.

    Return True if stored
    Return False if not
    """

    if conf is None:
        conf = config.get_config()

    if conf is None:
        log.warning("No config found; cannot store version for '%s'" % data_id)
        return False

    metadata_dir = conf['metadata']
    if not os.path.isdir( metadata_dir ):
        log.warning("No metadata directory found; cannot store version of '%s'" % data_id)
        return False

    serialized_data_id = data_id.replace("/", "\x2f").replace('\0', "\\0")
    version_file_path = os.path.join( metadata_dir, serialized_data_id + ".ver")

    try:
        with open( version_file_path, "w+" ) as f:
            f.write("%s" % ver )

        return True

    except Exception, e:
        # failed for whatever reason
        log.warn("Failed to store version of '%s' to '%s'" % (data_id, version_file_path))
        return False


def delete_mutable_data_version( conf, data_id ):
    """
    Locally delete the version of a piece of mutable data.

    Return True if deleted.
    Return False if not
    """

    if conf is None:
        conf = config.get_config()

    if conf is None:
        log.warning("No config found; cannot store version for '%s'" % data_id)
        return False

    metadata_dir = conf['metadata']
    if not os.path.isdir( metadata_dir ):
        log.warning("No metadata directory found; cannot store version of '%s'" % data_id)
        return False

    serialized_data_id = data_id.replace("/", "\x2f").replace('\0', "\\0")
    version_file_path = os.path.join( metadata_dir, serialized_data_id + ".ver")

    try:
        os.unlink( version_file_path )
        return True

    except Exception, e:
        # failed for whatever reason
        log.warn("Failed to remove version file '%s'" % (version_file_path))
        return False


def get_immutable(name, data_key):
    """
    get_immutable
    """

    user = get_name_record(name)
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


def get_mutable(name, data_id, ver_min=None, ver_max=None, ver_check=None, conf=None):
    """
    get_mutable
    """

    if conf is None:
        conf = config.get_config()

    user = get_name_record(name)
    if 'error' in user:

        # no user data
        return {'error': "Unable to load user record: %s" % user['error']}

    # find the mutable data ID
    data_route = user_db.get_mutable_data_route(user, data_id)
    if data_route is None:

        # no data
        return {'error': 'No such route'}

    # go and fetch the data
    data = storage.get_mutable_data(data_route, ver_min=ver_min,
                                    ver_max=ver_max,
                                    ver_check=ver_check)
    if data is None:

        # no data
        return {'error': 'No mutable data found'}

    # what's the expected version of this data?
    expected_version = load_mutable_data_version( conf, name, data_id, try_remote=False )
    if expected_version is not None:
        if expected_version > data['ver']:
            return {'error': 'Stale data', 'ver_minimum': expected_version, 'ver_received': data['ver']}

    elif ver_check is None:
        # we don't have a local version, and the caller didn't check it.
        log.warning("Unconfirmed version for data '%s'" % data_id)
        data['warning'] = "Unconfirmed version"

    # remember latest version
    if data['ver'] > expected_version:
        store_mutable_data_version( conf, data_id, data['ver'] )

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
    user = get_name_record(name, create_if_absent=True)
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
                txid=None, ver=None, make_ver=None, conf=None ):
    """
    put_mutable

    ** Consistency **

    ver, if given, is the version to include in the data.
    make_ver, if given, is a callback that takes the data_id, data_text, and current version as arguments, and generates the version to be included in the data record uploaded.
    If ver is not given, but make_ver is, then make_ver will be used to generate the version.
    If neither ver nor make_ver are given, the mutable data (if it already exists) is fetched, and the version is calculated as the larget known version + 1.

    ** Durability **

    Replication is best-effort.  If one storage provider driver succeeds, the put_mutable succeeds.  If they all fail, then put_mutable fails.
    More complex behavior can be had by creating a "meta-driver" that calls existing drivers' methods in the desired manner.
    """

    if proxy is None:
        proxy = get_default_proxy()

    result = {}
    user = get_name_record(name, create_if_absent=create)
    if 'error' in user:

        return {'error': "Unable to load user record: %s" % user['error']}

    route = None
    exists = user_db.has_mutable_data_route(user, data_id)
    old_hash = None
    cur_hash = None
    new_ver = ver

    if ver is None:

        if exists:
            # mutable record already exists.
            # generate one automatically.
            # use the existing locally-stored version,
            # and fall back to using the last-known version
            # from the existing mutable data record.
            new_ver = load_mutable_data_version( config.get_config(), name, data_id, try_remote=True )
            if new_ver is None:
                # data exists, but we couldn't figure out the version
                return {'error': "Unable to determine version"}

        if make_ver is not None:
            # generate version
            new_ver = make_ver( data_id, data_text, new_ver )

        else:
            # no version known, and no way to generate it.
            # by default, start at 1.  we'll manage it ourselves.
            if new_ver is None:
                new_ver = 1
            else:
                new_ver += 1


    # do we have a route for this data yet?
    if not exists:

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

    else:

        route = user_db.get_mutable_data_route(user, data_id)
        if route is None:

            return {"error": "No such route"}

    # generate the data
    data = storage.mutable_data(data_id, data_text, new_ver, privkey=privatekey)
    if data is None:
        return {"error": "Failed to generate data record"}

    # serialize...
    data_json = parsing.json_stable_serialize(data)

    # replicate...
    store_rc = storage.put_mutable_data( data, privatekey )
    if not store_rc:
        result['error'] = "Failed to store mutable data"

    else:
        result['status'] = True

    result['transaction_hash'] = txid

    if cur_hash:
        # propagate
        result['value_hash'] = cur_hash

    # cache new version
    store_mutable_data_version( conf, data_id, new_ver )

    return result


def delete_immutable(name, data_key, privatekey, proxy=None, txid=None):
    """
    delete_immutable
    """

    if proxy is None:
        proxy = get_default_proxy()

    result = {}
    user = get_name_record(name)
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
    user = get_name_record(name)
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

    # uncache local version
    delete_mutable_data_version( config.get_config(), data_id )

    return result
