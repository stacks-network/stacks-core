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

import argparse
import logging
import os
import sys
import subprocess
import signal
import json
import datetime
import traceback
import httplib
import time
import socket
import math
import random
import shutil
import tempfile
import binascii
import copy
import atexit
import threading
import errno

from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler

# stop common XML attacks 
from defusedxml import xmlrpc
xmlrpc.monkey_patch()

import virtualchain
log = virtualchain.get_logger("blockstack-server")

try:
    import blockstack_client
except:
    # storage API won't work
    blockstack_client = None

from ConfigParser import SafeConfigParser

import pybitcoin

from .blockchain import *
from .nameset import get_db_state
import nameset.virtualchain_hooks as virtualchain_hooks
import config


class BlockstackdRPCHandler(SimpleXMLRPCRequestHandler):
    """
    Hander to capture tracebacks
    """
    def _dispatch(self, method, params):
        try: 
            res = self.server.funcs["rpc_" + str(method)](*params)

            # lol jsonrpc within xmlrpc
            return json.dumps(res)
        except Exception, e:
            print >> sys.stderr, "\n\n%s\n\n" % traceback.format_exc()
            return rpc_traceback()


class BlockstackdRPC(SimpleXMLRPCServer):
    """
    Blockstackd RPC server, used for querying
    the name database and the blockchain peer.

    Methods that start with rpc_* will be registered
    as RPC methods.
    """

    def __init__(self, host='0.0.0.0', port=config.RPC_SERVER_PORT, handler=BlockstackdRPCHandler, testset=False):
        self.testset = testset
        log.info("Listening on %s:%s" % (host, port))
        SimpleXMLRPCServer.__init__( self, (host, port), handler, allow_none=True )

        # register methods 
        for attr in dir(self):
            if attr.startswith("rpc_"):
                method = getattr(self, attr)
                if callable(method) or hasattr(method, '__call__'):
                    self.register_function( method )


    def rpc_ping(self):
        reply = {}
        reply['status'] = "alive"
        return reply

    def rpc_get_name_blockchain_record(self, name):
        """
        Lookup the blockchain-derived profile for a name.
        """

        db = get_state_engine()

        try:
            name = str(name)
        except Exception as e:
            return {"error": str(e)}

        name_record = db.get_name(str(name))

        if name_record is None:
            if is_indexing():
                return {"error": "Indexing blockchain"}
            else:
                return {"error": "Not found."}

        else:
            return name_record

    def rpc_get_name_blockchain_history( self, name, start_block, end_block ):
        """
        Get the sequence of name operations processed for a given name.
        """
        db = get_state_engine()
        name_history = db.get_name_history( name, start_block, end_block )

        if name_history is None:
            if is_indexing():
                return {"error": "Indexing blockchain"}
            else:
                return {"error": "Not found."}

        else:
            return name_history


    def rpc_get_nameops_at( self, block_id ):
        """
        Get the sequence of names and namespaces altered at the given block.
        Returns the list of name operations to be fed into virtualchain.
        Used by SNV clients.
        """
        db = get_state_engine()

        all_ops = db.get_all_nameops_at( block_id )
        ret = []
        for op in all_ops:
            restored_op = nameop_restore_consensus_fields( op, block_id )
            ret.append( restored_op )

        return ret


    def rpc_get_nameops_hash_at( self, block_id ):
        """
        Get the hash over the sequence of names and namespaces altered at the given block.
        Used by SNV clients.
        """
        db = get_state_engine()

        ops = db.get_all_nameops_at( block_id )
        if ops is None:
            ops = []

        restored_ops = []
        for op in ops:
            restored_op = nameop_restore_consensus_fields( op, block_id )
            restored_ops.append( restored_op )

        # NOTE: extracts only the operation-given fields, and ignores ancilliary record fields
        serialized_ops = [ virtualchain.StateEngine.serialize_op( str(op['op'][0]), op, BlockstackDB.make_opfields(), verbose=False ) for op in restored_ops ]

        for serialized_op in serialized_ops:
            log.debug("SERIALIZED (%s): %s" % (block_id, serialized_op))

        ops_hash = virtualchain.StateEngine.make_ops_snapshot( serialized_ops )
        log.debug("Serialized hash at (%s): %s" % (block_id, ops_hash))

        return ops_hash


    def rpc_getinfo(self):
        """
        Get the number of blocks the
        """
        bitcoind_opts = default_bitcoind_opts( virtualchain.get_config_filename() )
        bitcoind = get_bitcoind( new_bitcoind_opts=bitcoind_opts, new=True )

        info = bitcoind.getinfo()
        reply = {}
        reply['bitcoind_blocks'] = info['blocks']       # legacy
        reply['blockchain_blocks'] = info['blocks']
        
        db = get_state_engine()
        reply['consensus'] = db.get_current_consensus()
        reply['blocks'] = db.get_current_block()
        reply['blockstack_version'] = "%s" % VERSION
        reply['testset'] = str(self.testset)
        reply['last_block'] = reply['blocks']
        return reply


    def rpc_get_names_owned_by_address(self, address):
        """
        Get the list of names owned by an address.
        Valid only for names with p2pkh sender scripts.
        """
        db = get_state_engine()
        names = db.get_names_owned_by_address( address )
        if names is None:
            names = []
        return names


    def rpc_preorder( self, name, privatekey, register_addr ):
        """
        Preorder a name:
        @name is the name to preorder
        @register_addr is the address of the key pair that will own the name
        @privatekey is the private key that will send the preorder transaction
        (it must be *different* from the register_addr keypair)

        Returns a JSON object with the transaction ID on success.
        Returns a JSON object with 'error' on error.
        """
        return blockstack_name_preorder( str(name), str(privatekey), str(register_addr), testset=self.testset )


    def rpc_preorder_tx( self, name, privatekey, register_addr ):
        """
        Generate a transaction that preorders a name:
        @name is the name to preorder
        @register_addr is the address of the key pair that will own the name
        @privatekey is the private key that will send the preorder transaction
        (it must be *different* from the register_addr keypair)

        Return a JSON object with the signed serialized transaction on success.  It will not be broadcast.
        Return a JSON object with 'error' on error.
        """
        return blockstack_name_preorder( str(name), str(privatekey), str(register_addr), tx_only=True, testset=self.testset )


    def rpc_preorder_tx_subsidized( self, name, register_addr, subsidy_key ):
        """
        Generate a transaction that preorders a name, but without paying fees.
        @name is the name to preorder
        @register_addr is the address of the key pair that will own the name
        (it must be *different* from the register_addr keypair)

        Return a JSON object with the signed serialized transaction on success.  It will not be broadcast.
        Return a JSON object with 'error' on error.
        """
        return blockstack_name_preorder( str(name), None, str(register_addr), tx_only=True, subsidy_key=str(subsidy_key), testset=self.testset )


    def rpc_register( self, name, privatekey, register_addr ):
        """
        Register a name:
        @name is the name to register
        @register_addr is the address of the key pair that will own the name
        (given earlier in the preorder)
        @privatekey is the private key that sent the preorder transaction.

        Returns a JSON object with the transaction ID on success.
        Returns a JSON object with 'error' on error.
        """
        return blockstack_name_register( str(name), str(privatekey), str(register_addr), testset=self.testset )


    def rpc_register_tx( self, name, privatekey, register_addr ):
        """
        Generate a transaction that will register a name:
        @name is the name to register
        @register_addr is the address of the key pair that will own the name
        (given earlier in the preorder)
        @privatekey is the private key that sent the preorder transaction.

        Return a JSON object with the signed serialized transaction on success.  It will not be broadcast.
        Return a JSON object with 'error' on error.
        """
        return blockstack_name_register( str(name), str(privatekey), str(register_addr), tx_only=True, testset=self.testset )


    def rpc_register_tx_subsidized( self, name, user_public_key, register_addr, subsidy_key ):
        """
        Generate a subsidizable transaction that will register a name
        @name is the name to register
        @register_addr is the address of the key pair that will own the name
        (given earlier in the preorder)
        @user_public_key is the public key whose private counterpart sent the preorder transaction.

        Return a JSON object with the signed serialized transaction on success.  It will not be broadcast.
        Return a JSON object with 'error' on error.
        """
        return blockstack_name_register( str(name), None, str(register_addr), tx_only=True, user_public_key=str(user_public_key), subsidy_key=str(subsidy_key), testset=self.testset )


    def rpc_update( self, name, data_hash, privatekey ):
        """
        Update a name's record:
        @name is the name to update
        @data_hash is the hash of the new name record
        @privatekey is the private key that owns the name

        Returns a JSON object with the transaction ID on success.
        Returns a JSON object with 'error' on error.
        """
        return blockstack_name_update( str(name), str(data_hash), str(privatekey), testset=self.testset )


    def rpc_update_tx( self, name, data_hash, privatekey ):
        """
        Generate a transaction that will update a name's name record hash.
        @name is the name to update
        @data_hash is the hash of the new name record
        @privatekey is the private key that owns the name

        Return a JSON object with the signed serialized transaction on success.  It will not be broadcast.
        Return a JSON object with 'error' on error.
        """
        return blockstack_name_update( str(name), str(data_hash), str(privatekey), tx_only=True, testset=self.testset )


    def rpc_update_tx_subsidized( self, name, data_hash, user_public_key, subsidy_key ):
        """
        Generate a subsidizable transaction that will update a name's name record hash.
        @name is the name to update
        @data_hash is the hash of the new name record
        @privatekey is the private key that owns the name

        Return a JSON object with the signed serialized transaction on success.  It will not be broadcast.
        Return a JSON object with 'error' on error.
        """
        return blockstack_name_update( str(name), str(data_hash), None, user_public_key=str(user_public_key), subsidy_key=str(subsidy_key), tx_only=True, testset=self.testset )


    def rpc_transfer( self, name, address, keepdata, privatekey ):
        """
        Transfer a name's record to a new address
        @name is the name to transfer
        @address is the new address that will own the name
        @keepdata determines whether or not the name record will
        remain associated with the name on transfer.
        @privatekey is the private key that owns the name

        Returns a JSON object with the transaction ID on success.
        Returns a JSON object with 'error' on error.
        """

        # coerce boolean
        if type(keepdata) != bool:
            if str(keepdata) == "True":
                keepdata = True
            else:
                keepdata = False

        return blockstack_name_transfer( str(name), str(address), keepdata, str(privatekey), testset=self.testset )


    def rpc_transfer_tx( self, name, address, keepdata, privatekey ):
        """
        Generate a transaction that will transfer a name to a new address
        @name is the name to transfer
        @address is the new address that will own the name
        @keepdata determines whether or not the name record will
        remain associated with the name on transfer.
        @privatekey is the private key that owns the name

        Return a JSON object with the signed serialized transaction on success.  It will not be broadcast.
        Return a JSON object with 'error' on error.
        """

        # coerce boolean
        if type(keepdata) != bool:
            if str(keepdata) == "True":
                keepdata = True
            else:
                keepdata = False

        return blockstack_name_transfer( str(name), str(address), keepdata, str(privatekey), tx_only=True, testset=self.testset )


    def rpc_transfer_tx_subsidized( self, name, address, keepdata, user_public_key, subsidy_key ):
        """
        Generate a subsidizable transaction that will transfer a name to a new address
        @name is the name to transfer
        @address is the new address that will own the name
        @keepdata determines whether or not the name record will
        remain associated with the name on transfer.
        @privatekey is the private key that owns the name

        Return a JSON object with the signed serialized transaction on success.  It will not be broadcast.
        Return a JSON object with 'error' on error.
        """

        # coerce boolean
        if type(keepdata) != bool:
            if str(keepdata) == "True":
                keepdata = True
            else:
                keepdata = False

        return blockstack_name_transfer( str(name), str(address), keepdata, None, user_public_key=str(user_public_key), subsidy_key=str(subsidy_key), tx_only=True, testset=self.testset )


    def rpc_renew( self, name, privatekey ):
        """
        Renew a name:
        @name is the name to renew
        @privatekey is the private key that owns the name

        Returns a JSON object with the transaction ID on success.
        Returns a JSON object with 'error' on error.
        """
        return blockstack_name_renew( str(name), str(privatekey), testset=self.testset )


    def rpc_renew_tx( self, name, privatekey ):
        """
        Generate a transaction that will register a name:
        @name is the name to renew
        @privatekey is the private key that owns the name

        Return a JSON object with the signed serialized transaction on success.  It will not be broadcast.
        Return a JSON object with 'error' on error.
        """
        return blockstack_name_renew( str(name), str(privatekey), tx_only=True, testset=self.testset )


    def rpc_renew_tx_subsidized( self, name, user_public_key, subsidy_key ):
        """
        Generate a subsidizable transaction that will register a name
        @name is the name to renew
        @privatekey is the private key that owns the name

        Return a JSON object with the signed serialized transaction on success.  It will not be broadcast.
        Return a JSON object with 'error' on error.
        """
        return blockstack_name_renew( name, None, user_public_key=str(user_public_key), subsidy_key=str(subsidy_key), tx_only=True, testset=self.testset )


    def rpc_revoke( self, name, privatekey ):
        """
        revoke a name:
        @name is the name to revoke
        @privatekey is the private key that owns the name

        Returns a JSON object with the transaction ID on success.
        Returns a JSON object with 'error' on error.
        """
        return blockstack_name_revoke( str(name), str(privatekey), testset=self.testset )


    def rpc_revoke_tx( self, name, privatekey ):
        """
        Generate a transaction that will revoke a name:
        @name is the name to revoke
        @privatekey is the private key that owns the name

        Return a JSON object with the signed serialized transaction on success.  It will not be broadcast.
        Return a JSON object with 'error' on error.
        """
        return blockstack_name_revoke( str(name), str(privatekey), tx_only=True, testset=self.testset )


    def rpc_revoke_tx_subsidized( self, name, user_public_key, subsidy_key ):
        """
        Generate a subsidizable transaction that will revoke a name
        @name is the name to revoke
        @privatekey is the private key that owns the name
        @user_public_key is the public key of the name owner. Must be given if @subsidy_key is given.
        @subsidy_key is the key that will pay for the tx

        Return a JSON object with the signed serialized transaction on success.  It will not be broadcast.
        Return a JSON object with 'error' on error.
        """
        return blockstack_name_revoke( str(name), None, user_public_key=str(user_public_key), subsidy_key=str(subsidy_key), tx_only=True, testset=self.testset )


    def rpc_name_import( self, name, recipient_address, update_hash, privatekey ):
        """
        Import a name into a namespace.
        """
        return blockstack_name_import( name, recipient_address, update_hash, privatekey, testset=self.testset )


    def rpc_name_import_tx( self, name, recipient_address, update_hash, privatekey ):
        """
        Generate a tx that will import a name
        """
        return blockstack_name_import( name, recipient_address, update_hash, privatekey, tx_only=True, testset=self.testset )


    def rpc_namespace_preorder( self, namespace_id, reveal_addr, privatekey ):
        """
        Define the properties of a namespace.
        Between the namespace definition and the "namespace begin" operation, only the
        user who created the namespace can create names in it.
        """
        return blockstack_namespace_preorder( namespace_id, reveal_addr, privatekey, testset=self.testset )


    def rpc_namespace_preorder_tx( self, namespace_id, reveal_addr, privatekey ):
        """
        Create a signed transaction that will define the properties of a namespace.
        Between the namespace definition and the "namespace begin" operation, only the
        user who created the namespace can create names in it.
        """
        return blockstack_namespace_preorder( namespace_id, reveal_addr, privatekey, tx_only=True, testset=self.testset )


    def rpc_namespace_reveal( self, namespace_id, reveal_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, privatekey ):
        """
        Reveal and define the properties of a namespace.
        Between the namespace definition and the "namespace begin" operation, only the
        user who created the namespace can create names in it.
        """
        return blockstack_namespace_reveal( namespace_id, reveal_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, privatekey, testset=self.testset )


    def rpc_namespace_reveal_tx( self, namespace_id, reveal_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, privatekey ):
        """
        Generate a signed transaction that will reveal and define the properties of a namespace.
        Between the namespace definition and the "namespace begin" operation, only the
        user who created the namespace can create names in it.
        """
        return blockstack_namespace_reveal( namespace_id, reveal_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, privatekey, tx_only=True, testset=self.testset )


    def rpc_namespace_ready( self, namespace_id, privatekey ):
        """
        Declare that a namespace is open to accepting new names.
        """
        return blockstack_namespace_ready( namespace_id, privatekey, testset=self.testset )


    def rpc_namespace_ready_tx( self, namespace_id, privatekey ):
        """
        Create a signed transaction that will declare that a namespace is open to accepting new names.
        """
        return blockstack_namespace_ready( namespace_id, privatekey, tx_only=True, testset=self.testset )


    def rpc_announce( self, message, privatekey ):
        """
        announce a message to all blockstack nodes on the blockchain
        @message is the message to send
        @privatekey is the private key that will sign the announcement

        Returns a JSON object with the transaction ID on success.
        Returns a JSON object with 'error' on error.
        """
        return blockstack_announce( str(message), str(privatekey), testset=self.testset )


    def rpc_announce_tx( self, message, privatekey ):
        """
        Generate a transaction that will make an announcement:
        @message is the message text to send
        @privatekey is the private key that signs the message

        Return a JSON object with the signed serialized transaction on success.  It will not be broadcast.
        Return a JSON object with 'error' on error.
        """
        return blockstack_announce( str(message), str(privatekey), tx_only=True, testset=self.testset )


    def rpc_announce_tx_subsidized( self, message, public_key, subsidy_key ):
        """
        Generate a subsidizable transaction that will make an announcement
        @message is hte message text to send
        @privatekey is the private key that signs the message

        Return a JSON object with the signed serialized transaction on success.  It will not be broadcast.
        Return a JSON object with 'error' on error.
        """
        return blockstack_announce( str(message), None, user_public_key=str(user_public_key), subsidy_key=str(subsidy_key), tx_only=True, testset=self.testset )


    def rpc_get_name_cost( self, name ):
        """
        Return the cost of a given name, including fees
        Return value is in satoshis
        """

        # are we doing our initial indexing?

        if len(name) > LENGTHS['blockchain_id_name']:
            return {"error": "Name too long"}

        ret = get_name_cost( name )
        if ret is None:
            if is_indexing():
               return {"error": "Indexing blockchain"}

            else:
               return {"error": "Unknown/invalid namespace"}

        return {"satoshis": int(math.ceil(ret))}


    def rpc_get_namespace_cost( self, namespace_id ):
        """
        Return the cost of a given namespace, including fees.
        Return value is in satoshis
        """

        if len(namespace_id) > LENGTHS['blockchain_id_namespace_id']:
            return {"error": "Namespace ID too long"}

        ret = price_namespace(namespace_id)
        return {"satoshis": int(math.ceil(ret))}


    def rpc_get_namespace_blockchain_record( self, namespace_id ):
        """
        Return the readied namespace with the given namespace_id
        """

        db = get_state_engine()
        ns = db.get_namespace( namespace_id )
        if ns is None:
            if is_indexing():
                return {"error": "Indexing blockchain"}
            else:
                return {"error": "No such ready namespace"}
        else:
            return ns


    def rpc_get_all_names( self, offset, count ):
        """
        Return all names
        """
        # are we doing our initial indexing?
        if is_indexing():
            return {"error": "Indexing blockchain"}

        db = get_state_engine()
        return db.get_all_names( offset=offset, count=count )


    def rpc_get_names_in_namespace( self, namespace_id, offset, count ):
        """
        Return all names in a namespace
        """
        # are we doing our initial indexing?
        if is_indexing():
            return {"error": "Indexing blockchain"}

        db = get_state_engine()
        return db.get_names_in_namespace( namespace_id, offset=offset, count=count )


    def rpc_get_consensus_at( self, block_id ):
        """
        Return the consensus hash at a block number
        """
        db = get_state_engine()
        return db.get_consensus_at( block_id )


    def rpc_get_mutable_data( self, blockchain_id, data_name ):
        """
        Get a mutable data record written by a given user.
        """
        client = get_blockstack_client_session()
        return client.get_mutable( str(blockchain_id), str(data_name) )


    def rpc_get_immutable_data( self, blockchain_id, data_hash ):
        """
        Get immutable data record written by a given user.
        """
        client = get_blockstack_client_session()
        return client.get_immutable( str(blockchain_id), str(data_hash) )


    def rpc_get_block_from_consensus( self, consensus_hash ):
        """
        Given the consensus hash, find the block number (or None)
        """
        db = get_db_state()
        return db.get_block_from_consensus( consensus_hash )


    def rpc_get_zonefiles( self, zonefile_hashes ):
        """
        Get a user's zonefile from the local cache,
        or (on miss), from upstream storage.
        Only return at most 100 zonefiles.
        Return {'status': True, 'zonefiles': [zonefiles]} on success
        Return {'error': ...} on error
        """
        config = get_blockstack_opts()
        if not config['serve_zonefiles']:
            return {'error': 'No data'}

        if len(zonefile_hashes) > 100:
            return {'error': 'Too many requests'}

        ret = {}
        for zonefile_hash in zonefile_hashes:
            if not is_current_zonefile_hash( zonefile_hash ):
                continue

            # check cache 
            cached_zonefile = get_cached_zonefile( zonefile_hash, zonefile_dir=config.get('zonefiles', None))
            if cached_zonefile is not None:
                ret[zonefile_hash] = cached_zonefile
                continue

            log.debug("Zonefile %s is not cached" % zonefile_hash)

            try:
                # check storage providers
                zonefile = get_zonefile_from_storage( zonefile_hash )
            except Exception, e:
                log.exception(e)
                continue

            if zonefile is not None:
                store_cached_zonefile( zonefile )
                ret[zonefile_hash] = zonefile

        return {'status': True, 'zonefiles': ret}


    def rpc_put_zonefiles( self, zonefile_datas ):
        """
        Replicate one or more zonefiles
        Returns {'status': True, 'saved': [0|1]'} on success ('saved' is a vector of success/failure)
        Returns {'error': ...} on error
        Takes at most 10 zonefiles
        """

        config = get_blockstack_opts()
        if not config['serve_zonefiles']:
            return {'error': 'No data'}

        if len(zonefile_datas) > 100:
            return {'error': 'Too many zonefiles'}

        if blockstack_client is None:
            return {'error': 'No storage support'}

        saved = []

        for zonefile_data in zonefile_datas:

            try: 
                zonefile_hash = blockstack_client.hash_zonefile( zonefile_data )
            except:
                log.debug("Invalid zonefile")
                saved.append(0)
                continue

            if not is_current_zonefile_hash( zonefile_hash ):
                log.debug("Unknown zonefile hash %s" % zonefile_hash)
                saved.append(0)
                continue

            # it's a valid zonefile.  cache and store it.
            rc = store_cached_zonefile( zonefile_data )
            if not rc:
                log.debug("Failed to store zonefile %s" % zonefile_hash)
                saved.append(0)
                continue

            rc = store_zonefile_to_storage( zonefile_data )
            if not rc:
                log.debug("Failed to replicate zonefile %s to external storage" % zonefile_hash)
                saved.append(0)
                continue

            saved.append(1)

        return {'status': True, 'saved': saved}

    
    def rpc_get_unspents(self, address):
        """
        Proxy to UTXO provider to get an address's
        unspent outputs.
        """
        conf = get_blockstack_opts()
        if not conf['blockchain_proxy']:
            return {'error': 'No such method'}

        utxo_client = get_utxo_provider_client()
        return pybitcoin.get_unspents( address, utxo_client )


    def rpc_broadcast_transaction(self, txdata ):
        """
        Proxy to UTXO provider to send a transaction
        """
        conf = get_blockstack_opts()
        if not conf['blockchain_proxy']:
            return {'error': 'No such method'}

        broadcaster = get_tx_broadcaster()
        return pybitcoin.broadcast_transaction( txdata, broadcaster )



class BlockstackdRPCServer( threading.Thread, object ):
    """
    RPC server thread
    """
    def __init__(self, port, testset=False):
        super( BlockstackdRPCServer, self ).__init__()
        self.testset = testset
        self.rpc_server = None
        self.port = port


    def run(self):
        """
        Serve until asked to stop
        """
        self.rpc_server = BlockstackdRPC( port=self.port, testset=self.testset )
        self.rpc_server.serve_forever()


    def stop_server(self):
        """
        Stop serving.  Also stops the thread.
        """
        self.rpc_server.shutdown()
     

def rpc_start( port, testset=False ):
    """
    Start the global RPC server thread
    """
    global rpc_server
    rpc_server = BlockstackdRPCServer( port, testset=testset )

    log.debug("Starting RPC")
    rpc_server.start()


def rpc_stop():
    """
    Stop the global RPC server thread
    """
    global rpc_server
    if rpc_server is not None:
        log.debug("Shutting down RPC")
        rpc_server.stop_server()
        rpc_server.join()
        log.debug("RPC joined")



