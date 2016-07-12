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
import blockstack_zones

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

from lib import nameset as blockstack_state_engine
from lib import get_db_state, invalidate_db_state
from lib.config import REINDEX_FREQUENCY, DEFAULT_DUST_FEE 
from lib import *
from lib.storage import *

import lib.nameset.virtualchain_hooks as virtualchain_hooks
import lib.config as config

# global variables, for use with the RPC server
blockstack_opts = None
bitcoind = None
bitcoin_opts = None
utxo_client = None
tx_broadcaster = None
rpc_server = None

def get_bitcoind( new_bitcoind_opts=None, reset=False, new=False ):
   """
   Get or instantiate our bitcoind client.
   Optionally re-set the bitcoind options.
   """
   global bitcoind
   global bitcoin_opts

   if reset:
       bitcoind = None

   elif not new and bitcoind is not None:
      return bitcoind

   if new or bitcoind is None:
      if new_bitcoind_opts is not None:
         bitcoin_opts = new_bitcoind_opts

      new_bitcoind = None
      try:
         if bitcoin_opts.has_key('bitcoind_mock') and bitcoin_opts['bitcoind_mock']:
            # make a mock connection
            log.debug("Use mock bitcoind")
            import blockstack_integration_tests.mock_bitcoind
            new_bitcoind = blockstack_integration_tests.mock_bitcoind.connect_mock_bitcoind( bitcoin_opts, reset=reset )

         else:
            try:
                new_bitcoind = virtualchain.connect_bitcoind( bitcoin_opts )
            except KeyError, ke:
                log.exception(ke)
                log.error("Invalid configuration: %s" % bitcoin_opts)
                return None

         if new:
             return new_bitcoind

         else:
             # save for subsequent reuse
             bitcoind = new_bitcoind
             return bitcoind

      except Exception, e:
         log.exception( e )
         return None


def get_bitcoin_opts():
   """
   Get the bitcoind connection arguments.
   """

   global bitcoin_opts
   return bitcoin_opts


def get_blockstack_opts():
   """
   Get blockstack configuration options.
   """
   global blockstack_opts
   return blockstack_opts


def set_bitcoin_opts( new_bitcoin_opts ):
   """
   Set new global bitcoind operations
   """
   global bitcoin_opts
   bitcoin_opts = new_bitcoin_opts


def set_blockstack_opts( new_opts ):
    """
    Set new global blockstack opts
    """
    global blockstack_opts
    blockstack_opts = new_opts
    

def get_pidfile_path():
   """
   Get the PID file path.
   """
   working_dir = virtualchain.get_working_dir()
   pid_filename = blockstack_state_engine.get_virtual_chain_name() + ".pid"
   return os.path.join( working_dir, pid_filename )


def put_pidfile( pidfile_path, pid ):
    """
    Put a PID into a pidfile
    """
    with open( pidfile_path, "w" ) as f:
        f.write("%s" % pid)

    return 


def get_logfile_path():
   """
   Get the logfile path for our service endpoint.
   """
   working_dir = virtualchain.get_working_dir()
   logfile_filename = blockstack_state_engine.get_virtual_chain_name() + ".log"
   return os.path.join( working_dir, logfile_filename )


def get_state_engine():
   """
   Get a handle to the blockstack virtual chain state engine.
   """
   return get_db_state()
     

def get_lastblock():
    """
    Get the last block processed.
    """
    lastblock_filename = virtualchain.get_lastblock_filename()
    if not os.path.exists( lastblock_filename ):
        return None

    try:
        with open(lastblock_filename, "r") as f:
           lastblock_txt = f.read()

        lastblock = int(lastblock_txt.strip())
        return lastblock
    except:
        return None


def get_index_range():
    """
    Get the bitcoin block index range.
    Mask connection failures with timeouts.
    Always try to reconnect.

    The last block will be the last block to search for names.
    This will be NUM_CONFIRMATIONS behind the actual last-block the
    cryptocurrency node knows about.
    """

    bitcoind_session = get_bitcoind( new=True )
    assert bitcoind_session is not None

    first_block = None
    last_block = None
    while last_block is None:

        first_block, last_block = virtualchain.get_index_range( bitcoind_session )

        if last_block is None:

            # try to reconnnect
            time.sleep(1)
            log.error("Reconnect to bitcoind")
            bitcoind_session = get_bitcoind( new=True )
            continue

        else:
            return first_block, last_block - NUM_CONFIRMATIONS


def rpc_traceback():
    exception_data = traceback.format_exc().splitlines()
    return {
        "error": exception_data[-1],
        "traceback": exception_data
    }



def get_name_cost( name ):
    """
    Get the cost of a name, given the fully-qualified name.
    Do so by finding the namespace it belongs to (even if the namespace is being imported).
    Return None if the namespace has not been declared
    """
    db = get_state_engine()

    namespace_id = get_namespace_from_name( name )
    if namespace_id is None or len(namespace_id) == 0:
        log.debug("No namespace '%s'" % namespace_id)
        return None

    namespace = db.get_namespace( namespace_id )
    if namespace is None:
        # maybe importing?
        log.debug("Revealing namespace '%s'" % namespace_id)
        namespace = db.get_namespace_reveal( namespace_id )

    if namespace is None:
        # no such namespace
        log.debug("No namespace '%s'" % namespace_id)
        return None

    name_fee = price_name( get_name_from_fq_name( name ), namespace )
    return name_fee


class BlockstackdRPCHandler(SimpleXMLRPCRequestHandler):
    """
    Hander to capture tracebacks
    """
    def _dispatch(self, method, params):
        try: 
            log.debug("%s(%s)" % ("rpc_" + str(method), params))
            res = self.server.funcs["rpc_" + str(method)](*params)

            # lol jsonrpc within xmlrpc
            ret = json.dumps(res)
            return ret
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

    def __init__(self, host='0.0.0.0', port=config.RPC_SERVER_PORT, handler=BlockstackdRPCHandler ):
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
        Lookup the blockchain-derived whois info for a name.
        """

        if type(name) not in [str, unicode]:
            return {'error': 'invalid name'}

        if not is_name_valid(name):
            return {'error': 'invalid name'}

        db = get_state_engine()

        try:
            name = str(name)
        except Exception as e:
            return {"error": str(e)}

        name_record = db.get_name(str(name))

        namespace_id = get_namespace_from_name(name)
        namespace_record = db.get_namespace(namespace_id)

        if name_record is None:
            if is_indexing():
                return {"error": "Indexing blockchain"}
            else:
                return {"error": "Not found."}

        else:

            # when does this name expire (if it expires)?
            if namespace_record['lifetime'] != NAMESPACE_LIFE_INFINITE:
                name_record['expire_block'] = namespace_record['lifetime'] + name_record['last_renewed']

            return name_record


    def rpc_get_name_blockchain_history( self, name, start_block, end_block ):
        """
        Get the sequence of name operations processed for a given name.
        """
        if type(name) not in [str, unicode]:
            return {'error': 'invalid name'}

        if not is_name_valid(name):
            return {'error': 'invalid name'}

        if type(start_block) not in [int, long]:
            return {'error': 'invalid start block'}

        if type(end_block) not in [int, long]:
            return {'error': 'invalid end block'}

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
        if type(block_id) not in [int, long]:
            return {'error': 'invalid block ID'}

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
        if type(block_id) not in [int, long]:
            return {'error': 'invalid block ID'}

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
        bitcoind_opts = blockstack_client.default_bitcoind_opts( virtualchain.get_config_filename(), prefix=True )
        bitcoind = get_bitcoind( new_bitcoind_opts=bitcoind_opts, new=True )
        
        if bitcoind is None:
            return {'error': 'Internal server error: failed to connect to bitcoind'}

        info = bitcoind.getinfo()
        reply = {}
        reply['bitcoind_blocks'] = info['blocks']       # legacy
        reply['blockchain_blocks'] = info['blocks']
        
        db = get_state_engine()
        reply['consensus'] = db.get_current_consensus()
        reply['blocks'] = db.get_current_block()
        reply['blockstack_version'] = "%s" % VERSION
        reply['last_block'] = reply['blocks']
        return reply


    def rpc_get_names_owned_by_address(self, address):
        """
        Get the list of names owned by an address.
        Valid only for names with p2pkh sender scripts.
        """
        if type(address) not in [str, unicode]:
            return {'error': 'invalid address'}

        db = get_state_engine()
        names = db.get_names_owned_by_address( address )
        if names is None:
            names = []
        return names


    def rpc_get_name_cost( self, name ):
        """
        Return the cost of a given name, including fees
        Return value is in satoshis
        """

        if type(name) not in [str, unicode]:
            return {'error': 'invalid name'}

        if not is_name_valid(name):
            return {'error': 'invalid name'}

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

        if type(namespace_id) not in [str, unicode]:
            return {'error': 'invalid namespace ID'}

        if not is_namespace_valid(namespace_id):
            return {'error': 'invalid namespace ID'}

        ret = price_namespace(namespace_id)
        return {"satoshis": int(math.ceil(ret))}


    def rpc_get_namespace_blockchain_record( self, namespace_id ):
        """
        Return the namespace with the given namespace_id
        """

        if type(namespace_id) not in [str, unicode]:
            return {'error': 'invalid namespace ID'}

        if not is_namespace_valid(namespace_id):
            return {'error': 'invalid namespace ID'}

        db = get_state_engine()
        ns = db.get_namespace( namespace_id )
        if ns is None:
            # maybe revealed?
            ns = db.get_namespace_reveal( namespace_id )
            if ns is None:
                if is_indexing():
                    return {"error": "Indexing blockchain"}
                else:
                    return {"error": "No such namespace"}

            ns['ready'] = False
            return ns

        else:
            ns['ready'] = True
            return ns


    def rpc_get_all_names( self, offset, count ):
        """
        Return all names
        """
        if type(offset) not in [int, long]:
            return {'error': 'invalid offset'}

        if type(count) not in [int, long]:
            return {'error': 'invalid count'}

        # are we doing our initial indexing?
        if is_indexing():
            return {"error": "Indexing blockchain"}

        db = get_state_engine()
        return db.get_all_names( offset=offset, count=count )


    def rpc_get_names_in_namespace( self, namespace_id, offset, count ):
        """
        Return all names in a namespace
        """
        if type(namespace_id) not in [str, unicode]:
            return {'error': 'invalid namespace ID'}
    
        if type(offset) not in [int, long]:
            return {'error': 'invalid offset'}

        if type(count) not in [int, long]:
            return {'error': 'invalid count'}

        if not is_namespace_valid( namespace_id ):
            return {'error': 'invalid namespace ID'}

        # are we doing our initial indexing?
        if is_indexing():
            return {"error": "Indexing blockchain"}

        db = get_state_engine()
        return db.get_names_in_namespace( namespace_id, offset=offset, count=count )


    def rpc_get_consensus_at( self, block_id ):
        """
        Return the consensus hash at a block number
        """
        if type(block_id) not in [int, long]:
            return {'error': 'Invalid block ID'}

        if is_indexing():
            return {'error': 'Indexing blockchain'}

        db = get_state_engine()
        return db.get_consensus_at( block_id )


    def rpc_get_consensus_hashes( self, block_id_list ):
        """
        Return the consensus hashes at multiple block numbers
        Return a dict mapping each block ID to its consensus hash
        """
        if is_indexing():
            return {'error': 'Indexing blockchain'}

        if type(block_id_list) != list:
            return {'error': 'Invalid block IDs'}

        for bid in block_id_list:
            if type(bid) not in [int, long]:
                return {'error': 'Invalid block ID'}

        db = get_state_engine()
        ret = {}
        for block_id in block_id_list:
            ret[block_id] = db.get_consensus_at(block_id)

        return ret


    def rpc_get_mutable_data( self, blockchain_id, data_name ):
        """
        Get a mutable data record written by a given user.
        """
        if type(blockchain_id) not in [str, unicode]:
            return {'error': 'Invalid blockchain ID'}

        if not is_name_valid(blockchain_id):
            return {'error': 'Invalid blockchain ID'}

        if type(data_name) not in [str, unicode]:
            return {'error': 'Invalid data name'}

        client = get_blockstack_client_session()
        return client.get_mutable( str(blockchain_id), str(data_name) )


    def rpc_get_immutable_data( self, blockchain_id, data_hash ):
        """
        Get immutable data record written by a given user.
        """
        if type(blockchain_id) not in [str, unicode]:
            return {'error': 'Invalid blockchain ID'}

        if not is_name_valid(blockchain_id):
            return {'error': 'Invalid blockchain ID'}

        if type(data_hash) not in [str, unicode]:
            return {'error': 'Invalid data hash'}

        client = get_blockstack_client_session()
        return client.get_immutable( str(blockchain_id), str(data_hash) )


    def rpc_get_block_from_consensus( self, consensus_hash ):
        """
        Given the consensus hash, find the block number (or None)
        """
        if type(consensus_hash) not in [str, unicode]:
            return {'error': 'Not a valid consensus hash'}

        db = get_state_engine()
        return db.get_block_from_consensus( consensus_hash )


    def get_zonefile( self, config, zonefile_hash, zonefile_storage_drivers ):
        """
        Get a zonefile by hash, caching it along the way.
        Return the zonefile (as a dict) on success
        Return None on error
        """
    
        # check cache 
        cached_zonefile = get_cached_zonefile( zonefile_hash, zonefile_dir=config.get('zonefiles', None))
        if cached_zonefile is not None:
            return cached_zonefile

        log.debug("Zonefile %s is not cached" % zonefile_hash)

        try:
            # check storage providers
            zonefile = get_zonefile_from_storage( zonefile_hash, drivers=zonefile_storage_drivers )
        except blockstack_zones.InvalidLineException:
            # legacy profile
            return None
        except Exception, e:
            log.exception(e)
            return None

        if zonefile is not None:
            store_cached_zonefile( zonefile )
            return zonefile
        else:
            return None


    def get_zonefile_by_name( self, conf, name, zonefile_storage_drivers ):
        """
        Get a zonefile by name
        Return the zonefile (as a dict) on success
        Return None one error
        """
        db = get_state_engine()
        name_rec = db.get_name( name )
        if name_rec is None:
            return None

        zonefile_hash = name_rec.get('value_hash', None)
        if zonefile_hash is None:
            return None

        # find zonefile 
        zonefile = self.get_zonefile( conf, zonefile_hash, zonefile_storage_drivers )
        if zonefile is None:
            return None

        return zonefile


    def rpc_get_zonefiles( self, zonefile_hashes ):
        """
        Get a users zonefiles from the local cache,
        or (on miss), from upstream storage.
        Only return at most 100 zonefiles.
        Return {'status': True, 'zonefiles': {zonefile_hash: zonefile}} on success
        Return {'error': ...} on error

        zonefiles will be serialized to string
        """
        conf = get_blockstack_opts()
        if not conf['serve_zonefiles']:
            return {'error': 'No data'}

        if type(zonefile_hashes) != list:
            return {'error': 'Invalid zonefile hashes'}

        if len(zonefile_hashes) > 100:
            return {'error': 'Too many requests'}

        zonefile_storage_drivers = conf['zonefile_storage_drivers'].split(",")

        ret = {}
        for zonefile_hash in zonefile_hashes:
            if type(zonefile_hash) not in [str, unicode]:
                return {'error': 'Not a zonefile hash'}

        for zonefile_hash in zonefile_hashes:
            if not is_current_zonefile_hash( zonefile_hash ):
                continue

            zonefile = self.get_zonefile( conf, zonefile_hash, zonefile_storage_drivers )
            if zonefile is None:
                continue

            else:
                ret[zonefile_hash] = serialize_zonefile( zonefile )

        return {'status': True, 'zonefiles': ret}


    def rpc_get_zonefiles_by_names( self, names ):
        """
        Get a users' zonefiles from the local cache,
        or (on miss), from upstream storage.
        Only return at most 100 zonefiles.
        Return {'status': True, 'zonefiles': {name: zonefile}]} on success
        Return {'error': ...} on error

        zonefiles will be serialized to string
        """
        conf = get_blockstack_opts()
        if not conf['serve_zonefiles']:
            return {'error': 'No data'}

        if type(names) != list:
            return {'error': 'Invalid data'}

        if len(names) > 100:
            return {'error': 'Too many requests'}
        
        zonefile_storage_drivers = conf['zonefile_storage_drivers'].split(",")

        ret = {}
        for name in names:
            if type(name) not in [str, unicode]:
                return {'error': 'Invalid name'}

            if not is_name_valid(name):
                return {'error': 'Invalid name'}

        for name in names:
            zonefile = self.get_zonefile_by_name( conf, name, zonefile_storage_drivers )
            if zonefile is None:
                continue

            else:
                ret[name] = serialize_zonefile( zonefile )

        return {'status': True, 'zonefiles': ret}


    def rpc_put_zonefiles( self, zonefile_datas ):
        """
        Replicate one or more zonefiles, given as serialized strings.
        Returns {'status': True, 'saved': [0|1]'} on success ('saved' is a vector of success/failure)
        Returns {'error': ...} on error
        Takes at most 10 zonefiles
        """

        conf = get_blockstack_opts()

        if not conf['serve_zonefiles']:
            return {'error': 'No data'}

        if type(zonefile_datas) != list:
            return {'error': 'Invalid data'}

        if len(zonefile_datas) > 100:
            return {'error': 'Too many zonefiles'}

        saved = []
        db = get_state_engine()
        zonefile_storage_drivers = conf['zonefile_storage_drivers'].split(",")

        for zonefile_data in zonefile_datas:
          
            if type(zonefile_data) not in [str,unicode]:
                log.debug("Invalid non-text zonefile")
                saved.append(0)
                continue

            if len(zonefile_data) > RPC_MAX_ZONEFILE_LEN:
                log.debug("Zonefile too long")
                saved.append(0)
                continue

            try: 
                zonefile = blockstack_zones.parse_zone_file( str(zonefile_data) )
                zonefile_hash = blockstack_client.get_zonefile_data_hash( str(zonefile_data) )
            except Exception, e:
                log.exception(e)
                log.debug("Invalid zonefile")
                saved.append(0)
                continue

            name_rec = db.get_name( zonefile['$origin'] )
            if str(name_rec['value_hash']) != zonefile_hash:
                log.debug("Unknown zonefile hash %s" % zonefile_hash)
                saved.append(0)
                continue

            # it's a valid zonefile.  cache and store it.
            rc = store_cached_zonefile( zonefile )
            if not rc:
                log.debug("Failed to store zonefile %s" % zonefile_hash)
                saved.append(0)
                continue

            rc = store_zonefile_to_storage( zonefile, required=zonefile_storage_drivers )
            if not rc:
                log.debug("Failed to replicate zonefile %s to external storage" % zonefile_hash)
                saved.append(0)
                continue

            saved.append(1)

        log.debug("Saved %s zonefile(s)\n", sum(saved))
        return {'status': True, 'saved': saved}


    def rpc_get_profile(self, name):
        """
        Get a profile for a particular name
        """
        if type(name) not in [str, unicode]:
            return {'error': 'Invalid name'}

        if not is_name_valid(name):
            return {'error': 'Invalid name'}

        conf = get_blockstack_opts()
        if not conf['serve_profiles']:
            return {'error': 'No data'}

        zonefile_storage_drivers = conf['zonefile_storage_drivers'].split(",")
        profile_storage_drivers = conf['profile_storage_drivers'].split(",")

        # find the name record 
        db = get_state_engine()
        name_rec = db.get_name(name)
        if name_rec is None:
            return {'error': 'No such name'}

        # find zonefile 
        zonefile_dict = self.get_zonefile_by_name( conf, name, zonefile_storage_drivers )
        if zonefile_dict is None:
            return {'error': 'No zonefile'}

        # find the profile
        try:
            # NOTE: since we did not generate this zonefile (i.e. it's untrusted input, and we may be using different storage drivers),
            # don't trust its URLs.  Auto-generate them using our designated drivers instead.
            # Also, do not attempt to decode the profile.  The client will do this instead (avoid any decode-related attack vectors)
            profile, zonefile = blockstack_client.get_name_profile(name, profile_storage_drivers=profile_storage_drivers, zonefile_storage_drivers=zonefile_storage_drivers,
                                                                   user_zonefile=zonefile_dict, name_record=name_rec, use_zonefile_urls=False, decode_profile=False)
        except Exception, e:
            log.exception(e)
            log.debug("Failed to load profile for '%s'" % name)
            return {'error': 'Failed to load profile'}

        if 'error' in zonefile:
            return zonefile
        
        else:
            return {'status': True, 'profile': profile}


    def rpc_put_profile(self, name, profile_txt, prev_profile_hash, sigb64 ):
        """
        Store a profile for a particular name
        @profile_txt must be a serialized JWT signed by the key in the user's zonefile.
        @prev_profile_hash must be the hex string representation of the hash of the previous profile
        @sig must cover prev_profile_hash+profile_txt
        """

        if type(name) not in [str, unicode]:
            return {'error': 'Invalid name'}

        if not is_name_valid(name):
            return {'error': 'Invalid name'}

        if type(profile_txt) not in [str, unicode]:
            return {'error': 'Profile must be a serialized JWT'}

        if len(profile_txt) > RPC_MAX_PROFILE_LEN:
            return {'error': 'Serialized profile is too big'}

        conf = get_blockstack_opts()
        if not conf['serve_profiles']:
            return {'error': 'No data'}

        profile_storage_drivers = conf['profile_storage_drivers'].split(",")
        zonefile_storage_drivers = conf['zonefile_storage_drivers'].split(",")

        # find name record 
        db = get_db_state()
        name_rec = db.get_name(name)
        if name_rec is None:
            return {'error': 'No such name'}

        # find zonefile 
        zonefile_dict = self.get_zonefile_by_name( conf, name, zonefile_storage_drivers )
        if zonefile_dict is None:
            return {'error': 'No zonefile'}

        # first, try to verify with zonefile public key (if one is given)
        user_data_pubkey = blockstack_client.user_zonefile_data_pubkey( zonefile_dict )
        if user_data_pubkey is not None:
            try:
                user_profile = blockstack_client.parse_signed_data( profile_txt, user_data_pubkey )
            except Exception, e:
                log.exception(e)
                return {'error': 'Failed to authenticate profile'}
        
        else:
            log.warn("Falling back to verifying with owner address")
            db = get_state_engine()
            name_rec = db.get_name( name )
            if name_rec is None:
                return {'error': 'No such name'}

            owner_addr = name_rec.get('address', None)
            if owner_addr is None:
                return {'error': 'No owner address'}

            try:
                user_profile = blockstack_client.parse_signed_data( profile_txt, None, public_key_hash=owner_addr )
            except Exception, e:
                log.exception(e)
                return {'error': 'Failed to authenticate profile'}

        # authentic!
        # next, verify that the previous profile actually does have this hash 
        try:
            old_profile_txt, zonefile = blockstack_client.get_name_profile(name, profile_storage_drivers=profile_storage_drivers, zonefile_storage_drivers=zonefile_storage_drivers,
                                                                           user_zonefile=zonefile_dict, name_record=name_rec, use_zonefile_urls=False, decode_profile=False)
        except Exception, e:
            log.exception(e)
            log.debug("Failed to load profile for '%s'" % name)
            return {'error': 'Failed to load profile'}

        old_profile_hash = pybitcoin.hex_hash160(old_profile_txt)
        if old_profile_hash != prev_profile_hash:
            return {'error': 'Invalid previous profile hash'}

        # which public key?
        data_pubkey = blockstack_client.user.user_zonefile_data_pubkey( zonefile )
        if data_pubkey is None:
            # fall back to owner pubkey from profile
            try:
                profile_jwt = json.loads(old_profile_txt)
                if type(profile_jwt) == list:
                    profile_jwt = profile_jwt[0]

                assert type(profile_jwt) == dict
                assert 'parentPublicKey' in profile_jwt.keys()

                data_pubkey = profile_jwt['parentPublicKey']
            except:
                return {'error': 'Could not determine user data public key'}

        # finally, verify the signature over the previous profile hash and this new profile
        rc = blockstack_client.storage.verify_raw_data( "%s%s" % (prev_profile_hash, profile_txt), data_pubkey, sigb64 )
        if not rc:
            return {'error': 'Invalid signature'}

        # success!  store it
        successes = 0
        for handler in blockstack_client.get_storage_handlers():
            try:
                rc = handler.put_mutable_handler( name, profile_txt, required=profile_storage_drivers )
            except Exception, e:
                log.exception(e)
                log.error("Failed to store profile with '%s'" % handler.__name__)
                continue

            if not rc:
                log.error("Failed to use handler '%s' to store profile for '%s'" % (handler.__name__, name))
                continue
            else:
                log.debug("Stored profile for '%s' with '%s'" % (name, handler.__name__))

            successes += 1

        if successes == 0:
            return {'error': 'Failed to replicate profile'}
        else:
            log.debug("Stored profile from '%s'" % name)
            return {'status': True, 'num_replicas': successes, 'num_failures': len(blockstack_client.get_storage_handlers()) - successes}

    
    def rpc_get_unspents(self, address):
        """
        Proxy to UTXO provider to get an address's
        unspent outputs.
        ONLY USE FOR TESTING
        """
        global utxo_client

        if type(address) not in [int, long]:
            return {'error': 'invalid address'}

        conf = get_blockstack_opts()
        if not conf['blockchain_proxy']:
            return {'error': 'No such method'}

        if utxo_client is None:
            utxo_client = blockstack_client.get_utxo_provider_client()

        unspents = pybitcoin.get_unspents( address, utxo_client )
        return unspents


    def rpc_broadcast_transaction(self, txdata ):
        """
        Proxy to UTXO provider to send a transaction
        ONLY USE FOR TESTING
        """
        global utxo_client 

        if type(txdata) not in [str, unicode]:
            return {'error': 'invalid transaction'}

        conf = get_blockstack_opts()
        if not conf['blockchain_proxy']:
            return {'error': 'No such method'}

        if utxo_client is None:
            utxo_client = blockstack_client.get_utxo_provider_client()

        return pybitcoin.broadcast_transaction( txdata, utxo_client )


    def rpc_get_analytics_key(self, client_uuid ):
        """
        Get the analytics key
        """

        if type(client_uuid) not in [str, unicode]:
            return {'error': 'invalid uuid'}

        conf = get_blockstack_opts()
        if not conf.has_key('analytics_key') or conf['analytics_key'] is None:
            return {'error': 'No analytics key'}
        
        log.debug("Give key to %s" % client_uuid)
        return {'analytics_key': conf['analytics_key']}


class BlockstackdRPCServer( threading.Thread, object ):
    """
    RPC server thread
    """
    def __init__(self, port ):
        super( BlockstackdRPCServer, self ).__init__()
        self.rpc_server = None
        self.port = port


    def run(self):
        """
        Serve until asked to stop
        """
        self.rpc_server = BlockstackdRPC( port=self.port )
        self.rpc_server.serve_forever()


    def stop_server(self):
        """
        Stop serving.  Also stops the thread.
        """
        self.rpc_server.shutdown()
     

def rpc_start( port ):
    """
    Start the global RPC server thread
    """
    global rpc_server

    # let everyone in this thread know the PID
    os.environ["BLOCKSTACK_RPC_PID"] = str(os.getpid())

    rpc_server = BlockstackdRPCServer( port )

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


def stop_server( clean=False, kill=False ):
    """
    Stop the blockstackd server.
    """

    # kill the main supervisor
    pid_file = get_pidfile_path()
    try:
        fin = open(pid_file, "r")
    except Exception, e:
        pass

    else:
        pid_data = fin.read().strip()
        fin.close()

        pid = int(pid_data)

        try:
           os.kill(pid, signal.SIGTERM)
        except OSError, oe:
           if oe.errno == errno.ESRCH:
              # already dead 
              log.info("Process %s is not running" % pid)
              try:
                  os.unlink(pid_file)
              except:
                  pass

              return

        except Exception, e:
            log.exception(e)
            sys.exit(1)

        if kill:
            clean = True
            timeout = 5.0
            log.info("Waiting %s seconds before sending SIGKILL to %s" % (timeout, pid))
            time.sleep(timeout)
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception, e:
                pass
   
    if clean:
        # always blow away the pid file 
        try:
            os.unlink(pid_file)
        except:
            pass

    
    log.debug("Blockstack server stopped")


def get_indexing_lockfile():
    """
    Return path to the indexing lockfile
    """
    return os.path.join( virtualchain.get_working_dir(), "blockstack.indexing" )


def get_bootstrap_lockfile():
    """
    Return path to the indexing lockfile
    """
    return os.path.join( virtualchain.get_working_dir(), "blockstack.bootstrapping" )


def is_indexing():
    """
    Is the blockstack daemon synchronizing with the blockchain?
    """
    indexing_path = get_indexing_lockfile()
    if os.path.exists( indexing_path ):
        return True
    else:
        return False


def set_indexing( flag ):
    """
    Set a flag in the filesystem as to whether or not we're indexing.
    """
    indexing_path = get_indexing_lockfile()
    if flag:
        try:
            fd = open( indexing_path, "w+" )
            fd.close()
            return True
        except:
            return False

    else:
        try:
            os.unlink( indexing_path )
            return True
        except:
            return False


def set_bootstrapped( flag ):
    """
    Set a flag in the filesystem as to whether or not we have sync'ed up to the latest block
    """
    bootstrap_path = get_bootstrap_lockfile()
    if flag:
        try:
            fd = open( bootstrap_path, "w+" )
            fd.close()
            return True
        except:
            return False

    else:
        try:
            os.unlink( bootstrap_path )
            return True
        except:
            return False


def is_bootstrapped():
    """
    Have we sync'ed up to the latest block?
    """
    bootstrap_path = get_bootstrap_lockfile()
    if os.path.exists(bootstrap_path):
        return True
    else:
        return False


def index_blockchain():
    """
    Index the blockchain:
    * find the range of blocks
    * synchronize our state engine up to them
    """

    bt_opts = get_bitcoin_opts() 
    start_block, current_block = get_index_range()

    if start_block is None and current_block is None:
        log.error("Failed to find block range")
        return

    # bring us up to speed
    log.debug("Begin indexing (up to %s)" % current_block)
    set_indexing( True )
    db = get_state_engine()
    virtualchain.sync_virtualchain( bt_opts, current_block, db )
    set_indexing( False )
    log.debug("End indexing (up to %s)" % current_block)

    # invalidate in-RAM copy, and reload eagerly
    invalidate_db_state()
    get_state_engine()


def blockstack_exit():
    """
    Shut down the server on exit(3)
    """
    stop_server(kill=True)


def blockstack_exit_handler( sig, frame ):
    """
    Fatal signal handler
    """
    sys.exit(0)


def run_server( foreground=False, index=True ):
    """
    Run the blockstackd RPC server, optionally in the foreground.
    """

    bt_opts = get_bitcoin_opts()
    blockstack_opts = get_blockstack_opts()
    indexer_log_file = get_logfile_path() + ".indexer"
    pid_file = get_pidfile_path()
    working_dir = virtualchain.get_working_dir()

    logfile = None
    if not foreground:
        try:
            if os.path.exists( indexer_log_file ):
                logfile = open( indexer_log_file, "a" )
            else:
                logfile = open( indexer_log_file, "a+" )
        except OSError, oe:
            log.error("Failed to open '%s': %s" % (indexer_log_file, oe.strerror))
            sys.exit(1)

        # become a daemon
        child_pid = os.fork()
        if child_pid == 0:

            # child! detach, setsid, and make a new child to be adopted by init
            sys.stdin.close()
            os.dup2( logfile.fileno(), sys.stdout.fileno() )
            os.dup2( logfile.fileno(), sys.stderr.fileno() )
            os.setsid()

            daemon_pid = os.fork()
            if daemon_pid == 0:

                # daemon!
                os.chdir("/")

            elif daemon_pid > 0:

                # parent (intermediate child)
                sys.exit(0)

            else:

                # error
                sys.exit(1)

        elif child_pid > 0:

            # grand-parent
            # wait for intermediate child
            pid, status = os.waitpid( child_pid, 0 )
            sys.exit(status)
   
    # make sure client is initialized 
    get_blockstack_client_session()

    # start API server
    rpc_start(blockstack_opts['rpc_port'])
    running = True

    # put supervisor pid file
    put_pidfile( pid_file, os.getpid() )
    atexit.register( blockstack_exit )

    if index:
        # clear any stale indexing state
        set_indexing( False )
        log.debug("Begin Indexing")

        while running:

            try:
               index_blockchain()
            except Exception, e:
               log.exception(e)
               log.error("FATAL: caught exception while indexing")
               sys.exit(1)
            
            # wait for the next block
            deadline = time.time() + REINDEX_FREQUENCY
            while time.time() < deadline:
                try:
                    time.sleep(1.0)
                except:
                    # interrupt
                    running = False
                    break
    
    else:
        log.info("Not going to index, but will idle for testing")
        while running:
            try:
                time.sleep(1.0)
            except:
                # interrupt 
                running = False
                break

    # stop API server 
    rpc_stop()

    # close logfile
    if logfile is not None:
        logfile.flush()
        logfile.close()

    return 0



def setup( working_dir=None, return_parser=False ):
   """
   Do one-time initialization.
   Call this to set up global state and set signal handlers.

   If return_parser is True, return a partially-
   setup argument parser to be populated with
   subparsers (i.e. as part of main())

   Otherwise return None.
   """

   # set up our implementation
   if working_dir is not None:
       if not os.path.exists( working_dir ):
           os.makedirs( working_dir, 0700 )

       blockstack_state_engine.working_dir = working_dir

   virtualchain.setup_virtualchain( blockstack_state_engine )

   # acquire configuration, and store it globally
   opts = configure( interactive=True )
   blockstack_opts = opts['blockstack']
   bitcoin_opts = opts['bitcoind']

   log.debug("config:\n%s" % json.dumps(opts, sort_keys=True, indent=4))

   # merge in command-line bitcoind options
   config_file = virtualchain.get_config_filename()

   arg_bitcoin_opts = None
   argparser = None

   if return_parser:
      arg_bitcoin_opts, argparser = virtualchain.parse_bitcoind_args( return_parser=return_parser )

   else:
      arg_bitcoin_opts = virtualchain.parse_bitcoind_args( return_parser=return_parser )

   # command-line overrides config file
   for (k, v) in arg_bitcoin_opts.items():
      bitcoin_opts[k] = v

   # store options
   set_bitcoin_opts( bitcoin_opts )
   set_blockstack_opts( blockstack_opts )

   if return_parser:
      return argparser
   else:
      return None


def reconfigure():
   """
   Reconfigure blockstackd.
   """
   configure( force=True )
   print "Blockstack successfully reconfigured."
   sys.exit(0)


def clean( confirm=True ):
    """
    Remove blockstack's db, lastblock, and snapshot files.
    Prompt for confirmation
    """

    delete = False
    exit_status = 0

    if confirm:
        warning = "WARNING: THIS WILL DELETE YOUR BLOCKSTACK DATABASE!\n"
        warning+= "Database: '%s'\n" % blockstack_state_engine.working_dir
        warning+= "Are you sure you want to proceed?\n"
        warning+= "Type 'YES' if so: "
        value = raw_input( warning )

        if value != "YES":
            sys.exit(exit_status)

        else:
            delete = True

    else:
        delete = True


    if delete:
        print "Deleting..."

        db_filename = virtualchain.get_db_filename()
        lastblock_filename = virtualchain.get_lastblock_filename()
        snapshots_filename = virtualchain.get_snapshots_filename()

        for path in [db_filename, lastblock_filename, snapshots_filename]:
            try:
                os.unlink( path )
            except:
                log.warning("Unable to delete '%s'" % path)
                exit_status = 1

    sys.exit(exit_status)


def rec_to_virtualchain_op( name_rec, block_number, history_index, untrusted_db ):
    """
    Given a record from the blockstack database,
    convert it into a virtualchain operation to
    process.
    """

    # apply opcodes so we can consume them with virtualchain
    opcode_name = str(name_rec['opcode'])
    ret_op = {}

    if name_rec.has_key('expired') and name_rec['expired']:
        # don't care
        return None

    if opcode_name == "NAME_PREORDER":
        name_rec_script = build_preorder( None, None, None, str(name_rec['consensus_hash']), name_hash=str(name_rec['preorder_name_hash']) )
        name_rec_payload = binascii.unhexlify( name_rec_script )[3:]
        ret_op = parse_preorder( name_rec_payload )

    elif opcode_name == "NAME_REGISTRATION":
        name_rec_script = build_registration( str(name_rec['name']) )
        name_rec_payload = binascii.unhexlify( name_rec_script )[3:]
        ret_op = parse_registration( name_rec_payload )

        # reconstruct the registration op...
        ret_op['recipient'] = str(name_rec['sender'])
        ret_op['recipient_address'] = str(name_rec['address'])

        # restore history to find prevoius sender and address
        untrusted_name_rec = untrusted_db.get_name( str(name_rec['name']) )
        name_rec['history'] = untrusted_name_rec['history']

        if history_index > 0:
            print "restore from %s" % block_number
            name_rec_prev = BlockstackDB.restore_from_history( name_rec, block_number )[ history_index - 1 ]
        else:
            print "restore from %s" % (block_number - 1)
            name_rec_prev = BlockstackDB.restore_from_history( name_rec, block_number - 1 )[ history_index - 1 ]

        sender = name_rec_prev['sender']
        address = name_rec_prev['address']

        ret_op['sender'] = sender
        ret_op['address'] = address

        del name_rec['history']

    elif opcode_name == "NAME_UPDATE":
        data_hash = None
        if name_rec['value_hash'] is not None:
            data_hash = str(name_rec['value_hash'])

        name_rec_script = build_update( str(name_rec['name']), str(name_rec['consensus_hash']), data_hash=data_hash )
        name_rec_payload = binascii.unhexlify( name_rec_script )[3:]
        ret_op = parse_update(name_rec_payload)

    elif opcode_name == "NAME_TRANSFER":

        # reconstruct the transfer op...

        KEEPDATA_OP = "%s%s" % (NAME_TRANSFER, TRANSFER_KEEP_DATA)
        if name_rec['op'] == KEEPDATA_OP:
            name_rec['keep_data'] = True
        else:
            name_rec['keep_data'] = False

        # what was the previous owner?
        recipient = str(name_rec['sender'])
        recipient_address = str(name_rec['address'])

        # restore history
        untrusted_name_rec = untrusted_db.get_name( str(name_rec['name']) )
        name_rec['history'] = untrusted_name_rec['history']
        prev_block_number = None
        prev_history_index = None

        # get previous owner
        if history_index > 0:
            name_rec_prev = BlockstackDB.restore_from_history( name_rec, block_number )[history_index - 1]
            prev_block_number = block_number 
            prev_history_index = history_index-1

        else:
            name_rec_prev = BlockstackDB.restore_from_history( name_rec, block_number - 1 )[history_index - 1]
            prev_block_number = block_number-1
            prev_history_index = history_index-1

        if 'transfer_send_block_id' not in name_rec:
            log.error("FATAL: Obsolete or invalid database.  Missing 'transfer_send_block_id' field for NAME_TRANSFER at (%s, %s)" % (block_number, history_index))
            sys.exit(1)

        sender = name_rec_prev['sender']
        address = name_rec_prev['address']

        send_block_id = name_rec['transfer_send_block_id']
        
        # reconstruct recipient and sender
        name_rec['recipient'] = recipient
        name_rec['recipient_address'] = recipient_address

        name_rec['sender'] = sender
        name_rec['address'] = address
        name_rec['consensus_hash'] = untrusted_db.get_consensus_at( send_block_id )

        name_rec_script = build_transfer( str(name_rec['name']), name_rec['keep_data'], str(name_rec['consensus_hash']) )
        name_rec_payload = binascii.unhexlify( name_rec_script )[3:]
        ret_op = parse_transfer(name_rec_payload, name_rec['recipient'] )

        del name_rec['history']

    elif opcode_name == "NAME_REVOKE":
        name_rec_script = build_revoke( str(name_rec['name']) )
        name_rec_payload = binascii.unhexlify( name_rec_script )[3:]
        ret_op = parse_revoke( name_rec_payload )

    elif opcode_name == "NAME_IMPORT":
        name_rec_script = build_name_import( str(name_rec['name']) )
        name_rec_payload = binascii.unhexlify( name_rec_script )[3:]

        # reconstruct recipient and importer
        name_rec['recipient'] = str(name_rec['sender'])
        name_rec['recipient_address'] = str(name_rec['address'])
        name_rec['sender'] = str(name_rec['importer'])
        name_rec['address'] = str(name_rec['importer_address'])

        ret_op = parse_name_import( name_rec_payload, str(name_rec['recipient']), str(name_rec['value_hash']) )

    elif opcode_name == "NAMESPACE_PREORDER":
        name_rec_script = build_namespace_preorder( None, None, None, str(name_rec['consensus_hash']), namespace_id_hash=str(name_rec['namespace_id_hash']) )
        name_rec_payload = binascii.unhexlify( name_rec_script )[3:]
        ret_op = parse_namespace_preorder(name_rec_payload)

    elif opcode_name == "NAMESPACE_REVEAL":
        name_rec_script = build_namespace_reveal( str(name_rec['namespace_id']), name_rec['version'], str(name_rec['recipient_address']), \
                                                  name_rec['lifetime'], name_rec['coeff'], name_rec['base'], name_rec['buckets'],
                                                  name_rec['nonalpha_discount'], name_rec['no_vowel_discount'] )

        name_rec_payload = binascii.unhexlify( name_rec_script )[3:]
        ret_op = parse_namespace_reveal( name_rec_payload, str(name_rec['sender']), str(name_rec['recipient_address']) )

    elif opcode_name == "NAMESPACE_READY":
        name_rec_script = build_namespace_ready( str(name_rec['namespace_id']) )
        name_rec_payload = binascii.unhexlify( name_rec_script )[3:]
        ret_op = parse_namespace_ready( name_rec_payload )

    ret_op = virtualchain.virtualchain_set_opfields( ret_op, virtualchain_opcode=getattr( config, opcode_name ), virtualchain_txid=str(name_rec['txid']), virtualchain_txindex=int(name_rec['vtxindex']) )
    ret_op['opcode'] = opcode_name

    merged_ret_op = copy.deepcopy( name_rec )
    merged_ret_op.update( ret_op )
    return merged_ret_op


def find_last_transfer_consensus_hash( name_rec, block_id, vtxindex ):
    """
    Given a name record, find the last non-NAME_TRANSFER consensus hash.
    Return None if not found.
    """

    history_keys = name_rec['history'].keys()
    history_keys.sort()
    history_keys.reverse()

    for hk in history_keys:
        if hk > block_id:
            continue
        
        history_states = BlockstackDB.restore_from_history( name_rec, hk )

        for history_state in reversed(history_states):
            if hk == block_id and history_state['vtxindex'] > vtxindex:
                # from the future
                continue

            if history_state['op'][0] == NAME_TRANSFER:
                # skip NAME_TRANSFERS
                continue

            if history_state['op'][0] in [NAME_IMPORT, NAME_REGISTRATION]:
                # out of history
                return None

            if history_state.has_key('consensus_hash') and history_state['consensus_hash'] is not None:
                return history_state['consensus_hash']

    return None


def nameop_restore_consensus_fields( name_rec, block_id ):
    """
    Given a nameop at a point in time, ensure
    that all of its consensus fields are present.
    Because they can be reconstructed directly from the nameop,
    but they are not always stored in the db.
    """

    opcode_name = str(name_rec['opcode'])
    ret_op = {}

    if opcode_name == "NAME_REGISTRATION":

        # reconstruct the recipient information
        ret_op['recipient'] = str(name_rec['sender'])
        ret_op['recipient_address'] = str(name_rec['address'])

    elif opcode_name == "NAME_IMPORT":

        # reconstruct the recipient information
        ret_op['recipient'] = str(name_rec['sender'])
        ret_op['recipient_address'] = str(name_rec['address'])

    elif opcode_name == "NAME_TRANSFER":

        db = get_state_engine()

        if 'transfer_send_block_id' not in name_rec:
            log.error("FATAL: Obsolete or invalid database.  Missing 'transfer_send_block_id' field for NAME_TRANSFER at (%s, %s)" % (prev_block_number, prev_history_index))
            sys.exit(1)

        full_rec = db.get_name( name_rec['name'], include_expired=True )
        full_history = full_rec['history']

        # reconstruct the recipient information
        ret_op['recipient'] = str(name_rec['sender'])
        ret_op['recipient_address'] = str(name_rec['address'])

        # reconstruct name_hash, consensus_hash, keep_data
        keep_data = None
        if name_rec['op'][-1] == TRANSFER_KEEP_DATA:
            keep_data = True
        else:
            keep_data = False

        old_history = name_rec.get('history', None)
        name_rec['history'] = full_history
        consensus_hash = find_last_transfer_consensus_hash( name_rec, block_id, name_rec['vtxindex'] )
        name_rec['history'] = old_history

        ret_op['keep_data'] = keep_data
        if consensus_hash is not None:
            print "restore consensus hash (%s,%s): %s" % (block_id, name_rec['vtxindex'], consensus_hash)
            ret_op['consensus_hash'] = consensus_hash
        else:
            ret_op['consensus_hash'] = db.get_consensus_at( name_rec['transfer_send_block_id'] )
            print "Use consensus hash from %s: %s" % (name_rec['transfer_send_block_id'], ret_op['consensus_hash'])

        ret_op['name_hash'] = hash256_trunc128( str(name_rec['name']) )

    elif opcode_name == "NAME_UPDATE":

        # reconstruct name_hash
        ret_op['name_hash'] = hash256_trunc128( str(name_rec['name']) + str(name_rec['consensus_hash']) )

    elif opcode_name == "NAME_REVOKE":

        ret_op['revoked'] = True

    ret_op = virtualchain.virtualchain_set_opfields( ret_op, virtualchain_opcode=getattr( config, opcode_name ), virtualchain_txid=str(name_rec['txid']), virtualchain_txindex=int(name_rec['vtxindex']) )
    ret_op['opcode'] = opcode_name

    merged_op = copy.deepcopy( name_rec )
    merged_op.update( ret_op )

    if 'name_hash' in merged_op.keys():
        nh = merged_op['name_hash']
        merged_op['name_hash128'] = nh

    return merged_op


def block_to_virtualchain_ops( block_id, db ):
    """
    convert a block's name ops to virtualchain ops.
    This is needed in order to recreate the virtualchain
    transactions that generated the block's name operations,
    such as for re-building the db or serving SNV clients.

    Returns the list of virtualchain ops.
    """

    # all sequences of operations at this block, in tx order
    nameops = db.get_all_nameops_at( block_id )

    virtualchain_ops = []

    # process nameops in order by vtxindex
    nameops = sorted( nameops, key=lambda op: op['vtxindex'] )

    # each name record has its own history, and their interleaving in tx order
    # is what makes up nameops.  However, when restoring a name record to
    # a previous state, we need to know the *relative* order of operations
    # that changed it during this block.  This is called the history index,
    # and it maps names to a dict, which maps the the virtual tx index (vtxindex)
    # to integer h such that nameops[name][vtxindex] is the hth update to the name
    # record.

    history_index = {}
    for i in xrange(0, len(nameops)):
        nameop = nameops[i]

        if 'name' not in nameop.keys():
            continue

        name = str(nameop['name'])
        if name not in history_index.keys():
            history_index[name] = { i: 0 }

        else:
            history_index[name][i] = max( history_index[name].values() ) + 1


    for i in xrange(0, len(nameops)):

        # only trusted fields
        opcode_name = nameops[i]['opcode']
        consensus_fields = SERIALIZE_FIELDS.get( opcode_name, None )
        if consensus_fields is None:
            raise Exception("BUG: no consensus fields defined for '%s'" % opcode_name )

        # coerce string, not unicode
        for k in nameops[i].keys():
            if type(nameops[i][k]) == unicode:
                nameops[i][k] = str(nameops[i][k])

        # remove virtualchain-specific fields--they won't be trusted
        nameops[i] = db.sanitize_op( nameops[i] )

        for field in nameops[i].keys():

            # remove untrusted fields, except for:
            # * 'opcode' (which will be fed into the consensus hash
            #             indirectly, once the fields are successfully processed and thus proven consistent with
            #             the fields),
            # * 'transfer_send_block_id' (which will be used to find the NAME_TRANSFER consensus hash,
            #             thus indirectly feeding this information into the consensus hash as well).
            if field not in consensus_fields and field not in ['opcode', 'transfer_send_block_id']:
                log.warning("OP '%s': Removing untrusted field '%s'" % (opcode_name, field))
                del nameops[i][field]

        try:
            # recover virtualchain op from name record
            h = 0
            if 'name' in nameops[i]:
                if nameops[i]['name'] in history_index:
                    h = history_index[ nameops[i]['name'] ][i]

            virtualchain_op = rec_to_virtualchain_op( nameops[i], block_id, h, db )
        except:
            print json.dumps( nameops[i], indent=4 )
            raise

        if virtualchain_op is not None:
            virtualchain_ops.append( virtualchain_op )

    return virtualchain_ops


def rebuild_database( target_block_id, untrusted_db_path, working_db_path=None, resume_dir=None, start_block=None ):
    """
    Given a target block ID and a path to an (untrusted) db, reconstruct it in a temporary directory by
    replaying all the nameops it contains.

    Return the consensus hash calculated at the target block.
    """

    # reconfigure the virtualchain to use a temporary directory,
    # so we don't interfere with this instance's primary database
    working_dir = None
    if resume_dir is None:
        working_dir = tempfile.mkdtemp( prefix='blockstack-verify-database-' )
    else:
        working_dir = resume_dir

    blockstack_state_engine.working_dir = working_dir
    virtualchain.setup_virtualchain( blockstack_state_engine )

    if resume_dir is None:
        # not resuming
        start_block = virtualchain.get_first_block_id()
    else:
        # resuming
        old_start_block = start_block
        start_block = get_lastblock()
        if start_block is None:
            start_block = old_start_block

    log.debug( "Rebuilding database from %s to %s" % (start_block, target_block_id) )

    # feed in operations, block by block, from the untrusted database
    untrusted_db = BlockstackDB( untrusted_db_path )

    # working db, to build up the operations in the untrusted db block-by-block
    working_db = None
    if working_db_path is None:
        working_db_path = virtualchain.get_db_filename()

    working_db = BlockstackDB( working_db_path )

    log.debug( "Working DB: %s" % working_db_path )
    log.debug( "Untrusted DB: %s" % untrusted_db_path )

    # map block ID to consensus hashes
    consensus_hashes = {}

    for block_id in xrange( start_block, target_block_id+1 ):

        virtualchain_ops = block_to_virtualchain_ops( block_id, untrusted_db )

        # feed ops to virtualchain to reconstruct the db at this block
        consensus_hash = working_db.process_block( block_id, virtualchain_ops )
        log.debug("VERIFY CONSENSUS(%s): %s" % (block_id, consensus_hash))

        consensus_hashes[block_id] = consensus_hash

    # final consensus hash
    return consensus_hashes[ target_block_id ]


def verify_database( trusted_consensus_hash, consensus_block_id, untrusted_db_path, working_db_path=None, start_block=None ):
    """
    Verify that a database is consistent with a
    known-good consensus hash.

    This algorithm works by creating a new database,
    parsing the untrusted database, and feeding the untrusted
    operations into the new database block-by-block.  If we
    derive the same consensus hash, then we can trust the
    database.
    """

    final_consensus_hash = rebuild_database( consensus_block_id, untrusted_db_path, working_db_path=working_db_path, start_block=start_block )

    # did we reach the consensus hash we expected?
    if final_consensus_hash == trusted_consensus_hash:
        return True

    else:
        log.error("Unverifiable database state stored in '%s'" % blockstack_state_engine.working_dir )
        return False
    

def restore( working_dir, block_number ):
    """
    Restore the database from a backup in the backups/ directory.
    If block_number is None, then use the latest backup.
    Raise an exception if no such backup exists
    """

    if block_number is None:
        all_blocks = BlockstackDB.get_backup_blocks( virtualchain_hooks )
        if len(all_blocks) == 0:
            log.error("No backups available")
            return False

        block_number = max(all_blocks)

    found = True
    backup_paths = BlockstackDB.get_backup_paths( block_number, virtualchain_hooks )
    for p in backup_paths:
        if not os.path.exists(p):
            log.error("Missing backup file: '%s'" % p)
            found = False

    if not found:
        return False 

    rc = BlockstackDB.backup_restore( block_number, virtualchain_hooks )
    if not rc:
        log.error("Failed to restore backup")

    return rc


def check_alternate_working_dir():
    """
    Check sys.argv to see if there is an alternative
    working directory selected.  We need to know this
    before setting up the virtual chain.
    """

    path = None
    for i in xrange(0, len(sys.argv)):
        arg = sys.argv[i]
        if arg.startswith('--working-dir'):
            if '=' in arg:
                argparts = arg.split("=")
                arg = argparts[0]
                parts = argparts[1:]
                path = "=".join(parts)
            elif i + 1 < len(sys.argv):
                path = sys.argv[i+1]
            else:
                print >> sys.stderr, "--working-dir requires an argument"
                return None

    return path


def run_blockstackd():
   """
   run blockstackd
   """

   working_dir = check_alternate_working_dir()
   blockstack_state_engine.working_dir = working_dir
   argparser = setup( working_dir=working_dir, return_parser=True )

   # get RPC server options
   subparsers = argparser.add_subparsers(
      dest='action', help='the action to be taken')

   parser = subparsers.add_parser(
      'start',
      help='start the blockstackd server')
   parser.add_argument(
      '--foreground', action='store_true',
      help='start the blockstackd server in foreground')
   parser.add_argument(
      '--working-dir', action='store',
      help='use an alternative working directory')
   parser.add_argument(
      '--no-index', action='store_true',
      help='do not index the blockchain, but only run an RPC endpoint')

   parser = subparsers.add_parser(
      'stop',
      help='stop the blockstackd server')
   parser.add_argument(
      '--working-dir', action='store',
      help='use an alternative working directory')

   parser = subparsers.add_parser(
      'configure',
      help='reconfigure the blockstackd server')
   parser.add_argument(
      '--working-dir', action='store',
      help='use an alternative working directory')

   parser = subparsers.add_parser(
      'clean',
      help='remove all blockstack database information')
   parser.add_argument(
      '--force', action='store_true',
      help='Do not confirm the request to delete.')
   parser.add_argument(
      '--working-dir', action='store',
      help='use an alternative working directory')

   parser = subparsers.add_parser(
      'restore',
      help="Restore the database from a backup")
   parser.add_argument(
      'block_number', nargs='?',
      help="The block number to restore from (if not given, the last backup will be used)")

   parser = subparsers.add_parser(
      'rebuilddb',
      help='Reconstruct the current database from particular block number by replaying all prior name operations')
   parser.add_argument(
      'db_path',
      help='the path to the database')
   parser.add_argument(
      'start_block_id',
      help='the block ID from which to start rebuilding')
   parser.add_argument(
      'end_block_id',
      help='the block ID at which to stop rebuilding')
   parser.add_argument(
      '--resume-dir', nargs='?',
      help='the temporary directory to store the database state as it is being rebuilt.  Blockstackd will resume working from this directory if it is interrupted.')
   parser.add_argument(
      '--working-dir', action='store',
      help='use an alternative working directory')

   parser = subparsers.add_parser(
      'verifydb',
      help='verify an untrusted database against a known-good consensus hash')
   parser.add_argument(
      'block_id',
      help='the block ID of the known-good consensus hash')
   parser.add_argument(
      'consensus_hash',
      help='the known-good consensus hash')
   parser.add_argument(
      'db_path',
      help='the path to the database')
   parser.add_argument(
      '--working-dir', action='store',
      help='use an alternative working directory')

   parser = subparsers.add_parser(
      'importdb',
      help='import an existing trusted database')
   parser.add_argument(
      'db_path',
      help='the path to the database')
   parser.add_argument(
      '--working-dir', action='store',
      help='use an alternative working directory')

   parser = subparsers.add_parser(
      'version',
      help='Print version and exit')

   args, _ = argparser.parse_known_args()

   if args.action == 'version':
      print "Blockstack version: %s" % VERSION
      sys.exit(0)

   if args.action == 'start':

      if os.path.exists( get_pidfile_path() ):
          log.error("Blockstackd appears to be running already.  If not, please run '%s stop'" % (sys.argv[0]))
          sys.exit(1)

      if args.foreground:
         log.info('Initializing blockstackd server in foreground (working dir = \'%s\')...' % (working_dir))
      else:
         log.info('Starting blockstackd server (working_dir = \'%s\') ...' % (working_dir))

      if args.no_index:
         log.info("Not indexing the blockchain; only running an RPC endpoint")

      exit_status = run_server( foreground=args.foreground, index=(not args.no_index) )
      if args.foreground:
         log.info("Service endpoint exited with status code %s" % exit_status )

   elif args.action == 'stop':
      stop_server(kill=True)

   elif args.action == 'configure':
      reconfigure()

   elif args.action == 'restore':
      restore( working_dir, args.block_number )

   elif args.action == 'clean':
      clean( confirm=(not args.force) )

   elif args.action == 'rebuilddb':

      resume_dir = None
      if hasattr(args, 'resume_dir') and args.resume_dir is not None:
          resume_dir = args.resume_dir

      final_consensus_hash = rebuild_database( int(args.end_block_id), args.db_path, start_block=int(args.start_block_id), resume_dir=resume_dir )
      print "Rebuilt database in '%s'" % blockstack_state_engine.working_dir
      print "The final consensus hash is '%s'" % final_consensus_hash

   elif args.action == 'verifydb':
      rc = verify_database( args.consensus_hash, int(args.block_id), args.db_path )
      if rc:
          # success!
          print "Database is consistent with %s" % args.consensus_hash
          print "Verified files are in '%s'" % blockstack_state_engine.working_dir

      else:
          # failure!
          print "Database is NOT CONSISTENT"

   elif args.action == 'importdb':
      old_working_dir = blockstack_state_engine.working_dir
      blockstack_state_engine.working_dir = None
      virtualchain.setup_virtualchain( blockstack_state_engine )

      db_path = virtualchain.get_db_filename()
      old_snapshots_path = os.path.join( old_working_dir, os.path.basename( virtualchain.get_snapshots_filename() ) )
      old_lastblock_path = os.path.join( old_working_dir, os.path.basename( virtualchain.get_lastblock_filename() ) )

      if os.path.exists( db_path ):
          print "Backing up existing database to %s.bak" % db_path
          shutil.move( db_path, db_path + ".bak" )

      print "Importing database from %s to %s" % (args.db_path, db_path)
      shutil.copy( args.db_path, db_path )

      print "Importing snapshots from %s to %s" % (old_snapshots_path, virtualchain.get_snapshots_filename() )
      shutil.copy( old_snapshots_path, virtualchain.get_snapshots_filename() )

      print "Importing lastblock from %s to %s" % (old_lastblock_path, virtualchain.get_lastblock_filename() )
      shutil.copy( old_lastblock_path, virtualchain.get_lastblock_filename() )

      # clean up
      shutil.rmtree( old_working_dir )
      if os.path.exists( old_working_dir ):
          os.rmdir( old_working_dir )

if __name__ == '__main__':

   run_blockstackd()
