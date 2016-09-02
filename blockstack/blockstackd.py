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

import blockstack_client

from ConfigParser import SafeConfigParser

import pybitcoin

from lib import nameset as blockstack_state_engine
from lib import get_db_state
from lib.config import REINDEX_FREQUENCY 
from lib import *
from lib.storage import *
from .atlas import *

import lib.nameset.virtualchain_hooks as virtualchain_hooks
import lib.config as config
from lib.consensus import *

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
    Dispatcher to properly instrument calls and do
    proper deserialization.
    """
    def _dispatch(self, method, params):
        try: 
            con_info = {
                "client_host": self.client_address[0],
                "client_port": RPC_SERVER_PORT
            }

            # if this is running as part of the atlas network simulator,
            # then for methods whose first argument is 'atlas_network', then
            # the second argument is always the simulated client host/port
            # (for atlas-specific methods)
            if os.environ.get("BLOCKSTACK_ATLAS_NETWORK_SIMULATION", None) == "1" and len(params) > 0 and params[0] == 'atlas_network':
                log.debug("Reformatting '%s(%s)' as atlas network simulator call" % (method, params))

                client_hostport = params[1]
                params = params[3:]
                con_info = {}

                if client_hostport is not None:
                    client_host, client_port = url_to_host_port( client_hostport )
                    con_info = {
                        "client_host": client_host,
                        "client_port": client_port
                    }

                else:
                    con_info = {
                        "client_host": "",
                        "client_port": 0
                    }
                
                log.debug("Inbound RPC begin %s(%s) (from atlas simulator)" % ("rpc_" + str(method), params))

            else:
                if os.environ.get("BLOCKSTACK_ATLAS_NETWORK_SIMULATION", None) == "1":
                    log.debug("Inbound RPC begin %s(%s)" % ("rpc_" + str(method), params))
                else:
                    log.debug("RPC %s(%s)" % ("rpc_" + str(method), params))

            res = self.server.funcs["rpc_" + str(method)](*params, **con_info)

            # lol jsonrpc within xmlrpc
            ret = json.dumps(res)

            if os.environ.get("BLOCKSTACK_ATLAS_NETWORK_SIMULATION", None) == "1":
                log.debug("Inbound RPC end %s(%s)" % ("rpc_" + str(method), params))

            return ret
        except Exception, e:
            print >> sys.stderr, "\n\n%s(%s)\n%s\n\n" % ("rpc_" + str(method), params, traceback.format_exc())
            return json.dumps( rpc_traceback() )


class BlockstackdRPC( SimpleXMLRPCServer):
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


    def analytics(self, event_type, event_payload):
        """
        Report analytics information for this server
        (uses this server's client handle)
        """
        ak = None
        conf = get_blockstack_opts()
        if conf.has_key('analytics_key'):
            ak = conf['analytics_key']

        if ak is None or len(ak) == 0:
            return

        try:
            blockstack_client.client.analytics_event( event_type, event_payload, analytics_key=ak, action_tag="Perform server action" )
        except:
            log.error("Failed to log analytics event")


    def rpc_ping(self, **con_info):
        reply = {}
        reply['status'] = "alive"
        self.analytics("ping", {})
        return reply


    def rpc_get_name_blockchain_record(self, name, **con_info):
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

            self.analytics("get_name_blockchain_record", {})
            return name_record


    def rpc_get_name_blockchain_history( self, name, start_block, end_block, **con_info ):
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
            self.analytics("get_name_history", {})
            return name_history



    def rpc_get_records_at( self, block_id, **con_info ):
        """
        Get the sequence of name and namespace records at the given block.
        Returns the list of name operations to be fed into virtualchain.
        Used by SNV clients.
        """
        db = get_db_state()

        prior_records = db.get_all_records_at( block_id, include_history=True )
        ret = []
        for rec in prior_records:
            restored_rec = rec_restore_snv_consensus_fields( rec, block_id )
            ret.append( restored_rec )

        return ret


    def rpc_get_nameops_at( self, block_id, **con_info ):
        """
        Old name for rpc_get_records_at
        """
        return self.rpc_get_records_at( block_id )


    def rpc_get_records_hash_at( self, block_id, **con_info ):
        """
        Get the hash over the sequence of names and namespaces altered at the given block.
        Used by SNV clients.
        """
        db = get_db_state()

        prior_recs = db.get_all_records_at( block_id, include_history=True )
        if prior_recs is None:
            prior_recs = []

        restored_recs = []
        for rec in prior_recs:
            restored_rec = rec_restore_snv_consensus_fields( rec, block_id )
            restored_recs.append( restored_rec )

        # NOTE: extracts only the operation-given fields, and ignores ancilliary record fields
        serialized_ops = [ virtualchain.StateEngine.serialize_op( str(op['op'][0]), op, BlockstackDB.make_opfields(), verbose=False ) for op in restored_recs ]

        for serialized_op in serialized_ops:
            log.debug("SERIALIZED (%s): %s" % (block_id, serialized_op))

        ops_hash = virtualchain.StateEngine.make_ops_snapshot( serialized_ops )
        log.debug("Serialized hash at (%s): %s" % (block_id, ops_hash))

        return ops_hash


    def rpc_get_nameops_hash_at( self, block_id, **con_info ):
        """
        Old name for rpc_get_records_hash_at
        """
        return self.rpc_get_records_hash_at( block_id )


    def rpc_getinfo(self, **con_info):
        """
        Get the number of blocks the
        """
        bitcoind_opts = blockstack_client.default_bitcoind_opts( virtualchain.get_config_filename(), prefix=True )
        bitcoind = get_bitcoind( new_bitcoind_opts=bitcoind_opts, new=True )
        
        if bitcoind is None:
            return {'error': 'Internal server error: failed to connect to bitcoind'}

        conf = get_blockstack_opts()
        info = bitcoind.getinfo()
        reply = {}
        reply['last_block_seen'] = info['blocks']
        
        db = get_state_engine()
        reply['consensus'] = db.get_current_consensus()
        reply['server_version'] = "%s" % VERSION
        reply['last_block_processed'] = db.get_current_block()
        reply['server_alive'] = True

        if conf.get('atlas', False):
            # return zonefile inv length 
            reply['zonefile_count'] = atlas_get_num_zonefiles()
        
        self.analytics("getinfo", {})
        return reply


    def rpc_get_names_owned_by_address(self, address, **con_info):
        """
        Get the list of names owned by an address.
        """
        if type(address) not in [str, unicode]:
            return {'error': 'invalid address'}

        db = get_state_engine()
        names = db.get_names_owned_by_address( address )
        if names is None:
            names = []
        return names


    def rpc_get_name_cost( self, name, **con_info ):
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


    def rpc_get_namespace_cost( self, namespace_id, **con_info ):
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


    def rpc_get_namespace_blockchain_record( self, namespace_id, **con_info ):
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


    def rpc_get_all_names( self, offset, count, **con_info ):
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
        self.analytics("get_all_names", {})
        return db.get_all_names( offset=offset, count=count )


    def rpc_get_names_in_namespace( self, namespace_id, offset, count, **con_info ):
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
        self.analytics("get_all_names_in_namespace", {'namespace_id': namespace_id})
        return db.get_names_in_namespace( namespace_id, offset=offset, count=count )


    def rpc_get_consensus_at( self, block_id, **con_info ):
        """
        Return the consensus hash at a block number
        """
        if type(block_id) not in [int, long]:
            return {'error': 'Invalid block ID'}

        if is_indexing():
            return {'error': 'Indexing blockchain'}

        db = get_state_engine()
        self.analytics("get_consensus_at", {'block_id': block_id})
        return db.get_consensus_at( block_id )


    def rpc_get_consensus_hashes( self, block_id_list, **con_info ):
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


    def rpc_get_mutable_data( self, blockchain_id, data_name, **con_info ):
        """
        Get a mutable data record written by a given user.
        TODO: disable by default, unless we're set up to serve data.
        """
        if type(blockchain_id) not in [str, unicode]:
            return {'error': 'Invalid blockchain ID'}

        if not is_name_valid(blockchain_id):
            return {'error': 'Invalid blockchain ID'}

        if type(data_name) not in [str, unicode]:
            return {'error': 'Invalid data name'}

        client = get_blockstack_client_session()
        return client.get_mutable( str(blockchain_id), str(data_name) )


    def rpc_get_immutable_data( self, blockchain_id, data_hash, **con_info ):
        """
        Get immutable data record written by a given user.
        TODO: disable by default, unless we're set up to serve data.
        """ 
        if type(blockchain_id) not in [str, unicode]:
            return {'error': 'Invalid blockchain ID'}

        if not is_name_valid(blockchain_id):
            return {'error': 'Invalid blockchain ID'}

        if type(data_hash) not in [str, unicode]:
            return {'error': 'Invalid data hash'}

        client = get_blockstack_client_session()
        return client.get_immutable( str(blockchain_id), str(data_hash) )


    def rpc_get_block_from_consensus( self, consensus_hash, **con_info ):
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


    def rpc_get_zonefiles( self, zonefile_hashes, **con_info ):
        """
        Get zonefiles from the local cache,
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

        # self.analytics("get_zonefiles", {'count': len(zonefile_hashes)})
        return {'status': True, 'zonefiles': ret}


    def rpc_get_zonefiles_by_names( self, names, **con_info ):
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

        self.analytics("get_zonefiles", {'count': len(names)})
        return {'status': True, 'zonefiles': ret}


    def rpc_put_zonefiles( self, zonefile_datas, **con_info ):
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

        zonefile_dir = conf.get("zonefiles", None)
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
            rc = store_zonefile_to_storage( zonefile, required=zonefile_storage_drivers, cache=True, zonefile_dir=zonefile_dir )
            if not rc:
                log.debug("Failed to replicate zonefile %s to external storage" % zonefile_hash)
                saved.append(0)
                continue

            # update atlas, if enabled
            if conf.get('atlas', False):
                sender_hostport = "%s:%s" % (con_info['client_host'], con_info['client_port'])
                was_missing = atlasdb_set_zonefile_present( zonefile_hash, True )
                if was_missing and atlas_get_peer( sender_hostport ) is None:
                    # we didn't have this zonefile, and we got it from an unknown origin.
                    # there's a good chance we got it from a client.
                    # see if we can replicate it to them in the background.
                    atlas_zonefile_push_enqueue( zonefile_hash, str(zonefile_data) )

            saved.append(1)
        
        log.debug("Saved %s zonefile(s)\n", sum(saved))
        self.analytics("put_zonefiles", {'count': len(zonefile_datas)})
        return {'status': True, 'saved': saved}


    def rpc_get_profile(self, name, **con_info):
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


    def rpc_put_profile(self, name, profile_txt, prev_profile_hash, sigb64, **con_info ):
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
            log.debug("No name for '%s'" % name)
            return {'error': 'No such name'}

        # find zonefile 
        zonefile_dict = self.get_zonefile_by_name( conf, name, zonefile_storage_drivers )
        if zonefile_dict is None:
            log.debug("No zonefile for '%s'" % name)
            return {'error': 'No zonefile'}

        # first, try to verify with zonefile public key (if one is given)
        user_data_pubkey = blockstack_client.user_zonefile_data_pubkey( zonefile_dict )
        if user_data_pubkey is not None:
            try:
                user_profile = blockstack_client.parse_signed_data( profile_txt, user_data_pubkey )
            except Exception, e:
                log.exception(e)
                log.debug("Failed to authenticate profile")
                return {'error': 'Failed to authenticate profile'}
        
        else:
            log.warn("Falling back to verifying with owner address")
            db = get_state_engine()
            name_rec = db.get_name( name )
            if name_rec is None:
                log.debug("No such name")
                return {'error': 'No such name'}

            owner_addr = name_rec.get('address', None)
            if owner_addr is None:
                log.debug("No owner address")
                return {'error': 'No owner address'}

            try:
                user_profile = blockstack_client.parse_signed_data( profile_txt, None, public_key_hash=owner_addr )

                # seems to have worked
                profile_jwt = json.loads(profile_txt)
                if type(profile_jwt) == list:
                    profile_jwt = profile_jwt[0]

                user_data_pubkey = profile_jwt['parentPublicKey']

            except Exception, e:
                log.exception(e)
                log.debug("Failed to authenticate profile")
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

        if old_profile_txt is None:
            # no profile yet (or error)
            old_profile_txt = ""

        old_profile_hash = pybitcoin.hex_hash160(old_profile_txt)
        if old_profile_hash != prev_profile_hash:
            log.debug("Invalid previous profile hash")
            return {'error': 'Invalid previous profile hash'}

        # finally, verify the signature over the previous profile hash and this new profile
        rc = blockstack_client.storage.verify_raw_data( "%s%s" % (prev_profile_hash, profile_txt), user_data_pubkey, sigb64 )
        if not rc:
            log.debug("Invalid signature")
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
            log.debug("Failed to store profile for '%s'" % name)
            return {'error': 'Failed to replicate profile'}
        else:
            log.debug("Stored profile for '%s'" % name)
            return {'status': True, 'num_replicas': successes, 'num_failures': len(blockstack_client.get_storage_handlers()) - successes}


    def rpc_get_atlas_peers( self, **con_info ):
        """
        Get the list of peer atlas nodes.
        Give its own atlas peer hostport.
        Return at most 100 peers
        Return {'status': True, 'peers': ...} on success
        Return {'error': ...} on failure
        """
        conf = get_blockstack_opts()
        if not conf.get('atlas', False):
            return {'error': 'Not an atlas node'}

        # identify the client...
        client_host = con_info['client_host']
        client_port = con_info['client_port']

        # get peers
        peer_list = atlas_get_live_neighbors( "%s:%s" % (client_host, client_port) )
        if len(peer_list) > atlas_max_neighbors():
            random.shuffle(peer_list)
            peer_list = peer_list[:atlas_max_neighbors()]

        atlas_peer_enqueue( "%s:%s" % (client_host, client_port))

        log.debug("\n\nLive peers: %s\n\n" % peer_list)
        return {'status': True, 'peers': peer_list}

    
    def rpc_get_zonefile_inventory( self, offset, length, **con_info ):
        """
        Get an inventory bit vector for the zonefiles in the 
        given bit range (i.e. offset and length are in bits)
        Returns at most 64k of inventory (or 524288 bits)
        Return {'status': True, 'inv': ...} on success, where 'inv' is a b64-encoded bit vector string
        Return {'error': ...} on error.
        """
        conf = get_blockstack_opts()
        if not conf['atlas']:
            return {'error': 'Not an atlas node'}

        if length > 524288:
            return {'error': 'Request length too large'}

        zonefile_inv = atlas_get_zonefile_inventory( offset=offset, length=length )

        if os.environ.get("BLOCKSTACK_TEST", None) == "1":
            log.debug("Zonefile inventory is '%s'" % (atlas_inventory_to_string(zonefile_inv)))

        return {'status': True, 'inv': base64.b64encode(zonefile_inv) }


    def rpc_get_all_neighbor_info( self, **con_info ):
        """
        For network simulator purposes only!
        This method returns all of our peer info.

        DISABLED BY DEFAULT
        """
        if os.environ.get("BLOCKSTACK_ATLAS_NETWORK_SIMULATION") != "1":
            return {'error': 'No such method'}

        return atlas_get_all_neighbors()
        
    
    def rpc_get_unspents(self, address, **con_info):
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


    def rpc_broadcast_transaction(self, txdata, **con_info ):
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


    def rpc_get_analytics_key(self, client_uuid, **con_info ):
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
        if self.rpc_server is not None:
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


def atlas_start( blockstack_opts, db, port ):
    """
    Start up atlas functionality
    """
    # start atlas node 
    atlas_state = None
    if blockstack_opts['atlas']:
         
        atlas_seed_peers = filter( lambda x: len(x) > 0, blockstack_opts['atlas_seeds'].split(","))
        atlas_blacklist = filter( lambda x: len(x) > 0, blockstack_opts['atlas_blacklist'].split(","))
        zonefile_dir = blockstack_opts.get('zonefiles', None)
        zonefile_storage_drivers = filter( lambda x: len(x) > 0, blockstack_opts['zonefile_storage_drivers'].split(","))
        my_hostname = blockstack_opts['atlas_hostname']

        initial_peer_table = atlasdb_init( blockstack_opts['atlasdb_path'], db, atlas_seed_peers, atlas_blacklist, validate=True, zonefile_dir=zonefile_dir )
        atlas_peer_table_init( initial_peer_table )

        atlas_state = atlas_node_start( my_hostname, port, atlasdb_path=blockstack_opts['atlasdb_path'], zonefile_storage_drivers=zonefile_storage_drivers, zonefile_dir=zonefile_dir )

    return atlas_state


def atlas_stop( atlas_state ):
    """
    Stop atlas functionality
    """
    if atlas_state is not None:
        atlas_node_stop( atlas_state )
        atlas_state = None


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
            os.abort()

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


def blockstack_tx_filter( tx ):
    """
    Virtualchain tx filter function:
    * only take txs whose OP_RETURN payload starts with 'id'
    """
    if not 'nulldata' in tx:
        return False

    payload = binascii.unhexlify( tx['nulldata'] )
    if payload.startswith("id"):
        return True

    else:
        return False


def index_blockchain( expected_snapshots=GENESIS_SNAPSHOT ):
    """
    Index the blockchain:
    * find the range of blocks
    * synchronize our state engine up to them
    """

    bt_opts = get_bitcoin_opts() 
    start_block, current_block = get_index_range()

    db = get_state_engine()
    old_lastblock = db.lastblock

    if start_block is None and current_block is None:
        log.error("Failed to find block range")
        return

    # bring the db up to the chain tip
    log.debug("Begin indexing (up to %s)" % current_block)
    set_indexing( True )
    virtualchain_hooks.sync_blockchain( bt_opts, current_block, expected_snapshots=expected_snapshots, tx_filter=blockstack_tx_filter )
    set_indexing( False )
    
    # synchronize atlas db
    blockstack_opts = get_blockstack_opts()
    if blockstack_opts.get('atlas', False):
        db = get_state_engine()
        if old_lastblock < db.lastblock:
            log.debug("Synchronize Atlas DB from %s to %s" % (old_lastblock+1, db.lastblock+1))
            zonefile_dir = blockstack_opts.get('zonefiles', get_zonefile_dir())
            atlasdb_sync_zonefiles( db, old_lastblock+1, zonefile_dir=zonefile_dir )

    log.debug("End indexing (up to %s)" % current_block)


def blockstack_exit():
    """
    Shut down the server on exit(3)
    """
    stop_server(kill=True)
    stop_atlas()


def blockstack_exit_handler( sig, frame ):
    """
    Fatal signal handler
    """
    sys.exit(0)


def run_server( foreground=False, index=True, expected_snapshots=GENESIS_SNAPSHOT, port=None ):
    """
    Run the blockstackd RPC server, optionally in the foreground.
    """

    bt_opts = get_bitcoin_opts()
    blockstack_opts = get_blockstack_opts()
    indexer_log_file = get_logfile_path() + ".indexer"
    pid_file = get_pidfile_path()
    working_dir = virtualchain.get_working_dir()

    if port is None:
        port = blockstack_opts['rpc_port']

    logfile = None
    if not foreground:
        try:
            if os.path.exists( indexer_log_file ):
                logfile = open( indexer_log_file, "a" )
            else:
                logfile = open( indexer_log_file, "a+" )
        except OSError, oe:
            log.error("Failed to open '%s': %s" % (indexer_log_file, oe.strerror))
            os.abort()

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

    # get db state
    db = get_state_engine()

    # start atlas node
    atlas_state = atlas_start( blockstack_opts, db, port )
    
    # start API server
    rpc_start(port)
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
               index_blockchain(expected_snapshots=expected_snapshots)
            except Exception, e:
               log.exception(e)
               log.error("FATAL: caught exception while indexing")
               os.abort()
            
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

    # stop atlas node 
    atlas_stop( atlas_state )

    # stop the atlas node, if it's running 
    if atlas_state is not None:
        atlas_node_stop( atlas_state )
        atlas_state = None

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

   # config file version check
   config_server_version = blockstack_opts.get('server_version', None)
   if config_server_version is None or not blockstack_client.config.semver_match( str(config_server_version), str(VERSION) ):
       print >> sys.stderr, "Obsolete config file (%s): '%s' != '%s'\nPlease move it out of the way, so Blockstack Server can generate a fresh one." % (virtualchain.get_config_filename(), config_server_version, VERSION)
       return None

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

    if path is None and os.environ.get("VIRTUALCHAIN_WORKING_DIR") is not None:
        path = os.environ["VIRTUALCHAIN_WORKING_DIR"]

    return path


def run_blockstackd():
   """
   run blockstackd
   """

   working_dir = check_alternate_working_dir()
   log.debug("Working directory is %s" % working_dir)

   blockstack_state_engine.working_dir = working_dir
   argparser = setup( working_dir=working_dir, return_parser=True )
   if argparser is None:
       # fatal error
       os.abort()

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
   parser.add_argument(
      '--expected-snapshots', action='store',
      help='path to a .snapshots file with the expected consensus hashes')
   parser.add_argument(
      '--port', action='store',
      help='port to bind on')

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

   # only meant for testing 
   parser = subparsers.add_parser(
      "atlas-testnet",
      help="Run an atlas peer on the atlas test network")
   parser.add_argument(
      "seeds",
      help="A CSV of initial peers, as 'host:port' strings")
   parser.add_argument(
      "name_updates",
      help="A CSV of zonefile hashes and their block heights, as 'zonefile_hash:blockheight' strings")

   parser = subparsers.add_parser(
      'version',
      help='Print version and exit')

   args, _ = argparser.parse_known_args()

   if args.action == 'version':
      print "Blockstack version: %s" % VERSION
      sys.exit(0)

   if args.action == 'start':

      # use snapshots?
      expected_snapshots = {}
      if args.expected_snapshots is not None:
          snapshots_path = args.expected_snapshots
          try:
              with open(snapshots_path, "r") as f:
                  snapshots_json = f.read()

              snapshots_data = json.loads(snapshots_json)
              assert 'snapshots' in snapshots_data.keys(), "Not a valid snapshots file"

              # extract snapshots: map int to consensus hash
              for (block_id_str, consensus_hash) in snapshots_data['snapshots'].items():
                  expected_snapshots[ int(block_id_str) ] = str(consensus_hash)

          except Exception, e:
              log.exception(e)
              log.error("Failed to read expected snapshots from '%s'" % snapshots_path)
              sys.exit(1)

      if os.path.exists( get_pidfile_path() ):
          log.error("Blockstackd appears to be running already.  If not, please run '%s stop'" % (sys.argv[0]))
          sys.exit(1)

      if args.foreground:
         log.info('Initializing blockstackd server in foreground (working dir = \'%s\')...' % (working_dir))
      else:
         log.info('Starting blockstackd server (working_dir = \'%s\') ...' % (working_dir))

      if args.no_index:
         log.info("Not indexing the blockchain; only running an RPC endpoint")

      if args.port is not None:
         log.info("Binding on port %s" % int(args.port))

      exit_status = run_server( foreground=args.foreground, index=(not args.no_index), expected_snapshots=expected_snapshots, port=int(args.port) )
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
