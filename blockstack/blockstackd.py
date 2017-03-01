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
import keylib
import base64
import urllib2
import jsonschema
from jsonschema import ValidationError

from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler

# stop common XML attacks 
from defusedxml import xmlrpc
xmlrpc.monkey_patch()

import virtualchain
log = virtualchain.get_logger("blockstack-core")

import blockstack_client

from ConfigParser import SafeConfigParser

import pybitcoin

from lib import nameset as blockstack_state_engine
from lib import get_db_state
from lib.config import REINDEX_FREQUENCY 
from lib import *
from lib.storage import *
from lib.atlas import *
from lib.fast_sync import *

import lib.nameset.virtualchain_hooks as virtualchain_hooks
import lib.config as config
from lib.consensus import *

from blockstack_client.constants import BLOCKSTACK_TEST

# global variables, for use with the RPC server
bitcoind = None
rpc_server = None
storage_pusher = None
has_indexer = True

def get_bitcoind( new_bitcoind_opts=None, reset=False, new=False ):
   """
   Get or instantiate our bitcoind client.
   Optionally re-set the bitcoind options.
   """
   global bitcoind

   if reset:
       bitcoind = None

   elif not new and bitcoind is not None:
      return bitcoind

   if new or bitcoind is None:
      if new_bitcoind_opts is not None:
         set_bitcoin_opts( new_bitcoind_opts )

      bitcoin_opts = get_bitcoin_opts()
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
        os.fsync(f.fileno())

    return 


def get_logfile_path():
   """
   Get the logfile path for our service endpoint.
   """
   working_dir = virtualchain.get_working_dir()
   logfile_filename = blockstack_state_engine.get_virtual_chain_name() + ".log"
   return os.path.join( working_dir, logfile_filename )
     

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
    wait = 1.0
    while last_block is None and is_running():

        first_block, last_block = virtualchain.get_index_range( bitcoind_session )

        if last_block is None:

            # try to reconnnect
            log.error("Reconnect to bitcoind in {} seconds".format(wait))
            time.sleep(wait)
            wait = min(wait * 2.0 + random.random() * wait, 60)

            bitcoind_session = get_bitcoind( new=True )
            continue

        else:
            return first_block, last_block - NUM_CONFIRMATIONS


def is_indexer():
    """
    Is this node indexing?
    """
    global has_indexer
    return has_indexer


def rpc_traceback():
    exception_data = traceback.format_exc().splitlines()
    return {
        "error": exception_data[-1],
        "traceback": exception_data
    }


def get_name_cost( db, name ):
    """
    Get the cost of a name, given the fully-qualified name.
    Do so by finding the namespace it belongs to (even if the namespace is being imported).
    Return None if the namespace has not been declared
    """
    lastblock = db.lastblock
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

    name_fee = price_name( get_name_from_fq_name( name ), namespace, lastblock )
    log.debug("Cost of '%s' at %s is %s" % (name, lastblock, int(name_fee)))

    return name_fee


def get_namespace_cost( db, namespace_id ):
    """
    Get the cost of a namespace.
    Returns (cost, ns) (where ns is None if there is no such namespace)
    """
    lastblock = db.lastblock
    namespace = db.get_namespace( namespace_id )
    namespace_fee = price_namespace( namespace_id, lastblock )
    return (namespace_fee, namespace)



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
        
        return


    def success_response(self, method_resp ):
        """
        Make a standard "success" response,
        which contains some ancilliary data.
        """
        resp = {
            'status': True,
            'indexing': config.is_indexing(),
            'lastblock': config.fast_getlastblock(),
        }

        resp.update( method_resp )
        return resp


    def rpc_ping(self, **con_info):
        reply = {}
        reply['status'] = "alive"
        self.analytics("ping", {})
        return reply


    def rpc_get_name_blockchain_record(self, name, **con_info):
        """
        Lookup the blockchain-derived whois info for a name.
        Return {'status': True, 'record': rec} on success
        Return {'error': ...} on error
        """

        if not is_indexer():
            return {'error': 'Method not supported'}

        if type(name) not in [str, unicode]:
            return {'error': 'invalid name'}

        if not is_name_valid(name):
            return {'error': 'invalid name'}

        db = get_db_state()

        try:
            name = str(name)
        except Exception as e:
            db.close()
            return {"error": str(e)}

        name_record = db.get_name(str(name))

        if name_record is None:
            db.close()
            return {"error": "Not found."}

        else:

            namespace_id = get_namespace_from_name(name)
            namespace_record = db.get_namespace(namespace_id)

            # when does this name expire (if it expires)?
            if namespace_record['lifetime'] != NAMESPACE_LIFE_INFINITE:
                namespace_lifetime_multiplier = get_epoch_namespace_lifetime_multiplier( db.lastblock, namespace_id )
                name_record['expire_block'] = max( namespace_record['ready_block'], name_record['last_renewed'] ) + namespace_record['lifetime'] * namespace_lifetime_multiplier

            else:
                name_record['expire_block'] = '-1'

            db.close()
            self.analytics("get_name_blockchain_record", {})
            return self.success_response( {'record': name_record} )


    def rpc_get_name_history_blocks( self, name, **con_info ):
        """
        Get the list of blocks at which the given name was affected.
        Return {'status': True, 'history_blocks': [...]} on success
        Return {'error': ...} on error
        """
        if not is_indexer():
            return {'error': 'Method not supported'}

        if type(name) not in [str, unicode]:
            return {'error': 'invalid name'}

        if not is_name_valid(name):
            return {'error': 'invalid name'}

        db = get_db_state()
        history_blocks = db.get_name_history_blocks( name )
        db.close()
        return self.success_response( {'history_blocks': history_blocks} )


    def rpc_get_name_at( self, name, block_height, **con_info ):
        """
        Get all the states the name was in at a particular block height.
        Return {'status': true, 'record': ...}
        """
        if not is_indexer():
            return {'error': 'Method not supported'}

        if type(name) not in [str, unicode]:
            return {'error': 'invalid name'}

        if block_height < FIRST_BLOCK_MAINNET:
            return {'status': True, 'record': None}

        db = get_db_state()
        name_at = db.get_name_at( name, block_height )
        db.close()

        return self.success_response( {'records': name_at} )


    def rpc_get_last_nameops( self, offset, count, **con_info ):
        """
        Get the last nameops processed, starting at the offset
        and returning up to count items.
        Operations are returned in newer to older order.
        """
        if not is_indexer():
            return {'error': 'Method not supported'}

        db = get_db_state()
        last_nameops = db.get_last_nameops( offset, count )
        db.close()
        return self.success_response( {'last_nameops': last_nameops} )


    def rpc_get_op_history_rows( self, history_id, offset, count, **con_info ):
        """
        Get a page of history rows for a name or namespace
        Return {'status': True, 'history_rows': [history rows]} on success
        Return {'error': ...} on error
        """
        if not is_indexer():
            return {'error': 'Method not supported'}

        if offset < 0 or count < 0:
            return {'error': 'Invalid offset, count'}

        if count > 10:
            return {'error': 'Count is too big'}

        db = get_db_state()
        history_rows = db.get_op_history_rows( history_id, offset, count )
        db.close()

        return self.success_response( {'history_rows': history_rows} )


    def rpc_get_num_op_history_rows( self, history_id, **con_info ):
        """
        Get the total number of history rows
        Return {'status': True, 'count': count} on success
        Return {'error': ...} on error
        """
        if not is_indexer():
            return {'error': 'Method not supported'}

        db = get_db_state()
        num_history_rows = db.get_num_op_history_rows( history_id )
        db.close()

        return self.success_response( {'count': num_history_rows} )


    def rpc_get_nameops_affected_at( self, block_id, offset, count, **con_info ):
        """
        Get the sequence of name and namespace records affected at the given block.
        The records returned will be in their *current* forms.  The caller
        should use get_op_history_rows() to fetch the history delta that
        can be used to restore the records to their *historic* forms i.e.
        at the given block height.

        Returns the list of name operations to be fed into virtualchain, as
        {'status': True, 'nameops': [nameops]}

        Returns {'error': ...} on failure

        Used by SNV clients.
        """
        if not is_indexer():
            return {'error': 'Method not supported'}

        if offset < 0 or count < 0:
            return {'error': 'invalid page offset/length'}

        if count > 10:
            return {'error': 'Page too big'}

        # do NOT restore history information, since we're paging
        db = get_db_state()
        prior_records = db.get_all_ops_at( block_id, offset=offset, count=count, include_history=False, restore_history=False )
        db.close()
        log.debug("%s name operations at block %s, offset %s, count %s" % (len(prior_records), block_id, offset, count))
        return self.success_response( {'nameops': prior_records} )


    def rpc_get_num_nameops_affected_at( self, block_id, **con_info ):
        """
        Get the number of name and namespace operations at the given block.
        Returns {'status': True, 'count': ...} on success
        Returns {'error': ...} on error
        """
        if not is_indexer():
            return {'error': 'Method not supported'}

        db = get_db_state()
        count = db.get_num_ops_at( block_id )
        db.close()

        log.debug("%s name operations at %s" % (count, block_id))
        return self.success_response( {'count': count} )


    def rpc_get_nameops_hash_at( self, block_id, **con_info ):
        """
        Get the hash over the sequence of names and namespaces altered at the given block.
        Used by SNV clients.

        Returns {'status': True, 'ops_hash': ops_hash} on success
        Returns {'error': ...} on error
        """
        if not is_indexer():
            return {'error': 'Method not supported'}

        db = get_db_state()
        ops_hash = db.get_block_ops_hash( block_id )
        db.close()

        return self.success_response( {'ops_hash': ops_hash} )


    def rpc_getinfo(self, **con_info):
        """
        Get information from the running server:
        * last_block_seen: the last block height seen
        * consensus: the consensus hash for that block
        * server_version: the server version
        * last_block_processed: the last block processed
        * server_alive: True
        * [optional] zonefile_count: the number of zonefiles known
        """
        if not is_indexer():
            return {'error': 'Method not supported'}

        bitcoind_opts = blockstack_client.default_bitcoind_opts( virtualchain.get_config_filename(), prefix=True )
        bitcoind = get_bitcoind( new_bitcoind_opts=bitcoind_opts, new=True )
        
        if bitcoind is None:
            return {'error': 'Internal server error: failed to connect to bitcoind'}

        conf = get_blockstack_opts()
        info = bitcoind.getinfo()
        reply = {}
        reply['last_block_seen'] = info['blocks']
        
        db = get_db_state()
        reply['consensus'] = db.get_current_consensus()
        reply['server_version'] = "%s" % VERSION
        reply['last_block_processed'] = db.get_current_block()
        reply['server_alive'] = True
        reply['indexing'] = config.is_indexing()

        db.close()

        if conf.get('atlas', False):
            # return zonefile inv length 
            reply['zonefile_count'] = atlas_get_num_zonefiles()
        
        self.analytics("getinfo", {})
        return reply


    def rpc_get_names_owned_by_address(self, address, **con_info):
        """
        Get the list of names owned by an address.
        Return {'status': True, 'names': ...} on success
        Return {'error': ...} on error
        """
        if not is_indexer():
            return {'error': 'Method not supported'}

        if type(address) not in [str, unicode]:
            return {'error': 'invalid address'}

        db = get_db_state()
        names = db.get_names_owned_by_address( address )
        db.close()

        if names is None:
            names = []

        return self.success_response( {'names': names} )


    def rpc_get_name_cost( self, name, **con_info ):
        """
        Return the cost of a given name, including fees
        Return value is in satoshis (as 'satoshis')
        """

        if not is_indexer():
            return {'error': 'Method not supported'}

        if type(name) not in [str, unicode]:
            return {'error': 'invalid name'}

        if not is_name_valid(name):
            return {'error': 'invalid name'}

        db = get_db_state()
        ret = get_name_cost( db, name )
        db.close()

        if ret is None:
            return {"error": "Unknown/invalid namespace"}

        return self.success_response( {"satoshis": int(math.ceil(ret))} )


    def rpc_get_namespace_cost( self, namespace_id, **con_info ):
        """
        Return the cost of a given namespace, including fees.
        Return value is in satoshis
        """

        if not is_indexer():
            return {'error': 'Method not supported'}

        if type(namespace_id) not in [str, unicode]:
            return {'error': 'invalid namespace ID'}

        if not is_namespace_valid(namespace_id):
            return {'error': 'invalid namespace ID'}

        db = get_db_state()
        cost, ns = get_namespace_cost( db, namespace_id )
        db.close()

        ret = {
            'satoshis': int(math.ceil(cost))
        }

        if ns is not None:
            ret['warning'] = 'Namespace already exists'

        return self.success_response( ret )


    def rpc_get_namespace_blockchain_record( self, namespace_id, **con_info ):
        """
        Return the namespace with the given namespace_id
        Return {'status': True, 'record': ...} on success
        Return {'error': ...} on error
        """

        if not is_indexer():
            return {'error': 'Method not supported'}

        if type(namespace_id) not in [str, unicode]:
            return {'error': 'invalid namespace ID'}

        if not is_namespace_valid(namespace_id):
            return {'error': 'invalid namespace ID'}

        db = get_db_state()
        ns = db.get_namespace( namespace_id )
        if ns is None:
            # maybe revealed?
            ns = db.get_namespace_reveal( namespace_id )
            db.close()

            if ns is None:
                return {"error": "No such namespace"}

            ns['ready'] = False
            return self.success_response( {'record': ns} )

        else:
            db.close()
            ns['ready'] = True
            return self.success_response( {'record': ns} )


    def rpc_get_num_names( self, **con_info ):
        """
        Get the number of names that exist
        Return {'status': True, 'count': count} on success
        Return {'error': ...} on error
        """
        
        if not is_indexer():
            return {'error': 'Method not supported'}

        db = get_db_state()
        self.analytics("get_num_names", {})
        num_names = db.get_num_names()
        db.close()

        return self.success_response( {'count': num_names} )


    def rpc_get_all_names( self, offset, count, **con_info ):
        """
        Get all names, paginated
        Return {'status': true, 'names': [...]} on success
        Return {'error': ...} on error
        """
        if not is_indexer():
            return {'error': 'Method not supported'}

        if type(offset) not in [int, long]:
            return {'error': 'invalid offset'}

        if type(count) not in [int, long]:
            return {'error': 'invalid count'}

        if offset < 0 or count < 0:
            return {'error': 'invalid pages'}

        # don't do more than 100 at a time 
        if count > 100:
            return {'error': 'count is too big'}

        db = get_db_state()
        self.analytics("get_all_names", {})
        all_names = db.get_all_names( offset=offset, count=count )
        db.close()

        return self.success_response( {'names': all_names} )


    def rpc_get_all_namespaces( self, **con_info ):
        """
        Get all namespace names
        Return {'status': true, 'namespaces': [...]} on success
        Return {'error': ...} on error
        """
        
        if not is_indexer():
            return {'error': 'Method not supported'}

        db = get_db_state()
        self.analytics("get_all_namespaces", {})
        all_namespaces = db.get_all_namespace_ids()
        db.close()

        return self.success_response( {'namespaces': all_namespaces} )


    def rpc_get_num_names_in_namespace( self, namespace_id, **con_info ):
        """
        Get the number of names in a namespace
        Return {'status': true, 'count': count} on success
        Return {'error': ...} on error
        """
        
        if not is_indexer():
            return {'error': 'Method not supported'}

        db = get_db_state()
        self.analytics('get_num_names_in_namespace', {})
        num_names = db.get_num_names_in_namespace( namespace_id )
        db.close()

        return self.success_response( {'count': num_names} )


    def rpc_get_names_in_namespace( self, namespace_id, offset, count, **con_info ):
        """
        Return all names in a namespace, paginated
        Return {'status': true, 'names': [...]} on success
        Return {'error': ...} on error
        """
        if not is_indexer():
            return {'error': 'Method not supported'}

        if type(namespace_id) not in [str, unicode]:
            return {'error': 'invalid namespace ID'}
    
        if type(offset) not in [int, long]:
            return {'error': 'invalid offset'}

        if type(count) not in [int, long]:
            return {'error': 'invalid count'}

        if offset < 0 or count < 0:
            return {'error': 'invalid pages'}

        if not is_namespace_valid( namespace_id ):
            return {'error': 'invalid namespace ID'}

        self.analytics("get_all_names_in_namespace", {'namespace_id': namespace_id})

        db = get_db_state()
        res = db.get_names_in_namespace( namespace_id, offset=offset, count=count )
        db.close()

        return self.success_response( {'names': res} )


    def rpc_get_consensus_at( self, block_id, **con_info ):
        """
        Return the consensus hash at a block number.
        Return {'status': True, 'consensus': ...} on success
        Return {'error': ...} on error
        """
        if not is_indexer():
            return {'error': 'Method not supported'}

        if type(block_id) not in [int, long]:
            return {'error': 'Invalid block ID'}

        db = get_db_state()
        self.analytics("get_consensus_at", {'block_id': block_id})
        consensus = db.get_consensus_at( block_id )
        db.close()
        return self.success_response( {'consensus': consensus} )


    def rpc_get_consensus_hashes( self, block_id_list, **con_info ):
        """
        Return the consensus hashes at multiple block numbers
        Return a dict mapping each block ID to its consensus hash.

        Returns {'status': True, 'consensus_hashes': dict} on success
        Returns {'error': ...} on success
        """
        if not is_indexer():
            return {'error': 'Method not supported'}

        if type(block_id_list) != list:
            return {'error': 'Invalid block IDs'}

        for bid in block_id_list:
            if type(bid) not in [int, long]:
                return {'error': 'Invalid block ID'}

        db = get_db_state()
        ret = {}
        for block_id in block_id_list:
            ret[block_id] = db.get_consensus_at(block_id)

        db.close()

        return self.success_response( {'consensus_hashes': ret} )


    def rpc_get_mutable_data( self, blockchain_id, fq_data_id, **con_info ):
        """
        Get a mutable data record written by a given user.
        """
        if type(fq_data_id) not in [str, unicode]:
            return {'error': 'Invalid data ID'}

        if not type(blockchain_id) in [str, unicode] or not blockstack_client.is_name_valid(blockchain_id):
            return {'error': 'Invalid blockchain ID'}

        conf = get_blockstack_opts()
        if not conf['serve_data']:
            return {'error': 'No data'}
      
        drivers = conf.get('data_storage_drivers', None)
        if drivers is not None:
            drivers = drivers.split(',')

        res = load_mutable_data_from_storage( blockchain_id, fq_data_id, drivers=drivers )
        if res is None:
            log.debug("Failed to get {}".format(fq_data_id))
            return {'error': 'Failed to get data'}

        return self.success_response({'data': res})


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

        conf = get_blockstack_opts()
        if not conf['serve_data']:
            return {'error': 'No data'}

        client = get_blockstack_client_session()
        return client.get_immutable( str(blockchain_id), str(data_hash) )


    def rpc_get_block_from_consensus( self, consensus_hash, **con_info ):
        """
        Given the consensus hash, find the block number (or None)
        """
        if not is_indexer():
            return {'error': 'Method not supported'}

        if type(consensus_hash) not in [str, unicode]:
            return {'error': 'Not a valid consensus hash'}

        db = get_db_state()
        block_id = db.get_block_from_consensus( consensus_hash )
        db.close()
        return self.success_response( {'block_id': block_id} )


    def get_zonefile_data( self, config, zonefile_hash, zonefile_storage_drivers, name=None ):
        """
        Get a zonefile by hash
        Return the serialized zonefile on success
        Return None on error
        """
    
        # check cache 
        cached_zonefile_data = get_cached_zonefile_data( zonefile_hash, zonefile_dir=config.get('zonefiles', None))
        if cached_zonefile_data is not None:
            # check hash 
            zfh = blockstack_client.get_zonefile_data_hash( cached_zonefile_data )
            if zfh != zonefile_hash:
                log.debug("Invalid cached zonefile %s" % zonefile_hash )
                remove_cached_zonefile_data( zonefile_hash, zonefile_dir=config.get('zonefiles', None))

            else:
                log.debug("Zonefile %s is cached" % zonefile_hash)
                return cached_zonefile_data

        return None
       

    def get_zonefile_data_by_name( self, conf, name, zonefile_storage_drivers, name_rec=None ):
        """
        Get a zonefile by name
        Return the serialized zonefile on success
        Return None one error
        """

        if name_rec is None:
            if not is_indexer():
                return None

            db = get_db_state()
            name_rec = db.get_name( name )
            db.close()

        if name_rec is None:
            return None

        zonefile_hash = name_rec.get('value_hash', None)
        if zonefile_hash is None:
            return None

        # find zonefile 
        zonefile_data = self.get_zonefile_data( conf, zonefile_hash, zonefile_storage_drivers, name=name )
        if zonefile_data is None:
            return None

        return zonefile_data


    def rpc_get_zonefiles( self, zonefile_hashes, **con_info ):
        """
        Get zonefiles from the local cache,
        or (on miss), from upstream storage.
        Only return at most 100 zonefiles.
        Return {'status': True, 'zonefiles': {zonefile_hash: zonefile}} on success
        Return {'error': ...} on error

        zonefiles will be serialized to string and base64-encoded
        """
        conf = get_blockstack_opts()
        if not conf['serve_zonefiles']:
            return {'error': 'No data'}

        if type(zonefile_hashes) != list:
            log.error("Not a zonefile hash list")
            return {'error': 'Invalid zonefile hashes'}

        if len(zonefile_hashes) > 100:
            log.error("Too many requests (%s)" % len(zonefile_hashes))
            return {'error': 'Too many requests'}

        zonefile_storage_drivers = conf['zonefile_storage_drivers'].split(",")

        ret = {}
        for zonefile_hash in zonefile_hashes:
            if type(zonefile_hash) not in [str, unicode]:
                log.error("Invalid zonefile hash")
                return {'error': 'Not a zonefile hash'}

        for zonefile_hash in zonefile_hashes:
            zonefile_data = self.get_zonefile_data( conf, zonefile_hash, zonefile_storage_drivers )
            if zonefile_data is None:
                continue

            else:
                ret[zonefile_hash] = base64.b64encode( zonefile_data )

        # self.analytics("get_zonefiles", {'count': len(zonefile_hashes)})
        log.debug("Serve back %s zonefiles" % len(ret.keys()))
        return self.success_response( {'zonefiles': ret} )


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
            zonefile_data = self.get_zonefile_data_by_name( conf, name, zonefile_storage_drivers )
            if zonefile_data is None:
                continue

            else:
                ret[name] = base64.b64encode(zonefile_data)

        self.analytics("get_zonefiles", {'count': len(names)})
        return self.success_response( {'zonefiles': ret} )


    def rpc_put_zonefiles( self, zonefile_datas, **con_info ):
        """
        Replicate one or more zonefiles, given as serialized strings.
        Note that the system *only* takes well-formed zonefiles.
        Returns {'status': True, 'saved': [0|1]'} on success ('saved' is a vector of success/failure)
        Returns {'error': ...} on error
        Takes at most 100 zonefiles
        """

        if not is_indexer():
            return {'error': 'Method not supported'}

        conf = get_blockstack_opts()

        if not conf['serve_zonefiles']:
            return {'error': 'No data'}

        if type(zonefile_datas) != list:
            return {'error': 'Invalid data'}

        if len(zonefile_datas) > 100:
            return {'error': 'Too many zonefiles'}

        zonefile_dir = conf.get("zonefiles", None)
        saved = []
        db = get_db_state()
        zonefile_storage_drivers = conf['zonefile_storage_drivers'].split(",")

        for zonefile_data in zonefile_datas:
          
            if type(zonefile_data) not in [str,unicode]:
                log.debug("Invalid non-text zonefile")
                saved.append(0)
                continue

            # decode
            try:
                zonefile_data = base64.b64decode( zonefile_data )
            except:
                log.debug("Invalid base64 zonefile")
                saved.append(0)
                continue
            
            if len(zonefile_data) > RPC_MAX_ZONEFILE_LEN:
                log.debug("Zonefile too long")
                saved.append(0)
                continue

            zonefile_hash = blockstack_client.get_zonefile_data_hash( str(zonefile_data) )

            # does it correspond to a valid zonefile?
            names_with_hash = db.get_names_with_value_hash( zonefile_hash )
            if names_with_hash is None or len(names_with_hash) == 0:
                log.debug("Unknown zonefile hash %s" % zonefile_hash)
                saved.append(0)
                continue

            rc = store_cached_zonefile_data( str(zonefile_data), zonefile_dir=zonefile_dir )
            if not rc:
                log.error("Failed to cache {}".format(zonefile_hash))
                saved.append(0)
                continue

            # maybe a proper zonefile?  if so, get the name out
            name = None
            txid = None
            try: 
                zonefile = blockstack_zones.parse_zone_file( str(zonefile_data) )
                name = str(zonefile['$origin'])
                txid = db.get_name_value_hash_txid( name, zonefile_hash )
            except Exception, e:
                log.debug("Not a well-formed zonefile: %s" % zonefile_hash)

            # queue for replication
            rc = storage_enqueue_zonefile( txid, str(zonefile_hash), str(zonefile_data) )
            if not rc:
                log.error("Failed to store zonefile {}".format(zonefile_hash))
                saved.append(0)
                continue

            log.debug("Enqueued {}".format(zonefile_hash))
            saved.append(1)
       
        db.close()

        log.debug("Saved %s zonefile(s)\n", sum(saved))
        self.analytics("put_zonefiles", {'count': len(zonefile_datas)})
        return self.success_response( {'saved': saved} )


    def get_name_rec(self, name):
        """
        Get a name record, even if we're not an indexer node.
        Return the name rec on success
        Return {'error': ...} on failure
        """
        name_rec = None

        if is_indexer():
            # fetch from db directly 
            db = get_db_state()
            name_rec = db.get_name(name)
            db.close()

            if name_rec is None:
                return {'error': 'No such name'}

        else:
            # fetch from upstream 
            name_rec = blockstack_client.proxy.get_name_blockchain_record(name)
            if 'error' in name_rec:
                return name_rec

        return name_rec

    
    def rpc_get_profile(self, name, **con_info):
        """
        Get a profile for a particular name
        Return {'profile': profile text} on success
        Return {'error': ...} on error
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

        name_rec = self.get_name_rec(name)
        if 'error' in name_rec:
            return name_rec

        # find zonefile 
        zonefile_data = self.get_zonefile_data_by_name( conf, name, zonefile_storage_drivers, name_rec=name_rec )
        if zonefile_data is None:
            return {'error': 'No zonefile'}

        # deserialize 
        try:
            zonefile_dict = blockstack_zones.parse_zone_file( zonefile_data )
        except:
            return {'error': 'Nonstandard zonefile'}

        # find the profile
        try:
            # NOTE: since we did not generate this zonefile (i.e. it's untrusted input, and we may be using different storage drivers),
            # don't trust its URLs.  Auto-generate them using our designated drivers instead.
            # Also, do not attempt to decode the profile.  The client will do this instead (avoid any decode-related attack vectors)
            profile, zonefile = blockstack_client.get_profile(name, profile_storage_drivers=profile_storage_drivers, zonefile_storage_drivers=zonefile_storage_drivers,
                                                             user_zonefile=zonefile_dict, name_record=name_rec, use_zonefile_urls=False, decode_profile=False)
        except Exception, e:
            log.exception(e)
            log.debug("Failed to load profile for '%s'" % name)
            return {'error': 'Failed to load profile'}

        if 'error' in zonefile:
            return zonefile
        
        else:
            return self.success_response( {'profile': profile} )


    def verify_data_timestamp( self, datum ):
        """
        Verify that the mutable timestamp is fresh,
        and that the datum has a valid timestamp.
        Return {'status': True} on success
        Return {'error': ...} on error
        """
        
        # needs a timestamp 
        if 'timestamp' not in datum.keys():
            log.debug("Datum has no timestamp")
            return {'error': 'Datum has no timestamp'}

        if type(datum['timestamp']) not in [int, long, float]:
            log.debug("Datum has invalid timestamp type")
            return {'error': 'Invalid timestamp type'}

        timestamp = datum['timestamp']

        # timestamp needs to be fresh 
        now = time.time()
        if abs(now - timestamp) > 30:
            log.debug("Out-of-sync timestamp: |%s - %s| == %s" % (now, timestamp, abs(now, timestamp)))
            return {'error': 'Invalid timestamp'}

        else:
            log.debug("Client and server differ by %s seconds" % abs(now - timestamp))
            return {'status': True}


    def verify_profile_hash( self, name, name_rec, zonefile_dict, profile_txt, prev_profile_hash, sigb64, user_data_pubkey ):
        """
        DEPRECATED

        Verify that the uploader signed the profile's previous hash.
        Return {'status': True} on success
        Return {'error': ...} on error
        """

        conf = get_blockstack_opts()
        if not conf['serve_profiles']:
            return {'error': 'No data'}

        profile_storage_drivers = conf['profile_storage_drivers'].split(",")
        zonefile_storage_drivers = conf['zonefile_storage_drivers'].split(",")

        # verify that the previous profile actually does have this hash 
        try:
            old_profile_txt, zonefile = blockstack_client.get_profile(name, profile_storage_drivers=profile_storage_drivers, zonefile_storage_drivers=zonefile_storage_drivers,
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

        return {'status': True}


    def load_mutable_data( self, name, data_txt, max_len=RPC_MAX_PROFILE_LEN, storage_drivers=None ):
        """
        Parse and authenticate user-given data
        Return {'status': True, 'data': data dict, 'data_pubkey': public key, 'owner': True|False} on success
        Return {'error': ...} on failure
        """

        if type(name) not in [str, unicode]:
            return {'error': 'Invalid name'}

        if not is_name_valid(name):
            return {'error': 'Invalid name'}

        if type(data_txt) not in [str, unicode]:
            return {'error': 'Data must be a serialized JWT'}

        if len(data_txt) > RPC_MAX_PROFILE_LEN:
            return {'error': 'Serialized data is too big'}

        conf = get_blockstack_opts()
        if conf['redirect_data']:
            # redirect!
            servers = filter(lambda x: len(x) > 0, conf['data_servers'].split(','))
            return {'error': 'redirect', 'servers': servers}

        zonefile_storage_drivers = conf['zonefile_storage_drivers'].split(",")
        zonefile_dict = None

        # find name record 
        name_rec = self.get_name_rec(name)
        if 'error' in name_rec:
            return name_rec

        if name_rec is None:
            log.debug("No name for '%s'" % name)
            return {'error': 'No such name'}

        # find zonefile 
        zonefile_data = self.get_zonefile_data_by_name( conf, name, zonefile_storage_drivers, name_rec=name_rec )
        if zonefile_data is None:
            log.debug("No zonefile for '%s'" % name)
            return {'error': 'No zonefile'}

        # must be standard 
        try:
            zonefile_dict = blockstack_zones.parse_zone_file( zonefile_data )
        except:
            log.debug("Non-standard zonefile for %s" % name)
            return {'error': 'Nonstandard zonefile'}

        # first, try to verify with zonefile public key (if one is given)
        user_data_pubkey = blockstack_client.user_zonefile_data_pubkey( zonefile_dict )
        user_data = None

        if user_data_pubkey is not None:
            try:
                user_data = blockstack_client.parse_signed_data( data_txt, user_data_pubkey )
                assert type(user_data) in [dict], "Failed to parse data"
            except Exception, e:
                log.exception(e)
                log.debug("Failed to authenticate data")
                return {'error': 'Failed to authenticate data'}
        
        else:
            log.warn("Falling back to verifying with owner address")
            owner_addr = name_rec.get('address', None)
            if owner_addr is None:
                log.debug("No owner address")
                return {'error': 'No owner address'}

            try:
                user_data = blockstack_client.parse_signed_data( data_txt, None, public_key_hash=owner_addr )
                assert type(user_data) in [dict], "Failed to parse data"

                # seems to have worked
                data_jwt = json.loads(data_txt)
                if type(data_jwt) == list:
                    data_jwt = data_jwt[0]

                user_data_pubkey = data_jwt['parentPublicKey']

            except Exception, e:
                log.exception(e)
                log.debug("Failed to authenticate data")
                return {'error': 'Failed to authenticate data'}

        # authentic!  try to verify via timestamp
        res = self.verify_data_timestamp( user_data )
        if 'error' in res:
            log.debug("Failed to verify with timestamp.")
            return {'error': 'Invalid timestamp', 'reason': 'timestamp', 'data_pubkey': user_data_pubkey, 'zonefile': zonefile_dict}

        return {'status': True, 'data': user_data, 'data_pubkey': user_data_pubkey}


    def rpc_put_profile(self, name, profile_txt, prev_profile_hash_or_ignored, sigb64_or_ignored, **con_info ):
        """
        Store a profile for a particular name
        @profile_txt must be a serialized JWT signed by the key in the user's zonefile.
        @prev_profile_hash_or_ignored, if given, must be the hex string representation of the hash of the previous profile
           (this argument is obsolete in 0.14.1)
        @sigb64_or_ignored, if given, must cover prev_profile_hash+profile_txt
           (this argument is obsolete in 0.14.1)
        """

        conf = get_blockstack_opts()
        if not conf['serve_profiles']:
            return {'error': 'No data'}

        data_info = self.load_mutable_data(name, profile_txt, max_len=RPC_MAX_PROFILE_LEN)
        if 'error' in data_info:
            if data_info.has_key('reason') and data_info['reason'] == 'timestamp' and data_info.has_key('data_pubkey') and data_info.has_key('zonefile'):

                user_data_pubkey = data_info['data_pubkey']
                zonefile_dict = data_info['zonefile']

                # try hash-based verification (deprecated)
                res = self.verify_profile_hash( name, name_rec, zonefile_dict, profile_txt, prev_profile_hash_or_ignored, sigb64_or_ignored, user_data_pubkey )
                if 'error' in res:
                    log.debug("Failed to verify profile by owner hash")
                    return {'error': 'Failed to validate profile: invalid or missing timestamp and/or previous hash'}

            else:
                return data_info
       
        res = storage_enqueue_profile( name, str(profile_txt) )
        if not res:
            log.error('Failed to queue {}-byte profile for {}'.format(len(profile_txt), name))
            return {'error': 'Failed to queue profile'}
        
        log.debug("Queued {}-byte profile for {}".format(len(profile_txt), name))
        return self.success_response( {'num_replicas': 1, 'num_failures': 0} )


    def rpc_put_mutable_data(self, blockchain_id, data_txt, **con_info ):
        """
        Store mutable data
        @data_txt is the data to store

        Only works if the mutable data payload has an associated blockchain ID that matches @blockchain_id

        This method does NOT need access to the database.
        However, it only works if the caller has a registered name.
        """
        if type(data_txt) not in [str, unicode]:
            return {'error': 'Data must be a serialized JWT'}

        # must be v2 or later 
        if not data_txt.startswith('bsk2.'):
            return {'error': 'Obsolete data format'}

        data_info = self.load_mutable_data(blockchain_id, data_txt, max_len=RPC_MAX_DATA_LEN)
        if 'error' in data_info:
            log.debug("Failed to parse mutable data: {}".format(data_info['error']))
            return data_info

        user_data = data_info['data']

        # must be mutable data 
        try:
            jsonschema.validate(user_data, blockstack_client.schemas.DATA_BLOB_SCHEMA)
        except ValidationError as ve:
            log.debug("User data is not a mutable data blob")
            return {'error': 'Not a mutable data blob'}

        # must match name 
        if not user_data.has_key('blockchain_id') or blockchain_id != user_data['blockchain_id']:
            log.debug("Data has no blockchain_id, or does not match {} (got {})".format(blockchain_id, user_data.get('blockchain_id', "None")))
            return {'error': 'Failed to validate data: invalid or missing blockchain ID'}

        fq_data_id = user_data['fq_data_id']

        res = storage_enqueue_data( blockchain_id, fq_data_id, str(data_txt) )
        if not res:
            log.error('Failed to queue {}-byte datum for {}'.format(len(data_txt), blockchain_id))
            return {'error': 'Failed to queue datum'}
        
        log.debug("Queued {}-byte datum from {}".format(len(data_txt), blockchain_id))
        return self.success_response( {'num_replicas': 1, 'num_failures': 0} )


    def rpc_get_data_servers( self, **con_info ):
        """
        Get the list of data servers
        Return {'status': True, 'servers': ...} on success
        Return {'error': ...} on error
        """
        conf = get_blockstack_opts()
        if not conf.get('redirect_data', False):
            return {'error': 'No data servers'}

        servers = filter(lambda x: len(x) > 0, conf['data_servers'].split(','))
        return {'status': True, 'servers': servers}


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

        log.debug("Live peers to %s:%s: %s" % (client_host, client_port, peer_list))
        return self.success_response( {'peers': peer_list} )

    
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

        return self.success_response( {'inv': base64.b64encode(zonefile_inv) } )


    def rpc_get_all_neighbor_info( self, **con_info ):
        """
        For network simulator purposes only!
        This method returns all of our peer info.

        DISABLED BY DEFAULT
        """
        if os.environ.get("BLOCKSTACK_ATLAS_NETWORK_SIMULATION") != "1":
            return {'error': 'No such method'}

        return atlas_get_all_neighbors()
        
   
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


class BlockstackStoragePusher( threading.Thread ):
    """
    worker thread to push data into storage providers,
    so we don't block the RPC server.
    """
    def __init__(self, conf, queue_path):
        threading.Thread.__init__(self)
        self.running = False
        self.accepting = True
        self.queue_path = queue_path
        self.config = conf

        self.zonefile_dir = conf.get('zonefile_dir', None)
        self.zonefile_storage_drivers = conf['zonefile_storage_drivers'].split(",")
        self.profile_storage_drivers = conf['profile_storage_drivers'].split(",")
        self.data_storage_drivers = conf['data_storage_drivers'].split(',')
        self.atlasdb_path = conf.get('atlasdb_path', None)

        self.zonefile_queue_id = "push-zonefile"
        self.profile_queue_id = "push-profile"
        self.data_queue_id = "push-data"

        # do not store data to ourselves
        if 'blockstack_server' in self.zonefile_storage_drivers:
            log.warn("Removing 'blockstack_server' from zone file storage drivers")
            self.zonefile_storage_drivers.remove('blockstack_server')

        if 'blockstack_server' in self.profile_storage_drivers:
            log.warn("Removing 'blockstack_server' from profile storage drivers")
            self.profile_storage_drivers.remove('blockstack_server')

        if 'blockstack_server' in self.data_storage_drivers:
            log.warn("Removing 'blockstack_server' from data storage drivers")
            self.data_storage_drivers.remove('blockstack_server')


    def enqueue_zonefile( self, txid, zonefile_hash, zonefile_data ):
        """
        Enqueue a zonefile for replication
        """
        if type(zonefile_data) not in [str, unicode]:
            log.debug("Invalid zonefile data type")
            return False
        
        if txid is not None and type(txid) not in [str, unicode]:
            log.debug("Invalid txid type")
            return False

        if type(zonefile_hash) not in [str, unicode]:
            log.debug("Invalid zonefile hash type")
            return False

        txid = str(txid)
        zonefile_hash = str(zonefile_hash)
        zonefile_data = str(zonefile_data)

        try:
            # NOTE: we don't use or rely on the name here, but use the zonefile hash instead
            existing = queue_findone( self.zonefile_queue_id, zonefile_hash, path=self.queue_path )
            if len(existing) > 0:
                log.error("Already queued {}".format(zonefile_hash))
                return False

            log.debug("Queue {}-byte zonefile".format(len(zonefile_data)))

            # NOTE: we don't use or rely on the name here, but use the zonefile hash instead
            res = queue_append( self.zonefile_queue_id, zonefile_hash, txid, block_height=0, zonefile_hash=zonefile_hash, zonefile_data=zonefile_data, path=self.queue_path )
            assert res
            return True
        except Exception as e:
            log.exception(e)
            return False


    def enqueue_profile_or_data( self, blockchain_id, queue_id, data ):
        """
        Enqueue a profile or mutable data for replication
        """
        if type(blockchain_id) not in [str, unicode]:
            log.debug("Invalid name type")
            return False

        if type(data) not in [str, unicode]:
            log.debug("Invalid profile or data type")
            return False

        blockchain_id = str(blockchain_id)
        data = str(data)

        try:
            existing = queue_findone( queue_id, blockchain_id, path=self.queue_path )
            if len(existing) > 0:
                log.error("Already queued something for {}".format(blockchain_id))
                return False

            log.debug("Queue {}-byte datum for {}".format(len(data), blockchain_id))
            res = queue_append( queue_id, blockchain_id, "00" * 32, block_height=0, profile=data, path=self.queue_path )
            assert res
            return True
        except Exception as e:
            log.exception(e)
            return False


    def enqueue_profile( self, blockchain_id, profile_data ):
        """
        Enqueue a profile for replication
        """
        return self.enqueue_profile_or_data(blockchain_id, self.profile_queue_id, profile_data)


    def enqueue_data( self, blockchain_id, fq_data_id, data_txt ):
        """
        Enqueue a mutable datum for replication
        """
        data_payload = {
            'data_txt': data_txt,
            'fq_data_id': fq_data_id
        }

        return self.enqueue_profile_or_data(blockchain_id, self.data_queue_id, json.dumps(data_payload))


    def store_one_zonefile(self):
        """
        Find and store one zonefile
        """
        # find a zonefile
        entries = queue_findall( self.zonefile_queue_id, limit=1, path=self.queue_path )
        if entries is None or len(entries) == 0:
            # empty 
            return False

        entry = entries[0]
        res = store_zonefile_data_to_storage( str(entry['zonefile']), entry['tx_hash'], required=self.zonefile_storage_drivers, skip=['blockstack_server'], cache=False, zonefile_dir=self.zonefile_dir, tx_required=False )
        if not res:
            log.error("Failed to store zonefile {} ({} bytes)".format(entry['zonefile_hash'], len(entry['zonefile'])))
            return False

        log.debug("Replicated zonefile {} ({} bytes)".format(entry['zonefile_hash'], len(entry['zonefile'])))

        if self.atlasdb_path is not None:
            # mark present in the atlas subsystem 
            atlasdb_set_zonefile_present( str(entry['zonefile_hash']), True, path=self.atlasdb_path )

        queue_removeall( entries, path=self.queue_path )
        return res


    def store_one_profile_or_datum(self, queue_id, storage_drivers):
        """
        Find and store one profile or datum
        """
        entries = queue_findall( queue_id, limit=1, path=self.queue_path )
        if entries is None or len(entries) == 0:
            # empty 
            return False

        entry = entries[0]
        
        blockchain_id = str(entry['fqu'])
        fq_data_id = None
        data_txt = None
        try:
            # mutable data?
            payload = json.loads(entry['profile'])
            
            assert isinstance(payload, dict)
            assert payload.has_key('fq_data_id')
            assert payload.has_key('data_txt')

            fq_data_id = str(payload['fq_data_id'])
            data_txt = str(payload['data_txt'])

            log.debug("mutable datum: {}".format(entry['profile']))
            log.debug("mutable datum txt: {}".format(data_txt))
        except AssertionError:
            
            # profile 
            fq_data_id = blockchain_id
            data_txt = str(entry['profile'])

        except Exception as e:
            log.exception(e)
            log.debug("entry = {}".format(entry))
            log.debug("Abandoning data from {}".format(blockchain_id))
            queue_removeall( entries, path=self.queue_path )
            return False
        
        success = store_mutable_data_to_storage( blockchain_id, fq_data_id, data_txt, required=storage_drivers, skip=['blockstack_server'])
        if not success:
            log.error("Failed to store data for {} ({} bytes)".format(blockchain_id, len(data_txt)))
            queue_removeall( entries, path=self.queue_path )
            return False

        log.debug("Replicated data for {} ({} bytes)".format(blockchain_id, len(data_txt)))
        queue_removeall( entries, path=self.queue_path )
        return True


    def store_one_profile(self):
        """
        Find and store one profile
        """
        return self.store_one_profile_or_datum(self.profile_queue_id, self.profile_storage_drivers)


    def store_one_datum(self):
        """
        Find and store one mutable datum
        """
        return self.store_one_profile_or_datum(self.data_queue_id, self.data_storage_drivers)


    def run(self):
        """
        Push zonefiles and profiles
        """
        self.running = True
        while self.running:
          
            res_zonefile = self.store_one_zonefile()
            res_profile = self.store_one_profile()
            res_data = self.store_one_datum()

            if not res_zonefile and not res_profile and not res_data:
                time.sleep(1.0)
                continue

        log.debug("StoragePusher thread exit")
        self.running = False


    def signal_stop(self):
        self.running = False
        log.debug("StoragePusher signal stop")


    def drain(self):
        """
        Stop taking requests and wait for the queue to drain
        """
        self.accepting = False
        return


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


def get_storage_queue_path():
   """
   Path to the on-disk storage queue
   """
   working_dir = virtualchain.get_working_dir()
   db_filename = blockstack_state_engine.get_virtual_chain_name() + ".queue"
   return os.path.join( working_dir, db_filename )


def storage_start( blockstack_opts ):
    """
    Start the global data-pusher thread
    """
    global storage_pusher
   
    storage_queue = get_storage_queue_path()
    storage_pusher = BlockstackStoragePusher( blockstack_opts, storage_queue )
    log.debug("Starting storage pusher")
    storage_pusher.start()


def storage_stop():
    """
    Stop the global data-pusher thread
    """
    global storage_pusher

    # if we're testing, then drain the storage queue completely 
    if os.environ.get("BLOCKSTACK_TEST") == "1":
        log.debug("Draining storage pusher queue")
        storage_pusher.drain()

    log.debug("Shutting down storage pusher")
    storage_pusher.signal_stop()
    storage_pusher.join()
    log.debug("Storage pusher joined")


def storage_enqueue_zonefile( txid, zonefile_hash, zonefile_data ):
    """
    Queue a zonefile for replication
    """
    global storage_pusher
    return storage_pusher.enqueue_zonefile( txid, zonefile_hash, zonefile_data )


def storage_enqueue_profile( name, profile_data ):
    """
    Queue a profile for replication
    """
    global storage_pusher
    return storage_pusher.enqueue_profile( name, profile_data )


def storage_enqueue_data( blockchain_id, fq_data_id, datum ):
    """
    Queue mutable data for replication
    """
    global storage_pusher
    return storage_pusher.enqueue_data( blockchain_id, fq_data_id, datum )


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

    timeout = 1.0
    dead = False

    for i in xrange(0, 5):
        # try to kill the main supervisor
        pid_file = get_pidfile_path()
        if not os.path.exists(pid_file):
            dead = True
            break

        try:
            fin = open(pid_file, "r")
        except Exception, e:
            pass

        else:
            pid_data = fin.read().strip()
            fin.close()

            try:
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
            
            except:
                log.info("Corrupt PID file.  Please make sure all instances of this program have stopped and remove {}".format(pid_file))
                os.abort()

            # is it actually dead?
            try:
                res = blockstack_client.ping()
            except socket.error as se:
                # dead?
                if se.errno == errno.ECONNREFUSED:
                    # couldn't connect, so infer dead
                    try:
                        os.kill(pid, 0)
                        log.info("Server %s is not dead yet..." % pid)

                    except OSError, oe:
                        log.info("Server %s is dead to us" % pid)
                        dead = True
                        break
                else:
                    continue
            
            log.info("Server %s is still running; trying again in %s seconds" % (pid, timeout))
            time.sleep(timeout)
            timeout *= 2

    if not dead and kill:
        # be sure to clean up the pidfile
        log.info("Killing server %s" % pid)
        clean = True
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception, e:
            pass
   
    if clean:
        # blow away the pid file 
        try:
            os.unlink(pid_file)
        except:
            pass

    
    log.debug("Blockstack server stopped")
    

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

    Return True if we should continue indexing
    Return False if not
    Aborts on error
    """
    
    if not is_indexer():
        # nothing to do
        return True

    bt_opts = get_bitcoin_opts() 
    start_block, current_block = get_index_range()

    db = get_db_state()
    old_lastblock = db.lastblock

    if start_block is None and current_block is None:
        log.error("Failed to find block range")
        db.close()
        return False

    # bring the db up to the chain tip.
    log.debug("Begin indexing (up to %s)" % current_block)
    set_indexing( True )
    rc = virtualchain_hooks.sync_blockchain( bt_opts, current_block, expected_snapshots=expected_snapshots, tx_filter=blockstack_tx_filter )
    set_indexing( False )
   
    db.close()

    if not rc:
        log.debug("Stopped indexing at %s" % current_block)
        return rc

    # synchronize atlas db
    # this is a recovery path--shouldn't be necessary unless
    # we're starting from a lack of atlas.db state (i.e. an older
    # version of the server, or a removed/corrupted atlas.db file).
    # TODO: this is racy--we also do this in virtualchain-hooks
    blockstack_opts = get_blockstack_opts()
    if blockstack_opts.get('atlas', False):
        db = get_db_state()
        if old_lastblock < db.lastblock:
            log.debug("Synchronize Atlas DB from %s to %s" % (old_lastblock+1, db.lastblock+1))
            zonefile_dir = blockstack_opts.get('zonefiles', get_zonefile_dir())
            atlasdb_sync_zonefiles( db, old_lastblock+1, zonefile_dir=zonefile_dir )

        db.close()

    log.debug("End indexing (up to %s)" % current_block)
    return rc


def blockstack_exit( atlas_state ):
    """
    Shut down the server on exit(3)
    """
    if atlas_state is not None:
        atlas_node_stop( atlas_state )

    storage_stop()


def blockstack_signal_handler( sig, frame ):
    """
    Fatal signal handler
    """
    set_running(False)


def run_server( foreground=False, expected_snapshots=GENESIS_SNAPSHOT, port=None ):
    """
    Run the blockstackd RPC server, optionally in the foreground.
    """
    bt_opts = get_bitcoin_opts()
    blockstack_opts = get_blockstack_opts()
    indexer_log_file = get_logfile_path()
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
   
    # set up signals 
    signal.signal( signal.SIGINT, blockstack_signal_handler )
    signal.signal( signal.SIGQUIT, blockstack_signal_handler )
    signal.signal( signal.SIGTERM, blockstack_signal_handler )

    # put supervisor pid file
    put_pidfile( pid_file, os.getpid() )

    # clear indexing state
    set_indexing( False )

    # make sure client is initialized 
    get_blockstack_client_session()

    # get db state
    db = get_db_state()

    # start atlas node
    atlas_state = atlas_start( blockstack_opts, db, port )
    atexit.register( blockstack_exit, atlas_state )
  
    db.close()

    # start storage 
    storage_start( blockstack_opts )

    # start API server
    rpc_start(port)
    set_running( True )

    # clear any stale indexing state
    set_indexing( False )
    log.debug("Begin Indexing")

    running = True
    while is_running():

        try:
           running = index_blockchain(expected_snapshots=expected_snapshots)
        except Exception, e:
           log.exception(e)
           log.error("FATAL: caught exception while indexing")
           os.abort()
       
        if not running:
            break

        # wait for the next block
        deadline = time.time() + REINDEX_FREQUENCY
        while time.time() < deadline and is_running():
            try:
                time.sleep(1.0)
            except:
                # interrupt
                break
     
    log.debug("End Indexing")
    set_running( False )

    # stop API server
    log.debug("Stopping API server")
    rpc_stop()

    # stop atlas node 
    log.debug("Stopping Atlas node")
    atlas_stop( atlas_state )
    atlas_state = None

    # stopping storage 
    log.debug("Stopping storage pusher")
    storage_stop()

    # close logfile
    if logfile is not None:
        logfile.flush()
        logfile.close()

    try:
        os.unlink( pid_file )
    except:
        pass

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
    virtualchain.setup_virtualchain( impl=blockstack_state_engine )
    working_dir = virtualchain.get_working_dir()

    if not os.path.exists( working_dir ):
        os.makedirs( working_dir, 0700 )

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


def check_and_set_envars( argv ):
    """
    Go through argv and find any special command-line flags
    that set environment variables that affect multiple modules.

    If any of them are given, then set them in this process's
    environment and re-exec the process without the CLI flags.

    argv should be like sys.argv:  argv[0] is the binary

    Does not return on re-exec.
    Return True if there was no need to re-exec
    Returns False on error.
    """
    special_flags = {
        '--working-dir': {
            'arg': True,
            'envar': 'VIRTUALCHAIN_WORKING_DIR',
        },
        '--debug': {
            'arg': False,
            'envar': 'BLOCKSTACK_DEBUG',
        },
        '--verbose': {
            'arg': False,
            'envar': 'BLOCKSTACK_DEBUG',
        },
        '--testnet': {
            'arg': False,
            'envar': 'BLOCKSTACK_TESTNET'
        },
    }

    cli_envs = {}
    new_argv = [argv[0]]

    for i in xrange(1, len(argv)):

        arg = argv[i]
        value = None

        for special_flag in special_flags.keys():

            if not arg.startswith( special_flag ):
                continue

            if special_flags[special_flag]['arg']:
                if '=' in arg:
                    argparts = arg.split("=")
                    value_parts = argparts[1:]
                    value = '='.join(value_parts)

                elif i + 1 < len(argv):
                    value = argv[i+1]
                    i += 1

                else:
                    print >> sys.stderr, "%s requires an argument" % special_flag
                    return False
            else:
                # just set
                value = "1"

            break

        if value is not None:
            # recognized
            cli_envs[ special_flags[special_flag]['envar'] ] = value

        else:
            # not recognized
            new_argv.append(arg)

    if len(cli_envs.keys()) > 0:
        # re-exec
        for cli_env, cli_env_value in cli_envs.items():
            os.environ[cli_env] = cli_env_value

        os.execv( new_argv[0], new_argv )

    return True


def load_expected_snapshots( snapshots_path ):
    """
    Load expected consensus hashes from a .snapshots file.
    Return the snapshots as a dict on success
    Return None on error
    """
    # use snapshots?
    expected_snapshots = {}
    try:
        with open(snapshots_path, "r") as f:
            snapshots_json = f.read()

        snapshots_data = json.loads(snapshots_json)
        assert 'snapshots' in snapshots_data.keys(), "Not a valid snapshots file"

        # extract snapshots: map int to consensus hash
        for (block_id_str, consensus_hash) in snapshots_data['snapshots'].items():
            expected_snapshots[ int(block_id_str) ] = str(consensus_hash)

        return expected_snapshots

    except Exception, e:
        log.exception(e)
        log.error("Failed to read expected snapshots from '%s'" % snapshots_path)
        return None


def run_blockstackd():
   """
   run blockstackd
   """

   check_and_set_envars( sys.argv )
   argparser = setup( return_parser=True )
   if argparser is None:
       # fatal error
       os.abort()

   # need sqlite3 
   sqlite3_tool = sqlite3_find_tool()
   if sqlite3_tool is None:
       print 'Failed to find sqlite3 tool in your PATH.  Cannot continue'
       sys.exit(1)
       
   working_dir = virtualchain.get_working_dir()

   # get RPC server options
   subparsers = argparser.add_subparsers(
      dest='action', help='the action to be taken')

   parser = subparsers.add_parser(
      'start',
      help='start the blockstackd server')
   parser.add_argument(
      '--foreground', action='store_true',
      help='start the blockstack server in foreground')
   parser.add_argument(
      '--expected-snapshots', action='store',
      help='path to a .snapshots file with the expected consensus hashes')
   parser.add_argument(
      '--port', action='store',
      help='port to bind on')
   parser.add_argument(
      '--no-indexer', action='store_true',
      help='do not index the blockchain')

   parser = subparsers.add_parser(
      'stop',
      help='stop the blockstackd server')

   parser = subparsers.add_parser(
      'configure',
      help='reconfigure the blockstackd server')

   parser = subparsers.add_parser(
      'clean',
      help='remove all blockstack database information')
   parser.add_argument(
      '--force', action='store_true',
      help='Do not confirm the request to delete.')

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
      '--expected-snapshots', action='store',
      help='path to a .snapshots file with the expected consensus hashes')

   parser = subparsers.add_parser(
      'importdb',
      help='import an existing trusted database')
   parser.add_argument(
      'db_path',
      help='the path to the database')

   parser = subparsers.add_parser(
      'version',
      help='Print version and exit')

   parser = subparsers.add_parser(
      'fast_sync',
      help='fetch and verify a recent known-good name database')
   parser.add_argument(
      'url',
      help='the URL to the name database snapshot')
   parser.add_argument(
      'public_keys', nargs='?',
      help='a CSV of public keys to use to verify the snapshot')
   parser.add_argument(
      '--num_required', action='store',
      help='the number of required signature matches')

   parser = subparsers.add_parser(
      'fast_sync_snapshot',
      help='make a fast-sync snapshot')
   parser.add_argument(
      'private_key',
      help='a private key to use to sign the snapshot')
   parser.add_argument(
      'path',
      help='the path to the resulting snapshot')
   parser.add_argument(
      'block_id', nargs='?',
      help='the block ID of the backup to use to make a fast-sync snapshot')

   parser = subparsers.add_parser(
      'fast_sync_sign',
      help='sign an existing fast-sync snapshot')
   parser.add_argument(
      'path', action='store',
      help='the path to the snapshot')
   parser.add_argument(
      'private_key', action='store',
      help='a private key to use to sign the snapshot')

   args, _ = argparser.parse_known_args()

   if args.action == 'version':
      print "Blockstack version: %s" % VERSION
      sys.exit(0)

   if args.action == 'start':
      global has_indexer
      has_indexer = (not args.no_indexer)

      expected_snapshots = {}

      if is_indexer():
          if config.is_indexing():
              # The server didn't shut down properly.
              # restore from back-up before running
              log.warning("Server did not shut down properly.  Restoring state from last known-good backup.")

              # move any existing db information out of the way so we can start fresh.
              state_paths = BlockstackDB.get_state_paths()
              need_backup = reduce( lambda x, y: x or y, map(lambda sp: os.path.exists(sp), state_paths), False )
              if need_backup:

                  # have old state.  keep it around for later inspection
                  target_dir = os.path.join( working_dir, 'crash.{}'.format(time.time()))
                  os.makedirs(target_dir)
                  for sp in state_paths:
                      if os.path.exists(sp):
                         target = os.path.join( target_dir, os.path.basename(sp) )
                         shutil.move( sp, target )
              
                  log.warning("State from crash stored to '{}'".format(target_dir))

              blockstack_backup_restore( working_dir, None )
              config.set_indexing(False)

              log.warning("State reverted")

          # use snapshots?
          if args.expected_snapshots is not None:
              expected_snapshots = load_expected_snapshots( args.expected_snapshots )
              if expected_snapshots is None:
                  sys.exit(1)

      if os.path.exists( get_pidfile_path() ):
          log.error("Blockstackd appears to be running already.  If not, please run '%s stop'" % (sys.argv[0]))
          sys.exit(1)

      if args.foreground:
          log.info('Initializing blockstackd server in foreground (working dir = \'%s\')...' % (working_dir))
      else:
          log.info('Starting blockstackd server (working_dir = \'%s\') ...' % (working_dir))

      if args.port is not None:
          log.info("Binding on port %s" % int(args.port))
      else:
          args.port = RPC_SERVER_PORT

      exit_status = run_server( foreground=args.foreground, expected_snapshots=expected_snapshots, port=int(args.port) )
      if args.foreground:
          log.info("Service endpoint exited with status code %s" % exit_status )

   elif args.action == 'stop':
      stop_server(kill=True)

   elif args.action == 'configure':
      reconfigure()

   elif args.action == 'restore':
      block_number = args.block_number
      if block_number is not None:
         block_number = int(block_number)

      blockstack_backup_restore( working_dir, args.block_number )

   elif args.action == 'clean':
      clean( confirm=(not args.force) )

   elif args.action == 'rebuilddb':

      resume_dir = None
      if hasattr(args, 'resume_dir') and args.resume_dir is not None:
          resume_dir = args.resume_dir

      final_consensus_hash = rebuild_database( int(args.end_block_id), args.db_path, start_block=int(args.start_block_id), resume_dir=resume_dir )
      print "Rebuilt database in '%s'" % working_dir
      print "The final consensus hash is '%s'" % final_consensus_hash

   elif args.action == 'verifydb':
      db_path = virtualchain.get_db_filename()
      working_db_path = os.path.join( working_dir, os.path.basename( db_path ) )
      expected_snapshots = None
      
      if args.expected_snapshots is not None:
          expected_snapshots = load_expected_snapshots( args.expected_snapshots )
          if expected_snapshots is None:
              sys.exit(1)

      rc = verify_database( args.consensus_hash, int(args.block_id), args.db_path, working_db_path=working_db_path, expected_snapshots=expected_snapshots )
      if rc:
          # success!
          print "Database is consistent with %s" % args.consensus_hash
          print "Verified files are in '%s'" % working_dir

      else:
          # failure!
          print "Database is NOT CONSISTENT"

   elif args.action == 'importdb':
      # re-target working dir so we move the database state to the correct location
      old_working_dir = virtualchain.get_working_dir()
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

   elif args.action == 'fast_sync_snapshot':
      # create a fast-sync snapshot from the last backup 
      dest_path = str(args.path)
      private_key = str(args.private_key)
      try:
          keylib.ECPrivateKey(private_key)
      except:
          print "Invalid private key"
          sys.exit(1)

      block_id = None
      if args.block_id is not None:
          block_id = int(args.block_id)

      rc = fast_sync_snapshot( dest_path, private_key, block_id )
      if not rc:
          print "Failed to create snapshot"
          sys.exit(1)

   elif args.action == 'fast_sync_sign':
      # sign an existing fast-sync snapshot with an additional key 
      snapshot_path = str(args.path)
      private_key = str(args.private_key)
      try:
          keylib.ECPrivateKey(private_key)
      except:
          print "Invalid private key"
          sys.exit(1)

      rc = fast_sync_sign_snapshot( snapshot_path, private_key )
      if not rc:
          print "Failed to sign snapshot"
          sys.exit(1)

   elif args.action == 'fast_sync':
      # fetch the snapshot and verify it 
      url = str(args.url)
      public_keys = config.FAST_SYNC_PUBLIC_KEYS

      if args.public_keys is not None:
          public_keys = args.public_keys.split(',')
          for pubk in public_keys:
              try:
                  keylib.ECPublicKey(pubk)
              except:
                  print "Invalid public key"
                  sys.exit(1)
      
      num_required = len(public_keys)
      if args.num_required:
          num_required = int(args.num_required)

      print "Synchronizing from snapshot.  This will take about 10-15 minutes."

      rc = fast_sync_import(working_dir, url, public_keys=public_keys, num_required=num_required)
      if not rc:
          print 'fast_sync failed'
          sys.exit(1)

      print "Node synchronized!  Node state written to {}".format(working_dir)
      print "Start your node with `blockstack-core start`"
      print "Pass `--debug` for extra output."

if __name__ == '__main__':

   run_blockstackd()
