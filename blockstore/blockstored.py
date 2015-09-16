#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org
    
    This file is part of Blockstore
    
    Blockstore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    Blockstore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore.  If not, see <http://www.gnu.org/licenses/>.
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

from ConfigParser import SafeConfigParser

import pybitcoin
from txjsonrpc.netstring import jsonrpc

from lib import nameset as blockstore_state_engine
from lib import get_db_state
from lib.config import REINDEX_FREQUENCY, TESTSET, DEFAULT_DUST_FEE
from lib import *

import virtualchain 
log = virtualchain.session.log 

# global variables, for use with the RPC server and the twisted callback
blockstore_opts = None
bitcoind = None
bitcoin_opts = None
utxo_opts = None
blockchain_client = None 
blockchain_broadcaster = None
indexer_pid = None

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
         new_bitcoind = virtualchain.connect_bitcoind( bitcoin_opts )
         
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


def get_utxo_opts():
   """
   Get UTXO provider options.
   """
   global utxo_opts
   return utxo_opts


def get_blockstore_opts():
   """
   Get blockstore configuration options.
   """
   global blockstore_opts 
   return blockstore_opts 


def set_bitcoin_opts( new_bitcoin_opts ):
   """
   Set new global bitcoind operations
   """
   global bitcoin_opts 
   bitcoin_opts = new_bitcoin_opts
   
   
def set_utxo_opts( new_utxo_opts ):
   """
   Set new global chian.com options 
   """
   global utxo_opts 
   utxo_opts = new_utxo_opts
   
   
def get_pidfile_path():
   """
   Get the PID file path.
   """
   working_dir = virtualchain.get_working_dir()
   pid_filename = blockstore_state_engine.get_virtual_chain_name() + ".pid"
   return os.path.join( working_dir, pid_filename )


def get_tacfile_path():
   """
   Get the TAC file path for our service endpoint.
   Should be in the same directory as this module.
   """
   working_dir = os.path.abspath(os.path.dirname(__file__))
   tac_filename = blockstore_state_engine.get_virtual_chain_name() + ".tac"
   return os.path.join( working_dir, tac_filename )


def get_logfile_path():
   """
   Get the logfile path for our service endpoint.
   """
   working_dir = virtualchain.get_working_dir()
   logfile_filename = blockstore_state_engine.get_virtual_chain_name() + ".log"
   return os.path.join( working_dir, logfile_filename )


def get_state_engine():
   """
   Get a handle to the blockstore virtual chain state engine.
   """
   return get_db_state()
   
   
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
        

def die_handler_server(signal, frame):
    """
    Handle Ctrl+C for server subprocess
    """
    
    log.info('Exiting blockstored server')
    stop_server()
    sys.exit(0)



def die_handler_indexer(signal, frame):
    """
    Handle Ctrl+C for indexer processe
    """
    
    db = get_state_engine()
    virtualchain.stop_sync_virtualchain( db )
    sys.exit(0)


def json_traceback():
    exception_data = traceback.format_exc().splitlines()
    return {
        "error": exception_data[-1],
        "traceback": exception_data
    }

 
def get_utxo_provider_client():
   """
   Get or instantiate our blockchain UTXO provider's client.
   Return None if we were unable to connect
   """
   
   # acquire configuration (which we should already have)
   blockstore_opts, blockchain_opts, utxo_opts, dht_opts = configure( interactive=False )
   
   try:
       blockchain_client = connect_utxo_provider( utxo_opts )
       return blockchain_client
   except:
       log.exception(e)
       return None 


def get_tx_broadcaster():
   """
   Get or instantiate our blockchain UTXO provider's transaction broadcaster.
   fall back to the utxo provider client, if one is not designated
   """
   
   # acquire configuration (which we should already have)
   blockstore_opts, blockchain_opts, utxo_opts, dht_opts = configure( interactive=False )
   
   # is there a particular blockchain client we want for importing?
   if 'tx_broadcaster' not in blockstore_opts:
       return get_utxo_provider_client() 
   
   broadcaster_opts = default_utxo_provider_opts( blockstore_opts['tx_broadcaster'] ) 
       
   try:
       blockchain_broadcaster = connect_utxo_provider( broadcaster_opts )
       return blockchain_broadcaster
   except:
       log.exception(e)
       return None 



def get_name_cost( name ):
    """
    Get the cost of a name, given the fully-qualified name.
    Do so by finding the namespace it belongs to (even if the namespace is being imported).
    Return None if the namespace has not been declared
    """
    db = get_state_engine()

    namespace_id = get_namespace_from_name( name )
    if namespace_id is None or len(namespace_id) == 0:
        return None
    
    namespace = db.get_namespace( namespace_id )
    if namespace is None:
        # maybe importing?
        namespace = db.get_namespace_reveal( namespace_id )
        
    if namespace is None:
        # no such namespace
        return None
    
    name_fee = price_name( get_name_from_fq_name( name ), namespace )
    return name_fee


class BlockstoredRPC(jsonrpc.JSONRPC):
    """
    Blockstored not-quote-JSON-RPC server.
    
    We say "not quite" because the implementation serves data 
    via Netstrings, not HTTP, and does not pay attention to 
    the 'id' or 'version' fields in the JSONRPC spec.
    
    This endpoint does *not* talk to a storage provider, but only 
    serves back information from the blockstore virtual chain.
    
    The client is responsible for resolving this information 
    to data, via an ancillary storage provider.
    """
    
    def jsonrpc_ping(self):
        reply = {}
        reply['status'] = "alive"
        return reply


    def jsonrpc_lookup(self, name):
        """
        Lookup the profile for a name.
        """
        
        # are we doing our initial indexing?
        if is_indexing():
            return {"error": "Indexing blockchain"}
        
        blockstore_state_engine = get_state_engine()
        name_record = blockstore_state_engine.get_name( name )
        
        if name is None:
           return {"error": "Not found."}
        
        else:
           return name_record 
        
        
    def jsonrpc_getinfo(self):
        """
        """
        
        # are we doing our initial indexing?
        if is_indexing():
            return {"error": "Indexing blockchain"}
        
        bitcoind = get_bitcoind()
        info = bitcoind.getinfo()
        reply = {}
        reply['blocks'] = info['blocks']
        
        db = get_state_engine()
        reply['consensus'] = db.get_current_consensus()
        return reply


    def jsonrpc_preorder(self, name, register_addr, privatekey):
        """ Preorder a name
        """
        
        # are we doing our initial indexing?
        if is_indexing():
            return {"error": "Indexing blockchain"}
        
        blockchain_client_inst = get_utxo_provider_client()
        if blockchain_client_inst is None:
            return {"error": "Failed to connect to blockchain UTXO provider"}
        
        db = get_state_engine()
        consensus_hash = db.get_current_consensus()
        
        if not consensus_hash:
            # consensus hash must exist
            return {"error": "Nameset snapshot not found."}
         
        if db.is_name_registered( name ):
            # name can't be registered
            return {"error": "Name already registered"}

        namespace_id = get_namespace_from_name( name )
        
        if not db.is_namespace_ready( namespace_id ):
            # namespace must be ready; otherwise this is a waste
            return {"error": "Namespace is not ready"}
        
        name_fee = get_name_cost( name )
            
        log.debug("The price of '%s' is %s satoshis" % (name, name_fee))
        
        try:
            resp = preorder_name(str(name), str(register_addr), str(consensus_hash), str(privatekey), blockchain_client_inst, name_fee, testset=TESTSET)
        except:
            return json_traceback()

        log.debug('preorder <%s, %s>' % (name, privatekey))

        return resp


    def jsonrpc_register(self, name, register_addr, privatekey, renewal_fee=None):
        """ Register a name
        """
        
        # are we doing our initial indexing?
        if is_indexing():
            return {"error": "Indexing blockchain"}
        
        blockchain_client_inst = get_utxo_provider_client()
        if blockchain_client_inst is None:
           return {"error": "Failed to connect to blockchain UTXO provider"}
        
        log.info("name: %s" % name)
        db = get_state_engine()
        
        if db.is_name_registered( name ) and renewal_fee is None:
            # *must* be given, so we don't accidentally charge
            return {"error": "Name already registered"}
        
        try:
            resp = register_name(str(name), str(register_addr), str(privatekey), blockchain_client_inst, renewal_fee=renewal_fee, testset=TESTSET)
        except:
            return json_traceback()

        return resp


    def jsonrpc_update(self, name, data_hash, privatekey):
        """
        Update a name with new data.
        """
        
        # are we doing our initial indexing?
        if is_indexing():
            return {"error": "Indexing blockchain"}
        
        log.debug('update <%s, %s, %s>' % (name, data_hash, privatekey))
        
        blockchain_client_inst = get_utxo_provider_client()
        db = get_state_engine()
        
        consensus_hash = db.get_current_consensus()
        
        if blockchain_client_inst is None:
           return {"error": "Failed to connect to blockchain UTXO provider"}
        
        try:
            resp = update_name(str(name), str(data_hash), str(consensus_hash), str(privatekey), blockchain_client_inst, testset=TESTSET)
        except:
            return json_traceback()

        
        return resp


    def jsonrpc_transfer(self, name, address, keep_data, privatekey):
        """ Transfer a name
        """
        
        # are we doing our initial indexing?
        if is_indexing():
            return {"error": "Indexing blockchain"}
        
        blockchain_client_inst = get_utxo_provider_client()
        db = get_state_engine()
        
        consensus_hash = db.get_current_consensus()
        
        if blockchain_client_inst is None:
           return {"error": "Failed to connect to blockchain UTXO provider"}
        
        try:
            resp = transfer_name(str(name), str(address), bool(keep_data), str(consensus_hash), str(privatekey), blockchain_client_inst, testset=TESTSET)
        except:
            return json_traceback()

        log.debug('transfer <%s, %s, %s>' % (name, address, privatekey))

        return resp


    def jsonrpc_renew(self, name, privatekey):
        """ Renew a name
        """
        
        # are we doing our initial indexing?
        if is_indexing():
            return {"error": "Indexing blockchain"}
        
        # renew the name for the caller
        db = get_state_engine()
        name_rec = db.get_name( name )
        if name_rec is None:
            return {"error": "Name is not registered"}
        
        # renew to the caller
        register_addr = name_rec['address']
        renewal_fee = get_name_cost( name )
        
        return self.jsonrpc_register( name, register_addr, privatekey, renewal_fee=renewal_fee )
   
   
    def jsonrpc_revoke( self, name, privatekey ):
        """ Revoke a name and all of its data.
        """
        
        # are we doing our initial indexing?
        if is_indexing():
            return {"error": "Indexing blockchain"}
        
        blockchain_client_inst = get_utxo_provider_client()
        
        if blockchain_client_inst is None:
           return {"error": "Failed to connect to blockchain UTXO provider"}
        
        try:
            resp = revoke_name(str(name), str(privatekey), blockchain_client_inst, testset=TESTSET)
        except:
            return json_traceback()
        
        log.debug("revoke <%s>" % name )
        
        return resp
       
    
    def jsonrpc_name_import( self, name, recipient_address, update_hash, privatekey ):
        """
        Import a name into a namespace.
        """
        
        # are we doing our initial indexing?
        if is_indexing():
            return {"error": "Indexing blockchain"}
        
        blockchain_client_inst = get_utxo_provider_client()
        if blockchain_client_inst is None:
           return {"error": "Failed to connect to blockchain UTXO provider"}
        
        broadcaster_client_inst = get_tx_broadcaster()
        if broadcaster_client_inst is None:
           return {"error": "Failed to connect to blockchain transaction broadcaster"}
       
        db = get_state_engine()
        
        try:
            resp = name_import( str(name), str(recipient_address), str(update_hash), str(privatekey), blockchain_client_inst, blockchain_broadcaster=broadcaster_client_inst, testset=TESTSET )
        except:
            return json_traceback()
        
        log.debug("import <%s>" % name )
        
        return resp
        
    
    def jsonrpc_namespace_preorder( self, namespace_id, register_addr, privatekey ):
        """
        Define the properties of a namespace.
        Between the namespace definition and the "namespace begin" operation, only the 
        user who created the namespace can create names in it.
        """
        
        # are we doing our initial indexing?
        if is_indexing():
            return {"error": "Indexing blockchain"}
        
        db = get_state_engine()
        
        blockchain_client_inst = get_utxo_provider_client()
        if blockchain_client_inst is None:
           return {"error": "Failed to connect to blockchain UTXO provider"}
        
        consensus_hash = db.get_current_consensus()
        
        namespace_fee = price_namespace( namespace_id )
        
        log.debug("Namespace '%s' will cost %s satoshis" % (namespace_id, namespace_fee))
        
        try:
           resp = namespace_preorder( str(namespace_id), str(register_addr), str(consensus_hash), str(privatekey), blockchain_client_inst, namespace_fee, testset=TESTSET )
        except:
           return json_traceback()
        
        log.debug("namespace_preorder <%s>" % (namespace_id))
        return resp 
    
    def jsonrpc_namespace_reveal( self, namespace_id, register_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, privatekey ):
        """
        Reveal and define the properties of a namespace.
        Between the namespace definition and the "namespace begin" operation, only the 
        user who created the namespace can create names in it.
        """
        
        # are we doing our initial indexing?
        if is_indexing():
            return {"error": "Indexing blockchain"}
        
        blockchain_client_inst = get_utxo_provider_client()
        if blockchain_client_inst is None:
           return {"error": "Failed to connect to blockchain UTXO provider"}
        
        try:
           resp = namespace_reveal( str(namespace_id), str(register_addr), int(lifetime),
                                    int(coeff), int(base), list(bucket_exponents),
                                    int(nonalpha_discount), int(no_vowel_discount),
                                    str(privatekey), blockchain_client_inst, testset=TESTSET )
        except:
           return json_traceback()
        
        log.debug("namespace_reveal <%s, %s, %s, %s, %s, %s, %s>" % (namespace_id, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount))
        return resp 
     
     
    def jsonrpc_namespace_ready( self, namespace_id, privatekey ):
        """
        Declare that a namespace is open to accepting new names.
        """
        
        # are we doing our initial indexing?
        if is_indexing():
            return {"error": "Indexing blockchain"}
        
        blockchain_client_inst = get_utxo_provider_client()
        if blockchain_client_inst is None:
           return {"error": "Failed to connect to blockchain UTXO provider"}
        
        try:
           resp = namespace_ready( str(namespace_id), str(privatekey), blockchain_client_inst, testset=TESTSET )
        except:
           return json_traceback()
        
        log.debug("namespace_ready %s" % namespace_id )
        return resp
        
    
    def jsonrpc_name_cost( self, name ):
        """
        Return the cost of a given name, including fees
        Return value is in satoshis
        """
        
        # are we doing our initial indexing?
        if is_indexing():
            return {"error": "Indexing blockchain"}
        
        if len(name) > LENGTHS['blockchain_id_name']:
            return {"error": "Name too long"}
        
        ret = get_name_cost( name )
        if ret is None:
            return {"error": "Unknown/invalid namespace"}
        
        return {"satoshis": int(math.ceil(ret))}
        
        
    def jsonrpc_namespace_cost( self, namespace_id ):
        """
        Return the cost of a given namespace, including fees.
        Return value is in satoshis
        """
        
        # are we doing our initial indexing?
        if is_indexing():
            return {"error": "Indexing blockchain"}
        
        if len(namespace_id) > LENGTHS['blockchain_id_namespace_id']:
            return {"error": "Namespace ID too long"}
        
        ret = price_namespace(namespace_id)
        return {"satoshis": int(math.ceil(ret))}
        
        
    def jsonrpc_lookup_namespace( self, namespace_id ):
        """
        Return the readied namespace with the given namespace_id
        """
        
        # are we doing our initial indexing?
        if is_indexing():
            return {"error": "Indexing blockchain"}
        
        db = get_state_engine()
        ns = db.get_namespace( namespace_id )
        if ns is None:
            return {"error": "No such ready namespace"}
        else:
            return ns
        
        
def run_indexer():
    """
    Continuously reindex the blockchain, but as a subprocess.
    """
    
    # set up this process
    signal.signal( signal.SIGINT, die_handler_indexer )
    signal.signal( signal.SIGQUIT, die_handler_indexer )
    signal.signal( signal.SIGTERM, die_handler_indexer )

    bitcoind_opts = get_bitcoin_opts()
    
    _, last_block_id = get_index_range()
    blockstore_state_engine = get_state_engine()
    
    while True:
        
        time.sleep( REINDEX_FREQUENCY )
        virtualchain.sync_virtualchain( bitcoind_opts, last_block_id, blockstore_state_engine )
        
        _, last_block_id = get_index_range()
        
    return


def stop_server():
    """
    Stop the blockstored server.
    """
    global indexer_pid 
    
    # Quick hack to kill a background daemon
    pid_file = get_pidfile_path()

    try:
        fin = open(pid_file, "r")
    except Exception, e:
        return
        
    else:
        pid_data = fin.read()
        fin.close()
        os.remove(pid_file)

        pid = int(pid_data)
        
        try:
           os.kill(pid, signal.SIGKILL)
        except Exception, e:
           return 

    
    if indexer_pid is not None:
        try:
           os.kill(indexer_pid, signal.SIGTERM)
        except Exception, e:
           return 
       
    # stop building new state if we're in the middle of it
    db = get_state_engine()
    virtualchain.stop_sync_virtualchain( db )
    
    set_indexing( False )
    
       
def get_indexing_lockfile():
    """
    Return path to the indexing lockfile 
    """
    return os.path.join( virtualchain.get_working_dir(), "blockstore.indexing" )
       
       
def is_indexing():
    """
    Is the blockstore daemon synchronizing with the blockchain?
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
        

def run_server( foreground=False ):
    """ 
    Run the blockstored RPC server, optionally in the foreground.
    """
    
    global indexer_pid
    
    bt_opts = get_bitcoin_opts()
    
    tac_file = get_tacfile_path()
    access_log_file = get_logfile_path() + ".access"
    indexer_log_file = get_logfile_path() + ".indexer"
    pid_file = get_pidfile_path()
    
    start_block, current_block = get_index_range()
    
    argv0 = os.path.normpath( sys.argv[0] )
    
    if os.path.exists("./%s" % argv0 ):
        indexer_command = ("%s indexer" % (os.path.join( os.getcwd(), argv0))).split()
    else:
        # hope its in the $PATH
        indexer_command = ("%s indexer" % argv0).split()
    
    
    logfile = None
    if not foreground:

        api_server_command = ('twistd --pidfile=%s --logfile=%s -noy %s' % (pid_file,
                                                                           access_log_file,
                                                                           tac_file)).split()

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
                
                # parent!
                sys.exit(0)
                
            else:
                
                # error
                sys.exit(1)
                
        elif child_pid > 0:
            
            # parent
            # wait for child 
            pid, status = os.waitpid( child_pid, 0 )
            sys.exit(status)
            
    else:
        
        # foreground
        api_server_command = ('twistd --pidfile=%s -noy %s' % (pid_file, tac_file)).split()
        
    
    # start API server
    blockstored = subprocess.Popen( api_server_command, shell=False)    
    
    set_indexing( False )
    
    if start_block != current_block:
        # bring us up to speed 
        set_indexing( True )
    
        blockstore_state_engine = get_state_engine()
        virtualchain.sync_virtualchain( bt_opts, current_block, blockstore_state_engine )
        
        set_indexing( False )
    
    # fork the indexer 
    if foreground:
        indexer = subprocess.Popen( indexer_command, shell=False )
    else:
        indexer = subprocess.Popen( indexer_command, shell=False, stdout=logfile, stderr=logfile )
        
    indexer_pid = indexer.pid
    
    # wait for the API server to die (we kill it with `blockstored stop`)
    blockstored.wait()
    
    # stop our indexer subprocess 
    indexer_pid = None
    
    os.kill( indexer.pid, signal.SIGINT )
    indexer.wait()
    
    logfile.flush()
    logfile.close()
    
    # stop building new state if we're in the middle of it
    db = get_state_engine()
    virtualchain.stop_sync_virtualchain( db )
    
    return blockstored.returncode 


def setup( return_parser=False ):
   """
   Do one-time initialization.
   Call this to set up global state and set signal handlers.
   
   If return_parser is True, return a partially-
   setup argument parser to be populated with 
   subparsers (i.e. as part of main())
   
   Otherwise return None.
   """
   
   global blockstore_opts 
   global blockchain_client
   global blockchain_broadcaster
   global bitcoin_opts
   global utxo_opts 
   global blockstore_opts
   global dht_opts
   
   # set up our implementation 
   virtualchain.setup_virtualchain( blockstore_state_engine )
   
   # acquire configuration, and store it globally
   blockstore_opts, bitcoin_opts, utxo_opts, dht_opts = configure( interactive=True )
   
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
   set_utxo_opts( utxo_opts )
   
   if return_parser:
      return argparser 
   else:
      return None
   

def run_blockstored():
   """
   run blockstored
   """
   
   argparser = setup( return_parser=True )
   
   # get RPC server options
   subparsers = argparser.add_subparsers(
      dest='action', help='the action to be taken')
   
   parser_server = subparsers.add_parser(
      'start',
      help='start the blockstored server')
   parser_server.add_argument(
      '--foreground', action='store_true',
      help='start the blockstored server in foreground')
   
   parser_server = subparsers.add_parser(
      'stop',
      help='stop the blockstored server')
   
   parser_server = subparsers.add_parser(
      'indexer',
      help='run blockstore indexer worker')
   
   args, _ = argparser.parse_known_args()
   
   log.debug( "bitcoin options: %s" % bitcoin_opts )
   
   if args.action == 'start':
      
      if os.path.exists( get_pidfile_path() ):
          log.error("Blockstored appears to be running already.  If not, please run '%s stop'" % (sys.argv[0]))
          sys.exit(1)
          
      if args.foreground:
         
         log.info('Initializing blockstored server in foreground ...')
         exit_status = run_server( foreground=True )
         log.info("Service endpoint exited with status code %s" % exit_status )
         
      else:
         
         log.info('Starting blockstored server ...')
         run_server()
         
   elif args.action == 'stop':
      stop_server()

   elif args.action == 'indexer':
      run_indexer()

if __name__ == '__main__':
    
   run_blockstored()
