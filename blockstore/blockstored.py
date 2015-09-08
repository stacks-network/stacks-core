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
from lib.config import REINDEX_FREQUENCY, TESTSET
from lib import *

import virtualchain 
log = virtualchain.session.log 

# global variables, for use with the RPC server and the twisted callback
bitcoind = None
bitcoin_opts = None
chaincom_opts = None
blockchain_client = None 

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


def get_chaincom_opts():
   """
   Get chain.com options.
   """
   global chaincom_opts
   return chaincom_opts


def set_bitcoin_opts( new_bitcoin_opts ):
   """
   Set new global bitcoind operations
   """
   global bitcoin_opts 
   bitcoin_opts = new_bitcoin_opts
   
   
def set_chaincom_opts( new_chaincom_opts ):
   """
   Set new global chian.com options 
   """
   global chaincom_opts 
   chaincom_opts = new_chaincom_opts
   
   
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
    Always try to reconnect
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
            return first_block, last_block 
        

def sigint_handler_server(signal, frame):
    """
    Handle Ctrl+C for server subprocess
    """
    
    log.info('\n')
    log.info('Exiting blockstored server')
    stop_server()
    sys.exit(0)



def sigint_handler_indexer(signal, frame):
    """
    Handle Ctrl+C for indexer processe
    """
    sys.exit(0)


def json_traceback():
    exception_data = traceback.format_exc().splitlines()
    return {
        "error": exception_data[-1],
        "traceback": exception_data
    }

 
def get_utxo_provider_client():
   """
   Get or instantiate our blockchain UTXO provider's client (i.e. chain.com; falling back to bitcoind otherwise).
   Return None if we were unable to connect
   """
   
   global blockchain_client 
   global chaincom_opts
   global blockchain_opts
   
   # acquire configuration (which we should already have)
   bitcoin_opts, chaincom_opts = configure( interactive=False )
   
   chaincom_id = chaincom_opts['api_key_id']
   chaincom_secret = chaincom_opts['api_key_secret']
   
   try:
      blockchain_client = pybitcoin.ChainComClient( chaincom_id, chaincom_secret )
      return blockchain_client
      
   except Exception, e:
      log.exception(e)
      
      # try bitcoind...
      try:
         blockchain_client = BitcoindClient( blockchain_opts['bitcoind_user'], blockchain_opts['bitcoind_passwd'],
                                             server=blockchain_opts['bitcoind_server'], port=str(blockchain_opts['bitcoind_port']), use_https=blockchain_opts.get('bitcoind_use_https', False) )
         
         return blockchain_client
         
      except Exception, e:
         log.exception(e)
         return None 
      
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
        
        blockstore_state_engine = get_state_engine()
        name_record = blockstore_state_engine.get_name( name )
        
        if name is None:
           return {"error": "Not found."}
        
        else:
           return name_record 
        
        
    def jsonrpc_getinfo(self):
        """
        """
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
        
        blockchain_client_inst = get_utxo_provider_client()
        db = get_state_engine()
        
        if db.is_name_registered( name ):
            return {"error": "Name already registered"}

        # calculate the import fee, plus the extra output fee
        name_fee = get_name_cost( name )
        
        log.debug("The price of '%s' is %s satoshis" % (name, name_fee))
        
        try:
            resp = name_import( str(name), str(recipient_address), str(update_hash), str(privatekey), blockchain_client_inst, name_fee, testset=TESTSET )
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
        
        db = get_state_engine()
        
        blockchain_client_inst = get_utxo_provider_client()
        if blockchain_client_inst is None:
           return {"error": "Failed to connect to blockchain UTXO provider"}
        
        consensus_hash = db.get_current_consensus()
        
        namespace_fee = price_namespace( namespace_id ) + DEFAULT_OP_RETURN_FEE
        
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
        ret = get_name_cost( name )
        if ret is None:
            return {"error": "Unknown/invalid namespace"}
        
        return {"satoshis": int(math.ceil(ret))}
        
        
    def jsonrpc_name_import_cost( self, name ):
        """
        Return the cost to import a given name, including fees.
        Return value is in satoshis
        """
        ret = get_name_cost( name )
        if ret is None:
            return {"error": "Unknown/invalid namespace"}
        
        return {"satoshis": int(math.ceil(ret))}
        
        
    def jsonrpc_namespace_cost( self, namespace_id ):
        """
        Return the cost of a given namespace, including fees.
        Return value is in satoshis
        """
        ret = price_namespace(namespace_id)
        return {"satoshis": int(math.ceil(ret))}
        
        
def run_indexer():
    """
    Continuously reindex the blockchain, but as a subprocess.
    """
    
    # set up this process
    signal.signal( signal.SIGINT, sigint_handler_indexer )

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


def run_server( foreground=False):
    """ 
    Run the blockstored RPC server, optionally in the foreground.
    """
    
    signal.signal( signal.SIGINT, sigint_handler_server )
   
    bitcoin_opts = get_bitcoin_opts()
    
    tac_file = get_tacfile_path()
    log_file = get_logfile_path()
    pid_file = get_pidfile_path()
    
    start_block, current_block = get_index_range()
    
    indexer_command = "%s indexer" % sys.argv[0]
    
    if foreground:
        command = 'twistd --pidfile=%s -noy %s' % (pid_file, tac_file)
    else:
        command = 'twistd --pidfile=%s --logfile=%s -y %s' % (pid_file,
                                                              log_file,
                                                              tac_file)

    if start_block != current_block:
       # bring us up to speed 
       log.info("Synchronizing with blockchain, up to %s" % current_block )
       
       blockstore_state_engine = get_state_engine()
       virtualchain.sync_virtualchain( bitcoin_opts, current_block, blockstore_state_engine )
    
    try:
        
       # fork the server
       blockstored = subprocess.Popen( command, shell=True, preexec_fn=os.setsid)
       
       # fork the indexer 
       indexer = subprocess.Popen( indexer_command, shell=True )
       
       log.info('Blockstored successfully started')
       
       # wait for it to die 
       blockstored.wait()
       
       # stop our indexing thread 
       os.kill( indexer.pid, signal.SIGINT )
       indexer.wait()
       
       return blockstored.returncode 
    
    except IndexError, ie:
        
        traceback.print_exc()
        # indicates that we don't have the latest block 
        log.error("\n\nFailed to find the first blockstore record (got block %s).\n" % current_block + \
                   "Please verify that your bitcoin provider has processd up to" + \
                   "to block %s.\n" % (START_BLOCK) + \
                   "    Example:  bitcoin-cli getblockcount" )
        try:
            os.killpg(blockstored.pid, signal.SIGTERM)
        except:
            pass
        exit(1)
    
    except Exception, e:
        log.exception(e)
        log.info('Exiting blockstored server')
        try:
            os.killpg(blockstored.pid, signal.SIGTERM)
        except:
            pass
        exit(1)


def setup( return_parser=False ):
   """
   Do one-time initialization.
   Call this to set up global state and set signal handlers.
   
   If return_parser is True, return a partially-
   setup argument parser to be populated with 
   subparsers (i.e. as part of main())
   
   Otherwise return None.
   """
   
   global blockchain_client
   global bitcoin_opts
   global chaincom_opts
   
   # set up our implementation 
   virtualchain.setup_virtualchain( blockstore_state_engine )
   
   # acquire configuration, and store it globally
   bitcoin_opts, chaincom_opts = configure( interactive=True )
   
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
   set_chaincom_opts( chaincom_opts )
   
   if return_parser:
      return argparser 
   else:
      return None
   

def run_blockstored():
   """
   run blockstored
   """
   
   argparser = setup( return_parser=True )
   
   log.debug( "\n" + str( chaincom_opts ) + "\n" )
   
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
      
      # make sure the server isn't already running 
      stop_server()
      
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
