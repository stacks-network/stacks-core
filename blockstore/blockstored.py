#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
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

from ConfigParser import SafeConfigParser

import pybitcoin
from txjsonrpc.netstring import jsonrpc
from twisted.internet import reactor

from lib import nameset as blockstore_state_engine
from lib import get_db_state
from lib import *

import virtualchain 
log = virtualchain.session.log 

# global variables, for use with the RPC server and the twisted callback
bitcoind = None
bitcoin_opts = None
chaincom_opts = None
blockchain_client = None 

def get_bitcoind( new_bitcoind_opts=None ):
   """
   Get or instantiate our bitcoind client.
   Optionally re-set the bitcoind options.
   """
   global bitcoind 
   global bitcoin_opts 
   
   if bitcoind is not None:
      return bitcoind 
   
   else:
      if new_bitcoind_opts is not None:
         bitcoin_opts = new_bitcoind_opts
      
      try:
         bitcoind = virtualchain.connect_bitcoind( bitcoin_opts )
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
   Get or construct the blockstore virtual chain state engine.
   """
   return get_db_state()
   
# ------------------------------
old_block = 0
index_initialized = False

def reindex_blockchain():
   """
   Reindex the virtual chain--bring it up to speed with bitcoind.
   This is called by twisted, so we'll need to re-initialize everything
   """
   
   from twisted.python import log
   global old_block
   global index_initialized
   
   # set up our implementation 
   setup()
   
   bitcoind_opts = get_bitcoin_opts()
   bitcoind = get_bitcoind()
   
   _, last_block_id = virtualchain.get_index_range( bitcoind )
   blockstore_state_engine = get_state_engine()
   
   virtualchain.sync_virtualchain( bitcoind_opts, last_block_id, blockstore_state_engine )
    

def sigint_handler(signal, frame):
    """
    Handle Ctrl+C for dht node
    """
    
    log.info('\n')
    log.info('Exiting blockstored server')
    stop_server()
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
   
   blockchain_opts = get_bitcoin_opts()
   chaincom_opts = get_chaincom_opts()
   
   chaincom_id = chaincom_opts['api_key_id']
   chaincom_secret = chaincom_opts['api_key_secret']
   
   try:
      blockchain_client = ChainComClient( chaincom_id, chaincom_secret )
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


class BlockstoredRPC(jsonrpc.JSONRPC):
    """
    Blockstored JSON RPC server.
    
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
        

    def jsonrpc_put(self, key, value):
        """
        Put data into the DHT.  Do not put the signed 
        hash into the blockchain.
        """

        reply = {}

        try:
            test_value = json.loads(value)
        except Exception as e:
            print e
            reply['error'] = "value not JSON, not storing"
            return reply

        hash = pybitcoin.hash.hex_hash160(value)
        test_key = hash

        if key != test_key:
            reply['error'] = "hash(value) doesn't match, not storing"
            return reply

        result = self.dht_server.set(key, value)
        if result:
           reply['key'] = hash 
           reply['result'] = True
        else:
           reply['result'] = False
      
        return reply


    def jsonrpc_signdata(self, name, key, value, privatekey):
        """
        Given a usenrame and data, put its signed hash into the blockchain.
        Follow this call up with jsonrpc_put to put it into the DHT.
        """

        reply = {}
        blockchain_client_inst = get_utxo_provider_client()

        try:
            test_value = json.loads(value)
        except Exception as e:
            print principale
            reply['error'] = "value not JSON, not storing"
            return reply

        hash = pybitcoin.hash.hex_hash160(value)
        test_key = hash

        if key != test_key:
            reply['error'] = "hash(value) doesn't match, not storing"
            return reply

        try:
           resp = putdata_storage( str(name), str(key), str(privatekey), blockchain_client_inst, testset=True)
        except:
           return json_traceback()

        log.debug('setsigned <%s, %s, %s>' % (name, privatekey, value))
        
        return resp
     
     
    def jsonrpc_putsigned( self, name, key, value, privatekey):
        """
        Given a username and data, sign it, broadcast the signature to the blockchain,
        and then if successful, put the data into the DHT.
        """        
        
        reply = self.jsonrpc_signdata( self, name, key, value, privatekey )
        if reply.has_key('error'):
           # error 
           return reply 
        else:
           return self.jsonrpc_put( self, key, value )
    
    
    def jsonrpc_get(self, key):
        """
        Given a key to data, look it up and return it.
        """
        return self.dht_server.get(key)


    def jsonrpc_verifydata(self, name, key ):
        """
        Given a username and hash, verify that the user that owns 
        the name has signed the hash in the blockchain.
        """
        
        db = get_state_engine()
        return verify_signed_data( name, key, db )
        
        
    def jsonrpc_getverified( self, name, key ):
        """
        Given a username and a hash, verify that the user that owns 
        the name has signed the hash in the blockchain, and if so,
        return the data.
        """
        
        reply = self.jsonrpc_verifydata( name, key )
        if reply.has_key('error'):
          # error
          return reply 
        else:
          return self.jsonrpc_get( self, key )


    def jsonrpc_getinfo(self):
        """
        """
        bitcoind = get_bitcoind()
        info = bitcoind.getinfo()
        reply = {}
        reply['blocks'] = info['blocks']
        return reply

    def jsonrpc_preorder(self, name, privatekey):
        """ Preorder a name
        """
        
        blockchain_client_inst = get_utxo_provider_client()
        if blockchain_client_inst is None:
           return {'error': 'Failed to connect to blockchain'}
        
        db = blockstore_state_engine()
        consensus_hash = db.get_current_consensus()
        if not consensus_hash:
            return {"error": "Nameset snapshot not found."}
         
        if str(name) in db.name_records:
            return {"error": "Name already registered"}

        try:
            resp = preorder_name(str(name), str(consensus_hash), str(privatekey), blockchain_client_inst, testset=True)
        except:
            return json_traceback()

        log.debug('preorder <%s, %s>' % (name, privatekey))

        return resp

    def jsonrpc_register(self, name, privatekey):
        """ Register a name
        """
        
        blockchain_client_inst = get_utxo_provider_client()
        if blockchain_client_inst is None:
           return {'error': 'Failed to connect to blockchain'}
        
        log.info("name: %s" % name)
        db = blockstore_state_engine()
        if str(name) in db.name_records:
            return {"error": "Name already registered"}

        try:
            resp = register_name(str(name), str(privatekey), blockchain_client_inst, testset=True)
        except:
            return json_traceback()

        log.debug('register <%s, %s>' % (name, privatekey))

        return resp

    def jsonrpc_update(self, name, data, privatekey):
        """
        Update a name with new data.
        """

        blockchain_client_inst = get_utxo_provider_client()
        consensus_hash = db.get_current_consensus()
        
        if blockchain_client_inst is None:
           return {'error': 'Failed to connect to blockchain'}
        
        try:
            resp = update_name(str(name), str(data), str(consensus_hash), str(privatekey), blockchain_client_inst, testset=True)
        except:
            return json_traceback()

        log.debug('update <%s, %s, %s>' % (name, data, privatekey))

        return resp

    def jsonrpc_transfer(self, name, address, privatekey):
        """ Transfer a name
        """

        blockchain_client_inst = get_utxo_provider_client()
        if blockchain_client_inst is None:
           return {'error': 'Failed to connect to blockchain'}
        
        try:
            resp = transfer_name(str(name), str(address), str(privatekey), blockchain_client_inst, testset=True)
        except:
            return json_traceback()

        log.debug('transfer <%s, %s, %s>' % (name, address, privatekey))

        return resp


    def jsonrpc_renew(self, name, privatekey):
        """ Renew a name
        """

        log.debug('renew <%s, %s>' % (name, privatekey))

        # TODO 
        return
   
    
    def jsonrpc_namespace_preorder( self, namespace_id, privatekey ):
        """
        Define the properties of a namespace.
        Between the namespace definition and the "namespace begin" operation, only the 
        user who created the namespace can create names in it.
        """
        
        db = blockstore_state_engine()
        
        blockchain_client_inst = get_utxo_provider_client()
        if blockchain_client_inst is None:
           return {'error': 'Failed to connect to blockchain'}
        
        consensus_hash = db.get_current_consensus()
        
        try:
           resp = namespace_preorder( str(namespace_id), str(consensus_hash), str(privatekey), blockchain_client_inst, testset=True )
        except:
           return json_traceback()
        
        log.debug("namespace_preorder <%s>" % (namespace_id))
        return resp 
    
    
    def jsonrpc_namespace_define( self, namespace_id, lifetime, base_name_cost, cost_decay_rate ):
        """
        Define the properties of a namespace.
        Between the namespace definition and the "namespace begin" operation, only the 
        user who created the namespace can create names in it.
        """
        
        blockchain_client_inst = get_utxo_provider_client()
        if blockchain_client_inst is None:
           return {'error': 'Failed to connect to blockchain'}
        
        try:
           resp = namespace_define( str(namespace_id), int(lifetime), int(base_name_cost), float(cost_decay_rate), blockchain_client_inst, testset=True )
        except:
           return json_traceback()
        
        log.debug("namespace_define <%s, %s, %s, %s>" % (namespace_id, lifetime, base_name_cost, cost_decay_rate))
        return resp 
     
     
    def jsonrpc_namespace_begin( self, namespace_id, privatekey ):
        """
        Declare that a namespace is open to accepting new names.
        """
        
        blockchain_client_inst = get_utxo_provider_client()
        if blockchain_client_inst is None:
           return {'error': 'Failed to connect to blockchain'}
        
        try:
           resp = namespace_begin( str(namespace_id), str(privatekey), blockchain_client_inst, testset=True )
        except:
           return json_traceback()
        
        log.debug("namespace_begin %s" % namespace_id )
        return resp
        


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
    
    bitcoin_opts = get_bitcoin_opts()
    bitcoind = virtualchain.connect_bitcoind( bitcoin_opts )
   
    tac_file = get_tacfile_path()
    log_file = get_logfile_path()
    pid_file = get_pidfile_path()

    start_block, current_block = virtualchain.get_index_range( bitcoind )

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
       log.info('Blockstored successfully started')

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
   
   global bitcoind
   global blockchain_client
   global bitcoin_opts
   global chaincom_opts
   
   signal.signal( signal.SIGINT, sigint_handler )
   
   # set up our implementation 
   virtualchain.setup_virtualchain( blockstore_state_engine )
   
   # acquire configuration, and store it globally
   bitcoin_opts, chaincom_opts = interactive_configure()
   
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
   
   args, _ = argparser.parse_known_args()
   
   log.debug( "bitcoin options: %s" % bitcoin_opts )
   
   if args.action == 'start':
      
      # make sure the server isn't already running 
      stop_server()
      
      if args.foreground:
         
         log.info('Initializing blockstored server in foreground ...')
         run_server( foreground=True )
         
         while(1):
            stay_alive = True
            
      else:
         
         log.info('Starting blockstored server ...')
         run_server( bitcoind )
         
   elif args.action == 'stop':
      stop_server()


if __name__ == '__main__':
    
   run_blockstored()
