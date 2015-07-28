#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

import argparse
import coinkit
import logging
import os
import os.path
import sys
import subprocess
import signal
import json
import datetime
import traceback
import httplib
import ssl
import threading
import time
import socket
from multiprocessing import Pool

from ConfigParser import SafeConfigParser

from txjsonrpc.netstring import jsonrpc
from twisted.internet import reactor

from lib import config
from lib import build_nameset, NameDb, verify_signed_data, get_blockstore_ops_in_blocks
from lib import config
from lib import cache
from lib import workpool
from coinkit import BitcoindClient, ChainComClient
from utilitybelt import is_valid_int

import lib.blockdaemon as blockdaemon
log = blockdaemon.log 

bitcoind = None
bitcoin_opts = None
blockchain_client = None 

CHAIN_COM_API_ID = None 
CHAIN_COM_API_SECRET = None

from lib import preorder_name, register_name, update_name, \
    transfer_name, namespace_define, namespace_begin, putdata_storage, rmdata_storage

def signal_handler(signal, frame):
    """ Handle Ctrl+C for dht node
    """
    import signal
    
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


def get_namedb():
    working_dir = blockdaemon.get_working_dir( config.BLOCKSTORED_WORKING_DIR )
    namespace_file = os.path.join(working_dir, config.BLOCKSTORED_NAMESPACE_FILE)
    snapshots_file = os.path.join(working_dir, config.BLOCKSTORED_SNAPSHOTS_FILE)
    db = NameDb(namespace_file, snapshots_file)
    return db
 
 
def get_blockchain_client():
   
   global CHAIN_COM_API_ID, CHAIN_COM_API_SECRET, blockchain_client, bitcoin_opts
   
   if blockchain_client is not None:
      return blockchain_client 
   
   config_file = blockdaemon.get_config_file( config.BLOCKSTORED_WORKING_DIR, config.BLOCKSTORED_CONFIG_FILE )
   
   # get chain.com info from the config file...
   config_parser = SafeConfigParser()
   config_parser.read(config_file)
   
   if config_parser.has_section('chain_com'):
      CHAIN_COM_API_ID = config_parser.get('chain_com', 'api_key_id')
      CHAIN_COM_API_SECRET = config_parser.get('chain_com', 'api_key_secret')

   try:
      blockchain_client = ChainComClient( CHAIN_COM_API_ID, CHAIN_COM_API_SECRET )
      return blockchain_client
      
   except Exception, e:
      log.exception(e)
      
      try:
         blockchain_client = BitcoindClient( bitcoin_opts['bitcoind_user'], bitcoin_opts['bitcoind_passwd'],
                                             server=bitcoin_opts['bitcoind_server'], port=str(bitcoin_opts['bitcoind_port']), use_https=bitcoin_opts.get('bitcoind_use_https', False) )
         
         return blockchain_client
         
      except Exception, e:
         log.exception(e)
         return None 
      
      return None


def refresh_index( bitcoind, first_block, last_block, working_dir, initial_index=False):
    """
    Obtain the name operation sequence from the blockchain.
    That is, go and fetch each block we haven't seen since the last call to this method,
    extract the blockstore operations from them, and record in the given working_dir where we left 
    off while watching the blockchain.
    
    Store the blockstore operations, name database, snapshots, and last block to the working_dir
    Return 0 on success 
    Raise an exception on error
    """
    
    working_dir = blockdaemon.get_working_dir( working_dir )

    namespace_file = os.path.join( working_dir, config.BLOCKSTORED_NAMESPACE_FILE)
    snapshots_file = os.path.join( working_dir, config.BLOCKSTORED_SNAPSHOTS_FILE)
    lastblock_file = os.path.join( working_dir, config.BLOCKSTORED_LASTBLOCK_FILE)

    start = datetime.datetime.now()
    
    num_workers = config.MULTIPROCESS_NUM_WORKERS
    blockstore_ops = []
    
    # feed workers bitcoind this way
    workpool.multiprocess_bitcoind_factory( blockdaemon.create_bitcoind_connection )
    
    pool = Pool( processes=num_workers )
    
    # get *all* the blockstore operations!
    blockstore_ops = get_blockstore_ops_in_blocks( pool, range(first_block, last_block+1) )
    pool.close()
    pool.join()
    blockstore_ops.sort()
    
    time_taken = "%s seconds" % (datetime.datetime.now() - start).seconds
    log.info(time_taken)

    db = get_namedb()
    merkle_snapshot = build_nameset(db, blockstore_ops)
    db.save_names(namespace_file)
    db.save_snapshots(snapshots_file)

    merkle_snapshot = "merkle snapshot: %s\n" % merkle_snapshot
    log.info(merkle_snapshot)
    log.info(db.name_records)

    fout = open(lastblock_file, 'w')  # to overwrite
    fout.write(str(last_block))
    fout.close()
    
    return 0
 

class BlockstoredRPC(jsonrpc.JSONRPC):
    """
    Blockstored JSON RPC server.
    """

    def __init__(self, dht_server=None, storagedb=None):
        self.dht_server = dht_server
        self.storagedb = storagedb

    def jsonrpc_ping(self):
        reply = {}
        reply['status'] = "alive"
        return reply

    def jsonrpc_lookup(self, name):
        """ Lookup the details for a name.
        """
        db = get_namedb()
        if str(name) in db.name_records:
            name_record = db.name_records[name]
        else:
            return {"error": "Not found."}

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

        hash = coinkit.hex_hash160(value)
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
        blockchain_client_inst = get_blockchain_client()

        try:
            test_value = json.loads(value)
        except Exception as e:
            print principale
            reply['error'] = "value not JSON, not storing"
            return reply

        hash = coinkit.hex_hash160(value)
        test_key = hash

        if key != test_key:
            reply['error'] = "hash(value) doesn't match, not storing"
            return reply

        try:
           resp = putdata_storage( str(name), str(key), str(privatekey), blockchain_client=blockchain_client_inst, testset=True)
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
        
        db = get_namedb()
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
        global bitcoind
        info = bitcoind.getinfo()
        reply = {}
        reply['blocks'] = info['blocks']
        return reply

    def jsonrpc_preorder(self, name, privatekey):
        """ Preorder a name
        """
        
        blockchain_client_inst = get_blockchain_client()
        if blockchain_client_inst is None:
           return {'error': 'Failed to connect to blockchain'}
        
        db = get_namedb()
        consensus_hash = db.consensus_hashes.get('current')
        if not consensus_hash:
            return {"error": "Nameset snapshot not found."}
         
        if str(name) in db.name_records:
            return {"error": "Name already registered"}

        try:
            resp = preorder_name(str(name), str(consensus_hash), str(privatekey), blockchain_client=blockchain_client_inst, testset=True)
        except:
            return json_traceback()

        log.debug('preorder <%s, %s>' % (name, privatekey))

        return resp

    def jsonrpc_register(self, name, privatekey):
        """ Register a name
        """
        
        blockchain_client_inst = get_blockchain_client()
        if blockchain_client_inst is None:
           return {'error': 'Failed to connect to blockchain'}
        
        log.info("name: %s" % name)
        db = get_namedb()
        if str(name) in db.name_records:
            return {"error": "Name already registered"}

        try:
            resp = register_name(str(name), str(privatekey), blockchain_client=blockchain_client_inst, testset=True)
        except:
            return json_traceback()

        log.debug('register <%s, %s>' % (name, privatekey))

        return resp

    def jsonrpc_update(self, name, data, privatekey):
        """
        Update a name with new data.
        """

        blockchain_client_inst = get_blockchain_client()
        if blockchain_client_inst is None:
           return {'error': 'Failed to connect to blockchain'}
        
        try:
            resp = update_name(str(name), str(data), str(privatekey), blockchain_client=blockchain_client_inst, testset=True)
        except:
            return json_traceback()

        log.debug('update <%s, %s, %s>' % (name, data, privatekey))

        return resp

    def jsonrpc_transfer(self, name, address, privatekey):
        """ Transfer a name
        """

        blockchain_client_inst = get_blockchain_client()
        if blockchain_client_inst is None:
           return {'error': 'Failed to connect to blockchain'}
        
        try:
            resp = transfer_name(str(name), str(address), str(privatekey), blockchain_client=blockchain_client_inst, testset=True)
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

    def jsonrpc_namespace_define( self, namespace_id, lifetime, base_name_cost, cost_decay_rate, privatekey ):
        """
        Define the properties of a namespace.
        Between the namespace definition and the "namespace begin" operation, only the 
        user who created the namespace can create names in it.
        """
        
        blockchain_client_inst = get_blockchain_client()
        if blockchain_client_inst is None:
           return {'error': 'Failed to connect to blockchain'}
        
        try:
           resp = namespace_define( str(namespace_id), int(lifetime), int(base_name_cost), float(cost_decay_rate), str(privatekey), blockchain_client=blockchain_client_inst, testset=True )
        except:
           return json_traceback()
        
        log.debug("namespace_define <%s, %s, %s, %s>" % (namespace_id, lifetime, base_name_cost, cost_decay_rate))
        return resp 
     
     
    def jsonrpc_namespace_begin( self, namespace_id, privatekey ):
        """
        Declare that a namespace is open to accepting new names.
        """
        
        blockchain_client_inst = get_blockchain_client()
        if blockchain_client_inst is None:
           return {'error': 'Failed to connect to blockchain'}
        
        try:
           resp = namespace_begin( str(namespace_id), str(privatekey), blockchain_client=blockchain_client_inst, testset=True )
        except:
           return json_traceback()
        
        log.debug("namespace_begin %s" % namespace_id )
        return resp
        

# ------------------------------
old_block = 0
index_initialized = False


def reindex_blockchain():
    """
    """

    from twisted.python import log
    global old_block
    global index_initialized
    global counter
    global bitcoind
    
    if bitcoind is None:
       bitcoind = blockdaemon.create_bitcoind_connection()

    start_block, current_block = blockdaemon.get_index_range( bitcoind, config.BLOCKSTORED_WORKING_DIR )
    
    # initial indexing
    if not index_initialized:

        index_initialized = True
        old_block = start_block
    else:

        # don't run this part until index is initialized
        if old_block == current_block:
            log.msg('Blockchain: no new blocks after', current_block)
        else:
            check_blocks = current_block - old_block
            message = 'Blockchain: checking last %s block(s) (%s-%s)' % (check_blocks, old_block, current_block)
            log.msg(message)

            # call the reindex func here
            refresh_index(bitcoind, old_block + 1, current_block, config.BLOCKSTORED_WORKING_DIR)
            old_block = current_block


def prompt_user_for_chaincom_details():
    """
    """
    global CHAIN_COM_API_ID
    global CHAIN_COM_API_SECRET
    
    config_file = blockdaemon.get_config_file( config.BLOCKSTORED_WORKING_DIR, config.BLOCKSTORED_CONFIG_FILE )
    parser = SafeConfigParser()

    parser.read(config_file)

    if not parser.has_section('chain_com'):

        message = '-' * 15 + '\n'
        message += 'NOTE: Blockstore currently requires API access to chain.com\n'
        message += 'for getting unspent outputs. We will add support for using\n'
        message += 'bitcoind and/or other API providers in the next release.\n'
        message += '-' * 15
        log.info(message)

        api_key_id = raw_input("Enter chain.com API Key ID: ")
        api_key_secret = raw_input("Enter chain.com API Key Secret: ")

        if api_key_id != '' and api_key_secret != '':
            parser.add_section('chain_com')
            parser.set('chain_com', 'api_key_id', api_key_id)
            parser.set('chain_com', 'api_key_secret', api_key_secret)

            fout = open(config_file, 'w')
            parser.write(fout)

        # update in config as well (which was already initialized)
        CHAIN_COM_API_ID = api_key_id
        CHAIN_COM_API_SECRET = api_key_secret


def stop_server():
    """ Stop the blockstored server
    """
    # Quick hack to kill a background daemon
    import subprocess
    import signal
    import os

    from .lib.config import BLOCKSTORED_PID_FILE

    working_dir = blockdaemon.get_working_dir( config.BLOCKSTORED_WORKING_DIR )

    pid_file = os.path.join(working_dir, BLOCKSTORED_PID_FILE)

    try:
        fin = open(pid_file)
    except:
        return
    else:
        pid_data = fin.read()
        fin.close()
        os.remove(pid_file)

        pid = int(pid_data)
        os.kill(pid, signal.SIGKILL)


def run_server( bitcoind, foreground=False):
    """ run the blockstored server
    """

    if bitcoind is None:
       prompt_user_for_chaincom_details()
       bitcoind = blockdaemon.init_bitcoind( config.BLOCKSTORED_WORKING_DIR, config.BLOCKSTORED_CONFIG_FILE )

    from .lib.config import BLOCKSTORED_PID_FILE, BLOCKSTORED_LOG_FILE
    from .lib.config import BLOCKSTORED_TAC_FILE
    from .lib.config import START_BLOCK

    working_dir = blockdaemon.get_working_dir( config.BLOCKSTORED_WORKING_DIR )

    current_dir = os.path.abspath(os.path.dirname(__file__))

    tac_file = os.path.join(current_dir, BLOCKSTORED_TAC_FILE)
    log_file = os.path.join(working_dir, BLOCKSTORED_LOG_FILE)
    pid_file = os.path.join(working_dir, BLOCKSTORED_PID_FILE)

    start_block, current_block = blockdaemon.get_index_range( bitcoind, config.BLOCKSTORED_WORKING_DIR )

    if foreground:
        command = 'twistd --pidfile=%s -noy %s' % (pid_file, tac_file)
    else:
        command = 'twistd --pidfile=%s --logfile=%s -y %s' % (pid_file,
                                                              log_file,
                                                              tac_file)

    try:
        # refresh_index(335563, 335566, initial_index=True)
        if start_block != current_block:
            refresh_index(bitcoind, start_block, current_block, config.BLOCKSTORED_WORKING_DIR, initial_index=True)
        
        blockstored = subprocess.Popen( command, shell=True, preexec_fn=os.setsid)
        log.info('Blockstored successfully started')

    except IndexError, ie:
        traceback.print_exc()
        # indicates that we don't have the latest block 
        log.error("\n\nFailed to find the first blockstore record (got block %s).\n" % current_block + \
                   "Please verify that your bitcoin provider has " + \
                   "processed up to block %s.\n" % (START_BLOCK) + \
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


def run_blockstored():
   """ run blockstored
   """
   global blockstored
   global bitcoind
   global blockchain_client
   global bitcoin_opts
   global CHAIN_COM_API_ID, CHAIN_COM_API_SECRET
   
   signal.signal(signal.SIGINT, signal_handler)
   
   config_file = blockdaemon.get_config_file( config.BLOCKSTORED_WORKING_DIR, config.BLOCKSTORED_CONFIG_FILE )
   bitcoin_opts = config.default_bitcoind_opts( config_file )
   
   arg_bitcoin_opts, argparser = blockdaemon.parse_bitcoind_args( return_parser=True )

   # command-line overrides config file
   for (k, v) in arg_bitcoin_opts.items():
      bitcoin_opts[k] = v
   
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
   
   print args 
   print "multiprocessing = (%s, %s)" % (config.MULTIPROCESS_NUM_WORKERS, config.MULTIPROCESS_WORKER_BATCH)
   
   # get chain.com info from the config file...
   blockchain_client = get_blockchain_client()
   if blockchain_client is None:
      log.error("Failed to initialized blockchain client")
      exit(1)
      
   """
   # Print default help message, if no argument is given
   if len(sys.argv) == 1:
      parser.print_help()
      sys.exit(1)
   """
   
   blockdaemon.setup( bitcoin_opts )
   
   try:
      
      bitcoind = blockdaemon.create_bitcoind_connection(bitcoin_opts['bitcoind_user'],
                                                        bitcoin_opts['bitcoind_passwd'],
                                                        bitcoin_opts['bitcoind_server'],
                                                        bitcoin_opts['bitcoind_port'],
                                                        bitcoin_opts['bitcoind_use_https'] )
   except Exception, e:
      log.exception(e)
      # NOTE: has the important side-effect of making create_bitcoind_connection() work in the future!
      bitcoind = blockdaemon.prompt_user_for_bitcoind_details( config.BLOCKSTORED_WORKING_DIR, config.BLOCKSTORED_CONFIG_FILE )

   if args.action == 'start':
      stop_server()
      if args.foreground:
         log.info('Initializing blockstored server in foreground ...')
         run_server( bitcoind, foreground=True )
         while(1):
               stay_alive = True
      else:
         log.info('Starting blockstored server ...')
         run_server( bitcoind )
   elif args.action == 'stop':
      stop_server()


if __name__ == '__main__':
    
   run_blockstored()
