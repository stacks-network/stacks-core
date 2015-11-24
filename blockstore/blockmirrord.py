#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

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
    along with Blockstore. If not, see <http://www.gnu.org/licenses/>.
"""


import argparse
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
import json
import requests

from lib import config
from lib import get_storage_ops_in_blocks
from lib import config
from lib import schemas
from lib import workpool

import dht.plugin

from pybitcoin.rpc.namecoind_client import NamecoindClient

"""
    Blockstore mirror daemon, for Amazon S3
"""

log = logging.getLogger()
log.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
log_format = ('[%(levelname)s] [%(module)s:%(lineno)d] %(message)s' if config.DEBUG else '%(message)s')
formatter = logging.Formatter( log_format )
console.setFormatter(formatter)
log.addHandler(console)

blockmirrord = None
bitcoind = None

cached_namespace = None

ONENAME_API_ENDPOINT="api.onename.com/v1/"

def signal_handler(signal, frame):
    """ Handle Ctrl+C for dht node
    """
    import signal
    
    log.info('\n')
    log.info('Exiting blockmirrord server')
    stop_server()
    sys.exit(0)


def json_traceback():
    exception_data = traceback.format_exc().splitlines()
    return {
        "error": exception_data[-1],
        "traceback": exception_data
    }


# ------------------------------
def stat_record( record_key ):
   """
   Determine whether or not a record has been put
   """

# ------------------------------
def get_record( record_key ):
   """
   Get a record from the mirror 
   """
   pass 


# ------------------------------
def put_record( record_key, record_value ):
   """
   Store a record to the mirror
   """
   pass 


# ------------------------------
def delete_record( record_key ):
   """
   Delete a record from the mirror 
   """
   pass


# ------------------------------
class BlockmirrordRPC(jsonrpc.JSONRPC):
    """ Blockmirrord rpc
    """

    def __init__(self):
        pass

    def jsonrpc_ping(self):
        reply = {}
        reply['status'] = "alive"
        return reply

    def jsonrpc_get(self, key):
        # 
        pass
     

# ------------------------------
old_block = 0
index_initialized = False

def sync_blockchain( working_dir, first_block, last_block ):
   """
   Synchronize the mirror with the blockchain.
   That is, make sure we have downloaded and validated 
   all cryptocurrency blocks up to the latest block, and 
   in doing so, have obtained the entire sequence of storage
   operations.
   
   Return the storage sequence for this range of blocks on success.
   """
   
   working_dir = blockdaemon.get_working_dir( working_dir )

   namespace_file = os.path.join( working_dir, config.BLOCKSTORED_NAMESPACE_FILE)
   snapshots_file = os.path.join( working_dir, config.BLOCKSTORED_SNAPSHOTS_FILE)
   lastblock_file = os.path.join( working_dir, config.BLOCKSTORED_LASTBLOCK_FILE)

   start = datetime.datetime.now()
   
   num_workers = config.MULTIPROCESS_NUM_WORKERS
   storage_ops = []
   
   # feed workers bitcoind this way
   workpool.multiprocess_bitcoind_factory( blockdaemon.create_bitcoind_connection )
   
   pool = Pool( processes=num_workers )
   
   # get *all* the block nameops!
   storage_ops = get_storage_ops_in_blocks( pool, range(first_block, last_block+1) )
   pool.close()
   pool.join()
   storage_ops.sort()
   
   time_taken = "%s seconds" % (datetime.datetime.now() - start).seconds
   log.info(time_taken)
   
   return storage_ops


def process_rmdata( working_dir, storage_ops ):
   """
   Find all DATA_RM operations, validate them, and remove them 
   from the mirror.
   """
   pass 


def process_putdata( working_dir, storage_ops ):
   """
   Find all DATA_PUT operations, validat them, fetch them, and 
   put them into the mirror.
   """
   pass


def refresh_mirror( working_dir, first_block, last_block ):
   """
   Refresh the mirror:
   * process all new invalidations
   * grab and mirror any new profiles from the DHT
   
   This gets called by Twisted every time there ought to be a new block.
   """

   from twisted.python import log
   from kademlia.network import Server 
   
   # make soure our bitcoind cached block index is up-to-speed 
   nameop_sequence = sync_blockchain( working_dir, first_block, last_block )
   if nameop_sequence is None:
      
      log.error("sync_blockchain(%s-%s) failed" % (first_block, last_block))
      return None
   
   # synchronize name registrations...
   
   
   server = Server()
   server.listen( dht.plugin.DHT_SERVER_PORT )
   server.bootstrap( dht.plugin.DEFAULT_DHT_SERVERS ).addCallback( connect_done, server )
   
   pass


def stop_server():
    """ Stop the blockmirrord server
    """
    # Quick hack to kill a background daemon
    import subprocess
    import signal
    import os

    from .lib.config import BLOCKMIRRORD_PID_FILE

    working_dir = get_working_dir()

    pid_file = os.path.join(working_dir, BLOCKMIRRORD_PID_FILE)
    pid_data = None 
    
    with open(pid_file) as fin:
       pid_data = fin.read()
       fin.close()
       os.remove(pid_file)
       
    pid = int(pid_data)
    os.kill(pid, signal.SIGKILL)
    

def run_server( bitcoind, foreground=False):
    """ run the blockmirrord server
    """

    global blockmirrord 
    
    if bitcoind is None:
       bitcoind = blockdaemon.init_bitcoind( config.BLOCKMIRRORD_WORKING_DIR, config.BLOCKMIRRORD_CONFIG_FILE )

    from .lib.config import BLOCKMIRRORD_PID_FILE, BLOCKMIRRORD_LOG_FILE
    from .lib.config import BLOCKMIRRORD_TAC_FILE

    working_dir = blockdaemon.get_working_dir( config.BLOCKMIRRORD_WORKING_DIR )

    current_dir = os.path.abspath(os.path.dirname(__file__))

    tac_file = os.path.join(current_dir, BLOCKMIRRORD_TAC_FILE)
    log_file = os.path.join(working_dir, BLOCKMIRRORD_LOG_FILE)
    pid_file = os.path.join(working_dir, BLOCKMIRRORD_PID_FILE)

    start_block, current_block = get_index_range()

    if foreground:
        command = 'twistd --pidfile=%s -noy %s' % (pid_file, tac_file)
    else:
        command = 'twistd --pidfile=%s --logfile=%s -y %s' % (pid_file,
                                                              log_file,
                                                              tac_file)

    try:
        
        # bring the mirror up to speed
        refresh_mirror()
        
        # begin serving
        blockmirrord = subprocess.Popen( command, shell=True, preexec_fn=os.setsid)
        log.info('Blockmirrord successfully started')

    except IndexError, ie:
        
        traceback.print_exc()
        
        try:
            os.killpg(blockmirrord.pid, signal.SIGTERM)
        except:
            pass
        exit(1)
    
    except Exception, e:
        log.exception(e)
        log.info('Exiting blockmirrord server')
        try:
            os.killpg(blockmirrord.pid, signal.SIGTERM)
        except:
            pass
        exit(1)



def parse_namecoind_args( return_parser=False, parser=None ):
    """
    Get namecoind command-line arguments.
    Optionally return the parser as well.
    """
    
    namecoin_opts = {}
    
    if parser is not None:
       parser = argparse.ArgumentParser(
          description='Blockmirror Daemon version {}'.format(config.VERSION))

    parser.add_argument(
        '--namecoind-server',
        help='the hostname or IP address of the namecoind RPC server')
    parser.add_argument(
        '--namecoind-port', type=int,
        help='the namecoind RPC port to connect to')
    parser.add_argument(
        '--namecoind-user',
        help='the username for namecoind RPC server')
    parser.add_argument(
        '--namecoind-passwd',
        help='the password for namecoind RPC server')
    parser.add_argument(
        "--namecoind-use-https", action='store_true',
        help='use HTTPS to connect to namecoind')
    
    args, _ = parser.parse_known_args()

    # propagate options 
    for (argname, config_name) in zip( ["namecoind_server", "namecoind_port", "namecoind_user", "namecoind_passwd"], \
                                       ["BITCOIND_SERVER", "BITCOIND_PORT", "BITCOIND_USER", "BITCOIND_PASSWD"] ):
        
        if hasattr( args, argname ) and getattr( args, argname ) is not None:
            
            namecoin_opts[ argname ] = getattr( args, argname )
    
    if hasattr( args, "namecoind_use_https" ):
        if args.namecoin_use_https:
            
           namecoin_opts[ "namecoind_use_https" ] = True
       
        else:
           
           namecoin_opts[ "namecoind_use_https" ] = False 
           
    if return_parser:
       return namecoin_opts, parser 
    else:
       return namecoin_opts
    
    

def run_blockmirrord():
    """ run blockmirrord
    """
    global blockmirrord
    global bitcoind
    global namecoind
    global cached_namespace
    
    signal.signal(signal.SIGINT, signal_handler)
    
    bitcoin_opts, parser = blockdaemon.parse_bitcoind_args( return_parser=True )
    namecoin_opts, parser = parse_namecoind_args( return_parser=True, parser=parser )
    
    parser.add_argument(
        "--namespace",
        help="path to the cached namespace JSON file")
    
    subparsers = parser.add_subparsers(
        dest='action', help='the action to be taken')
    parser_server = subparsers.add_parser(
        'start',
        help='start the blockmirrord server')
    parser_server.add_argument(
        '--foreground', action='store_true',
        help='start the blockmirrord server in foreground')
    parser_server = subparsers.add_parser(
        'stop',
        help='stop the blockmirrord server')
    
    args, _ = parser.parse_known_args()
    
    # did we get a namespace JSON file?
    if hasattr( args, "namespace" ) and getattr( args, "namespace" ) is not None:
       
       namespace_path = args.namespace
       namespace_json = None 
       
       log.info("Loading JSON from '%s'" % namespace_path)
          
       with open(namespace_path, "r") as namespace_fd:
          namespace_json = namespace_fd.read()
       
       log.info("Parsing JSON")
       
       try:
          cached_namespace = json.loads( namespace_json )
       except Exception, e:
          log.exception(e)
          exit(1)
       
    blockdaemon.setup( bitcoin_opts )
    
    config_file = blockdaemon.get_config_file( config.BLOCKMIRRORD_WORKING_DIR, config.BLOCKMIRRORD_CONFIG_FILE )
    
    if args.action == 'start':
        stop_server()
        if args.foreground:
            log.info('Initializing blockmirrord server in foreground ...')
            run_server( bitcoind, foreground=True )
            while(1):
                stay_alive = True
        else:
            log.info('Starting blockmirrord server ...')
            run_server( bitcoind )
    elif args.action == 'stop':
        stop_server()

if __name__ == '__main__':
    
   run_blockmirrord()

