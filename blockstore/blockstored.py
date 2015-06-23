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

from txjsonrpc.netstring import jsonrpc
from twisted.internet import reactor

from lib import config
from lib import get_nameops_in_block, get_nameops_in_blocks, build_nameset, NameDb
from lib import config
from lib import cache
from coinkit import BitcoindClient, ChainComClient
from utilitybelt import is_valid_int

import lib.blockdaemon as blockdaemon

log = logging.getLogger()
log.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
log_format = ('[%(levelname)s] [%(module)s:%(lineno)d] %(message)s' if config.DEBUG else '%(message)s')
formatter = logging.Formatter( log_format )
console.setFormatter(formatter)
log.addHandler(console)


global bitcoind 

from lib import preorder_name, register_name, update_name, \
    transfer_name


try:
    blockchain_client = ChainComClient(config.CHAIN_COM_API_ID,
                                       config.CHAIN_COM_API_SECRET)
except:
    try:
        blockchain_client = BitcoindClient(
            config.BITCOIND_USER, config.BITCOIND_PASSWD,
            server=config.BITCOIND_SERVER, port=str(config.BITCOIND_PORT),
            use_https=True)
    except:
        blockchain_client = BitcoindClient(
            'openname', 'opennamesystem',
            server='btcd.onename.com', port='8332', use_https=True)


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
    namespace_file = os.path.join(
        working_dir, config.BLOCKSTORED_NAMESPACE_FILE)
    snapshots_file = os.path.join(
        working_dir, config.BLOCKSTORED_SNAPSHOTS_FILE)
    db = NameDb(namespace_file, snapshots_file)
    return db


class BlockstoredRPC(jsonrpc.JSONRPC):
    """ blockstored rpc
    """

    def __init__(self, dht_server=None):
        self.dht_server = dht_server

    def jsonrpc_ping(self):
        reply = {}
        reply['status'] = "alive"
        return reply

    def jsonrpc_get(self, key):
        return self.dht_server.get(key)

    def jsonrpc_lookup(self, name):
        """ Lookup the details for a name.
        """
        db = get_namedb()
        if str(name) in db.name_records:
            name_record = db.name_records[name]
        else:
            return {"error": "Not found."}

        return name_record

    def jsonrpc_set(self, key, value):
        """
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

        return self.dht_server.set(key, value)

    def jsonrpc_getinfo(self):
        """
        """

        info = bitcoind.getinfo()
        reply = {}
        reply['blocks'] = info['blocks']
        return reply

    def jsonrpc_preorder(self, name, privatekey):
        """ Preorder a name
        """
        db = get_namedb()
        consensus_hash = db.consensus_hashes.get('current')
        if not consensus_hash:
            return {"error": "Nameset snapshot not found."}
        if str(name) in db.name_records:
            return {"error": "Name already registered"}

        try:
            resp = preorder_name(
                str(name), str(consensus_hash), str(privatekey),
                blockchain_client=blockchain_client, testset=True)
        except:
            return json_traceback()

        log.debug('preorder <%s, %s>' % (name, privatekey))

        return resp

    def jsonrpc_register(self, name, privatekey):
        """ Register a name
        """
        log.info("name: %s" % name)
        db = get_namedb()
        if str(name) in db.name_records:
            return {"error": "Name already registered"}

        try:
            resp = register_name(
                str(name), str(privatekey),
                blockchain_client=blockchain_client, testset=True)
        except:
            return json_traceback()

        log.debug('register <%s, %s>' % (name, privatekey))

        return resp

    def jsonrpc_update(self, name, data, privatekey):
        """ Update a name
        """

        try:
            resp = update_name(
                str(name), str(data), str(privatekey),
                blockchain_client=blockchain_client, testset=True)
        except:
            return json_traceback()

        log.debug('update <%s, %s, %s>' % (name, data, privatekey))

        return resp

    def jsonrpc_transfer(self, name, address, privatekey):
        """ Transfer a name
        """

        try:
            resp = transfer_name(
                str(name), str(address), str(privatekey),
                blockchain_client=blockchain_client, testset=True)
        except:
            return json_traceback()

        log.debug('transfer <%s, %s, %s>' % (name, address, privatekey))

        return resp

    def jsonrpc_renew(self, name, privatekey):
        """ Renew a name
        """

        log.debug('renew <%s, %s>' % (name, privatekey))

        return

# ------------------------------
old_block = 0
index_initialized = False


def reindex_blockchain( bitcoind=None ):
    """
    """

    from twisted.python import log
    global old_block
    global index_initialized
    global counter
    
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
            blockdaemon.refresh_index(bitcoind, old_block + 1, current_block)
            old_block = current_block


def prompt_user_for_chaincom_details():
    """
    """
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
        config.CHAIN_COM_API_ID = api_key_id
        config.CHAIN_COM_API_SECRET = api_key_secret


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
            blockdaemon.refresh_index(bitcoind, start_block, current_block, config.BLOCKSTORED_WORKING_DIR, initial_index=True)
        
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
    
    # signal.signal(signal.SIGINT, signal_handler)
    
    bitcoin_opts, parser = blockdaemon.parse_bitcoind_args( return_parser=True )
    
    subparsers = parser.add_subparsers(
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
    
    args, _ = parser.parse_known_args()
    
    """
    # Print default help message, if no argument is given
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    """
    
    config.BITCOIND_USE_HTTPS = bitcoin_opts[ "bitcoind_use_https" ]
    
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
