#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Opennamed
    ~~~~~
    :copyright: (c) 2014 by Openname.org
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

from txjsonrpc.netstring import jsonrpc
from twisted.internet import reactor

from lib import config
from lib import get_nameops_in_block, build_nameset, NameDb
from lib import config
from coinkit import BitcoindClient, ChainComClient

log = logging.getLogger()
log.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
formatter = logging.Formatter('%(message)s')
console.setFormatter(formatter)
log.addHandler(console)

from bitcoinrpc.authproxy import AuthServiceProxy

config_options = 'https://' + config.BITCOIND_USER + ':' + \
    config.BITCOIND_PASSWD + '@' + config.BITCOIND_SERVER + ':' + \
    str(config.BITCOIND_PORT)

bitcoind = AuthServiceProxy(config_options)

from lib import preorder_name, register_name, update_name, \
    transfer_name

bitcoind_client = BitcoindClient(
    config.BITCOIND_USER, config.BITCOIND_PASSWD, server=config.BITCOIND_SERVER,
    port=str(config.BITCOIND_PORT))

try:
    chain_com_client = ChainComClient(config.CHAIN_COM_API_ID,
                                      config.CHAIN_COM_API_SECRET)
except:
    pass


def signal_handler(signal, frame):
    """ Handle Ctrl+C for dht node
    """
    import signal
    log.info('\n')
    log.info('Exiting opennamed server')
    stop_server()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


class OpennamedRPC(jsonrpc.JSONRPC):
    """ opennamed rpc
    """

    def __init__(self, dht_server=None):
        self.dht_server = dht_server

    def jsonrpc_ping(self):
        reply = {}
        reply['status'] = "alive"
        return reply

    def jsonrpc_get(self, key):
        return self.dht_server.get(key)

    def jsonrpc_set(self, key, value):

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

        info = bitcoind.getinfo()
        reply = {}
        reply['blocks'] = info['blocks']
        reply['test'] = "hello"
        return reply

    def jsonrpc_preorder(self, name, consensushash, privatekey):
        """ Preorder a name
        """

        print str(privatekey)

        resp = preorder_name(
            name, consensushash, str(privatekey),
            blockchain_client=bitcoind_client,
            testset=True)

        log.debug('preorder <%s, %s>' % (name, privatekey))

        return resp

    def jsonrpc_register(self, name, salt, privatekey):
        """ Register a name
        """

        resp = register_name(name, salt, privatekey,
                             blockchain_client=bitcoind_client, testset=True)

        log.debug('register <%s, %s, %s>' % (name, salt, privatekey))

        return resp

    def jsonrpc_update(self, name, data, privatekey):
        """ Update a name
        """

        resp = update_name(name, data, privatekey,
                           blockchain_client=bitcoind_client, testset=True)

        log.debug('update <%s, %s, %s>' % (name, data, privatekey))

        return resp

    def jsonrpc_transfer(self, name, address, privatekey):
        """ Transfer a name
        """

        resp = transfer_name(name, address, privatekey,
                             blockchain_client=bitcoind_client, testset=True)

        log.debug('transfer <%s, %s, %s>' % (name, address, privatekey))

        return resp

    def jsonrpc_renew(self, name, privatekey):
        """ Renew a name
        """

        log.debug('renew <%s, %s>' % (name, privatekey))

        return


def refresh_index(first_block, last_block, initial_index=False):

    from twisted.python import log as twisted_log

    working_dir = get_working_dir()

    namespace_file = os.path.join(working_dir, config.OPENNAMED_NAMESPACE_FILE)
    lastblock_file = os.path.join(working_dir, config.OPENNAMED_LASTBLOCK_FILE)

    start = datetime.datetime.now()

    nameop_sequence = []

    if initial_index:
        log.info('Creating initial index ...')

    for block_number in range(first_block, last_block + 1):
        if initial_index:
            log.info('Processing block %s', block_number)
        else:
            twisted_log.msg('Processing block', block_number)

        block_nameops = get_nameops_in_block(bitcoind, block_number)
        
        if initial_index:
            log.info('block_nameops %s', block_nameops)
        else:
            twisted_log.msg('block_nameops', block_nameops)

        nameop_sequence.append((block_number, block_nameops))

    #log.info(nameop_sequence)

    time_taken = "%s seconds" % (datetime.datetime.now() - start).seconds
    #log.info(time_taken)

    db = NameDb(namespace_file)
    merkle_snapshot = build_nameset(db, nameop_sequence)
    db.save_names(namespace_file)

    merkle_snapshot = "merkle snapshot: %s\n" % merkle_snapshot
    #log.info(merkle_snapshot)
    #log.info(db.name_records)

    fout = open(lastblock_file, 'w')  # to overwrite
    fout.write(str(last_block))
    fout.close()

# ------------------------------
old_block = 0
index_initialized = False


def reindex_blockchain():

    from twisted.python import log
    global old_block
    global index_initialized
    global counter

    start_block, current_block = get_index_range()

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
            message = 'Blockchain: checking last %s block(s)' % check_blocks
            log.msg(message)

            # call the reindex func here
            refresh_index(old_block + 1, current_block)
            old_block = current_block


def get_working_dir():

    from os.path import expanduser
    home = expanduser("~")

    from lib.config import OPENNAMED_WORKING_DIR
    working_dir = os.path.join(home, OPENNAMED_WORKING_DIR)

    if not os.path.exists(working_dir):
        os.makedirs(working_dir)

    return working_dir


def get_index_range(start_block=0):

    from lib.config import START_BLOCK

    if start_block == 0:
        start_block = START_BLOCK

    current_block = int(bitcoind.getblockcount())

    working_dir = get_working_dir()
    lastblock_file = os.path.join(working_dir, config.OPENNAMED_LASTBLOCK_FILE)

    saved_block = 0
    if os.path.isfile(lastblock_file):

        fin = open(lastblock_file, 'r')
        saved_block = fin.read()
        saved_block = int(saved_block)
        fin.close()

    if saved_block == 0:
        pass
    elif saved_block == current_block:
        start_block = saved_block
    elif saved_block < current_block:
        start_block = saved_block + 1

    return start_block, current_block


def run_server(foreground=False):
    """ run the opennamed server
    """

    from .lib.config import OPENNAMED_PID_FILE, OPENNAMED_LOG_FILE
    from .lib.config import OPENNAMED_TAC_FILE
    from .lib.config import START_BLOCK

    working_dir = get_working_dir()

    current_dir = os.path.abspath(os.path.dirname(__file__))

    tac_file = os.path.join(current_dir, OPENNAMED_TAC_FILE)
    log_file = os.path.join(working_dir, OPENNAMED_LOG_FILE)
    pid_file = os.path.join(working_dir, OPENNAMED_PID_FILE)

    start_block, current_block = get_index_range()

    if foreground:
        command = 'twistd --pidfile=%s -noy %s' % (pid_file, tac_file)
    else:
        command = 'twistd --pidfile=%s --logfile=%s -y %s' % (pid_file,
                                                              log_file,
                                                              tac_file)

    try:
            #refresh_index(335563, 335566, initial_index=True)
            if start_block != current_block:
                refresh_index(start_block, current_block, initial_index=True)
            opennamed = subprocess.Popen(command,
                                         shell=True, preexec_fn=os.setsid)
            log.info('Opennamed successfully started')

    except Exception as e:
        log.debug(e)
        log.info('Exiting opennamed server')
        try:
            os.killpg(opennamed.pid, signal.SIGTERM)
        except:
            pass
        exit(1)


def stop_server():
    """ Stop the opennamed server
    """
    # Quick hack to kill a background daemon
    import subprocess
    import signal
    import os

    from .lib.config import OPENNAMED_PID_FILE

    working_dir = get_working_dir()

    pid_file = os.path.join(working_dir, OPENNAMED_PID_FILE)

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


def run_opennamed():
    """ run opennamed
    """
    parser = argparse.ArgumentParser(
        description='Openname Core Daemon version {}'.format(config.VERSION))

    parser.add_argument(
        '--bitcoind-server',
        help='the hostname or IP address of the bitcoind RPC server')
    parser.add_argument(
        '--bitcoind-port', type=int,
        help='the bitcoind RPC port to connect to')
    parser.add_argument(
        '--bitcoind-user',
        help='the username for bitcoind RPC server')
    parser.add_argument(
        '--bitcoind-passwd',
        help='the password for bitcoind RPC server')
    subparsers = parser.add_subparsers(
        dest='action', help='the action to be taken')
    parser_server = subparsers.add_parser(
        'start',
        help='start the opennamed server')
    parser_server.add_argument(
        '--foreground', action='store_true',
        help='start the opennamed server in foreground')
    parser_server = subparsers.add_parser(
        'stop',
        help='stop the opennamed server')

    # Print default help message, if no argument is given
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.action == 'start':
        stop_server()
        if args.foreground:
            log.info('Initializing opennamed server in foreground ...')
            run_server(foreground=True)
            while(1):
                stay_alive = True
        else:
            log.info('Starting opennamed server ...')
            run_server()
    elif args.action == 'stop':
        stop_server()

if __name__ == '__main__':
    run_opennamed()
