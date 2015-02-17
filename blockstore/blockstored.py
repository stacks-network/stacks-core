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

from txjsonrpc.netstring import jsonrpc
from twisted.internet import reactor

from lib import config
from lib import get_nameops_in_block, build_nameset, NameDb
from lib import config
from coinkit import BitcoindClient, ChainComClient
from utilitybelt import is_valid_int

log = logging.getLogger()
log.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
formatter = logging.Formatter('%(message)s')
console.setFormatter(formatter)
log.addHandler(console)

from bitcoinrpc.authproxy import AuthServiceProxy


def create_bitcoind_connection(
        rpc_username=config.BITCOIND_USER,
        rpc_password=config.BITCOIND_PASSWD,
        server=config.BITCOIND_SERVER,
        port=config.BITCOIND_PORT,
        use_https=config.BITCOIND_USE_HTTPS):
    """ creates an auth service proxy object, to connect to bitcoind
    """
    protocol = 'https' if use_https else 'http'
    if not server or len(server) < 1:
        raise Exception('Invalid bitcoind host address.')
    if not port or not is_valid_int(port):
        raise Exception('Invalid bitcoind port number.')
    authproxy_config_uri = '%s://%s:%s@%s:%s' % (
        protocol, rpc_username, rpc_password, server, port)

    return AuthServiceProxy(authproxy_config_uri)


def get_working_dir():

    from os.path import expanduser
    home = expanduser("~")

    from lib.config import BLOCKSTORED_WORKING_DIR
    working_dir = os.path.join(home, BLOCKSTORED_WORKING_DIR)

    if not os.path.exists(working_dir):
        os.makedirs(working_dir)

    return working_dir


def get_config_file():
    working_dir = get_working_dir()
    return os.path.join(working_dir, config.BLOCKSTORED_CONFIG_FILE)


from ConfigParser import SafeConfigParser


def prompt_user_for_bitcoind_details():
    """
    """
    config_file = get_config_file()
    parser = SafeConfigParser()

    parser.read(config_file)

    if not parser.has_section('bitcoind'):

        bitcoind_server = raw_input(
            "Enter bitcoind host address (default: 127.0.0.1): "
            ) or '127.0.0.1'
        bitcoind_port = raw_input(
            "Enter bitcoind rpc port (default: 8332): ") or '8332'
        bitcoind_user = raw_input("Enter bitcoind rpc user/username: ")
        bitcoind_passwd = raw_input("Enter bitcoind rpc password: ")
        use_https = raw_input("Is ssl enabled on bitcoind? (yes/no): ")

        if not parser.has_section('bitcoind'):
            parser.add_section('bitcoind')

        parser.set('bitcoind', 'server', bitcoind_server)
        parser.set('bitcoind', 'port', bitcoind_port)
        parser.set('bitcoind', 'user', bitcoind_user)
        parser.set('bitcoind', 'passwd', bitcoind_passwd)
        parser.set('bitcoind', 'use_https', use_https)

        fout = open(config_file, 'w')
        parser.write(fout)

        if use_https.lower() == "yes" or use_https.lower() == "y":
            bitcoind_use_https = True
        else:
            bitcoind_use_https = False

        return create_bitcoind_connection(bitcoind_user, bitcoind_passwd,
                                          bitcoind_server, bitcoind_port,
                                          bitcoind_use_https)

    else:
        parser.remove_section('bitcoind')
        fout = open(config_file, 'w')
        parser.write(fout)
        return create_bitcoind_connection()

try:
    bitcoind = create_bitcoind_connection()
except:
    bitcoind = prompt_user_for_bitcoind_details()

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

signal.signal(signal.SIGINT, signal_handler)


def json_traceback():
    exception_data = traceback.format_exc().splitlines()
    return {
        "error": exception_data[-1],
        "traceback": exception_data
    }


def get_namedb():
    working_dir = get_working_dir()
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


def refresh_index(first_block, last_block, initial_index=False):
    """
    """

    from twisted.python import log as twisted_log

    working_dir = get_working_dir()

    namespace_file = os.path.join(
        working_dir, config.BLOCKSTORED_NAMESPACE_FILE)
    snapshots_file = os.path.join(
        working_dir, config.BLOCKSTORED_SNAPSHOTS_FILE)
    lastblock_file = os.path.join(
        working_dir, config.BLOCKSTORED_LASTBLOCK_FILE)

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

    # log.info(nameop_sequence)

    time_taken = "%s seconds" % (datetime.datetime.now() - start).seconds
    # log.info(time_taken)

    db = get_namedb()
    merkle_snapshot = build_nameset(db, nameop_sequence)
    db.save_names(namespace_file)
    db.save_snapshots(snapshots_file)

    merkle_snapshot = "merkle snapshot: %s\n" % merkle_snapshot
    # log.info(merkle_snapshot)
    # log.info(db.name_records)

    fout = open(lastblock_file, 'w')  # to overwrite
    fout.write(str(last_block))
    fout.close()

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


def get_index_range(start_block=0):
    """
    """

    from lib.config import FIRST_BLOCK_MAINNET

    if start_block == 0:
        start_block = FIRST_BLOCK_MAINNET

    try:
        current_block = int(bitcoind.getblockcount())
    except:
        log.info("ERROR: Cannot connect to bitcoind")
        user_input = raw_input(
            "Do you want to re-enter bitcoind server configs? (yes/no): ")
        if user_input.lower() == "yes" or user_input.lower() == "y":
            prompt_user_for_bitcoind_details()
            log.info("Exiting. Restart blockstored to try the new configs.")
            exit(1)
        else:
            exit(1)

    working_dir = get_working_dir()
    lastblock_file = os.path.join(
        working_dir, config.BLOCKSTORED_LASTBLOCK_FILE)

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


def prompt_user_for_chaincom_details():
    """
    """
    config_file = get_config_file()
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


def init_bitcoind():
    """
    """

    config_file = get_config_file()
    parser = SafeConfigParser()

    parser.read(config_file)

    if parser.has_section('bitcoind'):
        try:
            return create_bitcoind_connection()
        except:
            return prompt_user_for_bitcoind_details()
        else:
            pass
    else:
        user_input = raw_input(
            "Do you have your own bitcoind server? (yes/no): ")
        if user_input.lower() == "yes" or user_input.lower() == "y":
            return prompt_user_for_bitcoind_details()
        else:
            log.info(
                "Using default bitcoind server at %s", config.BITCOIND_SERVER)
            return create_bitcoind_connection()


def stop_server():
    """ Stop the blockstored server
    """
    # Quick hack to kill a background daemon
    import subprocess
    import signal
    import os

    from .lib.config import BLOCKSTORED_PID_FILE

    working_dir = get_working_dir()

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


def run_server(foreground=False):
    """ run the blockstored server
    """

    global bitcoind
    prompt_user_for_chaincom_details()
    bitcoind = init_bitcoind()

    from .lib.config import BLOCKSTORED_PID_FILE, BLOCKSTORED_LOG_FILE
    from .lib.config import BLOCKSTORED_TAC_FILE
    from .lib.config import START_BLOCK

    working_dir = get_working_dir()

    current_dir = os.path.abspath(os.path.dirname(__file__))

    tac_file = os.path.join(current_dir, BLOCKSTORED_TAC_FILE)
    log_file = os.path.join(working_dir, BLOCKSTORED_LOG_FILE)
    pid_file = os.path.join(working_dir, BLOCKSTORED_PID_FILE)

    start_block, current_block = get_index_range()

    if foreground:
        command = 'twistd --pidfile=%s -noy %s' % (pid_file, tac_file)
    else:
        command = 'twistd --pidfile=%s --logfile=%s -y %s' % (pid_file,
                                                              log_file,
                                                              tac_file)

    try:
        # refresh_index(335563, 335566, initial_index=True)
        if start_block != current_block:
            refresh_index(start_block, current_block, initial_index=True)
        blockstored = subprocess.Popen(
            command, shell=True, preexec_fn=os.setsid)
        log.info('Blockstored successfully started')

    except Exception as e:
        log.debug(e)
        log.info('Exiting blockstored server')
        try:
            os.killpg(blockstored.pid, signal.SIGTERM)
        except:
            pass
        exit(1)


def run_blockstored():
    """ run blockstored
    """
    parser = argparse.ArgumentParser(
        description='Blockstore Core Daemon version {}'.format(config.VERSION))

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
        help='start the blockstored server')
    parser_server.add_argument(
        '--foreground', action='store_true',
        help='start the blockstored server in foreground')
    parser_server = subparsers.add_parser(
        'stop',
        help='stop the blockstored server')

    # Print default help message, if no argument is given
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.action == 'start':
        stop_server()
        if args.foreground:
            log.info('Initializing blockstored server in foreground ...')
            run_server(foreground=True)
            while(1):
                stay_alive = True
        else:
            log.info('Starting blockstored server ...')
            run_server()
    elif args.action == 'stop':
        stop_server()

if __name__ == '__main__':
    run_blockstored()
