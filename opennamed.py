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
import daemon
import logging
import os
import sys
import subprocess
import signal
from txjsonrpc.web import jsonrpc
from twisted.web import server
from twisted.internet import reactor

from opennamelib import config
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
dht_node = None


def signal_handler(signal, frame):
    """ Handle Ctrl+C for dht node
    """
    import signal
    log.info('\n')
    log.info('Exiting opennamed server')
    os.killpg(dht_node.pid, signal.SIGTERM)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

import opennamelib
from opennamelib import preorder_name, register_name, update_name, \
    transfer_name

bitcoind_client = BitcoindClient(
    config.BITCOIND_USER, config.BITCOIND_PASSWD, server=config.BITCOIND_SERVER,
    port=str(config.BITCOIND_PORT))

try:
    chain_com_client = ChainComClient(config.CHAIN_COM_API_ID,
                                      config.CHAIN_COM_API_SECRET)
except:
    pass

class OpennamedRPC(jsonrpc.JSONRPC):
    """ opennamed rpc
    """

    def jsonrpc_getinfo(self):
        info = bitcoind.getinfo()
        reply = {}
        reply['blocks'] = info['blocks']
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


def run_server():
    """ run the opennamed server
    """

    file_path = os.path.dirname(__file__) + '/dht/server.py'

    global dht_node
    dht_node = subprocess.Popen('twistd -noy ' + file_path,
                                shell=True, preexec_fn=os.setsid)
    log.info('Started dht server')

    try:
        reactor.listenTCP(int(config.DEFAULT_OPENNAMED_PORT), server.Site(OpennamedRPC()))
        reactor.run()

    except Exception as e:
        log.debug(e)
        log.info('Exiting opennamed server')
        os.killpg(dht_node.pid, signal.SIGTERM)
        exit(1)


def stop_server():
    """ Stop the opennamed server
    """
    # Quick hack to kill a background daemon
    import subprocess
    import signal
    import os

    p = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE)
    out, err = p.communicate()

    for line in out.splitlines():
        if 'opennamed start' in line:
            log.info('Stopping opennamed server')
            pid = int(line.split(None, 1)[0])
            os.kill(pid, signal.SIGKILL)

        elif 'twistd -noy' in line:
            log.info('Stopping dht node')
            pid = int(line.split(None, 1)[0])
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
        if args.foreground:
            log.info('Starting opennamed server in foreground')
            run_server()
        else:
            log.info('Starting opennamed server')
            with daemon.DaemonContext():
                run_server()
    elif args.action == 'stop':
        stop_server()

if __name__ == '__main__':
    run_opennamed()
