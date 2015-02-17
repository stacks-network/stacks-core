#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

import argparse
import sys
import json
import traceback

from lib import config
import coinkit

import logging

from twisted.python import log
from twisted.internet.error import ConnectionRefusedError

# Disable twisted log messages, because it's too noisy
log.startLoggingWithObserver(log.PythonLoggingObserver, setStdout=0)

logger = logging.getLogger()
logger.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
formatter = logging.Formatter('%(message)s')
console.setFormatter(formatter)
logger.addHandler(logging.NullHandler())
# logger.addHandler(console)

from twisted.internet import reactor
from txjsonrpc.netstring.jsonrpc import Proxy

proxy = Proxy(config.BLOCKSTORED_SERVER, config.BLOCKSTORED_PORT)


def printValue(value):
    # logger.info(pretty_dump(value))
    print pretty_dump(value)


def getFormat(result):
    reply = {}

    value = json.loads(json.dumps(result))

    try:
        value = ast.literal_eval(value)
    except:
        pass

    reply['value'] = value

    return reply

import traceback


def printError(error):
    reply = {}
    traceback.print_exc()
    reply['error'] = "Error"

    if error.type is ConnectionRefusedError:
        reply['error'] = "Failed to connect to Blockstored"

    # logger.info(pretty_dump(reply))
    print pretty_dump(reply)


def shutDown(data):
    reactor.stop()


def pretty_dump(input):
    """ pretty dump
    """
    return json.dumps(input, sort_keys=True, indent=4, separators=(',', ': '))


def run_cli():
    """ run cli
    """
    parser = argparse.ArgumentParser(
        description='Blockstore Cli version {}'.format(config.VERSION))

    parser.add_argument(
        '--blockstored-server',
        help="""the hostname or IP address of the blockstored RPC server
                (default: {})""".format(config.BLOCKSTORED_SERVER))
    parser.add_argument(
        '--blockstored-port', type=int,
        help="""the blockstored RPC port to connect to
                (default: {})""".format(config.BLOCKSTORED_PORT))

    subparsers = parser.add_subparsers(
        dest='action',
        help='the action to be taken')

    subparser = subparsers.add_parser(
        'getinfo',
        help='get basic info from the blockstored server')

    subparser = subparsers.add_parser(
        'ping',
        help='check if the blockstored server is up')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'preorder',
        help='<name> <privatekey> | preorder a name')
    subparser.add_argument(
        'name', type=str,
        help='the name that you want to preorder')
    subparser.add_argument(
        'privatekey', type=str,
        help='the private key of the Bitcoin address that will own the name')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'register',
        help='<name> <privatekey> | register/claim a name')
    subparser.add_argument(
        'name', type=str,
        help='the name that you want to register/claim')
    subparser.add_argument(
        'privatekey', type=str,
        help='the private key of the Bitcoin address that will own the name')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'update',
        help='<name> <data or datahash> <privatekey> | update data')
    subparser.add_argument(
        'name', type=str,
        help='the name that you want to update')
    subparser.add_argument(
        'data', type=str,
        help='data associated with name (value part of key-value) or datahash')
    subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the owner Bitcoin address')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'transfer',
        help='<name> <address> <privatekey> | transfer a name')
    subparser.add_argument(
        'name', type=str,
        help='the name that you want to register/claim')
    subparser.add_argument(
        'address', type=str,
        help='the new owner Bitcoin address')
    subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the owner Bitcoin address')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'renew',
        help='<name> <privatekey> | renew a name')
    subparser.add_argument(
        'name', type=str,
        help='the name that you want to renew')
    subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the owner Bitcoin address')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'storedata',
        help='<data> | data value to store in DHT')
    subparser.add_argument(
        'data', type=str,
        help='the data to store in DHT')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'getdata',
        help='<hash> | get the data from DHT for given hash')
    subparser.add_argument(
        'hash', type=str,
        help='the hash of the data, used as lookup key for DHT')

    subparser = subparsers.add_parser(
        'lookup',
        help='<name> | get the record for a given name')
    subparser.add_argument(
        'name', type=str,
        help='the name to look up')

    # Print default help message, if no argument is given
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.action == 'getinfo':
        client = proxy.callRemote('getinfo')

    elif args.action == 'ping':
        client = proxy.callRemote('ping')

    elif args.action == 'preorder':
        logger.debug('Preordering %s', args.name)
        client = proxy.callRemote(
            'preorder', str(args.name), str(args.privatekey))

    elif args.action == 'register':
        logger.debug('Registering %s', args.name)
        client = proxy.callRemote('register', args.name, args.privatekey)

    elif args.action == 'update':
        logger.debug('Updating %s', args.name)
        client = proxy.callRemote('update', args.name, args.data,
                                  args.privatekey)

    elif args.action == 'transfer':
        logger.debug('Transfering %s', args.name)
        client = proxy.callRemote('transfer', args.name, args.address,
                                  args.privatekey)

    elif args.action == 'renew':
        logger.debug('Renewing %s', args.name)
        client = proxy.callRemote('renew', args.name, args.privatekey)

    elif args.action == 'storedata':
        reply = {}
        value = args.data

        key = coinkit.hex_hash160(value)
        logger.debug('Storing %s', value)

        client = proxy.callRemote('set', key, value)

    elif args.action == 'getdata':
        logger.debug('Getting %s', args.hash)

        client = proxy.callRemote('get', args.hash)
        client.addCallback(getFormat)

    elif args.action == 'lookup':
        logger.debug('Looking up %s', args.name)
        client = proxy.callRemote('lookup', args.name)

    client.addCallback(printValue).addErrback(printError).addBoth(shutDown)
    reactor.run()

if __name__ == '__main__':
    run_cli()
