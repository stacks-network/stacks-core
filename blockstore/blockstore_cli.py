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
        'namespace_define',
        help='<namespace_id> <lifetime> <base_name_cost> <cost_decay_rate> <privatekey> | define a namespace, in preparation for importing names.')
    subparser.add_argument( 
        'namespace_id', type=str, 
        help='the human-readable namespace identifier')
    subparser.add_argument(
        'lifetime', type=int,
        help='the number of blocks for which a name will be valid (any value less than zero means "forever")')
    subparser.add_argument(
        'base_name_cost', type=int,
        help='the cost (in satoshis) for a 1-character name in this namespace')
    subparser.add_argument(
        'cost_decay_rate', type=float,
        help='the rate at which the value of a name decays, based on its length: if L is the length, R is the rate, and B is the base name cost, then the cost per name shall be ceil(B / (R^(L-1)))')
    subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the owner Bitcoin address')
    
    # ------------------------------------
    subparser = subparsers.add_parser(
        'namespace_begin',
        help='<namespace_id> <privatekey> | begin the namespace, completing its definition and opening it for registration.')
    subparser.add_argument(
        'namespace_id', type=str,
        help='the human-readable namespace identifier')
    subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the owner Bitcoin address')
    
    # ------------------------------------
    subparser = subparsers.add_parser(
        'putdata',
        help='<data> | store unsigned data into the DHT')
    subparser.add_argument(
        'data', type=str,
        help='the data to store in DHT')
    
    # ------------------------------------
    subparser = subparsers.add_parser(
        'signdata',
        help='<name> <data> <privatekey> | data value to sign in the blockchain')
    subparser.add_argument(
        'name', type=str,
        help='the name that owns this data')
    subparser.add_argument(
        'data', type=str,
        help='the data to sign')
    subparser.add_argument(
        'privatekey', type=str,
        help='the private key associated with the name')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'putsigned',
        help='<name> <data> <privatekey> | data value to sign in the blockchain')
    subparser.add_argument(
        'name', type=str,
        help='the name that owns this data')
    subparser.add_argument(
        'data', type=str,
        help='the data to sign')
    subparser.add_argument(
        'privatekey', type=str,
        help='the private key associated with the name')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'getdata',
        help='<hash> | get the data from DHT for given hash')
    subparser.add_argument(
        'hash', type=str,
        help='the hash of the data, used as lookup key for DHT')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'verifydata',
        help='<name> <hash> | verify that a datum was signed by a user')
    subparser.add_argument(
       'name', type=str,
       help='the name of the user that signed the data')
    subparser.add_argument(
       'hash', type=str,
       help='the hash of the data')
    
    # ------------------------------------
    subparser = subparsers.add_parser(
        'getverified',
        help='<name> <hash> | get the data from DHT for given hash, and verify that it was signed by a user')
    subparser.add_argument(
       'name', type=str,
       help='the name of the user that signed the data')
    subparser.add_argument(
        'hash', type=str,
        help='the hash of the data, used as lookup key for DHT')


    # ------------------------------------
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
        client = proxy.callRemote('update', args.name, args.data, args.privatekey)

    elif args.action == 'transfer':
        logger.debug('Transfering %s', args.name)
        client = proxy.callRemote('transfer', args.name, args.address, args.privatekey)

    elif args.action == 'renew':
        logger.debug('Renewing %s', args.name)
        client = proxy.callRemote('renew', args.name, args.privatekey)

    elif args.action == 'namespace_define':
        logger.debug('Defining namespace %s' % args.namespace_id)
        client = proxy.callRemote('namespace_define', args.namespace_id, args.lifetime, args.base_name_cost, args.cost_decay_rate, args.privatekey )
        
    elif args.action == 'namespace_begin':
        logger.debug('Starting namespace %s' % args.namespace_id)
        client = proxy.callRemote('namespace_begin', args.namespace_id, args.privatekey )
        
    elif args.action == 'putdata':
        value = args.data

        key = coinkit.hex_hash160(value)
        logger.debug('Storing %s', value)

        client = proxy.callRemote('put', key, value)

    elif args.action == 'signdata':
        name = args.name
        value = args.data 
        
        key = coinkit.hex_hash160(value)
        logger.debug("Signing hash '%s' by '%s'", key, name)
        
        client = proxy.callRemote('signdata', name, key, value, args.privatekey)
        
        
    elif args.action == 'putsigned':
        name = args.name
        value = args.data 
        
        key = coinkit.hex_hash160(value)
        logger.debug("Storing and signing hash '%s' by '%s'", key, name)
        
        client = proxy.callRemote('putsigned', name, key, value, args.privatekey )
        
    elif args.action == 'verifydata':
        name = args.name 
        key = args.hash
        
        logger.debug("Verifying that hash '%s' was signed by '%s'", key, name )
        
        client = proxy.callRemote('verifydata', name, key )
    
    elif args.action == 'getdata':
        logger.debug('Getting %s', args.hash)

        client = proxy.callRemote('get', args.hash)
        client.addCallback(getFormat)

    elif args.action == 'getverified':
        logger.debug("Getting %s and verifying that '%s' put it", args.hash, args.name )
        
        client = proxy.callRemote('getverified', args.name, args.hash )
        

    elif args.action == 'lookup':
        logger.debug('Looking up %s', args.name)
        client = proxy.callRemote('lookup', args.name)

    client.addCallback(printValue).addErrback(printError).addBoth(shutDown)
    reactor.run()

if __name__ == '__main__':
    run_cli()
