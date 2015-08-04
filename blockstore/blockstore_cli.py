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

from lib import config, schemas, parsing, profile
import pybitcoin

import logging

from kademlia.network import Server

from twisted.python import log
from twisted.internet.error import ConnectionRefusedError
from twisted.internet import reactor
from txjsonrpc.netstring.jsonrpc import Proxy

from dht.storage import BlockStorage

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


def link_immutable_profile( user_profile_json, data_hash ):
    """
    Reactor callback to a lookup(name) that 
    puts a hash for immutable data into a user's profile,
    and serializes and returns the new JSON
    """
    
    user_profile = parsing.parse_user_profile( user_profile_json )
    if user_profile is None:
       log.error("Failed to parse user profile '%s'" % user_profile_json )
       raise Exception("Failed to parse user profile")
    
    profile.add_immutable_data( user_profile, data_hash )
    
    # serialize 
    new_profile_json = None 
    try:
       new_profile_json = profile.serialize_user_profile( user_profile )
    except Exception, e:
       log.error("Failed to serialize '%s'" % new_profile_json )
       raise e
    
    return new_profile_json 
    
    
def update_profile_deferred( user_profile_json, apiProxy, name, privatekey ):
   """
   Reactor callback to update() the user profile.
   Returns a deferred call to update().
   """
   
   update_key = pybitcoin.hash.hex_hash160( user_profile_json )
   update_deferred = apiProxy.callRemote("update", name, update_key, privatekey )
   return update_deferred
   
   
def store_profile( result, user_profile_json ):
   """
   Store JSON profile data to the storage providers, synchronously.
   """
   
   profile_key = pybitcoin.hash.hex_hash160( user_profile_json )
   result = dht_server.set(key, value)
   return result       
   

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
        'put_mutable',
        help='<data> | Store data into the DHT, but do NOT put the hash into the blockchain.')
    subparser.add_argument(
        'data', type=str,
        help='the data to store in DHT')
    
    # ------------------------------------
    subparser = subparsers.add_parser(
        'put_immutable',
        help='<name> <data> <privatekey> | Store data into the DHT, update the user\'s profile\'s list of data keys, and sign and write the new profile\'s hash to the blockchain).')
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
        'link_immutable',
        help='<name> <key> <privatekey> | Put a data hash into the user\'s profile, and sign and write the new profile\'s hash to the blockchain.')
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
        'get_mutable',
        help='<hash> | Get data from the DHT that has a given hash.')
    subparser.add_argument(
        'hash', type=str,
        help='the hash of the data, used as lookup key for DHT')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'has_immutable',
        help='<name> <hash> | Determine whether or not the user\'s profile has a given data hash.')
    subparser.add_argument(
        'name', type=str,
        help='the name of the user')
    subparser.add_argument(
        'hash', type=str,
        help='the hash of the data')
    
    # ------------------------------------
    subparser = subparsers.add_parser(
        'get_immutable',
        help='<name> <hash> | Verify that a piece of data was authored by the given user, and fetch it from the DHT if so.')
    subparser.add_argument(
        'name', type=str,
        help='the name of the user')
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
        
    elif args.action == 'put_mutable':
        value = args.data

        key = pybitcoin.hash.hex_hash160(value)
        logger.debug('Storing to the DHT: %s, %s', key, value)

        client = proxy.callRemote('put_mutable', key, value)

    elif args.action == 'put_immutable':
        name = args.name
        value = args.data
        privatekey = args.private_key

        key = pybitcoin.hash.hex_hash160(value)
        logger.debug('Storing to the DHT and adding to %s\'s profile in the blockchain: %s, %s', name, key, value)

        client = proxy.callRemote('lookup', name)
        client.addCallback( link_immutable_profile, key )
        client.addCallback( update_profile, proxy, name, privatekey )

    elif args.action == 'link_immutable':
        name = args.name
        key = args.hash
        privatekey = args.private_key
        
        logger.debug('Adding to %s\'s profile in the blockchain: %s', name, key)

        client = proxy.callRemote('link_immutable', name, key, privatekey)

    elif args.action == 'get_mutable':         
        key = args.hash 
        
        logger.debug("Getting from the DHT: %s", key )
        client = proxy.callRemote('get_mutable', key)
        
    elif args.action == 'has_immutable':
        name = args.name 
        key = args.hash 
        
        logger.debug("Verifying that %s authored %s", name, key )
        client = proxy.callRemote('has_immutable', name, key )

    elif args.action == 'get_immutable':
        name = args.name 
        key = args.hash 
        
        logger.debug("Getting %s's data %s from the DHT", name, key )
        client = proxy.callRemote('get_immutable', name, key )
        
    elif args.action == 'lookup':
        logger.debug('Looking up %s', args.name)
        client = proxy.callRemote('lookup', args.name)

    client.addCallback(printValue).addErrback(printError).addBoth(shutDown)
    reactor.run()

if __name__ == '__main__':
    run_cli()
