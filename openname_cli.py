#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Opennamed
    ~~~~~
    :copyright: (c) 2014 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

import argparse
import sys
import json

import zerorpc
import config
import coinkit

client = zerorpc.Client(timeout=config.RPC_TIMEOUT)
client.connect('tcp://' + config.OPENNAMED_SERVER + ':' + config.OPENNAMED_PORT)

from dht.client import dht_client
dht_client = dht_client()

import logging

log = logging.getLogger()
log.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
formatter = logging.Formatter('%(message)s')
console.setFormatter(formatter)
log.addHandler(console)


def pretty_dump(input):
    """ pretty dump
    """
    return json.dumps(input, sort_keys=False, indent=4, separators=(',', ': '))


def run_cli():
    """ run cli
    """
    parser = argparse.ArgumentParser(
        description='Openname Cli version {}'.format(config.VERSION))

    parser.add_argument(
        '--opennamed-server',
        help="""the hostname or IP address of the opennamed RPC server
                (default: {})""".format(config.OPENNAMED_SERVER))
    parser.add_argument(
        '--opennamed-port', type=int,
        help="""the opennamed RPC port to connect to
                (default: {})""".format(config.OPENNAMED_PORT))

    subparsers = parser.add_subparsers(
        dest='action',
        help='the action to be taken')

    subparser = subparsers.add_parser(
        'getinfo',
        help='get basic info from the opennamed server')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'preorder',
        help='<name> <privatekey> | preorder a name')
    subparser.add_argument(
        'name', type=str,
        help='the name that you want to preorder')
    subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the Bitcoin address that will own the name')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'register',
        help='<name> <salt> <privatekey> | register/claim a name')
    subparser.add_argument(
        'name', type=str,
        help='the name that you want to register/claim')
    subparser.add_argument(
        'salt', type=str,
        help='the salt')
    subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the Bitcoin address that will own the name')

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

    # Print default help message, if no argument is given
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.action == 'getinfo':
        try:
            log.info(pretty_dump(client.getinfo()))
        except Exception as e:
            log.info("Couldn't connect to opennamed server")
            exit(0)

    elif args.action == 'preorder':
        log.debug('Preordering %s', args.name)
        log.info(pretty_dump(
            client.preorder(args.name, args.privatekey)))

    elif args.action == 'register':
        log.debug('Registering %s', args.name)
        log.info(pretty_dump(
            client.register(args.name, args.salt, args.privatekey)))

    elif args.action == 'update':
        log.debug('Updating %s', args.name)
        log.info(pretty_dump(
            client.update(args.name, args.data, args.privatekey)))

    elif args.action == 'transfer':
        log.debug('Transfering %s', args.name)
        log.info(pretty_dump(
            client.transfer(args.name, args.address, args.privatekey)))

    elif args.action == 'renew':
        log.debug('Renewing %s', args.name)
        log.info(pretty_dump(
            client.renew(args.name, args.privatekey)))

    elif args.action == 'storedata':
        log.debug('Storing %s', args.data)
        key = coinkit.hex_hash160(args.data)

        reply = dht_client.set_key(key, args.data)

        log.info(pretty_dump(reply))

    elif args.action == 'getdata':
        log.debug('Get %s', args.hash)

        reply = dht_client.get_key(args.hash)

        log.info(pretty_dump(reply))

if __name__ == '__main__':
    run_cli()
