#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstore-client.

    Blockstore-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstore-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore-client.  If not, see <http://www.gnu.org/licenses/>.
"""

import argparse
import sys
import json
import traceback
import os
import pybitcoin

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

from blockstore_client import config, client, schemas, parsing, user
from blockstore_client import storage, drivers
from blockstore_client.utils import pretty_dump, print_result

log = config.log


def get_sorted_commands(display_commands=False):
    """ when adding new commands to the parser, use this function to
        check the correct sorted order
    """

    command_list = ['status', 'ping', 'preorder', 'register', 'update',
                    'transfer', 'renew', 'name_import', 'namespace_preorder',
                    'namespace_ready', 'namespace_reveal', 'put_mutable',
                    'put_immutable', 'get_mutable', 'get_immutable',
                    'cost', 'get_namespace_cost', 'get_nameops_at',
                    'get_name_blockchain_record', 'get_namespace_blockchain_record',
                    'get_name_record', 'lookup',
                    'get_all_names', 'get_names_in_namespace', 'consensus',
                    'lookup_snv', 'get_names_owned_by_address',
                    'preorder_tx', 'preorder_subsidized',
                    'register_tx', 'register_subsidized',
                    'update_tx', 'update_subsidized',
                    'transfer_tx', 'transfer_subsidized',
                    'revoke_tx', 'revoke_subsidized',
                    'renew_tx', 'renew_subsidized']

    if display_commands:
        for cmd in sorted(command_list):
            log.debug(cmd)

    return command_list


def run_cli():
    """ run cli
    """

    conf = config.get_config()

    if conf is None:
        log.error("Failed to load config")
        sys.exit(1)

    advanced_mode = conf['advanced_mode']

    parser = argparse.ArgumentParser(
      description='Blockstore cli version {}'.format(config.VERSION))

    subparsers = parser.add_subparsers(
      dest='action')

    # ------------------------------------
    # start commands

    subparser = subparsers.add_parser(
      'server',
      help='display server:port | update using --server --port')

    subparser.add_argument(
      '--server',
      action='store',
      help="""the hostname/IP of blockstored (current: {})""".format(config.BLOCKSTORED_SERVER))

    subparser.add_argument(
      '--port',
      action='store',
      help="""the server port to connect to (current: {})""".format(config.BLOCKSTORED_PORT))

    # ------------------------------------

    subparser = subparsers.add_parser(
      'advanced',
      help='check advanced mode | turn --mode=off or --mode=on')

    subparser.add_argument(
      '--mode',
      action='store',
      help="can be 'on' or 'off'")

    # ------------------------------------
    if advanced_mode == "on":
      subparser = subparsers.add_parser(
        'delete_immutable',
        help='<name> <hash> <privatekey> | Delete immutable data from the storage providers.')
      subparser.add_argument(
        'name', type=str,
        help='the name of the user')
      subparser.add_argument(
        'hash', type=str,
        help='the hash of the data')
      subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the user')

    # ------------------------------------
    if advanced_mode == "on":
      subparser = subparsers.add_parser(
        'delete_mutable',
        help='<name> <data_id> <privatekey> | Delete mutable data from the storage providers.')
      subparser.add_argument(
        'name', type=str,
        help='the name of the user')
      subparser.add_argument(
        'data_id', type=str,
        help='the unchanging identifier for this data')
      subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the user')

    # ------------------------------------
    if advanced_mode == "on":
      subparser = subparsers.add_parser(
        'get_all_names',
        help='[offset] [count] | get all names that exist')
      subparser.add_argument(
        'offset', nargs='?',
        help='The offset into the list at which to start reading')
      subparser.add_argument(
        'count', nargs='?',
        help='The maximum number of names to return')

    # ------------------------------------
    subparser = subparsers.add_parser(
      'consensus',
      help='<block height> | get consensus hash at given block')
    subparser.add_argument(
      'block_height', type=int, nargs='?',
      help='The block height.')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'get_immutable',
        help='<name> <hash> | get immutable data from storage')
      subparser.add_argument(
        'name', type=str,
        help='the name of the user')
      subparser.add_argument(
        'hash', type=str,
        help='the hash of the data')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'get_mutable',
        help='<name> <data_id> | get mutable data from storage')
      subparser.add_argument(
        'name', type=str,
        help='the name associated with the data')
      subparser.add_argument(
        'data_id', type=str,
        help='the unchanging identifier for this data')

    # ------------------------------------
    subparser = subparsers.add_parser(
      'cost',
      help="<name> | get the cost of a name")
    subparser.add_argument(
      'name', type=str,
      help="The fully-qualified name to check")

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'get_names_in_namespace',
        help='<namespace ID> [offset] [count] | get all names in a particular namespace')
      subparser.add_argument(
        'namespace_id', type=str,
        help='The namespace to search')
      subparser.add_argument(
        'offset', nargs='?',
        help='The offset into the list at which to start reading')
      subparser.add_argument(
        'count', nargs='?',
        help='The maximum number of names to return')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'get_names_owned_by_address',
        help='<address> | get all names owned by an address')
      subparser.add_argument(
        'address', type=str,
        help='The address to query')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'get_namespace_cost',
        help="<namespace_id> | get the cost of a namespace")
      subparser.add_argument(
        'namespace_id', type=str,
        help="The namespace ID to check")

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'get_name_record',
        help='<name> | get the off-blockchain record for a given name')
      subparser.add_argument(
        'name', type=str,
        help='the name to look up')

    # ------------------------------------
    subparser = subparsers.add_parser(
      'status',
      help='get basic information from the blockstored server')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'get_name_blockchain_record',
        help='<name> | get the blockchain-hosted information for a particular name')
      subparser.add_argument(
        'name', type=str,
        help='the name to query')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'get_namespace_blockchain_record',
        help='<namespace_id> | get the blockchain-hosted information for a particular namespace')
      subparser.add_argument(
        'namespace_id', type=str,
        help='the namespace to look up')

    # ------------------------------------
    subparser = subparsers.add_parser(
      'lookup',
      help='<name> | get name record for a particular name')
    subparser.add_argument(
      'name', type=str,
      help='the name to look up')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'lookup_snv',
        help='<name> <block_id> <consensus_hash> | Look up a name as it existed at a particular block, using SNV protocol')
      subparser.add_argument(
        'name', type=str,
        help='the name to look up')
      subparser.add_argument(
        'block_id', type=int,
        help='the block ID in the desired point in the past')
      subparser.add_argument(
        'consensus_hash', type=str,
        help='the trusted consensus hash at the given block')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'get_nameops_at',
        help='<block_id> | Look up all name operations that occurred at a block')
      subparser.add_argument(
        'block_id', type=int,
        help='the block ID in the desired point in the past')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'name_import',
        help='import a name into a revealed namespace')
      subparser.add_argument(
        'name', type=str,
        help='the name that you want to import')
      subparser.add_argument(
        'address', type=str,
        help='the new owner\'s Bitcoin address')
      subparser.add_argument(
        'hash', type=str,
        help='hash of the storage index to associate with the name')
      subparser.add_argument(
        'privatekey', type=str,
        help='the private key of the namespace revealer\'s address')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'namespace_preorder',
        help='preorder a namespace and claim the name')
      subparser.add_argument(
        'namespace_id', type=str,
        help='the human-readable namespace identifier')
      subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the namespace creator')
      subparser.add_argument(
        'address', type=str, nargs='?',
        help='[OPTIONAL] the address of private key that will import names into this namespace (should be different from the private key given here).  \
        If not given, a new private key will be generated.  The private key must be used to sign name_import requests, and the address must be submitted on namespace_reveal')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'namespace_reveal',
        help='define a namespace\'s parameters once preorder succeeds')
      subparser.add_argument(
        'namespace_id', type=str,
        help='the human-readable namespace identifier')
      subparser.add_argument(
        'addr', type=str,
        help='the address that will import names into the namespace, and open it for registration')
      subparser.add_argument(
        'lifetime', type=int,
        help='the number of blocks for which a name will be valid (any value less than zero means "forever")')
      subparser.add_argument(
        'coeff', type=int,
        help='constant cost multipler for names (in range [0, 256))')
      subparser.add_argument(
        'base', type=int,
        help='base cost for names (in range [0, 256))')
      subparser.add_argument(
        'bucket_exponents', type=str,
        help='per-name-length cost exponents (CSV string of 16 values in range [0, 16))')
      subparser.add_argument(
        'nonalpha_discount', type=int,
        help='non-alpha discount multipler (in range [0, 16))')
      subparser.add_argument(
        'no_vowel_discount', type=int,
        help='no-vowel discount multipler (in range [0, 16))')
      subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the namespace creator (from namespace_preorder)')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'namespace_ready',
        help='open namespace for registrations')
      subparser.add_argument(
        'namespace_id', type=str,
        help='the human-readable namespace identifier')
      subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the namespace creator')

    # ------------------------------------
    subparser = subparsers.add_parser(
      'ping',
      help='check if the blockstored server is up')

    # ------------------------------------
    subparser = subparsers.add_parser(
      'preorder',
      help='<name> <private_key> | preorder a name')
    subparser.add_argument(
      'name', type=str,
      help='the name that you want to preorder')
    subparser.add_argument(
      'privatekey', type=str,
      help='the private key of the Bitcoin account to pay for the name')
    subparser.add_argument(
      'address', type=str, nargs='?',
      help='[OPTIONAL] the address that will own the name (should be different from the address of the private key given here). \
      If not given, a new private key will be generated, and its address must be submitted upon register.')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'preorder_tx',
        help='<name> <privatekey> [address] | create an unsigned serialized transaction that will preorder a name.')
      subparser.add_argument(
        'name', type=str,
        help='the name that you want to preorder')
      subparser.add_argument(
        'privatekey', type=str,
        help='the private key of the Bitcoin account to pay for the name and register it')
      subparser.add_argument(
        'address', type=str, nargs='?',
        help='[OPTIONAL] the address that will own the name (should be different from the address of the private key given here). \
        If not given, a new private key will be generated, and its address must be submitted upon register.')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'preorder_subsidized',
        help='<name> <public_key> <address> <subsidy_key> | create an "anyone-can-pay" transaction to preorder a name, subsidized with a separate key.  The client must sign the <public_key>\'s address input separately to complete the transaction.')
      subparser.add_argument(
        'name', type=str,
        help='the name that you want to preorder')
      subparser.add_argument(
        'public_key', type=str,
        help='the client\'s public key, whose private counterpart will sign the subsidized transaction.')
      subparser.add_argument(
        'address', type=str,
        help='The address that will own the name (should be different from the address of the public key given here). \
        If not given, a new private key will be generated, and its address must be submitted upon register.')
      subparser.add_argument(
        'subsidy_key', type=str,
        help='the private key of the Bitcoin account to pay for the name')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'put_immutable',
        help='store immutable data into storage')
      subparser.add_argument(
        'name', type=str,
        help='the name that owns this data')
      subparser.add_argument(
        'data', type=str,
        help='the data to store')
      subparser.add_argument(
        'privatekey', type=str,
        help='the private key associated with the name')

    if advanced_mode == "on":
      # ------------------------------------
      put_mutable_parser = subparsers.add_parser(
        'put_mutable',
        help='<name> <data_id> <data> <privatekey> [<nonce>] | Store mutable data into the storage providers, creating it if it does not exist.')
      put_mutable_parser.add_argument(
        'name', type=str,
        help='the name that owns this data')
      put_mutable_parser.add_argument(
        'data_id', type=str,
        help='the unchanging identifier for this data')
      put_mutable_parser.add_argument(
        'data', type=str,
        help='the data to store')
      put_mutable_parser.add_argument(
        'privatekey', type=str,
        help='the private key assocated with the name')

    # ------------------------------------
    subparser = subparsers.add_parser(
      'register',
      help='<name> <private_key> <addr> | register/claim a name')
    subparser.add_argument(
      'name', type=str,
      help='the name that you want to register/claim')
    subparser.add_argument(
      'privatekey', type=str,
      help='the private key used to preorder the name')
    subparser.add_argument(
      'addr', type=str,
      help='the address that will own the name (given in the preorder)')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'register_tx',
        help='<name> <privatekey> <addr> | Generate an unsigned transaction to register/claim a name')
      subparser.add_argument(
        'name', type=str,
        help='the name that you want to register/claim')
      subparser.add_argument(
        'privatekey', type=str,
        help='the private key used to preorder the name')
      subparser.add_argument(
        'addr', type=str,
        help='the address that will own the name (given in the preorder)')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'register_subsidized',
        help='<name> <public_key> <addr> <subsidy_key> | create an "anyone-can-pay" transaction to register/claim a name, subsidized by a separate key.  The client must sign the <public_key>\'s address inputs before broadcasting it.')
      subparser.add_argument(
        'name', type=str,
        help='the name that you want to register/claim')
      subparser.add_argument(
        'public_key', type=str,
        help='the private key used to preorder the name')
      subparser.add_argument(
        'addr', type=str,
        help='the address that will own the name (given in the preorder)')
      subparser.add_argument(
        'subsidy_key', type=str,
        help='the private key used to pay for this transaction')

    if advanced_mode == "on":
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

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'renew_tx',
        help='<name> <privatekey> | create an unsigned transaction to renew a name')
      subparser.add_argument(
        'name', type=str,
        help='the name that you want to renew')
      subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the owner Bitcoin address')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'renew_subsidized',
        help='<name> <public_key> <subsidy_key> | create an "anyone-can-pay" transaction to renew a name, subsidized by a separate key.  The client must sign the <public_key>\'s address inputs before broadcasting it.')
      subparser.add_argument(
        'name', type=str,
        help='the name that you want to renew')
      subparser.add_argument(
        'public_key', type=str,
        help='the public key of the owner')
      subparser.add_argument(
        'subsidy_key', type=str,
        help='the key to subsidize the transaction')

    if advanced_mode == "on":
        # ------------------------------------
        subparser = subparsers.add_parser(
          'revoke',
          help='<name> <privatekey> | revoke a name and its data')
        subparser.add_argument(
          'name', type=str,
          help='the name that you want to revoke')
        subparser.add_argument(
          'privatekey', type=str,
          help='the privatekey of the owner Bitcoin address')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'revoke_tx',
        help='<name> <privatekey> | generate an unsigned transaction to revoke a name and its data')
      subparser.add_argument(
        'name', type=str,
        help='the name that you want to revoke')
      subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the owner Bitcoin address')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'revoke_subsidized',
        help='<name> <public_key> <subsidy_key> | create an "anyone-can-pay" transaction to revoke a name and its data, subsidized by a separate key.  The client must sign the <public_key>\'s address inputs before broadcasting it.')
      subparser.add_argument(
        'name', type=str,
        help='the name that you want to revoke')
      subparser.add_argument(
        'public_key', type=str,
        help='the public key of the owner Bitcoin address')
      subparser.add_argument(
        'subsidy_key', type=str,
        help='the key to subsidize the transaction')

    # ------------------------------------
    subparser = subparsers.add_parser(
      'transfer',
      help='<name> <address> <private_key> | transfer a name')
    subparser.add_argument(
      'name', type=str,
      help='the name that you want to register/claim')
    subparser.add_argument(
      'address', type=str,
      help='the new owner Bitcoin address')
    subparser.add_argument(
      'keepdata', type=str,
      help='whether or not the storage index should remain associated with the name [true|false]')
    subparser.add_argument(
      'privatekey', type=str,
      help='the privatekey of the owner Bitcoin address')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'transfer_tx',
        help='<name> <address> <keepdata> <privatekey> | create an unsigned transaction that will transfer a name')
      subparser.add_argument(
        'name', type=str,
        help='the name that you want to register/claim')
      subparser.add_argument(
        'address', type=str,
        help='the new owner Bitcoin address')
      subparser.add_argument(
        'keepdata', type=str,
        help='whether or not the storage index should remain associated with the name [true|false]')
      subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the owner Bitcoin address')

    if advanced_mode == "on":
      # ------------------------------------
      subparser = subparsers.add_parser(
        'transfer_subsidized',
        help='<name> <address> <keepdata> <public_key> <subsidy_key> | create an "anyone-can-pay" transaction that will transfer a name, subsidized by a separate key.  The client must sign the <public_key>\s address inputs before broadcasting it.')
      subparser.add_argument(
        'name', type=str,
        help='the name that you want to register/claim')
      subparser.add_argument(
        'address', type=str,
        help='the new owner Bitcoin address')
      subparser.add_argument(
        'keepdata', type=str,
        help='whether or not the storage index should remain associated with the name [true|false]')
      subparser.add_argument(
        'public_key', type=str,
        help='the public key of the owner Bitcoin address')
      subparser.add_argument(
        'subsidy_key', type=str,
        help='the key to subsidize the transaction.')

    # ------------------------------------
    subparser = subparsers.add_parser(
      'update',
      help='<name> <data> <private_key> | update a name record')
    subparser.add_argument(
      'name', type=str,
      help='the name that you want to update')
    subparser.add_argument(
      'record_json', type=str,
      help='the JSON-encoded user record to associate with the name')
    subparser.add_argument(
      'privatekey', type=str,
      help='the privatekey of the owner Bitcoin address')
    subparser.add_argument(
      'txid', type=str, nargs='?',
      help='[OPTIONAL] the transaction ID of the previously-attempted, partially-successful update')

    if advanced_mode == 'true':
      # ------------------------------------
      subparser = subparsers.add_parser(
        'update_tx',
        help='<name> <record_json> <private_key> [txid] | generate an unsigned transaction to update and store a name record')
      subparser.add_argument(
        'name', type=str,
        help='the name that you want to update')
      subparser.add_argument(
        'record_json', type=str,
        help='the JSON-encoded user record to associate with the name')
      subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the owner Bitcoin address')
      subparser.add_argument(
        'txid', type=str, nargs='?',
        help='[OPTIONAL] the transaction ID of the previously-attempted, partially-successful update')

      # ------------------------------------
      subparser = subparsers.add_parser(
        'update_subsidized',
        help='<name> <record_json> <public_key> <subsidy_key> [txid] | generate an "anyone-can-pay" transaction to update and store a name record, subsidized by a separate key.  The client will need to sign the <public_key>\'s address inputs before broadcasting it.')
      subparser.add_argument(
        'name', type=str,
        help='the name that you want to update')
      subparser.add_argument(
        'record_json', type=str,
        help='the JSON-encoded user record to associate with the name')
      subparser.add_argument(
        'public_key', type=str,
        help='the public key of the owner Bitcoin address')
      subparser.add_argument(
        'subsidy_key', type=str,
        help='the key to subsidize the transaction')
      subparser.add_argument(
        'txid', type=str, nargs='?',
        help='[OPTIONAL] the transaction ID of the previously-attempted, partially-successful update')


    # Print default help message, if no argument is given
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args, unknown_args = parser.parse_known_args()
    result = {}

    conf = config.get_config()

    blockstore_server = conf['server']
    blockstore_port = conf['port']

    proxy = client.session(conf=conf, server_host=blockstore_server, server_port=blockstore_port )

    if args.action == 'server':
        data = {}

        if args.server is not None and args.port is not None:
            config.update_config('blockstore-client', 'server', args.server)
            config.update_config('blockstore-client', 'port', args.port)
            data["message"] = "Updated server and port"
        elif args.server is not None:
            config.update_config('blockstore-client', 'server', args.server)
            data["message"] = "Updated server"
        elif args.port is not None:
            config.update_config('blockstore-client', 'port', args.port)
            data["message"] = "Updated port"

        # reload conf
        conf = config.get_config()

        data['server'] = conf['server']
        data['port'] = conf['port']
        result = data

    elif args.action == 'advanced':
        data = {}
        data["advanced_mode"] = advanced_mode

        if args.mode is not None:

            if args.mode != "on" and args.mode != "off":
                data['error'] = "Valid values are 'on' or 'off'"
            else:
                config.update_config('blockstore-client', 'advanced_mode', args.mode)
                data["message"] = "Updated advanced_mode"

        # reload conf
        conf = config.get_config()

        data['advanced_mode'] = conf['advanced_mode']

        result = data

    elif args.action == 'status':
        resp = client.getinfo()
        result = {}
        result['server'] = conf['server'] + ':' + str(conf['port'])
        result['server_version'] = resp['blockstore_version']
        result['cli_version'] = config.VERSION
        result['blocks'] = "(%s, %s)" % (resp['last_block'], resp['bitcoind_blocks'])
        result['testset'] = resp['testset']
        result['consensus'] = resp['consensus']

    elif args.action == 'ping':
        result = client.ping()

    elif args.action == 'preorder':

        register_addr = None
        if args.address is not None:
            register_addr = str(args.address)

        result = client.preorder(str(args.name), str(args.privatekey), register_addr=register_addr )

    elif args.action == 'preorder_tx':

        register_addr = None
        if args.address is not None:
            register_addr = str(args.address)

        result = client.preorder(str(args.name), str(args.privatekey), register_addr=register_addr, tx_only=True )

    elif args.action == 'preorder_subsidized':

        result = client.preorder_subsidized( str(args.name), str(args.public_key), str(args.address), str(args.subsidy_key) )

    elif args.action == 'register':
        result = client.register(str(args.name), str(args.privatekey), str(args.addr))

    elif args.action == 'register_tx':
        result = client.register(str(args.name), str(args.privatekey), str(args.addr), tx_only=True )

    elif args.action == 'register_subsidized':
        result = client.register_subsidized(str(args.name), str(args.privatekey), str(args.addr), str(args.subsidy_key) )

    elif args.action == 'update':

        txid = None
        if args.txid is not None:
            txid = str(args.txid)

        result = client.update(str(args.name),
                               str(args.record_json),
                               str(args.privatekey),
                               txid=txid)

    elif args.action == 'update_tx':

        txid = None
        if args.txid is not None:
            txid = str(args.txid)

        result = client.update(str(args.name),
                               str(args.record_json),
                               str(args.privatekey),
                               txid=txid, tx_only=True)

    elif args.action == 'update_subsidized':

        txid = None
        if args.txid is not None:
            txid = str(args.txid)

        result = client.update_subsidized(str(args.name),
                                          str(args.record_json),
                                          str(args.public_key),
                                          str(args.subsidy_key),
                                          txid=txid)

    elif args.action == 'transfer':
        keepdata = False
        if args.keepdata.lower() not in ["on", "false"]:
            print >> sys.stderr, "Pass 'true' or 'false' for keepdata"
            sys.exit(1)

        if args.keepdata.lower() == "on":
            keepdata = True

        result = client.transfer(str(args.name),
                                 str(args.address),
                                 keepdata,
                                 str(args.privatekey))

    elif args.action == 'transfer_tx':
        keepdata = False
        if args.keepdata.lower() not in ["on", "false"]:
            print >> sys.stderr, "Pass 'true' or 'false' for keepdata"
            sys.exit(1)

        if args.keepdata.lower() == "on":
            keepdata = True

        result = client.transfer(str(args.name),
                                 str(args.address),
                                 keepdata,
                                 str(args.privatekey),
                                 tx_only=True)

    elif args.action == 'transfer_subsidized':
        keepdata = False
        if args.keepdata.lower() not in ["on", "false"]:
            print >> sys.stderr, "Pass 'true' or 'false' for keepdata"
            sys.exit(1)

        if args.keepdata.lower() == "on":
            keepdata = True

        result = client.transfer_subsidized(str(args.name),
                                            str(args.address),
                                            keepdata,
                                            str(args.public_key),
                                            str(args.subsidy_key))

    elif args.action == 'renew':
        result = client.renew(str(args.name), str(args.privatekey))

    elif args.action == 'renew_tx':
        result = client.renew(str(args.name), str(args.privatekey), tx_only=True)

    elif args.action == 'renew_subsidized':
        result = client.renew_subsidized(str(args.name), str(args.public_key), str(args.subsidy_key))

    elif args.action == 'revoke':
        result = client.revoke(str(args.name), str(args.privatekey))

    elif args.action == 'revoke_tx':
        result = client.revoke(str(args.name), str(args.privatekey), tx_only=True)

    elif args.action == 'revoke_subsidized':
        result = client.revoke_subsidized(str(args.name), str(args.public_key), str(args.subsidy_key))

    elif args.action == 'name_import':
        result = client.name_import(str(args.name), str(args.address), str(args.hash), str(args.privatekey))

    elif args.action == 'namespace_preorder':

        reveal_addr = None
        if args.address is not None:
            reveal_addr = str(args.address)

        result = client.namespace_preorder(str(args.namespace_id),
                                           str(args.privatekey),
                                           reveal_addr=reveal_addr)

    elif args.action == 'namespace_reveal':
        bucket_exponents = args.bucket_exponents.split(',')
        if len(bucket_exponents) != 16:
            raise Exception("bucket_exponents must be a 16-value CSV of integers")

        for i in xrange(0, len(bucket_exponents)):
            try:
                bucket_exponents[i] = int(bucket_exponents[i])
            except:
                raise Exception("bucket_exponents must contain integers in range [0, 16)")

        lifetime = int(args.lifetime)
        if lifetime < 0:
            lifetime = 0xffffffff       # means "infinite" to blockstore

        result = client.namespace_reveal(str(args.namespace_id),
                                         str(args.addr),
                                         lifetime,
                                         int(args.coeff),
                                         int(args.base),
                                         bucket_exponents,
                                         int(args.nonalpha_discount),
                                         int(args.no_vowel_discount),
                                         str(args.privatekey))

    elif args.action == 'namespace_ready':
        result = client.namespace_ready(str(args.namespace_id),
                                        str(args.privatekey))

    elif args.action == 'put_mutable':
        result = client.put_mutable(str(args.name),
                                    str(args.data_id),
                                    str(args.data),
                                    str(args.privatekey))

    elif args.action == 'put_immutable':
        result = client.put_immutable(str(args.name),
                                      str(args.data),
                                      str(args.privatekey),
                                      conf=conf)

    elif args.action == 'get_mutable':
        result = client.get_mutable(str(args.name), str(args.data_id), conf=conf)

    elif args.action == 'get_immutable':
        result = client.get_immutable(str(args.name), str(args.hash))

    elif args.action == 'delete_immutable':
        result = client.delete_immutable(str(args.name), str(args.hash), str(args.privatekey))

    elif args.action == 'delete_mutable':
        result = client.delete_mutable(str(args.name), str(args.data_id), str(args.privatekey))

    elif args.action == 'get_name_blockchain_record':
        result = client.get_name_blockchain_record(str(args.name))

    elif args.action == 'get_namespace_blockchain_record':
        result = client.get_namespace_blockchain_record(str(args.namespace_id))

    elif args.action == 'lookup':
        data = {}
        data['blockchain_record'] = client.get_name_blockchain_record(str(args.name))

        try:
            data_id = data['blockchain_record']['value_hash']
            data['data_record'] = json.loads(client.get_immutable(str(args.name), data_id)['data'])
        except:
            data['data_record'] = None

        result = data

    elif args.action == 'lookup_snv':
        result = client.lookup_snv(str(args.name), int(args.block_id), str(args.consensus_hash) )

    elif args.action == 'get_name_record':
        result = client.get_name_record( str(args.name) )

    elif args.action == 'cost':
        result = client.get_name_cost(str(args.name))

    elif args.action == 'get_names_owned_by_address':
        result = client.get_names_owned_by_address(str(args.address))

    elif args.action == 'get_namespace_cost':
        result = client.get_namespace_cost(str(args.namespace_id))

    elif args.action == 'get_all_names':
        offset = None
        count = None

        if args.offset is not None:
            offset = int(args.offset)

        if args.count is not None:
            count = int(args.count)

        result = client.get_all_names( offset, count )

    elif args.action == 'get_names_in_namespace':
        offset = None
        count = None

        if args.offset is not None:
            offset = int(args.offset)

        if args.count is not None:
            count = int(args.count)

        result = client.get_names_in_namespace( str(args.namespace_id), offset, count )

    elif args.action == 'consensus':

        if args.block_height is None:
            # by default get last indexed block
            args.block_height = client.getinfo()['last_block']

        resp = client.get_consensus_at( int(args.block_height) )

        data = {}
        data['consensus'] = resp
        data['block_height'] = args.block_height

        result = data

    elif args.action == 'get_nameops_at':
        result = client.get_nameops_at( int(args.block_id) )

    print_result(result)

if __name__ == '__main__':
    run_cli()
