#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack-client.

    Blockstack-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack-client.  If not, see <http://www.gnu.org/licenses/>.
"""

import config
import argparse


class AliasedSubParsersAction(argparse._SubParsersAction):

    """ Hack around adding aliases to parser
        Modified from a solution by Adrian Sampson:
        https://gist.github.com/sampsyo/471779
    """

    class _AliasedPseudoAction(argparse.Action):
        def __init__(self, name, aliases, help):
            dest = name
            if aliases:
                dest += ' (%s)' % ','.join(aliases)
            sup = super(AliasedSubParsersAction._AliasedPseudoAction, self)
            sup.__init__(option_strings=[], dest=dest, help=help) 

    def add_parser(self, name, **kwargs):
        if 'aliases' in kwargs:
            aliases = kwargs['aliases']
            del kwargs['aliases']
        else:
            aliases = []

        parser = super(AliasedSubParsersAction, self).add_parser(name, **kwargs)

        # Make the aliases work.
        for alias in aliases:
            self._name_parser_map[alias] = parser
        # Make the help text reflect them, first removing old help entry.
        #if 'help' in kwargs:
        #    help = kwargs.pop('help')
        #    self._choices_actions.pop()
        #    pseudo_action = self._AliasedPseudoAction(name, aliases, help)
        #    self._choices_actions.append(pseudo_action)

        return parser


def add_subparsers(subparsers):
    """ Adds default subparsers
    """

    # ------------------------------------
    subparser = subparsers.add_parser(
        'balance',
        help='display the wallet balance')
    subparser.add_argument(
        '--details',
        action="store_true",
        help="whether or not the full details of the output should be shown")

    # ------------------------------------
    subparser = subparsers.add_parser(
        'config',
        help='configure --server=x --port=y --advanced=on/off')

    subparser.add_argument(
        '--host',
        action='store',
        help="""the hostname/IP of blockstack server \
        (current: {})""".format(config.BLOCKSTACKD_SERVER))

    subparser.add_argument(
        '--port',
        action='store',
        help="""the server port to connect to (current: {})""".format(
            config.BLOCKSTACKD_PORT))

    subparser.add_argument(
        '--advanced',
        action='store',
        help="can be 'on' or 'off'")

    # ------------------------------------
    subparser = subparsers.add_parser(
        'price',
        help="<name> | get the cost of a name")
    subparser.add_argument(
        'name', type=str,
        help="The fully-qualified name to check e.g., fredwilson.id")

    # ------------------------------------
    subparser = subparsers.add_parser(
        'deposit',
        help='display the address with which to receive bitcoins')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'import',
        help='display the address with which to receive names')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'info',
        help='check server status and get details about the server',
        aliases=['status', 'ping'])

    # ------------------------------------
    subparser = subparsers.add_parser(
        'lookup',
        help='<name> | get the data record for a particular name')
    subparser.add_argument(
        'name', type=str,
        help='the name to look up')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'names',
        help='display the names owned by local addresses')
    subparser.add_argument(
        '--details',
        action="store_true",
        help="whether or not the full details of the output should be shown")

    # ------------------------------------
    subparser = subparsers.add_parser(
        'register',
        help='<name> | register a new name')
    subparser.add_argument(
        'name', type=str,
        help='the name that you want to register')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'transfer',
        help='<name> <address> | transfer a name you own')
    subparser.add_argument(
        'name', type=str,
        help='the name that you want to transfer')
    subparser.add_argument(
        'address', type=str,
        help='the new owner Bitcoin address')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'update',
        help='<name> <data> | update a name record with new data')
    subparser.add_argument(
        'name', type=str,
        help='the name that you want to update')
    subparser.add_argument(
        'data', type=str,
        help='the new data record (in JSON format)')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'whois',
        help='<name> | get the registration record of a name')
    subparser.add_argument(
        'name', type=str,
        help='the name to look up')


def add_advanced_subparsers(subparsers):
    """ Adds advanced subparsers
    """

    # ------------------------------------
    subparser = subparsers.add_parser(
        'wallet',
        help='display wallet information')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'consensus',
        help='<block number> | get consensus hash at given block')
    subparser.add_argument(
        'block_height', type=int, nargs='?',
        help='The block height.')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'delete_immutable',
        help='<name> <hash> <privatekey> | Delete immutable' +
             ' data from the storage providers.')
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
    subparser = subparsers.add_parser(
        'delete_mutable',
        help='<name> <data_id> <privatekey> | Delete mutable' +
             ' data from the storage providers.')
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
        'get_immutable',
        help='<name> <hash> | get immutable data from storage')
    subparser.add_argument(
        'name', type=str,
        help='the name of the user')
    subparser.add_argument(
        'hash', type=str,
        help='the hash of the data')

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
        'get_names_in_namespace',
        help='<namespace ID> [offset] [count] | get all names in a' +
             ' particular namespace')
    subparser.add_argument(
        'namespace_id', type=str,
        help='The namespace to search')
    subparser.add_argument(
        'offset', nargs='?',
        help='The offset into the list at which to start reading')
    subparser.add_argument(
        'count', nargs='?',
        help='The maximum number of names to return')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'get_names_owned_by_address',
        help='<address> | get all names owned by an address')
    subparser.add_argument(
        'address', type=str,
        help='The address to query')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'get_namespace_cost',
        help="<namespace_id> | get the cost of a namespace")
    subparser.add_argument(
        'namespace_id', type=str,
        help="The namespace ID to check")

    # ------------------------------------
    subparser = subparsers.add_parser(
        'get_name_record',
        help='<name> | get the off-blockchain record for a given name')
    subparser.add_argument(
        'name', type=str,
        help='the name to look up')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'get_name_blockchain_record',
        help='<name> | get the blockchain-hosted information' +
             ' for a particular name')
    subparser.add_argument(
        'name', type=str,
        help='the name to query')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'get_namespace_blockchain_record',
        help='<namespace_id> | get the blockchain-hosted' +
             ' information for a particular namespace')
    subparser.add_argument(
        'namespace_id', type=str,
        help='the namespace to look up')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'update_tx',
        help='<name> <record_json> <private_key> [txid] | generate an \
        unsigned transaction to update and store a name record')
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
        help='[OPTIONAL] the transaction ID of the previously-attempted, \
             partially-successful update')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'update_subsidized',
        help='<name> <record_json> <public_key> <subsidy_key> [txid] | \
             generate an "anyone-can-pay" transaction to update and store a \
             name record, subsidized by a separate key.  The client will need \
             to sign the <public_key>\'s address inputs before \
             broadcasting it.')
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
        help='[OPTIONAL] the transaction ID of the previously-attempted, \
             partially-successful update')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'lookup_snv',
        help='<name> <block_id> <consensus_hash> | Look up a name as it \
             existed at a particular block, using SNV protocol')
    subparser.add_argument(
        'name', type=str,
        help='the name to look up')
    subparser.add_argument(
        'block_id', type=int,
        help='the block ID in the desired point in the past')
    subparser.add_argument(
        'consensus_hash', type=str,
        help='the trusted consensus hash at the given block')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'get_nameops_at',
        help='<block_id> | Look up all name operations that occurred \
              at a block')
    subparser.add_argument(
        'block_id', type=int,
        help='the block ID in the desired point in the past')

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
        help='[OPTIONAL] the address of private key that will import names \
        into this namespace (should be different from the private key given \
        here. If not given, a new private key will be generated. The private \
        key must be used to sign name_import requests, and the \
        address must be submitted on namespace_reveal')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'namespace_reveal',
        help='define a namespace\'s parameters once preorder succeeds')
    subparser.add_argument(
        'namespace_id', type=str,
        help='the human-readable namespace identifier')
    subparser.add_argument(
        'addr', type=str,
        help='the address that will import names into the namespace, and \
              open it for registration')
    subparser.add_argument(
        'lifetime', type=int,
        help='the number of blocks for which a name will be valid (any value \
             less than zero means "forever")')
    subparser.add_argument(
        'coeff', type=int,
        help='constant cost multipler for names (in range [0, 256))')
    subparser.add_argument(
        'base', type=int,
        help='base cost for names (in range [0, 256))')
    subparser.add_argument(
        'bucket_exponents', type=str,
        help='per-name-length cost exponents (CSV string of 16 values in \
              range [0, 16))')
    subparser.add_argument(
        'nonalpha_discount', type=int,
        help='non-alpha discount multipler (in range [0, 16))')
    subparser.add_argument(
        'no_vowel_discount', type=int,
        help='no-vowel discount multipler (in range [0, 16))')
    subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the namespace creator \
             (from namespace_preorder)')

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
        help='[OPTIONAL] the address that will own the name (should \
             be different from the address of the private key given here). \
             If not given, a new private key will be generated, and its \
             address must be submitted upon register.')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'preorder_tx',
        help='<name> <privatekey> [address] | create an unsigned serialized \
             transaction that will preorder a name.')
    subparser.add_argument(
        'name', type=str,
        help='the name that you want to preorder')
    subparser.add_argument(
        'privatekey', type=str,
        help='the private key of the Bitcoin account to pay for the name \
              and register it')
    subparser.add_argument(
        'address', type=str, nargs='?',
        help='[OPTIONAL] the address that will own the name (should be \
              different from the address of the private key given here). \
              If not given, a new private key will be generated, and its \
              address must be submitted upon register.')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'preorder_subsidized',
        help='<name> <public_key> <address> <subsidy_key> | create an \
             "anyone-can-pay" transaction to preorder a name, subsidized with \
              a separate key. The client must sign the <public_key>\'s address \
              input separately to complete the transaction.')
    subparser.add_argument(
        'name', type=str,
        help='the name that you want to preorder')
    subparser.add_argument(
        'public_key', type=str,
        help='the client\'s public key, whose private counterpart will sign \
              the subsidized transaction.')
    subparser.add_argument(
        'address', type=str,
        help='The address that will own the name (should be different from \
        the address of the public key given here). \
        If not given, a new private key will be generated, and its address \
        must be submitted upon register.')
    subparser.add_argument(
        'subsidy_key', type=str,
        help='the private key of the Bitcoin account to pay for the name')

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

    # ------------------------------------
    put_mutable_parser = subparsers.add_parser(
        'put_mutable',
        help='<name> <data_id> <data> <privatekey> [<nonce>] | Store mutable \
        data into the storage providers, creating it if it does not exist.')
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
        help='the the private key associated with the name')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'register_tx',
        help='<name> <privatekey> <addr> | Generate an unsigned transaction \
        to register/claim a name')
    subparser.add_argument(
        'name', type=str,
        help='the name that you want to register/claim')
    subparser.add_argument(
        'privatekey', type=str,
        help='the private key used to preorder the name')
    subparser.add_argument(
        'addr', type=str,
        help='the address that will own the name (given in the preorder)')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'register_subsidized',
        help='<name> <public_key> <addr> <subsidy_key> | create an \
        "anyone-can-pay" transaction to register/claim a name, subsidized by \
        a separate key.  The client must sign the <public_key>\'s address \
        inputs before broadcasting it.')
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
        'renew_tx',
        help='<name> <privatekey> | create an unsigned transaction \
        to renew a name')
    subparser.add_argument(
        'name', type=str,
        help='the name that you want to renew')
    subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the owner Bitcoin address')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'renew_subsidized',
        help='<name> <public_key> <subsidy_key> | create an "anyone-can-pay" \
        transaction to renew a name, subsidized by a separate key. \
        The client must sign the <public_key>\'s address inputs before \
        broadcasting it.')
    subparser.add_argument(
        'name', type=str,
        help='the name that you want to renew')
    subparser.add_argument(
        'public_key', type=str,
        help='the public key of the owner')
    subparser.add_argument(
        'subsidy_key', type=str,
        help='the key to subsidize the transaction')

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

    # ------------------------------------
    subparser = subparsers.add_parser(
        'revoke_tx',
        help='<name> <privatekey> | generate an unsigned transaction to' +
             ' revoke a name and its data')
    subparser.add_argument(
        'name', type=str,
        help='the name that you want to revoke')
    subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the owner Bitcoin address')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'revoke_subsidized',
        help='<name> <public_key> <subsidy_key> | create an "anyone-can-pay"' +
             ' transaction to revoke a name and its data, subsidized by a' +
             ' separate key.  The client must sign the <public_key>\'s' +
             ' address inputs before broadcasting it.')
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
        'transfer_tx',
        help='<name> <address> <keepdata> <privatekey> | create an unsigned' +
             ' transaction that will transfer a name')
    subparser.add_argument(
        'name', type=str,
        help='the name that you want to register/claim')
    subparser.add_argument(
        'address', type=str,
        help='the new owner Bitcoin address')
    subparser.add_argument(
        'keepdata', type=str,
        help='whether or not the storage index should remain associated with' +
             ' the name [true|false]')
    subparser.add_argument(
        'privatekey', type=str,
        help='the privatekey of the owner Bitcoin address')

    # ------------------------------------
    subparser = subparsers.add_parser(
        'transfer_subsidized',
        help='<name> <address> <keepdata> <public_key> <subsidy_key> |' +
             ' create an "anyone-can-pay" transaction that will transfer a' +
             ' name, subsidized by a separate key.  The client must sign the' +
             ' <public_key>\s address inputs before broadcasting it.')
    subparser.add_argument(
        'name', type=str,
        help='the name that you want to register/claim')
    subparser.add_argument(
        'address', type=str,
        help='the new owner Bitcoin address')
    subparser.add_argument(
        'keepdata', type=str,
        help='whether or not the storage index should remain associated with' +
             ' the name [true|false]')
    subparser.add_argument(
        'public_key', type=str,
        help='the public key of the owner Bitcoin address')
    subparser.add_argument(
        'subsidy_key', type=str,
        help='the key to subsidize the transaction.')
