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

import argparse
import sys
import json
import traceback
import os
import re
import pybitcoin
import subprocess
from socket import error as socket_error
from time import sleep
from getpass import getpass

import requests
requests.packages.urllib3.disable_warnings()

import logging
logging.disable(logging.CRITICAL)

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

from blockstack_client import config
from blockstack_client.config import WALLET_PATH, WALLET_PASSWORD_LENGTH

from blockstack_client.parser import add_subparsers, add_advanced_subparsers
from blockstack_client.parser import AliasedSubParsersAction

from pybitcoin import is_b58check_address

from binascii import hexlify

from registrar.wallet import HDWallet
from registrar.crypto.utils import aes_encrypt, aes_decrypt
from registrar.blockchain import get_balance, dontuseAddress
from registrar.network import get_bs_client
from registrar.rpc_daemon import background_process
from registrar.utils import satoshis_to_btc
from registrar.states import nameRegistered, ownerName, profileonBlockchain
from registrar.blockchain import recipientNotReady, get_tx_confirmations

from .wallet import *
from .utils import exit_with_error, pretty_dump, print_result

log = config.get_logger()

def check_valid_name(fqu):

    try:
        name, tld = fqu.rsplit('.')
    except:
        msg = 'The name specified is invalid.'
        msg += ' Names must end with a period followed by a valid TLD.'
        exit_with_error(msg)

    if name == '':
        msg = 'The name specified is invalid.'
        msg += ' Names must be at least one character long, not including the TLD.'
        exit_with_error(msg)

    regrex = r'^[a-z0-9_]{1,60}$'

    if not re.search(regrex, name):
        msg = 'The name specified is invalid.'
        msg += ' Names may only contain alphanumeric characters,'
        msg += ' dashes, and underscores.'
        exit_with_error(msg)


def tests_for_update_and_transfer(fqu, transfer_address=None):
    """ Any update or transfer operation
        should pass these tests
    """

    if not nameRegistered(fqu):
        exit_with_error("%s is not registered yet." % fqu)

    payment_address, owner_address = get_addresses_from_file()

    if not ownerName(fqu, owner_address):
        exit_with_error("%s is not in your possession." % fqu)

    tx_fee_satoshi = approx_tx_fees(num_tx=1)
    tx_fee = satoshis_to_btc(tx_fee_satoshi)

    if not hasEnoughBalance(payment_address, tx_fee):
        msg = "Address %s doesn't have enough balance." % payment_address
        exit_with_error(msg)

    if dontuseAddress(payment_address):
        msg = "Address %s has pending transactions." % payment_address
        msg += " Wait and try later."
        exit_with_error(msg)

    if transfer_address is not None:

        try:
            resp = is_b58check_address(str(transfer_address))
        except:
            msg = "Address %s is not a valid Bitcoin address." % transfer_address
            exit_with_error(msg)

        if recipientNotReady(transfer_address):
            msg = "Address %s owns too many names already." % transfer_address
            exit_with_error(msg)


def run_cli(config_path=CONFIG_PATH):
    """ run cli
    """

    conf = config.get_config(config_path=config_path)

    if conf is None:
        log.error("Failed to load config")
        sys.exit(1)

    advanced_mode = conf['advanced_mode']

    parser = argparse.ArgumentParser(
            description='Blockstack cli version {}'.format(config.VERSION))

    parser.register('action', 'parsers', AliasedSubParsersAction)

    subparsers = parser.add_subparsers(dest='action')
    add_subparsers(subparsers)

    if advanced_mode:
        add_advanced_subparsers(subparsers)

    # Print default help message, if no argument is given
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args, unknown_args = parser.parse_known_args()
    result = {}

    blockstack_server = conf['server']
    blockstack_port = conf['port']

    proxy = blockstack_client.session(conf=conf, server_host=blockstack_server,
                                      server_port=blockstack_port, set_global=True)

    # start the two background processes (rpc daemon and monitor queue)
    start_background_daemons()

    if args.action == 'balance':

        if not os.path.exists(WALLET_PATH):
            initialize_wallet()

        result['total_balance'], result['addresses'] = get_total_balance()

    elif args.action == 'price':

        fqu = str(args.name)
        check_valid_name(fqu)

        try:
            resp = blockstack_client.get_name_cost(fqu)
        except socket_error:
            exit_with_error("Error connecting to server")

        if 'error' in resp:
            exit_with_error(resp['error'])

        data = get_total_fees(resp)

        result = data

    elif args.action == 'config':
        data = {}

        settings_updated = False

        data["message"] = "Updated settings for"

        if args.host is not None:
            config.update_config('blockstack-client', 'server', args.host, config_path=config_path)
            data["message"] += " host"
            settings_updated = True

        if args.port is not None:
            config.update_config('blockstack-client', 'port', args.port, config_path=config_path)
            data["message"] += " port"
            settings_updated = True

        if args.advanced is not None:

            if args.advanced != "on" and args.advanced != "off":
                exit_with_error("Use --advanced=on or --advanced=off")
            else:
                advanced = False
                if args.advanced == 'on':
                    advanced = True

                config.update_config('blockstack-client', 'advanced_mode', str(advanced), config_path=config_path)
                data["message"] += " advanced"
                settings_updated = True

        # reload conf
        conf = config.get_config(config_path=config_path)

        if settings_updated:
            result['message'] = data['message']
        else:
            result['message'] = "No config settings were updated."

    elif args.action == 'deposit':

        if not os.path.exists(WALLET_PATH):
            initialize_wallet()

        result['message'] = 'Send bitcoins to the address specified.'
        result['address'], owner_address = get_addresses_from_file()

    elif args.action == 'import':

        if not os.path.exists(WALLET_PATH):
            initialize_wallet()

        result['message'] = 'Send the name you want to receive to the'
        result['message'] += ' address specified.'
        payment_address, result['address'] = get_addresses_from_file()

    elif args.action == 'names':

        if not os.path.exists(WALLET_PATH):
            initialize_wallet()

        result['names_owned'] = get_all_names_owned()
        result['addresses'] = get_owner_addresses()

    elif args.action in ('info', 'status', 'ping', 'details'):

        resp = blockstack_client.getinfo()

        result = {}

        result['server_host'] = conf['server']
        result['server_port'] = str(conf['port'])
        result['cli_version'] = config.VERSION
        result['advanced_mode'] = conf['advanced_mode']

        if 'error' in resp:
            result['server_alive'] = False
            result['server_error'] = resp['error']
        else:
            result['server_alive'] = True

            if 'blockstack_version' in resp:
                result['server_version'] = resp['blockstack_version']
            elif 'blockstack_version' in resp:
                result['server_version'] = resp['blockstack_version']

            try:
                result['last_block_processed'] = resp['last_block']
            except:
                result['last_block_processed'] = resp['blocks']
            result['last_block_seen'] = resp['bitcoind_blocks']
            result['consensus_hash'] = resp['consensus']

            if advanced_mode:
                result['testset'] = resp['testset']

            proxy = get_local_proxy()

            if proxy is not False:

                current_state = json.loads(proxy.state())

                queue = {}
                pending_queue = []
                preorder_queue = []
                register_queue = []
                update_queue = []
                transfer_queue = []

                def format_new_entry(entry):
                    new_entry = {}
                    new_entry['name'] = entry['fqu']
                    confirmations = get_tx_confirmations(entry['tx_hash'])
                    if confirmations is None:
                        confirmations = 0
                    new_entry['confirmations'] = confirmations
                    return new_entry

                def format_queue_display(preorder_queue,
                                         register_queue):

                    for entry in register_queue:

                        name = entry['name']

                        for check_entry in preorder_queue:

                            if check_entry['name'] == name:
                                preorder_queue.remove(check_entry)

                for entry in current_state:

                    if 'type' in entry:
                        if entry['type'] == 'preorder':
                            preorder_queue.append(format_new_entry(entry))
                        elif entry['type'] == 'register':
                            register_queue.append(format_new_entry(entry))
                        elif entry['type'] == 'update':
                            update_queue.append(format_new_entry(entry))
                        elif entry['type'] == 'transfer':
                            transfer_queue.append(format_new_entry(entry))

                format_queue_display(preorder_queue,
                                     register_queue)

                if len(preorder_queue) != 0:
                    queue['preorder'] = preorder_queue

                if len(register_queue) != 0:
                    queue['register'] = register_queue

                if len(update_queue) != 0:
                    queue['update'] = update_queue

                if len(transfer_queue) != 0:
                    queue['transfer'] = transfer_queue

                if queue != {}:
                    result['queue'] = queue

    elif args.action == 'lookup':
        data = {}

        blockchain_record = None
        fqu = str(args.name)

        check_valid_name(fqu)

        try:
            blockchain_record = blockstack_client.get_name_blockchain_record(fqu)
        except socket_error:
            exit_with_error("Error connecting to server.")

        if 'value_hash' not in blockchain_record:
            exit_with_error("%s is not registered" % fqu)

        try:
            user_profile, user_zonefile = blockstack_client.get_name_profile(str(args.name))
            data['profile'] = user_profile
            data['zonefile'] = user_zonefile
        except:
            data['profile'] = None
            data['zonefile'] = None

        result = data

    elif args.action == 'whois':
        data = {}

        record = None
        fqu = str(args.name)

        check_valid_name(fqu)

        try:
            record = blockstack_client.get_name_blockchain_record(fqu)
        except socket_error:
            exit_with_error("Error connecting to server.")

        if 'value_hash' not in record:
            result['registered'] = False
        else:
            result['block_preordered_at'] = record['preorder_block_number']
            result['block_renewed_at'] = record['last_renewed']
            result['last_transaction_id'] = record['txid']
            result['owner_address'] = record['address']
            result['owner_script'] = record['sender']
            result['registered'] = True

    elif args.action == 'register':

        if not os.path.exists(WALLET_PATH):
            initialize_wallet()

        result = {}
        fqu = str(args.name)
        check_valid_name(fqu)
        cost = blockstack_client.get_name_cost(fqu)

        if 'error' in cost:
            exit_with_error(cost['error'])

        if nameRegistered(fqu):
            exit_with_error("%s is already registered." % fqu)

        if not walletUnlocked():
            unlock_wallet()

        fees = get_total_fees(cost)

        try:
            cost = fees['total_estimated_cost']
            input_prompt = "Registering %s will cost %s BTC." % (fqu, cost)
            input_prompt += " Continue? (y/n): "
            user_input = raw_input(input_prompt)
            user_input = user_input.lower()

            if user_input != 'y':
                print "Not registering."
                exit(0)
        except KeyboardInterrupt:
            print "\nExiting."
            exit(0)

        payment_address, owner_address = get_addresses_from_file()

        if not hasEnoughBalance(payment_address, fees['total_estimated_cost']):
            msg = "Address %s doesn't have enough balance." % payment_address
            exit_with_error(msg)

        if recipientNotReady(owner_address):
            msg = "Address %s owns too many names already." % owner_address
            exit_with_error(msg)

        if dontuseAddress(payment_address):
            msg = "Address %s has pending transactions." % payment_address
            msg += " Wait and try later."
            exit_with_error(msg)

        proxy = get_local_proxy()

        try:
            resp = proxy.preorder(fqu)
        except:
            exit_with_error("Error talking to server, try again.")

        if 'success' in resp and resp['success']:
            result = resp
        else:
            if 'error' in resp:
                exit_with_error(resp['error'])

            if 'message' in resp:
                exit_with_error(resp['message'])

    elif args.action == 'update':

        if not os.path.exists(WALLET_PATH):
            initialize_wallet()

        fqu = str(args.name)
        check_valid_name(fqu)

        user_data = str(args.data)
        try:
            user_data = json.loads(user_data)
        except:
            exit_with_error("Data is not in JSON format.")

        tests_for_update_and_transfer(fqu)

        if profileonBlockchain(fqu, user_data):
            msg ="Data is same as current data record, update not needed."
            exit_with_error(msg)

        if not walletUnlocked():
            unlock_wallet()

        proxy = get_local_proxy()

        try:
            resp = proxy.update(fqu, user_data)
        except:
            exit_with_error("Error talking to server, try again.")

        if 'success' in resp and resp['success']:
            result = resp
        else:
            if 'error' in resp:
                exit_with_error(resp['error'])

            if 'message' in resp:
                exit_with_error(resp['message'])

    elif args.action == 'transfer':

        if not os.path.exists(WALLET_PATH):
            initialize_wallet()

        fqu = str(args.name)
        check_valid_name(fqu)
        transfer_address = str(args.address)

        tests_for_update_and_transfer(fqu, transfer_address=transfer_address)

        if not walletUnlocked():
            unlock_wallet()

        proxy = get_local_proxy()

        try:
            resp = proxy.transfer(fqu, transfer_address)
        except:
            exit_with_error("Error talking to server, try again.")

        if 'success' in resp and resp['success']:
            result = resp
        else:
            if 'error' in resp:
                exit_with_error(resp['error'])

            if 'message' in resp:
                exit_with_error(resp['message'])

    # ---------------------- Advanced options ---------------------------------
    elif args.action == 'wallet':

        if not os.path.exists(WALLET_PATH):
            result = initialize_wallet()
        else:
            unlock_wallet(display_enabled=True)

    elif args.action == 'consensus':

        if args.block_height is None:
            # by default get last indexed block
            resp = blockstack_client.getinfo()

            if 'error' in resp:
                exit_with_error("Error connecting to server.")

            elif 'last_block' in resp or 'blocks' in resp:

                if 'last_block' in resp:
                    args.block_height = blockstack_client.getinfo()['last_block']
                elif 'blocks' in resp:
                    args.block_height = blockstack_client.getinfo()['blocks']
                else:
                    result['error'] = "Server is indexing. Try again"
                    exit(0)

        resp = blockstack_client.get_consensus_at(int(args.block_height))

        data = {}
        data['consensus'] = resp
        data['block_height'] = args.block_height

        result = data

    elif args.action == 'localrpc':
        pass

    elif args.action == 'register_tx':
        result = blockstack_client.register(str(args.name), str(args.privatekey),
                                            str(args.addr), tx_only=True)

    elif args.action == 'register_subsidized':
        result = blockstack_client.register_subsidized(str(args.name), str(args.privatekey),
                                                       str(args.addr), str(args.subsidy_key))

    elif args.action == 'update_tx':

        txid = None
        if args.txid is not None:
            txid = str(args.txid)

        result = blockstack_client.update(str(args.name),
                                          str(args.record_json),
                                          str(args.privatekey),
                                          txid=txid, tx_only=True)

    elif args.action == 'update_subsidized':

        txid = None
        if args.txid is not None:
            txid = str(args.txid)

        result = blockstack_client.update_subsidized(str(args.name),
                                                     str(args.record_json),
                                                     str(args.public_key),
                                                     str(args.subsidy_key),
                                                     txid=txid)

    elif args.action == 'transfer_tx':
        keepdata = False
        if args.keepdata.lower() not in ["on", "false"]:
            print >> sys.stderr, "Pass 'true' or 'false' for keepdata"
            sys.exit(1)

        if args.keepdata.lower() == "on":
            keepdata = True

        result = blockstack_client.transfer(str(args.name),
                                            str(args.address),
                                            keepdata,
                                            str(args.privatekey),
                                            tx_only=True)

    elif args.action == 'preorder':

        register_addr = None
        if args.address is not None:
            register_addr = str(args.address)

        result = blockstack_client.preorder(str(args.name), str(args.privatekey),
                                            register_addr=register_addr)

    elif args.action == 'preorder_tx':

        register_addr = None
        if args.address is not None:
            register_addr = str(args.address)

        result = blockstack_client.preorder(str(args.name), str(args.privatekey),
                                            register_addr=register_addr, tx_only=True)

    elif args.action == 'preorder_subsidized':

        result = blockstack_client.preorder_subsidized(str(args.name),
                                                       str(args.public_key),
                                                       str(args.address),
                                                       str(args.subsidy_key))

    elif args.action == 'transfer_subsidized':
        keepdata = False
        if args.keepdata.lower() not in ["on", "false"]:
            print >> sys.stderr, "Pass 'true' or 'false' for keepdata"
            sys.exit(1)

        if args.keepdata.lower() == "on":
            keepdata = True

        result = blockstack_client.transfer_subsidized(str(args.name),
                                                       str(args.address),
                                                       keepdata,
                                                       str(args.public_key),
                                                       str(args.subsidy_key))

    elif args.action == 'renew':
        result = blockstack_client.renew(str(args.name), str(args.privatekey))

    elif args.action == 'renew_tx':
        result = blockstack_client.renew(str(args.name), str(args.privatekey),
                                          tx_only=True)

    elif args.action == 'renew_subsidized':
        result = blockstack_client.renew_subsidized(str(args.name), str(args.public_key),
                                                    str(args.subsidy_key))

    elif args.action == 'revoke':
        result = blockstack_client.revoke(str(args.name), str(args.privatekey))

    elif args.action == 'revoke_tx':
        result = blockstack_client.revoke(str(args.name), str(args.privatekey),
                                          tx_only=True)

    elif args.action == 'revoke_subsidized':
        result = blockstack_client.revoke_subsidized(str(args.name), str(args.public_key),
                                                     str(args.subsidy_key))

    elif args.action == 'name_import':
        result = blockstack_client.name_import(str(args.name), str(args.address),
                                               str(args.hash), str(args.privatekey))

    elif args.action == 'namespace_preorder':

        reveal_addr = None
        if args.address is not None:
            reveal_addr = str(args.address)

        result = blockstack_client.namespace_preorder(str(args.namespace_id),
                                                      str(args.privatekey),
                                                      reveal_addr=reveal_addr)

    elif args.action == 'namespace_reveal':
        bucket_exponents = args.bucket_exponents.split(',')
        if len(bucket_exponents) != 16:
            raise Exception("bucket_exponents must be a 16-value CSV \
                             of integers")

        for i in xrange(0, len(bucket_exponents)):
            try:
                bucket_exponents[i] = int(bucket_exponents[i])
            except:
                raise Exception("bucket_exponents must contain integers in \
                                range [0, 16)")

        lifetime = int(args.lifetime)
        if lifetime < 0:
            lifetime = 0xffffffff       # means "infinite" to blockstack-server

        result = blockstack_client.namespace_reveal(str(args.namespace_id),
                                                    str(args.addr),
                                                    lifetime,
                                                    int(args.coeff),
                                                    int(args.base),
                                                    bucket_exponents,
                                                    int(args.nonalpha_discount),
                                                    int(args.no_vowel_discount),
                                                    str(args.privatekey))

    elif args.action == 'namespace_ready':
        result = blockstack_client.namespace_ready(str(args.namespace_id),
                                                   str(args.privatekey))

    elif args.action == 'put_mutable':
        result = blockstack_client.put_mutable(str(args.name),
                                               str(args.data_id),
                                               str(args.data)),

    elif args.action == 'put_immutable':
        result = blockstack_client.put_immutable(str(args.name),
                                                 str(args.data_id),
                                                 str(args.data),
                                                 conf=conf)

    elif args.action == 'get_mutable':
        result = blockstack_client.get_mutable(str(args.name), str(args.data_id),
                                               conf=conf)

    elif args.action == 'get_immutable':
        result = blockstack_client.get_immutable(str(args.name), str(args.data_id_or_hash))

    elif args.action == 'list_update_history':
        result = blockstack_client.list_update_history(str(args.name))

    elif args.action == 'list_zonefile_history':
        result = blockstack_client.list_zonefile_history(str(args.name))

    elif args.action == 'list_immutable_data_history':
        result = blockstack_client.list_immutable_data_history(str(args.name), str(args.data_id))

    elif args.action == 'delete_immutable':
        result = blockstack_client.delete_immutable(str(args.name), str(args.hash),
                                                    str(args.privatekey))

    elif args.action == 'delete_mutable':
        result = blockstack_client.delete_mutable(str(args.name), str(args.data_id),
                                                  str(args.privatekey))

    elif args.action == 'get_name_blockchain_record':
        result = blockstack_client.get_name_blockchain_record(str(args.name))

    elif args.action == 'get_namespace_blockchain_record':
        result = blockstack_client.get_namespace_blockchain_record(str(args.namespace_id))

    elif args.action == 'lookup_snv':
        result = blockstack_client.lookup_snv(str(args.name), int(args.block_id),
                                              str(args.consensus_hash))

    elif args.action == 'get_name_zonefile':
        result = blockstack_client.get_name_zonefile(str(args.name))

    elif args.action == 'get_names_owned_by_address':
        result = blockstack_client.get_names_owned_by_address(str(args.address))

    elif args.action == 'get_namespace_cost':
        result = blockstack_client.get_namespace_cost(str(args.namespace_id))

    elif args.action == 'get_all_names':
        offset = None
        count = None

        if args.offset is not None:
            offset = int(args.offset)

        if args.count is not None:
            count = int(args.count)

        result = blockstack_client.get_all_names(offset, count)

    elif args.action == 'get_names_in_namespace':
        offset = None
        count = None

        if args.offset is not None:
            offset = int(args.offset)

        if args.count is not None:
            count = int(args.count)

        result = blockstack_client.get_names_in_namespace(str(args.namespace_id), offset,
                                                          count)

    elif args.action == 'get_nameops_at':
        result = blockstack_client.get_nameops_at(int(args.block_id))

    print_result(result)

if __name__ == '__main__':
    try:
        run_cli()
    except:
        exit_with_error("Unexpected error. Try getting latest version of CLI" +
                        "'sudo pip install blockstack --upgrade'")
