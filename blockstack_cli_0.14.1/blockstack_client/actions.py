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
    along with Blockstack-client. If not, see <http://www.gnu.org/licenses/>.
"""

"""
Every method that begins with `cli_` in this module
is matched to an action to be taken, based on the
CLI input.

Default options begin with `cli_`.  For exmample, "blockstack transfer ..."
will cause `cli_transfer(...)` to be called.

Advanced options begin with `cli_advanced_`.  For example, "blockstack wallet ..."
will cause `cli_advanced_wallet(...)` to be called.

The following conventions apply to `cli_` methods here:
* Each will always take a Namespace (from ArgumentParser.parse_known_args()) 
as its first argument.
* Each will return a dict with the requested information.  The key 'error'
will be set to indicate an error condition.

If you want to add a new command-line action, implement it here.  This
will make it available not only via the command-line, but also via the
local RPC interface and the test suite.
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
import time

import requests
requests.packages.urllib3.disable_warnings()

import logging
logging.disable(logging.CRITICAL)

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

from blockstack_client import \
    delete_immutable, \
    delete_mutable, \
    get_all_names, \
    get_consensus_at, \
    get_immutable, \
    get_mutable, \
    get_name_blockchain_record, \
    get_name_cost, \
    get_name_profile, \
    get_name_zonefile, \
    get_nameops_at, \
    get_names_in_namespace, \
    get_names_owned_by_address, \
    get_namespace_blockchain_record, \
    get_namespace_cost, \
    list_immutable_data_history, \
    list_update_history, \
    list_zonefile_history, \
    lookup_snv, \
    put_immutable, \
    put_mutable

from rpc import local_rpc_connect, local_rpc_ensure_running, local_rpc_status, local_rpc_stop
import rpc as local_rpc
import config
from .config import WALLET_PATH, WALLET_PASSWORD_LENGTH, CONFIG_PATH, CONFIG_DIR, configure, FIRST_BLOCK_TIME_UTC, get_utxo_provider_client
from .storage import is_valid_name, is_b40

from pybitcoin import is_b58check_address

from binascii import hexlify

from .backend.blockchain import get_balance, is_address_usable, can_receive_name, get_tx_confirmations
from .backend.nameops import estimate_preorder_tx_fee, estimate_register_tx_fee, estimate_update_tx_fee, estimate_transfer_tx_fee

from .wallet import *
from .utils import pretty_dump, print_result
from .proxy import *

log = config.get_logger()

def check_valid_name(fqu):
    """
    Verify that a name is valid.
    Return None on success
    Return an error string on error
    """
    rc = is_valid_name( fqu )
    if rc:
        return None

    # get a coherent reason why
    if '.' not in fqu:
        msg = 'The name specified is invalid.'
        msg += ' Names must end with a period followed by a valid TLD.'
        return msg

    if len(fqu.split('.')[0]) == 0:
        msg = 'The name specified is invalid.'
        msg += ' Names must be at least one character long, not including the TLD.'
        return msg

    if not is_b40( fqu.split('.')[0] ):
        msg = 'The name specified is invalid.'
        msg += ' Names may only contain alphanumeric characters,'
        msg += ' dashes, and underscores.'
        return msg

    return "The name is invalid"


def can_update_or_transfer(fqu, owner_pubkey_hex, payment_privkey, config_path=CONFIG_PATH, transfer_address=None, proxy=None):
    """
    Any update or transfer operation
    should pass these tests:
    * name must be registered
    * name must be owned by the owner address in the wallet
    * the payment address must have enough BTC
    * the payment address can't have any pending transactions
    * if given, the transfer address must be suitable for receiving the name
    (i.e. it can't own too many names already).
    
    Return {'status': True} on success
    Return {'error': ...} on error
    """

    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    if proxy is None:
        proxy = get_default_proxy(config_path)

    if not is_name_registered(fqu, proxy=proxy):
        return {'error': '%s is not registered yet.' % fqu}

    utxo_client = get_utxo_provider_client( config_path=config_path )
    payment_address, owner_address, data_address = get_addresses_from_file(wallet_path=wallet_path)

    if not is_name_owner(fqu, owner_address, proxy=proxy):
        return {'error': '%s is not in your possession.' % fqu}

    # get tx fee 
    if transfer_address is not None:
        tx_fee = estimate_transfer_tx_fee( fqu, owner_pubkey_hex, payment_privkey, utxo_client, config_path=config_path ) 
    else:
        tx_fee = estimate_update_tx_fee( fqu, owner_pubkey_hex, payment_privkey, utxo_client, config_path=config_path )

    balance = get_balance( payment_address, config_path=config_path )

    if balance < tx_fee:
        return {'error': 'Address %s doesn\'t have a sufficient balance (need %s).' % (payment_address, balance)}

    if not is_address_usable(payment_address, config_path=config_path):
        return {'error': 'Address %s has pending transactions.  Wait and try later.' % payment_address}

    if transfer_address is not None:

        try:
            resp = is_b58check_address(str(transfer_address))
        except:
            return {'error': "Address %s is not a valid Bitcoin address." % transfer_address}

        if not can_receive_name(transfer_address, proxy=proxy):
            return {'error': "Address %s owns too many names already." % transfer_address}

    return {'status': True}


def get_total_registration_fees(name, owner_pubkey_hex, payment_privkey, proxy=None, config_path=CONFIG_PATH):

    try:
        data = get_name_cost(name, proxy=proxy)
    except Exception, e:
        log.exception(e)
        return {'error': 'Could not connect to server'}

    if 'error' in data:
        return {'error': 'Could not determine price of name: %s' % data['error']}

    utxo_client = get_utxo_provider_client( config_path=config_path )
    
    # fee stimation: cost of name + cost of preorder transaction + cost of registration transaction + cost of update transaction
    payment_pubkey_hex = pybitcoin.BitcoinPrivateKey(payment_privkey).public_key().to_hex()

    reply = {}
    reply['name_price'] = data['satoshis']
    reply['preorder_tx_fee'] = estimate_preorder_tx_fee( name, data['satoshis'], payment_pubkey_hex, utxo_client, config_path=config_path )
    reply['register_tx_fee'] = estimate_register_tx_fee( name, payment_pubkey_hex, utxo_client, config_path=config_path )
    reply['update_tx_fee'] = estimate_update_tx_fee( name, owner_pubkey_hex, payment_privkey, utxo_client, config_path=config_path )

    reply['total_estimated_cost'] = reply['name_price'] + reply['preorder_tx_fee'] + reply['register_tx_fee'] + reply['update_tx_fee']

    return reply


def start_rpc_endpoint(config_dir=CONFIG_DIR, password=None):
    """
    Decorator that will ensure that the RPC endpoint
    is running before the wrapped function is called.
    Raise on error
    """
    if not wallet_exists(config_dir=config_dir):
        res = initialize_wallet(wallet_path=wallet_path)
        if 'error' in res:
            return res

    rc = local_rpc_ensure_running( config_dir, password=password )
    if not rc:
        raise Exception("Failed to start RPC endpoint (from %s)" % config_dir)

    return True


def cli_configure( args, config_path=CONFIG_PATH ):
    """
    command: configure
    help: Interactively configure the client.
    """

    opts = configure( interactive=True, force=False, config_file=config_path )
    result = {}
    result['path'] = opts['blockstack-client']['path']
    return result


def cli_balance( args, config_path=CONFIG_PATH ):
    """
    command: balance
    help: Get and return the account balance.
    """

    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)
    if not wallet_exists(config_dir=config_dir):
        res = initialize_wallet(wallet_path=wallet_path)
        if 'error' in res:
            return res

    result = {}
    result['total_balance'], result['addresses'] = get_total_balance(config_path=config_path)
    return result


def cli_price( args, config_path=CONFIG_PATH, proxy=None):
    """
    command: price
    help: Get and return the price of a name
    arg: name (str) "Name to query"
    """

    if proxy is None:
        proxy = get_default_proxy()

    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    try:
        resp = get_name_cost(fqu, proxy=proxy)
    except socket_error:
        return {'error': 'Error connecting to server'}

    if 'error' in resp:
        return resp

    if not walletUnlocked(config_dir=config_dir):
        log.debug("unlocking wallet (%s)" % config_dir)
        res = unlock_wallet(config_dir=config_dir, password=password)
        if 'error' in res:
            log.debug("unlock_wallet: %s" % res['error'])
            return res

    wallet_keys = get_wallet( config_path=config_path )
    if 'error' in wallet_keys:
        return wallet_keys
    
    owner_privkey = wallet_keys['owner_privkey']
    payment_privkey = wallet_keys['payment_privkey']

    fees = get_total_registration_fees(fqu, pybitcoin.BitcoinPrivateKey(owner_privkey).public_key().to_hex(), payment_privkey, proxy=proxy, config_path=config_path)
    return fees


def cli_config( args, config_path=CONFIG_PATH ):
    """
    command: config
    help: Set configuration options
    arg: --host (str) "Hostname/IP of the Blockstack server"
    arg: --port (int) "Server port to connect to"
    arg: --advanced (str)  "Can be 'on' or 'off"
    """

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
            return {'error': "Use --advanced=on or --advanced=off"}
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

    return result


def cli_deposit( args, config_path=CONFIG_PATH ):
    """
    command: deposit
    help: Display the address with which to receive bitcoins
    """

    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)
    if not os.path.exists(wallet_path):
        res = initialize_wallet(wallet_path=wallet_path)
        if 'error' in res:
            return res

    result = {}
    result['message'] = 'Send bitcoins to the address specified.'
    result['address'], owner_address, data_address = get_addresses_from_file(wallet_path=wallet_path)
    return result


def cli_import( args, config_path=CONFIG_PATH ):
    """
    command: import
    help: Display the address with which to receive names
    """

    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)
    if not os.path.exists(wallet_path):
        res = initialize_wallet(wallet_path=wallet_path)
        if 'error' in res:
            return res

    result = {}
    result['message'] = 'Send the name you want to receive to the'
    result['message'] += ' address specified.'
    payment_address, result['address'], data_address = get_addresses_from_file(wallet_path=wallet_path)

    return result


def cli_import_wallet( args, config_path=CONFIG_PATH, password=None, force=False ):
    """
    command: import_wallet
    help: Set the payment, owner, and (optionally) data private keys for the wallet.
    arg: payment_privkey (str) "Payment private key"
    arg: owner_privkey (str) "Name owner private key"
    opt: data_privkey (str) "Data-signing private key"
    """
    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)
    if force and os.path.exists(wallet_path):
        # overwrite
        os.unlink(wallet_path)

    if not os.path.exists(wallet_path):
        if password is None:

            while True:
                res = make_wallet_password(password)
                if 'error' in res and password is None:
                    print res['error']
                    continue

                elif password is not None:
                    return res

                else:
                    password = res['password']
                    break

        data = make_wallet( password, payment_privkey=args.payment_privkey, owner_privkey=args.owner_privkey, data_privkey=args.data_privkey, config_path=config_path ) 
        if 'error' in data:
            return data

        else:
            write_wallet( data, path=wallet_path )

            # update RPC daemon if we're running
            if local_rpc_status(config_dir=config_dir):
                local_rpc_stop(config_dir=config_dir)
                start_rpc_endpoint(config_dir, password=password)

            return {'status': True}

    else:
        return {'error': 'Wallet already exists!', 'message': 'Back up or remove current wallet first: %s' % wallet_path}


def cli_names( args, config_path=CONFIG_DIR ):
    """
    command: names
    help: Display the names owned by local addresses
    """
    result = {}

    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)
    if not os.path.exists(wallet_path):
        res = initialize_wallet(wallet_path=wallet_path)
        if 'error' in res:
            return res

    result['names_owned'] = get_all_names_owned(wallet_path)
    result['addresses'] = get_owner_addresses(wallet_path)

    return result


def get_server_info( args, config_path=config.CONFIG_PATH ):
    """
    Get information about the running server,
    and any pending operations.
    """
    
    config_dir = os.path.dirname(config_path)
    conf = config.get_config(config_path)
    start_rpc_endpoint(config_dir)

    resp = getinfo()
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

        if conf['advanced_mode']:
            result['testset'] = resp['testset']

        rpc = local_rpc_connect(config_dir=config_dir)

        if rpc is not None:

            current_state = json.loads(rpc.backend_state())

            queue_types = {
                "preorder": [],
                "register": [],
                "update": [],
                "transfer": []
            }

            def format_new_entry(entry):
                """
                Determine data to display
                """
                new_entry = {}
                new_entry['name'] = entry['fqu']
                confirmations = get_tx_confirmations(entry['tx_hash'], config_path=config_path)
                if confirmations is None:
                    confirmations = 0
                new_entry['confirmations'] = confirmations
                return new_entry

            def format_queue_display(preorder_queue,
                                     register_queue):

                """
                Omit duplicates
                """
                for entry in register_queue:
                    name = entry['name']
                    for check_entry in preorder_queue:
                        if check_entry['name'] == name:
                            preorder_queue.remove(check_entry)

            for entry in current_state:
                if entry['type'] not in queue_types.keys():
                    log.error("Unknown entry type '%s'" % entry['type'])
                    continue

                queue_types[ entry['type'] ].append( format_new_entry(entry) )

            format_queue_display(queue_types['preorder'], queue_types['register'])

            for queue_type in queue_types.keys():
                if len(queue_types[queue_type]) == 0:
                    del queue_types[queue_type]

            if len(queue_types) > 0:
                result['queue'] = queue_types

    return result


def cli_info( args, config_path=CONFIG_PATH ):
    """
    command: info
    help: Check server status and get details about the server
    """
    return get_server_info( args, config_path=config_path )


def cli_ping( args, config_path=CONFIG_PATH ):
    """
    command: ping
    help: Check server status and get details about the server
    """
    return get_server_info( args, config_path=config_path )


def cli_status( args, config_path=CONFIG_PATH ):
    """
    command: status
    help: Check server status and get details about the server
    """
    return get_server_info( args, config_path=config_path )


def cli_details( args, config_path=CONFIG_PATH ):
    """
    command: details
    help: Check server status and get details about the server
    """
    return get_server_info( args, config_path=config_path )


def cli_lookup( args, config_path=CONFIG_PATH ):
    """
    command: lookup
    help: Get the data record for a particular name.
    arg: name (str) "The name to look up"
    """
    data = {}

    blockchain_record = None
    fqu = str(args.name)

    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    try:
        blockchain_record = get_name_blockchain_record(fqu)
    except socket_error:
        return {'error': 'Error connecting to server.'}

    if 'value_hash' not in blockchain_record:
        return {'error': '%s is not registered' % fqu}

    try:
        user_profile, user_zonefile = get_name_profile(str(args.name))
        data['profile'] = user_profile
        data['zonefile'] = user_zonefile
    except:
        data['profile'] = None
        data['zonefile'] = None

    result = data
    return result 


def cli_whois( args, config_path=CONFIG_PATH ):
    """
    command: whois
    help: Look up a name's blockchain info
    arg: name (str) "The name to look up"
    """
    result = {}

    record = None
    fqu = str(args.name)

    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    try:
        record = get_name_blockchain_record(fqu)
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

        if record.has_key('expire_block'):
            result['expire_block'] = record['expire_block']
            result['approx_expiration_date'] = time.strftime( "%Y %b %d %H:%M:%S UTC", FIRST_BLOCK_TIME_UTC + (record['expire_block'] - FIRST_BLOCK_MAINNET) * 600 )

    return result


def get_wallet_keys( config_path, password ):
    """
    Load up the wallet keys
    Return the dict with the keys on success
    Return {'error': ...} on failure
    """
    
    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)
    if not os.path.exists(wallet_path):
        res = initialize_wallet(wallet_path=wallet_path)
        if 'error' in res:
            return res

    if not walletUnlocked(config_dir=config_dir):
        log.debug("unlocking wallet (%s)" % config_dir)
        res = unlock_wallet(config_dir=config_dir, password=password)
        if 'error' in res:
            log.debug("unlock_wallet: %s" % res['error'])
            return res

    wallet_keys = get_wallet( config_path=config_path )
    if 'error' in wallet_keys:
        return wallet_keys

    return wallet_keys


def cli_register( args, config_path=CONFIG_PATH, interactive=True, password=None, proxy=None ):
    """
    command: register
    help: Register a name 
    arg: name (str) "The name to register"
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    config_dir = os.path.dirname(config_path)
    start_rpc_endpoint(config_dir, password=password)

    result = {}
    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error: 
        return {'error': error}

    if is_name_registered(fqu, proxy=proxy):
        return {'error': '%s is already registered.' % fqu}

    wallet_keys = get_wallet_keys( config_path, password )
    if 'error' in wallet_keys:
        return wallet_keys

    owner_privkey = wallet_keys['owner_privkey']
    payment_privkey = wallet_keys['payment_privkey']
    data_privkey = wallet_keys['data_privkey']
    owner_pubkey = pybitcoin.BitcoinPrivateKey(owner_privkey).public_key().to_hex()
    owner_address = pybitcoin.BitcoinPublicKey(owner_pubkey).address()
    payment_address = pybitcoin.BitcoinPrivateKey(owner_privkey).public_key().address()
    data_address = pybitcoin.BitcoinPrivateKey(data_privkey).public_key().address()

    fees = get_total_registration_fees(fqu, owner_pubkey, payment_privkey, proxy=proxy, config_path=config_path)

    if interactive:
        try:
            cost = fees['total_estimated_cost']
            input_prompt = "Registering %s will cost %s BTC." % (fqu, float(cost)/(10**8))
            input_prompt += " Continue? (y/n): "
            user_input = raw_input(input_prompt)
            user_input = user_input.lower()

            if user_input != 'y':
                print "Not registering."
                exit(0)
        except KeyboardInterrupt:
            print "\nExiting."
            exit(0)

    balance = get_balance( payment_address )
    if balance < fees['total_estimated_cost']:
        msg = "Address %s doesn't have enough balance (need %s)." % (payment_address, balance)
        return {'error': msg}

    if not can_receive_name(owner_address, proxy=proxy):
        msg = "Address %s owns too many names already." % owner_address
        return {'error': msg}

    if not is_address_usable(payment_address, config_path=config_path):
        msg = "Address %s has pending transactions." % payment_address
        msg += " Wait and try later."
        return {'error': msg}

    rpc = local_rpc_connect( config_dir=config_dir )

    try:
        resp = rpc.backend_preorder(fqu)
    except:
        return {'error': 'Error talking to server, try again.'}

    if 'success' in resp and resp['success']:
        result = resp
    else:
        if 'error' in resp:
            log.debug("RPC error: %s" % resp['error'])
            return resp

        if 'message' in resp:
            return {'error': resp['message']}

    return result


def cli_update( args, config_path=CONFIG_PATH, password=None ):
    """
    command: update
    help: Update a name's zonefile
    arg: name (str) "The name to update"
    arg: data (str) "A JSON-formatted zonefile"
    """

    config_dir = os.path.dirname(config_path)
    start_rpc_endpoint(config_dir, password=password)
    fqu = str(args.name)

    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    user_data = str(args.data)
    try:
        user_data = json.loads(user_data)
    except:
        return {'error': 'Zonefile data is not in JSON format.'}

    if is_zonefile_current(fqu, user_data):
        msg ="Zonefile data is same as current zonefile; update not needed."
        return {'error': msg}

    wallet_keys = get_wallet_keys( config_path, password )
    if 'error' in wallet_keys:
        return wallet_keys

    owner_privkey = wallet_keys['owner_privkey']
    payment_privkey = wallet_keys['payment_privkey']
    owner_pubkey = pybitcoin.BitcoinPrivateKey(owner_privkey).public_key().to_hex()

    res = can_update_or_transfer(fqu, owner_pubkey, payment_privkey, config_path=config_path)
    if 'error' in res:
        return res

    rpc = local_rpc_connect(config_dir=config_dir)

    try:
        resp = rpc.backend_update(fqu, user_data, None)
    except:
        return {'error': 'Error talking to server, try again.'}

    if 'success' in resp and resp['success']:
        result = resp
    else:
        if 'error' in resp:
            return resp

        if 'message' in resp:
            return {'error': resp['message']}

    return result


def cli_transfer( args, config_path=CONFIG_PATH, password=None ):
    """
    command: transfer
    help: Transfer a name to a new address
    arg: name (str) "The name to transfer"
    arg: address (str) "The address to receive the name"
    """

    config_dir = os.path.dirname(config_path)
    start_rpc_endpoint(config_dir, password=password)

    wallet_keys = get_wallet_keys( config_path, password )
    if 'error' in wallet_keys:
        return wallet_keys

    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    transfer_address = str(args.address)
    owner_privkey = wallet_keys['owner_privkey']
    payment_privkey = wallet_keys['payment_privkey']
    owner_pubkey = pybitcoin.BitcoinPrivateKey(owner_privkey).public_key().to_hex()

    res = can_update_or_transfer(fqu, owner_pubkey, payment_privkey, transfer_address=transfer_address, config_path=config_path)
    if 'error' in res:
        return res

    rpc = local_rpc_connect(config_dir=config_dir)

    try:
        resp = rpc.backend_transfer(fqu, transfer_address)
    except:
        return {'error': 'Error talking to server, try again.'}

    if 'success' in resp and resp['success']:
        result = resp
    else:
        if 'error' in resp:
            return resp

        if 'message' in resp:
            return {'error': resp['message']}

    return result


def cli_migrate( args, config_path=CONFIG_PATH, password=None, proxy=None ):
    """
    command: migrate
    help: Migrate your profile from the legacy format to the new format.  This will enable all new features.
    arg: name (str) "The name to migrate"
    opt: txid (str) "The transaction ID of a previously-sent but failed migration"
    """

    config_dir = os.path.dirname(config_path)
    start_rpc_endpoint(config_dir, password=password)

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    wallet_keys = get_wallet_keys( config_path, password )
    if 'error' in wallet_keys:
        return wallet_keys

    transfer_address = str(args.address)
    owner_privkey = wallet_keys['owner_privkey']
    payment_privkey = wallet_keys['payment_privkey']
    owner_pubkey = pybitcoin.BitcoinPrivateKey(owner_privkey).public_key().to_hex()

    res = can_update_or_transfer(fqu, owner_pubkey, payment_privkey, config_path=config_path)
    if 'error' in res:
        return res

    user_zonefile = get_name_zonefile( fqu, proxy=proxy, wallet_keys=wallet_keys )
    if user_zonefile is not None and 'error' not in user_zonefile and is_zonefile_current(fqu, user_zonefile):
        msg ="Zonefile data is same as current zonefile; update not needed."
        return {'error': msg}

    rpc = local_rpc_connect(config_dir=config_dir)

    try:
        resp = rpc.backend_migrate(fqu)
    except Exception, e:
        return {'error': 'Error talking to server, try again.'}

    if 'success' in resp and resp['success']:
        result = resp
    else:
        if 'error' in resp:
            return resp

        if 'message' in resp:
            return {'error': resp['message']}

    return result


def cli_advanced_wallet( args, config_path=CONFIG_PATH, password=None ):
    """
    command: wallet
    help: Query wallet information
    """
    
    result = {}
    config_dir = os.path.dirname(config_path)
    start_rpc_endpoint(config_dir, password=password)

    wallet_path = os.path.join(config_dir, WALLET_FILENAME)
    if not os.path.exists(wallet_path):
        result = initialize_wallet(wallet_path=wallet_path)
    else:
        result = unlock_wallet(display_enabled=True, config_dir=config_dir, password=password)

    return result


def cli_advanced_consensus( args, config_path=CONFIG_PATH ):
    """
    command: consensus
    help: Get current consensus information 
    opt: block_height (int) "The block height at which to query the consensus information.  If not given, the current height is used."
    """
    result = {}
    if args.block_height is None:
        # by default get last indexed block
        resp = getinfo()

        if 'error' in resp:
            return resp

        elif 'last_block' in resp or 'blocks' in resp:

            if 'last_block' in resp:
                args.block_height = getinfo()['last_block']
            elif 'blocks' in resp:
                args.block_height = getinfo()['blocks']
            else:
                result['error'] = "Server is indexing. Try again"
                return result

    resp = get_consensus_at(int(args.block_height))

    data = {}
    data['consensus'] = resp
    data['block_height'] = args.block_height

    result = data
    return result


def cli_advanced_rpcctl( args, config_path=CONFIG_PATH ):
    """
    command: rpcctl
    help: Control the background blockstack API endpoint
    arg: command (str) "'start', 'stop', 'restart', or 'status'"
    """

    config_dir = config.CONFIG_DIR
    if config_path is not None:
        config_dir = os.path.dirname(config_path)

    rc = local_rpc.local_rpc_action( str(args.command), config_dir=config_dir )
    if rc != 0:
        return {'error': 'RPC controller exit code %s' % rc}
    else:
        return {'status': True}


def cli_advanced_rpc( args, config_path=CONFIG_PATH ):
    """
    command: rpc
    help: Issue an RPC request to a locally-running API endpoint
    arg: method (str) "The method to call"
    opt: args (str) "A JSON list of positional arguments."
    opt: kwargs (str) "A JSON object of keyword arguments."
    """
    
    rpc_args = []
    rpc_kw = {}

    if args.args is not None:
        rpc_args = json.loads(args.args)

    if args.kwargs is not None:
        rpc_kw = json.loads(args.kwargs)

    conf = config.get_config( path=config_path )
    portnum = conf['api_endpoint_port']
    result = local_rpc.local_rpc_dispatch( portnum, str(args.method), *rpc_args, **rpc_kw ) 
    return result


def cli_advanced_register_tx( args, config_path=CONFIG_PATH ):
    """
    command: register_tx
    help: Generate an unsigned transaction to register a name
    arg: name (str) "The name to register"
    arg: public_key (str) "The public key to send the registration transaction"
    arg: addr (str) "The address to receive the name"
    """

    # BROKEN
    result = register_tx(str(args.name), str(args.public_key),
                      str(args.addr))
    return result


def cli_advanced_register_subsidized( args, config_path=CONFIG_PATH ):
    """
    command: register_subsidized
    help: Generate a signed, subsidized transaction to register a name
    arg: name (str) "The name to register"
    arg: public_key (str) "The public key that sent the preorder tx"
    arg: addr (str) "The address to receive the name"
    """
    # BROKEN
    result = register_subsidized(str(args.name), str(args.public_key),
                                 str(args.addr))

    return result


def cli_advanced_update_tx( args, config_path=CONFIG_PATH ):
    """
    command: update_tx
    help: Generate an unsigned transaction to update a name
    arg: name (str) "The name to update"
    arg: data (str) "The JSON-formatted zone file"
    arg: public_key (str) "The public key of the name's address"
    """

    # BROKEN
    txid = None
    if args.txid is not None:
        txid = str(args.txid)

    result = update_tx(str(args.name),
                    str(args.data),
                    str(args.public_key))

    return result


def cli_advanced_update_subsidized( args, config_path=CONFIG_PATH ):
    """
    command: update_subsidized
    help: Generate a signed, subsidized transaction to update a name
    arg: name (str) "The name to update"
    arg: data (str) "The JSON-formatted zone file"
    arg: public_key (str) "The public key of the name's address"
    opt: txid (str) "The transaction ID of a previously-sent but failed update"
    """
        
    # BROKEN
    txid = None
    if args.txid is not None:
        txid = str(args.txid)

    result = update_subsidized(str(args.name),
                               str(args.data),
                               str(args.public_key),
                               txid=txid)

    return result


def cli_advanced_preorder_tx( args, config_path=CONFIG_PATH ):
    """
    command: preorder_tx
    help: Generate an unsigned transaction that will preorder a name
    arg: name (str) "The name to preorder"
    arg: public_key (str) "The public key to pay for the preorder"
    opt: address (str) "The address to receive the name (automatically generated if not given)"
    """

    # BROKEN
    register_addr = None
    if args.address is not None:
        register_addr = str(args.address)

    result = preorder_tx(str(args.name), str(args.public_key),
                      register_addr=register_addr)

    return result


def cli_advanced_preorder_subsidized( args, config_path=CONFIG_PATH ):
    """
    command: preorder_subsidized
    help: Generate a subsidized transaction that will preorder a name.
    arg: name (str) "The name to preorder"
    arg: address (str) "The address of the name recipient"
    """
    # BROKEN
    result = preorder_subsidized(str(args.name),
                                 str(args.address))

    return result


def cli_advanced_transfer_tx( args, config_path=CONFIG_PATH ):
    """
    command: transfer_tx
    help: Generate an unsigned transaction that will transfer a name
    arg: name (str) "The name to transfer"
    arg: address (str) "The address to receive the name"
    arg: keepdata (str) "Whether or not to preserve the zonefile (True or False)"
    arg: privatekey (str) "The private key of the name owner"
    """
    # BROKEN
    keepdata = False
    if args.keepdata.lower() not in ['true', 'false']:
        return {'error': "Pass 'true' or 'false' for keepdata"}

    if args.keepdata.lower() == 'true':
        keepdata = True

    result = transfer( str(args.name),
                       str(args.address),
                       keepdata,
                       str(args.privatekey),
                       tx_only=True )

    return result


def cli_advanced_transfer_subsidized( args, config_path=CONFIG_PATH ):
    """
    command: transfer_subsidized
    help: Generate a subsidized transaction that will transfer a name
    arg: name (str) "The name to transfer"
    arg: address (str) "The address to receive the name"
    arg: keepdata (str) "Whether or not to preserve the zonefile (True or False)"
    arg: public_key (str) "The public key of the name owner"
    """
    # BROKEN

    keepdata = False
    if args.keepdata.lower() not in ["true", "false"]:
        print >> sys.stderr, "Pass 'true' or 'false' for keepdata"
        sys.exit(1)

    if args.keepdata.lower() == "true":
        keepdata = True

    result = transfer_subsidized(str(args.name),
                                 str(args.address),
                                 keepdata,
                                 str(args.public_key))

    return result


def cli_advanced_renew( args, config_path=CONFIG_PATH ):
    """
    command: renew
    help: Renew a name
    arg: name (str) "The name to renew"
    arg: privatekey (str) "The private key of the name owner"
    """
    # BROKEN
    config_dir = os.path.dirname(config_path)
    start_rpc_endpoint(config_dir)

    result = renew(str(args.name), str(args.privatekey))
    return result


def cli_advanced_renew_tx( args, config_path=CONFIG_PATH ):
    """
    command: renew_tx
    help: Generate an unsigned transaction that will renew a name
    arg: name (str) "The name to renew"
    arg: privatekey (str) "The private key of the name owner"
    """
    # BROKEN
    result = renew(str(args.name), str(args.privatekey),
                   tx_only=True)

    return result


def cli_advanced_renew_subsidized( args, config_path=CONFIG_PATH ):
    """
    command: renew_subsidized
    help: Generate a subsidized transaction that will renew a name
    arg: name (str) "The name to renew"
    arg: public_key (str) "The public key of the name owner"
    arg: subsidy_key (str) "The private key that will pay for the renewal"
    """
    # BROKEN
    result = renew_subsidized(str(args.name), str(args.public_key),
                              str(args.subsidy_key))

    return result


def cli_advanced_revoke( args, config_path=CONFIG_PATH ):
    """
    command: revoke
    help: Revoke a name, rendering it inaccessible
    arg: name (str) "The name to revoke"
    arg: privatekey (str) "The private key of the name owner"
    """
    # BROKEN
    result = revoke(str(args.name), str(args.privatekey))
    return result


def cli_advanced_revoke_tx( args, config_path=CONFIG_PATH ):
    """
    command: revoke_tx
    help: Generate an unsigned transaction that will revoke a name
    arg: name (str) "The name to revoke"
    arg: privatekey (str) "The private key of the name owner"
    """
    # BROKEN
    result = revoke(str(args.name), str(args.privatekey),
                    tx_only=True)

    return result


def cli_advanced_revoke_subsidized( args, config_path=CONFIG_PATH ):
    """
    command: revoke_subsidized
    help: Generate a subsidized transaction that will revoke a name
    arg: name (str) "The name to revoke"
    arg: public_key (str) "The public key of the name owner"
    arg: subsidy_key (str) "The private key that will pay for the revoke"
    """
    # BROKEN
    result = revoke_subsidized(str(args.name), str(args.public_key),
                               str(args.subsidy_key))
    return result


def cli_advanced_name_import( args, config_path=CONFIG_PATH ):
    """
    command: name_import
    help: Import a name to a revealed but not-yet-readied namespace
    arg: name (str) "The name to import"
    arg: address (str) "The address of the name recipient"
    arg: hash (str) "The zonefile hash of the name"
    arg: privatekey (str) "One of the private keys of the namespace revealer"
    """
    # BROKEN
    result = name_import(str(args.name), str(args.address),
                         str(args.hash), str(args.privatekey))

    return result


def cli_advanced_namespace_preorder( args, config_path=CONFIG_PATH ):
    """
    command: namespace_preorder
    help: Preorder a namespace
    arg: namespace_id (str) "The namesapce ID"
    arg: privatekey (str) "The private key to send and pay for the preorder"
    opt: reveal_addr (str) "The address of the keypair that will import names (automatically generated if not given)"
    """
    # BROKEN
    reveal_addr = None
    if args.address is not None:
        reveal_addr = str(args.address)

    result = namespace_preorder(str(args.namespace_id),
                                str(args.privatekey),
                                reveal_addr=reveal_addr)

    return result


def cli_advanced_namespace_reveal( args, config_path=CONFIG_PATH ):
    """
    command: namespace_reveal
    help: Reveal a namespace and set its pricing parameters
    arg: namespace_id (str) "The namespace ID"
    arg: addr (str) "The address of the keypair that will import names (given in the namespace preorder)"
    arg: lifetime (int) "The lifetime (in blocks) for eahc name.  Negative means 'never expires'."
    arg: coeff (int) "The multiplicative coefficient in the price function."
    arg: base (int) "The exponential base in the price function."
    arg: bucket_exponents (str) "A 16-field CSV of name-length exponents in the price function."
    arg: nonalpha_discount (int) "The denominator that defines the discount for names with non-alpha characters."
    arg: no_vowel_discount (int) "The denominator that defines the discount for names without vowels."
    arg: privatekey (str) "The private key of the import keypair (whose address is `addr` above)."
    """
    # BROKEN
    bucket_exponents = args.bucket_exponents.split(',')
    if len(bucket_exponents) != 16:
        return {'error': '`bucket_exponents` must be a 16-value CSV of integers'}

    for i in xrange(0, len(bucket_exponents)):
        try:
            bucket_exponents[i] = int(bucket_exponents[i])
        except:
            return {'error': '`bucket_exponents` must contain integers between 0 and 15, inclusively.'}

    lifetime = int(args.lifetime)
    if lifetime < 0:
        lifetime = 0xffffffff       # means "infinite" to blockstack-server

    result = namespace_reveal(str(args.namespace_id),
                              str(args.addr),
                              lifetime,
                              int(args.coeff),
                              int(args.base),
                              bucket_exponents,
                              int(args.nonalpha_discount),
                              int(args.no_vowel_discount),
                              str(args.privatekey))

    return result


def cli_advanced_namespace_ready( args, config_path=CONFIG_PATH ):
    """
    command: namespace_ready
    help: Mark a namespace as ready
    arg: namespace_id (str) "The namespace ID"
    arg: privatekey (str) "The private key of the keypair that imports names"
    """
    # BROKEN
    result = namespace_ready(str(args.namespace_id),
                             str(args.privatekey))

    return result


def cli_advanced_put_mutable( args, config_path=CONFIG_PATH ):
    """
    command: put_mutable
    help: Put mutable data into a profile
    arg: name (str) "The name to receive the data"
    arg: data_id (str) "The name of the data"
    arg: data (str) "The JSON-formatted data to store"
    """
    result = put_mutable(str(args.name),
                         str(args.data_id),
                         str(args.data))

    return result


def cli_advanced_put_immutable( args, config_path=CONFIG_PATH ):
    """
    command: put_immutable
    help: Put immutable data into a zonefile
    arg: name (str) "The name to receive the data"
    arg: data_id (str) "The name of the data"
    arg: data (str) "The JSON-formatted data to store"
    """
    config_dir = os.path.dirname(config_path)
    start_rpc_endpoint(config_dir)
    conf = config.get_config( config_path=config_path )
    result = put_immutable(str(args.name),
                           str(args.data_id),
                           str(args.data),
                           conf=conf)

    return result


def cli_advanced_get_mutable( args, config_path=CONFIG_PATH ):
    """
    command: get_mutable
    help: Get mutable data from a profile
    arg: name (str) "The name that has the data"
    arg: data_id (str) "The name of the data"
    """
    conf = config.get_config( config_path=config_path )
    result = get_mutable(str(args.name), str(args.data_id),
                         conf=conf)

    return result 


def cli_advanced_get_immutable( args, config_path=CONFIG_PATH ):
    """
    command: get_immutable
    help: Get immutable data from a zonefile
    arg: name (str) "The name that has the data"
    arg: data_id_or_hash (str) "Either the name or the SHA256 of the data to obtain"
    """
    result = get_immutable(str(args.name), str(args.data_id_or_hash))
    return result


def cli_advanced_list_update_history( args, config_path=CONFIG_PATH ):
    """
    command: list_update_history
    help: List the history of update hashes for a name
    arg: name (str) "The name whose data to list"
    """
    result = list_update_history(str(args.name))
    return result


def cli_advanced_list_zonefile_history( args, config_path=CONFIG_PATH ):
    """
    command: list_zonefile_history
    help: List the history of zonefiles for a name (if they can be obtained)
    arg: name (str) "The name whose zonefiles to list"
    """
    result = list_zonefile_history(str(args.name))
    return result


def cli_advanced_list_immutable_data_history( args, config_path=CONFIG_PATH ):
    """
    command: list_immutable_data_history
    help: List all prior hashes of a given immutable datum
    arg: name (str) "The name whose data to list"
    arg: data_id (str) "The data identifier whose history to list"
    """
    result = list_immutable_data_history(str(args.name), str(args.data_id))
    return result


def cli_advanced_delete_immutable( args, config_path=CONFIG_PATH ):
    """
    command: delete_immutable
    help: Delete an immutable datum from a zonefile.
    arg: name (str) "The name that owns the data"
    arg: hash (str) "The SHA256 of the data to remove"
    """
    
    config_dir = os.path.dirname(config_path)
    start_rpc_endpoint(config_dir)
    result = delete_immutable(str(args.name), str(args.hash))

    return result


def cli_advanced_delete_mutable( args, config_path=CONFIG_PATH ):
    """
    command: delete_mutable
    help: Delete a mutable datum from a profile.
    arg: name (str) "The name that owns the data"
    arg: data_id (str) "The ID of the data to remove"
    """
    result = delete_mutable(str(args.name), str(args.data_id))


    return result


def cli_advanced_get_name_blockchain_record( args, config_path=CONFIG_PATH ):
    """
    command: get_name_blockchain_record
    help: Get the raw blockchain record for a name
    arg: name (str) "The name to list"
    """
    result = get_name_blockchain_record(str(args.name))
    return result


def cli_advanced_get_namespace_blockchain_record( args, config_path=CONFIG_PATH ):
    """
    command: get_namespace_blockchain_record
    help: Get the raw namespace blockchain record for a name
    arg: namespace_id (str) "The namespace ID to list"
    """
    result = get_namespace_blockchain_record(str(args.namespace_id))
    return result


def cli_advanced_lookup_snv( args, config_path=CONFIG_PATH ):
    """
    command: lookup_snv
    help: Use SNV to look up a name at a particular block height
    arg: name (str) "The name to query"
    arg: block_id (int) "The block height at which to query the name"
    arg: trust_anchor (str) "The trusted consensus hash, transaction ID, or serial number from a higher block height than `block_id`"
    """
    result = lookup_snv(str(args.name), int(args.block_id),
                        str(args.trust_anchor))

    return result


def cli_advanced_get_name_zonefile( args, config_path=CONFIG_PATH ):
    """
    command: get_name_zonefile
    help: Get a name's zonefile, as a JSON dict
    arg: name (str) "The name to query"
    """
    result = get_name_zonefile(str(args.name))
    return result


def cli_advanced_get_names_owned_by_address( args, config_path=CONFIG_PATH ):
    """
    command: get_names_owned_by_address
    help: Get the list of names owned by an address
    arg: address (str) "The address to query"
    """
    result = get_names_owned_by_address(str(args.address))
    return result


def cli_advanced_get_namespace_cost( args, config_path=CONFIG_PATH ):
    """
    command: get_namespace_cost
    help: Get the cost of a namespace
    arg: namespace_id (str) "The namespace ID to query"
    """
    result = get_namespace_cost(str(args.namespace_id))
    return result


def cli_advanced_get_all_names( args, config_path=CONFIG_PATH ):
    """
    command: get_all_names
    help: Get all names in existence, optionally paginating through them
    opt: offset (int) "The offset into the sorted list of names"
    opt: count (int) "The number of names to return"
    """
    offset = None
    count = None

    if args.offset is not None:
        offset = int(args.offset)

    if args.count is not None:
        count = int(args.count)

    result = get_all_names(offset, count)
    return result


def cli_advanced_get_names_in_namespace( args, config_path=CONFIG_PATH ):
    """
    command: get_names_in_namespace
    help: Get the names in a given namespace, optionally patinating through them
    arg: namespace_id (str) "The ID of the namespace to query"
    opt: offset (int) "The offset into the sorted list of names"
    opt: count (int) "The number of names to return"
    """
    offset = None
    count = None

    if args.offset is not None:
        offset = int(args.offset)

    if args.count is not None:
        count = int(args.count)

    result = get_names_in_namespace(str(args.namespace_id), offset, count)
    return result


def cli_advanced_get_nameops_at( args, config_path=CONFIG_PATH ):
    """
    command: get_nameops_at
    help: Get the list of name operations that occurred at a given block number
    arg: block_id (int) "The block height to query"
    """
    result = get_nameops_at(int(args.block_id))
    return result

