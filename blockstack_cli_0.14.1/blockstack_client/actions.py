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
import blockstack_zones
import blockstack_profiles
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
    is_user_zonefile, \
    list_immutable_data_history, \
    list_update_history, \
    list_zonefile_history, \
    list_accounts, \
    get_account, \
    put_account, \
    delete_account, \
    lookup_snv, \
    put_immutable, \
    put_mutable

from rpc import local_rpc_connect, local_rpc_ensure_running, local_rpc_status, local_rpc_stop
import rpc as local_rpc
import config
from .config import WALLET_PATH, WALLET_PASSWORD_LENGTH, CONFIG_PATH, CONFIG_DIR, configure, FIRST_BLOCK_TIME_UTC, get_utxo_provider_client, set_advanced_mode
from .storage import is_valid_name, is_valid_hash, is_b40

from pybitcoin import is_b58check_address

from binascii import hexlify

from .backend.blockchain import get_balance, is_address_usable, can_receive_name, get_tx_confirmations
from .backend.nameops import estimate_preorder_tx_fee, estimate_register_tx_fee, estimate_update_tx_fee, estimate_transfer_tx_fee, \
                            do_update, estimate_renewal_tx_fee

from .wallet import *
from .utils import pretty_dump, print_result
from .proxy import *
from .client import analytics_event

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


def operation_sanity_check(fqu, payment_privkey, config_path=CONFIG_PATH, transfer_address=None, proxy=None):
    """
    Any update, transfer, renew, or revoke operation
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
        tx_fee = estimate_transfer_tx_fee( fqu, payment_privkey, owner_address, utxo_client, config_path=config_path ) 
    else:
        tx_fee = estimate_update_tx_fee( fqu, payment_privkey, owner_address, utxo_client, config_path=config_path )

    if tx_fee is None:
        return {'error': 'Failed to get fee estimate'}

    balance = get_balance( payment_address, config_path=config_path )

    if balance < tx_fee:
        return {'error': 'Address %s doesn\'t have a sufficient balance (need %s).' % (payment_address, balance)}

    if not is_address_usable(payment_address, config_path=config_path):
        return {'error': 'Address %s has insufficiently confirmed transactions.  Wait and try later.' % payment_address}

    if transfer_address is not None:

        try:
            resp = is_b58check_address(str(transfer_address))
        except:
            return {'error': "Address %s is not a valid Bitcoin address." % transfer_address}

        if not can_receive_name(transfer_address, proxy=proxy):
            return {'error': "Address %s owns too many names already." % transfer_address}

    return {'status': True}


def get_total_registration_fees(name, payment_privkey, owner_address, proxy=None, config_path=CONFIG_PATH):

    try:
        data = get_name_cost(name, proxy=proxy)
    except Exception, e:
        log.exception(e)
        return {'error': 'Could not connect to server'}

    if 'error' in data:
        return {'error': 'Could not determine price of name: %s' % data['error']}

    insufficient_funds = False
    payment_address = pybitcoin.BitcoinPrivateKey(payment_privkey).public_key().address()
    utxo_client = get_utxo_provider_client( config_path=config_path )
    
    # fee stimation: cost of name + cost of preorder transaction + cost of registration transaction + cost of update transaction
    reply = {}
    reply['name_price'] = data['satoshis']

    preorder_tx_fee = estimate_preorder_tx_fee( name, data['satoshis'], payment_address, utxo_client, config_path=config_path )
    if preorder_tx_fee is None:
        preorder_tx_fee = "ERROR: Could not calculate preorder fee:  Insufficient funds in %s" % payment_address
        insufficient_funds = True
    else:
        preorder_tx_fee = int(preorder_tx_fee)

    register_tx_fee = estimate_register_tx_fee( name, payment_address, utxo_client, config_path=config_path )
    if register_tx_fee is None:
        register_tx_fee = "ERROR: Could not calculate register fee:  Insufficient funds in %s" % payment_address
        insufficient_funds = True
    else:
        register_tx_fee = int(register_tx_fee)

    update_tx_fee = estimate_update_tx_fee( name, payment_privkey, owner_address, utxo_client, config_path=config_path )
    if update_tx_fee is None:
        update_tx_fee = "ERROR: Could not calculate update fee:  Insufficient funds in %s" % payment_address
        insufficient_funds = True
    else:
        update_tx_fee = int(update_tx_fee)

    reply['preorder_tx_fee'] = preorder_tx_fee
    reply['register_tx_fee'] = register_tx_fee
    reply['update_tx_fee'] = update_tx_fee

    if not insufficient_funds:
        reply['total_estimated_cost'] = int(reply['name_price']) + reply['preorder_tx_fee'] + reply['register_tx_fee'] + reply['update_tx_fee']

    return reply


def start_rpc_endpoint(config_dir=CONFIG_DIR, password=None, wallet_path=None):
    """
    Decorator that will ensure that the RPC endpoint
    is running before the wrapped function is called.
    Raise on error
    """

    wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    if not wallet_exists(config_dir=config_dir):
        res = initialize_wallet(wallet_path=wallet_path)
        if 'error' in res:
            return res

    rc = local_rpc_ensure_running( config_dir, password=password )
    if not rc:
        return {'error': 'Failed to start RPC endpoint (in working directory %s).\nPlease check your password, and verify that the working directory exists and is writeable.' % config_dir}

    return {'status': True}


def cli_configure( args, config_path=CONFIG_PATH ):
    """
    command: configure
    help: Interactively configure the client
    """

    opts = configure( interactive=True, force=True, config_file=config_path )
    result = {}
    result['path'] = opts['blockstack-client']['path']
    return result


def cli_balance( args, config_path=CONFIG_PATH ):
    """
    command: balance
    help: Get the account balance
    """

    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)
    if not wallet_exists(config_dir=config_dir):
        res = initialize_wallet(wallet_path=wallet_path)
        if 'error' in res:
            return res

    result = {}
    result['total_balance'], result['addresses'] = get_total_balance(wallet_path=wallet_path, config_path=config_path)
    return result


def cli_price( args, config_path=CONFIG_PATH, proxy=None, password=None):
    """
    command: price
    help: Get the price of a name
    arg: name (str) "Name to query"
    """

    if proxy is None:
        proxy = get_default_proxy()

    fqu = str(args.name)
    error = check_valid_name(fqu)
    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    if error:
        return {'error': error}

    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    wallet_keys = get_wallet_keys( config_path, password )
    if 'error' in wallet_keys:
        return wallet_keys

    owner_privkey = wallet_keys['owner_privkey']
    payment_privkey = wallet_keys['payment_privkey']

    owner_address = pybitcoin.BitcoinPrivateKey(owner_privkey).public_key().address()

    # must be available 
    try:
        blockchain_record = get_name_blockchain_record(fqu)
    except socket_error:
        return {'error': 'Error connecting to server.'}

    if 'owner_address' in blockchain_record:
        return {'error': 'Name already registered.'}

    
    payment_address, owner_address, data_pubkey = get_addresses_from_file(config_dir=config_dir, wallet_path=wallet_path)
    fees = get_total_registration_fees( fqu, payment_privkey, owner_address, proxy=proxy, config_path=config_path )
    analytics_event( "Name price", {} )
    return fees


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
    result['addresses'] = get_owner_addresses_and_names(wallet_path)

    return result


def get_server_info( args, config_path=config.CONFIG_PATH, get_local_info=False ):
    """
    Get information about the running server,
    and any pending operations.
    """
    
    config_dir = os.path.dirname(config_path)
    conf = config.get_config(config_path)

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

        if get_local_info:
            # get state of pending names
            res = start_rpc_endpoint(config_dir)
            if 'error' in res:
                return res 

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
                    new_entry['tx_hash'] = entry['tx_hash']
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
    help: Get details about pending name commands
    """
    return get_server_info( args, config_path=config_path, get_local_info=True )


def cli_ping( args, config_path=CONFIG_PATH ):
    """
    command: ping
    help: Check server status and get server details
    """
    return get_server_info( args, config_path=config_path )


def cli_lookup( args, config_path=CONFIG_PATH ):
    """
    command: lookup
    help: Get the zone file and profile for a particular name
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
 

    if 'error' in blockchain_record:
        return blockchain_record

    if 'value_hash' not in blockchain_record:
        return {'error': '%s has no profile' % fqu}

    if blockchain_record.has_key('revoked') and blockchain_record['revoked']:
        return {'error': 'Name is revoked.  Use get_name_blockchain_record for details.'}
    try:
        user_profile, user_zonefile = get_name_profile(str(args.name), name_record=blockchain_record)
        if 'error' in user_zonefile:
            return user_zonefile

        data['profile'] = user_profile
        data['zonefile'] = user_zonefile
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to look up name\n%s' % traceback.format_exc()}

    result = data
    analytics_event( "Name lookup", {} )
    return result 


def cli_whois( args, config_path=CONFIG_PATH ):
    """
    command: whois
    help: Look up the blockchain info for a name
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

    if 'error' in record:
        return record

    else:
        if record.has_key('revoked') and record['revoked']:
            return {'error': 'Name is revoked.  Use get_name_blockchain_record for details.'}

        result['block_preordered_at'] = record['preorder_block_number']
        result['block_renewed_at'] = record['last_renewed']
        result['last_transaction_id'] = record['txid']
        result['owner_address'] = record['address']
        result['owner_script'] = record['sender']

        if not record.has_key('value_hash') or record['value_hash'] in [None, "null", ""]:
            result['has_zonefile'] = False
        else:
            result['has_zonefile'] = True
            result['zonefile_hash'] = record['value_hash']

        if record.has_key('expire_block'):
            result['expire_block'] = record['expire_block']
            result['approx_expiration_date'] = time.strftime( "%Y %b %d %H:%M:%S UTC", time.gmtime(FIRST_BLOCK_TIME_UTC + (record['expire_block'] - FIRST_BLOCK_MAINNET) * 600) )

    analytics_event( "Whois", {} )
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
    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

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
    payment_address = pybitcoin.BitcoinPrivateKey(payment_privkey).public_key().address()
    data_address = pybitcoin.BitcoinPrivateKey(data_privkey).public_key().address()

    fees = get_total_registration_fees(fqu, payment_privkey, owner_address, proxy=proxy, config_path=config_path)
    if 'error' in fees:
        return fees

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
        msg = "Address %s doesn't have enough balance (need %s)." % (payment_address, fees['total_estimated_cost'])
        return {'error': msg}

    if not can_receive_name(owner_address, proxy=proxy):
        msg = "Address %s owns too many names already." % owner_address
        return {'error': msg}

    if not is_address_usable(payment_address, config_path=config_path):
        msg = "Address %s has insufficiently confirmed transactions." % payment_address
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

    analytics_event( "Register name", {"total_estimated_cost": fees['total_estimated_cost']} )
    return result


def cli_update( args, config_path=CONFIG_PATH, password=None ):
    """
    command: update
    help: Set the zone file for a name
    arg: name (str) "The name to update"
    arg: data (str) "A bare zonefile, or a JSON-serialized zonefile."
    """

    config_dir = os.path.dirname(config_path)
    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    fqu = str(args.name)

    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    user_data = str(args.data)
    try:
        user_data = json.loads(user_data)
    except:
        try:
            user_data = blockstack_zones.parse_zone_file(user_data)

            # force dict, not defaultdict
            tmp = {}
            tmp.update(user_data)
            user_data = tmp
        except:
            return {'error': 'Zonefile data is invalid.'}

    # is this a zonefile?
    try:
        user_zonefile = blockstack_zones.make_zone_file(user_data)
    except Exception, e:
        log.exception(e)
        log.error("Invalid zonefile")
        return {'error': 'Invalid zonefile\n%s' % traceback.format_exc()}

    # sanity checks...
    if user_data['$origin'] != fqu:
        return {'error': 'Invalid $origin; must use your name'}

    if not user_data.has_key('$ttl'):
        return {'error': 'Missing $ttl; please supply a positive integer'}

    if not is_user_zonefile(user_data):
        return {'error': 'Zonefile is missing or has invalid URI and/or TXT records'}

    try:
        ttl = int(user_data['$ttl'])
        assert ttl >= 0
    except Exception, e:
        return {'error': 'Invalid $ttl; must be a positive integer'}

    if is_zonefile_current(fqu, user_data):
        msg ="Zonefile data is same as current zonefile; update not needed."
        return {'error': msg}

    # load wallet
    wallet_keys = get_wallet_keys( config_path, password )
    if 'error' in wallet_keys:
        return wallet_keys

    payment_privkey = wallet_keys['payment_privkey']

    res = operation_sanity_check(fqu, payment_privkey, config_path=config_path)
    if 'error' in res:
        return res

    rpc = local_rpc_connect(config_dir=config_dir)

    try:
        resp = rpc.backend_update(fqu, user_data, None, None)
    except Exception, e:
        return {'error': 'Error talking to server, try again.'}

    if 'success' in resp and resp['success']:
        result = resp
    else:
        if 'error' in resp:
            return resp

        if 'message' in resp:
            return {'error': resp['message']}

    analytics_event( "Update name", {} )
    return result


def cli_transfer( args, config_path=CONFIG_PATH, password=None ):
    """
    command: transfer
    help: Transfer a name to a new address
    arg: name (str) "The name to transfer"
    arg: address (str) "The address to receive the name"
    """

    config_dir = os.path.dirname(config_path)
    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    wallet_keys = get_wallet_keys( config_path, password )
    if 'error' in wallet_keys:
        return wallet_keys

    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    # load wallet
    wallet_keys = get_wallet_keys( config_path, password )
    if 'error' in wallet_keys:
        return wallet_keys

    payment_privkey = wallet_keys['payment_privkey']

    transfer_address = str(args.address)
    res = operation_sanity_check(fqu, payment_privkey, transfer_address=transfer_address, config_path=config_path)
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

    analytics_event( "Transfer name", {} )
    return result


def cli_renew( args, config_path=CONFIG_PATH, interactive=True, password=None, proxy=None ):
    """
    command: renew
    help: Renew a name 
    arg: name (str) "The name to renew"
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    config_dir = os.path.dirname(config_path)
    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res


    result = {}
    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error: 
        return {'error': error}

    if not is_name_registered(fqu, proxy=proxy):
        return {'error': '%s does not exist.' % fqu}

    wallet_keys = get_wallet_keys( config_path, password )
    if 'error' in wallet_keys:
        return wallet_keys

    owner_privkey = wallet_keys['owner_privkey']
    payment_privkey = wallet_keys['payment_privkey']
    owner_pubkey = pybitcoin.BitcoinPrivateKey(owner_privkey).public_key().to_hex()
    owner_address = pybitcoin.BitcoinPublicKey(owner_pubkey).address()
    payment_address = pybitcoin.BitcoinPrivateKey(owner_privkey).public_key().address()

    if not is_name_owner(fqu, owner_address, proxy=proxy):
        return {'error': '%s is not in your possession.' % fqu}

    # estimate renewal fees 
    try:
        renewal_fee = get_name_cost(fqu, proxy=proxy)
    except Exception, e:
        log.exception(e)
        return {'error': 'Could not connect to server'}

    if 'error' in renewal_fee:
        return {'error': 'Could not determine price of name: %s' % renewal_fee['error']}

    utxo_client = get_utxo_provider_client( config_path=config_path )
    
    # fee stimation: cost of name + cost of renewal transaction
    payment_pubkey_hex = pybitcoin.BitcoinPrivateKey(payment_privkey).public_key().to_hex()

    name_price = renewal_fee['satoshis']
    renewal_tx_fee = estimate_renewal_tx_fee( fqu, payment_privkey, owner_address, utxo_client, config_path=config_path )
    if renewal_tx_fee is None:
        return {'error': 'Failed to estimate fee'}

    cost = name_price + renewal_tx_fee

    if interactive:
        try:
            cost = name_price + renewal_tx_fee
            input_prompt = "Renewing %s will cost %s BTC." % (fqu, float(cost)/(10**8))
            input_prompt += " Continue? (y/n): "
            user_input = raw_input(input_prompt)
            user_input = user_input.lower()

            if user_input != 'y':
                print "Not renewing."
                exit(0)
        except KeyboardInterrupt:
            print "\nExiting."
            exit(0)

    balance = get_balance( payment_address )
    if balance < cost:
        msg = "Address %s doesn't have enough balance (need %s)." % (payment_address, balance)
        return {'error': msg}

    if not is_address_usable(payment_address, config_path=config_path):
        msg = "Address %s has insufficiently confirmed transactions." % payment_address
        msg += " Wait and try later."
        return {'error': msg}

    rpc = local_rpc_connect( config_dir=config_dir )

    try:
        resp = rpc.backend_renew(fqu, name_price)
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

    analytics_event( "Renew name", {'total_estimated_cost': cost} )
    return result


def cli_revoke( args, config_path=CONFIG_PATH, interactive=True, password=None, proxy=None ):
    """
    command: revoke
    help: Revoke a name 
    arg: name (str) "The name to revoke"
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    config_dir = os.path.dirname(config_path)
    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    result = {}
    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error: 
        return {'error': error}

    if not is_name_registered(fqu, proxy=proxy):
        return {'error': '%s does not exist.' % fqu}

    wallet_keys = get_wallet_keys( config_path, password )
    if 'error' in wallet_keys:
        return wallet_keys

    owner_privkey = wallet_keys['owner_privkey']
    payment_privkey = wallet_keys['payment_privkey']
    owner_pubkey = pybitcoin.BitcoinPrivateKey(owner_privkey).public_key().to_hex()
    owner_address = pybitcoin.BitcoinPublicKey(owner_pubkey).address()
    payment_address = pybitcoin.BitcoinPrivateKey(owner_privkey).public_key().address()

    res = operation_sanity_check(fqu, payment_privkey, config_path=config_path)
    if 'error' in res:
        return res

    if interactive:
        try:
            input_prompt = "==============================\n"
            input_prompt+= "WARNING: THIS CANNOT BE UNDONE\n"
            input_prompt+= "==============================\n"
            input_prompt+= " Are you sure? (y/n): "
            user_input = raw_input(input_prompt)
            user_input = user_input.lower()

            if user_input != 'y':
                print "Not revoking."
                exit(0)

        except KeyboardInterrupt:
            print "\nExiting."
            exit(0)

    rpc = local_rpc_connect( config_dir=config_dir )

    try:
        resp = rpc.backend_revoke(fqu)
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

    analytics_event( "Revoke name", {} )
    return result



def cli_migrate( args, config_path=CONFIG_PATH, password=None, proxy=None, interactive=True, force=False ):
    """
    command: migrate
    help: Migrate a profile to the latest profile format
    arg: name (str) "The name to migrate"
    opt: txid (str) "The transaction ID of a previously-sent but failed migration"
    """

    config_dir = os.path.dirname(config_path)
    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    wallet_keys = get_wallet_keys( config_path, password )
    if 'error' in wallet_keys:
        return wallet_keys

    owner_privkey = wallet_keys['owner_privkey']
    payment_privkey = wallet_keys['payment_privkey']
    owner_pubkey = pybitcoin.BitcoinPrivateKey(owner_privkey).public_key().to_hex()

    res = operation_sanity_check(fqu, payment_privkey, config_path=config_path)
    if 'error' in res:
        return res

    user_zonefile = get_name_zonefile( fqu, proxy=proxy, wallet_keys=wallet_keys )
    if user_zonefile is not None and 'error' not in user_zonefile:
        
        # got a zonefile...
        if is_zonefile_current(fqu, user_zonefile):
            msg ="Zonefile data is same as current zonefile; update not needed."
            return {'error': msg}

        if not blockstack_profiles.is_profile_in_legacy_format( user_zonefile ):
            # maybe this is intentional (like fixing a corrupt zonefile)
            # ask if so
            if interactive:
                pass

            else:
                if not force:
                    msg = "Not a legacy profile; cannot migrate."
                    return {'error': msg}
                else:
                    # do it anyway
                    pass
                    

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

    analytics_event( "Migrate name", {} )
    return result


def cli_set_advanced_mode( args, config_path=CONFIG_PATH ):
    """
    command: set_advanced_mode
    help: Enable advanced commands
    arg: status (str) "On or Off."
    """

    status = str(args.status).lower()
    if status not in ['on', 'off']:
        return {'error': 'Invalid option; please use "on" or "off"'}

    if status == 'on':
        set_advanced_mode(True, config_path=config_path)
    else:
        set_advanced_mode(False, config_path=config_path)

    return {'status': True}


def cli_advanced_import_wallet( args, config_path=CONFIG_PATH, password=None, force=False ):
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
                res = start_rpc_endpoint(config_dir, password=password)
                if 'error' in res:
                    return res

            return {'status': True}

    else:
        return {'error': 'Wallet already exists!', 'message': 'Back up or remove current wallet first: %s' % wallet_path}



def cli_advanced_list_accounts( args, proxy=None, config_path=CONFIG_PATH, password=None ):
    """
    command: list_accounts
    help: List the set of accounts associated with a name.
    arg: name (str) "The name to query."
    """ 

    result = {}
    config_dir = os.path.dirname(config_path)
    res = start_rpc_endpoint(config_dir, password=password)
    if 'error 'in res:
        return res

    wallet_keys = get_wallet_keys( config_path, password )
    if 'error' in wallet_keys:
        return wallet_keys
    
    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    result = list_accounts( args.name, proxy=proxy, wallet_keys=wallet_keys )
    if 'error' not in result:
        analytics_event( "List accounts", {} )

    return result
   

def cli_advanced_get_account( args, proxy=None, config_path=CONFIG_PATH, password=None ):
    """
    command: get_account
    help: Get a particular account from a name.
    arg: name (str) "The name to query."
    arg: service (str) "The service for which this account was created."
    arg: identifier (str) "The name of the account."
    """

    result = {}
    config_dir = os.path.dirname(config_path)
    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    if not is_valid_name(args.name) or len(args.service) == 0 or len(args.identifier) == 0:
        return {'error': 'Invalid name or identifier'}

    wallet_keys = get_wallet_keys( config_path, password )
    if 'error' in wallet_keys:
        return wallet_keys
    
    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    result = get_account( args.name, args.service, args.identifier, proxy=proxy, wallet_keys=wallet_keys )
    if 'error' not in result:
        analytics_event( "Get account", {} )

    return result
    

def cli_advanced_put_account( args, proxy=None, config_path=CONFIG_PATH, password=None, required_drivers=None ):
    """
    command: put_account
    help: Set a particular account's details.  If the account already exists, it will be overwritten.
    arg: name (str) "The name to query."
    arg: service (str) "The service this account is for."
    arg: identifier (str) "The name of the account."
    arg: content_url (str) "The URL that points to external contact data."
    opt: extra_data (str) "A comma-separated list of 'name1=value1,name2=value2,name3=value3...' with any extra account information you need in the account."
    """

    result = {}
    config_dir = os.path.dirname(config_path)
    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res


    wallet_keys = get_wallet_keys( config_path, password )
    if 'error' in wallet_keys:
        return wallet_keys
    
    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    if not is_valid_name(args.name):
        return {'error': 'Invalid name'}

    if len(args.service) == 0 or len(args.identifier) == 0 or len(args.content_url) == 0:
        return {'error': 'Invalid data'}

    # parse extra data 
    extra_data = {}
    if hasattr(args, "extra_data") and args.extra_data is not None:
        extra_data_str = str(args.extra_data)
        if len(extra_data_str) > 0:
            extra_data_pairs = extra_data_str.split(",")
            for p in extra_data_pairs:
                if '=' not in p:
                    return {'error': "Could not interpret '%s' in '%s'" % (p, extra_data_str)}

                parts = p.split("=")
                k = parts[0]
                v = "=".join(parts[1:])
                extra_data[k] = v

    result = put_account( args.name, args.service, args.identifier, args.content_url, proxy=proxy, wallet_keys=wallet_keys, required_drivers=required_drivers, **extra_data )
    if 'error' not in result:
        analytics_event( "Put account", {} )

    return result


def cli_advanced_delete_account( args, proxy=None, config_path=CONFIG_PATH, password=None ):
    """
    command: delete_account
    help: Delete a particular account.
    arg: name (str) "The name to query."
    arg: service (str) "The service the account is for."
    arg: identifier (str) "The identifier of the account to delete."
    """

    result = {}
    config_dir = os.path.dirname(config_path)
    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    if not is_valid_name(args.name) or len(args.service) == 0 or len(args.identifier) == 0:
        return {'error': 'Invalid name or identifier'}

    wallet_keys = get_wallet_keys( config_path, password )
    if 'error' in wallet_keys:
        return wallet_keys
    
    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    result = delete_account( args.name, args.service, args.identifier, proxy=proxy, wallet_keys=wallet_keys )
    if 'error' not in result:
        analytics_event( "Delete account", {} )

    return result


def cli_advanced_wallet( args, config_path=CONFIG_PATH, password=None ):
    """
    command: wallet
    help: Query wallet information
    """
    
    result = {}
    config_dir = os.path.dirname(config_path)
    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

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
    res = start_rpc_endpoint(config_dir)
    if 'error' in res:
        return res

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
    res = start_rpc_endpoint(config_dir)
    if 'error' in res:
        return res

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


def cli_advanced_set_zonefile_hash( args, config_path=CONFIG_PATH, password=None ):
    """
    command: set_zonefile_hash
    help: Directly set the hash associated with the name in the blockchain.
    arg: name (str) "The name to update"
    arg: zonefile_hash (str) "The RIPEMD160(SHA256(zonefile)) hash"
    """
    config_dir = os.path.dirname(config_path)
    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    fqu = str(args.name)

    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    zonefile_hash = str(args.zonefile_hash)
    if re.match(r"^[a-fA-F0-9]+$", zonefile_hash ) is None or len(zonefile_hash) != 40:
        return {'error': 'Not a valid zonefile hash'}
    
    wallet_keys = get_wallet_keys( config_path, password )
    if 'error' in wallet_keys:
        return wallet_keys

    owner_privkey = wallet_keys['owner_privkey']
    payment_privkey = wallet_keys['payment_privkey']
    owner_pubkey = pybitcoin.BitcoinPrivateKey(owner_privkey).public_key().to_hex()

    res = operation_sanity_check(fqu, payment_privkey, config_path=config_path)
    if 'error' in res:
        return res

    rpc = local_rpc_connect(config_dir=config_dir)

    try:
        resp = rpc.backend_update(fqu, None, None, zonefile_hash)
    except Exception, e:
        log.exception(e)
        return {'error': 'Error talking to server, try again.'}

    if 'success' in resp and resp['success']:
        result = resp
    else:
        if 'error' in resp:
            return resp

        if 'message' in resp:
            return {'error': resp['message']}

    analytics_event( "Set zonefile hash", {} )
    return result

