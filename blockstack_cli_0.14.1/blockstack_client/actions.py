#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

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

CLI-accessible begin with `cli_`.  For exmample, "blockstack transfer ..."
will cause `cli_transfer(...)` to be called.

The following conventions apply to `cli_` methods here:
* Each will always take a Namespace (from ArgumentParser.parse_known_args())
as its first argument.
* Each will return a dict with the requested information.  The key 'error'
will be set to indicate an error condition.

If you want to add a new command-line action, implement it here.  This
will make it available not only via the command-line, but also via the
local RPC interface and the test suite.

Use the _cli_skel method below a template to create new functions.
"""

import sys
import json
import traceback
import os
import re
import errno
import virtualchain
from socket import error as socket_error
import time
import blockstack_zones
import blockstack_profiles
import requests
import base64
import jsonschema
from decimal import Decimal

requests.packages.urllib3.disable_warnings()

import logging
logging.disable(logging.CRITICAL)

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + '/../')

sys.path.insert(0, parent_dir)

from blockstack_client import (
    delete_immutable, delete_mutable, get_all_names, get_consensus_at,
    get_immutable, get_immutable_by_name, get_mutable, get_name_blockchain_record,
    get_name_cost, get_name_profile, get_user_profile, get_name_zonefile,
    get_nameops_at, get_names_in_namespace, get_names_owned_by_address,
    get_namespace_blockchain_record, get_namespace_cost,
    is_user_zonefile, list_immutable_data_history, list_update_history,
    list_zonefile_history, lookup_snv, put_immutable, put_mutable, zonefile_data_replicate
)

from blockstack_client.profile import put_profile, delete_profile

from rpc import local_rpc_connect, local_rpc_status, local_rpc_stop, start_rpc_endpoint
import rpc as local_rpc
import config

from .config import configure_zonefile, set_advanced_mode, configure, get_utxo_provider_client 
from .constants import (
    CONFIG_PATH, CONFIG_DIR, FIRST_BLOCK_TIME_UTC,
    APPROX_PREORDER_TX_LEN, APPROX_REGISTER_TX_LEN,
    APPROX_UPDATE_TX_LEN, APPROX_TRANSFER_TX_LEN,
    FIRST_BLOCK_MAINNET, NAME_UPDATE,
    BLOCKSTACK_DEBUG, BLOCKSTACK_TEST
)

from .b40 import is_b40
from .storage import get_drivers_for_url, get_driver_urls, get_storage_handlers

from pybitcoin import is_b58check_address

from .backend.blockchain import (
    get_balance, is_address_usable,
    can_receive_name, get_tx_confirmations, get_tx_fee
)

from .backend.nameops import (
    estimate_preorder_tx_fee, estimate_register_tx_fee,
    estimate_update_tx_fee, estimate_transfer_tx_fee,
    estimate_renewal_tx_fee
)

from .backend.queue import queuedb_remove, queuedb_find
from .backend.queue import extract_entry as queue_extract_entry

from .wallet import *
from .keys import *
from .proxy import *
from .client import analytics_event
from .scripts import UTXOException, is_name_valid
from .user import add_user_zonefile_url, remove_user_zonefile_url, user_zonefile_urls, \
        user_zonefile_data_pubkey, user_load, user_store, user_delete, users_list, user_init, \
        user_get_privkey

from .zonefile import make_empty_zonefile, url_to_uri_record

from .utils import exit_with_error, satoshis_to_btc
from .app import app_publish, app_make_resource_data_id, app_get_config, app_get_resource, \
        app_get_index_file, app_put_resource, app_account_get_privkey, app_load_account, app_make_account, \
        app_accounts_list, app_delete_account, app_store_account, app_account_name, app_account_parse_name, \
        app_account_datastore_name, app_account_parse_datastore_name, app_find_accounts

from .data import datastore_mkdir, datastore_rmdir, make_datastore, get_datastore, put_datastore, delete_datastore, \
        datastore_getfile, datastore_putfile, datastore_deletefile, datastore_listdir, datastore_stat, datastore_list, \
        datastore_rmtree

from .schemas import OP_URLENCODED_PATTERN, OP_NAME_PATTERN, OP_USER_ID_PATTERN

log = config.get_logger()


"""
The _cli_skel method is provided as a template for developers of
cli_ methods.

NOTE: extra cli arguments may be included in function params

NOTE: $NAME_OF_COMMAND must not have embedded whitespaces.

NOTE: As a security precaution, a cli_ function is not accessible
NOTE: via RPC by default. It has to be enabled explicitly. See below.

NOTE: If the "rpc" pragma is present, then the method will be
NOTE: accessible via the RPC interface of the background process

NOTE: Help string in arg and opt must be enclosed in single quotes.

The entire docstr must strictly adhere to this convention:
    command: $NAME_OF_COMMAND [rpc]
    help: $HELP_STRING
    arg: $ARG_NAME ($ARG_TYPE) '$ARG_HELP'
    arg: $ARG_NAME ($ARG_TYPE) '$ARG_HELP'
    opt: $OPT_ARG_NAME ($OPT_ARG_TYPE) '$OPT_ARG_HELP'
    opt: $OPT_ARG_NAME ($OPT_ARG_TYPE) '$OPT_ARG_HELP'
"""


def _cli_skel(args, config_path=CONFIG_PATH):
    """
    command: skel
    help: Skeleton cli function - developer template
    arg: foo (str) 'A required argument - foo'
    opt: bar (int) 'An optional argument - bar'
    """

    result = {}

    # update result as needed

    if 'error' in result:
        # ensure meaningful error message
        result['error'] = 'Error generating skel'
        return result

    # continue processing the result

    return result


def check_valid_name(fqu):
    """
    Verify that a name is valid.
    Return None on success
    Return an error string on error
    """

    rc = is_name_valid(fqu)
    if rc:
        return None

    # get a coherent reason why
    if '.' not in fqu:
        msg = (
            'The name specified is invalid. '
            'Names must end with a period followed by a valid TLD.'
        )

        return msg

    name = fqu.split('.')[0]

    if not name:
        msg = (
            'The name specified is invalid. '
            'Names must be at least one character long, not including the TLD.'
        )

        return msg

    if not is_b40(name):
        msg = (
            'The name specified is invalid. '
            'Names may only contain alphanumeric characters, '
            'dashes, and underscores.'
        )

        return msg

    return 'The name is invalid'


def operation_sanity_check(fqu, payment_privkey_info, owner_privkey_info,
                           config_path=CONFIG_PATH, transfer_address=None, proxy=None):
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
        return {'error': '{} is not registered yet.'.format(fqu)}

    utxo_client = get_utxo_provider_client(config_path=config_path)
    payment_address, owner_address, data_address = (
        get_addresses_from_file(wallet_path=wallet_path)
    )

    if not is_name_owner(fqu, owner_address, proxy=proxy):
        return {'error': '{} is not in your possession.'.format(fqu)}

    owner_privkey_params = get_privkey_info_params(owner_privkey_info)

    estimate_func = None

    # get tx fee
    if transfer_address is not None:
        estimate_func = estimate_transfer_tx_fee
        approx_tx = '00' * APPROX_TRANSFER_TX_LEN
    else:
        estimate_func = estimate_update_tx_fee
        approx_tx = '00' * APPROX_UPDATE_TX_LEN

    tx_fee = estimate_func(
        fqu, payment_privkey_info, owner_address, utxo_client,
        owner_privkey_params=owner_privkey_params,
        config_path=config_path, include_dust=True
    )

    if tx_fee is None:
        # do our best
        tx_fee = get_tx_fee(approx_tx, config_path=config_path)

    if tx_fee is None:
        return {'error': 'Failed to get fee estimate'}

    balance = get_balance(payment_address, config_path=config_path)
    if balance is None:
        msg = 'Failed to get balance'
        return {'error': msg}

    if balance < tx_fee:
        msg = 'Address {} does not have a sufficient balance (need {}, have {}).'
        return {'error': msg.format(payment_address, balance, tx_fee)}

    if not is_address_usable(payment_address, config_path=config_path):
        msg = 'Address {} has insufficiently confirmed transactions. Wait and try later.'
        return {'error': msg.format(payment_address)}

    if transfer_address is None:
        return {'status': True}

    try:
        is_b58check_address(str(transfer_address))
    except:
        msg = 'Address {} is not a valid Bitcoin address.'
        return {'error': msg.format(transfer_address)}

    if not can_receive_name(transfer_address, proxy=proxy):
        msg = 'Address {} owns too many names already.'
        return {'error': msg.format(transfer_address)}

    return {'status': True}


def get_total_registration_fees(name, payment_privkey_info, owner_privkey_info,
                                proxy=None, config_path=CONFIG_PATH, payment_address=None):
    """
    Get all fees associated with registrations.
    Returned values are in satoshis.
    """
    try:
        data = get_name_cost(name, proxy=proxy)
    except Exception as e:
        log.exception(e)
        return {'error': 'Could not connect to server'}

    if 'error' in data:
        msg = 'Could not determine price of name: {}'
        return {'error': msg.format(data['error'])}

    insufficient_funds, owner_address, payment_address = False, None, None

    if payment_privkey_info is not None:
        payment_address = get_privkey_info_address(payment_privkey_info)

    if owner_privkey_info is not None:
        owner_address = get_privkey_info_address(owner_privkey_info)

    utxo_client = get_utxo_provider_client(config_path=config_path)

    # fee estimation: cost of name + cost of preorder transaction +
    # fee estimation: cost of registration transaction + cost of update transaction

    reply = {}
    reply['name_price'] = data['satoshis']

    preorder_tx_fee, register_tx_fee, update_tx_fee = None, None, None

    try:
        owner_privkey_params = get_privkey_info_params(owner_privkey_info)

        preorder_tx_fee = estimate_preorder_tx_fee(
            name, data['satoshis'], payment_address, utxo_client,
            owner_privkey_params=owner_privkey_params,
            config_path=config_path, include_dust=True
        )

        if preorder_tx_fee is not None:
            preorder_tx_fee = int(preorder_tx_fee)
        else:
            # do our best
            preorder_tx_fee = get_tx_fee('00' * APPROX_PREORDER_TX_LEN, config_path=config_path)
            insufficient_funds = True

        register_tx_fee = estimate_register_tx_fee(
            name, payment_address, utxo_client,
            owner_privkey_params=owner_privkey_params,
            config_path=config_path, include_dust=True
        )

        if register_tx_fee is not None:
            register_tx_fee = int(register_tx_fee)
        else:
            register_tx_fee = get_tx_fee('00' * APPROX_REGISTER_TX_LEN, config_path=config_path)
            insufficient_funds = True

        update_tx_fee = estimate_update_tx_fee(
            name, payment_privkey_info, owner_address, utxo_client,
            owner_privkey_params=owner_privkey_params,
            config_path=config_path, payment_address=payment_address, include_dust=True
        )

        if update_tx_fee is not None:
            update_tx_fee = int(update_tx_fee)
        else:
            update_tx_fee = get_tx_fee('00' * APPROX_UPDATE_TX_LEN, config_path=config_path)
            insufficient_funds = True
    except UTXOException as ue:
        log.error('Failed to query UTXO provider.')
        if BLOCKSTACK_DEBUG is not None:
            log.exception(ue)

        return {'error': 'Failed to query UTXO provider.  Please try again.'}

    reply['preorder_tx_fee'] = int(preorder_tx_fee)
    reply['register_tx_fee'] = int(register_tx_fee)
    reply['update_tx_fee'] = int(update_tx_fee)

    reply['total_estimated_cost'] = sum((
        int(reply['name_price']),
        reply['preorder_tx_fee'],
        reply['register_tx_fee'],
        reply['update_tx_fee']
    ))

    if insufficient_funds and payment_privkey_info is not None:
        reply['warnings'] = ['Insufficient funds; fees are rough estimates.']

    if payment_privkey_info is None:
        reply.setdefault('warnings', [])
        reply['warnings'].append('Wallet not accessed; fees are rough estimates.')

    return reply


def wallet_ensure_exists(config_dir=CONFIG_DIR, password=None, wallet_path=None):
    """
    Ensure that the wallet exists and is initialized
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    if not wallet_exists(config_dir=config_dir):
        res = initialize_wallet(wallet_path=wallet_path, password=password)
        if 'error' in res:
            return res

    return {'status': True}


def load_zonefile(fqu, zonefile_data, check_current=True):
    """
    Load a zonefile from a string, which can be
    either JSON or text.  Verify that it is
    well-formed and current.

    Return {'status': True, 'zonefile': the serialized zonefile data (as a string)} on success.
    Return {'error': ...} on error
    Return {'error': ..., 'identical': True, 'zonefile': serialized zonefile string} if the zonefile is identical
    """

    user_data = str(zonefile_data)
    user_zonefile = None
    try:
        user_data = json.loads(user_data)
    except:
        log.debug('Zonefile is not a serialized JSON string; try parsing as text')
        try:
            user_data = blockstack_zones.parse_zone_file(user_data)
            user_data = dict(user_data)  # force dict. e.g if not defaultdict
        except Exception as e:
            if BLOCKSTACK_TEST is not None:
                log.exception(e)

            return {'error': 'Zonefile data is invalid.'}

    # is this a zonefile?
    try:
        user_zonefile = blockstack_zones.make_zone_file(user_data)
    except Exception as e:
        log.exception(e)
        log.error('Invalid zonefile')
        return {'error': 'Invalid zonefile\n{}'.format(traceback.format_exc())}

    # sanity checks...
    if fqu != user_data.get('$origin', ''):
        log.error('Zonefile is missing or has invalid $origin')
        return {'error': 'Invalid $origin; must use your name'}

    if '$ttl' not in user_data:
        log.error('Zonefile is missing a TTL')
        return {'error': 'Missing $ttl; please supply a positive integer'}

    if not is_user_zonefile(user_data):
        log.error('Zonefile is non-standard')
        return {'error': 'Zonefile is missing or has invalid URI and/or TXT records'}

    try:
        ttl = int(user_data['$ttl'])
        assert ttl >= 0
    except Exception as e:
        return {'error': 'Invalid $ttl; must be a positive integer'}

    if check_current and is_zonefile_current(fqu, user_data):
        msg = 'Zonefile data is same as current zonefile; update not needed.'
        log.error(msg)
        return {'error': msg, 'identical': True, 'zonefile': user_zonefile}

    return {'status': True, 'zonefile': user_zonefile}


def cli_configure(args, config_path=CONFIG_PATH):
    """
    command: configure
    help: Interactively configure the client
    """

    opts = configure(interactive=True, force=True, config_file=config_path)
    result = {}
    result['path'] = opts['blockstack-client']['path']

    return result


def cli_balance(args, config_path=CONFIG_PATH):
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
    addresses = []
    satoshis = 0
    satoshis, addresses = get_total_balance(wallet_path=wallet_path, config_path=config_path)

    if satoshis is None:
        log.error('Failed to get balance')
        # contains error
        return addresses

    # convert to BTC
    btc = float(Decimal(satoshis / 1e8))

    for address_info in addresses:
        address_info['bitcoin'] = float(Decimal(address_info['balance'] / 1e8))
        address_info['satoshis'] = address_info['balance']
        del address_info['balance']

    result = {
        'total_balance': {
            'satoshis': int(satoshis),
            'bitcoin': btc
        },
        'addresses': addresses
    }

    return result


def cli_price(args, config_path=CONFIG_PATH, proxy=None, password=None):
    """
    command: price
    help: Get the price of a name
    arg: name (str) 'Name to query'
    """

    proxy = get_default_proxy() if proxy is None else proxy

    fqu = str(args.name)
    error = check_valid_name(fqu)
    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    payment_privkey_info, owner_privkey_info = None, None
    payment_address, owner_address = None, None

    if error:
        return {'error': error}

    payment_address, owner_address, data_pubkey = (
        get_addresses_from_file(config_dir=config_dir, wallet_path=wallet_path)
    )

    if local_rpc_status(config_dir=config_dir):
        try:
            wallet_keys = get_wallet_keys(config_path, password)
            if 'error' in wallet_keys:
                return wallet_keys

            payment_privkey_info = wallet_keys['payment_privkey']
            owner_privkey_info = wallet_keys['owner_privkey']
        except (OSError, IOError) as e:
            # backend is not running; estimate with addresses
            if BLOCKSTACK_DEBUG is not None:
                log.exception(e)

    # must be available
    try:
        blockchain_record = get_name_blockchain_record(fqu)
    except socket_error:
        return {'error': 'Error connecting to server.'}

    if 'owner_address' in blockchain_record:
        return {'error': 'Name already registered.'}

    fees = get_total_registration_fees(
        fqu, payment_privkey_info, owner_privkey_info, proxy=proxy,
        config_path=config_path, payment_address=payment_address
    )

    analytics_event('Name price', {})

    if 'error' in fees:
        return fees

    # convert to BTC
    btc_keys = [
        'preorder_tx_fee', 'register_tx_fee',
        'update_tx_fee', 'total_estimated_cost',
        'name_price'
    ]

    for k in btc_keys:
        v = {
            'satoshis': '{}'.format(fees[k]),
            'btc': '{}'.format(satoshis_to_btc(fees[k]))
        }
        fees[k] = v

    return fees


def cli_deposit(args, config_path=CONFIG_PATH):
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
    result['address'], owner_address, data_address = (
        get_addresses_from_file(wallet_path=wallet_path)
    )

    return result


def cli_import(args, config_path=CONFIG_PATH):
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
    result['message'] = (
        'Send the name you want to receive to the address specified.'
    )

    payment_address, result['address'], data_address = (
        get_addresses_from_file(wallet_path=wallet_path)
    )

    return result


def cli_names(args, config_path=CONFIG_DIR):
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


def cli_get_registrar_info(args, config_path=CONFIG_PATH, queues=None):
    """
    command: get_registrar_info advanced
    help: Get information about the backend registrar queues
    """

    queues = ['preorder', 'register', 'update', 'transfer', 'renew', 'revoke'] if queues is None else queues
    config_dir = os.path.dirname(config_path)
    conf = config.get_config(config_path)

    # connect to backend thread
    rpc = local_rpc_connect(config_dir=config_dir)
    if rpc is None:
        return {'error': 'Failed to connect to RPC endpoint'}

    current_state = json.loads(rpc.backend_state(conf['rpc_token']))

    queue_types = dict( [(queue_name, []) for queue_name in queues] )

    def format_queue_entry(entry):
        """
        Determine data to display
        """
        new_entry = {}
        new_entry['name'] = entry['fqu']

        confirmations = get_tx_confirmations(
            entry['tx_hash'], config_path=config_path
        )

        confirmations = 0 if confirmations is None else confirmations

        new_entry['confirmations'] = confirmations
        new_entry['tx_hash'] = entry['tx_hash']

        return new_entry

    def remove_dups(preorder_queue, register_queue):
        """
        Omit duplicates between preorder and register queue
        """
        for entry in register_queue:
            name = entry['name']
            for check_entry in preorder_queue:
                if check_entry['name'] == name:
                    preorder_queue.remove(check_entry)

    # extract entries
    for entry in current_state:
        entry_type = entry['type']
        if entry_type not in queue_types:
            log.error('Unknown entry type "{}"'.format(entry_type))
            continue

        queue_types[entry['type']].append(format_queue_entry(entry))

    # clean up duplicates
    remove_dups(queue_types['preorder'], queue_types['register'])

    # remove empty entries
    ret = {}
    for queue_type in queue_types:
        if queue_types[queue_type]:
            ret[queue_type] = queue_types[queue_type]

    return ret


def get_server_info(config_path=CONFIG_PATH, get_local_info=False):
    """
    Get information about the running server,
    and any pending operations.
    """

    config_dir = os.path.dirname(config_path)
    conf = config.get_config(config_path)

    resp = getinfo()
    result = {}

    result['cli_version'] = VERSION
    result['advanced_mode'] = conf['advanced_mode']

    if 'error' in resp:
        result['server_alive'] = False
        result['server_error'] = resp['error']
        return result

    result['server_alive'] = True

    result['server_host'] = (
        resp.get('server_host') or
        conf.get('server')
    )

    result['server_port'] = (
        resp.get('server_port') or
        int(conf.get('port'))
    )

    result['server_version'] = (
        resp.get('server_version') or
        resp.get('blockstack_version') or
        resp.get('blockstore_version')
    )

    if result['server_version'] is None:
        raise Exception('Missing server version')

    result['last_block_processed'] = (
        resp.get('last_block_processed') or
        resp.get('last_block') or
        resp.get('blocks')
    )

    if result['last_block_processed'] is None:
        raise Exception('Missing height of block last processed')

    result['last_block_seen'] = (
        resp.get('last_block_seen') or
        resp.get('blockchain_blocks') or
        resp.get('bitcoind_blocks')
    )

    if result['last_block_seen'] is None:
        raise Exception('Missing height of last block seen')

    try:
        result['consensus_hash'] = resp['consensus']
    except KeyError:
        raise Exception('Missing consensus hash')

    if not get_local_info:
        return result

    # get state of pending names
    res = wallet_ensure_exists(config_dir)
    if 'error' in res:
        return res

    res = start_rpc_endpoint(config_dir)
    if 'error' in res:
        return res

    queue_info = cli_get_registrar_info(None, config_path=config_path)
    if len(queue_info.keys()) > 0:
        result['queues'] = queue_info

    return result


def cli_info(args, config_path=CONFIG_PATH):
    """
    command: info
    help: Get details about pending name commands
    """
    return get_server_info(config_path=config_path, get_local_info=True)


def cli_ping(args, config_path=CONFIG_PATH):
    """
    command: ping
    help: Check server status and get server details
    """
    return get_server_info(config_path=config_path)


def cli_lookup(args, config_path=CONFIG_PATH):
    """
    command: lookup
    help: Get the zone file and profile for a particular name
    arg: name (str) 'The name to look up'
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
        return {'error': '{} has no profile'.format(fqu)}

    if blockchain_record.get('revoked', False):
        msg = 'Name is revoked. Use get_name_blockchain_record for details.'
        return {'error': msg}

    try:
        user_profile, user_zonefile = get_name_profile(
            str(args.name), name_record=blockchain_record, include_raw_zonefile=True, use_legacy=True, use_legacy_zonefile=True
        )

        if isinstance(user_zonefile, dict) and 'error' in user_zonefile:
            return user_zonefile

        data['profile'] = user_profile
        data['zonefile'] = user_zonefile['raw_zonefile']
    except Exception as e:
        log.exception(e)
        msg = 'Failed to look up name\n{}'
        return {'error': msg.format(traceback.format_exc())}

    result = data
    analytics_event('Name lookup', {})

    return result


def cli_whois(args, config_path=CONFIG_PATH):
    """
    command: whois
    help: Look up the blockchain info for a name
    arg: name (str) 'The name to look up'
    """
    result = {}

    record, fqu = None, str(args.name)

    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    try:
        record = get_name_blockchain_record(fqu)
    except socket_error:
        exit_with_error('Error connecting to server.')

    if 'error' in record:
        return record

    if record.get('revoked', False):
        msg = 'Name is revoked. Use get_name_blockchain_record for details.'
        return {'error': msg}

    history = record.get('history', {})
    update_heights = []
    try:
        assert isinstance(history, dict)

        # all items must be ints
        update_heights = sorted(int(_) for _ in history)
    except (AssertionError, ValueError):
        return {'error': 'Invalid record data returned'}

    result['block_preordered_at'] = record['preorder_block_number']
    result['block_renewed_at'] = record['last_renewed']
    result['last_transaction_id'] = record['txid']
    result['owner_address'] = record['address']
    result['owner_script'] = record['sender']
    
    value_hash = record.get('value_hash', None)
    if value_hash in [None, 'null', '']:
        result['has_zonefile'] = False
    else:
        result['has_zonefile'] = True
        result['zonefile_hash'] = value_hash

    if update_heights:
        result['last_transaction_height'] = update_heights[-1]

    expire_block = record.get('expired_block', None)
    if expire_block is not None:
        result['expire_block'] = expire_block

    analytics_event('Whois', {})

    return result


def get_wallet_with_backoff(config_path):
    """
    Get the wallet, but keep trying
    in the case of a ECONNREFUSED
    (i.e. the API daemon could still be initializing)

    Return the wallet keys on success (as a dict)
    return {'error': ...} on error
    """

    wallet_keys = None
    i = 0
    for i in range(3):
        try:
            wallet_keys = get_wallet(config_path=config_path)
            return wallet_keys
        except (IOError, OSError) as se:
            if se.errno == errno.ECONNREFUSED:
                # still spinning up
                log.debug("Still spinning up")
                time.sleep(i + 1)
                continue

            raise

    if i == 3:
        log.error('Failed to get_wallet')
        wallet_keys = {'error': 'Failed to connect to API daemon'}

    return wallet_keys


def get_wallet_keys(config_path, password):
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

    if not is_wallet_unlocked(config_dir=config_dir):
        log.debug('unlocking wallet ({})'.format(config_dir))
        res = unlock_wallet(config_dir=config_dir, password=password)
        if 'error' in res:
            log.error('unlock_wallet: {}'.format(res['error']))
            return res

    return get_wallet_with_backoff(config_path)


def prompt_invalid_zonefile():
    """
    Prompt the user whether or not to replicate
    an invalid zonefile
    """
    warning_str = (
        '\nWARNING!  This zone file data does not look like a zone file.\n'
        'If you proceed to use this data, no one will be able to look\n'
        'up your profile.\n\n'
        'Proceed? (y/N): '
    )
    proceed = raw_input(warning_str)
    return proceed.lower() in ['y']


def prompt_transfer( new_owner_address ):
    """
    Prompt the user whether or not to replicate
    an invalid zonefile
    """
    warning_str = (
        '\nWARNING!  This will transfer your name to a different owner.\n'
        'The recipient\'s address will be: {}\n.'
        'THIS CANNOT BE UNDONE OR CANCELED.\n'
        '\n'
        'Proceed? (y/N): '
    )
    proceed = raw_input(warning_str.format(new_owner_address))
    return proceed.lower() in ['y']


def is_valid_path(path):
    """
    Is the given string a valid path?
    """
    if not isinstance(path, str):
        return False

    return '\x00' not in path


def cli_register(args, config_path=CONFIG_PATH,
                 interactive=True, password=None, proxy=None):
    """
    command: register
    help: Register a name
    arg: name (str) 'The name to register'
    """

    proxy = get_default_proxy(config_path) if proxy is None else proxy

    conf = config.get_config(config_path)
    assert conf 

    config_dir = os.path.dirname(config_path)
    res = wallet_ensure_exists(config_dir)
    if 'error' in res:
        return res

    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    result = {}
    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    if is_name_registered(fqu, proxy=proxy):
        return {'error': '{} is already registered.'.format(fqu)}

    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    owner_privkey_info = wallet_keys['owner_privkey']
    payment_privkey_info = wallet_keys['payment_privkey']

    owner_address = get_privkey_info_address(owner_privkey_info)
    payment_address = get_privkey_info_address(payment_privkey_info)

    fees = get_total_registration_fees(
        fqu, payment_privkey_info, owner_privkey_info,
        proxy=proxy, config_path=config_path
    )

    if 'error' in fees:
        return fees

    if interactive:
        try:
            cost = fees['total_estimated_cost']
            input_prompt = (
                'Registering {} will cost {} BTC.\n'
                'The entire process takes 30 confirmations, or about 5 hours.\n'
                'You need to have Internet access during this time period, so\n'
                'this program can send the right transactions at the right\n'
                'times.\n\n'
                'Continue? (y/N): '
            )
            input_prompt = input_prompt.format(fqu, satoshis_to_btc(cost))
            user_input = raw_input(input_prompt)
            user_input = user_input.lower()

            if user_input.lower() != 'y':
                print('Not registering.')
                exit(0)
        except KeyboardInterrupt:
            print('\nExiting.')
            exit(0)

    balance = get_balance(payment_address, config_path=config_path)
    if balance is None:
        msg = 'Failed to get balance'
        return {'error': msg}

    if balance < fees['total_estimated_cost']:
        msg = 'Address {} does not have enough balance (need {}, have {}).'
        msg = msg.format(payment_address, fees['total_estimated_cost'], balance)
        return {'error': msg}

    if not can_receive_name(owner_address, proxy=proxy):
        msg = 'Address {} owns too many names already.'.format(owner_address)
        return {'error': msg}

    if not is_address_usable(payment_address, config_path=config_path):
        msg = (
            'Address {} has insufficiently confirmed transactions. '
            'Wait and try later.'
        )
        msg = msg.format(payment_address)
        return {'error': msg}

    rpc = local_rpc_connect(config_dir=config_dir)

    try:
        resp = rpc.backend_preorder(conf['rpc_token'], fqu)
    except:
        return {'error': 'Error talking to server, try again.'}

    total_estimated_cost = {'total_estimated_cost': fees['total_estimated_cost']}

    if 'success' in resp and resp['success']:
        result = resp
        analytics_event('Register name', total_estimated_cost)
        return result

    if 'error' in resp:
        log.debug('RPC error: {}'.format(resp['error']))
        return resp

    if 'message' in resp:
        return {'error': resp['message']}

    analytics_event('Register name', total_estimated_cost)

    return result


def cli_update(args, config_path=CONFIG_PATH, password=None,
               interactive=True, proxy=None, nonstandard=False,
               force_data=False):

    """
    command: update
    help: Set the zone file for a name
    arg: name (str) 'The name to update'
    arg: data (str) 'A zone file string, or a path to a file with the data.'
    opt: nonstandard (str) 'If true, then do not validate or parse the zonefile.'
    """

    if not interactive and getattr(args, 'data', None) is None:
        return {'error': 'Zone file data required in non-interactive mode'}

    proxy = get_default_proxy() if proxy is None else proxy

    if hasattr(args, 'nonstandard') and not nonstandard:
        if args.nonstandard is not None and args.nonstandard.lower() in ['yes', '1', 'true']:
            nonstandard = True

    conf = config.get_config(config_path)
    assert conf

    config_dir = os.path.dirname(config_path)
    res = wallet_ensure_exists(config_dir)
    if 'error' in res:
        return res

    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    fqu = str(args.name)
    zonefile_data = None
    if getattr(args, 'data', None) is not None:
        zonefile_data = str(args.data)

    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    # is this a path?
    zonefile_data_exists = is_valid_path(zonefile_data) and os.path.exists(zonefile_data) and not force_data
    if zonefile_data is not None and zonefile_data_exists:
        try:
            with open(zonefile_data) as f:
                zonefile_data = f.read()
        except:
            return {'error': 'Failed to read "{}"'.format(zonefile_data)}

    # load wallet
    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    # fetch remotely?
    if zonefile_data is None:
        zonefile_data_res = get_name_zonefile(
            fqu, proxy=proxy, wallet_keys=wallet_keys, raw_zonefile=True
        )

        if zonefile_data_res is None:
            zonefile_data_res = {'error': 'No zonefile'}

        if 'error' not in zonefile_data_res:
            zonefile_data = zonefile_data_res['zonefile']
        else:
            log.warning('Failed to fetch zonefile: {}'.format(zonefile_data_res['error']))

    # load zonefile, if given
    user_data_txt, user_data_hash, user_zonefile_dict = None, None, {}

    user_data_res = load_zonefile(fqu, zonefile_data)
    if 'error' not in user_data_res:
        user_data_txt = user_data_res['zonefile']
        user_data_hash = storage.get_zonefile_data_hash(user_data_res['zonefile'])
        user_zonefile_dict = blockstack_zones.parse_zone_file(user_data_res['zonefile'])
    else:
        if 'identical' in user_data_res:
            return {'error': 'Zonefile matches the current name hash; not updating.'}

        if not interactive:
            if zonefile_data is None or nonstandard:
                log.warning('Using non-zonefile data')
            
            else:
                return {'error': 'Zone file not updated (invalid)'}

        #  not a well-formed zonefile (but maybe that's okay! ask the user)
        if zonefile_data is not None and interactive:
            # something invalid here.  prompt overwrite
            proceed = prompt_invalid_zonefile()
            if not proceed:
                msg = 'Zone file not updated (reason: {})'
                return {'error': msg.format(user_data_res['error'])}

        user_data_txt = zonefile_data
        if zonefile_data is not None:
            user_data_hash = storage.get_zonefile_data_hash(zonefile_data)

    # open the zonefile editor
    data_pubkey = wallet_keys['data_pubkey']

    '''
    if interactive:
        new_zonefile = configure_zonefile(
            fqu, user_zonefile_dict, data_pubkey=data_pubkey
        )
        if new_zonefile is None:
            # zonefile did not change; nothing to do
            return {'error': 'Zonefile did not change.  No update sent.'}
    '''

    payment_privkey_info = wallet_keys['payment_privkey']
    owner_privkey_info = wallet_keys['owner_privkey']

    res = operation_sanity_check(
        fqu, payment_privkey_info, owner_privkey_info, config_path=config_path
    )

    if 'error' in res:
        return res

    rpc = local_rpc_connect(config_dir=config_dir)

    try:
        resp = rpc.backend_update(
            conf['rpc_token'], fqu, base64.b64encode(user_data_txt), None, user_data_hash
        )
    except Exception as e:
        log.exception(e)
        return {'error': 'Error talking to server, try again.'}

    if 'success' in resp and resp['success']:
        result = resp
        analytics_event('Update name', {})
        return result

    if 'error' in resp:
        log.error('Backend failed to queue update: {}'.format(resp['error']))
        return resp

    if 'message' in resp:
        log.error('Backend reports error: {}'.format(resp['message']))
        return {'error': resp['message']}

    analytics_event('Update name', {})

    return result


def cli_transfer(args, config_path=CONFIG_PATH, password=None, interactive=False):
    """
    command: transfer
    help: Transfer a name to a new address
    arg: name (str) 'The name to transfer'
    arg: address (str) 'The address to receive the name'
    """

    conf = config.get_config(config_path)
    assert conf

    config_dir = os.path.dirname(config_path)
    res = wallet_ensure_exists(config_dir)
    if 'error' in res:
        return res

    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    # load wallet
    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    payment_privkey_info = wallet_keys['payment_privkey']
    owner_privkey_info = wallet_keys['owner_privkey']

    transfer_address = str(args.address)

    res = operation_sanity_check(
        fqu, payment_privkey_info, owner_privkey_info,
        transfer_address=transfer_address, config_path=config_path
    )

    if 'error' in res:
        return res

    if interactive:
        res = prompt_transfer(transfer_address)
        if not res:
            return {'error': 'Transfer cancelled.'}

    rpc = local_rpc_connect(config_dir=config_dir)

    try:
        resp = rpc.backend_transfer(conf['rpc_token'], fqu, transfer_address)
    except:
        return {'error': 'Error talking to server, try again.'}

    if 'success' in resp and resp['success']:
        result = resp
        analytics_event('Transfer name', {})
        return result

    if 'error' in resp:
        return resp

    if 'message' in resp:
        return {'error': resp['message']}

    analytics_event('Transfer name', {})

    return result


def cli_renew(args, config_path=CONFIG_PATH, interactive=True, password=None, proxy=None):
    """
    command: renew
    help: Renew a name
    arg: name (str) 'The name to renew'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    conf = config.get_config(config_path)
    assert conf

    config_dir = os.path.dirname(config_path)
    res = wallet_ensure_exists(config_dir)
    if 'error' in res:
        return res

    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    result = {}
    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    if not is_name_registered(fqu, proxy=proxy):
        return {'error': '{} does not exist.'.format(fqu)}

    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    owner_privkey_info = wallet_keys['owner_privkey']
    payment_privkey_info = wallet_keys['payment_privkey']

    owner_address = get_privkey_info_address(owner_privkey_info)
    payment_address = get_privkey_info_address(payment_privkey_info)

    if not is_name_owner(fqu, owner_address, proxy=proxy):
        return {'error': '{} is not in your possession.'.format(fqu)}

    # estimate renewal fees
    try:
        renewal_fee = get_name_cost(fqu, proxy=proxy)
    except Exception as e:
        log.exception(e)
        return {'error': 'Could not connect to server'}

    if 'error' in renewal_fee:
        msg = 'Could not determine price of name: {}'
        return {'error': msg.format(renewal_fee['error'])}

    utxo_client = get_utxo_provider_client(config_path=config_path)

    # fee stimation: cost of name + cost of renewal transaction
    name_price = renewal_fee['satoshis']

    renewal_tx_fee = estimate_renewal_tx_fee(
        fqu, name_price, payment_privkey_info, owner_privkey_info,
        utxo_client, config_path=config_path
    )

    if renewal_tx_fee is None:
        return {'error': 'Failed to estimate fee'}

    cost = name_price + renewal_tx_fee

    if interactive:
        try:
            cost = name_price + renewal_tx_fee
            msg = (
                'Renewing {} will cost {} BTC. '
                'Continue? (y/n): '
            )
            input_prompt = msg.format(fqu, satoshis_to_btc(cost))

            user_input = raw_input(input_prompt)
            user_input = user_input.lower()

            if user_input != 'y':
                print('Not renewing.')
                exit(0)
        except KeyboardInterrupt:
            print('\nExiting.')
            exit(0)

    balance = get_balance(payment_address, config_path=config_path)
    if balance is None:
        msg = 'Failed to get balance'
        return {'error': msg}

    if balance < cost:
        msg = 'Address {} does not have enough balance (need {}).'
        msg = msg.format(payment_address, balance)
        return {'error': msg}

    if not is_address_usable(payment_address, config_path=config_path):
        msg = (
            'Address {} has insufficiently confirmed transactions. '
            'Wait and try later.'
        )

        msg = msg.format(payment_address)
        return {'error': msg}

    rpc = local_rpc_connect(config_dir=config_dir)

    try:
        resp = rpc.backend_renew(conf['rpc_token'], fqu, name_price)
    except:
        return {'error': 'Error talking to server, try again.'}

    total_estimated_cost = {'total_estimated_cost': cost}

    if 'success' in resp and resp['success']:
        result = resp
        analytics_event('Renew name', total_estimated_cost)
        return result

    if 'error' in resp:
        log.debug('RPC error: {}'.format(resp['error']))
        return resp

    if 'message' in resp:
        return {'error': resp['message']}

    analytics_event('Renew name', total_estimated_cost)

    return result


def cli_revoke(args, config_path=CONFIG_PATH, interactive=True, password=None, proxy=None):
    """
    command: revoke
    help: Revoke a name
    arg: name (str) 'The name to revoke'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    conf = config.get_config(config_path)
    assert conf

    config_dir = os.path.dirname(config_path)
    res = wallet_ensure_exists(config_dir)
    if 'error' in res:
        return res

    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    result = {}
    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    if not is_name_registered(fqu, proxy=proxy):
        return {'error': '{} does not exist.'.format(fqu)}

    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    owner_privkey_info = wallet_keys['owner_privkey']
    payment_privkey_info = wallet_keys['payment_privkey']

    res = operation_sanity_check(
        fqu, payment_privkey_info, owner_privkey_info, config_path=config_path
    )

    if 'error' in res:
        return res

    if interactive:
        try:
            input_prompt = (
                'WARNING: This will render your name unusable and\n'
                'remove any links it points to.\n'
                'THIS CANNOT BE UNDONE OR CANCELLED.\n'
                '\n'
                'Proceed? (y/N) '
            )
            user_input = raw_input(input_prompt)
            user_input = user_input.lower()

            if user_input != 'y':
                print('Not revoking.')
                exit(0)
        except KeyboardInterrupt:
            print('\nExiting.')
            exit(0)

    rpc = local_rpc_connect(config_dir=config_dir)

    try:
        resp = rpc.backend_revoke(conf['rpc_token'], fqu)
    except:
        return {'error': 'Error talking to server, try again.'}

    if 'success' in resp and resp['success']:
        result = resp
        analytics_event('Revoke name', {})
        return result

    if 'error' in resp:
        log.debug('RPC error: {}'.format(resp['error']))
        return resp

    if 'message' in resp:
        return {'error': resp['message']}

    analytics_event('Revoke name', {})

    return result


def cli_migrate(args, config_path=CONFIG_PATH, password=None,
                proxy=None, interactive=True, force=False):
    """
    command: migrate
    help: Migrate a name-linked profile to the latest zonefile and profile format
    arg: name (str) 'The name to migrate'
    """

    conf = config.get_config(config_path)
    assert conf

    config_dir = os.path.dirname(config_path)
    res = wallet_ensure_exists(config_dir)
    if 'error' in res:
        return res

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    owner_privkey_info = wallet_keys['owner_privkey']
    payment_privkey_info = wallet_keys['payment_privkey']

    res = operation_sanity_check(
        fqu, payment_privkey_info, owner_privkey_info, config_path=config_path
    )

    if 'error' in res:
        return res

    user_zonefile = get_name_zonefile(
        fqu, proxy=proxy, wallet_keys=wallet_keys,
        raw_zonefile=True, include_name_record=True
    )

    if user_zonefile is not None and 'error' not in user_zonefile:
        name_rec = user_zonefile['name_record']
        user_zonefile_txt = user_zonefile['zonefile']
        user_zonefile_hash = storage.get_zonefile_data_hash(user_zonefile_txt)
        user_zonefile = None
        legacy = False
        nonstandard = False

        # try to parse
        try:
            user_zonefile = blockstack_zones.parse_zone_file(user_zonefile_txt)
            legacy = blockstack_profiles.is_profile_in_legacy_format(user_zonefile)
        except:
            log.warning('Non-standard zonefile {}'.format(user_zonefile_hash))
            nonstandard = True

        current = name_rec.get('value_hash', '') == user_zonefile_hash

        if nonstandard and not legacy:
            # maybe we're trying to reset the profile?
            if interactive and not force:
                msg = (
                    ''
                    'WARNING!  Non-standard zonefile detected.'
                    'If you proceed, your zonefile will be reset'
                    'and you will have to re-build your profile.'
                    ''
                    'Proceed? (y/N): '
                )

                proceed_str = raw_input(msg)
                proceed = proceed_str.lower() in ['y']
                if not proceed:
                    return {'error': 'Non-standard zonefile'}

            elif not force:
                return {'error': 'Non-standard zonefile'}

        # is current and either standard or legacy?
        elif not legacy and not force:
            if current:
                msg = 'Zonefile data is same as current zonefile; update not needed.'
                return {'error': msg}

            # maybe this is intentional (like fixing a corrupt zonefile)
            msg = 'Not a legacy profile; cannot migrate.'
            return {'error': msg}

    rpc = local_rpc_connect(config_dir=config_dir)

    try:
        resp = rpc.backend_migrate(conf['rpc_token'], fqu)
    except Exception as e:
        log.exception(e)
        return {'error': 'Error talking to server, try again.'}

    if 'success' in resp and resp['success']:
        result = resp
        analytics_event('Migrate name', {})
        return result

    if 'error' in resp:
        return resp

    if 'message' in resp:
        return {'error': resp['message']}

    analytics_event('Migrate name', {})

    return result


def cli_set_advanced_mode(args, config_path=CONFIG_PATH):
    """
    command: set_advanced_mode
    help: Enable advanced commands
    arg: status (str) 'On or Off.'
    """

    status = str(args.status).lower()
    if status not in ['on', 'off']:
        return {'error': 'Invalid option; please use "on" or "off"'}

    set_advanced_mode((status == 'on'), config_path=config_path)

    return {'status': True}


def _get_person_profile(name, proxy=None):
    """
    Get the person's zonefile and profile.
    Handle legacy zonefiles, but not legacy profiles.
    Return {'profile': ..., 'zonefile': ..., 'person': ...} on success
    Return {'error': ...} on error
    """

    profile, zonefile = get_name_profile(name, proxy=proxy, use_legacy_zonefile=True)
    if 'error' in zonefile:
        return {'error': 'Failed to load zonefile: {}'.format(zonefile['error'])}

    if blockstack_profiles.is_profile_in_legacy_format(profile):
        return {'error': 'Legacy profile'}

    person = None
    try:
        person = blockstack_profiles.Person(profile)
    except Exception as e:
        log.exception(e)
        return {'error': 'Failed to parse profile data into a Person record'}
    
    return {'profile': profile, 'zonefile': zonefile, 'person': person}


def _save_person_profile(name, zonefile, profile, wallet_keys, proxy=None, config_path=CONFIG_PATH):
    """
    Save a person's profile, given information fetched with _get_person_profile
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    conf = config.get_config(config_path)
    assert conf

    required_storage_drivers = conf.get(
        'storage_drivers_required_write',
        config.BLOCKSTACK_REQUIRED_STORAGE_DRIVERS_WRITE
    )
    required_storage_drivers = required_storage_drivers.split()

    owner_address = get_privkey_info_address(wallet_keys['owner_privkey'])
    res = put_profile(name, profile, user_zonefile=zonefile, owner_address=owner_address,
                       wallet_keys=wallet_keys, proxy=proxy, required_drivers=required_storage_drivers )

    return res


def _list_accounts(name, proxy=None):
    """
    Get the list of accounts in a name's Person-formatted profile.
    Return {'accounts': ...} on success
    Return {'error': ...} on error
    """

    name_info = _get_person_profile(name, proxy=proxy)
    if 'error' in name_info:
        return name_info

    profile = name_info.pop('profile')
    zonefile = name_info.pop('zonefile')
    person = name_info.pop('person')

    accounts = []
    if hasattr(person, 'account'):
        accounts = person.account

    return {'accounts': accounts}


# TODO: consider deprecating for 0.15
def cli_list_accounts( args, proxy=None, config_path=CONFIG_PATH ):
    """
    command: list_accounts advanced
    help: List the set of accounts associated with a name.
    arg: name (str) 'The name to query.'
    """ 

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)
    
    name = str(args.name)
    account_info = _list_accounts(name, proxy=proxy )
    if 'error' in account_info:
        return account_info

    return account_info['accounts']


# TODO: consider deprecating for 0.15
def cli_get_account( args, proxy=None, config_path=CONFIG_PATH ):
    """
    command: get_account advanced
    help: Get a particular account from a name.
    arg: name (str) 'The name to query.'
    arg: service (str) 'The service for which this account was created.'
    arg: identifier (str) 'The name of the account.'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)
    
    name = str(args.name)
    service = str(args.service)
    identifier = str(args.identifier)

    account_info = _list_accounts(name, proxy=proxy )
    if 'error' in account_info:
        return account_info

    accounts = account_info['accounts']
    for account in accounts:
        if not account.has_key('service') or not account.has_key('identifier'):
            continue

        if account['service'] == service and account['identifier'] == identifier:
            return account

    return {'error': 'No such account'}


# TODO: consider deprecating for 0.15
def cli_put_account( args, proxy=None, config_path=CONFIG_PATH, password=None, wallet_keys=None ):
    """
    command: put_account advanced
    help: Set a person's account's details.  If the account already exists, it will be overwritten.
    arg: name (str) 'The name to query.'
    arg: service (str) 'The service this account is for.'
    arg: identifier (str) 'The name of the account.'
    arg: content_url (str) 'The URL that points to external contact data.'
    opt: extra_data (str) 'A comma-separated list of "name1=value1,name2=value2,name3=value3..." with any extra account information you need in the account.'
    """
    proxy = get_default_proxy(config_path=config_path) if proxy is None else proxy
    config_dir = os.path.dirname(config_path)

    if wallet_keys is None:
        res = start_rpc_endpoint(config_dir)
        if 'error' in res:
            return res

        wallet_keys = get_wallet_keys(config_path, password)
        if 'error' in wallet_keys:
            return wallet_keys

    name = str(args.name)
    service = str(args.service)
    identifier = str(args.identifier)
    content_url = str(args.content_url)

    if not is_name_valid(args.name):
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
                if k in ['service', 'identifier', 'contentUrl']:
                    continue

                v = "=".join(parts[1:])
                extra_data[k] = v

    person_info = _get_person_profile(name, proxy=proxy)
    if 'error' in person_info:
        return person_info

    # make data
    new_account = {
        'service': service,
        'identifier': identifier,
        'contentUrl': content_url,
    }
    new_account.update(extra_data)

    zonefile = person_info.pop('zonefile')
    profile = person_info.pop('profile')
    if not profile.has_key('account'):
        profile['account'] = []

    # overwrite existing, if given 
    replaced = False
    for i in xrange(0, len(profile['account'])):
        account = profile['account'][i]
        if not account.has_key('service') or not account.has_key('identifier'):
            continue

        if account['service'] == service and account['identifier'] == identifier:
            profile['account'][i] = new_account
            replaced = True
            break

    if not replaced:
        profile['account'].append(new_account)

    # save
    result = _save_person_profile(name, zonefile, profile, wallet_keys, proxy=proxy, config_path=config_path)
    return result


# TODO: consider deprecating for 0.15
def cli_delete_account( args, proxy=None, config_path=CONFIG_PATH, password=None, wallet_keys=None ):
    """
    command: delete_account advanced
    help: Delete a particular account.
    arg: name (str) 'The name to query.'
    arg: service (str) 'The service the account is for.'
    arg: identifier (str) 'The identifier of the account to delete.'
    """
    proxy = get_default_proxy(config_path=config_path) if proxy is None else proxy

    config_dir = os.path.dirname(config_path)
    if wallet_keys is None:
        res = start_rpc_endpoint(config_dir)
        if 'error' in res:
            return res

        wallet_keys = get_wallet_keys(config_path, password)
        if 'error' in wallet_keys:
            return wallet_keys

    name = str(args.name)
    service = str(args.service)
    identifier = str(args.identifier)

    if not is_name_valid(args.name):
        return {'error': 'Invalid name'}

    if len(args.service) == 0 or len(args.identifier) == 0:
        return {'error': 'Invalid data'}

    person_info = _get_person_profile(name, proxy=proxy)
    if 'error' in person_info:
        return person_info

    zonefile = person_info['zonefile']
    profile = person_info['profile']
    if not profile.has_key('account'):
        # nothing to do
        return {'error': 'No such account'}

    found = False
    for i in xrange(0, len(profile['account'])):
        account = profile['account'][i]
        if not account.has_key('service') or not account.has_key('identifier'):
            continue

        if account['service'] == service and account['identifier'] == identifier:
            profile['account'].pop(i)
            found = True
            break

    if not found:
        return {'error': 'No such account'}

    result = _save_person_profile(name, zonefile, profile, wallet_keys, proxy=proxy, config_path=config_path)
    return result


def cli_import_wallet(args, config_path=CONFIG_PATH, password=None, force=False):
    """
    command: import_wallet advanced
    help: Set the payment, owner, and data private keys for the wallet.
    arg: payment_privkey (str) 'Payment private key.  M-of-n multisig is supported by passing the CSV string "m,n,pk1,pk2,...".'
    arg: owner_privkey (str) 'Name owner private key.  M-of-n multisig is supported by passing the CSV string "m,n,pk1,pk2,...".'
    arg: data_privkey (str) 'Data-signing private key.  Must be a single private key.'
    """

    # we require m and n, even though n can be inferred, so we can at least sanity-check the user's arguments.
    # it's hard to get both n and the number of private keys wrong in the same way.

    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    if force and os.path.exists(wallet_path):
        # back up
        backup_wallet(wallet_path)

    if os.path.exists(wallet_path):
        msg = 'Back up or remove current wallet first: {}'
        return {
            'error': 'Wallet already exists!',
            'message': msg.format(wallet_path),
        }

    if password is None:
        while True:
            res = make_wallet_password(password)
            if 'error' in res and password is None:
                print(res['error'])
                continue

            if password is not None:
                return res

            password = res['password']
            break

    try:
        assert args.owner_privkey
        assert args.payment_privkey
        assert args.data_privkey
    except Exception, e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)
        return {'error': 'Invalid private keys'}

    def parse_multisig_csv(multisig_csv):
        """
        Helper to parse 'm,n,pk1,pk2.,,,' into a virtualchain private key bundle.
        """
        parts = multisig_csv.split(',')
        m = None
        n = None
        try:
            m = int(parts[0])
            n = int(parts[1])
            assert m <= n
            assert len(parts[2:]) == n
        except ValueError as ve:
            log.exception(ve)
            log.debug("Invalid multisig CSV {}".format(multisig_csv))
            log.error("Invalid m, n")
            return {'error': 'Unparseable m or n'}
        except AssertionError as ae:
            log.exception(ae)
            log.debug("Invalid multisig CSV {}".format(multisig_csv))
            log.error("Invalid argument: n must not exceed m, and there must be n private keys")
            return {'error': 'Invalid argument: invalid values for m or n'}

        keys = parts[2:]
        key_info = None
        try:
            key_info = virtualchain.make_multisig_info(m, keys)
        except Exception as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            log.error("Failed to make multisig information from keys")
            return {'error': 'Failed to make multisig information'}

        return key_info

    owner_privkey_info = None
    payment_privkey_info = None
    data_privkey_info = None

    # make absolutely certain that these are valid keys or multisig key strings
    try:
        owner_privkey_info = virtualchain.BitcoinPrivateKey(str(args.owner_privkey)).to_hex()
    except:
        log.debug("Owner private key string is not a valid Bitcoin private key")
        owner_privkey_info = parse_multisig_csv(args.owner_privkey)
        if 'error' in owner_privkey_info:
            return owner_privkey_info

    try:
        payment_privkey_info = virtualchain.BitcoinPrivateKey(str(args.payment_privkey)).to_hex()
    except:
        log.debug("Payment private key string is not a valid Bitcoin private key")
        payment_privkey_info = parse_multisig_csv(args.payment_privkey)
        if 'error' in payment_privkey_info:
            return payment_privkey_info

    try:
        data_privkey_info = virtualchain.BitcoinPrivateKey(str(args.data_privkey)).to_hex()
    except:
        log.error("Only single private keys are supported for data at this time")
        return {'error': 'Invalid data private key'}

    data = make_wallet(password, config_path=config_path,
            payment_privkey_info=payment_privkey_info,
            owner_privkey_info=owner_privkey_info,
            data_privkey_info=data_privkey_info )

    if 'error' in data:
        return data

    write_wallet(data, path=wallet_path)

    if not local_rpc_status(config_dir=config_dir):
        return {'status': True}

    # update RPC daemon if we're running
    local_rpc_stop(config_dir=config_dir)

    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    return {'status': True}


def cli_wallet(args, config_path=CONFIG_PATH, password=None):
    """
    command: wallet advanced
    help: Query wallet information
    """

    result = {}
    config_dir = os.path.dirname(config_path)
    res = wallet_ensure_exists(config_dir, password=password)
    if 'error' in res:
        return res

    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    wallet_path = os.path.join(config_dir, WALLET_FILENAME)
    if os.path.exists(wallet_path):
        result = get_wallet_with_backoff(config_path)
        return result

    result = initialize_wallet(wallet_path=wallet_path)

    payment_privkey = result.get('payment_privkey', None)
    owner_privkey = result.get('owner_privkey', None)
    data_privkey = result.get('data_privkey', None)

    display_wallet_info(
        result.get('payment_address'),
        result.get('owner_address'),
        result.get('data_pubkey'),
        config_path=CONFIG_PATH
    )

    print('-' * 60)
    print('Payment private key info: {}'.format(privkey_to_string(payment_privkey)))
    print('Owner private key info:   {}'.format(privkey_to_string(owner_privkey)))
    print('Data private key info:    {}'.format(privkey_to_string(data_privkey)))

    return result


def cli_consensus(args, config_path=CONFIG_PATH):
    """
    command: consensus advanced
    help: Get current consensus information
    opt: block_height (int) 'The block height at which to query the consensus information.  If not given, the current height is used.'
    """
    result = {}
    if args.block_height is None:
        # by default get last indexed block
        resp = getinfo()

        if 'error' in resp:
            return resp

        if 'last_block_processed' in resp and 'consensus_hash' in resp:
            return {'consensus': resp['consensns_hash'], 'block_height': resp['last_block_processed']}
        else:
            return {'error': 'Server is indexing.  Try again shortly.'}

    resp = get_consensus_at(int(args.block_height))

    data = {}
    data['consensus'] = resp
    data['block_height'] = args.block_height

    result = data

    return result


def cli_rpcctl(args, config_path=CONFIG_PATH):
    """
    command: rpcctl advanced
    help: Control the background blockstack API endpoint
    arg: command (str) '"start", "stop", "restart", or "status"'
    """

    config_dir = CONFIG_DIR
    if config_path is not None:
        config_dir = os.path.dirname(config_path)

    rc = local_rpc.local_rpc_action(str(args.command), config_dir=config_dir)
    if rc != 0:
        return {'error': 'RPC controller exit code {}'.format(rc)}

    return {'status': True}


def cli_rpc(args, config_path=CONFIG_PATH):
    """
    command: rpc advanced
    help: Issue an RPC request to a locally-running API endpoint
    arg: method (str) 'The method to call'
    opt: args (str) 'A JSON list of positional arguments.'
    opt: kwargs (str) 'A JSON object of keyword arguments.'
    """

    rpc_args = []
    rpc_kw = {}

    if args.args is not None:
        try:
            rpc_args = json.loads(args.args)
        except:
            print('Not JSON: "{}"'.format(args.args), file=sys.stderr)
            return {'error': 'Invalid arguments'}

    if args.kwargs is not None:
        try:
            rpc_kw = json.loads(args.kwargs)
        except:
            print('Not JSON: "{}"'.format(args.kwargs), file=sys.stderr)
            return {'error': 'Invalid arguments'}

    conf = config.get_config(path=config_path)
    portnum = conf['api_endpoint_port']
    rpc_kw['config_dir'] = os.path.dirname(config_path)

    result = local_rpc.local_rpc_dispatch(portnum, str(args.method), *rpc_args, **rpc_kw)
    return result


def cli_name_import(args, config_path=CONFIG_PATH):
    """
    command: name_import advanced
    help: Import a name to a revealed but not-yet-readied namespace
    arg: name (str) 'The name to import'
    arg: address (str) 'The address of the name recipient'
    arg: hash (str) 'The zonefile hash of the name'
    arg: privatekey (str) 'One of the private keys of the namespace revealer'
    """
    # BROKEN
    result = name_import(
        str(args.name), str(args.address),
        str(args.hash), str(args.privatekey)
    )

    return result


def cli_namespace_preorder(args, config_path=CONFIG_PATH):
    """
    command: namespace_preorder advanced
    help: Preorder a namespace
    arg: namespace_id (str) 'The namespace ID'
    arg: privatekey (str) 'The private key to send and pay for the preorder'
    opt: reveal_addr (str) 'The address of the keypair that will import names (automatically generated if not given)'
    """
    # BROKEN
    reveal_addr = None
    if args.address is not None:
        reveal_addr = str(args.address)

    result = namespace_preorder(
        str(args.namespace_id),
        str(args.privatekey),
        reveal_addr=reveal_addr
    )

    return result


def cli_namespace_reveal(args, config_path=CONFIG_PATH):
    """
    command: namespace_reveal advanced
    help: Reveal a namespace and set its pricing parameters
    arg: namespace_id (str) 'The namespace ID'
    arg: addr (str) 'The address of the keypair that will import names (given in the namespace preorder)'
    arg: lifetime (int) 'The lifetime (in blocks) for each name.  Negative means "never expires".'
    arg: coeff (int) 'The multiplicative coefficient in the price function.'
    arg: base (int) 'The exponential base in the price function.'
    arg: bucket_exponents (str) 'A 16-field CSV of name-length exponents in the price function.'
    arg: nonalpha_discount (int) 'The denominator that defines the discount for names with non-alpha characters.'
    arg: no_vowel_discount (int) 'The denominator that defines the discount for names without vowels.'
    arg: privatekey (str) 'The private key of the import keypair (whose address is `addr` above).'
    """
    # BROKEN
    bucket_exponents = args.bucket_exponents.split(',')
    if len(bucket_exponents) != 16:
        msg = '`bucket_exponents` must be a 16-value CSV of integers'
        return {'error': msg}

    for i in range(len(bucket_exponents)):
        try:
            bucket_exponents[i] = int(bucket_exponents[i])
            assert 0 <= bucket_exponents[i] < 16
        except (ValueError, AssertionError) as e:
            msg = '`bucket_exponents` must contain integers between 0 and 15, inclusively.'
            return {'error': msg}

    lifetime = int(args.lifetime)
    if lifetime < 0:
        lifetime = 0xffffffff       # means "infinite" to blockstack-server

    # BUG: undefined function
    result = namespace_reveal(
        str(args.namespace_id),
        str(args.addr),
        lifetime,
        int(args.coeff),
        int(args.base),
        bucket_exponents,
        int(args.nonalpha_discount),
        int(args.no_vowel_discount),
        str(args.privatekey)
    )

    return result


def cli_namespace_ready(args, config_path=CONFIG_PATH):
    """
    command: namespace_ready advanced
    help: Mark a namespace as ready
    arg: namespace_id (str) 'The namespace ID'
    arg: privatekey (str) 'The private key of the keypair that imports names'
    """
    # BROKEN
    result = namespace_ready(
        str(args.namespace_id),
        str(args.privatekey)
    )

    return result


def cli_put_mutable(args, config_path=CONFIG_PATH, password=None, proxy=None):
    """
    command: put_mutable advanced
    help: Put mutable data into a profile
    arg: name (str) 'The name to receive the data'
    arg: data_id (str) 'The name of the data'
    arg: data (str) 'The JSON-serializable data to store'
    """
    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    config_dir = os.path.dirname(config_path)
    res = start_rpc_endpoint(config_dir)
    if 'error' in res:
        return res

    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    proxy = get_default_proxy(config_path=config_path) if proxy is None else proxy

    result = put_mutable(
        fqu, str(args.data_id), str(args.data),
        wallet_keys=wallet_keys, proxy=proxy
    )

    return result


def cli_put_immutable(args, config_path=CONFIG_PATH,
                               password=None, proxy=None):
    """
    command: put_immutable advanced
    help: Put immutable data into a zonefile
    arg: name (str) 'The name to receive the data'
    arg: data_id (str) 'The name of the data'
    arg: data (str) 'The JSON-formatted data to store'
    """

    config_dir = os.path.dirname(config_path)
    res = wallet_ensure_exists(config_dir, password=password)
    if 'error' in res:
        return res

    res = start_rpc_endpoint(config_dir)
    if 'error' in res:
        return res

    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    try:
        data = json.loads(args.data)
    except:
        return {'error': 'Invalid JSON'}

    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    owner_privkey_info = wallet_keys['owner_privkey']
    payment_privkey_info = wallet_keys['payment_privkey']

    res = operation_sanity_check(
        fqu, payment_privkey_info, owner_privkey_info, config_path=config_path
    )

    if 'error' in res:
        return res

    proxy = get_default_proxy() if proxy is None else proxy

    result = put_immutable(
        fqu, str(args.data_id), data,
        wallet_keys=wallet_keys, proxy=proxy
    )
    return result


def cli_get_mutable(args, config_path=CONFIG_PATH, proxy=None):
    """
    command: get_mutable advanced
    help: Get mutable data from a profile
    arg: name (str) 'The name that has the data'
    arg: data_id (str) 'The name of the data'
    """
    conf = config.get_config(config_path)
    proxy = get_default_proxy() if proxy is None else proxy

    result = get_mutable(str(args.name), str(args.data_id), proxy=proxy, conf=conf)
    return result


def cli_get_immutable(args, config_path=CONFIG_PATH, proxy=None):
    """
    command: get_immutable advanced
    help: Get immutable data from a zonefile
    arg: name (str) 'The name that has the data'
    arg: data_id_or_hash (str) 'Either the name or the SHA256 of the data to obtain'
    """
    proxy = get_default_proxy() if proxy is None else proxy

    if is_valid_hash( args.data_id_or_hash ):
        result = get_immutable(str(args.name), str(args.data_id_or_hash), proxy=proxy)
        if 'error' not in result:
            return result

    # either not a valid hash, or no such data with this hash.
    # maybe this hash-like string is the name of something?
    result = get_immutable_by_name(str(args.name), str(args.data_id_or_hash), proxy=proxy)
    return result


def cli_list_update_history(args, config_path=CONFIG_PATH):
    """
    command: list_update_history advanced
    help: List the history of update hashes for a name
    arg: name (str) 'The name whose data to list'
    """
    result = list_update_history(str(args.name))
    return result


def cli_list_zonefile_history(args, config_path=CONFIG_PATH):
    """
    command: list_zonefile_history advanced
    help: List the history of zonefiles for a name (if they can be obtained)
    arg: name (str) 'The name whose zonefiles to list'
    """
    result = list_zonefile_history(str(args.name))
    return result


def cli_list_immutable_data_history(args, config_path=CONFIG_PATH):
    """
    command: list_immutable_data_history advanced
    help: List all prior hashes of a given immutable datum
    arg: name (str) 'The name whose data to list'
    arg: data_id (str) 'The data identifier whose history to list'
    """
    result = list_immutable_data_history(str(args.name), str(args.data_id))
    return result


def cli_delete_immutable(args, config_path=CONFIG_PATH, proxy=None, password=None):
    """
    command: delete_immutable advanced
    help: Delete an immutable datum from a zonefile.
    arg: name (str) 'The name that owns the data'
    arg: hash (str) 'The SHA256 of the data to remove'
    """

    config_dir = os.path.dirname(config_path)
    res = wallet_ensure_exists(config_dir, password=password)
    if 'error' in res:
        return res

    res = start_rpc_endpoint(config_dir)
    if 'error' in res:
        return res

    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    owner_privkey_info = wallet_keys['owner_privkey']
    payment_privkey_info = wallet_keys['payment_privkey']

    res = operation_sanity_check(
        fqu, payment_privkey_info,
        owner_privkey_info, config_path=config_path
    )

    if 'error' in res:
        return res

    if proxy is None:
        proxy = get_default_proxy()

    result = delete_immutable(
        str(args.name), str(args.hash),
        proxy=proxy, wallet_keys=wallet_keys
    )

    return result


def cli_delete_mutable(args, config_path=CONFIG_PATH):
    """
    command: delete_mutable advanced
    help: Delete a mutable datum from a profile.
    arg: name (str) 'The name that owns the data'
    arg: data_id (str) 'The ID of the data to remove'
    """
    result = delete_mutable(str(args.name), str(args.data_id))
    return result


def cli_get_name_blockchain_record(args, config_path=CONFIG_PATH):
    """
    command: get_name_blockchain_record advanced
    help: Get the raw blockchain record for a name
    arg: name (str) 'The name to list'
    """
    result = get_name_blockchain_record(str(args.name))
    return result


def cli_get_name_blockchain_history(args, config_path=CONFIG_PATH):
    """
    command: get_name_blockchain_history advanced
    help: Get a sequence of historic blockchain records for a name
    arg: name (str) 'The name to query'
    opt: start_block (int) 'The start block height'
    opt: end_block (int) 'The end block height'
    """
    start_block = args.start_block
    if start_block is None:
        start_block = FIRST_BLOCK_MAINNET
    else:
        start_block = int(args.start_block)

    end_block = args.end_block
    if end_block is None:
        # I would love to have to update this number in the future,
        # if it proves too small.  That would be a great problem
        # to have :-)
        end_block = 100000000
    else:
        end_block = int(args.end_block)

    result = get_name_blockchain_history(str(args.name), start_block, end_block)
    return result


def cli_get_namespace_blockchain_record(args, config_path=CONFIG_PATH):
    """
    command: get_namespace_blockchain_record advanced
    help: Get the raw namespace blockchain record for a name
    arg: namespace_id (str) 'The namespace ID to list'
    """
    result = get_namespace_blockchain_record(str(args.namespace_id))
    return result


def cli_lookup_snv(args, config_path=CONFIG_PATH):
    """
    command: lookup_snv advanced
    help: Use SNV to look up a name at a particular block height
    arg: name (str) 'The name to query'
    arg: block_id (int) 'The block height at which to query the name'
    arg: trust_anchor (str) 'The trusted consensus hash, transaction ID, or serial number from a higher block height than `block_id`'
    """
    result = lookup_snv(
        str(args.name),
        int(args.block_id),
        str(args.trust_anchor)
    )

    return result


def cli_get_name_zonefile(args, config_path=CONFIG_PATH):
    """
    command: get_name_zonefile advanced
    help: Get a name's zonefile
    arg: name (str) 'The name to query'
    opt: json (str) 'If true is given, try to parse as JSON'
    """
    parse_json = getattr(args, 'json', 'false')
    parse_json = parse_json is not None and parse_json.lower() in ['true', '1']

    result = get_name_zonefile(str(args.name), raw_zonefile=True)
    if result is None:
        return {'error': 'Failed to get zonefile'}

    if 'error' in result:
        log.error("get_name_zonefile failed: %s" % result['error'])
        return result

    if 'zonefile' not in result:
        return {'error': 'No zonefile data'}

    if parse_json:
        # try to parse
        try:
            new_zonefile = decode_name_zonefile(result['zonefile'])
            assert new_zonefile is not None
            result['zonefile'] = new_zonefile
        except:
            result['warning'] = 'Non-standard zonefile'

    return result


def cli_get_names_owned_by_address(args, config_path=CONFIG_PATH):
    """
    command: get_names_owned_by_address advanced
    help: Get the list of names owned by an address
    arg: address (str) 'The address to query'
    """
    result = get_names_owned_by_address(str(args.address))
    return result


def cli_get_namespace_cost(args, config_path=CONFIG_PATH):
    """
    command: get_namespace_cost advanced
    help: Get the cost of a namespace
    arg: namespace_id (str) 'The namespace ID to query'
    """
    result = get_namespace_cost(str(args.namespace_id))
    return result


def get_offset_count(offset, count):
    return (
        int(offset) if offset is not None else -1,
        int(count) if count is not None else -1,
    )


def cli_get_all_names(args, config_path=CONFIG_PATH):
    """
    command: get_all_names advanced
    help: Get all names in existence, optionally paginating through them
    opt: offset (int) 'The offset into the sorted list of names'
    opt: count (int) 'The number of names to return'
    """

    offset = int(args.offset) if args.offset is not None else None
    count = int(args.count) if args.count is not None else None

    result = get_all_names(offset=offset, count=count)

    return result


def cli_get_names_in_namespace(args, config_path=CONFIG_PATH):
    """
    command: get_names_in_namespace
    help: Get the names in a given namespace, optionally paginating through them
    arg: namespace_id (str) 'The ID of the namespace to query'
    opt: offset (int) 'The offset into the sorted list of names'
    opt: count (int) 'The number of names to return'
    """

    offset = int(args.offset) if args.offset is not None else None
    count = int(args.count) if args.count is not None else None

    result = get_names_in_namespace(str(args.namespace_id), offset, count)

    return result


def cli_get_nameops_at(args, config_path=CONFIG_PATH):
    """
    command: get_nameops_at advanced
    help: Get the list of name operations that occurred at a given block number
    arg: block_id (int) 'The block height to query'
    """
    result = get_nameops_at(int(args.block_id))
    return result


def cli_set_zonefile_hash(args, config_path=CONFIG_PATH, password=None):
    """
    command: set_zonefile_hash advanced
    help: Directly set the hash associated with the name in the blockchain.
    arg: name (str) 'The name to update'
    arg: zonefile_hash (str) 'The RIPEMD160(SHA256(zonefile)) hash'
    """
    conf = config.get_config(config_path)
    assert conf

    config_dir = os.path.dirname(config_path)
    res = wallet_ensure_exists(config_dir, password=password)
    if 'error' in res:
        return res

    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    fqu = str(args.name)

    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    zonefile_hash = str(args.zonefile_hash)
    if re.match(r'^[a-fA-F0-9]+$', zonefile_hash) is None or len(zonefile_hash) != 40:
        return {'error': 'Not a valid zonefile hash'}

    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    owner_privkey_info = wallet_keys['owner_privkey']
    payment_privkey_info = wallet_keys['payment_privkey']

    res = operation_sanity_check(
        fqu, payment_privkey_info, owner_privkey_info, config_path=config_path
    )

    if 'error' in res:
        return res

    rpc = local_rpc_connect(config_dir=config_dir)

    try:
        resp = rpc.backend_update(conf['rpc_token'], fqu, None, None, zonefile_hash)
    except Exception as e:
        log.exception(e)
        return {'error': 'Error talking to server, try again.'}

    if 'success' in resp and resp['success']:
        result = resp
        analytics_event('Set zonefile hash', {})
        return result

    if 'error' in resp:
        return resp

    if 'message' in resp:
        return {'error': resp['message']}

    analytics_event('Set zonefile hash', {})

    return result


def cli_unqueue(args, config_path=CONFIG_PATH, password=None):
    """
    command: unqueue advanced
    help: Remove a stuck transaction from the queue.
    arg: name (str) 'The affected name'
    arg: queue_id (str) 'The type of queue ("preorder", "register", "update", etc)'
    arg: txid (str) 'The transaction ID'
    """
    conf = config.get_config(config_path)
    queue_path = conf['queue_path']

    try:
        queuedb_remove(
            str(args.queue_id), str(args.name),
            str(args.txid), path=queue_path
        )
    except:
        msg = 'Failed to remove from queue\n{}'
        return {'error': msg.format(traceback.format_exc())}

    return {'status': True}


def cli_put_name_profile(args, config_path=CONFIG_PATH, password=None, proxy=None):
    """
    command: put_name_profile advanced
    help: Set the profile for a user named by a blockchain ID.
    arg: name (str) 'The name of the user to set the profile for'
    arg: data (str) 'The profile as a JSON string, or a path to the profile.'
    """

    conf = config.get_config(config_path)
    name = str(args.name)
    profile_json_str = str(args.data)

    proxy = get_default_proxy() if proxy is None else proxy

    profile = None
    if is_valid_path(profile_json_str) and os.path.exists(profile_json_str):
        # this is a path.  try to load it
        try:
            with open(profile_json_str, 'r') as f:
                profile_json_str = f.read()
        except:
            return {'error': 'Failed to load "{}"'.format(profile_json_str)}

    # try to parse it
    try:
        profile = json.loads(profile_json_str)
    except:
        return {'error': 'Invalid profile JSON'}

    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    required_storage_drivers = conf.get(
        'storage_drivers_required_write',
        config.BLOCKSTACK_REQUIRED_STORAGE_DRIVERS_WRITE
    )
    required_storage_drivers = required_storage_drivers.split()

    owner_address = get_privkey_info_address(wallet_keys['owner_privkey'])
    user_zonefile = get_name_zonefile(name, proxy=proxy, wallet_keys=wallet_keys)
    if 'error' in user_zonefile:
        return user_zonefile

    user_zonefile = user_zonefile['zonefile']
    if blockstack_profiles.is_profile_in_legacy_format(user_zonefile):
        msg = 'Profile in legacy format.  Please migrate it with the "migrate" command first.'
        return {'error': msg}

    res = put_profile(name, profile, user_zonefile=user_zonefile, owner_address=owner_address,
                       wallet_keys=wallet_keys, proxy=proxy, required_drivers=required_storage_drivers )

    if 'error' in res:
        return res

    return {'status': True}


def cli_sync_zonefile(args, config_path=CONFIG_PATH, proxy=None, interactive=True, nonstandard=False):
    """
    command: sync_zonefile advanced
    help: Upload the current zone file to all storage providers.
    arg: name (str) 'Name of the zone file to synchronize.'
    opt: txid (str) 'NAME_UPDATE transaction ID that set the zone file.'
    opt: zonefile (str) 'The zone file (JSON or text), if unavailable from other sources.'
    opt: nonstandard (str) 'If true, do not attempt to parse the zonefile.  Just upload as-is.'
    """

    conf = config.get_config(config_path)

    assert 'server' in conf
    assert 'port' in conf
    assert 'queue_path' in conf

    queue_path = conf['queue_path']
    name = str(args.name)

    proxy = get_default_proxy(config_path=config_path) if proxy is None else proxy

    txid = None
    if hasattr(args, 'txid'):
        txid = getattr(args, 'txid')

    user_data, zonefile_hash = None, None

    if not nonstandard and getattr(args, 'nonstandard', None):
        nonstandard = args.nonstandard.lower() in ['yes', '1', 'true']

    if getattr(args, 'zonefile', None) is not None:
        # zonefile given
        user_data = args.zonefile
        valid = False
        try:
            user_data_res = load_zonefile(name, user_data)
            if 'error' in user_data_res and 'identical' not in user_data_res:
                log.warning('Failed to parse zonefile (reason: {})'.format(user_data_res['error']))
            else:
                valid = True
                user_data = user_data_res['zonefile']
        except Exception as e:
            if BLOCKSTACK_DEBUG is not None:
                log.exception(e)
            valid = False

        # if it's not a valid zonefile, ask if the user wants to sync
        if not valid and interactive:
            proceed = prompt_invalid_zonefile()
            if not proceed:
                return {'error': 'Not replicating invalid zone file'}
        elif not valid and not nonstandard:
            return {'error': 'Not replicating invalid zone file'}
        else:
            pass

    if txid is None or user_data is None:
        # load zonefile and txid from queue?
        queued_data = queuedb_find('update', name, path=queue_path)
        if queued_data:
            # find the current one (get raw zonefile)
            log.debug("%s updates queued for %s" % (len(queued_data), name))
            for queued_zfdata in queued_data:
                update_data = queue_extract_entry(queued_zfdata)
                zfdata = update_data.get('zonefile', None)
                if zfdata is None:
                    continue

                user_data = zfdata
                txid = queued_zfdata.get('tx_hash', None)
                break

        if user_data is None:
            # not in queue.  Maybe it's available from one of the storage drivers?
            log.debug('no pending updates for "{}"; try storage'.format(name))
            user_data = get_name_zonefile( name, raw_zonefile=True )
            if user_data is None:
                user_data = {'error': 'No data loaded'}

            if 'error' in user_data:
                msg = 'Failed to get zonefile: {}'
                log.error(msg.format(user_data['error']))
                return user_data

            user_data = user_data['zonefile']

        # have user data
        zonefile_hash = storage.get_zonefile_data_hash(user_data)

        if txid is None:
            # not in queue.  Fetch from blockstack server

            name_rec = get_name_blockchain_record(name, proxy=proxy)
            if 'error' in name_rec:
                msg = 'Failed to get name record for {}: {}'
                log.error(msg.format(name, name_rec['error']))
                msg = 'Failed to get name record to look up tx hash.'
                return {'error': msg}

            # find the tx hash that corresponds to this zonefile
            if name_rec['op'] == NAME_UPDATE:
                if name_rec['value_hash'] == zonefile_hash:
                    txid = name_rec['txid']
            else:
                name_history = name_rec['history']
                for history_key in reversed(sorted(name_history)):
                    name_history_item = name_history[history_key]

                    op = name_history_item.get('op', None)
                    if op is None:
                        continue

                    if op != NAME_UPDATE:
                        continue

                    value_hash = name_history_item.get('value_hash', None)

                    if value_hash is None:
                        continue

                    if value_hash != zonefile_hash:
                        continue

                    txid = name_history_item.get('txid', None)
                    break

        if txid is None:
            log.error('Unable to lookup txid for update {}, {}'.format(name, zonefile_hash))
            return {'error': 'Unable to lookup txid that wrote zonefile'}

    # can proceed to replicate
    res = zonefile_data_replicate(
        name, user_data, txid,
        ((conf['server'], conf['port'])),
        config_path=config_path
    )

    if 'error' in res:
        log.error('Failed to replicate zonefile: {}'.format(res['error']))
        return res

    return {'status': True, 'value_hash': zonefile_hash}


def cli_convert_legacy_profile(args, config_path=CONFIG_PATH):
    """
    command: convert_legacy_profile advanced
    help: Convert a legacy profile into a modern profile.
    arg: path (str) 'Path on disk to the JSON file that contains the legacy profile data from Onename'
    """

    profile_json_str, profile = None, None

    try:
        with open(args.path, 'r') as f:
            profile_json_str = f.read()

        profile = json.loads(profile_json_str)
    except:
        return {'error': 'Failed to load profile JSON'}

    # should have 'profile' key
    if 'profile' not in profile:
        return {'error': 'JSON has no "profile" key'}

    profile = profile['profile']
    profile = blockstack_profiles.get_person_from_legacy_format(profile)

    return profile


def get_app_name(appname):
    """
    Get the application name, or if not given, the default name
    """
    return appname if appname is not None else '_default'


def cli_app_publish( args, config_path=CONFIG_PATH, interactive=False, password=None, proxy=None ):
    """
    command: app_publish advanced
    help: Publish a Blockstack application
    arg: name (str) 'The name that will own the application'
    arg: methods (str) 'A comma-separated list of API methods this application will call'
    arg: index_file (str) 'The path to the index file'
    opt: appname (str) 'The name of the application, if different from name'
    opt: urls (str) 'A comma-separated list of URLs to publish the index file to'
    opt: drivers (str) 'A comma-separated list of storage drivers for clients to use'
    """
   
    config_dir = os.path.dirname(config_path)
    if proxy is None:
        proxy = get_default_proxy(config_path)

    index_file_data = None
    try:
        with open(args.index_file, 'r') as f:
            index_file_data = f.read()

    except:
        return {'error': 'Failed to load index file'}

    methods = None
    if hasattr(args, 'methods') and args.methods is not None:
        methods = args.methods.split(',')
        # TODO: validate
        
    else:
        methods = []

    appname = get_app_name( getattr(args, 'appname', None) )
    drivers = []
    if hasattr(args, 'drivers'):
        drivers = args.drivers.split(",")

    fq_index_data_id = app_make_resource_data_id( args.name, appname, "index.html" )
    uris = []
    if not hasattr(args, 'urls') or args.urls is not None:
        urls = args.urls.split(',')
    
    else:
        urls = get_driver_urls( fq_index_data_id, get_storage_handlers() )

    uris = [url_to_uri_record(u, datum_name=fq_index_data_id) for u in urls]

    # RPC daemon must be running 
    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    res = app_publish( args.name, appname, methods, uris, index_file_data, app_driver_hints=drivers, wallet_keys=wallet_keys, proxy=proxy, config_path=config_path )
    if 'error' in res:
        return res

    return {'status': True}


def cli_app_get_config( args, config_path=CONFIG_PATH, interactive=False, proxy=None ):
    """
    command: get_app_config advanced
    help: Get the configuration structure for an application.
    arg: name (str) 'The name that owns the app'
    opt: appname (str) 'The name of the app, if different from the owning name'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    name = args.name
    appname = get_app_name( getattr(args, 'appname', None) )

    app_config = app_get_config(name, appname, proxy=proxy, config_path=config_path )
    return app_config


def cli_app_get_index_file( args, config_path=CONFIG_PATH, interactive=False, proxy=None ):
    """
    command: app_get_index_file advanced
    help: Get an application's index file from mutable storage.
    arg: name (str) 'The name that owns the app'
    opt: appname (str) 'The name of the app, if different from the owning name'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    name = args.name
    appname = get_app_name( getattr(args, 'appname', None) )

    res = app_get_index_file( name, appname, proxy=proxy, config_path=config_path )
    return res


def cli_app_get_resource( args, config_path=CONFIG_PATH, interactive=False, proxy=None ):
    """
    command: app_get_resource advanced
    help: Get an application resource from mutable storage.
    arg: name (str) 'The name that owns the app'
    arg: resname (str) 'The name of the resource'
    opt: appname (str) 'The name of the app, if different from the owning name'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    name = args.name
    appname = get_app_name( getattr(args, 'appname', None) )
    resname = args.resname

    res = app_get_resource( name, appname, resname, proxy=proxy, config_path=config_path )
    return res


def cli_app_put_resource( args, config_path=CONFIG_PATH, interactive=False, proxy=None ):
    """
    command: app_put_resource advanced
    help: Get an application resource from mutable storage.
    arg: name (str) 'The name that owns the app'
    arg: resname (str) 'The name of the resource'
    arg: res_file (str) 'The file with the resource data'
    opt: appname (str) 'The name of the app, if different from the owning name'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    name = args.name
    appname = get_app_name( getattr(args, 'appname', None) )
    resname = args.resname

    resdata = None
    if not os.path.exists(args.res_file):
        return {'error': 'No such file or directory'}

    with open(args.res_file, "r") as f:
        resdata = f.read()

    res = app_put_resource( name, appname, resname, resdata, proxy=proxy, config_path=config_path )
    return res


def cli_app_get_account( args, config_path=CONFIG_PATH, proxy=None ):
    """
    command: app_get_account advanced
    help: Get an application's local user account and datastore information.
    arg: user_id (str) 'The user ID that owns the account'
    arg: app_blockchain_id (str) 'The blockchain ID that owns the application'
    arg: app_name (str) 'The name of the application'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    config_dir = os.path.dirname(config_path)
    user_id = str(args.user_id)
    app_fqu = str(args.app_blockchain_id)
    appname = str(args.app_name)
 
    _, _, master_data_pubkey = get_addresses_from_file(config_dir=config_dir)
    if not master_data_pubkey:
        return {'error': 'No wallet'}

    datastore_info = get_account_datastore_info( master_data_pubkey, None, user_id, app_fqu, appname, proxy=proxy )
    if 'error' in datastore_info:
        return datastore_info

    acct = datastore_info['account']
    datastore = datastore_info['datastore']

    return {
        'account': acct,
        'datastore': datastore
    }


def cli_app_list_accounts( args, config_path=CONFIG_PATH, proxy=None ):
    """
    command: app_list_accounts advanced
    help: List all local application user accounts.  Does not include datastores.
    opt: user_id (str) 'Only list accounts owned by this user.  Pass * for all.'
    opt: app_blockchain_id (str) 'Only list accounts for apps owned by this blockchain ID.  Pass * for all.'
    opt: app_name (str) 'Only list accounts for apps for this particular application.  Pass * for all.'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    user_id = getattr(args, 'user_id', None)
    app_blockchain_id = getattr(args, "app_blockchain_id", None)
    app_name = getattr(args, 'app_name', None)

    if user_id == '*':
        user_id = None

    if app_blockchain_id == '*':
        app_blockchain_id = None

    if app_name == '*':
        app_name = None

    _, _, data_pubkey = get_addresses_from_file(config_dir=config_dir)
    if not data_pubkey:
        return {'error': 'No wallet'}

    all_accounts = app_accounts_list( user_id=user_id, app_fqu=app_blockchain_id, appname=app_name, config_path=config_path )
    return all_accounts


def cli_app_put_account( args, config_path=CONFIG_PATH, interactive=False, proxy=None, password=None ):
    """
    command: app_put_account advanced
    help: Create a local user account and datastore for an application.
    arg: user_id (str) 'The user ID that owns the account'
    arg: app_blockchain_id (str) 'The blockchain ID that owns the application'
    arg: app_name (str) 'The name of the application'
    arg: api_methods (str) 'A CSV of API methods this application may call'
    opt: session_lifetime (int) 'How long an application session will last (in seconds).'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    user_id = str(args.user_id)
    app_fqu = str(args.app_blockchain_id)
    app_name = str(args.app_name)
    api_methods = str(args.api_methods).split(',')
    session_lifetime = getattr(args, 'session_lifetime', None)
    
    if session_lifetime is None:
        session_lifetime = 3600*24*7     # 1 week

    # TODO: validate API methods

    # RPC daemon must be running
    config_dir = os.path.dirname(config_path)
    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    master_data_privkey = wallet_keys['data_privkey']
    master_data_pubkey = get_pubkey_hex(master_data_privkey)
    
    # load user 
    res = user_load( user_id, master_data_pubkey, config_path=config_path )
    if 'error' in res:
        return res

    user = res['user']
    user_privkey_hex = user_get_privkey( master_data_privkey, user )
    if user_privkey_hex is None:
        return {'error': 'Failed to load user private key'}

    # make the account
    res = app_make_account( user, user_privkey_hex, app_fqu, app_name, api_methods, config_path=config_path, session_lifetime=session_lifetime )
    if 'error' in res:
        return res

    acct = res['account']
    tok = res['account_token']

    # store the account
    res = app_store_account( tok, config_path=config_path )
    if 'error' in res:
        return res

    # make the account datastore
    datastore_info = make_account_datastore( acct, user_privkey_hex, config_path=config_path )
    if 'error' in datastore_info:
        return datastore_info

    res = put_account_datastore( acct, datastore_info, user_privkey_hex, proxy=proxy, config_path=config_path )
    if 'error' in res:
        return res

    return {
        'account': acct,
        'datastore': datastore_info['datastore']
    }


def _delete_account_info( user_id, app_fqu, appname, wallet_keys, config_path=CONFIG_PATH, proxy=None ):
    """
    Delete an account's datastore and its files and directories.
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    master_data_privkey = wallet_keys['data_privkey']
    master_data_pubkey = get_pubkey_hex(master_data_privkey)

    datastore_info = get_account_datastore_info( master_data_pubkey, master_data_privkey, user_id, app_fqu, appname, proxy=proxy )
    if 'error' in datastore_info:
        return datastore_info

    user = datastore_info['user']
    user_privkey_hex = datastore_info['user_privkey']
    acct = datastore_info['account']
    datastore = datastore_info['datastore']
    datastore_privkey_hex = datastore_info['datastore_privkey']

    res = delete_account_datastore(acct, user_privkey_hex, force=False, config_path=config_path, proxy=proxy )
    if 'error' in res:
        return res

    res = app_delete_account( user_id, acct['name'], acct['appname'], config_path=config_path )
    if 'error' in res:
        return res

    return {'status': True}


def cli_app_delete_account( args, config_path=CONFIG_PATH, proxy=None, password=None ):
    """
    command: app_delete_account advanced
    help: Delete a local user account and datastore for an application.
    arg: user_id (str) 'The user ID that owns the account'
    arg: app_blockchain_id (str) 'The blockchain ID that owns the application'
    arg: app_name (str) 'The name of the application'
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    user_id = str(args.user_id)
    app_fqu = str(args.app_blockchain_id)
    appname = str(args.app_name)

    config_dir = os.path.dirname(config_path)

    # RPC daemon must be running 
    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    res = _delete_account_info( user_id, app_fqu, appname, wallet_keys, config_path=config_path, proxy=proxy )
    return res


def cli_get_user(args, proxy=None, config_path=CONFIG_PATH):
    """
    command: get_user advanced
    help: Get a persona associated with your identity
    arg: user_id (str) 'The ID of the user to look up'
    """
    config_dir = os.path.dirname(config_path)
    proxy = get_default_proxy(config_path=config_path) if proxy is None else proxy
   
    _, _, data_pubkey = get_addresses_from_file(config_dir=config_dir)
    if not data_pubkey:
        return {'error': 'No wallet'}

    user_id = str(args.user_id)

    res = user_load(user_id, data_pubkey, config_path=config_path)
    if 'error' in res:
        return res

    user = res['user']
    return user


def cli_create_user(args, proxy=None, password=None, config_path=CONFIG_PATH):
    """
    command: create_user advanced
    help: Create a persona associated with your identity.
    arg: user_id (str) 'A pet name for the persona'
    """

    config_dir = os.path.dirname(config_path)
    proxy = get_default_proxy(config_path=config_path) if proxy is None else proxy

    user_id = str(args.user_id)

    # RPC daemon must be running 
    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    master_data_privkey = str(wallet_keys['data_privkey'])
    res = user_init(user_id, master_data_privkey, config_path=config_path)
    if 'error' in res:
        return res

    user = res['user']
    tok = res['user_token']

    res = user_store(tok, config_path=config_path)
    if 'error' in res:
        return res

    return {'status': True}


def cli_delete_user(args, proxy=None, password=None, wallet_keys=None, config_path=CONFIG_PATH):
    """
    command: delete_user advanced
    help: Delete a persona associated with your identity.  All assocated accounts and data stores will also be deleted.
    arg: user_id (str) 'The ID of the user to delete'
    """
    
    config_dir = os.path.dirname(config_path)
    proxy = get_default_proxy(config_path=config_path) if proxy is None else proxy

    user_id = str(args.user_id)

    if password is None:
        # RPC daemon must be running 
        res = start_rpc_endpoint(config_dir, password=password)
        if 'error' in res:
            return res

        wallet_keys = get_wallet_keys(config_path, password)
        if 'error' in wallet_keys:
            return wallet_keys

    master_data_privkey = wallet_keys['data_privkey']
    master_data_pubkey = get_pubkey_hex(master_data_privkey)

    res = user_load(user_id, master_data_pubkey, config_path=config_path)
    if 'error' in res:
        return res

    user = res['user']
    user_privkey_hex = user_get_privkey(master_data_privkey, user)
    if user_privkey_hex is None:
        return {'error': 'Failed to get user private key'}

    # find and delete all accounts and account datastores
    user_accts = app_find_accounts( user_id=user_id, user_pubkey_hex=str(user['public_key']), config_path=config_path )
    if 'error' in user_accts:
        return user_accts

    for account in user_accts:
        app_fqu = account['name']
        appname = account['appname']

        res = _delete_account_info(user_id, app_fqu, appname, wallet_keys, config_path=config_path, proxy=proxy )
        if 'error' in res:
            log.error("Failed to delete account {}/{}".format(app_fqu, appname))
            return res

    # find and delete all user datastores
    datastore_listing = datastore_list(config_path=config_path)
    if 'error' in datastore_listing:
        return datastore_listing

    for datastore_entry in datastore_listing:
        if user_id != datastore_listing['user_id']:
            continue
        
        datastore_id = datastore_listing['datastore_name']
       
        res = delete_user_datastore(user, datastore_id, user_privkey_hex, rmtree=True, force=False, config_path=config_path, proxy=proxy )
        if 'error' in res:
            log.error("Failed to delete datastore {}".format(datastore_id))
            return res

    # delete the user itself
    res = user_delete( user_id, config_path=config_path )
    if 'error' in res:
        return res

    return {'status': True}


def cli_list_users( args, proxy=None, password=None, config_path=CONFIG_PATH ):
    """
    command: list_users advanced
    help: List all identity personas available on this computer.
    """
    config_dir = os.path.dirname(config_path)
    proxy = get_default_proxy(config_path=config_path) if proxy is None else proxy
   
    _, _, data_pubkey = get_addresses_from_file(config_dir=config_dir)
    if not data_pubkey:
        return {'error': 'No wallet'}

    ret = users_list( data_pubkey, config_path=config_path )
    return ret


def cli_get_user_profile(args, proxy=None, config_path=CONFIG_PATH):
    """
    command: get_user_profile advanced
    help: Get a profile for a persona.
    arg: user_id (str) 'The ID of the user to query.'
    """

    config_dir = os.path.dirname(config_path)
    proxy = get_default_proxy(config_path=config_path) if proxy is None else proxy
   
    _, _, data_pubkey = get_addresses_from_file(config_dir=config_dir)
    if not data_pubkey:
        return {'error': 'No wallet'}

    user_id = str(args.user_id)

    res = user_load(user_id, data_pubkey, config_path=config_path)
    if 'error' in res:
        return res

    user = res['user']

    res = get_user_profile( str(args.user_id), user_data_pubkey=str(user['public_key']), use_zonefile_urls=False )
    if res is None:
        return {'error': 'No such profile'}

    return res


def cli_put_user_profile(args, proxy=None, password=None, config_path=CONFIG_PATH):
    """
    command: put_user_profile advanced
    help: Set a profile for a user persona.
    arg: user_id (str) 'The ID of the user to to receive the profile'
    arg: data (str) 'A JSON-formatted profile data string, or a path to a file with such data'
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)
    
    config_dir = os.path.dirname(config_path)

    user_id = str(args.user_id)
    profile_json_str = str(args.data)

    profile = None
    if is_valid_path(profile_json_str) and os.path.exists(profile_json_str):
        # this is a path.  try to load it
        try:
            with open(profile_json_str, 'r') as f:
                profile_json_str = f.read()
        except:
            return {'error': 'Failed to load "{}"'.format(profile_json_str)}

    # try to parse it
    try:
        profile = json.loads(profile_json_str)
    except:
        return {'error': 'Invalid profile JSON'}

    # RPC daemon must be running 
    res = start_rpc_endpoint(config_dir, password=password)
    if 'error' in res:
        return res

    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    master_data_privkey = wallet_keys['data_privkey']
    master_data_pubkey = get_pubkey_hex(master_data_privkey)

    user = None
    res = user_load(user_id, master_data_pubkey, config_path=config_path)
    if 'error' in res:
        return res
                
    user = res['user']
    user_privkey_hex = user_get_privkey(master_data_privkey, user)
    if user_privkey_hex is None:
        return {'error': 'Failed to get user private key'}

    res = put_profile(user_id, profile, user_data_privkey=user_privkey_hex, proxy=proxy)
    return res


def cli_delete_user_profile(args, proxy=None, config_path=CONFIG_PATH, password=None, wallet_keys=None):
    """
    command: delete_user_profile advanced
    help: Delete a profile for a persona.
    arg: user_id (str) 'The ID of the user whose profile will be deleted.'
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    config_dir = os.path.dirname(config_path)

    user_id = str(args.user_id)

    if wallet_keys is None:
        # RPC daemon must be running 
        res = start_rpc_endpoint(config_dir, password=password)
        if 'error' in res:
            return res

        wallet_keys = get_wallet_keys(config_path, password)
        if 'error' in wallet_keys:
            return wallet_keys

    master_data_privkey = wallet_keys['data_privkey']
    master_data_pubkey = get_pubkey_hex(master_data_privkey)

    res = user_load(user_id, master_data_pubkey, config_path=config_path)
    if 'error' in res:
        return res

    user = res['user']
    user_privkey_hex = user_get_privkey(master_data_privkey, user)
    if user_privkey_hex is None:
        return {'error': 'Failed to get user private key'}

    res = delete_profile(user_id, user_data_privkey=user_privkey_hex)
    return res


def cli_sign_profile( args, config_path=CONFIG_PATH, proxy=None, password=None, interactive=False ):
    """
    command: sign_profile
    help: Sign a JSON file to be used as a profile.
    arg: path (str) 'The path to the profile data on disk.'
    opt: privkey (str) 'The optional private key to sign it with (defaults to the data private key in your wallet)'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)
    
    config_dir = os.path.dirname(config_path)
    path = str(args.path)
    data_json = None
    try:
        with open(path, 'r') as f:
            dat = f.read()
            data_json = json.loads(dat)
    except Exception as e:
        if os.environ.get("BLOCKSTACK_DEBUG") == "1":
            log.exception(e)

        log.error("Failed to load {}".format(path))
        return {'error': 'Failed to load {}'.format(path)}

    privkey = None
    if hasattr(args, "privkey") and args.privkey:
        privkey = str(args.privkey)

    else:
        res = wallet_ensure_exists(config_dir, password=password)
        if 'error' in res:
            return res

        res = start_rpc_endpoint(config_dir, password=password)
        if 'error' in res:
            return res

        wallet_keys = get_wallet_keys( config_path, password )
        if 'error' in wallet_keys:
            return wallet_keys

        if not wallet_keys.has_key('data_privkey'):
            log.error("No data private key in the wallet.  You may need to explicitly select a private key.")
            return {'error': 'No data private key set.\nTry passing your owner private key.'}

        privkey = wallet_keys['data_privkey']

    privkey = ECPrivateKey(privkey).to_hex()
    pubkey = get_pubkey_hex(privkey)

    res = storage.serialize_mutable_data(data_json, privkey, pubkey, profile=True)
    if res is None:
        return {'error': 'Failed to sign and serialize profile'}

    # sanity check 
    assert storage.parse_mutable_data(res, pubkey)
    return json.loads(res) 


def make_account_datastore(account_info, user_privkey_hex, driver_names=None, config_path=CONFIG_PATH ):
    """
    Create a datastore for a particular application account.

    Return {'datastore': datastore information, 'root': root inode}
    """
    ds_info = _get_account_datastore_creds(account_info, user_privkey_hex)
    user_id = ds_info['user_id']
    datastore_name = ds_info['datastore_name']
    datastore_privkey_hex = ds_info['datastore_privkey']

    return make_datastore( user_id, datastore_name, datastore_privkey_hex, driver_names=driver_names, config_path=config_path )


def _get_account_datastore_name(account_info):
    """
    Get the name for an account datastore
    """
    user_id = account_info['user_id']
    app_fqu = account_info['name']
    appname = account_info['appname']

    datastore_name = app_account_datastore_name( app_account_name(user_id, app_fqu, appname) )
    return datastore_name


def _get_account_datastore_creds( account_info, user_privkey_hex ):
    """
    Get an account datastore's name and private key
    """
    datastore_privkey_hex = app_account_get_privkey( user_privkey_hex, account_info )
    user_id = account_info['user_id']
    datastore_name = _get_account_datastore_name(account_info)

    return {'user_id': user_id, 'datastore_name': datastore_name, 'datastore_privkey': datastore_privkey_hex}


def get_account_datastore(account_info, proxy=None, config_path=CONFIG_PATH ):
    """
    Get the datastore for the given account
    @account_info is the account information
    return {'status': True} on success
    return {'error': ...} on failure
    """
    user_id = account_info['user_id']
    datastore_name = _get_account_datastore_name(account_info)
    datastore_pubkey = str(account_info['public_key'])
    log.debug("Get account datastore {}".format(datastore_name))
    return get_datastore(user_id, datastore_name, datastore_pubkey, config_path=config_path, proxy=proxy ) 


def get_user_datastore(user_info, datastore_name, proxy=None, config_path=CONFIG_PATH ):
    """
    Get the datastore for the given user
    @account_info is the account information
    return {'status': True} on success
    return {'error': ...} on failure
    """
    user_id = user_info['user_id']
    datastore_pubkey = str(user_info['public_key'])
    log.debug("Get user datastore {}".format(datastore_name))
    return get_datastore(user_id, datastore_name, datastore_pubkey, config_path=config_path, proxy=proxy ) 


def put_account_datastore(account_info, datastore_info, user_privkey_hex, proxy=None, config_path=CONFIG_PATH ):
    """
    Create and store a new datastore for the given account.
    @account_info is the account information
    @datastore_info is the datastore information 
    return {'status': True} on success
    return {'error': ...} on failure
    """
    ds_info = _get_account_datastore_creds(account_info, user_privkey_hex)
    user_id = ds_info['user_id']
    datastore_name = ds_info['datastore_name']
    datastore_privkey_hex = ds_info['datastore_privkey']
    log.debug("Put account datastore {}".format(datastore_name))
    return put_datastore(user_id, datastore_name, datastore_info, datastore_privkey_hex, proxy=proxy, config_path=config_path)


def put_user_datastore(user_info, datastore_name, datastore_info, user_privkey_hex, proxy=None, config_path=CONFIG_PATH ):
    """
    Create and store a new datastore for the given user
    return {'status': True} on success
    return {'error': ...} on failure
    """
    user_id = user_info['user_id']
    log.debug("Put user datastore {}".format(datastore_name))
    return put_datastore(user_id, datastore_name, datastore_info, user_privkey_hex, proxy=None, config_path=CONFIG_PATH )


def delete_account_datastore(account_info, user_privkey_hex, rmtree=True, force=False, config_path=CONFIG_PATH, proxy=None ):
    """
    Delete an account datastore
    If rmtree is True, then the datastore will be emptied first.
    If force is True, then the datastore will be deleted even if rmtree fails.
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    ds_info = _get_account_datastore_creds(account_info, user_privkey_hex)
    user_id = ds_info['user_id']
    datastore_name = ds_info['datastore_name']
    datastore_privkey = ds_info['datastore_privkey']

    # clear the datastore
    if rmtree:
        datastore_rec = get_account_datastore(account_info, proxy=proxy, config_path=config_path)
        if 'error' in datastore_rec:
            return datastore_rec
        
        datastore = datastore_rec['datastore']

        log.debug("Clear account datastore {}".format(datastore_name))
        res = datastore_rmtree(datastore, '/', datastore_privkey, config_path=config_path, proxy=proxy)
        if 'error' in res and not force:
            log.error("Failed to rmtree account datastore {}".format(datastore_name))
            return {'error': 'Failed to remove all files and directories'}

    # delete the datastore record
    log.debug("Delete account datastore {}".format(datastore_name))
    return delete_datastore(user_id, datastore_name, datastore_privkey, force=force, config_path=config_path, proxy=proxy)


def delete_user_datastore(user_info, datastore_name, user_privkey_hex, rmtree=True, force=False, config_path=CONFIG_PATH, proxy=None ):
    """
    Delete a user datastore
    If rmtree is True, then the datastore will be emptied first.
    If force is True, then the datastore will be deleted even if rmtree fails
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    user_id = user_info['user_id']

    # clear the datastore 
    if rmtree:
        datastore_rec = get_user_datastore(user_info, datastore_name, proxy=proxy, config_path=config_path)
        if 'error' in datastore_rec:
            return datastore_rec

        datastore = datastore_rec['datastore']

        log.debug("Clear user datastore {}".format(datastore_name))
        res = datastore_rmtree(datastore, '/', user_privkey_hex, config_path=config_path, proxy=proxy)
        if 'error' in res and not force:
            log.error("Failed to rmtree user datastore {}".format(datastore_name))
            return {'error': 'Failed to remove all files and directories'}

    # delete the datastore record
    log.debug("Delete user datastore {}".format(datastore_name))
    return delete_datastore(user_id, datastore_name, user_privkey_hex, force=force, config_path=config_path, proxy=proxy )


def get_account_datastore_info( master_data_pubkey, master_data_privkey, user_id, app_fqu, app_name, config_path=CONFIG_PATH, proxy=None ):
    """
    Get information about an account datastore.
    At least, get the user and account owner.
    If master_data_privkey is not None, then also get the datastore private key.

    Return {'status': True, 'user': user, 'user_privkey': ..., 'account': account, 'datastore': ..., 'datastore_privkey': ...} on success.
    If master_data_privkey is not given, then user_privkey and datastore_privkey will not be provided.

    Return {'error': ...} on failure
    """
   
    res = user_load(user_id, master_data_pubkey, config_path=config_path)
    if 'error' in res:
        return res

    user = res['user']
    user_privkey_hex = None

    if master_data_privkey is not None:
        user_privkey_hex = user_get_privkey(master_data_privkey, user)
        if user_privkey_hex is None:
            return {'error': 'Failed to load user private key'}
    
    res = app_load_account(user_id, app_fqu, app_name, user['public_key'], config_path=config_path)
    if 'error' in res:
        return res

    acct = res['account']

    res = get_account_datastore(acct, proxy=proxy, config_path=config_path)
    if 'error' in res:
        log.debug("Failed to get datastore for {}".format(user_id))
        return res

    datastore = res['datastore']
    datastore_privkey_hex = None

    if user_privkey_hex is not None:
        datastore_privkey_hex = app_account_get_privkey( user_privkey_hex, acct )
        if datastore_privkey_hex is None:
            return {'error': 'Failed to load app account private key'}


    ret = {
        'user': user,
        'account': acct,
        'datastore': datastore,
        'status': True
    }

    if user_privkey_hex is not None:
        ret['user_privkey'] = user_privkey_hex

    if datastore_privkey_hex is not None:
        ret['datastore_privkey'] = datastore_privkey_hex

    return ret


def get_user_datastore_info( master_data_pubkey, master_data_privkey, user_id, datastore_name, config_path=CONFIG_PATH, proxy=None ):
    """
    Get information about a datastore that belongs directly to a user (without an account)
    If master_data_privkey is not None, then also get the datastore private key.

    Return {'status': True, 'user': user, 'user_privkey': ..., 'datastore': ..., 'datastore_privkey': ...} on success.
    If master_data_privkey is not given, then user_privkey and datastore_privkey will not be provided.

    Return {'error': ...} on failure
    """
    
    res = user_load(user_id, master_data_pubkey, config_path=config_path)
    if 'error' in res:
        return res

    user = res['user']
    user_pubkey = user['public_key']
    user_privkey_hex = None

    if master_data_privkey is not None:
        user_privkey_hex = user_get_privkey(master_data_privkey, user)
        if user_privkey_hex is None:
            return {'error': 'Failed to load user private key'}
    
    res = get_user_datastore(user, datastore_name, proxy=proxy, config_path=config_path)
    if 'error' in res:
        return res
    
    datastore = res['datastore']
    datastore_privkey_hex = user_privkey_hex

    ret = {
        'user': user,
        'datastore': datastore,
        'status': True
    }

    if datastore_privkey_hex is not None:
        ret['datastore_privkey'] = datastore_privkey_hex

    return ret


def get_datastore_name_info( user_id, datastore_id ):
    """
    Parse a datastore ID into an application blockchain ID and name, if 
    the datastore ID refers to an account-owned datastore.
    
    Return {'app_fqu': app_fqu, 'appname': appname, 'datastore_name': datastore_name} on success
    Return {'error': ...} on error
    """
    account_name_parts = app_account_parse_datastore_name(datastore_id)
    app_fqu = None
    appname = None
    datastore_name = None

    if account_name_parts is not None:
        # this is an account-specific datastore
        if user_id != account_name_parts['user_id']:
            return {'error': 'Invalid user ID for given data store name'}

        app_fqu = account_name_parts['app_blockchain_id']
        appname = account_name_parts['app_name']
    
    else:
        # this is a generic datastore
        datastore_name = datastore_id

    return {'app_fqu': app_fqu, 'appname': appname, 'datastore_name': datastore_name}


def get_datastore_info( user_id, datastore_id, include_private=False, config_path=CONFIG_PATH, proxy=None, password=None, wallet_keys=None ):
    """
    Get datastore information
    Returns {
        'datastore': datastore record,
        'datastore_privkey': datastore private key (if include_private is True).  Hex-encoded
        'app_fqu': name that points to application that owns the datastore (if defined)
        'appname': name of application that owns the datastore (if defined)
        'datastore_name': name of datastore
        'master_data_pubkey': master data public key
        'master_data_privkey': master data private key (only given if include_private is True)
    }

    Returns {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    config_dir = os.path.dirname(config_path)

    account_name_parts = app_account_parse_datastore_name(datastore_id)
    app_fqu = None
    appname = None
    datastore_name = None
    master_data_privkey = None
    datastore_privkey_hex = None

    name_info = get_datastore_name_info(user_id, datastore_id)
    if 'error' in name_info:
        # user ID mismatch
        return name_info

    app_fqu = name_info['app_fqu']
    appname = name_info['appname']
    datastore_name = name_info['datastore_name']

    _, _, master_data_pubkey = get_addresses_from_file(config_dir=config_dir)
    if not master_data_pubkey:
        return {'error': 'No wallet'}

    if include_private:
        # RPC daemon must be running 
        res = start_rpc_endpoint(config_dir, password=password)
        if 'error' in res:
            return res

        if wallet_keys is None:
            wallet_keys = get_wallet_keys(config_path, password)
            if 'error' in wallet_keys:
                return wallet_keys

        master_data_privkey = wallet_keys['data_privkey']

    datastore_info = None
    datastore = None

    if app_fqu is not None and appname is not None:
        datastore_info = get_account_datastore_info( str(master_data_pubkey), master_data_privkey, user_id, app_fqu, appname, config_path=config_path, proxy=proxy )

    else:
        datastore_info = get_user_datastore_info( str(master_data_pubkey), master_data_privkey, user_id, datastore_name, config_path=config_path, proxy=proxy )

    if 'error' in datastore_info:
        log.error("Failed to get datastore information")
        return datastore_info

    datastore = datastore_info['datastore']
    if include_private:
        datastore_privkey_hex = datastore_info['datastore_privkey']

    ret = {
        'datastore': datastore,
        'datastore_privkey': datastore_privkey_hex,
        'datastore_info': datastore_info,
        'app_fqu': app_fqu,
        'appname': appname,
        'datastore_name': datastore_name,
        'master_data_pubkey': master_data_pubkey,
        'master_data_privkey': master_data_privkey
    }

    return ret


def cli_get_datastore( args, config_path=CONFIG_PATH, proxy=None, password=None, wallet_keys=None ):
    """
    command: get_datastore advanced
    help: Get a datastore record
    arg: user_id (str) 'The user ID that owns the datastore'
    arg: datastore_id (str) 'The ID of the datastore'
    opt: include_private (str) 'If True, then include the private key information as well'
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    user_id = str(args.user_id)
    datastore_id = str(args.datastore_id)
    include_private = str(args.include_private)
    if include_private.lower() in ['1', 'true', 'yes']:
        include_private = True
    else:
        include_private = False

    datastore_info = get_datastore_info(user_id, datastore_id, include_private=include_private, config_path=config_path, proxy=proxy, password=password, wallet_keys=wallet_keys)
    if 'error' in datastore_info:
        return datastore_info

    datastore = datastore_info['datastore']
    return datastore


def cli_list_datastores( args, config_path=CONFIG_PATH, proxy=None, password=None ):
    """
    command: list_datastores advanced
    help: List datastores accessible from this device.
    opt: user_id (str) 'The optional user ID to filter datastores.'
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    user_id = str(args.user_id)
    res = datastore_list( config_path=config_path )

    if len(str(getattr(args, "user_id", ""))) > 0:
        res = filter(lambda ds: ds['user_id'] == str(args.user_id), res)

    return res


def cli_create_datastore( args, config_path=CONFIG_PATH, proxy=None, password=None, wallet_keys=None ):
    """
    command: create_datastore advanced
    help: Make a new datastore for a given user.
    arg: user_id (str) 'The user ID'
    arg: datastore_id (str) 'The ID of the datastore'
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)
    
    config_dir = os.path.dirname(config_path)
    user_id = str(args.user_id)
    datastore_id = str(args.datastore_id)

    name_info = get_datastore_name_info( user_id, datastore_id )
    if 'error' in name_info or (name_info['app_fqu'] is not None and name_info['appname'] is not None):
        return {'error': 'Cannot create app-specific data store with this command.  Use app_put_account for that.'}

    datastore_info = get_datastore_info(user_id, datastore_id, config_path=config_path, proxy=proxy, password=password, wallet_keys=wallet_keys)
    if 'error' not in datastore_info:
        # already exists
        return {'error': 'Datastore exists'}

    if wallet_keys is None:
        # RPC daemon must be running 
        res = start_rpc_endpoint(config_dir, password=password)
        if 'error' in res:
            return res

        wallet_keys = get_wallet_keys(config_path, password)
        if 'error' in wallet_keys:
            return wallet_keys

    master_data_privkey = wallet_keys['data_privkey']
    master_data_pubkey = get_pubkey_hex(master_data_privkey)

    res = user_load(user_id, master_data_pubkey, config_path=config_path)
    if 'error' in res:
        return res

    user = res['user']
    user_pubkey = user['public_key']
    user_privkey_hex = user_get_privkey(master_data_privkey, user)
    if user_privkey_hex is None:
        return {'error': 'Failed to load user private key'}

    datastore_info = make_datastore(user_id, datastore_id, user_privkey_hex, config_path=CONFIG_PATH)
    if 'error' in datastore_info:
        return datastore_info

    res = put_user_datastore(user, datastore_id, datastore_info, user_privkey_hex, proxy=proxy, config_path=config_path)
    if 'error' in res:
        return res

    return {'status': True}


def cli_delete_datastore( args, config_path=CONFIG_PATH, proxy=None, password=None, wallet_keys=None ):
    """
    command: delete_datastore advanced
    help: Delete a datastore owned by a given user, and all of the data it contains.
    arg: user_id (str) 'The ID of the user that owns the datastore'
    arg: datastore_id (str) 'The ID of the datastore'
    opt: force (str) 'If True, then delete the datastore even if it cannot be emptied'
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    config_dir = os.path.dirname(config_path)
    user_id = str(args.user_id)
    datastore_id = str(args.datastore_id)
    force = (str(args.force).lower() in ['1', 'true', 'force', 'yes'])

    datastore_info = get_datastore_info(user_id, datastore_id, include_private=True, config_path=config_path, proxy=proxy, password=password, wallet_keys=wallet_keys)
    if 'error' in datastore_info:
        return datastore_info

    if datastore_info['app_fqu'] is not None and datastore_info['appname'] is not None:
        return {'error': 'Cannot delete application data store.  Use app_delete_account for that.'}

    datastore = datastore_info['datastore']
    master_data_privkey = datastore_info['master_data_privkey']
    master_data_pubkey = get_pubkey_hex(master_data_privkey)

    res = user_load(user_id, master_data_pubkey, config_path=config_path)
    if 'error' in res:
        return res

    user = res['user']
    user_pubkey = user['public_key']
    user_privkey_hex = user_get_privkey(master_data_privkey, user)
    if user_privkey_hex is None:
        return {'error': 'Failed to load user private key'}

    res = delete_user_datastore(user, datastore_id, user_privkey_hex, rmtree=True, force=force, config_path=config_path, proxy=proxy )
    if 'error' in res:
        log.error("Failed to delete datastore record")
        return res

    return {'status': True}


def cli_datastore_mkdir( args, config_path=CONFIG_PATH, interactive=False, proxy=None, password=None, wallet_keys=None ):
    """
    command: datastore_mkdir advanced
    help: Make a directory in a datastore.
    arg: user_id (str) 'The user ID that owns the datastore'
    arg: datastore_id (str) 'The ID of the datatore'
    arg: path (str) 'The path to the directory to remove'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    user_id = str(args.user_id)
    datastore_id = str(args.datastore_id)
    path = str(args.path)

    datastore_info = get_datastore_info(user_id, datastore_id, include_private=True, config_path=config_path, proxy=proxy, password=password, wallet_keys=wallet_keys)
    if 'error' in datastore_info:
        datastore_info['errno'] = errno.EPERM
        return datastore_info

    datastore = datastore_info['datastore']
    datastore_privkey_hex = datastore_info['datastore_privkey']

    res = datastore_mkdir(datastore, path, datastore_privkey_hex, config_path=config_path, proxy=proxy)
    return res

    
def cli_datastore_rmdir( args, config_path=CONFIG_PATH, interactive=False, proxy=None, password=None, wallet_keys=None ):
    """
    command: datastore_rmdir advanced
    help: Remove a directory in a datastore.
    arg: user_id (str) 'The user ID that owns the datastore'
    arg: datastore_id (str) 'The ID of the datastore'
    arg: path (str) 'The path to the directory to remove'
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    user_id = str(args.user_id)
    datastore_id = str(args.datastore_id)
    path = str(args.path)

    datastore_info = get_datastore_info(user_id, datastore_id, include_private=True, config_path=config_path, proxy=proxy, password=password, wallet_keys=wallet_keys)
    if 'error' in datastore_info:
        datastore_info['errno'] = errno.EPERM
        return datastore_info

    datastore = datastore_info['datastore']
    datastore_privkey_hex = datastore_info['datastore_privkey']

    res = datastore_rmdir(datastore, path, datastore_privkey_hex, config_path=config_path, proxy=proxy )
    return res


def cli_datastore_getfile( args, config_path=CONFIG_PATH, interactive=False, proxy=None ):
    """
    command: datastore_getfile advanced
    help: Get a file from a datastore.
    arg: user_id (str) 'The user ID that owns the datastore'
    arg: datastore_id (str) 'The ID of the datastore'
    arg: path (str) 'The path to the file to load'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    user_id = str(args.user_id)
    datastore_id = str(args.datastore_id)
    path = str(args.path)

    datastore_info = get_datastore_info(user_id, datastore_id, include_private=False, config_path=config_path, proxy=proxy)
    if 'error' in datastore_info:
        datastore_info['errno'] = errno.EPERM
        return datastore_info

    datastore = datastore_info['datastore']

    res = datastore_getfile( datastore, path, config_path=config_path, proxy=proxy )
    return res


def cli_datastore_listdir(args, config_path=CONFIG_PATH, interactive=False, proxy=None ):
    """
    command: datastore_listdir advanced
    help: List a directory in the datastore.
    arg: user_id (str) 'The user ID that owns the datastore'
    arg: datastore_id (str) 'The ID of the datastore'
    arg: path (str) 'The path to the directory to list'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    user_id = str(args.user_id)
    datastore_id = str(args.datastore_id)
    path = str(args.path)

    datastore_info = get_datastore_info(user_id, datastore_id, include_private=False, config_path=config_path, proxy=proxy)
    if 'error' in datastore_info:
        datastore_info['errno'] = errno.EPERM
        return datastore_info

    datastore = datastore_info['datastore']

    res = datastore_listdir( datastore, path, config_path=config_path, proxy=proxy )
    return res


def cli_datastore_stat(args, config_path=CONFIG_PATH, interactive=False, proxy=None ):
    """
    command: datastore_stat advanced
    help: Stat a file or directory in the datastore
    arg: user_id (str) 'The user ID that owns this datastore'
    arg: datastore_id (str) 'The ID of the datastore'
    arg: path (str) 'The path to the file or directory to stat'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    user_id = str(args.user_id)
    datastore_id = str(args.datastore_id)
    path = str(args.path)

    datastore_info = get_datastore_info(user_id, datastore_id, include_private=False, config_path=config_path, proxy=proxy)
    if 'error' in datastore_info:
        datastore_info['errno'] = errno.EPERM
        return datastore_info

    datastore = datastore_info['datastore']

    res = datastore_stat( datastore, path, config_path=config_path, proxy=proxy )
    return res


def cli_datastore_putfile(args, config_path=CONFIG_PATH, interactive=False, proxy=None, password=None, force_data=False, wallet_keys=None ):
    """
    command: datastore_putfile advanced
    help: Put a file into the datastore at the given path.
    arg: user_id (str) 'The user ID that owns the datastore'
    arg: datastore_id (str) 'The ID of the datastore'
    arg: path (str) 'The path to the new file'
    arg: data (str) 'The data to store, or a path to a file with the data'
    opt: create (str) 'If True, then only succeed if the file does not exist already'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    user_id = str(args.user_id)
    datastore_id = str(args.datastore_id)
    path = str(args.path)
    data = args.data
    create = (str(getattr(args, "create", "")).lower() in ['1', 'create', 'true'])

    # is this a path, and are we allowed to take paths?
    if is_valid_path(data) and os.path.exists(data) and not force_data:
        log.warning("Using data in file {}".format(data))
        try:
            with open(data) as f:
                data = f.read()
        except:
            return {'error': 'Failed to read "{}"'.format(data)}

    datastore_info = get_datastore_info(user_id, datastore_id, include_private=True, config_path=config_path, proxy=proxy, password=password, wallet_keys=wallet_keys)
    if 'error' in datastore_info:
        datastore_info['errno'] = errno.EPERM
        return datastore_info

    datastore = datastore_info['datastore']
    datastore_privkey_hex = datastore_info['datastore_privkey']

    res = datastore_putfile( datastore, path, data, datastore_privkey_hex, create=create, config_path=config_path, proxy=proxy )
    return res
    

def cli_datastore_deletefile(args, config_path=CONFIG_PATH, interactive=False, proxy=None, password=None, wallet_keys=None ):
    """
    command: datastore_deletefile advanced
    help: Delete a file from the datastore.
    arg: user_id (str) 'The user ID that owns the datastore'
    arg: datastore_id (str) 'The blockchain ID that owns the application'
    arg: path (str) 'The path to the file to delete'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    user_id = str(args.user_id)
    datastore_id = str(args.datastore_id)
    path = str(args.path)

    datastore_info = get_datastore_info(user_id, datastore_id, include_private=True, config_path=config_path, proxy=proxy, password=password, wallet_keys=wallet_keys)
    if 'error' in datastore_info:
        datastore_info['errno'] = errno.EPERM
        return datastore_info

    datastore = datastore_info['datastore']
    datastore_privkey_hex = datastore_info['datastore_privkey']

    res = datastore_deletefile( datastore, path, datastore_privkey_hex, config_path=config_path, proxy=proxy )
    return res
    

def cli_start_server( args, config_path=CONFIG_PATH, interactive=False ):
    """
    command: start_server advanced
    help: Start a Blockstack server
    opt: foreground (str) 'If True, then run in the foreground.'
    opt: working_dir (str) 'The directory which contains the server state.'
    opt: testnet (str) 'If True, then communicate with Bitcoin testnet.'
    """

    foreground = False
    testnet = False
    working_dir = args.working_dir

    if args.foreground:
        foreground = str(args.foreground)
        foreground = (foreground.lower() in ['1', 'true', 'yes', 'foreground'])

    if args.testnet:
        testnet = str(args.testnet)
        testnet = (testnet.lower() in ['1', 'true', 'yes', 'testnet'])

    cmds = ['blockstack-server', 'start']
    if foreground:
        cmds.append('--foreground')

    if testnet:
        cmds.append('--testnet')

    if working_dir is not None:
        working_dir_envar = 'VIRTUALCHAIN_WORKING_DIR={}'.format(working_dir)
        cmds = [working_dir_envar] + cmds

    cmd_str = " ".join(cmds)
    
    log.debug('Execute: {}'.format(cmd_str))
    exit_status = os.system(cmd_str)

    if not os.WIFEXITED(exit_status) or os.WEXITSTATUS(exit_status) != 0:
        error_str = 'Failed to execute "{}". Exit code {}'.format(cmd_str, exit_status)
        return {'error': error_str}

    return {'status': True}


def cli_stop_server( args, config_path=CONFIG_PATH, interactive=False ):
    """
    command: stop_server advanced
    help: Stop a running Blockstack server
    opt: working_dir (str) 'The directory which contains the server state.'
    """

    working_dir = args.working_dir

    cmds = ['blockstack-server', 'stop']

    if working_dir is not None:
        working_dir_envar = 'VIRTUALCHAIN_WORKING_DIR={}'.format(working_dir)
        cmds = [working_dir_envar] + cmds

    cmd_str = " ".join(cmds)

    log.debug('Execute: {}'.format(cmd_str))
    exit_status = os.system(cmd_str)

    if not os.WIFEXITED(exit_status) or os.WEXITSTATUS(exit_status) != 0:
        error_str = 'Failed to execute "{}". Exit code {}'.format(cmd_str, exit_status)
        return {'error': error_str}

    return {'status': True}

