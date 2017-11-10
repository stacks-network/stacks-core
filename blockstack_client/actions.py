#!/usr/bin/env python2
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
import binascii
from decimal import Decimal
import string
import jsontokens
import keychain

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
    get_name_zonefile, get_nameops_at, get_names_in_namespace, get_names_owned_by_address,
    get_namespace_blockchain_record, get_namespace_cost,
    is_user_zonefile, list_immutable_data_history, list_update_history,
    list_zonefile_history, lookup_snv, put_immutable, put_mutable, zonefile_data_replicate,
    get_historic_names_by_address
)

from blockstack_client import subdomains
from blockstack_client.profile import put_profile, delete_profile, get_profile, \
        profile_add_device_id, profile_remove_device_id, profile_list_accounts, profile_get_account, \
        profile_put_account, profile_delete_account

from rpc import local_api_connect, local_api_status
import rpc as local_rpc
import config

from .config import configure_zonefile, configure, get_utxo_provider_client, get_tx_broadcaster, get_local_device_id
from .constants import (
    CONFIG_PATH, CONFIG_DIR, WALLET_FILENAME,
    FIRST_BLOCK_MAINNET, NAME_UPDATE, NAME_IMPORT, NAME_REGISTRATION, NAME_RENEWAL,
    BLOCKSTACK_DEBUG, TX_MIN_CONFIRMATIONS, DEFAULT_SESSION_LIFETIME,
    get_secret, set_secret, BLOCKSTACK_TEST, VERSION
)

from .storage import get_driver_urls, get_storage_handlers, sign_data_payload, \
    get_zonefile_data_hash

from .backend.blockchain import (
    get_balance, get_utxos, broadcast_tx, select_utxos,
    get_tx_confirmations, get_block_height, get_bitcoind_client
)

from .backend.registrar import get_wallet as registrar_get_wallet

from .backend.nameops import (
    do_namespace_preorder, do_namespace_reveal, do_namespace_ready,
    do_name_import
)

from .backend.safety import (
    check_valid_name, check_valid_namespace, check_operations,
    interpret_operation_fees, get_operation_fees
)
from .backend.queue import queuedb_remove, queuedb_find, queue_append
from .backend.queue import extract_entry as queue_extract_entry

from .wallet import (
    get_total_balance,
    get_all_names_owned,
    get_owner_addresses_and_names,
    get_wallet,
    get_names_owned,
    get_wallet_path,
    get_addresses_from_file,
    getpass,
    backup_wallet,
    is_wallet_unlocked,
    prompt_wallet_password,
    encrypt_wallet,
    write_wallet,
    wallet_setup,
    make_wallet_password,
    make_wallet,
    decrypt_wallet,
    load_wallet,
    wallet_exists,
    unlock_wallet
)

from .keys import privkey_to_string, get_data_privkey
from .proxy import (
    is_zonefile_current, get_default_proxy, json_is_error,
    get_name_blockchain_history, get_all_namespaces, getinfo,
    storage, is_zonefile_data_current, get_num_names
)
from .scripts import UTXOException, is_name_valid, is_valid_hash, is_namespace_valid
from .user import make_empty_user_profile, user_zonefile_data_pubkey

from .tx import serialize_tx, sign_tx
from .zonefile import make_empty_zonefile, url_to_uri_record, decode_name_zonefile

from .utils import exit_with_error, satoshis_to_btc, ScatterGather
from .app import app_publish, app_get_config, app_get_resource, \
        app_put_resource, app_delete_resource

from .data import datastore_mkdir, datastore_rmdir, make_datastore_info, put_datastore, delete_datastore, \
        datastore_getfile, datastore_putfile, datastore_deletefile, datastore_listdir, datastore_stat, \
        datastore_rmtree, datastore_get_id, datastore_get_privkey, \
        datastore_getinode, datastore_get_privkey, \
        make_mutable_data_info, data_blob_parse, data_blob_serialize, make_mutable_data_tombstones, sign_mutable_data_tombstones

from .schemas import (
    OP_URLENCODED_PATTERN, OP_NAME_PATTERN,
    OP_BASE58CHECK_PATTERN, MUTABLE_DATUM_FILE_TYPE)

import keylib

import virtualchain
from virtualchain.lib.ecdsalib import (
    ecdsa_private_key, set_privkey_compressed,
    get_pubkey_hex
)
from virtualchain.lib.hashing import (
    bin_double_sha256
)

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


def wallet_ensure_exists(config_path=CONFIG_PATH):
    """
    Check that the wallet exists
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    if not wallet_exists(config_path=config_path):
        return {'error': 'No wallet exists for {}.  Please create one with `blockstack setup`'.format(config_path)}

    return {'status': True}


def load_zonefile_from_string(fqu, zonefile_data, check_current=True):
    """
    Load a zonefile from a string, which can be
    either JSON or text.  Verify that it is
    well-formed and current.

    Return {'status': True, 'zonefile': the serialized zonefile data (as a string), 'parsed_zonefile': ...} on success.
    Return {'error': ..., 'nonstandard': True/False, 'identical': True/False} if the zonefile is nonstandard and/or identical
    """

    # is this a new, standard zonefile?
    nonstandard = False
    identical = False

    user_data = None
    user_zonefile = None
    try:
        user_data = json.loads(zonefile_data)
    except:
        log.debug('Zonefile is not a serialized JSON string; try parsing as text')
        try:
            user_data = blockstack_zones.parse_zone_file(zonefile_data)
            user_data = dict(user_data)  # force dict. e.g if not defaultdict
        except Exception as e:
            if BLOCKSTACK_DEBUG is not None:
                log.exception(e)

            nonstandard = True

    if user_data is not None:
        try:
            user_zonefile = blockstack_zones.make_zone_file(user_data)
        except Exception as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            log.error('Nonstandard zonefile')
            nonstandard = True

    # sanity checks on the standard-ness
    if not nonstandard:

        if fqu != user_data.get('$origin', ''):
            log.error('Zonefile is missing or has invalid $origin')
            nonstandard = True

        if '$ttl' not in user_data:
            log.error('Zonefile is missing a TTL')
            nonstandard = True

        if not is_user_zonefile(user_data):
            log.error("Zonefile does not match standard schema")
            nonstandard = True

        try:
            ttl = int(user_data['$ttl'])
            assert ttl >= 0
        except Exception as e:
            log.error("Zonefile has an invalid $ttl; must be a positive integer")
            nonstandard = True

    if check_current:
        current = False
        if not nonstandard and user_data is not None:
            current = is_zonefile_current(fqu, user_data)
        else:
            current = is_zonefile_data_current(fqu, zonefile_data)

        if current:
            log.debug('Zonefile data is same as current zonefile; update not needed.')
            identical = True

    if user_zonefile is not None and not identical and not nonstandard:
        return {'status': True, 'zonefile': user_zonefile, 'parsed_zonefile': user_data, 'identical': identical, 'nonstandard': nonstandard}

    elif nonstandard:
        return {'error': 'nonstandard zonefile', 'identical': identical, 'nonstandard': nonstandard}

    else:
        return {'error': 'identical zonefile', 'zonefile': user_zonefile, 'parsed_zonefile': user_data, 'identical': identical, 'nonstandard': nonstandard}


def get_default_password(password):
    """
    Get the default password
    """
    return password if password is not None else get_secret("BLOCKSTACK_CLIENT_WALLET_PASSWORD")


def get_default_interactive(interactive):
    """
    Get default interactive setting
    """
    if os.environ.get("BLOCKSTACK_CLIENT_INTERACTIVE_YES", None) == "1":
        return False
    else:
        return interactive


def cli_setup(args, config_path=CONFIG_PATH, password=None):
    """
    command: setup
    help: Set up your Blockstack installation
    """

    password = get_default_password(password)
    interactive = get_default_interactive(True)

    ret = {}

    log.debug("Set up config file")

    # are we configured?
    opts = config.setup_config(config_path=config_path, interactive=interactive)
    if 'error' in opts:
        return opts

    class WalletSetupArgs(object):
        pass

    wallet_args = WalletSetupArgs()

    # is our wallet ready?
    res = cli_setup_wallet(wallet_args, interactive=interactive, config_path=config_path, password=password)
    if 'error' in res:
        return res

    if 'backup_wallet' in res:
        ret['backup_wallet'] = res['backup_wallet']

    ret['status'] = True
    return ret


def cli_configure(args, config_path=CONFIG_PATH):
    """
    command: configure
    help: Interactively configure the client
    """

    interactive = True
    force = True

    if os.environ.get("BLOCKSTACK_CLIENT_INTERACTIVE_YES", None) == "1":
        interactive = False
        force = False

    opts = configure(interactive=interactive, force=force, config_file=config_path)
    result = {}
    result['path'] = opts['blockstack-client']['path']

    return result


def cli_balance(args, config_path=CONFIG_PATH):
    """
    command: balance
    help: Get the account balance
    opt: min_confs (int) 'The minimum confirmations of transactions to include in balance'
    """

    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    res = wallet_ensure_exists(config_path=config_path)
    if 'error' in res:
        return res

    min_confs = getattr(args, 'min_confs', None)

    result = {}
    addresses = []
    satoshis = 0
    satoshis, addresses = get_total_balance(
        wallet_path=wallet_path, config_path=config_path, min_confs = min_confs)

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


def cli_withdraw(args, password=None, interactive=True, wallet_keys=None, config_path=CONFIG_PATH):
    """
    command: withdraw
    help: Transfer funds out of the Blockstack wallet to a new address
    arg: address (str) 'The recipient address'
    opt: amount (int) 'The amount to withdraw (defaults to all)'
    opt: message (str) 'A message to include with the payment (up to 40 bytes)'
    opt: min_confs (int) 'The minimum confirmations for oustanding transactions'
    opt: tx_only (str) 'If "True", only return the transaction'
    opt: payment_key (str) 'Payers private key string'
    """

    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)
    password = get_default_password(password)

    recipient_addr = str(args.address)
    amount = getattr(args, 'amount', None)
    message = getattr(args, 'message', None)
    min_confs = getattr(args, 'min_confs', TX_MIN_CONFIRMATIONS)
    tx_only = getattr(args, 'tx_only', False)
    payment_key = getattr(args, 'payment_key', None)
    if payment_key is None or len(payment_key) == 0:
        payment_key = None

    if min_confs is None:
        min_confs = TX_MIN_CONFIRMATIONS

    if tx_only and isinstance(tx_only, (str,unicode)):
        if tx_only.lower() in ['1', 'yes', 'true']:
            tx_only = True
        else:
            tx_only = False

    else:
        tx_only = False

    if not re.match(OP_BASE58CHECK_PATTERN, recipient_addr):
        log.debug("recipient = {}".format(recipient_addr))
        return {'error': 'Invalid address'}

    if amount is not None and not isinstance(amount, int):
        log.debug("amount = {}".format(amount))
        return {'error': 'Invalid amount'}

    if not isinstance(min_confs, int):
        log.debug("min_confs = {}".format(min_confs))
        return {'error': 'Invalid min confs'}

    if not isinstance(tx_only, bool):
        log.debug("tx_only = {}".format(tx_only))
        return {'error': 'Invalid tx_only'}

    if message:
        message = str(message)
        if len(message) > virtualchain.lib.blockchain.bitcoin_blockchain.MAX_DATA_LEN:
            return {'error': 'Message must be {} bytes or less (got {})'.format(
                virtualchain.lib.blockchain.bitcoin_blockchain.MAX_DATA_LEN, len(message))}

    if payment_key is None:
        res = wallet_ensure_exists(config_path=config_path)
        if 'error' in res:
            return res

        if wallet_keys is None:
            res = load_wallet(password=password, wallet_path=wallet_path,
                              interactive=interactive, include_private=True)
            if 'error' in res:
                return res
            wallet_keys = res['wallet']

        payment_key = wallet_keys['payment_privkey']
        send_addr, _, _ = get_addresses_from_file(config_dir=config_dir, wallet_path=wallet_path)
    else:
        send_addr = virtualchain.get_privkey_address(payment_key)

    inputs = get_utxos(str(send_addr), min_confirmations=min_confs, config_path=config_path)

    if len(inputs) == 0:
        log.error("No UTXOs for {}".format(send_addr))
        return {'error': 'Failed to find UTXOs for payment address'}

    total_value = sum(inp['value'] for inp in inputs)

    def mktx( amt, tx_fee ):
        """
        Make the transaction with the given fee
        """
        change = 0
        selected_inputs = []
        if amt is None:
            # total transfer, minus tx fee
            log.debug("No amount given; assuming all ({})".format(total_value - tx_fee))
            amt = total_value - tx_fee
            if amt < 0:
                log.error("Dust: total value = {}, tx fee = {}".format(total_value, tx_fee))
                return {'error': 'Cannot withdraw dust'}

            if total_value < amt:
                # too high
                return {'error': 'Requested withdraw value {} exceeds balance {}'.format(amt, total_value)}

            selected_inputs = select_utxos(inputs, amt)
            if selected_inputs is None:
                # too high
                return {'error': 'Not enough inputs: requested withdraw value {} exceeds balance {}'.format(amt, total_value)}

        else:
            if total_value < amt:
                # too high
                return {'error': 'Requested withdraw value {} exceeds balance {}'.format(amt, total_value)}

            selected_inputs = select_utxos(inputs, amt)
            if selected_inputs is None:
                # too high
                return {'error': 'Not enough inputs: requested withdraw value {} exceeds balance {}'.format(amt, total_value)}

            change = virtualchain.calculate_change_amount(selected_inputs, amt, tx_fee)
            log.debug("Withdraw {}, tx fee {}".format(amt, tx_fee))

        outputs = [
            {'script': virtualchain.make_payment_script(recipient_addr),
             'value': amt},
        ]

        if amt < total_value and change > 0:
            # need change and tx fee
            outputs.append(
                {'script': virtualchain.make_payment_script(send_addr),
                  "value": change}
            )

        if message:
            outputs = [
                {"script": virtualchain.make_data_script(binascii.hexlify(message)),
                 "value": 0} ] + outputs

        serialized_tx = serialize_tx(selected_inputs, outputs)
        signed_tx = sign_tx(serialized_tx, selected_inputs, payment_key)
        return signed_tx

    tx = mktx(amount, 0)
    if json_is_error(tx):
        return tx

    tx_fee = virtualchain.get_tx_fee(tx, config_path=config_path)

    tx = mktx(amount, tx_fee)
    if json_is_error(tx):
        return tx

    if tx_only:
        return {'status': True, 'tx': tx}

    log.debug("Withdraw {} from {} to {}".format(amount, send_addr, recipient_addr))

    res = broadcast_tx( tx, config_path=config_path )
    if 'error' in res:
        res['errno'] = errno.EIO

    return res


def get_price_and_fees(name_or_ns, operations, payment_privkey_info, owner_privkey_info,
                       payment_address=None, owner_address=None, transfer_address=None,
                       config_path=CONFIG_PATH, proxy=None, fake_utxos=False):
    """
    Get the price and fees associated with a set of operations, using
    a given owner and payment key.
    Returns a dict with each operation as a key, and the prices in BTC and satoshis.
    Returns {'error': ...} on failure
    """

    # first things first: get fee per byte
    tx_fee_per_byte = virtualchain.get_tx_fee_per_byte(config_path=config_path)
    if tx_fee_per_byte is None:
        log.error("Unable to calculate fee per byte")
        return {'error': 'Unable to get fee estimate'}

    log.debug("Get operation fees for {}".format(", ".join(operations)))

    sg = ScatterGather()
    res = get_operation_fees( name_or_ns, operations, sg, payment_privkey_info, owner_privkey_info, tx_fee_per_byte,
                              proxy=proxy, config_path=config_path, payment_address=payment_address,
                              owner_address=owner_address, transfer_address=transfer_address,
                              fake_utxos = fake_utxos )

    if not res:
        return {'error': 'Failed to get the requisite operation fees'}

    if 'error' in res:
        return res

    # do queries
    sg.run_tasks()

    # get results 
    fees = interpret_operation_fees(operations, sg)
    if 'error' in fees:
        log.error("Failed to get all operation fees: {}".format(fees['error']))
        return {'error': 'Failed to get some operation fees: {}.  Try again with `--debug` for details.'.format(fees['error'])}

    # convert to BTC
    btc_keys = [
        'preorder_tx_fee', 'register_tx_fee',
        'update_tx_fee', 'total_estimated_cost',
        'name_price', 'transfer_tx_fee', 'renewal_tx_fee',
        'revoke_tx_fee', 'namespace_preorder_tx_fee',
        'namespace_reveal_tx_fee', 'namespace_ready_tx_fee',
        'name_import_tx_fee'
    ]

    for k in btc_keys:
        if k in fees.keys():
            v = {
                'satoshis': fees[k],
                'btc': satoshis_to_btc(fees[k])
            }
            fees[k] = v

    return fees


def cli_price(args, config_path=CONFIG_PATH, proxy=None, password=None, interactive=True):
    """
    command: price
    help: Get the price to register a name
    arg: name_or_namespace (str) 'Name or namespace ID to query'
    opt: recipient (str) 'Address of the recipient, if not this wallet.'
    opt: operations (str) 'A CSV of operations to check.'
    opt: use_single_sig (str) 'Compute price assuming single sig addresses'
    """

    proxy = get_default_proxy(config_path) if proxy is None else proxy
    password = get_default_password(password)

    name_or_ns = str(args.name_or_namespace)
    transfer_address = getattr(args, 'recipient', None)
    operations = getattr(args, 'operations', None)

    use_single_sig = getattr(args, 'use_single_sig', 'F')
    use_single_sig = ( use_single_sig in ['1','T'] )

    if transfer_address is not None:
        transfer_address = str(transfer_address)

    if operations is not None:
        operations = operations.split(',')
    else:
        operations = ['preorder', 'register']
        if transfer_address:
            operations.append('transfer')

    res = wallet_ensure_exists(config_path=config_path)
    if 'error' in res:
        return res

    error = check_valid_name(name_or_ns)
    if error:
        if 'preorder' in operations:
            # this means this is a pricecheck on a NAME, not a namespace
            return {'error': 'Not a valid name: \n * {}'.format(error)}
        else:
            # must be valid namespace
            ns_error = check_valid_namespace(name_or_ns)
            if ns_error:
                return {'error': 'Neither a valid name or namespace:\n   * {}\n   * {}'.format(error, ns_error)}

    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    payment_privkey_info, owner_privkey_info = None, None

    payment_address, owner_address, data_pubkey = (
        get_addresses_from_file(config_dir=config_dir, wallet_path=wallet_path)
    )

    if local_api_status(config_dir=config_dir):
        # API server is running.  Use actual wallet keys.
        log.debug("Try to get wallet keys from API server")
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

            log.error("Could not get wallet keys from API server")
            return {'error': 'Could not load wallet keys from API server.  Try `blockstack api stop` and `blockstack api start`'}
    
    else:
        # unlock
        log.warning("API server is not running; unlocking wallet directly")
        res = load_wallet(password=password, wallet_path=wallet_path, interactive=interactive, include_private=True)
        if 'error' in res:
            return res
        
        if res['migrated']:
            return {'error': 'Wallet is in legacy format.  Please migrate it with `setup_wallet`'}

        wallet_keys = res['wallet']
        payment_privkey_info = wallet_keys['payment_privkey']
        owner_privkey_info = wallet_keys['owner_privkey']

    if use_single_sig:
        dummy_ecpk = virtualchain.lib.ecdsalib.ecdsa_private_key()
        dummy_pk = dummy_ecpk.to_hex()
        dummy_address = virtualchain.address_reencode(dummy_ecpk.public_key().address())
        fees = get_price_and_fees( name_or_ns, operations, dummy_pk, dummy_pk,
                                   payment_address=dummy_address, owner_address=dummy_address,
                                   transfer_address=None, config_path=config_path, proxy=proxy,
                                   fake_utxos = True )
    else:
        fees = get_price_and_fees( name_or_ns, operations, payment_privkey_info, owner_privkey_info,
                                   payment_address=payment_address, owner_address=owner_address, transfer_address=transfer_address, config_path=config_path, proxy=proxy )

    return fees


def cli_deposit(args, config_path=CONFIG_PATH):
    """
    command: deposit
    help: Display the address with which to receive bitcoins
    """

    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)
    
    res = wallet_ensure_exists(config_path=config_path)
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
    
    res = wallet_ensure_exists(config_path=config_path)
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
    help: Display the names owned by the wallet owner key
    """
    result = {}

    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)
    
    res = wallet_ensure_exists(config_path=config_path)
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
    
    queues = ['preorder', 'register', 'update', 'transfer', 'renew', 'revoke', 'name_import'] if queues is None else queues
    config_dir = os.path.dirname(config_path)
    conf = config.get_config(config_path)
    
    rpc = local_api_connect(config_path=config_path)
    if rpc is None:
        return {'error': 'API endpoint not running. Please start it with `api start`'}

    try:
        current_state = rpc.backend_state()
    except Exception, e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to contact Blockstack daemon")
        return {'error': 'Failed to contact blockstack daemon.  Please ensure that it is running with the `api` command.'}

    if 'error' in current_state:
        return current_state

    queue_types = dict( [(queue_name, []) for queue_name in queues] )

    def format_queue_entry(entry):
        """
        Determine data to display for a queue entry.
        Return {'name': ..., 'tx_hash': ..., 'confirmations': ...}
        """
        new_entry = {}
        new_entry['name'] = entry['fqu']

        confirmations = get_tx_confirmations(
            entry['tx_hash'], config_path=config_path
        )

        confirmations = 0 if confirmations is None else confirmations

        new_entry['confirmations'] = confirmations
        new_entry['tx_hash'] = entry['tx_hash']
        if 'errors' in entry:
            new_entry['errors'] = entry['errors']

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

    queue_info = cli_get_registrar_info(None, config_path=config_path)
    if 'error' not in queue_info:
        result['queues'] = queue_info
    else:
        return queue_info

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
    opt: force (str) 'If true, then look up even if expired'
    """
    data = {}

    blockchain_record = None
    fqu = str(args.name)
    subdomain = None
    force = getattr(args, 'force', 'False')
    if force is None:
        force = 'False'

    force = force.lower() in ['1', 'true', 'force']

    error = check_valid_name(fqu)
    if error:
        res = subdomains.is_address_subdomain(fqu)
        if res:
            subdomain, domain = res[1]
            fqu = domain

        else:
            return {'error': error}

    try:
        blockchain_record = get_name_blockchain_record(fqu)
    except socket_error:
        return {'error': 'Error connecting to server.'}

    if 'error' in blockchain_record:
        return blockchain_record

    if 'value_hash' not in blockchain_record:
        return {'error': '{} has no profile'.format(fqu)}

    if not force and blockchain_record.get('revoked', False):
        msg = 'Name is revoked. Use `whois` or `get_name_blockchain_record` for details.'
        return {'error': msg}

    if not force and blockchain_record.get('expired', False):
        msg = 'Name is expired. Use `whois` or `get_name_blockchain_record` for details. If you own this name, use `renew` to renew it.'
        return {'error': msg}

    # subdomain?
    if subdomain:
        try:
            return subdomains.resolve_subdomain(subdomain, domain)
        except subdomains.SubdomainNotFound as e:
            log.exception(e)
            return {'error' : "Failed to find name {}.{}".format(subdomain, domain)}

    # regular domain
    try:
        res = get_profile(
            str(args.name), name_record=blockchain_record, include_raw_zonefile=True, use_legacy=True, use_legacy_zonefile=True
        )

        if 'error' in res:
            return res

        data['profile'] = res['profile']
        data['zonefile'] = res['raw_zonefile']
        data['public_key'] = res['public_key']
    except Exception as e:
        log.exception(e)
        msg = 'Failed to look up name\n{}'
        return {'error': msg.format(traceback.format_exc())}

    result = data

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
        res = subdomains.is_address_subdomain(fqu)
        if res:
            subdomain, domain = res[1]
            try:
                subdomain_obj = subdomains.get_subdomain_info(subdomain, domain)
            except subdomains.SubdomainNotFound:
                return {'error': 'Not found.'}

            ret = {
                'status' : 'registered_subdomain',
                'zonefile_txt' : subdomain_obj.zonefile_str,
                'zonefile_hash' : storage.get_zonefile_data_hash(subdomain_obj.zonefile_str),
                'address' : subdomain_obj.address,
                'blockchain' : 'bitcoin',
                'last_txid' : subdomain_obj.last_txid,
            }
            return ret
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

    expire_block = record.get('expire_block', None)
    if expire_block is not None:
        result['expire_block'] = expire_block

    renew_deadline = record.get('renewal_deadline', None)
    if renew_deadline is not None:
        result['renewal_deadline'] = renew_deadline

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
    if local_rpc.is_api_server(config_dir):
        # can return directly
        return registrar_get_wallet(config_path=config_path) 

    wallet_path = os.path.join(config_dir, WALLET_FILENAME)
    
    res = wallet_ensure_exists(config_path=config_path)
    if 'error' in res:
        return res

    status = local_api_status(config_dir=os.path.dirname(config_path))
    if not status:
        return {'error': 'API endpoint not running. Please start it with `blockstack api start`'}
    
    if not is_wallet_unlocked(config_dir=config_dir):
        log.debug('unlocking wallet ({})'.format(config_dir))
        res = unlock_wallet(config_dir=config_dir, password=password)
        if 'error' in res:
            log.error('unlock_wallet: {}'.format(res['error']))
            return res

        if res.has_key('legacy') and res['legacy']:
            log.error("Wallet is in legacy format.  Please migrate it to the latest version with `setup_wallet`.")
            return {'error': 'Wallet is in legacy format.  Please migrate it to the latest version with `setup_wallet.`'}

    return get_wallet_with_backoff(config_path)


def prompt_invalid_zonefile():
    """
    Prompt the user whether or not to replicate
    an invalid zonefile
    """
    if os.environ.get("BLOCKSTACK_CLIENT_INTERACTIVE_YES", None) == "1":
        return True

    warning_str = (
        '\nWARNING!  This zone file data does not look like a zone file.\n'
        'If you proceed to use this data, no one will be able to look\n'
        'up your profile or any data you replicate with Blockstack.\n\n'
        'Proceed? (y/N): '
    )
    proceed = raw_input(warning_str)
    return proceed.lower() in ['y']


def prompt_transfer( new_owner_address ):
    """
    Prompt whether or not to proceed with a transfer
    """

    if os.environ.get("BLOCKSTACK_CLIENT_INTERACTIVE_YES", None) == "1":
        return True

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

    # while not technically denied by POSIX, paths usually
    # have only printable characters and without the "weird"
    # whitespace characters
    valid_chars = set(string.printable) - set("\t\n\r\x0b\x0c")
    filtered_string = filter(lambda x: x in valid_chars, path)
    return filtered_string == path


def analyze_zonefile_string(fqu, zonefile_data, force_data=False, check_current=True, proxy=None):
    """
    Figure out what to do with a zone file data string, based on whether or not
    we can prompt the user and whether or not we expect a standard zonefile.

    if @force_data is True, then the zonefile_data will be treated as raw data.
    Otherwise, it will be considered to be a path

    Returns: {
        'is_string': True/False # whether or not the zone file string is a raw zone file
        'is_path': True/False   # whether or not the zone file string is a path to a file on disk
        'downloaded': True/False    # whether or not the zone file was fetched remotely
        'identical': True/False     # whether or not the zone file is identical to the name's current zone file
        'nonstandard': True/False   # whether or not the zone file follows the standard format
        'raw_zonefile': str     # the raw zone file data. will be equal to zonefile_data if it is not None
        'zonefile': dict        # the parsed standard zone file (or None if nonstandard)
        'zonefile_str': str     # the serialized zone file data.  Will be equal to 'raw_zonefile' if nonstandard; otherwise is equal to serialized zonefile if standard
    }

    Return {'error': ...} on error
    """

    ret = {}
   
    zonefile_data_exists_on_disk = zonefile_data is not None and is_valid_path(zonefile_data) and os.path.exists(zonefile_data)

    if zonefile_data is None:
        # fetch remotely
        zonefile_data_res = get_name_zonefile(
            fqu, proxy=proxy, raw_zonefile=True
        )
        if 'error' not in zonefile_data_res:
            zonefile_data = zonefile_data_res['zonefile']
        else:
            log.warning('Failed to fetch zonefile: {}'.format(zonefile_data_res['error']))

        # zone file is not given; we had to fetch it
        ret['downloaded'] = True
        ret['raw_zonefile'] = zonefile_data
        ret['is_path'] = False
        ret['is_string'] = False

    elif zonefile_data_exists_on_disk and not force_data:
        # this sure looks like a path
        try:
            with open(zonefile_data) as f:
                zonefile_data = f.read()
        except:
            raise Exception("Invalid arguments: failed to read file")
        
        # loaded from path
        ret['downloaded'] = False
        ret['raw_zonefile'] = zonefile_data
        ret['is_path'] = True
        ret['is_string'] = False
    
    elif force_data:
        # string given
        ret['downloaded'] = False
        ret['raw_zonefile'] = zonefile_data
        ret['is_path'] = False
        ret['is_string'] = True

    else:
        if force_data:
            return {'error': 'Invalid argument: no data given'}
        else:
            return {'error': 'Invalid argument: no such file or directory: {}'.format(zonefile_data)}

    # load zonefile, if given
    user_data_res = load_zonefile_from_string(fqu, zonefile_data, check_current=check_current)

    # propagate identical and nonstandard...
    ret['identical'] = user_data_res['identical'] 
    ret['nonstandard'] = user_data_res['nonstandard']

    if user_data_res.has_key('zonefile'):
        ret['zonefile'] = user_data_res['zonefile']

    if user_data_res.has_key('parsed_zonefile'):
        ret['zonefile_str'] = blockstack_zones.make_zone_file(user_data_res['parsed_zonefile'])
    else:
        ret['zonefile_str'] = ret['raw_zonefile']

    return ret


def cli_register(args, config_path=CONFIG_PATH, force_data=False, make_profile=False,
              cost_satoshis=None, interactive=True, password=None, proxy=None):
    """
    command: register
    help: Register a blockchain ID
    arg: name (str) 'The blockchain ID to register'
    opt: zonefile (str) 'The path to the zone file for this name'
    opt: recipient (str) 'The recipient address, if not this wallet'
    opt: min_confs (int) 'The minimum number of confirmations on the initial preorder'
    opt: unsafe_reg (str) 'Should we aggressively register the name (ie, use low min confs)'
    opt: owner_key (str) 'Owners private key string which will receive the name'
    opt: payment_key (str) 'Payers private key string'
    """

    # NOTE: if force_data == True, then the zonefile will be the zonefile text itself, not a path.

    config_dir = os.path.dirname(config_path)
    if not local_api_status(config_dir=config_dir):
        return {'error': 'API server not running.  Please start it with `blockstack api start`.'}

    proxy = get_default_proxy(config_path) if proxy is None else proxy
    password = get_default_password(password)

    conf = config.get_config(config_path)
    assert conf

    res = wallet_ensure_exists(config_path=config_path)
    if 'error' in res:
        return res

    result = {}

    fqu = str(args.name)
    user_zonefile = getattr(args, 'zonefile', None)
    transfer_address = getattr(args, 'recipient', None)
    min_payment_confs = getattr(args, 'min_confs', TX_MIN_CONFIRMATIONS)
    unsafe_reg = getattr(args, 'unsafe_reg', 'False')

    if min_payment_confs is None:
        min_payment_confs = TX_MIN_CONFIRMATIONS

    if unsafe_reg is None:
        unsafe_reg = 'False'

    if unsafe_reg.lower() in ('true', 't', 'yes', '1'):
        unsafe_reg = True
    else:
        unsafe_reg = False

    args_ownerkey = getattr(args, 'owner_key', None)
    if args_ownerkey is None or len(args_ownerkey) == 0:
        owner_key = None
    else:
        owner_key = args_ownerkey
    args_paymentkey = getattr(args, 'payment_key', None)
    if args_paymentkey is None or len(args_paymentkey) == 0:
        payment_key = None
    else:
        payment_key = args_paymentkey

    # name must be well-formed
    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    log.debug("Use UTXOs with a minimum of {} confirmations".format(min_payment_confs))

    if transfer_address:
        if not re.match(OP_BASE58CHECK_PATTERN, transfer_address):
            return {'error': 'Not a valid address'}

    user_profile = None

    if user_zonefile:
        zonefile_info = analyze_zonefile_string(fqu, user_zonefile, force_data=force_data, proxy=proxy)
        if 'error' in zonefile_info:
            log.error("Failed to analyze user zonefile: {}".format(zonefile_info['error']))
            return {'error': zonefile_info['error']}

        if zonefile_info.get('nonstandard'):
            log.warning("Non-standard zone file")
            if interactive:
                proceed = prompt_invalid_zonefile()
                if not proceed:
                    return {'error': 'Non-standard zone file'}

        user_zonefile = zonefile_info['zonefile_str']

    else:
        # make a default zonefile
        _, _, data_pubkey = get_addresses_from_file(config_dir=config_dir)
        if not data_pubkey:
            return {'error': 'No data key in wallet.  Please add one with `setup_wallet`'}

        user_zonefile_dict = make_empty_zonefile(fqu, data_pubkey)
        user_zonefile = blockstack_zones.make_zone_file(user_zonefile_dict)

        if (make_profile and transfer_address):
            log.error("Transfer address supplied to register, and was asked to make an empty profile. This is wrong.")
            return {'error' : 'Error in logic surrounding profile creation. Please report this as a bug.'}
        # only *assume* we need to make a profile if the user didn't supply
        #   a zonefile, and didn't supply a transfer_address
        make_profile = not transfer_address

    if make_profile:
        # let's put an empty profile
        _, _, data_pubkey = get_addresses_from_file(config_dir=config_dir)
        if not data_pubkey:
            return {'error': 'No data key in wallet.  Please add one with `setup_wallet`'}
        user_profile = make_empty_user_profile()

    # operation checks (API server only)
    if local_rpc.is_api_server(config_dir=config_dir):
        # find tx fee, and do sanity checks
        wallet_keys = get_wallet_keys(config_path, password)
        if 'error' in wallet_keys:
            return wallet_keys

        if owner_key:
            owner_privkey_info = owner_key
        else:
            owner_privkey_info = wallet_keys['owner_privkey']

        if payment_key:
            payment_privkey_info = payment_key
        else:
            payment_privkey_info = wallet_keys['payment_privkey']

        operations = ['preorder', 'register']
        required_checks = ['is_name_available', 'is_payment_address_usable', 'owner_can_receive']
        if transfer_address:
            required_checks.append('recipient_can_receive')

        res = check_operations( fqu, operations, owner_privkey_info, payment_privkey_info, min_payment_confs=min_payment_confs,
                                transfer_address=transfer_address, required_checks=required_checks, config_path=config_path, proxy=proxy )

        if 'error' in res:
            return res

        opchecks = res['opchecks']

        if cost_satoshis is not None:
            if opchecks['name_price'] > cost_satoshis:
                return {'error': 'Invalid cost: expected {}, got {}'.format(opchecks['name_price'], cost_satoshis)}

        else:
            cost_satoshis = opchecks['name_price']
    if transfer_address == '':
        transfer_address = None

    if interactive and os.environ.get("BLOCKSTACK_CLIENT_INTERACTIVE_YES", None) != "1":
        try:

            print("Calculating total registration costs for {}...".format(fqu))

            class PriceArgs(object):
                pass

            price_args = PriceArgs()
            price_args.name_or_namespace = fqu
            price_args.recipient = transfer_address

            costs = cli_price( price_args, config_path=config_path, password=password, proxy=proxy )
            if 'error' in costs:
                return {'error': 'Failed to get name costs.  Please try again with `--debug` to see error messages.'}

            cost = costs['total_estimated_cost']
            input_prompt = (
                'Registering {} will cost about {} BTC.\n'
                'Use `blockstack price {}` for a cost breakdown\n'
                '\n'
                'The entire process takes 48 confirmations, or about 5 hours.\n'
                'You need to have Internet access during this time period, so\n'
                'this program can send the right transactions at the right\n'
                'times.\n\n'
                'Continue? (y/N): '
            )
            input_prompt = input_prompt.format(fqu, cost['btc'], fqu)
            user_input = raw_input(input_prompt)
            user_input = user_input.lower()

            if user_input.lower() != 'y':
                print('Not registering.')
                exit(0)

        except KeyboardInterrupt:
            print('\nExiting.')
            exit(0)

    # forward along to RESTful server (or if we're the RESTful server, call the registrar method)
    log.debug("Preorder {}, zonefile={}, profile={}, recipient={} min_confs={}".format(fqu, user_zonefile, user_profile, transfer_address, min_payment_confs))
    rpc = local_api_connect(config_path=config_path)
    assert rpc

    additionals = {}
    if payment_key:
        additionals['payment_key'] = payment_key
    if owner_key:
        additionals['owner_key'] = owner_key

    try:
        resp = rpc.backend_preorder(fqu, cost_satoshis, user_zonefile, user_profile,
                                    transfer_address, min_payment_confs,
                                    unsafe_reg = unsafe_reg, **additionals)
    except Exception as e:
        log.exception(e)
        return {'error': 'Error talking to server, try again.'}

    if 'error' in resp:
        log.debug('RPC error: {}'.format(resp['error']))
        return resp

    if (not 'success' in resp or not resp['success']) and 'message' in resp:
        return {'error': resp['message']}

    result = resp

    if local_rpc.is_api_server(config_dir):
        # log this
        total_estimated_cost = {'total_estimated_cost': opchecks['total_estimated_cost']}

    return result



def cli_update(args, config_path=CONFIG_PATH, password=None,
               interactive=True, proxy=None, nonstandard=False,
               force_data=False):

    """
    command: update
    help: Set the zone file for a blockchain ID
    arg: name (str) 'The name to update.'
    opt: data (str) 'A path to a file with the zone file data.'
    opt: nonstandard (str) 'If true, then do not validate or parse the zone file.'
    opt: owner_key (str) 'A private key string to be used for the update.'
    opt: payment_key (str) 'Payers private key string'
    """

    # NOTE: if force_data == True, then the zonefile will be the zonefile text itself, not a path.

    config_dir = os.path.dirname(config_path)
    if not local_api_status(config_dir=config_dir):
        return {'error': 'API server not running.  Please start it with `blockstack api start`.'}

    if not interactive and getattr(args, 'data', None) is None:
        return {'error': 'Zone file data required in non-interactive mode'}

    proxy = get_default_proxy(config_path) if proxy is None else proxy
    password = get_default_password(password)

    if hasattr(args, 'nonstandard') and not nonstandard:
        if args.nonstandard is not None and args.nonstandard.lower() in ['yes', '1', 'true']:
            nonstandard = True

    conf = config.get_config(config_path)
    assert conf

    res = wallet_ensure_exists(config_path=config_path)
    if 'error' in res:
        return res

    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    zonefile_data_path_or_string = None
    downloaded = False
    if getattr(args, 'data', None) is not None:
        zonefile_data_path_or_string = str(args.data)

    args_ownerkey = getattr(args, 'owner_key', None)
    if args_ownerkey is None or len(args_ownerkey) == 0:
        owner_key = None
    else:
        owner_key = args_ownerkey
    args_paymentkey = getattr(args, 'payment_key', None)
    if args_paymentkey is None or len(args_paymentkey) == 0:
        payment_key = None
    else:
        payment_key = args_paymentkey

    if not local_rpc.is_api_server(config_dir=config_dir):
        # verify that we own the name before trying to edit its zonefile
        if owner_key:
            owner_address = virtualchain.get_privkey_address(owner_key)
        else:
            _, owner_address, _ = get_addresses_from_file(config_dir=config_dir)
        assert owner_address

        res = get_names_owned_by_address( owner_address, proxy=proxy )
        if 'error' in res:
            return res

        if fqu not in res:
            return {'error': 'This wallet does not own this name'}

    zonefile_info = analyze_zonefile_string(fqu, zonefile_data_path_or_string, force_data=force_data, proxy=proxy)
    if 'error' in zonefile_info:
        log.error("Failed to analyze zone file: {}".format(zonefile_info['error']))
        return {'error': zonefile_info['error']}

    if zonefile_info['identical'] and not zonefile_info['downloaded']:
        log.error("Zone file has not changed")
        return {'error': 'Zone file matches the current name hash; not updating'}

    # load zonefile, if given
    user_data_txt, user_data_hash, user_zonefile_dict = None, None, {}
    zonefile_data = zonefile_info['zonefile_str']

    if not zonefile_info['nonstandard'] and (not zonefile_info['identical'] or zonefile_info['downloaded']):
        # standard zone file that is not identital to what we have now, or standard zonefile that we downloaded and wish to edit
        user_data_txt = zonefile_data
        user_data_hash = get_zonefile_data_hash(zonefile_data)
        user_zonefile_dict = blockstack_zones.parse_zone_file(zonefile_data)

    else:
        if not interactive:
            if zonefile_data is None or nonstandard:
                log.warning('Using non-zonefile data')

            else:
                return {'error': 'Zone file not updated (invalid)'}

        # not a standard zonefile (but maybe that's okay! ask the user)
        if zonefile_data is not None and interactive:
            # something invalid here.  prompt overwrite
            proceed = prompt_invalid_zonefile()
            if not proceed:
                return {'error': 'Zone file not updated'}

            else:
                nonstandard = True

        user_data_txt = zonefile_data
        if zonefile_data is not None:
            user_data_hash = get_zonefile_data_hash(zonefile_data)


    # open the zonefile editor
    if interactive and not nonstandard:
        _, _, data_pubkey = get_addresses_from_file(config_dir=config_dir)

        if data_pubkey is None:
            return {'error': 'No data public key set in the wallet. ' +
                    ' Please use `blockstack setup_wallet` to fix this.'}

        # configuration wizard!
        if user_zonefile_dict is None:
            user_zonefile_dict = make_empty_zonefile(fqu, data_pubkey)

        new_zonefile = configure_zonefile(
            fqu, user_zonefile_dict, data_pubkey
        )

        if new_zonefile is None:
            # zonefile did not change; nothing to do
            return {'error': 'Zonefile did not change.  No update sent.'}

        user_zonefile_dict = new_zonefile
        user_data_txt = blockstack_zones.make_zone_file(user_zonefile_dict)
        user_data_hash = get_zonefile_data_hash(user_data_txt)

    # forward along to RESTful server (or registrar)
    log.debug("Update {}, zonefile={}, zonefile_hash={}".format(fqu, user_data_txt, user_data_hash))
    rpc = local_api_connect(config_path=config_path)
    assert rpc

    try:
        # NOTE: already did safety checks
        resp = rpc.backend_update(
            fqu, user_data_txt, None, None, owner_key = owner_key, payment_key = payment_key)
    except Exception as e:
        log.exception(e)
        return {'error': 'Error talking to server, try again.'}

    if 'error' in resp:
        log.debug('RPC error: {}'.format(resp['error']))
        return resp

    if (not 'success' in resp or not resp['success']) and 'message' in resp:
        return {'error': resp['message']}

    resp['zonefile_hash'] = user_data_hash
    return resp


def cli_transfer(args, config_path=CONFIG_PATH, password=None, interactive=False, proxy=None):
    """
    command: transfer
    help: Transfer a blockchain ID to a new owner
    arg: name (str) 'The name to transfer'
    arg: address (str) 'The address (base58check-encoded pubkey hash) to receive the name'
    opt: owner_key (str) 'A private key string to be used for the update.'
    opt: payment_key (str) 'Payers private key string'
    """

    config_dir = os.path.dirname(config_path)
    if not local_api_status(config_dir=config_dir):
        return {'error': 'API server not running.  Please start it with `blockstack api start`.'}

    proxy = get_default_proxy(config_path) if proxy is None else proxy
    password = get_default_password(password)
    conf = config.get_config(config_path)
    assert conf

    res = wallet_ensure_exists(config_path=config_path)
    if 'error' in res:
        return res

    fqu = str(args.name)
    transfer_address = str(args.address)

    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    if interactive:
        res = prompt_transfer(transfer_address)
        if not res:
            return {'error': 'Transfer cancelled.'}

    # do the name transfer via the RESTful server (or registrar)
    rpc = local_api_connect(config_path=config_path)
    assert rpc

    try:
        args_ownerkey = getattr(args, 'owner_key', None)
        if args_ownerkey is None or len(args_ownerkey) == 0:
            owner_key = None
        else:
            owner_key = args_ownerkey

        args_paymentkey = getattr(args, 'payment_key', None)
        if args_paymentkey is None or len(args_paymentkey) == 0:
            payment_key = None
        else:
            payment_key = args_paymentkey

        resp = rpc.backend_transfer(
            fqu, transfer_address, owner_key = owner_key, payment_key = payment_key)
    except Exception as e:
        log.exception(e)
        return {'error': 'Error talking to server, try again.'}

    if 'error' in resp:
        log.debug('RPC error: {}'.format(resp['error']))
        return resp

    if (not 'success' in resp or not resp['success']) and 'message' in resp:
        return {'error': resp['message']}

    return resp


def cli_renew(args, config_path=CONFIG_PATH, force_data=False, interactive=True, password=None, proxy=None, cost_satoshis=None):
    """
    command: renew
    help: Renew a blockchain ID
    arg: name (str) 'The blockchain ID to renew'
    opt: owner_key (str) 'A private key string to be used for the update.'
    opt: payment_key (str) 'Payers private key string'
    opt: recipient_address (str) 'The new owner address'
    opt: zonefile_data (str) 'The new zone file data'
    """

    config_dir = os.path.dirname(config_path)
    if not local_api_status(config_dir=config_dir):
        return {'error': 'API server not running.  Please start it with `blockstack api start`.'}

    if proxy is None:
        proxy = get_default_proxy(config_path)

    password = get_default_password(password)

    conf = config.get_config(config_path)
    assert conf

    res = wallet_ensure_exists(config_path=config_path)
    if 'error' in res:
        return res

    fqu = str(args.name)

    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    # inspect zonefile
    zonefile_data = getattr(args, 'zonefile_data', None)
    zonefile_hash = None

    if zonefile_data:
        zonefile_data = str(zonefile_data)
        zonefile_info = analyze_zonefile_string(fqu, zonefile_data, force_data=force_data, check_current=False, proxy=proxy)
        if 'error' in zonefile_info:
            log.error("Failed to analyze zone file: {}".format(zonefile_info['error']))
            return {'error': zonefile_info['error']}

        if zonefile_info['nonstandard']:
            if interactive:
                proceed = prompt_invalid_zonefile()
                if not proceed:
                    return {'error': 'Aborting name import on invalid zone file'}

            else:
                log.warning("Using nonstandard zone file data")

        zonefile_data = zonefile_info['zonefile_str']
        zonefile_hash = get_zonefile_data_hash(zonefile_data)

    new_owner_address = getattr(args, 'recipient_address', None)
    if new_owner_address:
        new_owner_address = str(new_owner_address)

    if interactive:
        print("Calculating total renewal costs for {}...".format(fqu))

    # get the costs...
    class PriceArgs(object):
        pass

    price_args = PriceArgs()
    price_args.name_or_namespace = fqu
    price_args.operations = 'renewal'

    args_ownerkey = getattr(args, 'owner_key', None)
    if args_ownerkey is None or len(args_ownerkey) == 0:
        owner_key = None
    else:
        owner_key = args_ownerkey

    args_paymentkey = getattr(args, 'payment_key', None)
    if args_paymentkey is None or len(args_paymentkey) == 0:
        payment_key = None
    else:
        payment_key = args_paymentkey

    costs = cli_price( price_args, config_path=config_path, password=password, proxy=proxy )
    if 'error' in costs:
        return {'error': 'Failed to get renewal costs.  Please try again with `--debug` to see error messages.'}

    cost = costs['total_estimated_cost']

    if cost_satoshis is None:
        cost_satoshis = costs['name_price']['satoshis']

    if not local_rpc.is_api_server(config_dir=config_dir):
        # also verify that we own the name
        _, owner_address, _ = get_addresses_from_file(config_dir=config_dir)
        assert owner_address

        res = get_names_owned_by_address( owner_address, proxy=proxy )
        if 'error' in res:
            return res

        if fqu not in res:
            return {'error': 'This wallet does not own this name'}

    if interactive and os.environ.get("BLOCKSTACK_CLIENT_INTERACTIVE_YES", None) != "1":
        try:
            input_prompt = (
                'Renewing {} will cost about {} BTC.\n'
                'Use `blockstack price {} "" renewal` for a cost breakdown\n'
                '\n'
                'The entire process takes 12 confirmations, or about 2 hours.\n'
                'You need to have Internet access during this time period, so\n'
                'this program can send the right transactions at the right\n'
                'times.\n\n'
                'Continue? (y/N): '
            )
            input_prompt = input_prompt.format(fqu, cost['btc'], fqu)
            user_input = raw_input(input_prompt)
            user_input = user_input.lower()

            if user_input.lower() != 'y':
                print('Not renewing.')
                exit(0)

        except KeyboardInterrupt:
            print('\nExiting.')
            exit(0)

    rpc = local_api_connect(config_path=config_path)
    assert rpc

    log.debug("Renew {} for {} BTC".format(fqu, cost_satoshis))
    if zonefile_data:
        log.debug('new zonefile:\n{}'.format(zonefile_data))

    if new_owner_address:
        log.debug("new owner address: {}".format(new_owner_address))

    try:
        additionals = {}
        if owner_key:
            additionals['owner_key'] = owner_key
        if payment_key:
            additionals['payment_key'] = payment_key
        if zonefile_data:
            additionals['zonefile_data'] = zonefile_data
        if new_owner_address:
            additionals['new_owner_address'] = new_owner_address

        resp = rpc.backend_renew(fqu, cost_satoshis, **additionals)
    except Exception as e:
        log.exception(e)
        return {'error': 'Error talking to server, try again.'}

    total_estimated_cost = {'total_estimated_cost': cost}

    if 'error' in resp:
        log.debug('RPC error: {}'.format(resp['error']))
        return resp

    if (not 'success' in resp or not resp['success']) and 'message' in resp:
        return {'error': resp['message']}

    return resp


def cli_revoke(args, config_path=CONFIG_PATH, interactive=True, password=None, proxy=None):
    """
    command: revoke
    help: Revoke a blockchain ID
    arg: name (str) 'The blockchain ID to revoke'
    """

    config_dir = os.path.dirname(config_path)
    if not local_api_status(config_dir=config_dir):
        return {'error': 'API server not running.  Please start it with `blockstack api start`.'}

    if proxy is None:
        proxy = get_default_proxy(config_path)
    
    password = get_default_password(password)

    conf = config.get_config(config_path)
    assert conf

    res = wallet_ensure_exists(config_path=config_path)
    if 'error' in res:
        return res

    fqu = str(args.name)

    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    if interactive and os.environ.get("BLOCKSTACK_CLIENT_INTERACTIVE_YES", None) != "1":
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

    rpc = local_api_connect(config_path=config_path)
    assert rpc

    log.debug("Revoke {}".format(fqu))

    try:
        resp = rpc.backend_revoke(fqu)
    except Exception as e:
        log.exception(e)
        return {'error': 'Error talking to server, try again.'}

    if 'error' in resp:
        log.debug('RPC error: {}'.format(resp['error']))
        return resp

    if (not 'success' in resp or not resp['success']) and 'message' in resp:
        return {'error': resp['message']}

    return resp


def cli_migrate(args, config_path=CONFIG_PATH, password=None,
                proxy=None, interactive=True, force=False):
    """
    command: migrate
    help: Migrate a legacy blockchain-linked profile to the latest zonefile and profile format
    arg: name (str) 'The blockchain ID with the profile to migrate'
    opt: force (str) 'Reset the zone file no matter what.'
    """

    config_dir = os.path.dirname(config_path)
    if not local_api_status(config_dir=config_dir):
        return {'error': 'API server not running.  Please start it with `blockstack api start`.'}

    password = get_default_password(password)
    conf = config.get_config(config_path)
    assert conf

    res = wallet_ensure_exists(config_path=config_path)
    if 'error' in res:
        return res

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    fqu = str(args.name)

    if hasattr(args, 'force'):
        force = args.force
        if force is None:
            force = ''
    else:
        force = ''

    force = (force.lower() in ['1', 'yes', 'force', 'true'])

    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    # need data public key 
    _, _, data_pubkey = get_addresses_from_file(config_dir=config_dir)
    if data_pubkey is None:
        return {'error': 'No data key in wallet'}

    res = get_name_zonefile(
        fqu, proxy=proxy,
        raw_zonefile=True, include_name_record=True
    )

    user_zonefile = None
    user_profile = None

    if 'error' not in res:
        name_rec = res['name_record']
        user_zonefile_txt = res['zonefile']
        user_zonefile_hash = get_zonefile_data_hash(user_zonefile_txt)
        user_zonefile = None
        legacy = False
        nonstandard = False

        # TODO: handle zone files that do not have data keys.
        # try to parse
        try:
            user_zonefile = blockstack_zones.parse_zone_file(user_zonefile_txt)
            legacy = blockstack_profiles.is_profile_in_legacy_format(user_zonefile)
        except:
            log.warning('Non-standard zonefile {}'.format(user_zonefile_hash))
            nonstandard = True

        if nonstandard:
            if force:
                # forcibly reset the zone file
                user_profile = make_empty_user_profile()
                user_zonefile = make_empty_zonefile(fqu, data_pubkey)

            else:
                if interactive or os.environ.get("BLOCKSTACK_CLIENT_INTERACTIVE_YES", None) != "1":
                    # prompt
                    msg = (
                        ''
                        'WARNING!  Non-standard zone file detected.'
                        'If you proceed, your zone file will be reset.'
                        ''
                        'Proceed? (y/N): '
                    )

                    proceed_str = raw_input(msg)
                    proceed = proceed_str.lower() in ['y']
                    if not proceed:
                        return {'error': 'Non-standard zonefile'}

                    else:
                        user_profile = make_empty_user_profile()
                        user_zonefile = make_empty_zonefile(fqu, data_pubkey)
                else:
                    return {'error': 'Non-standard zonefile'}

            # going ahead with zonefile and profile reset

        else:
            # standard or legacy zone file
            if not legacy:
                msg = 'Zone file is in the latest format.  No migration needed'
                return {'error': msg}

            # convert
            user_profile = blockstack_profiles.get_person_from_legacy_format(user_zonefile)
            user_zonefile = make_empty_zonefile(fqu, data_pubkey)

    else:
        log.error("Failed to get zone file for {}".format(fqu))
        return {'error': res['error']}

    zonefile_txt = blockstack_zones.make_zone_file(user_zonefile)
    zonefile_hash = get_zonefile_data_hash(zonefile_txt) 

    rpc = local_api_connect(config_path=config_path)
    assert rpc

    try:
        resp = rpc.backend_update(fqu, zonefile_txt, user_profile, None)
    except Exception as e:
        log.exception(e)
        return {'error': 'Error talking to server, try again.'}

    if 'error' in resp:
        log.debug('RPC error: {}'.format(resp['error']))
        return resp

    if (not 'success' in resp or not resp['success']) and 'message' in resp:
        return {'error': resp['message']}

    resp['zonefile_hash'] = zonefile_hash
    return resp


def cli_wallet_password(args, config_path=CONFIG_PATH, password=None, interactive=True):
    """
    command: wallet_password
    help: Change your wallet password
    opt: old_password (str) 'The old password. It will be prompted if not given.'
    opt: new_password (str) 'The new password. It will be prompted if not given.'
    """
    
    password = get_default_password(password)
    if password is None:
        password = getattr(args, 'password', None)

    wallet_path = get_wallet_path(config_path=config_path)
    
    res = load_wallet(password=password, wallet_path=wallet_path, interactive=interactive, include_private=True)
    if 'error' in res:
        return res
    
    if res['migrated']:
        return {'error': 'Wallet is in legacy format.  Please migrate it with `setup_wallet`'}

    wallet_keys = res['wallet']
    password = res['password']

    new_password = getattr(args, 'new_password', None)
    if new_password is None:
        new_password = prompt_wallet_password('Enter new wallet password: ')
        new_password_2 = prompt_wallet_password('Re-enter new wallet password: ')

        if new_password != new_password_2:
            return {'error': 'New passwords do not match'}

    if new_password == password:
        return {'error': 'Passwords are the same'}

    enc_wallet = encrypt_wallet(wallet_keys, new_password)
    if 'error' in enc_wallet:
        return enc_wallet

    legacy_path = backup_wallet(wallet_path=wallet_path)
    if legacy_path is None:
        return {'error': 'Failed to replace old wallet'}
    
    res = write_wallet(enc_wallet, path=wallet_path)
    if 'error' in res:
        return res
    
    try:
        os.unlink(legacy_path)
    except:
        pass

    return {'status': True}
    

def cli_setup_wallet(args, config_path=CONFIG_PATH, password=None, interactive=True):
    """
    command: setup_wallet
    help: Create or upgrade up your wallet.
    """
    
    password = get_default_password(password)
    ret = {}

    res = wallet_setup(config_path=config_path, interactive=interactive, password=password)
    if 'error' in res:
        return res

    if res.has_key('backup_wallet'):
        # return this
        ret['backup_wallet'] = res['backup_wallet']

    ret['status'] = True
    return ret


def cli_get_public_key(args, config_path=CONFIG_PATH, proxy=None):
    """
    command: get_public_key
    help: Get the ECDSA public key for a blockchain ID
    arg: name (str) 'The blockchain ID'
    """
    # reply ENODATA if we can't load the zone file
    # reply EINVAL if we can't parse the zone file

    fqu = str(args.name)
    zfinfo = get_name_zonefile(fqu, proxy=proxy)
    if 'error' in zfinfo:
        log.error("unable to load zone file for {}: {}".format(fqu, zfinfo['error']))
        return {'error': 'unable to load or parse zone file for {}'.format(fqu), 'errno': errno.ENODATA}
   
    if not user_zonefile_data_pubkey(zfinfo['zonefile']):
        log.error("zone file for {} has no public key".format(fqu))
        return {'error': 'zone file for {} has no public key'.format(fqu), 'errno': errno.EINVAL}

    zfpubkey = keylib.key_formatting.decompress(user_zonefile_data_pubkey(zfinfo['zonefile']))
    return {'public_key': zfpubkey}


def cli_list_accounts( args, proxy=None, config_path=CONFIG_PATH ):
    """
    command: list_accounts advanced
    help: List the set of accounts in a name's profile.
    arg: name (str) 'The name to query.'
    """ 

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)
    
    name = str(args.name)
    account_info = profile_list_accounts(name, proxy=proxy )
    if 'error' in account_info:
        return account_info

    return account_info['accounts']


def cli_get_account( args, proxy=None, config_path=CONFIG_PATH ):
    """
    command: get_account advanced
    help: Get an account from a name's profile.
    arg: name (str) 'The name to query.'
    arg: service (str) 'The service for which this account was created.'
    arg: identifier (str) 'The name of the account.'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)
    
    name = str(args.name)
    service = str(args.service)
    identifier = str(args.identifier)

    res = profile_get_account(name, service, identifier, config_path=config_path, proxy=proxy)
    if 'error' in res:
        return {'error': res['error']}

    return res['account']


def cli_put_account( args, proxy=None, config_path=CONFIG_PATH, password=None, wallet_keys=None ):
    """
    command: put_account advanced
    help: Add or overwrite an account in a name's profile.
    arg: name (str) 'The name to query.'
    arg: service (str) 'The service this account is for.'
    arg: identifier (str) 'The name of the account.'
    arg: content_url (str) 'The URL that points to external contact data.'
    opt: extra_data (str) 'A comma-separated list of "name1=value1,name2=value2,name3=value3..." with any extra account information you need in the account.'
    """
    password = get_default_password(password)
    proxy = get_default_proxy(config_path=config_path) if proxy is None else proxy
    config_dir = os.path.dirname(config_path)

    if wallet_keys is None:
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

    return profile_put_account(name, service, identifier, content_url, extra_data, wallet_keys, config_path=config_path, proxy=proxy)


def cli_delete_account( args, proxy=None, config_path=CONFIG_PATH, password=None, wallet_keys=None ):
    """
    command: delete_account advanced
    help: Delete a particular account from a name's profile.
    arg: name (str) 'The name to query.'
    arg: service (str) 'The service the account is for.'
    arg: identifier (str) 'The identifier of the account to delete.'
    """
    password = get_default_password(password)
    proxy = get_default_proxy(config_path=config_path) if proxy is None else proxy

    config_dir = os.path.dirname(config_path)
    if wallet_keys is None:
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

    return profile_delete_account(name, service, identifier, wallet_keys, config_path=config_path, proxy=proxy)


def parse_multisig_csv(multisig_csv, segwit=False):
    """
    Helper to parse 'm,n,pk1,pk2.,,,' into a virtualchain private key bundle.
    Parses 'm,n,pk1,pk2,...' as p2sh
    Parses 'segwit:m,n,pk1,pk2,...' as p2sh-p2wsh
    """
    if multisig_csv.startswith("segwit:"):
        segwit = True
        multisig_csv = multisig_csv[len('segwit:'):]

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
        if segwit:
            # p2wsh
            key_info = virtualchain.make_multisig_segwit_info(m, keys)
        else:
            # p2sh
            key_info = virtualchain.make_multisig_info(m, keys)

    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to make multisig information from keys")
        return {'error': 'Failed to make multisig information'}

    return key_info


def parse_privkey_info(privkey_str):
    """
    Parse a private key or a bundle of private keys.
    Formats:
        * "pk" --> p2pkh private key
        * "segwit:pk" --> p2sh-p2wpkh private key bundle
        * "m,n,pk1,pk2,..." --> p2sh multisig bundle
        * "segwit:m,n,pk1,pk2,..." --> p2sh-p2wsh multisig bundle
    """
    segwit = False
    if privkey_str.startswith('segwit:'):
        segwit = True
        privkey_str = privkey_str[len('segwit:'):]

    privkey_info = None
    try:
        privkey_info = ecdsa_private_key(str(privkey_str)).to_hex()
        if segwit:
            privkey_info = virtualchain.make_segwit_info(privkey_info)

    except:
        log.debug("Private key string is not a valid Bitcoin private key")
        privkey_info = parse_multisig_csv(str(privkey_str), segwit=segwit)
        if 'error' in privkey_info:
            return privkey_info

    return privkey_info


def serialize_privkey_info(payment_privkey):
    """
    Serialize a wallet private key into a CLI-parseable string
    """
    payment_privkey_str = None
    if isinstance(payment_privkey, (str,unicode)):
        payment_privkey_str = payment_privkey
    else:
        if payment_privkey['segwit']:
            m = payment_privkey['m']
            n = len(payment_privkey['private_keys'])

            if n > 1:
                payment_privkey_str = 'segwit:{},{},{}'.format(m, n, ','.join(payment_privkey['private_keys']))
            else:
                payment_privkey_str = 'segwit:{}'.format(payment_privkey['private_keys'][0])
        else:
            m, pubks = virtualchain.parse_multisig_redeemscript(payment_privkey['redeem_script'])
            n = len(payment_privkey['private_keys'])
            payment_privkey_str = '{},{},{}'.format(m, n, ','.join(payment_privkey['private_keys']))

    return payment_privkey_str


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
    password = get_default_password(password)

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

    owner_privkey_info = None
    payment_privkey_info = None
    data_privkey_info = None

    # make absolutely certain that these are valid keys or multisig key strings
    owner_privkey_info = parse_privkey_info(args.owner_privkey)
    if 'error' in owner_privkey_info:
        return owner_privkey_info

    payment_privkey_info = parse_privkey_info(args.payment_privkey)
    if 'error' in payment_privkey_info:
        return payment_privkey_info

    data_privkey_info = parse_privkey_info(args.data_privkey)
    if 'error' in data_privkey_info:
        return data_privkey_info
    
    if not isinstance(data_privkey_info, (str,unicode)):
        return {'error': 'Invalid data private key: only single private keys are supported'}

    data = make_wallet(password,
            payment_privkey_info=payment_privkey_info,
            owner_privkey_info=owner_privkey_info,
            data_privkey_info=data_privkey_info )

    if 'error' in data:
        return data

    write_wallet(data, path=wallet_path)

    if not local_api_status(config_dir=config_dir):
        return {'status': True}

    # load into RPC daemon, if it is running
    rpc = local_api_connect(config_path=config_path)
    if rpc is None:
        log.error("Failed to connect to API endpoint. Trying to shut it down...")
        res = local_rpc.local_api_action('stop', config_dir=config_dir)
        if 'error' in res:
            log.error("Failed to stop API daemon")
            return res

        return {'status': True}

    try:
        wallet = decrypt_wallet(data, password, config_path=config_path)
        if 'error' in wallet:
            return {'error': 'Failed to decrypt new wallet'}

        rpc.backend_set_wallet( wallet )
    except Exception as e:
        log.exception(e)
        return {'error': 'Failed to load wallet into API endpoint'}
                
    return {'status': True}


def display_wallet_info(payment_address, owner_address, data_public_key, config_path=CONFIG_PATH):
    """
    Print out useful wallet information
    """
    print('-' * 60)
    print('Payment address:\t{}'.format(payment_address))
    print('Owner address:\t\t{}'.format(owner_address))

    if data_public_key is not None:
        print('Data public key:\t{}'.format(data_public_key))

    balance = None
    if payment_address is not None:
        balance = get_balance( payment_address, config_path=config_path )

    if balance is None:
        print('Failed to look up balance')
    else:
        balance = satoshis_to_btc(balance)
        print('-' * 60)
        print('Balance:')
        print('{}: {}'.format(payment_address, balance))
        print('-' * 60)

    names_owned = None
    if owner_address is not None:
        names_owned = get_names_owned(owner_address)
        
    if names_owned is None or 'error' in names_owned:
        print('Failed to look up names owned')

    else:
        print('Names Owned:')
        names_owned = get_names_owned(owner_address)
        print('{}: {}'.format(owner_address, names_owned))
        print('-' * 60)


def cli_wallet(args, config_path=CONFIG_PATH, interactive=True, password=None):
    """
    command: wallet advanced
    help: Query wallet information
    """

    password = get_default_password(password)
    wallet_path = get_wallet_path(config_path=config_path)
  
    payment_address = None
    owner_address = None
    data_pubkey = None
    migrated = False
   
    config_dir = os.path.dirname(config_path)
        
    if local_api_status(config_dir=config_dir):
        wallet_keys = get_wallet_keys(config_path, password)
        if 'error' in wallet_keys:
            return wallet_keys

        result = wallet_keys
        
        payment_address = result['payment_address']
        owner_address = result['owner_address']
        data_pubkey = result['data_pubkey']
    
    else:
        log.debug("API endpoint does not appear to be running")
        res = load_wallet(password=password, wallet_path=wallet_path, interactive=interactive, include_private=True)
        if 'error' in res:
            return res
    
        wallet = res['wallet']
        migrated = res['migrated']

        payment_address = wallet['payment_addresses'][0]
        owner_address = wallet['owner_addresses'][0]
        data_pubkey = wallet['data_pubkey']

        result = {
            'payment_privkey': wallet['payment_privkey'],
            'owner_privkey': wallet['owner_privkey'],
            'data_privkey': wallet['data_privkey'],
            'payment_address': payment_address,
            'owner_address': owner_address,
            'data_pubkey': data_pubkey
        }

    payment_privkey = result.get('payment_privkey', None)
    owner_privkey = result.get('owner_privkey', None)
    data_privkey = result.get('data_privkey', None)

    display_wallet_info(
        payment_address,
        owner_address,
        data_pubkey,
        config_path=CONFIG_PATH
    )

    if migrated:
        print ('WARNING: Wallet is in legacy format.  Please migrate it with `setup_wallet`.')
        print('-' * 60)

    print('Payment private key info: {}'.format(privkey_to_string(payment_privkey)))
    print('Owner private key info:   {}'.format(privkey_to_string(owner_privkey)))
    print('Data private key info:    {}'.format(privkey_to_string(data_privkey)))
    
    print('-' * 60)
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

        if 'last_block_processed' in resp and 'consensus' in resp:
            return {'consensus': resp['consensus'], 'block_height': resp['last_block_processed']}
        else:
            log.debug("Resp is {}".format(resp))
            return {'error': 'Server is indexing.  Try again shortly.'}

    resp = get_consensus_at(int(args.block_height))

    data = {}
    data['consensus'] = resp
    data['block_height'] = args.block_height

    result = data

    return result


def cli_api(args, password=None, interactive=True, config_path=CONFIG_PATH):
    """
    command: api 
    help: Control the RESTful API endpoint
    arg: command (str) '"start", "start-foreground", "stop", or "status"'
    opt: wallet_password (str) 'The wallet password. Will prompt if required.'
    """

    config_dir = CONFIG_DIR
    if config_path is not None:
        config_dir = os.path.dirname(config_path)

    command = str(args.command)
    password = get_default_password(password)
    if password is None and command in ['start', 'start-foreground']:
        password = getattr(args, 'wallet_password', None)
        if password is None:
            if not interactive:
                return {'error': 'No wallet password given, and not in interactive mode'}

            password = prompt_wallet_password()

    if password:
        set_secret("BLOCKSTACK_CLIENT_WALLET_PASSWORD", password)

    api_pass = getattr(args, 'api_pass', None)
    if api_pass is None:
        # environment?
        api_pass = get_secret('BLOCKSTACK_API_PASSWORD')
        
        if api_pass is None:
            # config file?
            conf = config.get_config(config_path)
            assert conf

            api_pass = conf.get('api_password', None)
            set_secret("BLOCKSTACK_API_PASSWORD", api_pass)

    if api_pass is None:
        return {'error': 'Need --api-password on the CLI, or `api_password=` set in your config file ({})'.format(config_path)}

    # sanity check: wallet must exist 
    if str(args.command) == 'start' and not wallet_exists(config_path=config_path):
        return {'error': 'Wallet does not exist.  Please create one with `blockstack setup`'}

    res = local_rpc.local_api_action(str(args.command), config_dir=config_dir, password=password, api_pass=api_pass)
    return res


def cli_name_import(args, interactive=True, config_path=CONFIG_PATH, proxy=None):
    """
    command: name_import advanced
    help: Import a name to a revealed but not-yet-launched namespace
    arg: name (str) 'The name to import'
    arg: address (str) 'The address of the name recipient'
    arg: zonefile_path (str) 'The path to the zone file'
    arg: privatekey (str) 'An unhardened child private key derived from the namespace reveal key'
    """

    import blockstack

    proxy = get_default_proxy(config_path) if proxy is None else proxy
    config_dir = os.path.dirname(config_path)
    conf = config.get_config(config_path)
    assert conf
    assert 'queue_path' in conf
    queue_path = conf['queue_path']

    # NOTE: we only need this for the queues.  This command is otherwise not accessible from the RESTful API,
    if not local_api_status(config_dir=config_dir):
        return {'error': 'API server not running.  Please start it with `blockstack api start`.'}

    name = str(args.name)
    address = virtualchain.address_reencode( str(args.address) )
    zonefile_path = str(args.zonefile_path)
    privkey = str(args.privatekey)

    try:
        privkey = ecdsa_private_key(privkey).to_hex()
    except:
        return {'error': 'Invalid private key'}

    if not re.match(OP_BASE58CHECK_PATTERN, address):
        return {'error': 'Invalid address'}

    if not os.path.exists(zonefile_path):
        return {'error': 'No such file or directory: {}'.format(zonefile_path)}

    zonefile_data = None
    try:
        with open(zonefile_path) as f:
            zonefile_data = f.read()

    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        return {'error': 'Failed to load {}'.format(zonefile_path)}

    zonefile_info = analyze_zonefile_string(name, zonefile_data, force_data=True, check_current=False, proxy=proxy)
    if 'error' in zonefile_info:
        log.error("Failed to analyze zone file: {}".format(zonefile_info['error']))
        return {'error': zonefile_info['error']}

    if zonefile_info['nonstandard']:
        if interactive:
            proceed = prompt_invalid_zonefile()
            if not proceed:
                return {'error': 'Aborting name import on invalid zone file'}

        else:
            log.warning("Using nonstandard zone file data")

    zonefile_data = zonefile_info['zonefile_str']
    zonefile_hash = get_zonefile_data_hash(zonefile_data)

    if interactive:
        fees = get_price_and_fees(name, ['name_import'], privkey, privkey, transfer_address=address, config_path=config_path, proxy=proxy)
        if 'error' in fees:
            return fees

        print("Import cost breakdown:\n{}".format(json.dumps(fees, indent=4, sort_keys=True)))
        print("Importing name '{}' to be owned by '{}' with zone file hash '{}'".format(name, address, zonefile_hash))
        proceed = raw_input("Proceed? (y/N) ")
        if proceed.lower() != 'y':
            return {'error': 'Name import aborted'}

    utxo_client = get_utxo_provider_client(config_path=config_path)
    tx_broadcaster = get_tx_broadcaster(config_path=config_path)
    res = do_name_import(name, privkey, address, zonefile_hash, utxo_client, tx_broadcaster, config_path=config_path, proxy=proxy, safety_checks=True)
    if 'error' in res:
        return res

    # success! enqueue to back-end
    queue_append("name_import", name, res['transaction_hash'], zonefile_data=zonefile_data, zonefile_hash=zonefile_hash, owner_address=address, config_path=config_path, path=queue_path)

    res['value_hash'] = zonefile_hash
    return res


def cli_make_import_keys(args, config_path=CONFIG_PATH, proxy=None):
    """
    command: make_import_keys advanced
    help: Generate private keys to import names into a revealed namespace
    arg: namespace_id (str) 'The namespace ID'
    arg: reveal_privkey (str) 'The private key that was used to reveal the namespace'
    """
    import blockstack

    reveal_privkey = str(args.reveal_privkey)
    namespace_id = str(args.namespace_id)
    proxy = get_default_proxy(config_path) if proxy is None else proxy

    namespace_rec = get_namespace_blockchain_record(namespace_id, proxy=proxy)
    if 'error' in namespace_rec:
        return namespace_rec

    if namespace_rec['ready']:
        return {'error': 'Namespace is already launched'}

    try:
        reveal_addr = virtualchain.get_privkey_address(reveal_privkey)
    except:
        return {'error': 'Unparseable private key'}

    if namespace_rec['recipient_address'] != reveal_addr:
        msg = "Wrong reveal private key: given private key address {} does not match namespace address {}".format(reveal_addr, namespace_rec['recipient_address'])
        print(msg)
        return {'error': msg}

    private_keychain = keychain.PrivateKeychain.from_private_key(reveal_privkey)
    
    for i in xrange(0, blockstack.NAME_IMPORT_KEYRING_SIZE):
        import_key = private_keychain.child(i).private_key()
        import_addr = virtualchain.get_privkey_address(import_key)
        print('{} ({})'.format(import_key, import_addr))

    return {'status': True}


def cli_namespace_preorder(args, config_path=CONFIG_PATH, interactive=True, proxy=None):
    """
    command: namespace_preorder advanced
    help: Preorder a namespace
    arg: namespace_id (str) 'The namespace ID'
    arg: payment_privkey (str) 'The private key to pay for the namespace'
    arg: reveal_privkey (str) 'The private key that will import names'
    """

    import blockstack

    # NOTE: this does *not* go through the API.
    # exposing this through the API is dangerous.
    proxy = get_default_proxy(config_path) if proxy is None else proxy

    config_dir = os.path.dirname(config_path)
    nsid = str(args.namespace_id)
    ns_privkey = str(args.payment_privkey)
    ns_reveal_privkey = str(args.reveal_privkey)
    reveal_addr = None
   
    try:
        ns_privkey = parse_privkey_info(ns_privkey)
        ns_reveal_privkey = keylib.ECPrivateKey(ns_reveal_privkey).to_hex()

        # force compresssed
        if virtualchain.is_singlesig(ns_privkey):
            ns_privkey = set_privkey_compressed(ns_privkey, compressed=True)

        ns_reveal_privkey = set_privkey_compressed(ns_reveal_privkey, compressed=True)
        reveal_addr = virtualchain.get_privkey_address(ns_reveal_privkey)
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        return {'error': 'Invalid namespace private key'}
   
    print("Calculating fees...")
    fees = get_price_and_fees(nsid, ['namespace_preorder'], ns_privkey, ns_privkey, config_path=config_path, proxy=proxy )
    if 'error' in fees or 'warnings' in fees:
        print('You do not have enough money to order this namespace!')
        return fees

    print("Checking that the namespace does not exist...")
    namespace_rec = get_namespace_blockchain_record(nsid, proxy=proxy)
    if 'error' not in namespace_rec:
        print("Namespace {} already exists!".format(nsid))
        return namespace_rec

    if 'failed to contact blockstack node' in namespace_rec['error'].lower():
        return namespace_rec
    
    msg = "".join([
        "\n",
        "IMPORTANT:  PLEASE READ THESE INSTRUCTIONS CAREFULLY\n",
        "\n",
        "You are about to preorder the namespace '{}'.  It will cost about {} BTC ({} satoshi).\n".format(nsid, fees['total_estimated_cost']['btc'], fees['total_estimated_cost']['satoshis']),
        'The address {} will be used to pay the fee, and will capture name fees (if created to do so).\n'.format(virtualchain.address_reencode(virtualchain.get_privkey_address(ns_privkey))),
        'The address {} will be used to reveal the namespace.\n'.format(virtualchain.address_reencode(reveal_addr)),
        'MAKE SURE YOU KEEP THE PRIVATE KEYS FOR BOTH ADDRESSES\n',
        "\n",
        "Before you preorder this namespace {}, there are some things you should know.\n".format(nsid),
        "\n",
        "* Once you preorder the namespace, you will need to reveal it within 144 blocks (about 24 hours).\n",
        "  If you do not do so, then the namespace fee is LOST FOREVER and someone else can preorder it.\n",
        "  In addition, there is a very small (but non-zero) chance that someone else can preorder and reveal\n",
        "  the same namespace at the same time as you are.  If this happens, your namespace fee is LOST FOREVER as well.\n",
        "\n",
        "  The command to reveal the namespace is `blockstack namespace_reveal`.  Please be prepared to run it\n",
        "  once your namespace-preorder transaction is confirmed.\n",
        "\n",
        "* You must launch the namespace within {} blocks (about 1 year) after it is revealed with the above command.\n".format(blockstack.BLOCKS_PER_YEAR),
        "  If you do not do so, then the namespace and all the names in it will DISAPPEAR, and you (or someone else)\n",
        "  will have to START THE NAMESPACE OVER FROM SCRATCH.\n",
        "\n",
        "  The command to launch the namespace is `blockstack namespace_ready`.  Please be prepared to run it\n",
        "  once your namespace-reveal transaction is confirmed, and once you have populated your namespace with\n",
        "  the initial names.\n",
        "\n",
        "* After you reveal the namespace but before you launch it, you can pre-populate it with names.\n",
        "  This is optional, but you have 1 year to import as many names as you want.\n",
        "  ONLY YOU WILL BE ABLE TO IMPORT NAMES until the namespace has been launched.  Then, anyone can register names.\n",
        "\n",
        "  The command to do so is `blockstack name_import`.\n",
        "\n",
        "\n",
        "To review, the sequence of steps you must take are:\n",
        "\n",
        "     $ blockstack namespace_preorder '{}' '{}' '{}'\n".format(nsid, serialize_privkey_info(ns_privkey), serialize_privkey_info(ns_reveal_privkey)),
        "     $ blockstack namespace_reveal '{}' '{}' '{}' $TXID   # within 144 blocks\n".format(nsid, serialize_privkey_info(ns_privkey), serialize_privkey_info(ns_reveal_privkey)),
        "     $ blockstack name_import .... # OPTIONAL\n",
        "     $ blockstack namespace_ready '{}' '{}'               # within {} blocks\n".format(nsid, serialize_privkey_info(ns_reveal_privkey), blockstack.BLOCKS_PER_YEAR),
        "\n",
        "\n"
        "You SHOULD test your namespace parameters before creating it using the integration test framework first.\n",
        "Instructions are at https://github.com/blockstack/blockstack-core/tree/master/integration_tests\n",
        "\n",
        "The addresses {} and {} SHOULD NOT have \n".format(
            virtualchain.address_reencode(reveal_addr), 
            virtualchain.address_reencode(keylib.ECPrivateKey(ns_reveal_privkey, compressed=False).public_key().address())
        ),
        "been used at any point in the past ({} is used as a salt in the preorder).\n".format(reveal_addr),
        "If either address was used before, then there is a chance that an attacker could deduce the namespace you\n",
        "are preordering, and preorder/reveal it before you do.\n",
        "\n",
        "If you have any questions, please contact us at support@blockstack.com or via https://blockstack.slack.com\n",
        "\n",
        "Full cost breakdown:\n",
        "{}".format(json.dumps(fees, indent=4, sort_keys=True)),
        "\n",
    ])

    print(msg)

    prompts = [
        "I acknowledge that I have read and understood the above instructions (yes/no) ",
        "I acknowledge that this will cost {} BTC or more (yes/no) ".format(fees['total_estimated_cost']['btc']),
        "I acknowledge that by not following these instructions, I may lose {} BTC (yes/no) ".format(fees['total_estimated_cost']['btc']),
        "I acknowledge that I have tested my namespace in Blockstack's test mode (yes/no) ",
        "I acknowledge that the addresses {} and {} have never been used before (yes/no) ".format(
            virtualchain.address_reencode(reveal_addr),
            virtualchain.address_reencode(keylib.ECPrivateKey(ns_reveal_privkey, compressed=False).public_key().address())
        ),
        "I have copied down the sequence of commands above, so I do not forget them (yes/no) ",
        "I will remember to copy down the transaction ID, and wait for it to confirm before revealing the namespace (yes/no) ",
        "I will issue these commands at the right times (yes/no) ",
        "If I do not understand any of the above, I will seek help first (yes/no) ",
        "I am ready to preorder this namespace (yes/no) "
    ]

    for prompt in prompts:
        while True:
            if interactive:
                proceed = raw_input(prompt)
            else:
                proceed = 'yes'

            if proceed.lower() == 'y':
                print("Please type 'yes' or 'no'")
                continue

            if proceed.lower() != 'yes':
                return {'error': 'Aborting namespace preorder on user command'}

            break

    # proceed!
    utxo_client = get_utxo_provider_client(config_path=config_path)
    tx_broadcaster = get_tx_broadcaster(config_path=config_path)
    res = do_namespace_preorder(nsid, int(fees['namespace_price']), ns_privkey, reveal_addr, utxo_client, tx_broadcaster, config_path=config_path, proxy=proxy, safety_checks=True)
    if 'error' in res:
        return res

    print('')
    print('Remember this transaction ID: {}'.format(res['transaction_hash']))
    print('You will need it for `blockstack namespace_reveal`')
    print('')
    print('Wait until {} has six (6) confirmations.  Then, you can reveal `{}` with:'.format(res['transaction_hash'], nsid))
    print('')
    print('    $ blockstack namespace_reveal "{}" "{}" "{}" "{}"'.format(nsid, serialize_privkey_info(ns_privkey), serialize_privkey_info(ns_reveal_privkey), res['transaction_hash']))
    print('')
            
    return res


def format_cost_table(namespace_id, base, coeff, bucket_exponents, nonalpha_discount, no_vowel_discount, block_height):
    """
    Generate a string that contains a table of how much a name of a particular length will cost,
    subject to particular discounts.
    """
    import blockstack

    columns = [
        'length',
        'price',
        'price, nonalpha',
        'price, no vowel',
        'price, both'
    ]

    table = dict( [(c, [c]) for c in columns] )

    namespace_params = {
        'base': base,
        'coeff': coeff,
        'buckets': bucket_exponents,
        'nonalpha_discount': nonalpha_discount,
        'no_vowel_discount': no_vowel_discount,
        'namespace_id': namespace_id
    }

    for i in xrange(0, len(bucket_exponents)):
        length = i+1
        price_normal = str(int(round( blockstack.price_name("a" * length, namespace_params, block_height) )))
        price_nonalpha = str(int(round( blockstack.price_name(("1a" * length)[:length], namespace_params, block_height) )))
        price_novowel = str(int(round( blockstack.price_name("b" * length, namespace_params, block_height) )))
        price_nonalpha_novowel = str(int(round( blockstack.price_name("1" * length, namespace_params, block_height) )))
        
        len_str = str(length)
        if i == len(bucket_exponents)-1:
            len_str += '+'

        table['length'].append(len_str)
        table['price'].append(price_normal)
        table['price, nonalpha'].append(price_nonalpha)
        table['price, no vowel'].append(price_novowel)
        table['price, both'].append(price_nonalpha_novowel)

    col_widths = {}
    for k in table.keys():
        max_width = reduce( lambda x, y: max(x,y), map( lambda p: len(p), table[k] ) )
        col_widths[k] = max_width

    row_template_parts = [' {{: >{}}} '.format(col_widths[c]) for c in columns]
    header_template_parts = [' {{: <{}}} '.format(col_widths[c]) for c in columns]

    row_template = '|' + '|'.join(row_template_parts) + '|'
    header_template = '|' + '|'.join(header_template_parts) + '|'

    table_str = header_template.format(*columns) + '\n'
    table_str += '-' * (len(table_str) - 1) + '\n'
    
    for i in xrange(1, len(bucket_exponents)+1):
        row_data = [table[c][i] for c in columns]
        table_str += row_template.format(*row_data) + '\n'

    return table_str


def format_price_formula(namespace_id, block_height):
    """
    Generate a string that encodes the generic price function
    """
    import blockstack


    exponent_str =    "                                     buckets[min(len(name)-1, 15)]\n"
    numerator_str =   "             UNIT_COST * coeff * base                             \n"
    divider_str =     "cost(name) = -----------------------------------------------------\n"
    denominator_str = "                   max(nonalpha_discount, no_vowel_discount)      \n"

    unit_cost = blockstack.NAME_COST_UNIT * blockstack.get_epoch_price_multiplier(block_height, '*')
    currency_name = 'satoshi'
    
    formula_str = "(UNIT_COST = {} {}):\n".format(unit_cost, currency_name) + \
                  exponent_str + \
                  numerator_str + \
                  divider_str + \
                  denominator_str

    return formula_str


def format_price_formula_worksheet(name, namespace_id, base, coeff, bucket_exponents, nonalpha_discount, no_vowel_discount, block_height):
    """
    Generate a string that encodes the namespace price function for a particular name
    """
    import blockstack

    if '.' in name:
        if name.count('.') != 1:
            return '\nThe specified name is invalid.  Names may not have periods (.) in them\n'

        name_parts = name.split('.')
        name = name_parts[0]
        if name_parts[1] != namespace_id:
            return '\nThe name specified does not belong to this namespace\n'

    full_name = '{}.{}'.format(name, namespace_id)
    err = check_valid_name(full_name)
    if err:
        return "\nFully-qualified name: {}\n{}\n".format(full_name, err)

    namespace_params = {
        'base': base,
        'coeff': coeff,
        'buckets': bucket_exponents,
        'nonalpha_discount': nonalpha_discount,
        'no_vowel_discount': no_vowel_discount,
        'namespace_id': namespace_id
    }

    def has_no_vowel_discount(n):
        return sum( [n.lower().count(v) for v in ["a", "e", "i", "o", "u", "y"]] ) == 0

    def has_nonalpha_discount(n):
        return sum( [n.lower().count(v) for v in ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "-", "_"]] ) > 0
    
    discount = 1

    # no vowel discount?
    if has_no_vowel_discount(name):
       # no vowels!
       discount = max( discount, no_vowel_discount )

    # non-alpha discount?
    if has_nonalpha_discount(name):
       # non-alpha!
       discount = max( discount, nonalpha_discount )

    eval_numerator_str = "{} * {} * {}".format(blockstack.NAME_COST_UNIT * blockstack.get_epoch_price_multiplier(block_height, namespace_id), coeff, base)
    eval_exponent_str = "{}".format(bucket_exponents[min(len(name)-1, 15)])
    eval_denominator_str = "{}".format(discount)

    eval_divider_str = "cost({}) = ".format(name)
    left_pad = len(eval_divider_str)

    numerator_len = len(eval_numerator_str) + len(eval_exponent_str)
    denominator_len = len(eval_denominator_str)

    padded_exponent_str = (" " * (left_pad + len(eval_numerator_str))) + eval_exponent_str + '\n'
    padded_numerator_str = (" " * left_pad) + eval_numerator_str + '\n'
    padded_divider_str = eval_divider_str + ("-" * numerator_len) + (" = {}".format(int(blockstack.price_name(name, namespace_params, block_height)))) + '\n'
    padded_denominator_str = (" " * (left_pad + (numerator_len / 2) - (denominator_len / 2))) + eval_denominator_str + '\n'

    formula_str = "Worksheet:\n" + \
                  "\n" + \
                  "len({}) = {}\n".format(name, len(name)) + \
                  "buckets[min(len(name)-1, 15)] = buckets[min({}, 15)] = buckets[{}] = {}\n".format(len(name)-1, min(len(name)-1, 15), bucket_exponents[min(len(name)-1, 15)]) + \
                  "nonalpha_discount = {}\n".format( nonalpha_discount if has_nonalpha_discount(name) else 1 ) + \
                  "no_vowel_discount = {}\n".format( no_vowel_discount if has_no_vowel_discount(name) else 1 ) + \
                  "max(nonalpha_discount, no_vowel_discount) = max({}, {}) = {}\n".format(nonalpha_discount if has_nonalpha_discount(name) else 1, no_vowel_discount if has_no_vowel_discount(name) else 1, discount) + \
                  "\n" + \
                  padded_exponent_str + \
                  padded_numerator_str + \
                  padded_divider_str + \
                  padded_denominator_str + \
                  "\n"
    
    return formula_str


def verify_namespace_preorder(namespace_id, ns_preorder_txid, payment_privkey, ns_reveal_privkey, config_path=CONFIG_PATH):
    """
    Verify that the given txid corresponds to a well-formed namespace preorder transaction,
    and that the given keys are valid.
    Return {'status': True} on success
    Return {'error': ...} on failure
    """
    import blockstack

    # load config
    conf = config.get_config(config_path)
    assert conf

    bitcoind_opts = virtualchain.get_bitcoind_config(config_file=config_path)
    assert bitcoind_opts

    # confirm that these are, in fact, the correct keys
    print("Looking up NAMESPACE_PREORDER at {}...".format(ns_preorder_txid))

    # TODO: this is messy, and exposes a need for a classmethod for fetching and parsing bulk transactions.
    # Introduce this in the next version of virtualchain.
    bdl = virtualchain.BlockchainDownloader(bitcoind_opts, conf['bitcoind_spv_path'], 0, 0, p2p_port=int(conf['bitcoind_port']))
    tx = None
    try:
        txinfo = bdl.fetch_txs_rpc(bitcoind_opts, [ns_preorder_txid])

        assert txinfo is not None and 'error' not in txinfo
        assert ns_preorder_txid in txinfo

        txinfo = txinfo[ns_preorder_txid]
    except Exception as e:
        log.exception(e)
        return {'error': 'Failed to look up transaction {}'.format(ns_preorder_txid)}

    # find OP_RETURN output
    payload_hex = None
    payload_idx = None
    for i, out in enumerate(txinfo['vout']):
        if out['scriptPubKey']['type'] == 'nulldata':
            payload_hex = out['scriptPubKey']['hex']
            payload_idx = i

    if payload_hex is None:
        # definitely not a NAMESPACE_PREORDER
        return {'error': 'Transaction {} is not a NAMESPACE_PREORDER: no OP_RETURN output'.format(ns_preorder_txid)}

    if payload_hex[4:10].decode('hex') != 'id*':
        # (note: wire format is "OP_RETURN [1-byte-length] ord('i') ord('d') ord('*')")
        # definitely NOT a NAMESPACE_PREORDER
        return {'error': 'Transaction {} is not a NAMESPACE_PREORDER: invalid OP_RETURN output {}'.format(ns_preorder_txid, payload_hex)}

    print("Lookup up NAMESPACE_PREORDER funding transactions...")

    # go find the senders
    bdl = virtualchain.BlockchainDownloader(bitcoind_opts, conf['bitcoind_spv_path'], 0, 0, p2p_port=int(conf['bitcoind_port']))
    sender_txids = []
    senders = {}
    for inp in txinfo['vin']:
        sender_txid = inp['txid']
        sender_txids.append(sender_txid)

    for i in xrange(0, len(sender_txids), 20):
        txid_batch = sender_txids[i:i+20]
        txs = bdl.fetch_txs_rpc(bitcoind_opts, txid_batch)
        if txs is None or 'error' in txs:
            if txs is None:
                txs = {'error': 'Failed to fetch NAMESPACE_PREORDER funding transactions {}-{}'.format(i,i+20)}

            log.error("Failed to fetch NAMESPACE_PREORDER funding transactions {}-{}".format(i,i+20))
            return txs

        senders.update(txs)

    assert len(senders) == len(txinfo['vin']), "Failed to fetch all funding transactions for {}".format(ns_preorder_txid)

    # senders maps sender txid to the transaction that created it.
    # instead, put senders in 1-to-1 correspondance with the NAMESPACE_PREORDER inputs
    # TODO: clean this up--this basically duplicates functionality in the blockchain downloader in virtualchain
    sender_list = [None] * len(senders)
    for i in xrange(0, len(txinfo['vin'])):
        if txinfo['vin'][i]['txid'] in senders.keys():
            sender_rec = senders[txinfo['vin'][i]['txid']]
            sender_outpoint = txinfo['vin'][i]['vout']
            sender_output = sender_rec['vout'][sender_outpoint]

            sender_info = {
                "amount": sender_output['value'],
                "script_pubkey": sender_output['scriptPubKey']['hex'],
                "script_type": sender_output['scriptPubKey']['type'],
                "addresses": sender_output['scriptPubKey']['addresses'],
                "nulldata_vin_outpoint": payload_idx,
                "txid": txinfo['vin'][i]['txid']
            }

            sender_list[i] = sender_info
           
        else:
            print("Failed to find funding transaction to input {} in {} (missing {})".format(i, ns_preorder_txid, txinfo['vin'][i]['txid']))
            return {'error': 'Failed to find funding transactions for {}'.format(ns_preorder_txid)}

    try:
        ns_preorder_info = blockstack.lib.operations.extract_namespace_preorder(payload_hex[10:].decode('hex'), sender_list, txinfo['vin'], txinfo['vout'], 0, 0, ns_preorder_txid)
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        return {'error': 'Transaction {} could not be parsed as a NAMESPACE_PREORDER'.format(ns_preorder_txid)}

    # this looks like a NAMESPACE_PREORDER
    # but was it created with these keys?
    if ns_preorder_info['address'] != virtualchain.get_privkey_address(payment_privkey):
        return {'error': 'Private key does not match namespace preorder address: expected {}, got {}'.format(ns_preorder_info['address'], virtualchain.get_privkey_address(payment_privkey))}

    # does the hash match?
    ph = blockstack.hash_name(namespace_id, virtualchain.make_payment_script(virtualchain.get_privkey_address(payment_privkey)), virtualchain.get_privkey_address(ns_reveal_privkey))
    if ns_preorder_info['preorder_hash'] != ph:
        return {'error': 'Preorder hash {} does not match: hash({}, {}, {}) == {}'.format(
            ns_preorder_info['preorder_hash'],
            namespace_id, 
            virtualchain.make_payment_script(virtualchain.get_privkey_address(payment_privkey)),
            virtualchain.get_privkey_address(ns_reveal_privkey),
            ph
        )}

    return {'status': True}


def cli_namespace_reveal(args, interactive=True, config_path=CONFIG_PATH, proxy=None, version=None):
    """
    command: namespace_reveal advanced
    help: Reveal a namespace and interactively set its pricing parameters
    arg: namespace_id (str) 'The namespace ID'
    arg: payment_privkey (str) 'The private key or keys that paid for the namespace'
    arg: reveal_privkey (str) 'The private key that will import names'
    arg: preorder_txid (str) 'The TXID of the NAMESPACE_PREORDER transaction, from the `namespace_preorder` command'
    """
    # NOTE: this will not use the RESTful API.
    # it is too dangerous to expose this to web browsers.
    import blockstack
    
    namespace_id = str(args.namespace_id)
    privkey = str(args.payment_privkey)
    ns_addr = None
    reveal_privkey = str(args.reveal_privkey)
    ns_preorder_txid = str(args.preorder_txid)

    reveal_addr = None

    res = is_namespace_valid(namespace_id)
    if not res:
        return {'error': 'Invalid namespace ID'}

    try:
        privkey = parse_privkey_info(privkey)
        reveal_privkey = keylib.ECPrivateKey(reveal_privkey).to_hex()

        # force compresssed
        if virtualchain.is_singlesig(privkey):
            privkey = set_privkey_compressed(privkey, compressed=True)

        ns_reveal_privkey = set_privkey_compressed(reveal_privkey, compressed=True)

        reveal_addr = virtualchain.get_privkey_address(reveal_privkey)
        ns_addr = virtualchain.get_privkey_address(privkey)
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        return {'error': 'Invalid private keys'}
           
    res = verify_namespace_preorder(namespace_id, ns_preorder_txid, privkey, reveal_privkey, config_path=config_path)
    if 'error' in res:
        return res

    infinite_lifetime = 0xffffffff       # means "infinite" to blockstack-core
    
    def _sane_default(argvec, value, default):
        res = None
        if hasattr(argvec, value):
            res = getattr(argvec, value)
        
        if res is None:
            res = default

        return res

    # sane defaults
    lifetime = int(_sane_default(args, 'lifetime', infinite_lifetime))
    coeff = int(_sane_default(args, 'coeff', 4))
    base = int(_sane_default(args, 'base', 4))
    bucket_exponents_str = _sane_default(args, 'buckets', "15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0")
    nonalpha_discount = int(_sane_default(args, 'nonalpha_discount', 2))
    no_vowel_discount = int(_sane_default(args, 'no_vowel_discount', 5))

    def parse_bucket_exponents(exp_str):

        bucket_exponents_strs = exp_str.split(',')
        if len(bucket_exponents_strs) != 16:
            raise Exception('bucket_exponents must be a 16-value comma-separated list of integers')

        bucket_exponents = []
        for i in xrange(0, len(bucket_exponents_strs)):
            try:
                bucket_exponents.append( int(bucket_exponents_strs[i]) )
                assert 0 <= bucket_exponents[i]
                assert bucket_exponents[i] < 16
            except (ValueError, AssertionError) as e:
                raise Exception('bucket_exponents must contain integers between 0 and 15, inclusively')

        return bucket_exponents

    def print_namespace_configuration(params):
        
        namespace_lifetime_multiplier = blockstack.get_epoch_namespace_lifetime_multiplier(block_height, '*')

        print("Namespace ID:            {}".format(namespace_id))
        print("Name lifetimes (blocks): {}".format(params['lifetime'] * namespace_lifetime_multiplier if params['lifetime'] != infinite_lifetime else "infinite"))
        print("Price coefficient:       {}".format(params['coeff']))
        print("Price base:              {}".format(params['base']))
        print("Price bucket exponents:  {}".format(params['buckets']))
        print("Non-alpha discount:      {}".format(params['nonalpha_discount']))
        print("No-vowel discount:       {}".format(params['no_vowel_discount']))
        print("Burn or receive fees?    {}".format('Receive to {}'.format(virtualchain.address_reencode(ns_addr)) if params['receive_fees'] else 'Burn'))
        print("")

        formula_str = format_price_formula(namespace_id, block_height)
        price_table_str = format_cost_table(namespace_id, params['base'], params['coeff'], params['buckets'],
                                                          params['nonalpha_discount'], params['no_vowel_discount'], block_height)

        print("Name price formula:")
        print(formula_str)
        print("")
        print("Name price table:")
        print(price_table_str)

        print("")


    bbs = None
    try:
        bbs = parse_bucket_exponents(bucket_exponents_str)
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        return {'error': 'Invalid bucket exponents.  Must be a list of 16 integers between 0 and 15.'}
        
    namespace_params = {
        'lifetime': lifetime,
        'coeff': coeff,
        'base': base,
        'buckets': bbs,
        'nonalpha_discount': nonalpha_discount,
        'no_vowel_discount': no_vowel_discount,
        'receive_fees': True
    }

    if version is not None:
        namespace_params['receive_fees'] = True if (version & blockstack.NAMESPACE_VERSION_PAY_TO_BURN) else False

    block_height = get_block_height(config_path=config_path)
    log.debug("Block height is {}".format(block_height))

    options = {
        '0': {
            'msg': 'Set name lifetime in blocks             (positive integer between 1 and {}, or "infinite")'.format(2**32 - 1),
            'var': 'lifetime',
            'parse': lambda x: infinite_lifetime if x == "infinite" else int(x)/namespace_lifetime_multiplier
        },
        '1': {
            'msg': 'Set price coefficient                   (positive integer between 1 and 255)',
            'var': 'coeff',
            'parse': lambda x: int(x)
        },
        '2': {
            'msg': 'Set base price                          (positive integer between 1 and 255)',
            'var': 'base',
            'parse': lambda x: int(x)
        },
        '3': {
            'msg': 'Set price bucket exponents              (16 comma-separated integers, each between 1 and 15)',
            'var': 'buckets',
            'parse': lambda x: parse_bucket_exponents(x)
        },
        '4': {
            'msg': 'Set non-alphanumeric character discount (positive integer between 1 and 15)',
            'var': 'nonalpha_discount',
            'parse': lambda x: int(x)
        },
        '5': {
            'msg': 'Set no-vowel discount                   (positive integer between 1 and 15)',
            'var': 'no_vowel_discount',
            'parse': lambda x: int(x)
        },
        '6': {
            'msg': 'Toggle collecting name fees             (True: receive fees; False: burn fees)',
            'var': 'receive_fees',
            'parse': lambda x: False if x.lower() in ['false', '0'] else True
        },
        '7': {
            'msg': 'Show name price formula',
            'input': 'Enter name: ',
            'callback': lambda inp: print(format_price_formula_worksheet(inp, namespace_id, namespace_params['base'], namespace_params['coeff'],
                                                                         namespace_params['buckets'], namespace_params['nonalpha_discount'], 
                                                                         namespace_params['no_vowel_discount'], block_height))
        },
        '8': {
            'msg': 'Show price table',
            'callback': lambda: print(print_namespace_configuration(namespace_params)),
        },
        '9': {
            'msg': 'Done',
            'break': True,
        },
    }
    option_order = options.keys()
    option_order.sort()
    
    print_namespace_configuration(namespace_params)

    while interactive:

        print("What would you like to do?")

        for opt in option_order:
            print("({}) {}".format(opt, options[opt]['msg']))

        print("")

        selection = None
        value = None
        while True:
            selection = raw_input("({}-{}) ".format(option_order[0], option_order[-1]))
            if selection not in options:
                print("Please select between {} and {}".format(option_order[0], option_order[-1]))
                continue
            else:
                break

        if options[selection].has_key('var'):
            value_str = raw_input("New value for '{}': ".format(options[selection]['var']))
            old_value = namespace_params[ options[selection]['var'] ]
            try:
                value = options[selection]['parse'](value_str)
                namespace_params[ options[selection]['var'] ] = value
                version = blockstack.NAMESPACE_VERSION_PAY_TO_CREATOR if namespace_params['receive_fees'] else blockstack.NAMESPACE_VERSION_PAY_TO_BURN

                assert blockstack.namespacereveal.namespacereveal_sanity_check( namespace_id, version, namespace_params['lifetime'],
                                                                                namespace_params['coeff'], namespace_params['base'], namespace_params['buckets'],
                                                                                namespace_params['nonalpha_discount'], namespace_params['no_vowel_discount'] )

            except Exception as e:
                if BLOCKSTACK_DEBUG:
                    log.exception(e)

                print("Invalid value for '{}'".format(options[selection]['var']))
                namespace_params[ options[selection]['var'] ] = old_value

            print_namespace_configuration(namespace_params)
            continue

        elif options[selection].has_key('input'):
            inpstr = options[selection]['input']
            inp = raw_input(inpstr)
            options[selection]['callback'](inp)
            continue

        elif options[selection].has_key('callback'):
            options[selection]['callback']()
            continue

        elif options[selection].has_key('break'):
            break

        else:
            raise Exception("BUG: selection {}".format(selection))

    if not interactive:
        # still check this 
        try:
            version = blockstack.NAMESPACE_VERSION_PAY_TO_CREATOR if namespace_params['receive_fees'] else blockstack.NAMESPACE_VERSION_PAY_TO_BURN
            assert blockstack.namespacereveal.namespacereveal_sanity_check( namespace_id, version, namespace_params['lifetime'],
                                                                            namespace_params['coeff'], namespace_params['base'], namespace_params['buckets'],
                                                                            namespace_params['nonalpha_discount'], namespace_params['no_vowel_discount'] )
        except Exception as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            return {'error': 'Invalid namespace parameters'}

    # do we have enough btc?
    print("Calculating fees...")
    fees = get_price_and_fees(namespace_id, ['namespace_reveal'], privkey, reveal_privkey, config_path=config_path, proxy=proxy )
    if 'error' in fees:
        return fees

    if 'warnings' in fees:
        return {'error': 'Not enough information for fee calculation: {}'.format( ", ".join(["'{}'".format(w) for w in fees['warnings']]) )}

    # got the params we wanted
    print("This is the final configuration for your namespace:") 
    print_namespace_configuration(namespace_params)
    print("You will NOT be able to change this once it is set.")
    print("Reveal address:            {}".format(virtualchain.address_reencode(reveal_addr)))
    print("Payment address:           {}".format(virtualchain.address_reencode(ns_addr)))
    print("Burn or receive name fees? {}".format('Receive' if namespace_params['receive_fees'] else 'Burn'))
    print("Transaction cost breakdown:\n{}".format(json.dumps(fees, indent=4, sort_keys=True)))
    print("")

    while interactive:
        proceed = raw_input("Proceed? (yes/no) ")
        if proceed.lower() == 'y':
            print("Please type 'yes' or 'no'")
            continue

        if proceed.lower() != 'yes':
            return {'error': 'Aborted namespace reveal'}

        break

    # proceed!
    utxo_client = get_utxo_provider_client(config_path=config_path)
    tx_broadcaster = get_tx_broadcaster(config_path=config_path)
    version = blockstack.NAMESPACE_VERSION_PAY_TO_CREATOR if namespace_params['receive_fees'] else blockstack.NAMESPACE_VERSION_PAY_TO_BURN

    res = do_namespace_reveal(namespace_id, version, reveal_addr, namespace_params['lifetime'], namespace_params['coeff'], namespace_params['base'], namespace_params['buckets'],
                              namespace_params['nonalpha_discount'], namespace_params['no_vowel_discount'], privkey, utxo_client, tx_broadcaster, config_path=config_path, proxy=proxy, safety_checks=True)

    if 'error' in res:
        return res

    print('')
    print('Successfully sent transaction to reveal namespace `.{}`'.format(namespace_id))
    print('Once it confirms, you will have the option to import names.')
    print('To do so, you can use the following command:')
    print('')
    print('    $ blockstack name_import NAME.{} RECIPIENT_ADDRESS /path/to/name/zonefile {}'.format(namespace_id, reveal_privkey))
    print('')
    print('Example:')
    print('')
    print('    $ blockstack name_import helloworld.{} {} /var/blockstack/helloworld.{} {}'.format(namespace_id, ns_addr, namespace_id, reveal_privkey))
    print('')
    print('If you want to import many names (thousands or more), please see docs/namespace_creation.md for how to do so efficiently.')
    print('')
    print('Once you are satisfied with your namespace, you can launch it to the public with this command:')
    print('')
    print('    $ blockstack namespace_ready {} {}'.format(namespace_id, reveal_privkey))
    print('')
    print('(NOTE: you may need to fund the reveal private key address {} first)'.format(reveal_addr))
    print('')
    print('YOU MUST RUN THE ABOVE namespace_ready COMMAND BEFORE BLOCK {}'.format(block_height + blockstack.NAMESPACE_REVEAL_EXPIRE - 10))     # - 10 to give a buffer
    print('')
    return res


def cli_namespace_ready(args, interactive=True, config_path=CONFIG_PATH, proxy=None):
    """
    command: namespace_ready advanced
    help: Mark a namespace as ready
    arg: namespace_id (str) 'The namespace ID'
    arg: reveal_privkey (str) 'The private key used to import names'
    """

    import blockstack
    namespace_id = str(args.namespace_id)
    reveal_privkey = str(args.reveal_privkey)

    res = is_namespace_valid(namespace_id)
    if not res:
        return {'error': 'Invalid namespace ID'}
    
    try:
        reveal_privkey = keylib.ECPrivateKey(reveal_privkey).to_hex()

        # force compresssed 
        reveal_privkey = set_privkey_compressed(reveal_privkey, compressed=True)
        reveal_addr = virtualchain.get_privkey_address(reveal_privkey)
    except:
        return {'error': 'Invalid private keys'}

    # do we have enough btc?
    print("Calculating fees...")
    fees = get_price_and_fees(namespace_id, ['namespace_ready'], reveal_privkey, reveal_privkey, config_path=config_path, proxy=proxy )
    if 'error' in fees:
        return fees

    if 'warnings' in fees:
        print('Insufficient balance in {}'.format(reveal_addr))
        return {'error': 'Not enough information for fee calculation: {}'.format( ", ".join(["'{}'".format(w) for w in fees['warnings']]) )}

    namespace_rec = get_namespace_blockchain_record(namespace_id, proxy=proxy)
    if 'error' in namespace_rec:
        return namespace_rec

    if namespace_rec['ready']:
        return {'error': 'Namespace is already launched'}

    if namespace_rec['recipient_address'] != reveal_addr:
        msg = "Wrong reveal private key: given private key address {} does not match namespace address {}".format(reveal_addr, namespace_rec['recipient_address'])
        print(msg)
        return {'error': msg}

    launch_deadline = namespace_rec['reveal_block'] + blockstack.NAMESPACE_REVEAL_EXPIRE

    print("Cost breakdown:\n{}".format(json.dumps(fees, indent=4, sort_keys=True)))
    print("This command will launch the namespace '{}'".format(namespace_id))
    print("Once launched, *anyone* can register a name in it.")
    print("This namespace must be launched by block {}, so please run this command before block {}.".format(launch_deadline, launch_deadline - 144))
    print("THIS CANNOT BE UNDONE.")
    print("")
    while True:
        proceed = None
        if interactive:
            proceed = raw_input("Proceed? (yes/no) ")
        else:
            proceed = 'yes'

        if proceed.lower() == 'y':
            print("Please type 'yes' or 'no'")
            continue

        if proceed.lower() != 'yes':
            return {'error': 'Namespace launch aborted'}

        break

    # proceed!
    utxo_client = get_utxo_provider_client(config_path=config_path)
    tx_broadcaster = get_tx_broadcaster(config_path=config_path)
    res = do_namespace_ready(namespace_id, reveal_privkey, utxo_client, tx_broadcaster, config_path=config_path, proxy=proxy, safety_checks=True)
    return res


def cli_put_mutable(args, config_path=CONFIG_PATH, password=None, proxy=None, storage_drivers=None, storage_drivers_exclusive=False):
    """
    command: put_mutable advanced
    help: Low-level method to store off-chain signed data.
    arg: name (str) 'The name that points to the zone file to use'
    arg: data_id (str) 'The name of the data'
    arg: data_path (str) 'The path to the data to store'
    opt: privkey (str) 'The private key to sign with'
    opt: version (str) 'The version of this data to store'
    """
    
    password = get_default_password(password)
    
    fqu = str(args.name)
    data_id = str(args.data_id)
    data_path = str(args.data)

    data = None
    with open(data_path, 'r') as f:
        data = f.read()

    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    config_dir = os.path.dirname(config_path)
    privkey = None
    if not hasattr(args, 'privkey') or args.privkey is None:
        
        # get the data private key from the wallet.
        # put_mutable() should only succeed if the zone file for this name
        # has the corresponding public key, since otherwise there would be
        # no way to authenticate this data.
        zfinfo = get_name_zonefile(fqu, proxy=proxy)
        if 'error' in zfinfo:
            log.error("unable to load zone file for {}: {}".format(fqu, zfinfo['error']))
            return {'error': 'unable to load or parse zone file for {}'.format(fqu)}
       
        if not user_zonefile_data_pubkey(zfinfo['zonefile']):
            log.error("zone file for {} has no public key".format(fqu))
            return {'error': 'zone file for {} has no public key'.format(fqu)}

        wallet_keys = get_wallet_keys(config_path, password)
        if 'error' in wallet_keys:
            return wallet_keys

        privkey = str(wallet_keys['data_privkey'])
        pubkey = keylib.key_formatting.compress(ecdsa_private_key(privkey).public_key().to_hex())
        zfpubkey = keylib.key_formatting.compress(user_zonefile_data_pubkey(zfinfo['zonefile']))
        if pubkey != zfpubkey:
            log.error("public key mismatch: wallet public key {} != zonefile public key {}".format(pubkey, zfpubkey))
            return {'error': 'public key mismatch: wallet public key {} does not match zone file public key {}'.format(pubkey, zfpubkey)}

    else:
        privkey = str(args.privkey)

    try:
        pubkey = ecdsa_private_key(privkey).public_key().to_hex()
    except Exception as e:
        if BLOCKSTACK_TEST:
            log.exception(e)
            log.error("Invalid private key {}".format(privkey))

        return {'error': 'Failed to parse private key'}

    mutable_data_info = make_mutable_data_info(data_id, data, blockchain_id=fqu, config_path=config_path)
    mutable_data_payload = data_blob_serialize(mutable_data_info)

    proxy = get_default_proxy(config_path=config_path) if proxy is None else proxy
    sig = sign_data_payload(mutable_data_payload, privkey)

    result = put_mutable(mutable_data_info['fq_data_id'], mutable_data_payload, pubkey, sig, mutable_data_info['version'], \
                         blockchain_id=fqu, config_path=config_path, proxy=proxy, storage_drivers=storage_drivers, storage_drivers_exclusive=storage_drivers_exclusive) 

    if 'error' in result:
        return result

    return result


def cli_put_immutable(args, config_path=CONFIG_PATH, password=None, proxy=None):
    """
    command: put_immutable advanced
    help: Put signed, blockchain-hashed data into your storage providers.
    arg: name (str) 'The name that points to the zone file to use'
    arg: data_id (str) 'The name of the data'
    arg: data (str) 'Path to the data to store'
    """

    password = get_default_password(password)
    config_dir = os.path.dirname(config_path)

    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    data_path = str(args.data)
    with open(data_path, 'r') as f:
        data = f.read()

    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    proxy = get_default_proxy(config_path) if proxy is None else proxy

    result = put_immutable(
        fqu, str(args.data_id), data,
        wallet_keys=wallet_keys, proxy=proxy
    )

    if 'error' in result:
        return result
    
    data_hash = result['immutable_data_hash']
    result['hash'] = data_hash
    return result


def cli_get_mutable(args, config_path=CONFIG_PATH, proxy=None):
    """
    command: get_mutable advanced
    help: Low-level method to get signed off-chain data.
    arg: name (str) 'The blockchain ID that owns the data'
    arg: data_id (str) 'The name of the data'
    opt: data_pubkey (str) 'The public key to use to verify the data'
    opt: device_ids (str) 'A CSV of devices to query'
    """
    data_pubkey = str(args.data_pubkey) if hasattr(args, 'data_pubkey') and getattr(args, 'data_pubkey') is not None else None

    # get the list of device IDs to use 
    device_ids = getattr(args, 'device_ids', None)
    if device_ids:
        device_ids = device_ids.split(',')

    else:
        device_ids = [get_local_device_id(os.path.dirname(config_path))]

    result = get_mutable(str(args.data_id), device_ids, proxy=proxy, config_path=config_path, blockchain_id=str(args.name), data_pubkey=data_pubkey)
    if 'error' in result:
        return result

    return {'status': True, 'data': result['data']}


def cli_get_immutable(args, config_path=CONFIG_PATH, proxy=None):
    """
    command: get_immutable advanced
    help: Get signed, blockchain-hashed data from storage providers.
    arg: name (str) 'The name that points to the zone file with the data hash'
    arg: data_id_or_hash (str) 'Either the name or the SHA256 of the data to obtain'
    """
    proxy = get_default_proxy(config_path) if proxy is None else proxy

    if is_valid_hash( args.data_id_or_hash ):
        result = get_immutable(str(args.name), str(args.data_id_or_hash), proxy=proxy)
        if 'error' not in result:
            return result

    # either not a valid hash, or no such data with this hash.
    # maybe this hash-like string is the name of something?
    result = get_immutable_by_name(str(args.name), str(args.data_id_or_hash), proxy=proxy)
    if 'error' in result:
        return result

    return {
        'data': result['data'],
        'hash': result['hash']
    }


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
    arg: data_id (str) 'The SHA256 of the data to remove, or the data ID'
    """

    password = get_default_password(password)

    config_dir = os.path.dirname(config_path)
    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    if proxy is None:
        proxy = get_default_proxy(config_path)

    result = None
    if is_valid_hash(str(args.data_id)):
        result = delete_immutable(
            str(args.name), str(args.data_id),
            proxy=proxy, wallet_keys=wallet_keys
        )
    else:
        result = delete_immutable(
            str(args.name), None, data_id=str(args.data_id),
            proxy=proxy, wallet_keys=wallet_keys
        )

    return result


def cli_delete_mutable(args, config_path=CONFIG_PATH, password=None, proxy=None):
    """
    command: delete_mutable advanced
    help: Low-level method to delete signed off-chain data.
    arg: name (str) 'The name that owns the data'
    arg: data_id (str) 'The ID of the data to remove'
    opt: privkey (str) 'If given, the data private key to use'
    """ 
    password = get_default_password(password)
    
    data_id = str(args.data_id)
    fqu = str(args.name)
    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    device_ids = [get_local_device_id(os.path.dirname(config_path))]

    config_dir = os.path.dirname(config_path)

    # this should only succeed if the zone file is well-formed,
    # since otherwise no one would be able to get the public key
    # to verify the tombstones.
    zfinfo = get_name_zonefile(fqu, proxy=proxy)
    if 'error' in zfinfo:
        log.error("Unable to load zone file for {}: {}".format(fqu, zfinfo['error']))
        return {'error': 'Unable to load or parse zone file for {}'.format(fqu)}
   
    if not user_zonefile_data_pubkey(zfinfo['zonefile']):
        log.error("Zone file for {} has no public key".format(fqu))
        return {'error': 'Zone file for {} has no public key'.format(fqu)}

    privkey = None

    if hasattr(args, 'privkey') and args.privkey:
        privkey = str(args.privkey)

    else:
        wallet_keys = get_wallet_keys(config_path, password)
        if 'error' in wallet_keys:
            return wallet_keys

        privkey = wallet_keys['data_privkey']
        assert privkey

    proxy = get_default_proxy(config_path=config_path) if proxy is None else proxy

    data_tombstones = make_mutable_data_tombstones(device_ids, data_id) 
    signed_data_tombstones = sign_mutable_data_tombstones(data_tombstones, privkey)

    result = delete_mutable(data_id, signed_data_tombstones, proxy=proxy, config_path=config_path)
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


def cli_get_snv_blockchain_record(args, config_path=CONFIG_PATH):
    """
    command: get_snv_blockchain_record advanced
    help: Use SNV to look up a name or namespace blockchain record at a particular block height
    arg: name (str) 'The name or namespace to query'
    arg: block_id (str) 'The block height at which the name or namespace was last altered'
    arg: trust_anchor (str) 'A trusted consensus hash, Blockstack transaction ID with a consensus hash, or a serial number from a higher block height than `block_id`'
    """

    blockchain_records = lookup_snv(
        str(args.name),
        int(args.block_id),
        str(args.trust_anchor)
    )
    
    if 'error' in blockchain_records:
        return blockchain_records

    return blockchain_records[-1]


def cli_lookup_snv(args, config_path=CONFIG_PATH):
    """
    command: lookup_snv advanced
    help: Use SNV to look up a name at a particular block height
    arg: name (str) 'The name to query'
    arg: block_id (int) 'The block height at which the name was last altered'
    arg: trust_anchor (str) 'A trusted consensus hash, Blockstack transaction ID with a consensus hash, or serial number from a higher block height than `block_id`'
    opt: force (str) 'If True, then resolve the name even if it is expired'
    """
    
    force = False
    if hasattr(args, 'force') and args.force and args.force.lower() in ['true', '1', 'force']:
        force = True

    name = str(args.name)
    error = check_valid_name(name)
    if error:
        res = subdomains.is_address_subdomain(name)
        if res:
            subdomain, domain = res[1]
            if subdomain:
                return {'error': 'SNV lookup on subdomains is not yet supported'}

            name = domain

        else:
            return {'error': error}

    blockchain_records = lookup_snv(
        name,
        int(args.block_id),
        str(args.trust_anchor)
    )

    if 'error' in blockchain_records:
        return blockchain_records
    
    # use latest record
    blockchain_record = blockchain_records[-1]

    if 'value_hash' not in blockchain_record:
        return {'error': '{} has no profile'.format(name)}

    if not force and blockchain_record.get('revoked', False):
        msg = 'Name is revoked. Use `whois` or `get_name_blockchain_record` for details.'
        return {'error': msg}

    if not force and blockchain_record.get('expired', False):
        msg = 'Name is expired. Use `whois` or `get_name_blockchain_record` for details. If you own this name, use `renew` to renew it.'
        return {'error': msg}

    data = {}
    try:
        res = get_profile(
            name, name_record=blockchain_record, include_raw_zonefile=True, use_legacy=True, use_legacy_zonefile=True
        )

        if 'error' in res:
            return res

        data['profile'] = res['profile']
        data['zonefile'] = res['raw_zonefile']
        data['public_key'] = res['public_key']
    except Exception as e:
        log.exception(e)
        msg = 'Failed to look up name\n{}'
        return {'error': msg.format(traceback.format_exc())}

    result = data
    return result


def cli_get_name_zonefile(args, config_path=CONFIG_PATH, raw=True, proxy=None):
    """
    command: get_name_zonefile advanced raw
    help: Get a name's zonefile
    arg: name (str) 'The name to query'
    opt: json (str) 'If true is given, try to parse as JSON'
    """
    # the 'raw' kwarg is set by the API daemon to False to get back structured data

    name = str(args.name)
    parse_json = getattr(args, 'json', 'false')
    parse_json = parse_json is not None and parse_json.lower() in ['true', '1']

    result = get_name_zonefile(str(args.name), raw_zonefile=True, allow_legacy=True)
    if 'error' in result:
        log.error("get_name_zonefile failed: %s" % result['error'])
        return result

    if 'zonefile' not in result:
        return {'error': 'No zonefile data'}

    if parse_json:
        # try to parse
        try:
            new_zonefile = decode_name_zonefile(name, result['zonefile'])
            assert new_zonefile is not None, "Failed to decode zone file"
            result['zonefile'] = result['zonefile']
        except Exception as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            return {'error': 'Non-standard zonefile.'}
    
    if raw:
        return result['zonefile']

    else:
        return result


def cli_get_names_owned_by_address(args, config_path=CONFIG_PATH):
    """
    command: get_names_owned_by_address advanced
    help: Get the list of names owned by an address
    arg: address (str) 'The address to query'
    """
    result = get_names_owned_by_address(str(args.address))
    return result


def cli_get_historic_names_by_address(args, config_path=CONFIG_PATH):
    """
    command: get_historic_names_by_address advanced
    help: Get all of the names historically owned by an address
    arg: address (str) 'The address that owns names'
    arg: page (int) 'The page of names to fetch (groups of 100)'
    """

    offset = int(args.page) * 100
    count = 100

    result = get_historic_names_by_address(str(args.address), offset, count)

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
    arg: page (int) 'The page of names to fetch (groups of 100)'
    opt: include_expired (int) 'If True, then count expired names as well'
    """

    offset = int(args.page) * 100
    count = 100
    include_expired = False
    if getattr(args, 'include_expired', None) is not None and args.include_expired.lower() in ['true', '1']:
        include_expired = True

    result = get_all_names(offset=offset, count=count, include_expired=include_expired)

    return result


def cli_get_num_names(args, config_path=CONFIG_PATH):
    """
    command: get_num_names advanced
    help: Get the number of names in existence
    opt: include_expired (str) 'If True, then count expired names as well'
    """
    include_expired = False
    if getattr(args, 'include_expired', None) is not None and args.include_expired.lower() in ['true', '1']:
        include_expired = True

    result = get_num_names(include_expired=include_expired)

    return result


def cli_get_all_namespaces(args, config_path=CONFIG_PATH):
    """
    command: get_all_namespaces
    help: Get the list of namespaces
    """
    result = get_all_namespaces()
    return result


def cli_get_names_in_namespace(args, config_path=CONFIG_PATH):
    """
    command: get_names_in_namespace advanced
    help: Get the names in a given namespace, optionally paginating through them
    arg: namespace_id (str) 'The ID of the namespace to query'
    arg: page (int) 'The page of names to fetch (groups of 100)'
    """

    offset = int(args.page) * 100
    count = 100

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
    arg: owner_key (str) 'The key to be used if not the wallets ownerkey'
    arg: payment_key (str) 'The key to be used if not the wallets paymentkey'
    """
    password = get_default_password(password)

    conf = config.get_config(config_path)
    assert conf

    config_dir = os.path.dirname(config_path)
    fqu = str(args.name)

    error = check_valid_name(fqu)
    if error:
        return {'error': error}

    zonefile_hash = str(args.zonefile_hash)
    if re.match(r'^[a-fA-F0-9]+$', zonefile_hash) is None or len(zonefile_hash) != 40:
        return {'error': 'Not a valid zonefile hash'}

    # forward along to RESTful server (or registrar)
    log.debug("Update {}, zonefile_hash={}".format(fqu, zonefile_hash))
    rpc = local_api_connect(config_path=config_path)
    assert rpc

    try:
        args_ownerkey = getattr(args, 'owner_key', None)
        # NOTE: already did safety checks
        if args_ownerkey is None or len(args_ownerkey) == 0:
            owner_key = None
        else:
            owner_key = args_ownerkey
        args_paymentkey = getattr(args, 'payment_key', None)
        if args_paymentkey is None or len(args_paymentkey) == 0:
            payment_key = None
        else:
            payment_key = args_paymentkey

        # NOTE: already did safety checks
        resp = rpc.backend_update(
            fqu, None, None, zonefile_hash, owner_key = owner_key, payment_key = payment_key)
    except Exception as e:
        log.exception(e)
        return {'error': 'Error talking to server, try again.'}

    if 'error' in resp:
        log.debug('RPC error: {}'.format(resp['error']))
        return resp

    if (not 'success' in resp or not resp['success']) and 'message' in resp:
        return {'error': resp['message']}

    resp['zonefile_hash'] = zonefile_hash
    return resp


def cli_unqueue(args, config_path=CONFIG_PATH):
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


def cli_put_profile(args, config_path=CONFIG_PATH, password=None, proxy=None, force_data=False, wallet_keys=None):
    """
    command: put_profile advanced
    help: Set the profile for a blockchain ID.
    arg: blockchain_id (str) 'The blockchain ID.'
    arg: data (str) 'The profile as a JSON string, or a path to the profile.'
    """

    password = get_default_password(password)

    config_dir = os.path.dirname(config_path)
    conf = config.get_config(config_path)
    name = str(args.blockchain_id)
    profile_json_str = str(args.data)

    proxy = get_default_proxy(config_path) if proxy is None else proxy

    profile = None
    if not force_data and is_valid_path(profile_json_str) and os.path.exists(profile_json_str):
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

    if wallet_keys is None:
        wallet_keys = get_wallet_keys(config_path, password)
        if 'error' in wallet_keys:
            return wallet_keys

    required_storage_drivers = conf.get(
        'storage_drivers_required_write',
        config.BLOCKSTACK_REQUIRED_STORAGE_DRIVERS_WRITE
    )
    required_storage_drivers = required_storage_drivers.split()

    user_zonefile = get_name_zonefile(name, proxy=proxy)
    if 'error' in user_zonefile:
        return user_zonefile

    user_zonefile = user_zonefile['zonefile']
    if blockstack_profiles.is_profile_in_legacy_format(user_zonefile):
        msg = 'Profile in legacy format.  Please migrate it with the "migrate" command first.'
        return {'error': msg}

    res = put_profile(name, profile, user_zonefile=user_zonefile,
                       wallet_keys=wallet_keys, proxy=proxy,
                       required_drivers=required_storage_drivers, blockchain_id=name,
                       config_path=config_path)

    if 'error' in res:
        return res

    return {'status': True}


def cli_delete_profile(args, config_path=CONFIG_PATH, password=None, proxy=None, wallet_keys=None ):
    """
    command: delete_profile advanced
    help: Delete a profile from a blockchain ID.
    arg: blockchain_id (str) 'The blockchain ID.'
    """

    proxy = get_default_proxy(config_path) if proxy is None else proxy
    password = get_default_password(password)
    
    name = str(args.blockchain_id)

    if wallet_keys is None:
        wallet_keys = get_wallet_keys(config_path, password)
        if 'error' in wallet_keys:
            return wallet_keys

    res = delete_profile(name, user_data_privkey=wallet_keys['data_privkey'], proxy=proxy, wallet_keys=wallet_keys)
    return res


def cli_sync_zonefile(args, config_path=CONFIG_PATH, proxy=None, interactive=True, nonstandard=False):
    """
    command: sync_zonefile advanced
    help: Upload the current zone file to all storage providers.
    arg: name (str) 'Name of the zone file to synchronize.'
    opt: txid (str) 'NAME_UPDATE transaction ID that set the zone file.'
    opt: zonefile (str) 'The path to the zone file on disk, if unavailable from other sources.'
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
        # zonefile path given
        zonefile_path = str(args.zonefile)
        zonefile_info = analyze_zonefile_string(name, zonefile_path, proxy=proxy)
        if 'error' in zonefile_info:
            log.error("Failed to analyze user zonefile: {}".format(zonefile_info['error']))
            return {'error': zonefile_info['error']}

        if zonefile_info.get('nonstandard'):
            log.warning("Non-standard zone file")
            if interactive and not nonstandard:
                proceed = prompt_invalid_zonefile()
                if not proceed:
                    return {'error': 'Non-standard zone file'}

        user_data = zonefile_info['zonefile_str']

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
            if name_rec['op'] in [NAME_UPDATE, NAME_REGISTRATION, NAME_REGISTRATION + ":", NAME_IMPORT]:
                if name_rec['value_hash'] == zonefile_hash:
                    txid = name_rec['txid']
            else:
                name_history = name_rec['history']
                for history_key in reversed(sorted(name_history)):
                    name_history_items = name_history[history_key]

                    for name_history_item in name_history_items:
                        op = name_history_item.get('op', None)
                        if op is None:
                            continue

                        if op not in [NAME_UPDATE, NAME_IMPORT, NAME_REGISTRATION]:
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
        [(conf['server'], conf['port'])],
        config_path=config_path
    )

    if 'error' in res:
        log.error('Failed to replicate zonefile: {}'.format(res['error']))
        return res

    return {'status': True, 'zonefile_hash': zonefile_hash}


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
    arg: blockchain_id (str) 'The blockchain ID that will own the application'
    arg: app_domain (str) 'The application domain name'
    arg: methods (str) 'A comma-separated list of API methods this application will call'
    arg: index_file (str) 'The path to the index file'
    opt: urls (str) 'A comma-separated list of URLs to publish the index file to'
    opt: drivers (str) 'A comma-separated list of storage drivers for clients to use'
    """
  
    password = get_default_password(password)

    blockchain_id = str(args.blockchain_id)
    app_domain = str(args.app_domain)

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
        methods = str(args.methods).split(',')
        # TODO: validate
        
    else:
        methods = []

    drivers = []
    if hasattr(args, 'drivers') and args.drivers is not None:
        drivers = str(args.drivers).split(",")

    uris = []
    index_data_id = '{}/index.html'.format(app_domain)
    if not hasattr(args, 'urls') or args.urls is not None:
        urls = str(args.urls).split(',')
    
    else:
        urls = get_driver_urls( index_data_id, get_storage_handlers() )

    uris = [url_to_uri_record(u, datum_name=index_data_id) for u in urls]

    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    res = app_publish( blockchain_id, app_domain, methods, uris, index_file_data, app_driver_hints=drivers, wallet_keys=wallet_keys, proxy=proxy, config_path=config_path )
    if 'error' in res:
        return res

    return {'status': True}


def cli_app_get_config( args, config_path=CONFIG_PATH, interactive=False, proxy=None ):
    """
    command: app_get_config advanced
    help: Get the configuration structure for an application.
    arg: blockchain_id (str) 'The app owner blockchain ID'
    arg: app_domain (str) 'The application domain name'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    blockchain_id = str(args.blockchain_id)
    app_domain = str(args.app_domain)

    app_config = app_get_config(blockchain_id, app_domain, proxy=proxy, config_path=config_path )
    return app_config


def cli_app_get_resource( args, config_path=CONFIG_PATH, interactive=False, proxy=None ):
    """
    command: app_get_resource advanced
    help: Get an application resource from mutable storage.
    arg: blockchain_id (str) 'The app owner blockchain ID'
    arg: app_domain (str) 'The application domain name'
    arg: res_path (str) 'The resource path'
    opt: pubkey (str) 'The public key'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    blockchain_id = str(args.blockchain_id)
    app_domain = str(args.app_domain)
    res_path = str(args.res_path)

    pubkey = None
    if hasattr(args, "pubkey") and args.pubkey:
        pubkey = str(args.pubkey)

    res = app_get_resource( blockchain_id, app_domain, res_path, data_pubkey=pubkey, proxy=proxy, config_path=config_path )
    return res


def cli_app_put_resource( args, config_path=CONFIG_PATH, interactive=False, proxy=None, password=None ):
    """
    command: app_put_resource advanced
    help: Store an application resource from mutable storage.
    arg: blockchain_id (str) 'The app owner blockchain ID'
    arg: app_domain (str) 'The application domain name'
    arg: res_path (str) 'The location to which to store this resource'
    arg: res_file (str) 'The path on disk to the resource to upload'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    password = get_default_password(password)

    blockchain_id = str(args.blockchain_id)
    app_domain = str(args.app_domain)
    res_path = str(args.res_path)
    res_file_path = str(args.res_file)

    resdata = None
    if not os.path.exists(res_file_path):
        return {'error': 'No such file or directory'}

    with open(res_file_path, "r") as f:
        resdata = f.read()

    config_dir = os.path.dirname(config_path)
    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    res = app_put_resource( blockchain_id, app_domain, res_path, resdata, proxy=proxy, wallet_keys=wallet_keys, config_path=config_path )
    return res


def cli_app_delete_resource( args, config_path=CONFIG_PATH, interactive=False, proxy=None, password=None ):
    """
    command: app_delete_resource advanced
    help: Delete an application resource from mutable storage.
    arg: blockchain_id (str) 'The app owner blockchain ID'
    arg: app_domain (str) 'The application domain name'
    arg: res_path (str) 'The location to which to store this resource'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    password = get_default_password(password)

    blockchain_id = str(args.blockchain_id)
    app_domain = str(args.app_domain)
    res_path = str(args.res_path)

    config_dir = os.path.dirname(config_path)
    wallet_keys = get_wallet_keys(config_path, password)
    if 'error' in wallet_keys:
        return wallet_keys

    res = app_delete_resource( blockchain_id, app_domain, res_path, proxy=proxy, wallet_keys=wallet_keys, config_path=config_path )
    return res


def cli_app_signin(args, config_path=CONFIG_PATH, interactive=True):
    """
    command: app_signin advanced
    help: Create a session token for the RESTful API for a given application
    arg: blockchain_id (str) 'The blockchain ID of the caller'
    arg: privkey (str) 'The app-specific private key to use'
    arg: app_domain (str) 'The application domain'
    arg: api_methods (str) 'A CSV of requested methods to allow'
    arg: device_ids (str) 'A CSV of device IDs that can write to the app datastore'
    arg: public_keys (str) 'A CSV of public keys that can write to the app datastore'
    """

    blockchain_id = str(args.blockchain_id)
    app_domain = str(args.app_domain)
    api_methods = str(args.api_methods)
    app_privkey = str(args.privkey)
    device_ids = str(args.device_ids)
    public_keys = str(args.public_keys)

    api_methods = api_methods.split(',')
    device_ids = device_ids.split(',')
    public_keys = public_keys.split(',')

    if len(device_ids) != len(public_keys):
        return {'error': 'Mismatch between device IDs and public keys'}

    for pubk in public_keys:
        try:
            keylib.ECPublicKey(pubk)
        except:
            return {'error': 'Invalid public key {}'.format(pubk)}

    # get API password 
    api_pass = get_secret("BLOCKSTACK_API_PASSWORD")
    if api_pass is None:
        conf = config.get_config(config_path)
        if conf:
            api_pass = conf.get('api_password', None)

    if api_pass is None:
        if interactive:
            try:
                api_pass = getpass.getpass("API password: ")
            except KeyboardInterrupt:
                return {'error': 'Keyboard interrupt'}

        else:
            return {'error': 'No API password set'}
            
    # TODO: validate API methods
    # TODO: fetch api methods from app domain, if need be

    this_device_id = config.get_local_device_id(config_dir=os.path.dirname(config_path))

    rpc = local_api_connect(config_path=config_path, api_pass=api_pass)
    sesinfo = rpc.backend_signin(blockchain_id, app_privkey, app_domain, api_methods, device_ids, public_keys, this_device_id) 
    if 'error' in sesinfo:
        return sesinfo

    return {'status': True, 'token': sesinfo['token']}


def cli_sign_profile( args, config_path=CONFIG_PATH, proxy=None, password=None, interactive=False ):
    """
    command: sign_profile advanced raw
    help: Sign a JSON file to be used as a profile.
    arg: name (str) 'The name for whom to sign the profile.'
    arg: path (str) 'The path to the profile data on disk.'
    opt: privkey (str) 'The optional private key to sign it with (defaults to the data private key in your wallet)'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)
    
    password = get_default_password(password)

    config_dir = os.path.dirname(config_path)

    name = str(args.name)
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
        wallet_keys = get_wallet_keys( config_path, password )
        if 'error' in wallet_keys:
            return wallet_keys
        
        zonefile_data = None
        name_rec = None
        zonefile_data_res = get_name_zonefile(
            name, proxy=proxy, raw_zonefile=False, include_name_record=True
        )
        if 'error' not in zonefile_data_res:
            zonefile_data = zonefile_data_res['zonefile']
            name_rec = zonefile_data_res['name_record']

            if 'error' in zonefile_data:
                # zonefile itself is bad
                zonefile_data = None
        
        privkey = get_data_privkey(zonefile_data, wallet_keys=wallet_keys, config_path=config_path)
        if privkey is None or 'error' in privkey:
            log.error("No data private key in the wallet, and cannot use owner private key.  You will need to either explicitly select a private key, or insert the data public key into your zone file.")
            return {'error': 'No data private key found.  Try passing your owner private key, or adding your data public key to your zone file.'}

    privkey = ecdsa_private_key(privkey).to_hex()
    pubkey = get_pubkey_hex(privkey)

    res = storage.serialize_mutable_data(data_json, privkey, pubkey, profile=True)
    if res is None:
        return {'error': 'Failed to sign and serialize profile'}

    # sanity check 
    assert storage.parse_mutable_data(res, pubkey)

    return res


def cli_verify_profile( args, config_path=CONFIG_PATH, proxy=None, interactive=False ):
    """
    command: verify_profile advanced
    help: Verify a profile JWT and deserialize it into a profile object.
    arg: name (str) 'The name that points to the public key to use to verify.'
    arg: path (str) 'The path to the profile data on disk'
    opt: pubkey (str) 'The public key to use to verify. Overrides `name`.'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    name = str(args.name)
    path = str(args.path)
    pubkey = None
    owner_address = None

    if not os.path.exists(path):
        return {'error': 'No such file or directory'}

    if hasattr(args, 'pubkey') and args.pubkey is not None:
        pubkey = str(args.pubkey)
        try:
            pubkey = keylib.ECPublicKey(pubkey).to_hex()
        except Exception as e:
            log.exception(e)
            return {'error': 'Invalid public key : "{}"'.format(pubkey)}

    if pubkey is None:
        zonefile_data = None
        pubkey = None
        name_rec = None
        # get the pubkey 
        zonefile_data_res = get_name_zonefile(
            name, proxy=proxy, raw_zonefile=True, include_name_record=True
        )
        if 'error' not in zonefile_data_res:
            zonefile_data = zonefile_data_res['zonefile']
            name_rec = zonefile_data_res['name_record']

            # parse 
            zonefile_dict = None
            try:
                zonefile_dict = blockstack_zones.parse_zone_file(zonefile_data)
            except:
                log.warning("Nonstandard zone file")

            if zonefile_dict is not None:
                pubkey = user_zonefile_data_pubkey(zonefile_dict)

        if pubkey is None:
            # fall back to owner hash
            owner_address = str(name_rec['address'])
            if virtualchain.is_multisig_address(owner_address):
                return {'error': 'No data public key in zone file, and owner is a p2sh address'}

            else:
                log.warn("Falling back to owner address")

    profile_data = None
    try:
        with open(path, 'r') as f:
            profile_data = f.read()
    except:
        return {'error': 'Failed to read profile file'}

    res = storage.parse_mutable_data(profile_data, pubkey, public_key_hash=owner_address)
    if res is None:
        return {'error': 'Failed to verify profile'}

    return res


def cli_sign_data( args, config_path=CONFIG_PATH, proxy=None, password=None, interactive=False ):
    """
    command: sign_data advanced raw
    help: Sign data to be used in a data store.
    arg: path (str) 'The path to the profile data on disk.'
    opt: privkey (str) 'The optional private key to sign it with (defaults to the data private key in your wallet)'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)
    
    password = get_default_password(password)

    config_dir = os.path.dirname(config_path)
    path = str(args.path)
    data = None
    try:
        with open(path, 'r') as f:
            data = f.read()
            data = data_blob_serialize(data)

    except Exception as e:
        if os.environ.get("BLOCKSTACK_DEBUG") == "1":
            log.exception(e)

        log.error("Failed to load {}".format(path))
        return {'error': 'Failed to load {}'.format(path)}

    privkey = None
    if hasattr(args, "privkey") and args.privkey:
        privkey = str(args.privkey)

    else:
        wallet_keys = get_wallet_keys( config_path, password )
        if 'error' in wallet_keys:
            return wallet_keys

        if not wallet_keys.has_key('data_privkey'):
            log.error("No data private key in the wallet.  You may need to explicitly select a private key.")
            return {'error': 'No data private key set.\nTry passing your owner private key.'}

        privkey = wallet_keys['data_privkey']

    privkey = ecdsa_private_key(privkey).to_hex()
    pubkey = get_pubkey_hex(privkey)

    res = storage.serialize_mutable_data(data, privkey, pubkey)
    if res is None:
        return {'error': 'Failed to sign and serialize data'}

    # sanity check
    if BLOCKSTACK_DEBUG:
        assert storage.parse_mutable_data(res, pubkey)

    if BLOCKSTACK_TEST:
        log.debug("Verified {} with {}".format(res, pubkey))

    return res


def cli_verify_data( args, config_path=CONFIG_PATH, proxy=None, interactive=True ):
    """
    command: verify_data advanced raw
    help: Verify signed data and return the payload.
    arg: name (str) 'The name that points to the public key to use to verify.'
    arg: path (str) 'The path to the profile data on disk'
    opt: pubkey (str) 'The public key to use to verify. Overrides `name`.'
    """
    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    name = str(args.name)
    path = str(args.path)
    pubkey = None

    if not os.path.exists(path):
        return {'error': 'No such file or directory'}

    if hasattr(args, 'pubkey') and args.pubkey is not None:
        pubkey = str(args.pubkey)
        try:
            pubkey = keylib.ECPublicKey(pubkey).to_hex()
        except Exception as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            return {'error': 'Invalid public key'}

    if pubkey is None:
        zonefile_data = None

        # get the pubkey 
        zonefile_data_res = get_name_zonefile(
            name, proxy=proxy, raw_zonefile=True
        )
        if 'error' not in zonefile_data_res:
            zonefile_data = zonefile_data_res['zonefile']
        else:
            return {'error': "Failed to get zonefile data: {}".format(name)}

        # parse 
        zonefile_dict = None
        try:
            zonefile_dict = blockstack_zones.parse_zone_file(zonefile_data)
        except:
            return {'error': 'Nonstandard zone file'}

        pubkey = user_zonefile_data_pubkey(zonefile_dict)
        if pubkey is None:
            return {'error': 'No data public key in zone file'}

    data = None
    try:
        with open(path, 'r') as f:
            data = f.read().strip()
    except:
        return {'error': 'Failed to read file'}

    if BLOCKSTACK_TEST:
        log.debug("Verify {} with {}".format(data, pubkey))

    res = storage.parse_mutable_data(data, pubkey)
    if res is None:
        return {'error': 'Failed to verify data'}

    return data_blob_parse(res)


def cli_validate_zone_file(args, config_path=CONFIG_PATH, proxy=None):
    """
    command: validate_zone_file advanced
    help: Validate an on-disk zone file to ensure that is properly formatted.
    arg: name (str) 'The name that will use this zone file'
    arg: zonefile_path (str) 'The path on disk to the zone file'
    opt: verbose (str) 'Pass True to see more analysis beyond "valid" or "invalid".'
    """
    
    name = str(args.name)
    zonefile_path = str(args.zonefile_path)
    verbose = str(getattr(args, 'verbose', '')).lower() in ['true', 'yes', '1']

    if not os.path.exists(zonefile_path):
        return {'error': 'No such file or directory: {}'.format(zonefile_path)}

    zonefile_data = None
    try:
        with open(zonefile_path, 'r') as f:
            zonefile_data = f.read()

    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        return {'error': 'Failed to read zone file.'}

    res = analyze_zonefile_string(name, zonefile_data, force_data=True, check_current=False, proxy=proxy)
    if verbose:
        return res
       
    # simplify...
    if res['nonstandard']:
        return {'error': 'Nonstandard zone file data'}

    return {'status': True}


def cli_list_devices( args, config_path=CONFIG_PATH, proxy=None ):
    """
    command: list_devices advanced
    help: Get the list of device IDs and public keys for a particular application
    arg: blockchain_id (str) 'The blockchain ID whose devices to list'
    arg: appname (str) 'The name of the application'
    """
    
    raise NotImplementedError("Missing token file parsing logic")


def cli_add_device( args, config_path=CONFIG_PATH, proxy=None ):
    """
    command: add_device advanced
    help: Add a device that can read and write your data
    arg: blockchain_id (str) 'The blockchain ID whose profile to update'
    opt: device_id (str) 'The ID of the device to add, if not this one'
    """

    raise NotImplementedError("Missing token file parsing logic")
    

def cli_remove_device( args, config_path=CONFIG_PATH, proxy=None ):
    """
    command: remove_device advanced
    help: Remove a device so it can no longer access your application data
    arg: blockchain_id (str) 'The blockchain ID whose profile to update'
    arg: device_id (str) 'The ID of the device to remove'
    """
    
    raise NotImplementedError("Missing token file parsing logic")


def _remove_datastore(rpc, datastore, datastore_privkey, data_pubkeys, rmtree=True, force=False, config_path=CONFIG_PATH ):
    """
    Delete a user datastore
    If rmtree is True, then the datastore will be emptied first.
    If force is True, then the datastore will be deleted even if rmtree fails
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    
    datastore_pubkey = get_pubkey_hex(datastore_privkey)
    datastore_id = datastore_get_id(datastore_pubkey)

    # clear the datastore 
    if rmtree:
        log.debug("Clear datastore {}".format(datastore_id))
        res = datastore_rmtree(rpc, datastore, '/', datastore_privkey, data_pubkeys, config_path=config_path)
        if 'error' in res and not force:
            log.error("Failed to rmtree datastore {}".format(datastore_id))
            return {'error': 'Failed to remove all files and directories', 'errno': errno.ENOTEMPTY}

    # delete the datastore record
    log.debug("Delete datastore {}".format(datastore_id))
    return delete_datastore(rpc, datastore, datastore_privkey, data_pubkeys, config_path=config_path)


def create_datastore_by_type( datastore_type, blockchain_id, datastore_privkey, session, drivers=None, config_path=CONFIG_PATH ):
    """
    Create a datastore or a collection for the given user with the given name.
    Return {'status': True} on success
    Return {'error': ...} on error
    """

    data_pubkeys = jsontokens.decode_token(session)['payload']['app_public_keys']
    device_ids = [dk['device_id'] for dk in data_pubkeys]

    datastore_pubkey = get_pubkey_hex(datastore_privkey)
    datastore_id = datastore_get_id(datastore_pubkey)

    rpc = local_api_connect(config_path=config_path, api_session=session)
    if rpc is None:
        return {'error': 'API endpoint not running. Please start it with `api start`'}

    res = rpc.backend_datastore_get(blockchain_id, datastore_id, device_ids)
    if 'error' not in res:
        # already exists
        log.error("Datastore exists")
        return {'error': 'Datastore exists', 'errno': errno.EEXIST}

    datastore_info = make_datastore_info( datastore_type, datastore_pubkey, device_ids, driver_names=drivers, config_path=config_path)
    if 'error' in datastore_info:
        return datastore_info
   
    # can put
    res = put_datastore(rpc, datastore_info, datastore_privkey, config_path=config_path)
    if 'error' in res:
        return res

    return {'status': True}


def get_datastore_by_type( datastore_type, blockchain_id, datastore_id, device_ids, config_path=CONFIG_PATH ):
    """
    Get a datastore or collection.
    Return the datastore object on success
    Return {'error': ...} on error
    """
    rpc = local_api_connect(config_path=config_path)
    if rpc is None:
        return {'error': 'API endpoint not running. Please start it with `api start`'}

    datastore_info = rpc.backend_datastore_get(blockchain_id, datastore_id, device_ids)
    if 'error' in datastore_info:
        return datastore_info

    datastore = datastore_info['datastore']
    if datastore['type'] != datastore_type:
        return {'error': '{} is a {}'.format(datastore_id, datastore['type'])}

    return datastore


def delete_datastore_by_type( datastore_type, blockchain_id, datastore_privkey, session, force=False, config_path=CONFIG_PATH ):
    """
    Delete a datastore or collection.
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    datastore_id = datastore_get_id(get_pubkey_hex(datastore_privkey))
    
    data_pubkeys = jsontokens.decode_token(session)['payload']['app_public_keys']
    device_ids = [dk['device_id'] for dk in data_pubkeys]
    
    rpc = local_api_connect(config_path=config_path, api_session=session)
    if rpc is None:
        return {'error': 'API endpoint not running. Please start it with `api start`'}

    datastore_info = rpc.backend_datastore_get(blockchain_id, datastore_id, device_ids)
    if 'error' in datastore_info:
        return datastore_info

    datastore = datastore_info['datastore']
    if datastore['type'] != datastore_type:
        return {'error': '{} is a {}'.format(datastore_id, datastore['type'])}

    res = _remove_datastore(rpc, datastore, datastore_privkey, data_pubkeys, rmtree=True, force=force, config_path=config_path)
    if 'error' in res:
        log.error("Failed to delete datastore record")
        return res

    return {'status': True}


def datastore_file_get(datastore_type, blockchain_id, datastore_id, path, data_pubkeys, extended=False, force=False, config_path=CONFIG_PATH ):
    """
    Get a file from a datastore or collection.
    Return {'status': True, 'data': ...} on success
    Return {'error': ...} on error
    """
    # connect 
    rpc = local_api_connect(config_path=config_path)
    if rpc is None:
        return {'error': 'API endpoint not running. Please start it with `api start`'}

    device_ids = [dk['device_id'] for dk in data_pubkeys]
    datastore_info = rpc.backend_datastore_get(blockchain_id, datastore_id, device_ids)
    if 'error' in datastore_info:
        if 'errno' not in datastore_info:
            datastore_info['errno'] = errno.EPERM

        return datastore_info

    datastore = datastore_info['datastore']
    if datastore['type'] != datastore_type:
        return {'error': '{} is a {}'.format(datastore_id, datastore['type'])}

    res = datastore_getfile( rpc, blockchain_id, datastore, path, data_pubkeys, extended=extended, force=force, config_path=config_path )
    return res


def datastore_file_put(datastore_type, blockchain_id, datastore_privkey, path, data, session, create=False, force_data=False, force=False, config_path=CONFIG_PATH ):
    """
    Put a file int oa datastore or collection.
    Return {'status': True} on success
    Return {'error': ...} on failure.

    If this is a collection, then path must be in the root directory
    """

    datastore_id = datastore_get_id(get_pubkey_hex(datastore_privkey))
    data_pubkeys = jsontokens.decode_token(session)['payload']['app_public_keys']

    # is this a path, and are we allowed to take paths?
    if is_valid_path(data) and os.path.exists(data) and not force_data:
        log.warning("Using data in file {}".format(data))
        try:
            with open(data) as f:
                data = f.read()
        except:
            return {'error': 'Failed to read "{}"'.format(data)}
    
    # connect 
    rpc = local_api_connect(config_path=config_path, api_session=session)
    if rpc is None:
        return {'error': 'API endpoint not running. Please start it with `api start`'}

    device_ids = [dk['device_id'] for dk in data_pubkeys]
    datastore_info = rpc.backend_datastore_get(blockchain_id, datastore_id, device_ids)
    if 'error' in datastore_info:
        return datastore_info

    datastore = datastore_info['datastore']

    log.debug("putfile {} to {}".format(path, datastore_id))

    res = datastore_putfile( rpc, datastore, path, data, datastore_privkey, data_pubkeys, create=create, config_path=config_path )
    if 'error' in res:
        return res

    return res


def datastore_dir_list(datastore_type, blockchain_id, datastore_id, path, data_pubkeys, extended=False, force=False, config_path=CONFIG_PATH ):
    """
    List a directory in a datastore or collection
    Return {'status': True, 'dir': ...} on success
    Return {'error': ...} on error
    """

    # connect 
    rpc = local_api_connect(config_path=config_path)
    if rpc is None:
        return {'error': 'API endpoint not running. Please start it with `api start`'}

    device_ids = [dk['device_id'] for dk in data_pubkeys]
    datastore_info = rpc.backend_datastore_get(blockchain_id, datastore_id, device_ids)
    if 'error' in datastore_info:
        if 'errno' not in datastore_info:
            datastore_info['errno'] = errno.EPERM

        return datastore_info

    datastore = datastore_info['datastore']
    if datastore['type'] != datastore_type:
        return {'error': '{} is a {}'.format(datastore_id, datastore['type']), 'errno': errno.EINVAL}

    if datastore_type == 'collection':
        # can only be '/'
        if path != '/':
            return {'error': 'Invalid argument: collections do not have directories', 'errno': errno.EINVAL}

    res = datastore_listdir( rpc, blockchain_id, datastore, path, data_pubkeys, extended=extended, force=force, config_path=config_path )
    return res


def datastore_path_stat(datastore_type, blockchain_id, datastore_id, path, data_pubkeys, extended=False, force=False, config_path=CONFIG_PATH ):
    """
    Stat a path in a datastore or collection
    Return {'status': True, 'inode': ...} on success
    Return {'error': ...} on error
    """
    # connect 
    rpc = local_api_connect(config_path=config_path)
    if rpc is None:
        return {'error': 'API endpoint not running. Please start it with `api start`'}

    device_ids = [dk['device_id'] for dk in data_pubkeys]
    datastore_info = rpc.backend_datastore_get(blockchain_id, datastore_id, device_ids)
    if 'error' in datastore_info:
        return datastore_info

    datastore = datastore_info['datastore']
    if datastore['type'] != datastore_type:
        return {'error': '{} is a {}'.format(datastore_id, datastore['type'])}

    res = datastore_stat( rpc, blockchain_id, datastore, path, data_pubkeys, extended=extended, force=force, config_path=config_path )
    return res


def datastore_inode_getinode(datastore_type, blockchain_id, datastore_id, inode_uuid, data_pubkeys, extended=False, force=False, idata=False, config_path=CONFIG_PATH ):
    """
    Get an inode in a datastore or collection
    Return {'status': True, 'inode': ...} on success
    Return {'error': ...} on error
    """
    # connect 
    rpc = local_api_connect(config_path=config_path)
    if rpc is None:
        return {'error': 'API endpoint not running. Please start it with `api start`'}

    device_ids = [dk['device_id'] for dk in data_pubkeys]
    datastore_info = rpc.backend_datastore_get(blockchain_id, datastore_id, device_ids)
    if 'error' in datastore_info:
        return datastore_info

    datastore = datastore_info['datastore']
    if datastore['type'] != datastore_type:
        return {'error': '{} is a {}'.format(datastore_id, datastore['type'])}

    res = datastore_getinode( rpc, blockchain_id, datastore, inode_uuid, data_pubkeys, extended=False, force=force, idata=idata, config_path=config_path )
    return res


def cli_get_device_keys( args, config_path=CONFIG_PATH ):
    """
    command: get_device_keys advanced
    help: Get the device IDs and public keys for a blockchain ID
    arg: blockchain_id (str) 'The blockchain Id'
    """
    blockchain_id = str(args.blockchain_id)

    # TODO: implement token file support 
    log.warning("Token file support is NOT IMPLEMENTED")
    
    # find the "data public key"
    

def cli_get_datastore( args, config_path=CONFIG_PATH ):
    """
    command: get_datastore advanced
    help: Get a datastore record
    arg: blockchain_id (str) 'The ID of the owner' 
    arg: datastore_id (str) 'The application datastore ID'
    opt: device_ids (str) 'The CSV of device IDs owned by the blockchain ID'
    """
    blockchain_id = str(args.blockchain_id)
    datastore_id = str(args.datastore_id)

    # get the list of device IDs to use 
    device_ids = getattr(args, 'device_ids', None)
    if device_ids:
        device_ids = device_ids.split(',')

    else:
        raise NotImplementedError("Missing token file parsing logic")

    return get_datastore_by_type('datastore', blockchain_id, datastore_id, device_ids, config_path=config_path )


def cli_create_datastore( args, config_path=CONFIG_PATH, proxy=None ):
    """
    command: create_datastore advanced 
    help: Make a new datastore
    arg: blockchain_id (str) 'The blockchain ID that will own this datastore'
    arg: privkey (str) 'The ECDSA private key of the datastore'
    arg: session (str) 'The API session token'
    opt: drivers (str) 'A CSV of drivers to use.'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    blockchain_id = str(args.blockchain_id)
    privkey = str(args.privkey)
    drivers = getattr(args, 'drivers', None)
    if drivers:
        drivers = drivers.split(',')
 
    return create_datastore_by_type('datastore', blockchain_id, privkey, str(args.session), drivers=drivers, config_path=config_path )


def cli_delete_datastore( args, config_path=CONFIG_PATH ):
    """
    command: delete_datastore advanced 
    help: Delete a datastore owned by a given user, and all of the data it contains.
    arg: blockchain_id (str) 'The owner of this datastore'
    arg: privkey (str) 'The ECDSA private key of the datastore'
    arg: session (str) 'The API session token'
    opt: force (str) 'If True, then delete the datastore even if it cannot be emptied'
    """
    
    blockchain_id = str(args.blockchain_id)
    privkey = str(args.privkey)
    force = False
    if hasattr(args, 'force'):
        force = (str(args.force).lower() in ['1', 'true', 'force', 'yes'])

    return delete_datastore_by_type('datastore', blockchain_id, privkey, str(args.session), force=force, config_path=config_path)


def cli_datastore_mkdir( args, config_path=CONFIG_PATH, interactive=False ):
    """
    command: datastore_mkdir advanced 
    help: Make a directory in a datastore.
    arg: blockchain_id (str) 'The owner of this datastore'
    arg: privkey (str) 'The app-specific private key'
    arg: path (str) 'The path to the directory to remove'
    arg: session (str) 'The API session token'
    """

    blockchain_id = str(args.blockchain_id)
    path = str(args.path)
    datastore_privkey_hex = str(args.privkey)
    datastore_pubkey_hex = get_pubkey_hex(datastore_privkey_hex)
    datastore_id = datastore_get_id(datastore_pubkey_hex)

    session = jsontokens.decode_token(str(args.session))
    data_pubkeys = session['payload']['app_public_keys']
    device_ids = [dk['device_id'] for dk in data_pubkeys]

    # connect 
    rpc = local_api_connect(config_path=config_path, api_session=str(args.session))
    if rpc is None:
        return {'error': 'API endpoint not running. Please start it with `api start`'}

    datastore_info = rpc.backend_datastore_get(blockchain_id, datastore_id, device_ids)
    if 'error' in datastore_info:
        return datastore_info

    datastore = datastore_info['datastore']
    assert datastore_id == datastore_get_id(get_pubkey_hex(datastore_privkey_hex))

    res = datastore_mkdir(rpc, datastore, path, datastore_privkey_hex, data_pubkeys, config_path=config_path )
    if 'error' in res:
        return res

    # make url 
    if not path.endswith('/'):
        path += '/'

    return res

    
def cli_datastore_rmdir( args, config_path=CONFIG_PATH, interactive=False ):
    """
    command: datastore_rmdir advanced 
    help: Remove a directory in a datastore.
    arg: blockchain_id (str) 'The owner of this datastore'
    arg: privkey (str) 'The app-specific data private key'
    arg: path (str) 'The path to the directory to remove'
    arg: session (str) 'The API session token'
    """

    blockchain_id = str(args.blockchain_id)
    path = str(args.path)
    datastore_privkey_hex = str(args.privkey)
    datastore_pubkey_hex = get_pubkey_hex(datastore_privkey_hex)
    datastore_id = datastore_get_id(datastore_pubkey_hex)
    force = (str(getattr(args, 'force', '').lower()) in ['1', 'true'])

    session = jsontokens.decode_token(str(args.session))
    data_pubkeys = session['payload']['app_public_keys']
    device_ids = [dk['device_id'] for dk in data_pubkeys]

    # connect 
    rpc = local_api_connect(config_path=config_path, api_session=str(args.session))
    if rpc is None:
        return {'error': 'API endpoint not running. Please start it with `api start`'}

    datastore_info = rpc.backend_datastore_get(blockchain_id, datastore_id, device_ids)
    if 'error' in datastore_info:
        return datastore_info

    datastore = datastore_info['datastore']
    assert datastore_id == datastore_get_id(get_pubkey_hex(datastore_privkey_hex))

    res = datastore_rmdir(rpc, datastore, path, datastore_privkey_hex, data_pubkeys, force=force, config_path=config_path )
    return res


def cli_datastore_rmtree( args, config_path=CONFIG_PATH, interactive=False ):
    """
    command: datastore_rmtree advanced
    help: Remove a directory and all its children from a datastore.
    arg: blockchain_id (str) 'The owner of this datastore'
    arg: privkey (str) 'The app-specific data private key'
    arg: path (str) 'The path to the directory tree to remove'
    arg: session (str) 'The API session token'
    """

    blockchain_id = str(args.blockchain_id)
    path = str(args.path)
    datastore_privkey_hex = str(args.privkey)
    datastore_pubkey_hex = get_pubkey_hex(datastore_privkey_hex)
    datastore_id = datastore_get_id(datastore_pubkey_hex)

    session = jsontokens.decode_token(str(args.session))
    data_pubkeys = session['payload']['app_public_keys']
    device_ids = [dk['device_id'] for dk in data_pubkeys]

    # connect 
    rpc = local_api_connect(config_path=config_path, api_session=str(args.session))
    if rpc is None:
        return {'error': 'API endpoint not running. Please start it with `api start`'}

    datastore_info = rpc.backend_datastore_get(blockchain_id, datastore_id, device_ids)
    if 'error' in datastore_info:
        return datastore_info

    datastore = datastore_info['datastore']
    assert datastore_id == datastore_get_id(get_pubkey_hex(datastore_privkey_hex))

    res = datastore_rmtree(rpc, datastore, path, datastore_privkey_hex, data_pubkeys, config_path=config_path )
    return res


def cli_datastore_getfile( args, config_path=CONFIG_PATH, interactive=False ):
    """
    command: datastore_getfile advanced raw
    help: Get a file from a datastore.
    arg: blockchain_id (str) 'The ID of the datastore owner'
    arg: datastore_id (str) 'The ID of the application datastore'
    arg: path (str) 'The path to the file to load'
    opt: extended (str) 'If True, then include the full inode and parent information as well.'
    opt: force (str) 'If True, then tolerate stale data faults.'
    opt: device_ids (str) 'If given, a CSV of device IDs owned by the blockchain ID'
    opt: device_pubkeys (str) 'If given, a CSV of device public keys owned by the blockchain ID'
    """

    blockchain_id = getattr(args, 'blockchain_id', '')
    if len(blockchain_id) == 0:
        blockchain_id = None
    else:
        blockchain_id = str(blockchain_id)

    datastore_id = str(args.datastore_id)
    path = str(args.path)
    extended = False
    force = False
    device_ids = None

    if hasattr(args, 'extended') and args.extended.lower() in ['1', 'true']:
        extended = True

    if hasattr(args, 'force') and args.force.lower() in ['1', 'true']:
        force = True

    # get the list of device IDs to use 
    device_ids = getattr(args, 'device_ids', None)
    if device_ids:
        device_ids = device_ids.split(',')

    else:
        raise NotImplementedError("Missing token file parsing logic")

    device_pubkeys = None
    if hasattr(args, 'device_pubkeys'):
        device_pubkeys = str(args.device_pubkeys).split(',')
    else:
        raise NotImplementedError("No support for token files")

    assert len(device_ids) == len(device_pubkeys)
    data_pubkeys = [{
        'device_id': dev_id,
        'public_key': pubkey
    } for (dev_id, pubkey) in zip(device_ids, device_pubkeys)]

    res = datastore_file_get('datastore', blockchain_id, datastore_id, path, data_pubkeys, extended=extended, force=force, config_path=config_path)
    if json_is_error(res):
        return res

    if not extended:
        # just the data
        return res['data']

    return res


def cli_datastore_listdir(args, config_path=CONFIG_PATH, interactive=False ):
    """
    command: datastore_listdir advanced
    help: List a directory in the datastore.
    arg: blockchain_id (str) 'The ID of the datastore owner'
    arg: datastore_id (str) 'The ID of the application datastore'
    arg: path (str) 'The path to the directory to list'
    opt: extended (str) 'If True, then include the full inode and parent information as well.'
    opt: force (str) 'If True, then tolerate stale data faults.'
    opt: device_ids (str) 'If given, a CSV of device IDs owned by the blockchain ID'
    opt: device_pubkeys (str) 'If given, a CSV of device public keys owned by the blockchain ID'
    """

    blockchain_id = getattr(args, 'blockchain_id', '')
    if len(blockchain_id) == 0:
        blockchain_id = None
    else:
        blockchain_id = str(blockchain_id)

    datastore_id = str(args.datastore_id)
    path = str(args.path)
    extended = False
    force = False
    device_ids = None

    if hasattr(args, 'extended') and args.extended.lower() in ['1', 'true']:
        extended = True

    if hasattr(args, 'force') and args.force.lower() in ['1', 'true']:
        force = True

    # get the list of device IDs to use 
    device_ids = getattr(args, 'device_ids', None)
    if device_ids:
        device_ids = device_ids.split(',')

    else:
        raise NotImplementedError("Missing token file parsing logic")

    device_pubkeys = None
    if hasattr(args, 'device_pubkeys'):
        device_pubkeys = str(args.device_pubkeys).split(',')
    else:
        raise NotImplementedError("No support for token files")

    assert len(device_ids) == len(device_pubkeys)
    data_pubkeys = [{
        'device_id': dev_id,
        'public_key': pubkey
    } for (dev_id, pubkey) in zip(device_ids, device_pubkeys)]

    res = datastore_dir_list('datastore', blockchain_id, datastore_id, path, data_pubkeys, extended=extended, force=force, config_path=config_path )
    if json_is_error(res):
        return res

    if not extended:
        return res['data']

    return res


def cli_datastore_stat(args, config_path=CONFIG_PATH, interactive=False ):
    """
    command: datastore_stat advanced
    help: Stat a file or directory in the datastore, returning only the header for files but returning the entire listing for directories.
    arg: blockchain_id (str) 'The ID of the datastore owner'
    arg: datastore_id (str) 'The datastore ID'
    arg: path (str) 'The path to the file or directory to stat'
    opt: extended (str) 'If True, then include the path information as well'
    opt: force (str) 'If True, then tolerate stale inode data.'
    opt: device_ids (str) 'If given, a CSV of device IDs owned by the blockchain ID'
    opt: device_pubkeys (str) 'If given, a CSV of device public keys owned by the blockchain ID'
    """

    blockchain_id = getattr(args, 'blockchain_id', '')
    if blockchain_id is None or len(blockchain_id) == 0:
        blockchain_id = None
    else:
        blockchain_id = str(blockchain_id)

    path = str(args.path)
    datastore_id = str(args.datastore_id)
    path = str(args.path)
    extended = False
    force = False
    device_ids = None

    if hasattr(args, 'extended') and args.extended.lower() in ['1', 'true']:
        extended = True

    if hasattr(args, 'force') and args.force.lower() in ['1', 'true']:
        force = True

    # get the list of device IDs to use 
    device_ids = getattr(args, 'device_ids', None)
    if device_ids:
        device_ids = device_ids.split(',')

    else:
        # TODO
        raise NotImplementedError("Missing token file parsing logic")

    device_pubkeys = None
    if hasattr(args, 'device_pubkeys'):
        device_pubkeys = str(args.device_pubkeys).split(',')
    else:
        # TODO
        raise NotImplementedError("No support for token files")

    assert len(device_ids) == len(device_pubkeys)
    data_pubkeys = [{
        'device_id': dev_id,
        'public_key': pubkey
    } for (dev_id, pubkey) in zip(device_ids, device_pubkeys)]

    res = datastore_path_stat('datastore', blockchain_id, datastore_id, path, data_pubkeys, extended=extended, force=force, config_path=config_path) 
    if json_is_error(res):
        return res

    if not extended:
        return res['data']

    return res


def cli_datastore_getinode(args, config_path=CONFIG_PATH, interactive=False):
    """
    command: datastore_getinode advanced
    help: Get a raw inode from a datastore
    arg: blockchain_id (str) 'The ID of the datastore owner'
    arg: datastore_id (str) 'The ID of the application user'
    arg: inode_uuid (str) 'The inode UUID'
    opt: extended (str) 'If True, then include the path information as well'
    opt: idata (str) 'If True, then include the inode payload as well.'
    opt: force (str) 'If True, then tolerate stale inode data.'
    opt: device_ids (str) 'If given, the CSV of devices owned by the blockchain ID'
    opt: device_pubkeys (str) 'If given, the CSV of device public keys owned by the blockchain ID'
    """

    blockchain_id = getattr(args, 'blockchain_id', '')
    if blockchain_id is None or len(blockchain_id) == 0:
        blockchain_id = None
    else:
        blockchain_id = str(blockchain_id)

    datastore_id = str(args.datastore_id)
    inode_uuid = str(args.inode_uuid)
    
    session = jsontokens.decode_token(str(args.session))
    data_pubkeys = session['payload']['app_public_keys']

    extended = False
    force = False
    idata = False
    device_ids = None

    if hasattr(args, 'extended') and args.extended.lower() in ['1', 'true']:
        extended = True

    if hasattr(args, 'force') and args.force.lower() in ['1', 'true']:
        force = True

    if hasattr(args, 'idata') and args.idata.lower() in ['1', 'true']:
        idata = True

    # get the list of device IDs to use 
    device_ids = getattr(args, 'device_ids', None)
    if device_ids:
        device_ids = device_ids.split(',')

    else:
        # TODO
        raise NotImplementedError("Missing token file parsing logic")

    device_pubkeys = None
    if hasattr(args, 'device_pubkeys'):
        device_pubkeys = str(args.device_pubkeys).split(',')
    else:
        # TODO
        raise NotImplementedError("No support for token files")

    assert len(device_ids) == len(device_pubkeys)
    data_pubkeys = [{
        'device_id': dev_id,
        'public_key': pubkey
    } for (dev_id, pubkey) in zip(device_ids, device_pubkeys)]

    return datastore_inode_getinode('datastore', blockchain_id, datastore_id, inode_uuid, data_pubkeys, extended=extended, force=force, idata=idata, config_path=config_path) 


def cli_datastore_putfile(args, config_path=CONFIG_PATH, interactive=False, force_data=False ):
    """
    command: datastore_putfile advanced 
    help: Put a file into the datastore at the given path.
    arg: blockchain_id (str) 'The owner of this datastore'
    arg: privkey (str) 'The app-specific data private key'
    arg: path (str) 'The path to the new file'
    arg: data (str) 'The data to store, or a path to a file with the data'
    arg: session (str) 'The API session token'
    opt: create (str) 'If True, then succeed only if the file has never before existed.'
    opt: force (str) 'If True, then tolerate stale inode data.'
    """
    
    blockchain_id = str(args.blockchain_id)
    path = str(args.path)
    data = str(args.data)
    privkey = str(args.privkey)
    create = (str(getattr(args, "create", "")).lower() in ['1', 'create', 'true'])
    force = (str(getattr(args, 'force', '')).lower() in ['1', 'true'])

    return datastore_file_put('datastore', blockchain_id, privkey, path, data, str(args.session), create=create, force_data=force_data, config_path=config_path )


def cli_datastore_deletefile(args, config_path=CONFIG_PATH, interactive=False ):
    """
    command: datastore_deletefile advanced
    help: Delete a file from the datastore.
    arg: blockchain_id (str) 'The owner of this datastore'
    arg: privkey (str) 'The datastore private key'
    arg: path (str) 'The path to the file to delete'
    arg: session (str) 'The API session token'
    opt: force (str) 'If True, then tolerate stale inode data.'
    """

    blockchain_id = str(args.blockchain_id)
    path = str(args.path)
    privkey = str(args.privkey)
    datastore_id = datastore_get_id(get_pubkey_hex(privkey))
    force = (str(getattr(args, 'force', '')).lower() in ['1', 'true'])

    session = jsontokens.decode_token(str(args.session))
    data_pubkeys = session['payload']['app_public_keys']
    device_ids = [dk['device_id'] for dk in session['payload']['app_public_keys']]

    # connect 
    rpc = local_api_connect(config_path=config_path)
    if rpc is None:
        return {'error': 'API endpoint not running. Please start it with `api start`'}

    datastore_info = rpc.backend_datastore_get(blockchain_id, datastore_id, device_ids)
    if 'error' in datastore_info:
        datastore_info['errno'] = errno.EPERM
        return datastore_info

    datastore = datastore_info['datastore']

    res = datastore_deletefile( rpc, datastore, path, privkey, data_pubkeys, force=force, config_path=config_path )
    return res


def cli_datastore_get_privkey(args, config_path=CONFIG_PATH, interactive=False ):
    """
    command: datastore_get_privkey advanced
    help: Get the private key for a datastore, given the master private key.
    arg: master_privkey (str) 'The master data private key'
    arg: app_domain (str) 'The name of the application'
    """
    raise NotImplementedError("Token file support not yet implemented")

    app_domain = str(args.app_domain)
    master_privkey = str(args.master_privkey)

    datastore_privkey = datastore_get_privkey(master_privkey, app_domain, config_path=config_path)
    return {'status': True, 'datastore_privkey': datastore_privkey}


def cli_datastore_get_id(args, config_path=CONFIG_PATH, interactive=False ):
    """
    command: datastore_get_id advanced
    help: Get the ID of an application data store
    arg: datastore_privkey (str) 'The datastore private key'
    """
    datastore_id = datastore_get_id(get_pubkey_hex(str(args.datastore_privkey)))
    return {'status': True, 'datastore_id': datastore_id}


def cli_get_collection( args, config_path=CONFIG_PATH, proxy=None, password=None ):
    """
    command: get_collection advanced
    help: Get a collection record
    arg: blockchain_id (str) 'The ID of the owner'
    arg: collection_domain (str) 'The name of the collection'
    opt: device_ids (str) 'The list of device IDs that can write'
    """
    raise NotImplementedError("Collections not implemented")

    blockchain_id = str(args.blockchain_id)
    collection_domain = str(args.collection_domain)
    device_ids = args.device_ids.split(',')
    return get_datastore_by_type('collection', blockchain_id, collection_domain, device_ids, config_path=config_path )


def cli_create_collection( args, config_path=CONFIG_PATH, proxy=None, password=None, master_data_privkey=None ):
    """
    command: create_collection advanced 
    help: Make a new collection for a given user.
    arg: blockchain_id (str) 'The blockchain ID that will own this collection'
    arg: collection_domain (str) 'The domain of this collection.'
    opt: device_ids (str) 'A CSV of your device IDs.'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)
    
    raise NotImplementedError("Collections not implemented")

    blockchain_id = str(args.blockchain_id)
    password = get_default_password(password)
    collection_domain = str(args.collection_domain)

    # get the list of device IDs to use 
    device_ids = getattr(args, 'device_ids', None)
    if device_ids:
        device_ids = device_ids.split(',')

    else:
        raise NotImplementedError("Missing token file parsing logic")

    # TODO: privkey
    # privkey = 
    raise NotImplementedError("Collections are not implemented yet")

    # get the list of device IDs to use 
    device_ids = getattr(args, 'device_ids', None)
    if device_ids:
        device_ids = device_ids.split(',')

    else:
        raise NotImplementedError("Missing token file parsing logic")

    return create_datastore_by_type('collection', blockchain_id, privkey, device_ids, proxy=proxy, config_path=config_path, password=password, master_data_privkey=master_data_privkey)


def cli_delete_collection( args, config_path=CONFIG_PATH, proxy=None, password=None, master_data_privkey=None ):
    """
    command: delete_collection advanced 
    help: Delete a collection owned by a given user, and all of the data it contains.
    arg: blockchain_id (str) 'The owner of this collection'
    arg: collection_domain (str) 'The domain of this collection'
    opt: device_ids (str) 'A CSV of your devices'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    raise NotImplementedError("Collections not implemented")

    password = get_default_password(password)

    blockchain_id = str(args.blockchain_id)
    collection_domain = str(args.collection_domain)
    
    # get the list of device IDs to use 
    device_ids = getattr(args, 'device_ids', None)
    if device_ids:
        device_ids = device_ids.split(',')

    else:
        raise NotImplementedError("Missing token file parsing logic")

    # TODO: privkey
    # privkey = 
    raise NotImplementedError("Collections are not implemented")

    device_ids = None
    if hasattr(args, 'device_ids'):
        device_ids = str(args.device_ids).split(',')
    else:
        raise NotImplementedError("No support for token files")

    return delete_datastore_by_type('collection', blockchain_id, privkey, device_ids, force=True, config_path=config_path, proxy=proxy, password=password)


def cli_collection_listitems(args, config_path=CONFIG_PATH, password=None, interactive=False, proxy=None ):
    """
    command: collection_items advanced
    help: List the contents of a collection
    arg: blockchain_id (str) 'The ID of the collection owner'
    arg: collection_domain (str) 'The domain of this collection'
    arg: path (str) 'The path to the directory to list'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    raise NotImplementedError("Collections not implemented")

    password = get_default_password(password)
    blockchain_id = str(args.blockchain_id)

    # get the list of device IDs to use 
    device_ids = getattr(args, 'device_ids', None)
    if device_ids:
        device_ids = device_ids.split(',')

    else:
        raise NotImplementedError("Missing token file parsing logic")

    collection_domain = str(args.collection_domain)
    path = str(args.path)

    res = datastore_dir_list('collection', blockchain_id, collection_domain, '/', device_ids, config_path=config_path, proxy=proxy)
    if 'error' in res:
        return res

    # if somehow we get a directory in here, exclude it
    dir_info = res['dir']
    filtered_dir_info = {}
    for name in dir_info.keys():
        if dir_info[name]['type'] == MUTABLE_DATUM_FILE_TYPE:
            filtered_dir_info[name] = dir_info[name]

    return {'status': True, 'dir': filtered_dir_info}


def cli_collection_statitem(args, config_path=CONFIG_PATH, interactive=False, proxy=None):
    """
    command: collection_statitem advanced
    help: Stat an item in a collection
    arg: blockchain_id (str) 'The ID of the collection owner'
    arg: collection_domain (str) 'The name of this collection'
    arg: item_id (str) 'The name of the item to stat'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    raise NotImplementedError("Collections not implemented")

    password = get_default_password(password)

    # get the list of device IDs to use 
    device_ids = getattr(args, 'device_ids', None)
    if device_ids:
        device_ids = device_ids.split(',')

    else:
        raise NotImplementedError("Missing token file parsing logic")

    blockchain_id = str(args.blockchain_id)
    collection_domain = str(args.collection_domain)
    item_id = str(args.item_id)

    return datastore_path_stat('collection', blockchain_id, collection_domain, '/{}'.format(item_id), device_ids, proxy=proxy, config_path=config_path)


def cli_collection_putitem(args, config_path=CONFIG_PATH, interactive=False, proxy=None, password=None, force_data=False, master_data_privkey=None ):
    """
    command: collection_putitem advanced 
    help: Put an item into a collection.  Overwrites are forbidden.
    arg: blockchain_id (str) 'The owner of the collection'
    arg: collection_privkey (str) 'The collection private key'
    arg: item_id (str) 'The item name'
    arg: data (str) 'The data to store, or a path to a file with the data'
    opt: device_ids (str) 'A CSV of your device IDs'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)
    
    raise NotImplementedError("Collections not implemented")

    password = get_default_password(password)

    blockchain_id = str(args.blockchain_id)
    collection_domain = str(args.collection_domain)
    item_id = str(args.item_id)
    data = args.data
    collection_privkey = str(args.collection_privkey)

    # get the list of device IDs to use 
    device_ids = getattr(args, 'device_ids', None)
    if device_ids:
        device_ids = device_ids.split(',')

    else:
        raise NotImplementedError("Missing token file parsing logic")


    return datastore_file_put('collection', blockchain_id, collection_privkey, '/{}'.format(item_id), data, device_ids=device_ids, 
                              create=True, force_data=force_data, proxy=proxy, config_path=config_path, master_data_privkey=master_data_privkey, password=password)


def cli_collection_getitem( args, config_path=CONFIG_PATH, interactive=False, password=None, proxy=None ):
    """
    command: collection_getitem advanced
    help: Get an item from a collection.
    arg: blockchain_id (str) 'The ID of the datastore owner'
    arg: collection_domain (str) 'The domain of this collection'
    arg: item_id (str) 'The item to fetch'
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    raise NotImplementedError("Collections not implemented")

    password = get_default_password(password)

    config_dir = os.path.dirname(config_path)
    blockchain_id = getattr(args, 'blockchain_id', '')
    if blockchain_id is None or len(blockchain_id) == 0:
        blockchain_id = None
    else:
        blockchain_id = str(blockchain_id)
    
    collection_domain = str(args.collection_domain)
    item_id = str(args.item_id)

    return datastore_file_get('collection', blockchain_id, collection_domain, '/{}'.format(item_id), password=password, config_path=config_path, proxy=proxy)


def cli_start_server( args, config_path=CONFIG_PATH, interactive=False ):
    """
    command: start_server advanced
    help: Start a Blockstack indexing server
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
        testnet = (testnet.lower() in ['1', 'true', 'yes', 'testnet3'])

    cmds = ['blockstack-core', 'start']
    if foreground:
        cmds.append('--foreground')

    if testnet:
        cmds.append('--testnet3')

    # TODO: use subprocess
    if working_dir is not None:
        working_dir_envar = 'VIRTUALCHAIN_WORKING_DIR="{}"'.format(working_dir)
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
    help: Stop a running Blockstack indexing server
    opt: working_dir (str) 'The directory which contains the server state.'
    """

    working_dir = args.working_dir

    cmds = ['blockstack-core', 'stop']

    if working_dir is not None:
        working_dir_envar = 'VIRTUALCHAIN_WORKING_DIR="{}"'.format(working_dir)
        cmds = [working_dir_envar] + cmds

    cmd_str = " ".join(cmds)

    # TODO: use subprocess
    log.debug('Execute: {}'.format(cmd_str))
    exit_status = os.system(cmd_str)

    if not os.WIFEXITED(exit_status) or os.WEXITSTATUS(exit_status) != 0:
        error_str = 'Failed to execute "{}". Exit code {}'.format(cmd_str, exit_status)
        return {'error': error_str}

    return {'status': True}

