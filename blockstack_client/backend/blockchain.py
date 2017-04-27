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

import os
import virtualchain
import json

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

from ..constants import TX_EXPIRED_INTERVAL, TX_CONFIRMATIONS_NEEDED, TX_MIN_CONFIRMATIONS
from ..constants import MAXIMUM_NAMES_PER_ADDRESS
from ..constants import BLOCKSTACK_TEST, BLOCKSTACK_DRY_RUN
from ..constants import CONFIG_PATH

from ..logger import get_logger

log = get_logger() 

def get_bitcoind_client(config_path=CONFIG_PATH):
    """
    Connect to bitcoind
    """
    bitcoind_opts = virtualchain.get_bitcoind_config(config_file=config_path)
    log.debug("Connect to bitcoind at %s:%s (%s)" % (bitcoind_opts['bitcoind_server'], bitcoind_opts['bitcoind_port'], config_path))
    client = virtualchain.connect_bitcoind( bitcoind_opts )

    return client


def get_block_height(config_path=CONFIG_PATH):
    """
    Return block height (currently uses bitcoind)
    Return the height on success
    Return None on error
    """

    resp = None

    # get a fresh local client (needed after waking up from sleep)
    bitcoind_client = get_bitcoind_client(config_path=config_path)

    try:
        data = bitcoind_client.getinfo()

        if 'blocks' in data:
            resp = int(data['blocks'])

    except Exception as e:
        log.debug("ERROR: block height")
        log.debug(e)

    return resp


def get_tx_confirmations(tx_hash, config_path=CONFIG_PATH):
    """
    Get the number of confirmations for a transaction
    Return None if not given
    """

    resp = None

    # get a fresh local client (needed after waking up from sleep)
    bitcoind_client = get_bitcoind_client(config_path=config_path)

    try:
        # second argument of '1' asks for results in JSON
        tx_data = bitcoind_client.getrawtransaction(tx_hash, 1)
        if tx_data is None:
            resp = 0
            log.debug("No such tx %s (%s configured from %s)" % (tx_hash, bitcoind_client, config_path))

        else:
            if 'confirmations' in tx_data:
                resp = tx_data['confirmations']
            elif 'txid' in tx_data:
                resp = 0

            log.debug("Tx %s has %s confirmations" % (tx_hash, resp))

    except Exception as e:
        log.debug("ERROR: failed to query tx details for %s" % tx_hash)

    return resp


def get_tx_fee( tx_hex, config_path=CONFIG_PATH ):
    """
    Get the tx fee from bitcoind
    Return the fee on success, in satoshis
    Return None on error
    """
    bitcoind_client = get_bitcoind_client(config_path=config_path)
    try:
        # try to confirm in 2-3 blocks
        fee = bitcoind_client.estimatefee(2)
        if fee < 0:
            # if we're testing, then use our own fee
            if BLOCKSTACK_TEST or os.environ.get("BLOCKSTACK_TESTNET", None) == "1":
                fee = 5500.0 / 10**8

            else:
                log.error("Failed to estimate tx fee")
                return None

        fee = float(fee) 

        # / 2048, since tx_hex is a hex string (otherwise / 1024, since it's BTC per kb)
        return round((fee * (len(tx_hex) / 2048.0)) * 10**8)
    except Exception, e:
        log.exception(e)
        log.debug("Failed to estimate fee")
        return None


def is_tx_accepted( tx_hash, num_needed=TX_CONFIRMATIONS_NEEDED, config_path=CONFIG_PATH ):
    """
    Determine whether or not a transaction was accepted.
    """
    tx_confirmations = get_tx_confirmations(tx_hash, config_path=config_path)
    if tx_confirmations > num_needed:
        return True

    return False


def is_tx_rejected(tx_hash, tx_sent_at_height, config_path=CONFIG_PATH):
    """
    Determine whether or not a transaction was "rejected".
    That is, determine whether or not the transaction is still
    unconfirmed, so the caller can do something like e.g.
    resend it.
    """
    current_height = get_block_height(config_path=config_path)
    tx_confirmations = get_tx_confirmations(tx_hash, config_path=config_path)

    if (current_height - tx_sent_at_height) > TX_EXPIRED_INTERVAL and tx_confirmations == 0:
        # if no confirmations and retry limit hits
        return True

    return False


def get_utxos(address, config_path=CONFIG_PATH, utxo_client=None, min_confirmations=TX_MIN_CONFIRMATIONS):
    """ 
    Given an address get unspent outputs (UTXOs)
    Return array of UTXOs on success
    Return {'error': ...} on failure
    """

    from ..scripts import tx_get_unspents
    from ..config import get_utxo_provider_client

    if min_confirmations != TX_MIN_CONFIRMATIONS:
        log.warning("Using a different number of confirmations ({}) instead of default ({})".format(min_confirmations, TX_MIN_CONFIRMATIONS))

    if utxo_client is None:
        utxo_client = get_utxo_provider_client(config_path=config_path)
   
    data = []
    try:
        data = tx_get_unspents( address, utxo_client )
    except Exception, e:
        log.exception(e)
        log.debug("Failed to get UTXOs for %s" % address)
        data = {'error': 'Failed to get UTXOs for %s' % address}
        return data
   
    # filter unconfirmed
    ret = []
    for utxo in data:
        if 'confirmations' in utxo:
            if int(utxo['confirmations']) >= min_confirmations:
                ret.append(utxo)

    return ret


def broadcast_tx(tx_hex, config_path=CONFIG_PATH, tx_broadcaster=None):
    """
    Send a signed transaction to the blockchain
    Return {'status': True, 'transaction_hash': ...} on success.  Include 'tx': ... if BLOCKSTACK_DRY_RUN is set.
    Return {'error': ...} on failure.
    """
    from ..config import get_tx_broadcaster
    from ..utxo import broadcast_transaction

    if tx_broadcaster is None:
        tx_broadcaster = get_tx_broadcaster(config_path=config_path)

    if BLOCKSTACK_TEST is not None:
        log.debug('Send {}'.format(tx_hex))
    
    resp = {}
    try:
        if BLOCKSTACK_DRY_RUN:
            # TODO: expand to other blockchains...
            resp = {
                'tx': tx_hex,
                'transaction_hash': virtualchain.btc_tx_get_hash(tx_hex),
                'status': True
            }
            return resp

        else:
            resp = broadcast_transaction(tx_hex, tx_broadcaster)
            if 'tx_hash' not in resp or 'error' in resp:
                log.error('Failed to send {}'.format(tx_hex))
                resp['error'] = 'Failed to broadcast transaction: {}'.format(tx_hex)
                return resp

    except Exception as e:
        log.exception(e)
        resp['error'] = 'Failed to broadcast transaction: {}'.format(tx_hex)

        if BLOCKSTACK_TEST is not None:
            # should NEVER happen in test mode
            msg = 'FATAL: failed to send transaction:\n{}'
            log.error(msg.format(json.dumps(resp, indent=4, sort_keys=True)))
            os.abort()

    # for compatibility
    resp['status'] = True
    resp['transaction_hash'] = resp.pop('tx_hash')

    return resp


def get_balance(address, config_path=CONFIG_PATH, utxo_client=None, min_confirmations=TX_MIN_CONFIRMATIONS):
    """
    Check if BTC key being used has enough balance on unspents
    Returns value in satoshis on success
    Return None on failure
    """

    data = get_utxos(address, config_path=config_path, utxo_client=utxo_client, min_confirmations=min_confirmations)
    if 'error' in data:
        log.error("Failed to get UTXOs for %s: %s" % (address, data['error']))
        return None 

    satoshi_amount = 0

    for utxo in data:

        if 'confirmations' in utxo:
            if int(utxo['confirmations']) < min_confirmations:
                # doesn't count
                continue

        if 'value' in utxo:
            satoshi_amount += utxo['value']

    return satoshi_amount


def is_address_usable(address, config_path=CONFIG_PATH, utxo_client=None, min_confirmations=TX_MIN_CONFIRMATIONS):
    """
    Check if an address is usable (i.e. it has no unconfirmed transactions)
    """
    try:
        unspents = get_utxos(address, config_path=config_path, utxo_client=None, min_confirmations=min_confirmations)
        if 'error' in unspents:
            log.error("Failed to get UTXOs for %s: %s" % (address, unspents['error']))
            return False

    except Exception as e:
        log.exception(e)
        return False

    for unspent in unspents:

        if 'confirmations' in unspent:
            if int(unspent['confirmations']) < min_confirmations:
                return False

    return True


def can_receive_name( address, proxy=None ):
    """
    Can an address receive a name?
    """
    from ..proxy import get_default_proxy
    from ..proxy import get_names_owned_by_address as blockstack_get_names_owned_by_address

    if proxy is None:
        proxy = get_default_proxy()

    resp = blockstack_get_names_owned_by_address(address, proxy=proxy)
    names_owned = resp

    if len(names_owned) > MAXIMUM_NAMES_PER_ADDRESS:
        return False

    return True

