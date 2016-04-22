#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
"""

import os
import sys
import virtualchain
import pybitcoin
import blockstack_utxo
import json

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

from ..config import TX_EXPIRED_INTERVAL, TX_CONFIRMATIONS_NEEDED
from ..config import MAXIMUM_NAMES_PER_ADDRESS
from ..config import BLOCKSTACKD_SERVER, BLOCKSTACKD_PORT

from ..config import MINIMUM_BALANCE, CONFIG_PATH
from ..config import get_logger

from ..utils import satoshis_to_btc
from ..utils import pretty_print as pprint

from ..proxy import get_default_proxy
from ..proxy import get_names_owned_by_address as blockstack_get_names_owned_by_address
from ..proxy import get_name_blockchain_record as blockstack_get_name_blockchain_record

log = get_logger() 

def get_bitcoind_client(config_file=CONFIG_PATH):
    """
    Connect to bitcoind
    """
    bitcoind_opts = virtualchain.get_bitcoind_config(config_file=config_file)
    if bitcoind_opts['bitcoind_mock']:
        # testing 
        from blockstack_integration_tests import connect_mock_bitcoind
        client = connect_mock_bitcoind( bitcoind_opts, reset=True )
    else:
        # production
        client = virtualchain.connect_bitcoind( bitcoind_opts )
    return client


def get_utxo_client(config_file=CONFIG_PATH):
    """
    Connect to UTXO provider
    """
    # which UTXO provider to use?
    # opt for 'blockstack_utxo' if available, since that indicates testing 
    available_utxo_providers = blockstack_utxo.all_utxo_providers( config_file )
    utxo_provider = None

    if 'blockstack_utxo' in available_utxo_providers:
        utxo_provider = 'blockstack_utxo'
    else:
        utxo_provider = 'blockcypher'

    client = blockstack_utxo.get_utxo_provider_client( utxo_provider, config_file )
    return client


def get_block_height():
    """
    Return block height (currently uses bitcoind)
    """

    resp = None

    # get a fresh local client (needed after waking up from sleep)
    bitcoind_client = get_bitcoind_client()

    try:
        data = bitcoind_client.getinfo()

        if 'blocks' in data:
            resp = data['blocks']

    except Exception as e:
        log.debug("ERROR: block height")
        log.debug(e)

    return resp


def get_tx_confirmations(tx_hash):
    """
    Get the number of confirmations for a transaction
    Return None if not given
    """

    resp = None

    # get a fresh local client (needed after waking up from sleep)
    bitcoind_client = get_bitcoind_client()

    try:
        # second argument of '1' asks for results in JSON
        tx_data = bitcoind_client.getrawtransaction(tx_hash, 1)
        if tx_data is None:
            resp = 0
            log.debug("No such tx %s (%s configured from %s)" % (tx_hash, bitcoind_client, CONFIG_PATH))

        else:
            if 'confirmations' in tx_data:
                resp = tx_data['confirmations']
            elif 'txid' in tx_data:
                resp = 0

            log.debug("Tx %s has %s confirmations" % (tx_hash, resp))

    except Exception as e:
        log.exception(e)
        log.debug("ERROR: tx details: %s" % tx_hash)

    return resp


def is_tx_accepted( tx_hash, num_needed=TX_CONFIRMATIONS_NEEDED ):
    """
    Determine whether or not a transaction was accepted.
    """
    tx_confirmations = get_tx_confirmations(tx_hash)
    if tx_confirmations > num_needed:
        return True

    return False


def is_tx_rejected(tx_hash, tx_sent_at_height):
    """
    Determine whether or not a transaction was "rejected".
    That is, determine whether or not the transaction is still
    unconfirmed, so the caller can do something like e.g.
    resend it.
    """
    current_height = get_block_height()
    tx_confirmations = get_tx_confirmations(tx_hash)

    if (current_height - tx_sent_at_height) > TX_EXPIRED_INTERVAL and tx_confirmations == 0:
        # if no confirmations and retry limit hits
        return True

    return False


def get_utxos(address):
    """ 
    Given an address get unspent outputs (UTXOs)
    Return array of UTXOs, empty array if none available
    """

    utxo_client = get_utxo_client()
    data = []

    try:
        data = pybitcoin.get_unspents(address, utxo_client)
    except Exception as e:
        log.exception(e)
        log.debug("Error in getting UTXOs from UTXO provider: %s" % e)

    return data


def get_balance(address):
    """
    Check if BTC key being used has enough balance on unspents
    """

    data = get_utxos(address)
    satoshi_amount = 0

    for utxo in data:

        if 'value' in utxo:
            satoshi_amount += utxo['value']

    btc_amount = satoshis_to_btc(satoshi_amount)
    btc_amount = float(btc_amount)

    return btc_amount


def recipientNotReady(address, proxy=None):
    """
    Check if address can own more names or not
    """

    if proxy is None:
        proxy = get_default_proxy()

    resp = blockstack_get_names_owned_by_address(address, proxy=proxy)
    names_owned = resp

    if len(names_owned) > MAXIMUM_NAMES_PER_ADDRESS:
        return True

    # if tests pass, then can use the address
    return False


def dontuseAddress(address):
    """
    Check if an address should not be used because of:
    a) it has unconfirmed TX
    b) it has more than maximum registered names (blockstack restriction)
    """

    try:
        unspents = get_utxos(address)
    except Exception as e:
        log.debug(e)
        return True

    for unspent in unspents:

        if 'confirmations' in unspent:
            if int(unspent['confirmations']) == 0:
                return True

    # if all tests pass, then can use the address
    return False


def underfundedAddress(address):
    """
    Determine whether or not an address is underfunded.
    Return True if underfunded
    Return False if not.
    """
    balance = get_balance(address)

    if balance is None:
        log.debug("Balance: (%s, %s)" % (address, balance))
        return True

    if float(balance) <= MINIMUM_BALANCE:
        return True
    else:
        return False


