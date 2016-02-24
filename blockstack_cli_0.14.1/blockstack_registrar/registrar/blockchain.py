#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~

    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

This file is part of Registrar.

    Registrar is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Registrar is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Registrar. If not, see <http://www.gnu.org/licenses/>.
"""

import sys
from pybitcoin import BlockcypherClient
from pybitcoin.services.blockcypher import get_unspents
from pybitcoin.rpc.bitcoind_client import BitcoindClient

from .config import BLOCKCYPHER_TOKEN
from .config import RETRY_INTERVAL, TX_CONFIRMATIONS_NEEDED, PREORDER_REJECTED
from .config import BITCOIND_SERVER, BITCOIND_PORT
from .config import BITCOIND_USER, BITCOIND_PASSWD
from .config import BITCOIND_WALLET_PASSPHRASE, BITCOIND_USE_HTTPS
from .config import MAXIMUM_NAMES_PER_ADDRESS

from .config import UTXO_SERVER, UTXO_USER, UTXO_PASSWD
from .config import UTXO_PROVIDER
from .config import BLOCKSTORED_IP, BLOCKSTORED_PORT

from .utils import satoshis_to_btc
from .utils import pretty_print as pprint
from .utils import config_log

from blockcypher import get_address_details

from .config import MINIMUM_BALANCE

log = config_log(__name__)


def get_bitcoind_client():

    client = BitcoindClient(server=BITCOIND_SERVER, port=BITCOIND_PORT,
                                user=BITCOIND_USER, passwd=BITCOIND_PASSWD,
                                use_https=BITCOIND_USE_HTTPS,
                                passphrase=BITCOIND_WALLET_PASSPHRASE)

    return client


def get_utxo_client():

    client = BitcoindClient(server=UTXO_SERVER, port=BITCOIND_PORT,
                            user=UTXO_USER, passwd=UTXO_PASSWD,
                            use_https=BITCOIND_USE_HTTPS)

    return client


def get_block_height():
    """ Return block height (currently uses bitcoind)
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
    """ Return block height (currently uses bitcoind)
    """

    resp = None

    # get a fresh local client (needed after waking up from sleep)
    bicoind_client = get_bitcoind_client()

    try:
        # second argument of '1' asks for results in JSON
        tx_data = bicoind_client.getrawtransaction(tx_hash, 1)

        if 'confirmations' in tx_data:
            resp = tx_data['confirmations']
        elif 'txid' in tx_data:
            resp = 0

    except Exception as e:
        log.debug("ERROR: tx details: %s" % tx_hash)
        log.debug(e)

    return resp


def txRejected(tx_hash, tx_sent_at_height):

    current_height = get_block_height()

    if type(current_height) is not int:
        log.debug("ERROR: getting current height")
        return False

    if tx_sent_at_height is None:
        log.debug("ERROR: stored height is incorrect")
        return False

    tx_confirmations = get_tx_confirmations(tx_hash)

    if (current_height - tx_sent_at_height) > RETRY_INTERVAL:

        # if no confirmations and retry limit hits
        if tx_confirmations == 0:
            return True

    return False


def preorderRejected(tx_hash):

    tx_confirmations = get_tx_confirmations(tx_hash)

    if tx_confirmations > PREORDER_REJECTED:
        return True

    return False


def get_balance_from_unspents(address):
    """ Check if BTC key being used has enough balance on unspents
    """

    client = BlockcypherClient(api_key=BLOCKCYPHER_TOKEN)

    unspents = get_unspents(address, client)

    total_satoshis = 0
    counter = 0

    for unspent in unspents:

        counter += 1
        total_satoshis += unspent['value']

    btc_amount = satoshis_to_btc(total_satoshis)
    btc_amount = float(btc_amount)

    return btc_amount


def get_utxos(address):
    """ Given an address get unspent outputs (UTXOs)

        Return array of UTXOs, empty array if none available
    """

    bitcoind_client = get_utxo_client()

    data = []

    try:
        data = bitcoind_client.get_unspents(address)
    except Exception as e:
        log.debug("Error in getting UTXOs from bitcoind: %s" % e)

    return data


def get_balance(address):
    """ Check if BTC key being used has enough balance on unspents
    """

    if UTXO_PROVIDER == 'blockcypher':
        return get_balance_from_blockcypher(address)
    else:

        data = get_utxos(address)

        satoshi_amount = 0

        for utxo in data:

            if 'value' in utxo:
                satoshi_amount += utxo['value']

        btc_amount = satoshis_to_btc(satoshi_amount)
        btc_amount = float(btc_amount)

        return btc_amount


def get_balance_from_blockcypher(address):
    """ Check if BTC key being used has enough balance on unspents
    """
    data = get_address_details(address, api_key=BLOCKCYPHER_TOKEN)

    if 'final_balance' not in data:
        return None

    btc_amount = satoshis_to_btc(data['final_balance'])
    btc_amount = float(btc_amount)

    return btc_amount


def recipientNotReady(address):
    """
        Check if address can own more names or not
    """

    # hack to ensure local, until we update client
    from blockstore_client import client as bs_client
    # start session using blockstore_client
    bs_client.session(server_host=BLOCKSTORED_IP, server_port=BLOCKSTORED_PORT,
                      set_global=True)

    resp = bs_client.get_names_owned_by_address(address)
    names_owned = resp

    if len(names_owned) > MAXIMUM_NAMES_PER_ADDRESS:
        return True

    # if tests pass, then can use the address
    return False


def dontuseAddress(address):
    """ Check if an address should not be used because of:
        a) it has unconfirmed TX
        b) it has more than maximum registered names (blockstore restriction)
    """

    if UTXO_PROVIDER == 'blockcypher':
        try:
            data = get_address_details(address)
        except:
            return True

        try:
            unconfirmed_n_tx = data['unconfirmed_n_tx']
        except:
            return True

        if int(unconfirmed_n_tx) == 0:
            return False
        else:
            return True
    else:
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

    if UTXO_PROVIDER == 'blockcypher':
        balance = get_balance_from_blockcypher(address)
    else:
        balance = get_balance(address)

    if balance is None:
        log.debug("Balance: (%s, %s)" % (address, balance))
        return True

    if float(balance) <= MINIMUM_BALANCE:
        return True
    else:
        return False
