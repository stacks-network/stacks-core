#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~

    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

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

from pybitcoin import BlockcypherClient
from pybitcoin.services.blockcypher import get_unspents

from .config import BLOCKCYPHER_TOKEN
from .config import RETRY_INTERVAL, TX_CONFIRMATIONS_NEEDED

from .utils import satoshis_to_btc, get_address_from_pvtkey
from .utils import pretty_print as pprint
from .utils import config_log

from blockcypher import get_transaction_details, get_blockchain_overview

log = config_log(__name__)


def get_block_height():
    """ Return block height (currently uses BlockCypher API)
    """

    resp = None

    try:
        data = get_blockchain_overview()
    except Exception as e:
        print e

    if 'height' in data:
        resp = data['height']

    return resp


def get_tx_confirmations(tx_hash):
    """ Return block height (currently uses BlockCypher API)
    """

    resp = None

    try:
        data = get_transaction_details(tx_hash)
    except Exception as e:
        print e

    if 'confirmations' in data:
        resp = data['confirmations']

    return resp


def txRejected(tx_hash, tx_sent_at_height):

    current_height = get_block_height()
    tx_confirmations = get_tx_confirmations(tx_hash)

    if (current_height - tx_sent_at_height) > RETRY_INTERVAL:

        # if no confirmations and retry limit hits
        if tx_confirmations == 0:
            return True
    else:

        if tx_confirmations > TX_CONFIRMATIONS_NEEDED:
            log.debug("confirmed on the network")
        else:
            log.debug("waiting: (tx: %s, confirmations: %s)" % (queue_obj['transaction_hash'], tx_confirmations))

    return False


def test_inputs():
        """ Check if BTC key being used has enough inputs
        """

        from registrar.config import BTC_PRIV_KEY
        btc_address = get_address_from_pvtkey(BTC_PRIV_KEY)

        log.debug("Testing address: %s" % btc_address)

        client = BlockcypherClient(api_key=BLOCKCYPHER_TOKEN)

        unspents = get_unspents(btc_address, client)

        total_satoshis = 0
        counter = 0
        for unspent in unspents:

            counter += 1
            total_satoshis += unspent['value']

        print counter

        btc_amount = satoshis_to_btc(total_satoshis)
        btc_amount = float(btc_amount)

        print "btc_amount: %s" % btc_amount

if __name__ == '__main__':

    print get_block_height()
    print get_tx_confirmations('0b0fd5c26d877e129281777c9c2eda5d399ac3b26b9f82fb3bc8f64545a2a67f')
