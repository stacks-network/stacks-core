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

import sys
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

        if 'height' in data:
            resp = data['height']

    except Exception as e:
        log.debug(e)

    return resp


def get_tx_confirmations(tx_hash):
    """ Return block height (currently uses BlockCypher API)
    """

    resp = None

    try:
        data = get_transaction_details(tx_hash)

        if 'confirmations' in data:
            resp = data['confirmations']

    except Exception as e:
        log.debug(e)

    return resp


def txRejected(tx_hash, tx_sent_at_height):

    current_height = get_block_height()

    if type(current_height) is not int:
        log.debug("ERROR: getting current height")
        return False

    tx_confirmations = get_tx_confirmations(tx_hash)

    if (current_height - tx_sent_at_height) > RETRY_INTERVAL:

        # if no confirmations and retry limit hits
        if tx_confirmations == 0:
            return True
    else:

        if tx_confirmations > TX_CONFIRMATIONS_NEEDED:
            log.debug("confirmed on the network")
        else:
            log.debug("waiting: (tx: %s, confirmations: %s)" % (tx_hash, tx_confirmations))

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

        btc_amount = satoshis_to_btc(total_satoshis)
        btc_amount = float(btc_amount)

        log.debug("btc_amount: %s" % btc_amount)

if __name__ == '__main__':

    try:
        command = sys.argv[1]
    except Exception as e:
        log.info("Options are block_height, tx_confirmations")
        exit(0)

    if command == "block_height":
        log.info("Block height: %s" % get_block_height())
    elif command == "tx_confirmations":
        try:
            tx_hash = sys.argv[2]
        except:
            log.info("Tx hash missing")

        log.info("(tx, confirmations): (%s, %s)" % (tx_hash, get_tx_confirmations(tx_hash)))