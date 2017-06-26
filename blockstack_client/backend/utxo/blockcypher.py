#!/usr/bin/env python2
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

import json
import requests

BLOCKCYPHER_BASE_URL = 'https://api.blockcypher.com/v1/btc/main'

from .blockchain_client import BlockchainClient


class BlockcypherClient(BlockchainClient):
    def __init__(self, api_key=None, timeout=30, min_confirmations=None):
        self.type = 'blockcypher.com'
        if api_key:
            self.auth = (api_key, '')
        else:
            self.auth = None

        self.timeout = timeout
        self.min_confirmations = min_confirmations

def format_unspents(unspents):

    # sandowhich confirmed and unconfiremd unspents
    all_unspents = unspents.get('txrefs', []) + unspents.get('unconfirmed_txrefs', [])

    return [{
        "transaction_hash": s["tx_hash"],
        "outpoint": {
            'hash': s['tx_hash'],
            'index': s["tx_output_n"],
        },
        "value": s["value"],
        "out_script": s.get("script"),
        "confirmations": s["confirmations"],
        }
        for s in all_unspents
    ]


def get_unspents(address, blockchain_client=BlockcypherClient()):
    """ Get the spendable transaction outputs, also known as UTXOs or
        unspent transaction outputs.
    """
    if not isinstance(blockchain_client, BlockcypherClient):
        raise Exception('A BlockcypherClient object is required')

    url = '%s/addrs/%s?unspentOnly=true&includeScript=true' % (
          BLOCKCYPHER_BASE_URL, address)

    if blockchain_client.auth:
        r = requests.get(url + '&token=' + blockchain_client.auth[0], timeout=blockchain_client.timeout)
    else:
        r = requests.get(url, timeout=blockchain_client.timeout)

    try:
        unspents = r.json()
    except ValueError:
        raise Exception('Received non-JSON response from blockcypher.com.')

    # sandwich unconfirmed and confirmed unspents

    return format_unspents(unspents)


def broadcast_transaction(hex_tx, blockchain_client):
    """ Dispatch a raw hex transaction to the network.
    """
    if not isinstance(blockchain_client, BlockcypherClient):
        raise Exception('A BlockcypherClient object is required')

    url = '%s/txs/push' % (BLOCKCYPHER_BASE_URL)
    payload = json.dumps({'tx': hex_tx})
    r = requests.post(url, data=payload, timeout=blockchain_client.timeout)

    try:
        data = r.json()
    except ValueError:
        raise Exception('Received non-JSON from blockcypher.com.')

    if 'tx' in data:
        reply = {}
        reply['tx_hash'] = data['tx']['hash']
        reply['success'] = True
        return reply
    else:
        err_str = 'Tx hash missing from blockcypher response: ' + str(data)
        raise Exception(err_str)
