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

import requests

BLOCKCHAIN_API_BASE_URL = "https://blockchain.info"

from .blockchain_client import BlockchainClient
from binascii import hexlify
import virtualchain

class BlockchainInfoClient(BlockchainClient):
    def __init__(self, api_key=None, timeout=30, min_confirmations=None):
        self.type = 'blockchain.info'
        self.timeout = timeout
        if api_key:
            self.auth = (api_key, '')
        else:
            self.auth = None

        self.min_confirmations = min_confirmations

def reverse_hash(hash, hex_format=True):
    """ hash is in hex or binary format
    """
    if not hex_format:
        hash = hexlify(hash)
    return "".join(reversed([hash[i:i+2] for i in range(0, len(hash), 2)]))


def format_unspents(unspents):
    return [{
        "transaction_hash": reverse_hash(s["tx_hash"]),
        "outpoint": {
            'hash': reverse_hash(s['tx_hash']),
            'index': s["tx_output_n"],
        },
        "value": s["value"],
        "out_script": s["script"],
        "confirmations": s["confirmations"]
        }
        for s in unspents
    ]

def get_unspents(address, blockchain_client=BlockchainInfoClient()):
    """ Get the spendable transaction outputs, also known as UTXOs or
        unspent transaction outputs.
    """
    if not isinstance(blockchain_client, BlockchainInfoClient):
        raise Exception('A BlockchainInfoClient object is required')

    url = BLOCKCHAIN_API_BASE_URL + "/unspent?format=json&active=" + address

    auth = blockchain_client.auth
    if auth and len(auth) == 2 and isinstance(auth[0], str):
        url = url + "&api_code=" + auth[0]

    r = requests.get(url, auth=auth, timeout=blockchain_client.timeout)
    try:
        unspents = r.json()["unspent_outputs"]
    except ValueError, e:
        raise Exception('Invalid response from blockchain.info.')
    
    return format_unspents(unspents)


def broadcast_transaction(hex_tx, blockchain_client=BlockchainInfoClient()):
    """ Dispatch a raw transaction to the network.
    """
    url = BLOCKCHAIN_API_BASE_URL + '/pushtx'
    payload = {'tx': hex_tx}
    r = requests.post(url, data=payload, auth=blockchain_client.auth, timeout=blockchain_client.timeout)
    
    if 'submitted' in r.text.lower():
        return {'success': True, 'tx_hash': virtualchain.btc_tx_get_hash(hex_tx)}
    else:
        raise Exception('Invalid response from blockchain.info.')


