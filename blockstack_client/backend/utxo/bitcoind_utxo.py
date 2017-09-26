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

import httplib
from virtualchain import AuthServiceProxy, JSONRPCException
from .blockchain_client import BlockchainClient

from blockstack_client import constants
from decimal import Decimal

SATOSHIS_PER_COIN = 10**8


def create_bitcoind_service_proxy(
    rpc_username, rpc_password, server='127.0.0.1', port=8332, use_https=False):
    """ create a bitcoind service proxy
    """
    protocol = 'https' if use_https else 'http'
    uri = '%s://%s:%s@%s:%s' % (protocol, rpc_username, rpc_password,
        server, port)
    return AuthServiceProxy(uri)


class BitcoindClient(BlockchainClient):
    def __init__(self, rpc_username, rpc_password, use_https=False,
                 server='127.0.0.1', port=8332, version_byte=0, min_confirmations=None):
        self.type = 'bitcoind'
        self.auth = (rpc_username, rpc_password)
        self.bitcoind = create_bitcoind_service_proxy(rpc_username,
            rpc_password, use_https=use_https, server=server, port=port)
        self.version_byte = version_byte
        self.min_confirmations = min_confirmations

    def get_unspents(self, address):
        return get_unspents(address, self.bitcoind)

    def broadcast_transaction(self, hex_tx):
        return broadcast_transaction(hex_tx, self.bitcoind)

def format_unspents(unspents):
    return [{
        "transaction_hash": s["txid"],
        "outpoint": {
            'hash': s['txid'],
            'index': s["vout"],
        },
        "value": int(Decimal(s["amount"]*SATOSHIS_PER_COIN)),
        "out_script": s["scriptPubKey"],
        "confirmations": s["confirmations"]
        }
        for s in unspents
    ]


def get_unspents(address, blockchain_client):
    """ Get the spendable transaction outputs, also known as UTXOs or
        unspent transaction outputs.

        NOTE: this will only return unspents if the address provided is present
        in the bitcoind server. Use the chain, blockchain, or blockcypher API
        to grab the unspents for arbitrary addresses.
    """
    if isinstance(blockchain_client, BitcoindClient):
        bitcoind = blockchain_client.bitcoind
        version_byte = blockchain_client.version_byte
    elif isinstance(blockchain_client, AuthServiceProxy):
        bitcoind = blockchain_client
        version_byte = 0
    else:
        raise Exception('A BitcoindClient object is required')

    addresses = []
    addresses.append(str(address))
    min_confirmations = 0
    max_confirmation = 2000000000  # just a very large number for max
    unspents = bitcoind.listunspent(min_confirmations, max_confirmation,
                                    addresses)

    if constants.BLOCKSTACK_TESTNET and len(unspents) == 0:
        try:
            bitcoind.importaddress(str(address))
            unspents = bitcoind.listunspent(min_confirmations, max_confirmation,
                                            addresses)
        except Exception as e:
            return format_unspents([])
    return format_unspents(unspents)


def broadcast_transaction(hex_tx, blockchain_client):
    """ Dispatch a raw transaction to the network.
    """
    if isinstance(blockchain_client, BitcoindClient):
        bitcoind = blockchain_client.bitcoind
    elif isinstance(blockchain_client, AuthServiceProxy):
        bitcoind = blockchain_client
    else:
        raise Exception('A BitcoindClient object is required')

    try:
        resp = bitcoind.sendrawtransaction(hex_tx)
    except httplib.BadStatusLine:
        raise Exception('Invalid HTTP status code from bitcoind.')

    if len(resp) > 0:
        return {'tx_hash': resp, 'success': True}
    else:
        raise Exception('Invalid response from bitcoind.')
