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

import sys
import requests
import json
import traceback
from ...logger import get_logger

log = get_logger("insight-api")

class InsightClient(object):
    def __init__(self, url, min_confirmations=None):
        assert url
        self.url = url
        self.min_confirmations = min_confirmations

    def get_unspents(self, address):
        url = self.url + '/insight-api/addr/{}/utxo'.format(address)
        resp = None
        log.debug("GET {}".format(url))
        try:
            req = requests.get(url)
            resp = req.json()
        except Exception as e:
            log.error("Failed to query UTXos")
            raise

        # format...
        try:
            unspents = format_unspents(resp)
            log.debug("{} has {} UTXOs".format(address, len(unspents)))
            return unspents
        except Exception as e:
            traceback.print_exc()
            raise ValueError("Invalid UTXO response")


    def broadcast_transaction(self, rawtx):
        url = self.url + '/insight-api/tx/send'
        req = None

        data = json.dumps({'rawtx': rawtx})
        headers = {'content-type': 'application/json', 'accept': 'application/json'}

        req = None
        resp = None

        log.debug("POST {}".format(url))

        try:
            req = requests.post(url, data=data, headers=headers)
        except Exception as e:
            log.error("Failed to send transaction")
            raise

        try:
            resp = req.json()
            return {'success': True, 'tx_hash': resp['txid']}
        except:
            raise Exception("Failed to broadcast transaction, got response: {}".format(req.text))


def format_unspents(unspents):
    return [{
        'transaction_hash': s['txid'],
        'outpoint': {
            'hash': s['txid'],
            'index': s['vout'],
        },
        'value': s['satoshis'],
        'out_script': s['scriptPubKey'],
        'confirmations': s['confirmations']
    } for s in unspents]


def _get_unspents( address, client=None ):
    """
    Get unspent outputs from an Insight API endpoint
    """

    if not isinstance(client, InsightClient):
        raise Exception("Not a Blockstack Explorer client")

    unspents = client.get_unspents( address )
    return unspents


def _broadcast_transaction( txdata, client=None ):
    """
    Send a transaction through an Insight API endpoint
    """

    if not isinstance(client, InsightClient):
        raise Exception("Not a Blockstack Explorer client")

    res = client.broadcast_transaction( txdata )
    return res


if __name__ == '__main__':
    import sys
    op = sys.argv[1]
    arg = sys.argv[2]

    if op == 'get_unspents':
        res = _get_unspents(arg)
        print json.dumps(res, indent=4, sort_keys=True)
        sys.exit(0)

    elif op == 'broadcast_transaction':
        res = _broadcast_transaction(arg)
        print json.dumps(res, indent=4, sort_keys=True)
        sys.exit(0)

    else:
        raise Exception("invalid argument")

