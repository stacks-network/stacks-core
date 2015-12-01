#!/usr/bin/env python
"""
    Blockstore
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstore

    Blockstore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore. If not, see <http://www.gnu.org/licenses/>.
"""

import os
import sys

# hack around absolute paths 
current_dir =  os.path.abspath(os.path.dirname(__file__) + "/../..")
sys.path.insert(0, current_dir)

from blockstore.lib import *
import hashlib
import binascii

import mock_bitcoind

import virtualchain 

""""
Mock UTXO provider.
"""

mock_utxo_client = None

if not globals().has_key('log'):
    log = virtualchain.session.log

class MockUTXOProvider(object):

    def __init__(self, bitcoind ):
        
        self.unspents = {}  # map address to unspent outputs
        self.tx_addrs = {}  # map txid to list of addresses
        self.bitcoind = bitcoind

        # crawl blocks and build up utxo set 
        for i in xrange( bitcoind.getstartblock(), bitcoind.getblockcount()+1 ):
            block_hash = bitcoind.getblockhash( i )
            block = bitcoind.getblock( block_hash )
            txids = block['tx']
            txs = [bitcoind.getrawtransaction( txid, 0 ) for txid in txids]

            for tx in txs:
               # synchronize utxos
               self.broadcast_transaction( tx, utxos_only=True )


    def get_unspents( self, address ):
        """
        Get UTXOs for an address.
        Returns a list of transaction outputs.
        """
        return self.unspents.get(address, [])


    def broadcast_transaction( self, hex_tx, utxos_only=False ):
        """
        Broadcast a transaction.
        By this, we mean 'update our set of UTXOs using this tx,
        and optionally forward the tx along to the mock bitcoind
        connection.'

        NOTE: assumes that the tx outputs use *only* pay-to-pubkey-hash scripts.

        Return {"transaction_hash": txid}
        """

        # update the current unspent set.
        inputs, outputs, locktime, version = tx_deserialize( hex_tx )
        txid = mock_bitcoind.make_txid( hex_tx )

        for i in xrange(0, len(outputs)):

            out = outputs[i]
            value = out['value']
            script_hex = out['script_hex']

            if value < DEFAULT_DUST_FEE and script_hex[0:2].lower() != '6a':
                # non-OP_RETURN insufficent fee
                raise Exception("Value of %s[vout][%s] is %s" % (txid, i, value))

            utxo = {
               "transaction_hash": txid,
               "value": value,
               "output_index": i,
               "script_hex": script_hex,
            }

            # NOTE: assumes p2pkh
            addr = pybitcoin.script_hex_to_address( script_hex )
            if not self.unspents.has_key( addr ):
                self.unspents[addr] = [utxo]
            else:
                self.unspents[addr].append( utxo )

        for inp in inputs:
            
            transaction_hash = inp['transaction_hash']
            output_index = inp['output_index']

            # NOTE: we don't check the signature; just verify that it's there
            script_sig = inp.get('script_sig', None)
            if script_sig is None or len(script_sig) == 0:
                raise Exception("Unsigned input for output %s in tx %s" % (output_index, transaction_hash))

            if transaction_hash == '00' * 32:
                # coinbase transaction.  ignore.
                continue

            # debit unspent outputs
            ref_tx_hex = self.bitcoind.getrawtransaction(transaction_hash, 0)
            if ref_tx_hex is None:
                raise Exception("Unknown transaction '%s'" % transaction_hash)

            ref_inputs, ref_outputs, ref_locktime, ref_version = tx_deserialize( ref_tx_hex )
            if output_index >= len(ref_outputs):
                raise Exception("Invalid output index (%s) for %s-length inputs" % (output_index, len(ref_outputs)))

            # NOTE: assumes p2pkh
            ref_out = ref_outputs[output_index]
            ref_addr = pybitcoin.script_hex_to_address( ref_out['script_hex'] ) 

            # unspent output was consumed by this transaction
            if self.unspents.has_key( ref_addr ):
                for utxo in self.unspents[ref_addr]:
                    if utxo['transaction_hash'] == transaction_hash:
                        self.unspents[ref_addr].remove( utxo )


        if not utxos_only:
            self.bitcoind.sendrawtransaction( hex_tx )

        resp = {
            'transaction_hash': txid
        }
        return resp


def get_unspents(address, blockchain_client):
    """
    Get the unspent outputs for an address.
    """
    return blockchain_client.get_unspents( address )


def broadcast_transaction(hex_tx, blockchain_client):
    """
    Broadcast a transaction to the mock utxo provider.
    """
    return blockchain_client.broadcast_transaction( hex_tx )


def connect_mock_utxo_provider( utxo_opts ):
    """
    Create a 'connection' to the mock UTXO provider.
    """
    global mock_utxo_client

    if mock_utxo_client is not None:
        return mock_utxo_client 

    else:
        mock_bitcoind_client = mock_bitcoind.connect_mock_bitcoind( utxo_opts ) 
        return MockUTXOProvider( mock_bitcoind_client )
        
