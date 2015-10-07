#!/usr/bin/env python

""""
Mock UTXO provider.
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

mock_utxo_client = None

log = virtualchain.session.log

class MockUTXOProvider(object):

    def __init__(self, bitcoind ):
        
        self.unspents = {}  # map address to unspent outputs
        self.bitcoind = bitcoind

        # crawl blocks and build up utxo set 
        for i in xrange( bitcoind.getstartblock(), bitcoind.getblockcount() ):
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
        and forward the tx along to the mock bitcoind connection.'

        Return {"transaction_hash": txid}
        """

        # update the current unspent set.
        inputs, outputs, locktime, version = tx_deserialize( hex_tx )
        
        for i in xrange(0, len(outputs)):

            txid = self.bitcoind.make_txid( hex_tx )
            out = outputs[i]
            value = out['value']
            script_hex = out['script_hex']

            utxo = {
               "transaction_hash": txid,
               "value": value,
               "output_index": i,
               "script_hex": script_hex,
            }

            addr = pybitcoin.script_hex_to_address( script_hex )
            if not self.unspents.has_key( addr ):
                self.unspents[addr] = [utxo]
            else:
                self.unspents[addr].append( utxo )

        for inp in inputs:
            
            transaction_hash = inp['transaction_hash']
            output_index = inp['output_index']
            script_sig = inp.get('script_sig', None)

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

            ref_out = ref_outputs[output_index]
            ref_addr = pybitcoin.script_hex_to_address( ref_out['script_hex'] ) 

            # unspent output was consumed by this transaction
            if self.unspents.has_key( ref_addr):
                for utxo in self.unspents[ref_addr]:
                    if utxo['transaction_hash'] == transaction_hash:
                        self.unspents[ref_addr].remove( utxo )
                        break
        
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
        
