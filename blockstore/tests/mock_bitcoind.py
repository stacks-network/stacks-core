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

import argparse
import logging
import os
import os.path
import sys
import subprocess
import signal
import json
import datetime
import traceback
import httplib
import ssl
import threading
import time
import socket
import hashlib 
import binascii
from decimal import *

from utilitybelt import is_valid_int
from ConfigParser import SafeConfigParser

import pybitcoin
import pybitcoin.transactions.opcodes as opcodes

# hack around absolute paths 
current_dir =  os.path.abspath(os.path.dirname(__file__) + "../..")
sys.path.insert(0, current_dir)

import blockstore
from blockstore.lib import *
import virtualchain

# global singleton
mock_bitcoind = None

# global opcode table 
opcode_table = {}

class MockBitcoindConnection( object ):
    """
    Mock bitcoind connection.
    Holds a small set of transactions in-RAM, but 
    otherwise implements just enough of the bitcoind 
    API for virtualchain to use it for testing.
    """

    def __init__(self, tx_path=None, tx_list=None, tx_grouping=1, start_block=0, start_time=0x11111111, difficulty=1.0, initial_utxos={}, **kw ):
        """
        Create a mock bitcoind connection, either from a 
        list of serialized transactions on-file, or a given Python
        list of serialized transactions.

        Transactions will be bundled into blocks in groups of size tx_grouping.
        """

        self.block_hashes = {}    # map block ID to block hash 
        self.blocks = {}        # map block hash to block info (including transaction IDs)
        self.txs = {}       # map tx hash to a list of transactions
        self.next_block_txs = []    # next block's transactions

        self.difficulty = difficulty 
        self.time = start_time 
        self.start_block = start_block 
        self.end_block = start_block
        
        self.block_hashes[ start_block - 1 ] = '00' * 32
        self.blocks[ '00' * 32 ] = {}
        
        # the initial utxos might be a serialized CSV (i.e. loaded directly from the config file).
        # if so, then parse it 
        if type(initial_utxos) in [str, unicode]:
            tmp = {}
            parts = initial_utxos.split(",")
            for utxo in parts:
                privkey, value = utxo.split(':')
                tmp[ privkey ] = int(value)

            initial_utxos = tmp
            
        tx_recs = []
        if tx_path is not None:
            with open( tx_path, "r" ) as f:
                tmp = f.readlines()
                tx_recs = [l.strip() for l in tmp]

        elif tx_list is not None:
            tx_recs = tx_list 

        # prepend utxos
        if len(initial_utxos) > 0:
            initial_outputs = []
            for (privkey, value) in initial_utxos.items():
                
                addr = pybitcoin.BitcoinPrivateKey( privkey ).public_key().address()
                out = {
                    'value': value,
                    'script_hex': pybitcoin.make_pay_to_address_script( addr )
                }
                initial_outputs.append( out )

            tx = {
                'inputs': [],
                'outputs': initial_outputs,
                'locktime': 0,
                'version': 0xff
            }
            
            tx_hex = tx_serialize( tx['inputs'], tx['outputs'], tx['locktime'], tx['version'] )
            tx_recs = [tx_hex] + tx_recs
       
        i = 0 
        while True:
            
            txs = []
            count = 0
            while i < len(tx_recs) and count < tx_grouping:
                txs.append( tx_recs[i] )
                i += 1

            if len(txs) > 0:
                for tx in txs:
                    self.sendrawtransaction( tx )
                self.flush_transactions()
            
            if i >= len(tx_recs):
                break


    def getinfo( self ):
        """
        Mock getinfo
        """

        return {"errors": "Mock bitcoind",
                "blocks": len(self.blocks)}

    def getblockhash( self, block_id ):
        """
        Get the block hash, given the ID
        """

        return self.block_hashes.get( block_id, None)
        

    def getblock( self, block_hash ):
        """
        Given the block hash, get the list of transactions
        """
        
        blockinfo = self.blocks.get( block_hash, None )
        if blockinfo is None:
            return blockinfo 

        # fill in missing data 
        blockinfo['confirmations'] = self.end_block - blockinfo['height']
        return blockinfo

    
    def getblockcount( self ):
        """
        Get the number of blocks processed
        """
        return self.end_block - 1


    def getstartblock( self ):
        """
        TESTING ONLY
        
        Get the first mock block that has actual data.
        """
        return self.start_block


    def getrawtransaction( self, txid, verbose ):
        """
        Given the transaction ID, get the raw transaction
        """

        raw_tx = self.txs.get( txid, None )
        if raw_tx is None:
            return None

        if not verbose:
            return raw_tx

        # parse like how bitcoind would have
        """
        btcd = virtualchain.create_bitcoind_connection( "openname", "opennamesystem", "btcd.onename.com", 8332, True )
        ret = btcd.decoderawtransaction( raw_tx )
        """
        ret = btc_decoderawtransaction_compat( raw_tx )

        return ret


    def getrawtransactions( self, verbose ):
        """
        TESTING ONLY 
        
        Get all transactions 
        """
        txs = []
        for i in xrange(self.start_block, self.end_block ):
            block_hash = self.block_hashes[ i ]
            block = self.blocks[ block_hash ]
            txids = block['tx']
            for txid in txids:
                tx = self.getrawtransaction( txid, verbose )
                txs.append( tx )

        return txs


    def sendrawtransaction( self, tx_hex ):
        """
        Send a raw transaction.
        Buffer it up until flush_transactions().

        TODO: we don't check for transaction validity here...
        """

        inputs, outputs, locktime, version = tx_deserialize( tx_hex )
        self.next_block_txs.append( tx_hex )

    
    def decoderawtransaction( self, tx_hex ):
        """
        Decode a raw transaction, as bitcoind would.
        """
        return btc_decoderawtransaction_compat( tx_hex )


    def get_num_pending_transactions( self ):
        """
        TESTING ONLY 

        Get the number of unflushed transactions
        """
        return len( self.next_block_txs )


    def flush_transactions( self ):
        """
        TESTING ONLY

        Send the bufferred list of transactions as a block.
        """
        
        # next block
        txs = self.next_block_txs
        self.next_block_txs = []

        # add a fake coinbase 
        txs.append( "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff53038349040d00456c69676975730052d8f72ffabe6d6dd991088decd13e658bbecc0b2b4c87306f637828917838c02a5d95d0e1bdff9b0400000000000000002f73733331312f00906b570400000000e4050000ffffffff01bf208795000000001976a9145399c3093d31e4b0af4be1215d59b857b861ad5d88ac00000000" )

        block_txs = {}
        block_txids = []
        for tx in txs:
            txid = make_txid( tx )
            block_txids.append( txid )
            block_txs[ txid ] = tx

        version = '01000000'
        t_hex = "%08X" % self.time
        difficulty_hex = "%08X" % self.difficulty
        tx_merkle_tree = pybitcoin.MerkleTree( block_txs )
        tx_merkle_root = binascii.hexlify( tx_merkle_tree.root() )
        prev_block_hash = self.block_hashes[ self.end_block - 1 ]        

        block_header = version + prev_block_hash + tx_merkle_root + t_hex + difficulty_hex + '00000000'

        # NOTE: not accurate; just get *a* hash
        block_hash = make_txid( block_header )

        # update nextblockhash at least 
        self.blocks[prev_block_hash]['nextblockhash'] = block_hash 
        
        # next block
        block = {
            'merkleroot': tx_merkle_root,
            'nonce': 0,                 # mock
            'previousblockhash': prev_block_hash,
            'hash': block_hash,
            'version': 3,
            'tx': block_txids,
            'chainwork': '00' * 32,     # mock
            'height': self.end_block,
            'difficulty': Decimal(0.0), # mock
            'nextblockhash': None,      # to be filled in
            'confirmations': None,      # to be filled in 
            'time': self.time,          # mock
            'bits': 0x00000000,         # mock
            'size': sum( [len(tx) for tx in txs] ) + len(block_hash)    # mock
        }
        
        self.block_hashes[ self.end_block ] = block_hash
        self.blocks[ block_hash ] = block
        self.txs.update( block_txs )

        self.time += 600    # 10 minutes
        self.difficulty += 1
        self.end_block += 1

        return [ make_txid( tx ) for tx in txs ]



def connect_mock_bitcoind( mock_opts, reset=False ):
    """
    Mock connection factory for bitcoind
    """

    global mock_bitcoind

    if reset:
        mock_bitcoind = None 

    if mock_bitcoind is not None:
        return mock_bitcoind 

    else:
        mock_bitcoind = MockBitcoindConnection( **mock_opts )
        return mock_bitcoind


def get_mock_bitcoind():
    """
    Get the global singleton mock bitcoind
    """
    global mock_bitcoind
    return mock_bitcoind
    

def make_txid( tx_hex ):
    """
    Create a transaction ID from a serialized transaction.
    """

    sha256 = hashlib.sha256()
    sha256.update( binascii.unhexlify(tx_hex) )
    sha256_1 = sha256.digest()

    sha256 = hashlib.sha256()
    sha256.update( sha256_1 )
    sha256_2 = sha256.digest()

    txid = binascii.hexlify( "".join( list(reversed(sha256_2)) ) )

    return txid
        

def btc_decoderawtransaction_script_hex_to_asm( script_hex ):
    """
    Given a script in hex, decode it to assembler.
    """

    global opcode_table

    asm_bytes = binascii.unhexlify( script_hex )
    asm_vec = []

    if len(opcode_table) == 0:
        for attr in dir(opcodes):
            if attr.startswith("OP_"):
                # map op values to op names
                opcode_table[ getattr(opcodes, attr) ] = attr

    i = 0
    while i < len(asm_bytes):
        
        opcode = ord( asm_bytes[i] )

        if opcode not in opcode_table.keys():
            # first byte is length; remaining bytes are data
            length = ord( asm_bytes[i] )
            data = "".join( [("%02x" % ord(j)) for j in asm_bytes[i+1:i+1+length]] )

            i += length + 1

            asm_vec.append( data )

        else:
            
            asm_vec.append( opcode_table[opcode] )

            # special case: OP_RETURN 
            if opcode_table[opcode] == 'OP_RETURN':
                asm_vec.append( binascii.hexlify(asm_bytes[i+2:]) )
                i = len(asm_bytes)

            else:

                # next op
                i += 1

    return " ".join( asm_vec )


def btc_decoderawtransaction_get_pubkey_from_script( script ):
    """
    Given a pay-to-public-key script, get the public key.
    Returns a hex string on success.
    Returns None on error.
    """

    # format: [1-byte length] [pubkey] OP_CHECKSIG
    pubkey_len = int( script[0:1], 16 )
    if len(script[:-2]) == pubkey_len * 2 and script[-2:].lower() == 'ac':

        # the rest of the script is a public key
        bin_pubkey = binascii.unhexlify( script[2:2*pubkey_len] )
        try:
            pk = pybitcoin.BitcoinPublicKey( bin_pubkey )
            return pk.to_hex()

        except:
            return None 

    else:
        return None


def btc_decoderawtransaction_get_script_hash_from_script( script ):
    """
    Given a pay-to-script-hash script, get the script hash.
    Returns a hex string on success.
    Returns None on error.
    """

    # format: OP_HASH160 [hash len] [hash] OP_EQUAL
    hash_len = int( script[2:4], 16 )
    hash_hex = script[4:len(hash_len)*2]

    return hash_hex


def btc_decoderawtransaction_get_script_type( script ):
    """
    Given a hex script, deduce the type.
    """

    if len(script) == (25 * 2) and script[0:6].lower() == '76a914' and script[-4:].lower() == '88ac':
        # format: OP_DUP OP_HASH160 0x14 [20-byte hash] OP_EQUALVERIFY OP_CHECKSIG
        return "pubkeyhash"

    elif script[-2:].lower() == 'ac':

        # maybe a pay-to-pubkey...
        # format: [pubkey len] [pubkey] OP_CHECKSIG
        pk_hex = btc_decoderawtransaction_get_pubkey_from_script( script )
        if pk_hex is not None:
            return "pubkey"

    elif len(script) == (24 * 2) and script[0:2].lower() == 'a9' and script[-2:].lower() == '87':

        # maybe a pay-to-script-hash...
        # format: OP_HASH160 [hash len] [hash] OP_EQUAL
        return "scripthash"

    elif script[0:2].lower() == '6a':
        
        # format: OP_RETURN [data]
        return "nulldata"

    elif script[-2:].lower() == 'ae':

        # format (?): [instructions] OP_CHECKMULTISIG
        # TODO: not sure if this check is correct...
        return "multisig"

    return "nonstandard"


def btc_decoderawtransaction_compat( tx_hex ):
    """
    Implementation of bitcoind's decoderawtransaction
    JSONRPC method.  Tries to be faithful enough to
    bitcoind for virtualchain's sake.

    Does NOT handle coinbase transactions
    """

    inputs, outputs, locktime, version = tx_deserialize( tx_hex )
    txid = make_txid( tx_hex )

    vin = []
    vout = []

    for inp in inputs:
        vin_inp = {
            "txid": inp['transaction_hash'],
            "vout": inp['output_index'],
        }

        if inp.has_key("script_sig"):
            scriptsig_hex = inp['script_sig']
            scriptsig_asm = btc_decoderawtransaction_script_hex_to_asm( scriptsig_hex )

            vin_inp['scriptSig'] = {
                'asm': scriptsig_asm,
                'hex': scriptsig_hex
            }

        if inp.has_key("sequence"):

            vin_inp['sequence'] = inp['sequence']

        vin.append( vin_inp )

    for i in xrange( 0, len(outputs) ):

        out = outputs[i]
        script_type = btc_decoderawtransaction_get_script_type( out['script_hex'] )
        addresses = []

        if script_type == "pubkeyhash":
            addresses.append( pybitcoin.script_hex_to_address( out['script_hex'] ) )

        elif script_type == "pubkey":
            pubkey = btc_decoderawtransaction_get_pubkey_from_script( out['script_hex'] )
            addr = pybitcoin.BitcoinPublicKey( pubkey ).address()
            addresses.append( addr )

        elif script_type == "scripthash":
            script_hash = btc_decoderawtransaction_get_script_hash_from_script( out['script_hex'] ) 
            addr = pybitcoin.b58check_encode( binascii.unhexlify( script_hash ), version_byte=5 )
            addresses.append( addr )

        vout_out = {
            "value": float(out['value']) / 10e7,
            "mock_bitcoind_value_satoshi": out['value'],  # NOTE: extra
            "n": i,
            "scriptPubKey": {
                'asm': btc_decoderawtransaction_script_hex_to_asm( out['script_hex'] ),
                'hex': out['script_hex'],
                "type": script_type
            },
        }

        if script_type in ["pubkeyhash", "pubkey", "scripthash"]:
            vout_out['scriptPubKey']['reqSigs'] = 1

        if len(addresses) > 0:
            vout_out['scriptPubKey']['addresses'] = addresses

        vout.append( vout_out )

    tx_decoded = {
        "txid": txid,
        "version": version,
        "locktime": locktime,
        "vin": vin,
        "vout": vout
    }

    return tx_decoded


