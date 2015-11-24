#!/usr/bin/env python
# -*- coding: utf-8 -*-
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

from pybitcoin import embed_data_in_blockchain, serialize_transaction, \
    analyze_private_key, serialize_sign_and_broadcast, make_op_return_script, \
    make_pay_to_address_script, b58check_encode, b58check_decode, BlockchainInfoClient, hex_hash160

from pybitcoin.transactions.outputs import calculate_change_amount

from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40, is_b40
from ..config import *
from ..scripts import *
from ..hashing import hash_name

# consensus hash fields (ORDER MATTERS!) 
FIELDS = [
    'namespace_id_hash',    # hash(namespace_id,sender,reveal_addr)
    'consensus_hash',       # consensus hash at the time issued
    'op',                   # bytecode describing the operation (not necessarily 1 byte)
    'op_fee',               # fee paid for the namespace to the burn address
    'txid',                 # transaction ID
    'vtxindex',             # the index in the block where the tx occurs
    'block_number',         # block number at which this transaction occurred
    'sender',               # scriptPubKey hex from the principal that issued this preorder (identifies the preorderer)
    'sender_pubkey',        # if sender is a p2pkh script, this is the public key
    'address'               # address from the scriptPubKey
]

def build( namespace_id, script_pubkey, register_addr, consensus_hash, namespace_id_hash=None, testset=False ):
   """
   Preorder a namespace with the given consensus hash.  This records that someone has begun to create 
   a namespace, while blinding all other peers to its ID.  This operation additionally records the 
   consensus hash in order to ensure that all peers will recognize that this sender has begun the creation.
   
   Takes an ASCII-encoded namespace ID.
   NOTE: "namespace_id" must not start with ., but can contain anything else we want
   
   We put the hash of the namespace ID instead of the namespace ID itself to avoid races with squatters (akin to pre-ordering)
   
   Format:
   
   0     2   3                                      23               39
   |-----|---|--------------------------------------|----------------|
   magic op  hash(ns_id,script_pubkey,reveal_addr)   consensus hash
   """
   
   # sanity check 
   if namespace_id_hash is None:

       # expect inputs to the hash...
       if not is_b40( namespace_id ) or "+" in namespace_id or namespace_id.count(".") > 0:
          raise Exception("Namespace identifier '%s' has non-base-38 characters" % namespace_id)
       
       if len(namespace_id) == 0 or len(namespace_id) > LENGTHS['blockchain_id_namespace_id']:
          raise Exception("Invalid namespace ID length '%s (expected length between 1 and %s)" % (namespace_id, LENGTHS['blockchain_id_namespace_id']))
   
       namespace_id_hash = hash_name(namespace_id, script_pubkey, register_addr=register_addr)
   
   readable_script = "NAMESPACE_PREORDER 0x%s 0x%s" % (namespace_id_hash, consensus_hash)
   hex_script = blockstore_script_to_hex(readable_script)
   packaged_script = add_magic_bytes(hex_script, testset=testset)
   
   return packaged_script


def make_outputs( data, inputs, change_addr, fee, pay_fee=True, format='bin' ):
    """
    Make outputs for a namespace preorder:
    [0] OP_RETURN with the name 
    [1] change address with the NAME_PREORDER sender's address
    [2] pay-to-address with the *burn address* with the fee
    """
    
    dust_fee = DEFAULT_OP_RETURN_FEE + (len(inputs) + 2) * DEFAULT_DUST_FEE
    op_fee = max(fee, DEFAULT_DUST_FEE)
    dust_value = DEFAULT_DUST_FEE
    
    bill = op_fee
   
    if not pay_fee:
        # subsidized
        dust_fee = 0
        op_fee = 0
        dust_value = 0
        bill = 0
    
    return [
        # main output
        {"script_hex": make_op_return_script(data, format=format),
         "value": 0},
        
        # change address
        {"script_hex": make_pay_to_address_script(change_addr),
         "value": calculate_change_amount(inputs, bill, dust_fee)},
        
        # burn address
        {"script_hex": make_pay_to_address_script(BLOCKSTORE_BURN_ADDRESS),
         "value": op_fee}
    ]
    

def broadcast( namespace_id, register_addr, consensus_hash, private_key, blockchain_client, fee, pay_fee=True, tx_only=False, testset=False, blockchain_broadcaster=None ):
   """
   Propagate a namespace.
   
   Arguments:
   namespace_id         human-readable (i.e. base-40) name of the namespace
   register_addr        the addr of the key that will reveal the namespace (mixed into the preorder to prevent name preimage attack races)
   private_key          the Bitcoin address that created this namespace, and can populate it.
   """
  
   if blockchain_broadcaster is None:
       blockchain_broadcaster = blockchain_client 
   
   pubkey_hex = BitcoinPrivateKey( private_key ).public_key().to_hex()
   
   script_pubkey = get_script_pubkey( pubkey_hex )
   nulldata = build( namespace_id, script_pubkey, register_addr, consensus_hash, testset=testset )
   
   # get inputs and from address
   private_key_obj, from_address, inputs = analyze_private_key(private_key, blockchain_client)
    
   # build custom outputs here
   outputs = make_outputs(nulldata, inputs, from_address, fee, format='hex')
    
   if tx_only:
       
        unsigned_tx = serialize_transaction( inputs, outputs )
        return {"unsigned_tx": unsigned_tx}
       
   else:
        # serialize, sign, and broadcast the tx
        response = serialize_sign_and_broadcast(inputs, outputs, private_key_obj, blockchain_broadcaster)
            
        # response = {'success': True }
        response.update({'data': nulldata})
            
        return response
   

def parse( bin_payload ):
   """
   NOTE: the first three bytes will be missing
   """
   
   if len(bin_payload) != LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash']:
       log.error("Invalid namespace preorder payload length %s" % len(bin_payload))
       return None

   namespace_id_hash = bin_payload[ :LENGTHS['preorder_name_hash'] ]
   consensus_hash = bin_payload[ LENGTHS['preorder_name_hash']: LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash'] ]
   
   namespace_id_hash = hexlify( namespace_id_hash )
   consensus_hash = hexlify( consensus_hash )

   
   return {
      'opcode': 'NAMESPACE_PREORDER',
      'namespace_id_hash': namespace_id_hash,
      'consensus_hash': consensus_hash
   }


def get_fees( inputs, outputs ):
    """
    Blockstore currently does not allow 
    the subsidization of namespaces.
    """
    return (None, None)

