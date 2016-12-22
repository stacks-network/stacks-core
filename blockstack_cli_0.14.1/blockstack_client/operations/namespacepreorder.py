#!/usr/bin/env python
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

import pybitcoin
from pybitcoin import embed_data_in_blockchain, serialize_transaction, \
    serialize_sign_and_broadcast, make_op_return_script, \
    make_pay_to_address_script, hex_hash160

from pybitcoin.transactions.outputs import calculate_change_amount

from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40, is_b40
from ..config import *
from ..scripts import *

import virtualchain
log = virtualchain.get_logger("blockstack-client")


def build( namespace_id, script_pubkey, register_addr, consensus_hash, namespace_id_hash=None):
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
       
       if len(namespace_id) == 0 or len(namespace_id) > LENGTH_MAX_NAMESPACE_ID:
          raise Exception("Invalid namespace ID length '%s (expected length between 1 and %s)" % (namespace_id, LENGTH_MAX_NAMESPACE_ID))
  
       # NOTE: dup of the above checks
       if not is_namespace_valid(namespace_id):
          raise Exception("Invalid namespace ID")

       namespace_id_hash = hash_name(namespace_id, script_pubkey, register_addr=register_addr)
   
   readable_script = "NAMESPACE_PREORDER 0x%s 0x%s" % (namespace_id_hash, consensus_hash)
   hex_script = blockstack_script_to_hex(readable_script)
   packaged_script = add_magic_bytes(hex_script)
   
   return packaged_script


def make_outputs( data, inputs, change_addr, fee, tx_fee, pay_fee=True ):
    """
    Make outputs for a namespace preorder:
    [0] OP_RETURN with the name 
    [1] change address with the NAME_PREORDER sender's address
    [2] pay-to-address with the *burn address* with the fee
    Raise ValueError if there are not enough inputs to make the transaction
    """
    
    dust_fee = DEFAULT_OP_RETURN_FEE + (len(inputs) + 2) * DEFAULT_DUST_FEE + tx_fee
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
        {"script_hex": make_op_return_script(str(data), format='hex'),
         "value": 0},
        
        # change address
        {"script_hex": virtualchain.make_payment_script( change_addr ),
         "value": calculate_change_amount(inputs, bill, dust_fee)},
        
        # burn address
        {"script_hex": virtualchain.make_payment_script(BLOCKSTACK_BURN_ADDRESS),
         "value": op_fee}
    ]
    

def make_transaction( namespace_id, register_addr, fee, consensus_hash, preorder_addr, blockchain_client, tx_fee=0, safety=True ):
   """
   Propagate a namespace.
   
   Arguments:
   namespace_id         human-readable (i.e. base-40) name of the namespace
   register_addr        the addr of the key that will reveal the namespace (mixed into the preorder to prevent name preimage attack races).  Must be a p2pkh address
   private_key          the Bitcoin address that created this namespace, and can populate it.
   """

   namespace_id = str(namespace_id)
   register_addr = str(register_addr)
   fee = int(fee)
   consensus_hash = str(consensus_hash)
   preorder_addr = str(preorder_addr)
   tx_fee = int(tx_fee)

   assert is_namespace_valid(namespace_id)
   assert len(consensus_hash) == LENGTH_CONSENSUS_HASH * 2
   assert pybitcoin.b58check_version_byte( preorder_addr ) == virtualchain.version_byte, "Only p2pkh reveal addresses are supported"

   script_pubkey = virtualchain.make_payment_script( preorder_addr )
   nulldata = build( namespace_id, script_pubkey, register_addr, consensus_hash )
   
   # get inputs and from address
   inputs = tx_get_unspents( preorder_addr, blockchain_client )
   if safety:
       assert len(inputs) > 0

   # build custom outputs here
   outputs = make_outputs(nulldata, inputs, preorder_addr, fee, tx_fee )
   
   return (inputs, outputs)


def get_fees( inputs, outputs ):
    """
    Blockstack currently does not allow 
    the subsidization of namespaces.
    """
    return (None, None)


def snv_consensus_extras( name_rec, block_id, blockchain_name_data ):
    """
    Calculate any derived missing data that goes into the check() operation,
    given the block number, the name record at the block number, and the db.
    """
    return {}

