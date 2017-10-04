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

import keylib

from ..b40 import is_b40
from ..logger import get_logger
from ..constants import (
   DEFAULT_DUST_FEE, DEFAULT_OP_RETURN_FEE,
   BLOCKSTACK_BURN_ADDRESS, LENGTH_MAX_NAMESPACE_ID,
   LENGTH_CONSENSUS_HASH)
from ..scripts import (
   hash256_trunc128,
   hash_name,
   blockstack_script_to_hex,
   add_magic_bytes,
   is_namespace_valid,
   tx_get_unspents,
   hash256_trunc128
)

import virtualchain
log = get_logger("blockstack-client")


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
    
    bill = op_fee
   
    if not pay_fee:
        # subsidized
        dust_fee = 0
        op_fee = 0
        bill = 0
    
    return [
        # main output
        {"script": virtualchain.make_data_script(str(data)),
         "value": 0},
        
        # change address
        {"script": virtualchain.make_payment_script( change_addr ),
         "value": virtualchain.calculate_change_amount(inputs, bill, dust_fee)},
        
        # burn address
        {"script": virtualchain.make_payment_script(BLOCKSTACK_BURN_ADDRESS),
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
    Get (dust fee, op fee) for namespace preorder.
    op fee is the namespace cost (burnt)
    dust fee is the total cost that our outputs must sum to
    """
    if len(outputs) != 3:
        log.debug("Expected 3 outputs; got %s" % len(outputs))
        return (None, None)
    
    # 0: op_return
    if not virtualchain.tx_output_has_data( outputs[0] ):
        log.debug("outputs[0] is not an OP_RETURN")
        return (None, None) 
    
    if outputs[0]["value"] != 0:
        log.debug("outputs[0] has value %s'" % outputs[0]["value"])
        return (None, None) 
    
    # 1: change address 
    if virtualchain.script_hex_to_address( outputs[1]["script"] ) is None:
        log.error("outputs[1] has no decipherable change address")
        return (None, None)
    
    # 2: burn address 
    addr_hash = virtualchain.script_hex_to_address( outputs[2]["script"] )
    if addr_hash is None:
        log.error("outputs[2] has no decipherable burn address")
        return (None, None) 
    
    if addr_hash != BLOCKSTACK_BURN_ADDRESS:
        log.error("outputs[2] is not the burn address (%s)" % BLOCKSTACK_BURN_ADDRESS)
        return (None, None)
   
    # should match make_outputs()
    dust_fee = (len(inputs) + 2) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
    op_fee = outputs[2]["value"]
    
    return (dust_fee, op_fee)


def snv_consensus_extras( name_rec, block_id, blockchain_name_data ):
    """
    Calculate any derived missing data that goes into the check() operation,
    given the block number, the name record at the block number, and the db.
    """
    return {}

