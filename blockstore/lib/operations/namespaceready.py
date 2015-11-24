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

from pybitcoin import embed_data_in_blockchain, BlockchainInfoClient, hex_hash160, make_op_return_tx, serialize_transaction, broadcast_transaction, make_op_return_outputs
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40, is_b40
from ..config import *
from ..scripts import *

import virtualchain

if not globals().has_key('log'):
    log = virtualchain.session.log

from namespacereveal import FIELDS as NAMESPACE_REVEAL_FIELDS

# consensus hash fields (ORDER MATTERS!) 
FIELDS = NAMESPACE_REVEAL_FIELDS + [
    'ready_block',      # block number at which the namespace was readied
]

def build( namespace_id, testset=False ):
   """
   Record to mark the end of a namespace import in the blockchain.
   
   Takes an base40-encoded namespace ID to mark the end.
   
   Format:
   
   0     2  3  4           23
   |-----|--|--|------------|
   magic op  .  ns_id
   """
   
   # sanity check 
   if not is_b40( namespace_id ) or "+" in namespace_id or namespace_id.count(".") > 0:
      raise Exception("Namespace ID '%s' has non-base-38 characters" % namespace_id)
   
   if len(namespace_id) == 0 or len(namespace_id) > LENGTHS['blockchain_id_namespace_id']:
      raise Exception("Invalid namespace ID '%s (expected length between 1 and %s)" % (namespace_id, LENGTHS['blockchain_id_namespace_id']))
   
   readable_script = "NAMESPACE_READY 0x%s" % (hexlify("." + namespace_id))
   hex_script = blockstore_script_to_hex(readable_script)
   packaged_script = add_magic_bytes(hex_script, testset=testset)
   
   return packaged_script


def broadcast( namespace_id, private_key, blockchain_client, testset=False, tx_only=False, blockchain_broadcaster=None ):
   
   if blockchain_broadcaster is None:
       blockchain_broadcaster = blockchain_client 
    
   nulldata = build( namespace_id, testset=testset )
   
   # get inputs and from address
   private_key_obj, from_address, inputs = analyze_private_key(private_key, blockchain_client)
   
   # OP_RETURN outputs 
   outputs = make_op_return_outputs( nulldata, inputs, from_address, fee=DEFAULT_OP_RETURN_FEE, format='hex' )
   
   if tx_only:
       
       unsigned_tx = serialize_transaction( inputs, outputs )
       return {'unsigned_tx': signed_tx}

   else:
       
       signed_tx = tx_serialize_and_sign( inputs, outputs, private_key_obj )
       response = broadcast_transaction( signed_tx, blockchain_broadcaster )
       response.update({'data': nulldata})
       return response


def parse( bin_payload ):
   """
   NOTE: the first three bytes will be missing
   NOTE: the first byte in bin_payload is a '.'
   """
   
   if bin_payload[0] != '.':
       log.error("Missing namespace delimiter .")
       return None 

   namespace_id = bin_payload[ 1: ]
   
   # sanity check
   if not is_b40( namespace_id ) or "+" in namespace_id or namespace_id.count(".") > 0:
       log.error("Invalid namespace ID '%s'" % namespace_id)
       return None

   if len(namespace_id) <= 0 or len(namespace_id) > LENGTHS['blockchain_id_namespace_id']:
       log.error("Invalid namespace of length %s" % len(namespace_id))
       return None 

   return {
      'opcode': 'NAMESPACE_READY',
      'namespace_id': namespace_id
   }


def get_fees( inputs, outputs ):
    """
    Blockstore currently does not allow 
    the subsidization of namespaces.
    """
    return (None, None)

