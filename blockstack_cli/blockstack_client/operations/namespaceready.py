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
from pybitcoin import embed_data_in_blockchain, BlockchainInfoClient, hex_hash160, \
        make_op_return_tx, serialize_transaction, broadcast_transaction, make_op_return_outputs, \
        get_unspents

from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40, is_b40
from ..config import *
from ..scripts import *

import virtualchain
log = virtualchain.get_logger("blockstack-client")


def build( namespace_id):
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
   hex_script = blockstack_script_to_hex(readable_script)
   packaged_script = add_magic_bytes(hex_script)
   
   return packaged_script


def make_transaction( namespace_id, payment_addr, blockchain_client, tx_fee=0 ):
   """
   Make the namespace ready transaction
   Raise ValueError if there are not enough inputs to make the transaction
   """
   namespace_id = str(namespace_id)
   payment_addr = str(payment_addr)
   tx_fee = int(tx_fee)

   assert is_namespace_valid( namespace_id )

   nulldata = build( namespace_id )
   
   # get inputs and from public key
   inputs = get_unspents( payment_addr, blockchain_client )
   
   # OP_RETURN outputs 
   outputs = make_op_return_outputs( nulldata, inputs, payment_addr, fee=(DEFAULT_OP_RETURN_FEE + tx_fee), format='hex' )
  
   return (inputs, outputs)



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
    Blockstack currently does not allow 
    the subsidization of namespaces.
    """
    return (None, None)

