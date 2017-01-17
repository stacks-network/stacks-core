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
from pybitcoin import embed_data_in_blockchain, hex_hash160, \
        make_op_return_tx, serialize_transaction, broadcast_transaction, make_op_return_script

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
   
   if len(namespace_id) == 0 or len(namespace_id) > LENGTH_MAX_NAMESPACE_ID:
      raise Exception("Invalid namespace ID '%s (expected length between 1 and %s)" % (namespace_id, LENGTH_MAX_NAMESPACE_ID))
   
   readable_script = "NAMESPACE_READY 0x%s" % (hexlify("." + namespace_id))
   hex_script = blockstack_script_to_hex(readable_script)
   packaged_script = add_magic_bytes(hex_script)
   
   return packaged_script


def make_outputs( nulldata, inputs, change_addr, fee=0, format='bin' ):
   """
   Make namespace-ready outputs
   """
   return [
        { "script_hex": make_op_return_script(nulldata, format=format),
          "value": 0
        },
        # change output
        { "script_hex": virtualchain.make_payment_script(change_addr),
          "value": calculate_change_amount(inputs, 0, fee)
        }
    ]


def make_transaction( namespace_id, reveal_addr, blockchain_client, tx_fee=0, safety=True ):
   """
   Make the namespace ready transaction
   Raise ValueError if there are not enough inputs to make the transaction
   """
   namespace_id = str(namespace_id)
   reveal_addr = str(reveal_addr)
   tx_fee = int(tx_fee)

   assert is_namespace_valid( namespace_id )

   nulldata = build( namespace_id )
   
   # get inputs and from public key
   inputs = tx_get_unspents( reveal_addr, blockchain_client )
   if safety:
       assert len(inputs) > 0

   # OP_RETURN outputs 
   outputs = make_outputs( nulldata, inputs, reveal_addr, fee=(DEFAULT_OP_RETURN_FEE + tx_fee), format='hex' )
  
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
