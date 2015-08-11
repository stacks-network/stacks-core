#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org
    
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
    along with Blockstore.  If not, see <http://www.gnu.org/licenses/>.
"""

from pybitcoin import embed_data_in_blockchain, BlockchainInfoClient, hex_hash160
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40, is_b40
from ..config import *
from ..scripts import blockstore_script_to_hex, add_magic_bytes

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
   if not is_b40( namespace_id ):
      raise Exception("Namespace ID '%s' is not base-40" % namespace_id)
   
   if len(namespace_id) == 0 or len(namespace_id) > LENGTHS['blockchain_id_namespace_id']:
      raise Exception("Invalid namespace ID '%s (expected length between 1 and %s)" % (namespace_id, LENGTHS['blockchain_id_namespace_id']))
   
   readable_script = "NAMESPACE_BEGIN 0x%s" % (hexlify("." + namespace_id))
   hex_script = blockstore_script_to_hex(readable_script)
   packaged_script = add_magic_bytes(hex_script, testset=testset)
   
   return packaged_script


def broadcast( namespace_id, private_key, blockchain_client, testset=False ):
   
   nulldata = build( namespace_id, testset=testset )
   # response = {'success': True }
   response = embed_data_in_blockchain( nulldata, private_key, blockchain_client, format='hex')
   response.update({'data': nulldata})
   return response


def parse( bin_payload ):
   """
   NOTE: the first three bytes will be missing
   NOTE: the first byte in bin_payload is a '.'
   """
   
   namespace_id = bin_payload[ 1: ]
   
   return {
      'opcode': 'NAMESPACE_BEGIN',
      'namespace_id': namespace_id
   }
