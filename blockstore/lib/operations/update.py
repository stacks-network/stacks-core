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

from ..b40 import b40_to_hex, bin_to_b40
from ..config import *
from ..scripts import blockstore_script_to_hex, add_magic_bytes
from ..hashing import hash256_trunc128

def build(name, consensus_hash, data_hash=None, testset=False):
    """
    Takes in the name to update the data for and the data update itself.
    Name must include the namespace ID, but not the scheme.
    
    Record format:
    
    0     2  3                                   19                      39
    |-----|--|-----------------------------------|-----------------------|
    magic op  hash128(name.ns_id,consensus hash) hash160(data)
    """
    
    if name.startswith(NAME_SCHEME):
       raise Exception("Invalid name %s: must not start with %s" % (name, NAME_SCHEME))
    
    if not is_hex( data_hash ):
       raise Exception("Invalid hex string '%s': not hex" % (data_hash))
    
    if len(data_hash) != 2 * LENGTHS['update_hash']:
       raise Exception("Invalid hex string '%s': bad length" % (data_hash))
       
    hex_name = hash256_trunc128( name + consensus_hash )
    
    readable_script = 'NAME_UPDATE 0x%s 0x%s' % (hex_name, data_hash)
    hex_script = blockstore_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script, testset=testset)

    return packaged_script


def broadcast(name, data_hash, consensus_hash, private_key, blockchain_client=BlockchainInfoClient(), testset=False):
    """
    Write a name update into the blockchain.
    Returns a JSON object with 'data' set to the nulldata and 'transaction_hash' set to the transaction hash on success.
    """
    nulldata = build(name, consensus_hash, data_hash=data_hash, testset=testset)
    response = embed_data_in_blockchain(nulldata, private_key, blockchain_client, format='hex')
    response.update({'data': nulldata})
    return response


def parse(bin_payload):
    """
    Parse a payload to get back the name and update hash.
    NOTE: bin_payload excludes the leading three bytes.
    """
    name_hash_bin = bin_payload[:LENGTHS['name_hash']]
    update_hash_bin = bin_payload[LENGTHS['name_hash']:]
    
    name_hash = hexlify( name_hash_bin )
    update_hash = hexlify( update_hash_bin )
    
    return {
        'opcode': 'NAME_UPDATE',
        'name_hash': name_hash,
        'update_hash': update_hash
    }
