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

from pybitcoin import embed_data_in_blockchain, BlockchainInfoClient, bin_hash160, BitcoinPrivateKey
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, is_b40
from ..config import *
from ..scripts import blockstore_script_to_hex, add_magic_bytes, get_script_pubkey
from ..hashing import hash_name


def build(name, script_pubkey, consensus_hash, testset=False):
    """
    Takes a name, including the namespace ID (but not the id:// scheme), a script_publickey to prove ownership
    of the subsequent NAME_REGISTER operation, and the current consensus hash for this block (to prove that the 
    caller is not on a shorter fork).
    
    Returns a NAME_PREORDER script.
    
    Record format:
    
    0     2  3                               23             39
    |-----|--|-------------------------------|--------------|
    magic op  hash(name.ns_id,script_pubkey)  consensus hash
    
    """
    
    if not is_b40( name ):
       raise Exception("Name '%s' is not base-40" % name)
    
    # name itself cannot exceed LENGTHS['blockchain_id_name']
    if len(NAME_SCHEME) + len(name) > LENGTHS['blockchain_id_name']:
       raise Exception("Name '%s' is too long; exceeds %s bytes" % (name, LENGTHS['blockchain_id_name'] - len(NAME_SCHEME)))
    
    name_hash = hash_name(name, script_pubkey)

    script = 'NAME_PREORDER %s %s' % (name_hash, consensus_hash)
    hex_script = blockstore_script_to_hex(script)
    packaged_script = add_magic_bytes(hex_script, testset=testset)
    
    return packaged_script


def broadcast(name, consensus_hash, private_key, blockchain_client, testset=False):
    """
    Builds and broadcasts a preorder transaction.
    """
    
    script_pubkey = get_script_pubkey( private_key )
    
    nulldata = build( name, script_pubkey, consensus_hash, testset=testset)
    response = embed_data_in_blockchain( nulldata, private_key, blockchain_client, format='hex')
    
    # response = {'success': True }
    response.update( {'data': nulldata, 'consensus_hash': consensus_hash})
    return response


def parse(bin_payload):
    """
    Parse a name preorder.
    NOTE: bin_payload *excludes* the leading 3 bytes (magic + op) returned by build.
    """
    
    name_hash = hexlify( bin_payload[0:LENGTHS['preorder_name_hash']] )
    consensus_hash = hexlify( bin_payload[LENGTHS['preorder_name_hash']:] )
    
    return {
        'opcode': 'NAME_PREORDER',
        'preorder_name_hash': name_hash,
        'consensus_hash': consensus_hash
    }
