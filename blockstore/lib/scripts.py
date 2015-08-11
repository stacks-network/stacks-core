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

from utilitybelt import is_hex, is_valid_int
from binascii import hexlify, unhexlify
from pybitcoin import BitcoinPrivateKey, script_to_hex
 
from .config import *

def add_magic_bytes(hex_script, testset=False):
    if not testset:
        magic_bytes = MAGIC_BYTES_MAINSET
    else:
        magic_bytes = MAGIC_BYTES_TESTSET
    return hexlify(magic_bytes) + hex_script


def blockstore_script_to_hex(script):
    """ Parse the readable version of a script, return the hex version.
    """
    hex_script = ''
    parts = script.split(' ')
    for part in parts:
       
        if part.startswith("NAME_") or part.startswith("NAMESPACE_"):
            try:
                hex_script += '%0.2x' % ord(eval(part))
            except:
                raise Exception('Invalid opcode: %s' % part)
            
        elif is_valid_int(part):
            hex_part = '%0.2x' % int(part)
            if len(hex_part) % 2 != 0:
               hex_part = '0' + hex_part
               
            hex_script += hex_part
         
        elif is_hex(part) and len(part) % 2 == 0:
            hex_script += part
            
        else:
            raise ValueError('Invalid script (at %s), contains invalid characters: %s' % (part, script))
         
    if len(hex_script) % 2 != 0:
        raise ValueError('Invalid script: must have an even number of chars (got %s).' % hex_script)
     
    return hex_script


# generate a pay-to-pubkeyhash script from a private key.
def get_script_pubkey( private_key ):
   
   hash160 = BitcoinPrivateKey(private_key).public_key().hash160()
   script_pubkey = script_to_hex( 'OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG' % hash160)
   return  script_pubkey
