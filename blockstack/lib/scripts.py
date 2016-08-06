#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack

    Blockstack is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
"""

from utilitybelt import is_hex, is_valid_int
from binascii import hexlify, unhexlify
from virtualchain import BitcoinPrivateKey, BitcoinPublicKey
from pybitcoin import script_to_hex, make_pay_to_address_script
from pybitcoin.transactions.outputs import calculate_change_amount

import virtualchain
log = virtualchain.get_logger("blockstack-server")

import bitcoin
import json

try:
    from .config import *
    from .b40 import *
except:
    # hack around relative paths
    import sys 
    import os
    sys.path.append(os.path.dirname(__file__))
    from config import *
    from b40 import *

def add_magic_bytes(hex_script, testset=False):
    magic_bytes = MAGIC_BYTES_MAINSET
    return hexlify(magic_bytes) + hex_script


def is_name_valid( fqn ):
    """
    Is a fully-qualified name acceptable?
    Return True if so
    Return False if not

    TODO: DRY up; use client
    """

    if fqn.count( "." ) != 1:
        return False

    name, namespace_id = fqn.split(".")

    if len(name) == 0 or len(namespace_id) == 0:
        return False 

    if not is_b40( name ) or "+" in name or "." in name:
        return False 

    if not is_b40( namespace_id ) or "+" in namespace_id or "." in namespace_id:
        return False
    
    name_hex = hexlify(name)
    if len(name_hex) > LENGTHS['blockchain_id_name'] * 2:
       # too long
       return False 

    return True


def is_namespace_valid( namespace_id ):
    """
    Is a namespace ID valid?

    TODO: DRY up; use client
    """
    if not is_b40( namespace_id ) or "+" in namespace_id or namespace_id.count(".") > 0:
        return False

    if len(namespace_id) == 0 or len(namespace_id) > LENGTHS['blockchain_id_namespace_id']:
        return False

    return True


def blockstack_script_to_hex(script):
    """ Parse the readable version of a script, return the hex version.
    """
    hex_script = ''
    parts = script.split(' ')
    for part in parts:
       
        if part in NAME_OPCODES.keys():
            try:
                hex_script += '%0.2x' % ord(NAME_OPCODES[part])
            except:
                raise Exception('Invalid opcode: %s' % part)
        
        elif part.startswith("0x"):
            # literal hex string
            hex_script += part[2:]
            
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

