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
from virtualchain import BitcoinPublicKey
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
   
    if not is_namespace_valid( namespace_id ):
        return False

    if len(fqn) > LENGTHS['blockchain_id_name']:
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


def get_namespace_from_name( name ):
   """
   Get a fully-qualified name's namespace, if it has one.
   It's the sequence of characters after the last "." in the name.
   If there is no "." in the name, then it belongs to the null
   namespace (i.e. the empty string will be returned)
   """
   if "." not in name:
      # empty namespace
      return ""

   return name.split(".")[-1]


def get_name_from_fq_name( name ):
   """
   Given a fully-qualified name, get the name part.
   It's the sequence of characters before the last "." in the name.

   Return None if malformed
   """
   if "." not in name:
      # malformed
      return None

   return name.split(".")[0]


def price_name( name, namespace, block_height ):
   """
   Calculate the price of a name (without its namespace ID), given the
   namespace parameters.

   The minimum price is NAME_COST_UNIT
   """

   base = namespace['base']
   coeff = namespace['coeff']
   buckets = namespace['buckets']

   bucket_exponent = 0
   discount = 1.0

   if len(name) < len(buckets):
       bucket_exponent = buckets[len(name)-1]
   else:
       bucket_exponent = buckets[-1]

   # no vowel discount?
   if sum( [name.lower().count(v) for v in ["a", "e", "i", "o", "u", "y"]] ) == 0:
       # no vowels!
       discount = max( discount, namespace['no_vowel_discount'] )

   # non-alpha discount?
   if sum( [name.lower().count(v) for v in ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "-", "_"]] ) > 0:
       # non-alpha!
       discount = max( discount, namespace['nonalpha_discount'] )

   price = (float(coeff * (base ** bucket_exponent)) / float(discount)) * NAME_COST_UNIT
   if price < NAME_COST_UNIT:
       price = NAME_COST_UNIT

   price_multiplier = get_epoch_price_multiplier( block_height, namespace['namespace_id'] )
   return price * price_multiplier


def price_namespace( namespace_id, block_height ):
   """
   Calculate the cost of a namespace.
   """

   price_multiplier = get_epoch_price_multiplier( block_height, namespace_id )

   if len(namespace_id) == 1:
       return NAMESPACE_1_CHAR_COST * price_multiplier

   elif len(namespace_id) in [2, 3]:
       return NAMESPACE_23_CHAR_COST * price_multiplier

   elif len(namespace_id) in [4, 5, 6, 7]:
       return NAMESPACE_4567_CHAR_COST * price_multiplier

   else:
       return NAMESPACE_8UP_CHAR_COST * price_multiplier


def find_by_opcode( checked_ops, opcode ):
    """
    Given all previously-accepted operations in this block,
    find the ones that are of a particular opcode.

    @opcode can be one opcode, or a list of opcodes
    """

    if type(opcode) != list:
        opcode = [opcode]

    ret = []
    for opdata in checked_ops:
        if op_get_opcode_name(opdata['op']) in opcode:
            ret.append(opdata)

    return ret 


def get_burn_fee_from_outputs( outputs ):
    """
    Given the set of outputs, find the fee sent 
    to our burn address.
    
    Return the fee on success
    Return None if not found
    """
    
    ret = None
    for output in outputs:
       
        output_script = output['scriptPubKey']
        output_asm = output_script.get('asm')
        output_hex = output_script.get('hex')
        output_addresses = output_script.get('addresses')
        
        if output_asm[0:9] != 'OP_RETURN' and BLOCKSTACK_BURN_ADDRESS == output_addresses[0]:
            
            # recipient's script_pubkey and address
            ret = int(output['value']*(10**8))
            if os.environ.get("BLOCKSTACK_TEST") == "1" and ret > 1000 * (10**8):
                raise Exception("Absurdly high burn output\n%s" % simplejson.dumps(outputs, indent=4, sort_keys=True))

            break
    
    return ret 
    

def get_public_key_hex_from_tx( inputs, address ):
    """
    Given a list of inputs and the address of one of the inputs,
    find the public key.

    This only works for p2pkh scripts.
    """
    
    ret = None 
    
    for inp in inputs:
        
        input_scriptsig = inp.get('scriptSig', None )
        if input_scriptsig is None:
            continue 
        
        input_asm = input_scriptsig.get("asm")
        
        if len(input_asm.split(" ")) >= 2:
            
            # public key is the second hex string.  verify it matches the address
            pubkey_hex = input_asm.split(" ")[1]
            pubkey = None 
            
            try:
                pubkey = virtualchain.BitcoinPublicKey( str(pubkey_hex) ) 
            except Exception, e: 
                traceback.print_exc()
                log.warning("Invalid public key '%s'" % pubkey_hex)
                continue 
            
            if address != pubkey.address():
                continue 
            
            ret = pubkey_hex
            break
        
    return ret 


