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

from pybitcoin import b58check_decode
from binascii import hexlify, unhexlify

from ..config import *
from ..scripts import *

from ..nameset import NAMEREC_FIELDS

# consensus hash fields (ORDER MATTERS!) 
FIELDS = NAMEREC_FIELDS + [
    'recipient',            # scriptPubKey hex that identifies the name recipient 
    'recipient_address'     # address of the recipient
]

def get_import_update_hash_from_outputs( outputs, recipient ):
    """
    This is meant for NAME_IMPORT operations, which 
    have five outputs:  the OP_RETURN, the sender (i.e.
    the namespace owner), the name's recipient, the
    name's update hash, and the burn output.
    This method extracts the name update hash from
    the list of outputs.
    
    By construction, the update hash address in 
    the NAME_IMPORT operation is the first 
    non-OP_RETURN output that is *not* the recipient.
    """
    
    ret = None
    count = 0
    for output in outputs:
       
        output_script = output['scriptPubKey']
        output_asm = output_script.get('asm')
        output_hex = output_script.get('hex')
        output_addresses = output_script.get('addresses')
        
        if output_asm[0:9] != 'OP_RETURN' and output_hex is not None and output_hex != recipient:
            
            ret = hexlify( b58check_decode( str(output_addresses[0]) ) )
            break
            
    if ret is None:
       raise Exception("No update hash found")
    
    return ret 

