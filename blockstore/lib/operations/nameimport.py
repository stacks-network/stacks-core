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

from pybitcoin import embed_data_in_blockchain, \
    analyze_private_key, serialize_sign_and_broadcast, make_op_return_script, \
    make_pay_to_address_script, b58check_encode, b58check_decode, serialize_transaction
 
from pybitcoin.transactions.outputs import calculate_change_amount
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40, is_b40
from ..config import *
from ..scripts import *
from ..hashing import hash256_trunc128

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


def build(name, testset=False):
    """
    Takes in a name to import.  Name must include the namespace ID.
    
    Record format:
    
    0    2  3                             39
    |----|--|-----------------------------|
    magic op   name.ns_id (37 bytes)
    
    The transaction itself will have two outputs:
    * the recipient
    * the hash of the name's associated data
    """
    
    if not is_name_valid( name ):
        raise Exception("Invalid name '%s'" % name)

    readable_script = "NAME_IMPORT 0x%s" % (hexlify(name))
    hex_script = blockstore_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script, testset=testset)
    
    return packaged_script


def make_outputs( data, inputs, recipient_address, sender_address, update_hash_b58, format='bin'):
    """
    Builds the outputs for a name import:
    * [0] is the OP_RETURN 
    * [1] is the new owner (recipient)
    * [2] is the update hash
    * [3] is the change sent to the original owner
    """
    
    dust_fee = DEFAULT_OP_RETURN_FEE + (len(inputs) + 3) * DEFAULT_DUST_FEE
    op_fee = 2 * DEFAULT_DUST_FEE
    dust_value = DEFAULT_DUST_FEE
    
    return [
        # main output
        {"script_hex": make_op_return_script(data, format=format),
         "value": 0},
    
        # recipient output
        {"script_hex": make_pay_to_address_script(recipient_address),
         "value": dust_value},
        
        # update hash output
        {"script_hex": make_pay_to_address_script(update_hash_b58),
         "value": dust_value},
        
        # change output
        {"script_hex": make_pay_to_address_script(sender_address),
         "value": calculate_change_amount(inputs, op_fee, dust_fee)}
    ]


def broadcast(name, recipient_address, update_hash, private_key, blockchain_client, blockchain_broadcaster=None, tx_only=False, testset=False):
   
    if blockchain_broadcaster is None:
        blockchain_broadcaster = blockchain_client 
    
    nulldata = build(name, testset=testset)
    
    # convert update_hash from a hex string so it looks like an address
    update_hash_b58 = b58check_encode( unhexlify(update_hash) )
    
    # get inputs and from address
    private_key_obj, from_address, inputs = analyze_private_key(private_key, blockchain_client)
    
    # NAME_IMPORT outputs
    outputs = make_outputs(nulldata, inputs, recipient_address, from_address, update_hash_b58, format='hex')
    
    if tx_only:
        
        unsigned_tx = serialize_transaction( inputs, outputs )
        return {"unsigned_tx": unsigned_tx}
    
    else:
        # serialize, sign, and broadcast the tx
        response = serialize_sign_and_broadcast(inputs, outputs, private_key_obj, blockchain_broadcaster)
        
        # response = {'success': True }
        response.update({'data': nulldata})
        
        # return the response
        return response


def parse(bin_payload, recipient, update_hash ):
    """
    # NOTE: first three bytes were stripped
    """
    
    fqn = bin_payload
    if not is_name_valid( fqn ):
        return None 

    return {
        'opcode': 'NAME_IMPORT',
        'name': fqn,
        'recipient': recipient,
        'update_hash': update_hash
    }


def get_fees( inputs, outputs ):
    """
    Blockstore currently does not allow 
    the subsidization of namespaces.
    """
    return (None, None)
