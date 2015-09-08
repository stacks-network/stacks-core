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

from pybitcoin import embed_data_in_blockchain, \
    analyze_private_key, serialize_sign_and_broadcast, make_op_return_script, \
    make_pay_to_address_script
 
from pybitcoin.transactions.outputs import calculate_change_amount
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40, is_b40
from ..config import *
from ..scripts import blockstore_script_to_hex, add_magic_bytes
from ..hashing import hash256_trunc128

def get_transfer_recipient_from_outputs( outputs ):
    """
    Given the outputs from a name transfer operation,
    find the recipient's script_pubkey string and address
    
    By construction, it will be the first non-OP_RETURN 
    output (i.e. the second output).
    """
    
    ret = None
    for output in outputs:
       
        output_script = output['scriptPubKey']
        output_asm = output_script.get('asm')
        output_hex = output_script.get('hex')
        output_addresses = output_script.get('addresses')
        
        if output_asm[0:9] != 'OP_RETURN' and output_hex:
            
            ret = (output_hex, output_addresses[0])
            break
            
    if ret is None:
       raise Exception("No recipients found")
    
    return ret 


def build(name, keepdata, consensus_hash, testset=False):
    """
    Takes in a name to transfer.  Name must include the namespace ID, but not the scheme.
    
    Record format:
    
    0     2  3    4                   20              36
    |-----|--|----|-------------------|---------------|
    magic op keep  hash128(name.ns_id) consensus hash
             data?
    """
    
    if not is_b40( name ) or "+" in name or name.count(".") > 1:
       raise Exception("Name '%s' has non-base-38 characters" % name)
    
    # without the scheme, name must be 34 bytes 
    if len(name) > LENGTHS['blockchain_id_name']:
       raise Exception("Name '%s' is too long; expected %s bytes" % (name, LENGTHS['blockchain_id_name']))
    
    data_disposition = None 
    
    if keepdata:
       data_disposition = TRANSFER_KEEP_DATA 
    else:
       data_disposition = TRANSFER_REMOVE_DATA
    
    name_hash = hash256_trunc128( name )
    disposition_hex = hexlify(data_disposition)
    
    readable_script = 'NAME_TRANSFER 0x%s 0x%s 0x%s' % (disposition_hex, name_hash, consensus_hash)
    hex_script = blockstore_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script, testset=testset)
    
    return packaged_script


def make_outputs( data, inputs, new_name_owner_address, change_address, format='bin' ):
    """
    Builds the outputs for a name transfer operation.
    """
    
    total_to_send = DEFAULT_OP_RETURN_FEE + DEFAULT_DUST_FEE*2
 
    return [
        # main output
        {"script_hex": make_op_return_script(data, format=format),
         "value": DEFAULT_OP_RETURN_FEE},
        # new name owner output
        {"script_hex": make_pay_to_address_script(new_name_owner_address),
         "value": DEFAULT_DUST_FEE},
        # change output
        {"script_hex": make_pay_to_address_script(change_address),
         "value": calculate_change_amount(inputs, total_to_send, (len(inputs) + 3) * DEFAULT_DUST_FEE)}
    ]


def broadcast(name, destination_address, keepdata, consensus_hash, private_key, blockchain_client, testset=False):
   
    nulldata = build(name, keepdata, consensus_hash, testset=testset)
    
    # get inputs and from address
    private_key_obj, from_address, inputs = analyze_private_key(private_key, blockchain_client)
    
    # build custom outputs here
    outputs = make_outputs(nulldata, inputs, destination_address, from_address, format='hex')
    
    # serialize, sign, and broadcast the tx
    response = serialize_sign_and_broadcast(inputs, outputs, private_key_obj, blockchain_client)
    
    # response = {'success': True }
    response.update({'data': nulldata})
    
    # return the response
    return response


def parse(bin_payload, recipient):
    """
    # NOTE: first three bytes were stripped
    """
    
    disposition_char = bin_payload[0:1]
    name_hash = bin_payload[1:1+LENGTHS['name_hash']]
    consensus_hash = bin_payload[1+LENGTHS['name_hash']:]
    
    # keep data by default 
    disposition = True 
    
    if disposition_char == TRANSFER_REMOVE_DATA:
       disposition = False 
    
    return {
        'opcode': 'NAME_TRANSFER',
        'name_hash': hexlify( name_hash ),
        'consensus_hash': hexlify( consensus_hash ),
        'recipient': recipient,
        'keep_data': disposition
    }
