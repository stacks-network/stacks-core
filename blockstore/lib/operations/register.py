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
    make_pay_to_address_script, b58check_encode, b58check_decode, BlockchainInfoClient, hex_hash160

from pybitcoin.transactions.outputs import calculate_change_amount
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40, is_b40
from ..config import *
from ..scripts import blockstore_script_to_hex, add_magic_bytes
from ..hashing import hash256_trunc128

def get_registration_recipient_from_outputs( outputs ):
    """
    There are three or four outputs:  the OP_RETURN, the registration 
    address, the change address (i.e. from the name preorderer), and 
    (for renwals) the burn for the renewal fee.
    
    Given the outputs from a name register operation,
    find the registration address.
    
    By construction, it will be the first non-OP_RETURN 
    output (i.e. the second output).
    """
    
    ret = None
    for output in outputs:
       
        output_script = output['scriptPubKey']
        output_asm = output_script.get('asm')
        output_hex = output_script.get('hex')
        output_addresses = output_script.get('addresses')
        
        if output_asm[0:9] != 'OP_RETURN' and output_hex is not None:
            
            # recipient's script_pubkey and address
            ret = (output_hex, output_addresses[0])
            break
            
    if ret is None:
       raise Exception("No registration address found")
    
    return ret 


def build(name, testset=False):
    """
    Takes in the name that was preordered, including the namespace ID (but not the id: scheme)
    Returns a hex string representing up to LENGTHS['blockchain_id_name'] bytes.
    
    Record format:
    
    0    2  3                             39
    |----|--|-----------------------------|
    magic op   name.ns_id (37 bytes)
    
    """
    
    if not is_b40( name ) or "+" in name or name.count(".") > 1:
       raise Exception("Name '%s' has non-base-38 characters" % name)
    
    name_hex = hexlify(name)
    if len(name_hex) > LENGTHS['blockchain_id_name'] * 2:
       # too long
      raise Exception("Name '%s' too long (exceeds %d bytes)" % (fqn, LENGTHS['blockchain_id_name']))
    
    readable_script = "NAME_REGISTRATION 0x%s" % (hexlify(name))
    hex_script = blockstore_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script, testset=testset)
    
    return packaged_script 


def make_outputs( data, inputs, register_addr, change_addr, renewal_fee=None, format='bin' ):
    """
    Make outputs for a register:
    [0] OP_RETURN with the name 
    [1] pay-to-address with the *register_addr*, not the sender's address.
    [2] change address with the NAME_PREORDER sender's address
    """
    
    total_to_send = DEFAULT_OP_RETURN_FEE + DEFAULT_DUST_FEE + len(inputs) * DEFAULT_DUST_FEE
    if renewal_fee is not None:
        total_to_send += max(renewal_fee, DEFAULT_OP_RETURN_FEE)
    
    outputs = [
        # main output
        {"script_hex": make_op_return_script(data, format=format),
         "value": DEFAULT_OP_RETURN_FEE},
    
        # register address
        {"script_hex": make_pay_to_address_script(register_addr),
         "value": DEFAULT_DUST_FEE},
        
        # change address
        {"script_hex": make_pay_to_address_script(change_addr),
         "value": calculate_change_amount(inputs, total_to_send, DEFAULT_OP_RETURN_FEE)},
    ]
    
    if renewal_fee is not None:
        outputs.append(
            
            # burn address (when renewing)
            {"script_hex": make_pay_to_address_script(BLOCKSTORE_BURN_ADDRESS),
             "value": max(renewal_fee, DEFAULT_OP_RETURN_FEE)}
        )

    return outputs
    

def broadcast(name, register_addr, private_key, blockchain_client, renewal_fee=None, testset=False):
    
    nulldata = build(name, testset=testset)
    
    # get inputs and from address
    private_key_obj, from_address, inputs = analyze_private_key(private_key, blockchain_client)
    
    # build custom outputs here
    outputs = make_outputs(nulldata, inputs, register_addr, from_address, renewal_fee=renewal_fee, format='hex')
    
    # serialize, sign, and broadcast the tx
    response = serialize_sign_and_broadcast(inputs, outputs, private_key_obj, blockchain_client)
    
    # response = {'success': True }
    response.update({'data': nulldata})
    
    return response


def parse(bin_payload):
    
    """
    Interpret a block's nulldata back into a name.  The first three bytes (2 magic + 1 opcode)
    will not be present in bin_payload.
    
    The name will be directly represented by the bytes given.
    """
    
    fqn = bin_payload
    
    return {
       'opcode': 'NAME_REGISTRATION',
       'name': fqn
    }
 
