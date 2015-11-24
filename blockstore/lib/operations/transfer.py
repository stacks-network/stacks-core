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

from pybitcoin import embed_data_in_blockchain, serialize_transaction, \
    analyze_private_key, serialize_sign_and_broadcast, make_op_return_script, \
    make_pay_to_address_script, BitcoinPrivateKey, BitcoinPublicKey, get_unspents, script_hex_to_address
 
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
    'name_hash',            # hash(name)
    'consensus_hash',       # consensus hash when this operation was sent
    'keep_data'             # whether or not to keep the profile data associated with the name when transferred
]

def get_transfer_recipient_from_outputs( outputs ):
    """
    Given the outputs from a name transfer operation,
    find the recipient's script hex.
    
    By construction, it will be the first non-OP_RETURN 
    output (i.e. the second output).

    This also applies to a NAME_IMPORT.
    """
    
    ret = None
    for output in outputs:
       
        output_script = output['scriptPubKey']
        output_asm = output_script.get('asm')
        output_hex = output_script.get('hex')
        output_addresses = output_script.get('addresses')
        
        if output_asm[0:9] != 'OP_RETURN' and output_hex:
            
            ret = output_hex
            break
            
    if ret is None:
       raise Exception("No recipients found")
    
    return ret 


def transfer_sanity_check( name, consensus_hash ):
    """
    Verify that data for a transfer is valid.

    Return True on success
    Raise Exception on error
    """
    if name is not None and (not is_b40( name ) or "+" in name or name.count(".") > 1):
       raise Exception("Name '%s' has non-base-38 characters" % name)
    
    # without the scheme, name must be 37 bytes 
    if name is not None and (len(name) > LENGTHS['blockchain_id_name']):
       raise Exception("Name '%s' is too long; expected %s bytes" % (name, LENGTHS['blockchain_id_name']))
    
    return True


def build(name, keepdata, consensus_hash, testset=False):
    """
    Takes in a name to transfer.  Name must include the namespace ID, but not the scheme.
    
    Record format:
    
    0     2  3    4                   20              36
    |-----|--|----|-------------------|---------------|
    magic op keep  hash128(name.ns_id) consensus hash
             data?
    """
    
    rc = transfer_sanity_check( name, consensus_hash )
    if not rc:
        raise Exception("Invalid transfer data")

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


def make_outputs( data, inputs, new_name_owner_address, change_address, pay_fee=True, format='bin' ):
    """
    Builds the outputs for a name transfer operation.
    """
    
    dust_fee = None
    op_fee = None
    dust_value = DEFAULT_DUST_FEE
    
    if pay_fee:
        dust_fee = (len(inputs) + 2) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
        op_fee = DEFAULT_DUST_FEE
    
    else:
        dust_fee = 0
        op_fee = 0
    
    return [
        # main output
        {"script_hex": make_op_return_script(data, format=format),
         "value": 0},
        # new name owner output
        {"script_hex": make_pay_to_address_script(new_name_owner_address),
         "value": dust_value},
        # change output
        {"script_hex": make_pay_to_address_script(change_address),
         "value": calculate_change_amount(inputs, op_fee, dust_fee)}
    ]


def broadcast(name, destination_address, keepdata, consensus_hash, private_key, blockchain_client, blockchain_broadcaster=None, tx_only=False, user_public_key=None, testset=False):
    
    # sanity check 
    pay_fee = True
    if user_public_key is not None:
        pay_fee = False
        tx_only = True 

    if user_public_key is None and private_key is None:
        raise Exception("Missing both public and private key")
    
    if not tx_only and private_key is None:
        raise Exception("Need private key for broadcasting")
    
    if blockchain_broadcaster is None:
        blockchain_broadcaster = blockchain_client 
    
    from_address = None 
    inputs = None
    private_key_obj = None
    
    if user_public_key is not None:
        # subsidizing 
        pubk = BitcoinPublicKey( user_public_key )

        from_address = pubk.address()
        inputs = get_unspents( from_address, blockchain_client )

    elif private_key is not None:
        # ordering directly 
        pubk = BitcoinPrivateKey( private_key ).public_key()
        public_key = pubk.to_hex()
        
        # get inputs and from address using private key
        private_key_obj, from_address, inputs = analyze_private_key(private_key, blockchain_client)
        
    nulldata = build(name, keepdata, consensus_hash, testset=testset)
    outputs = make_outputs(nulldata, inputs, destination_address, from_address, pay_fee=pay_fee, format='hex')
    
    if tx_only:
    
        unsigned_tx = serialize_transaction( inputs, outputs )
        return {"unsigned_tx": unsigned_tx}
    
    else:
        # serialize, sign, and broadcast the tx
        response = serialize_sign_and_broadcast(inputs, outputs, private_key_obj, blockchain_broadcaster)
        response.update({'data': nulldata})
        return response


def parse(bin_payload, recipient):
    """
    # NOTE: first three bytes were stripped
    """
    
    if len(bin_payload) != 1 + LENGTHS['name_hash'] + LENGTHS['consensus_hash']:
        log.error("Invalid transfer payload length %s" % len(bin_payload))
        return None 

    disposition_char = bin_payload[0:1]
    name_hash = bin_payload[1:1+LENGTHS['name_hash']]
    consensus_hash = bin_payload[1+LENGTHS['name_hash']:]
   
    if disposition_char not in [TRANSFER_REMOVE_DATA, TRANSFER_KEEP_DATA]:
        log.error("Invalid disposition character")
        return None 

    # keep data by default 
    disposition = True 
    
    if disposition_char == TRANSFER_REMOVE_DATA:
       disposition = False 
   
    try:
       rc = transfer_sanity_check( None, consensus_hash )
       if not rc:
           raise Exception("Invalid transfer data")

    except Exception, e:
       log.error("Invalid transfer data")
       return None

    return {
        'opcode': 'NAME_TRANSFER',
        'name_hash': hexlify( name_hash ),
        'consensus_hash': hexlify( consensus_hash ),
        'recipient': recipient,
        'keep_data': disposition
    }


def get_fees( inputs, outputs ):
    """
    Given a transaction's outputs, look up its fees:
    * the first output should be an OP_RETURN with the transfer info 
    * the second output should be the new owner's address, with a DEFAULT_DUST_FEE
    * the third output should be the change address
    
    Return (dust fees, operation fees) on success 
    Return (None, None) on invalid output listing
    """
    if len(outputs) != 3:
        return (None, None)
    
    # 0: op_return
    if not tx_output_is_op_return( outputs[0] ):
        return (None, None) 
    
    if outputs[0]["value"] != 0:
        return (None, None) 
    
    # 1: transfer address 
    if script_hex_to_address( outputs[1]["script_hex"] ) is None:
        return (None, None)
    
    # 2: change address 
    if script_hex_to_address( outputs[2]["script_hex"] ) is None:
        return (None, None)
    
    dust_fee = (len(inputs) + 2) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
    op_fee = DEFAULT_DUST_FEE
    
    return (dust_fee, op_fee)

