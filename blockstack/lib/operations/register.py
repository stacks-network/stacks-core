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

# from blockstack_utxo import get_unspents, broadcast_transaction, analyze_private_key
import virtualchain
from virtualchain.lib.blockchain.bitcoin import tx_serialize, script_hex_to_address, make_op_return_script, \
        calculate_change_amount, make_pay_to_address_script

from keylib import ECPrivateKey, ECPublicKey
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40, is_b40
from ..config import *
from ..scripts import *
from ..hashing import hash256_trunc128
from ..nameset import NAMEREC_FIELDS, get_namespace_from_name
from ..blockchain import get_tx_inputs

log = virtualchain.get_logger("blockstack-server")

# consensus hash fields (ORDER MATTERS!)
FIELDS = NAMEREC_FIELDS + [
    'recipient',            # scriptPubKey hex script that identifies the principal to own this name
    'recipient_address'     # principal's address from the scriptPubKey in the transaction
]

def get_registration_recipient_from_outputs( outputs ):
    """
    There are three or four outputs:  the OP_RETURN, the registration 
    address, the change address (i.e. from the name preorderer), and 
    (for renwals) the burn address for the renewal fee.
    
    Given the outputs from a name register operation,
    find the registration address's script hex.
    
    By construction, it will be the first non-OP_RETURN 
    output (i.e. the second output).
    """
    
    ret = None
    for output in outputs:
       
        """
        output_script = output['scriptPubKey']
        output_asm = output_script.get('asm')
        output_hex = output_script.get('hex')
        output_addresses = output_script.get('addresses')
        
        if output_asm[0:9] != 'OP_RETURN' and output_hex is not None:
            
            # recipient's script_pubkey and address
            # ret = (output_hex, output_addresses[0])
            ret = output_hex
            break
        """
        if output.type() != "data":
            continue
        
        ret = output.sender_id()
        break
            
    if ret is None:
       raise Exception("No registration address found")
    
    return ret 


def build(name):
    """
    Takes in the name that was preordered, including the namespace ID (but not the id: scheme)
    Returns a hex string representing up to LENGTHS['blockchain_id_name'] bytes.
    
    Record format:
    
    0    2  3                             39
    |----|--|-----------------------------|
    magic op   name.ns_id (37 bytes)
    
    """
    
    if not is_name_valid( name ):
        raise Exception("Invalid name '%s'" % name)

    readable_script = "NAME_REGISTRATION 0x%s" % (hexlify(name))
    hex_script = blockstack_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script)
    
    return packaged_script 


def make_outputs( data, change_inputs, register_addr, change_addr, renewal_fee=None, pay_fee=True, format='bin' ):
    """
    Make outputs for a register:
    [0] OP_RETURN with the name 
    [1] pay-to-address with the *register_addr*, not the sender's address.
    [2] change address with the NAME_PREORDER sender's address
    [3] (OPTIONAL) renewal fee, sent to the burn address
    """
    
    dust_fee = None
    dust_value = None
    op_fee = None
    bill = None 
    
    if pay_fee:
        
        # sender pays
        if renewal_fee is not None:
            # renewing
            dust_fee = (len(change_inputs) + 3) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
            dust_value = DEFAULT_DUST_FEE
            op_fee = max(renewal_fee, DEFAULT_DUST_FEE)
            bill = op_fee
            
        else:
            # registering
            dust_fee = (len(change_inputs) + 2) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
            dust_value = DEFAULT_DUST_FEE
            op_fee = 0
            bill = DEFAULT_DUST_FEE * 2
            
    else:
        
        # subsidized by another address
        if renewal_fee is not None:
            # renewing
            dust_fee = 0
            dust_value = 0
            op_fee = max(renewal_fee, DEFAULT_DUST_FEE)
            bill = 0
            
        else:
            # registering
            dust_fee = 0
            dust_value = 0
            op_fee = 0
            bill = 0
  
    outputs = [
        # main output
        {"script_hex": make_op_return_script(data, format=format),
         "value": 0},
    
        # register address
        {"script_hex": make_pay_to_address_script(register_addr),
         "value": dust_fee},
        
        # change address (can be the subsidy address)
        {"script_hex": make_pay_to_address_script(change_addr),
         "value": calculate_change_amount(change_inputs, bill, dust_fee)},
    ]
    
    if renewal_fee is not None:
        outputs.append(
            
            # burn address (when renewing)
            {"script_hex": make_pay_to_address_script(BLOCKSTACK_BURN_ADDRESS),
             "value": op_fee}
        )

    return outputs
    
 
def state_transition(name, private_key, register_addr, renewal_fee=None, user_public_key=None, subsidy_public_key=None):
    
    namespace_id = get_namespace_from_name( name )
    blockchain_name = namespace_to_blockchain( namespace_id )

    if subsidy_public_key is None and private_key is None:
        raise Exception("Missing both public and private key")
      
    subsidized_renewal = False
    
    if subsidy_public_key is not None:
        # subsidizing
        
        if user_public_key is not None and renewal_fee is not None:
            # renewing, and subsidizing the renewal
            pubk = ECPublicKey( user_public_key )
            subsidized_renewal = True

        else:
            # registering or renewing under the subsidy key
            pubk = ECPublicKey( subsidy_public_key )

    elif private_key is not None:
        # ordering directly
        pubk = ECPrivateKey( private_key ).public_key()
       
    from_address = pubk.address()
    unspents = get_tx_inputs( blockchain_name, from_address )

    nulldata = build(name)
    outputs = make_outputs(nulldata, change_inputs, register_addr, from_address, renewal_fee=renewal_fee, pay_fee=(not subsidized_renewal), format='hex')
    return inputs, outputs
   

def broadcast(name, private_key, register_addr, blockchain_client, renewal_fee=None, blockchain_broadcaster=None, tx_only=False, user_public_key=None, subsidy_public_key=None, testset=False):
    
    # sanity check 
    if subsidy_public_key is not None:
        # if subsidizing, we're only giving back a tx to be signed
        tx_only = True

    if subsidy_public_key is None and private_key is None:
        raise Exception("Missing both public and private key")
    
    if not tx_only and private_key is None:
        raise Exception("Need private key for broadcasting")
    
    if blockchain_broadcaster is None:
        blockchain_broadcaster = blockchain_client 
   
    subsidized_renewal = False
    
    if subsidy_public_key is not None:
        # subsidizing
        
        if user_public_key is not None and renewal_fee is not None:
            # renewing, and subsidizing the renewal
            pubk = ECPublicKey( user_public_key )
            subsidized_renewal = True

        else:
            # registering or renewing under the subsidy key
            pubk = ECPublicKey( subsidy_public_key )

    elif private_key is not None:
        # ordering directly
        pubk = ECPrivateKey( private_key ).public_key()
       
    from_address = pubk.address()
    unspents = get_unspents( from_ddress, blockchain_client )

    nulldata = build(name, testset=testset)
    outputs = make_outputs(nulldata, change_inputs, register_addr, from_address, renewal_fee=renewal_fee, pay_fee=(not subsidized_renewal), format='hex')
   
    if tx_only:
        
        unsigned_tx = tx_serialize( change_inputs, outputs )
        return {"unsigned_tx": unsigned_tx}
    
    else:
        
        # serialize, sign, and broadcast the tx
        signed_tx = tx_serialize_sign( change_inputs, outputs, private_key )
        response = broadcast_transaction( signed_tx, blockchain_broadcaster )
        # response = serialize_sign_and_broadcast(change_inputs, outputs, private_key_obj, blockchain_broadcaster)
        response.update({'data': nulldata})
        return response


def parse(bin_payload):
    
    """
    Interpret a block's nulldata back into a name.  The first three bytes (2 magic + 1 opcode)
    will not be present in bin_payload.
    
    The name will be directly represented by the bytes given.
    """
    
    fqn = bin_payload
 
    if not is_name_valid( fqn ):
        return None

    return {
       'opcode': 'NAME_REGISTRATION',
       'name': fqn
    }
 

def get_fees( inputs, outputs ):
    """
    Given a transaction's outputs, look up its fees:
    * the first output must be an OP_RETURN, and it must have a fee of 0.
    * the second output must be the reveal address, and it must have a dust fee
    * the third must be the change address
    * the fourth, if given, must be a burned fee sent to the burn address
    
    Return (dust fees, operation fees) on success 
    Return (None, None) on invalid output listing
    """
    
    dust_fee = 0
    op_fee = 0
    
    if len(outputs) != 3 and len(outputs) != 4:
        return (None, None)
    
    # 0: op_return
    if not tx_output_is_op_return( outputs[0] ):
        return (None, None) 
    
    if outputs[0]["value"] != 0:
        return (None, None) 
    
    # 1: reveal address 
    if script_hex_to_address( outputs[1]["script_hex"] ) is None:
        return (None, None)
    
    # 2: change address 
    if script_hex_to_address( outputs[2]["script_hex"] ) is None:
        return (None, None)
    
    # 3: burn address, if given 
    if len(outputs) == 4:
        
        addr_hash = script_hex_to_address( outputs[3]["script_hex"] )
        if addr_hash is None:
            return (None, None) 
        
        if addr_hash != BLOCKSTACK_BURN_PUBKEY_HASH:
            return (None, None)
    
        dust_fee = (len(inputs) + 3) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
        op_fee = outputs[3]["value"]
        
    else:
        dust_fee = (len(inputs) + 2) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
    
    return (dust_fee, op_fee)
    
