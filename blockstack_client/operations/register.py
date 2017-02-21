#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack-client.

    Blockstack-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack-client. If not, see <http://www.gnu.org/licenses/>.
"""

import pybitcoin
from pybitcoin import embed_data_in_blockchain, serialize_transaction, \
    serialize_sign_and_broadcast, make_op_return_script, \
    make_pay_to_address_script, hex_hash160

from pybitcoin.transactions.outputs import calculate_change_amount
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40, is_b40
from ..config import *
from ..scripts import *

import virtualchain
log = virtualchain.get_logger("blockstack-server")


def build(name):
    """
    Takes in the name that was preordered, including the namespace ID (but not the id: scheme)
    Returns a hex string representing up to the maximum-length name's bytes.
    
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


def make_outputs( data, change_inputs, register_addr, change_addr, tx_fee, renewal_fee=None, pay_fee=True):
    """
    Make outputs for a register:
    [0] OP_RETURN with the name 
    [1] pay-to-address with the *register_addr*, not the sender's address.
    [2] change address with the NAME_PREORDER sender's address
    [3] (OPTIONAL) renewal fee, sent to the burn address
    Raise ValueError if there are not enough inputs to make the transaction
    """
    
    dust_fee = None
    dust_value = DEFAULT_DUST_FEE
    op_fee = None
    bill = None 
    
    if pay_fee:
        
        # sender pays
        if renewal_fee is not None:
            # renewing
            dust_fee = (len(change_inputs) + 3) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE + tx_fee
            op_fee = max(renewal_fee, DEFAULT_DUST_FEE)
            bill = op_fee
            
        else:
            # registering
            dust_fee = (len(change_inputs) + 2) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE + tx_fee
            op_fee = 0
            bill = DEFAULT_DUST_FEE * 2
            
    else:
        
        # subsidized by another address
        if renewal_fee is not None:
            # renewing
            dust_fee = 0
            op_fee = max(renewal_fee, DEFAULT_DUST_FEE)
            bill = 0
            
        else:
            # registering
            dust_fee = 0
            op_fee = 0
            bill = 0
  
    outputs = [
        # main output
        {"script_hex": make_op_return_script(str(data), format='hex'),
         "value": 0},
    
        # register address
        {"script_hex": virtualchain.make_payment_script(register_addr),
         "value": dust_value},
        
        # change address (can be the subsidy address)
        {"script_hex": virtualchain.make_payment_script(change_addr),
         "value": calculate_change_amount(change_inputs, bill, dust_fee)},
    ]
    
    if renewal_fee is not None:
        outputs.append(
            
            # burn address (when renewing)
            {"script_hex": virtualchain.make_payment_script(BLOCKSTACK_BURN_ADDRESS),
             "value": op_fee}
        )

    return outputs
    

def make_transaction(name, preorder_addr, register_addr, blockchain_client, tx_fee=0, renewal_fee=None, subsidized=False, safety=True):
    
    preorder_addr = str(preorder_addr)
    register_addr = str(register_addr)
    name = str(name)
    tx_fee = int(tx_fee)
    
    assert is_name_valid(name)

    if renewal_fee is not None:
        renewal_fee = int(renewal_fee)

    change_inputs = None
    pay_fee = True
    
    change_inputs = tx_get_unspents( preorder_addr, blockchain_client )
    if safety:
        assert len(change_inputs) > 0, "No UTXOs for {}".format(preorder_addr)

    if renewal_fee is not None:
        # will be subsidizing with a separate payment key
        assert preorder_addr == register_addr, "%s != %s" % (preorder_addr, register_addr)
        pay_fee = False

    if subsidized:
        pay_fee = False

    nulldata = build(name)
    outputs = make_outputs(nulldata, change_inputs, register_addr, preorder_addr, tx_fee, renewal_fee=renewal_fee, pay_fee=pay_fee )
 
    return (change_inputs, outputs)


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
        log.debug("len(outputs) == %s" % len(outputs))
        return (None, None)
    
    # 0: op_return
    if not tx_output_is_op_return( outputs[0] ):
        log.debug("output[0] is not an OP_RETURN")
        return (None, None) 
   
    # 1: reveal address 
    if virtualchain.script_hex_to_address( outputs[1]["script_hex"] ) is None:
        log.debug("output[1] is not a p2pkh or p2sh script")
        return (None, None)
    
    # 2: change address 
    if virtualchain.script_hex_to_address( outputs[2]["script_hex"] ) is None:
        log.debug("output[2] is not a p2pkh or p2sh script")
        return (None, None)
    
    # 3: burn address, if given 
    if len(outputs) == 4:
        
        addr_hash = virtualchain.script_hex_to_address( outputs[3]["script_hex"] )
        if addr_hash is None:
            log.debug("output[3] is not a valid script")
            return (None, None) 
        
        if addr_hash != BLOCKSTACK_BURN_ADDRESS:
            log.debug("output[3] is not the burn address %s (got %s)" % (BLOCKSTACK_BURN_ADDRESS, addr_hash))
            return (None, None)
    
        dust_fee = (len(inputs) + 3) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
        op_fee = outputs[3]["value"]
        
    else:
        dust_fee = (len(inputs) + 2) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
    
    return (dust_fee, op_fee)
   

def snv_consensus_extras( name_rec, block_id, blockchain_name_data ):
    """
    Given a name record most recently affected by an instance of this operation, 
    find the dict of consensus-affecting fields from the operation that are not
    already present in the name record.
    """
  
    ret_op = {}
    
    # reconstruct the recipient information
    ret_op['recipient'] = str(name_rec['sender'])
    ret_op['recipient_address'] = str(name_rec['address'])
    return ret_op

