#!/usr/bin/env python2
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

from binascii import hexlify

from ..logger import get_logger
from ..constants import (
    DEFAULT_DUST_FEE, DEFAULT_OP_RETURN_FEE)
from ..scripts import (
    hash_name,
    hash256_trunc128,
    blockstack_script_to_hex,
    add_magic_bytes,
    is_name_valid,
    tx_get_unspents,
    hash256_trunc128
)

import virtualchain
log = get_logger("blockstack-client")


def build(name):
    """
    Takes in the name, including the namespace ID (but not the id: scheme)
    Returns a hex string representing up to the maximum name length bytes.
    
    Record format:
    
    0    2  3                             39
    |----|--|-----------------------------|
    magic op   name.ns_id (37 bytes)
    
    """
    
    if not is_name_valid( name ):
       raise Exception("Invalid name '%s'" % name)

    readable_script = "NAME_REVOKE 0x%s" % (hexlify(name))
    hex_script = blockstack_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script)
    
    return packaged_script 


def make_outputs( data, inputs, change_address, tx_fee, pay_fee=True ):
    """
    Make outputs for a revoke.
    Raise ValueError if there are not enough inputs to make the transaction
    """

    dust_fee = None
    op_fee = None
    dust_value = None 
    
    if pay_fee:
        dust_fee = (len(inputs) + 1) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE + tx_fee
        op_fee = DEFAULT_DUST_FEE
        dust_value = DEFAULT_DUST_FEE
    
    else:
        # will be subsidized
        dust_fee = 0
        op_fee = 0
        dust_value = 0
   
    return [
        # main output
        {"script": virtualchain.make_data_script(str(data)),
         "value": 0},
        
        # change output
        {"script": virtualchain.make_payment_script(change_address),
         "value": virtualchain.calculate_change_amount(inputs, op_fee, dust_fee)}
    ]


def make_transaction(name, owner_addr, blockchain_client, tx_fee=0, subsidize=False, safety=True ):
    
    name = str(name)
    owner_addr = str(owner_addr)
    tx_fee = int(tx_fee)

    assert is_name_valid(name)
    
    # sanity check 
    pay_fee = True
    if subsidize:
        pay_fee = False

    inputs = tx_get_unspents( owner_addr, blockchain_client )
    if safety:
        assert len(inputs) > 0, "No UTXOs for {}".format(owner_addr)

    nulldata = build(name)
    outputs = make_outputs( nulldata, inputs, owner_addr, tx_fee, pay_fee=pay_fee )
   
    return (inputs, outputs)


def get_fees( inputs, outputs ):
    """
    Given a transaction's outputs, look up its fees:
    * there should be two outputs: the OP_RETURN and change address
    
    Return (dust fees, operation fees) on success 
    Return (None, None) on invalid output listing
    """
    if len(outputs) != 2:
        return (None, None)
    
    # 0: op_return
    if not virtualchain.tx_output_has_data( outputs[0] ):
        return (None, None) 
    
    if outputs[0]["value"] != 0:
        return (None, None) 
    
    # 1: change address 
    if virtualchain.script_hex_to_address( outputs[1]["script"] ) is None:
        return (None, None)
    
    # should match make_outputs().
    # the +1 comes from one new output
    dust_fee = (len(inputs) + 1) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
    op_fee = 0
    
    return (dust_fee, op_fee)


def snv_consensus_extras( name_rec, block_id, blockchain_name_data ):
    """
    Calculate any derived missing data that goes into the check() operation,
    given the block number, the name record at the block number, and the db.
    """

    ret_op = {}
    return ret_op

