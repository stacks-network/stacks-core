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
from ..scripts import (
    hash256_trunc128,
    blockstack_script_to_hex,
    add_magic_bytes,
    is_name_valid,
    tx_get_unspents,
    hash256_trunc128
)

from ..constants import (
    DEFAULT_DUST_FEE, DEFAULT_OP_RETURN_FEE,
    BLOCKSTACK_BURN_ADDRESS, LENGTH_VALUE_HASH,
    MAX_OP_LENGTH, LENGTH_MAX_NAME
)

from ..logger import get_logger

import virtualchain
log = get_logger("blockstack-server")


def build(name, value_hash=None):
    """
    Takes in the name that was preordered, including the namespace ID (but not the id: scheme)
    Returns a hex string representing up to the maximum-length name's bytes.
    
    Record format (pre F-day 2017):
    
    0    2  3                                  39
    |----|--|----------------------------------|
    magic op   name.ns_id (up to 37 bytes)


    Record format (post F-day 2017):
    
    0    2  3                                  39                  59
    |----|--|----------------------------------|-------------------|
    magic op   name.ns_id (37 bytes, 0-padded)       value hash


    """
    
    if not is_name_valid( name ):
        raise Exception("Invalid name '%s'" % name)

    if value_hash is not None:
        if len(value_hash) != LENGTH_VALUE_HASH * 2:
            raise Exception("Invalid value hash '%s' (%s)" % (value_hash, type(value_hash)))

    data = name.encode('hex')
    payload = None

    if value_hash:
        # pad name with 0's until it's 37 bytes (so id:${name} will be 40 bytes)
        name_data = '{}{}'.format(data, '00' * (LENGTH_MAX_NAME - len(data)/2))
        assert len(name_data) == LENGTH_MAX_NAME * 2, 'BUG: invalid name data {}'.format(name_data)

        payload = '{}{}'.format(name_data, value_hash)
        assert len(payload) == (LENGTH_MAX_NAME + LENGTH_VALUE_HASH) * 2, 'BUG: invalid payload {}'.format(payload)

    else:
        payload = data

    readable_script = "NAME_REGISTRATION 0x%s" % (payload)

    hex_script = blockstack_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script)
    
    return packaged_script 


def make_outputs( data, change_inputs, register_addr, change_addr, tx_fee,
                  renewal_fee=None, burn_address=BLOCKSTACK_BURN_ADDRESS, pay_fee=True,
                  dust_included = False ):
    """
    Make outputs for a register:
    [0] OP_RETURN with the name, and possibly a value hash
    [1] pay-to-address with the *register_addr*, not the sender's address.  If renewing, this is the new owner address.
    [2] change address with the NAME_PREORDER or NAME_RENEWAL's subsidizer's sender's address
    [3] (OPTIONAL) renewal fee, sent to the burn address

    Raise ValueError if there are not enough inputs to make the transaction
    """

    dust_fee = None
    dust_value = DEFAULT_DUST_FEE
    op_fee = None
    bill = None

    if pay_fee:
        # sender pays
        total_tx_fee = tx_fee
        if renewal_fee is not None:
            # renewing
            dust_fee = (len(change_inputs) + 3) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
            op_fee = max(renewal_fee, DEFAULT_DUST_FEE)
            bill = op_fee
        else:
            # registering
            dust_fee = (len(change_inputs) + 2) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
            op_fee = 0
            bill = DEFAULT_DUST_FEE * 2
        if not dust_included:
            total_tx_fee += dust_fee
    else:
        # subsidized by another address
        bill = 0
        total_tx_fee = 0
        if renewal_fee is not None:
            # renewing
            op_fee = max(renewal_fee, DEFAULT_DUST_FEE)
        else:
            # registering
            op_fee = 0

    payload = str(data)

    outputs = [
        # main output
        {"script": virtualchain.make_data_script(payload),
         "value": 0},

        # register/new-owner address
        {"script": virtualchain.make_payment_script(str(register_addr)),
         "value": dust_value},

        # change address (can be the subsidy address)
        {"script": virtualchain.make_payment_script(str(change_addr)),
         "value": virtualchain.calculate_change_amount(change_inputs, bill, total_tx_fee)},
    ]

    if renewal_fee is not None:
        outputs.append(
            # burn address (when renewing)
            {"script": virtualchain.make_payment_script(str(burn_address)),
             "value": op_fee}
        )

    return outputs

def make_transaction(name, preorder_or_owner_addr, register_or_new_owner_addr, blockchain_client,
                     tx_fee=0, burn_address=BLOCKSTACK_BURN_ADDRESS, renewal_fee=None,
                     zonefile_hash=None, subsidize=False, safety=True, dust_included=False):
    # register_or_new_owner_addr is the address of the recipient in NAME_PREORDER
    # register_or_new_owner_addr is the address of the current name owner in standard NAME_RENEWAL (pre F-day 2017)
    # register_or_new_owner_addr is the address of the current or new name owner, in the post-F-day 2017 NAME_RENEWAL
    # if zonefile_hash is given, it must be a hex string (and will only be accepted post F-day 2017)

    preorder_or_owner_addr = str(preorder_or_owner_addr)
    register_or_new_owner_addr = str(register_or_new_owner_addr)
    name = str(name)
    tx_fee = int(tx_fee)

    assert is_name_valid(name)

    if renewal_fee is not None:
        renewal_fee = int(renewal_fee)

    change_inputs = None
    pay_fee = True

    change_inputs = tx_get_unspents( preorder_or_owner_addr, blockchain_client )
    if safety:
        assert len(change_inputs) > 0, "No UTXOs for {}".format(preorder_or_owner_addr)

    if renewal_fee is not None:
        # this is a NAME_RENEWAL
        # will be subsidizing with a separate payment key
        # assert preorder_addr == register_addr, "%s != %s" % (preorder_addr, register_addr)
        pay_fee = False

    if subsidize:
        pay_fee = False

    nulldata = build(name, value_hash=zonefile_hash)
    outputs = make_outputs(nulldata, change_inputs, register_or_new_owner_addr, preorder_or_owner_addr, tx_fee,
                           burn_address=burn_address, renewal_fee=renewal_fee, pay_fee=pay_fee,
                           dust_included = dust_included)

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
    if not virtualchain.tx_output_has_data( outputs[0] ):
        log.debug("output[0] is not an OP_RETURN")
        return (None, None) 
   
    # 1: reveal address 
    if virtualchain.script_hex_to_address( outputs[1]["script"] ) is None:
        log.debug("output[1] is not a standard script")
        return (None, None)
    
    # 2: change address 
    if virtualchain.script_hex_to_address( outputs[2]["script"] ) is None:
        log.debug("output[2] is not a a standard script")
        return (None, None)
    
    # 3: burn address, if given 
    if len(outputs) == 4:
        
        addr_hash = virtualchain.script_hex_to_address( outputs[3]["script"] )
        if addr_hash is None:
            log.debug("output[3] is not a standard script")
            return (None, None) 
        
        # should match make_outputs().
        # the +3 comes from 1 owner UTXO + 2 new outputs
        dust_fee = (len(inputs) + 3) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
        op_fee = outputs[3]["value"]
        
    else:
        # should match make_outputs().
        # the +2 comes from 1 owner UTXO + 1 new output
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

