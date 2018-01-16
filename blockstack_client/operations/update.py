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

from utilitybelt import is_hex

from ..constants import (
    DEFAULT_DUST_FEE, DEFAULT_OP_RETURN_FEE,
    LENGTH_VALUE_HASH,
    LENGTH_CONSENSUS_HASH)
from ..b40 import is_b40
from ..scripts import (
    hash_name,
    hash256_trunc128,
    blockstack_script_to_hex,
    add_magic_bytes,
    is_name_valid,
    tx_get_unspents,
)

from ..logger import get_logger

import virtualchain
log = get_logger("blockstack-server")

def update_sanity_test( name, consensus_hash, data_hash ):
    """
    Verify the validity of an update's data

    Return True if valid
    Raise exception if not
    """
    
    if name is not None and (not is_b40( name ) or "+" in name or name.count(".") > 1):
       raise Exception("Name '%s' has non-base-38 characters" % name)
   
    if data_hash is not None and not is_hex( data_hash ):
       raise Exception("Invalid hex string '%s': not hex" % (data_hash))
    
    if len(data_hash) != 2 * LENGTH_VALUE_HASH:
       raise Exception("Invalid hex string '%s': bad length" % (data_hash))

    return True


def build(name, consensus_hash, data_hash=None):
    """
    Takes in the name to update the data for and the data update itself.
    Name must include the namespace ID, but not the scheme.
    
    Record format:
    
    0     2  3                                   19                      39
    |-----|--|-----------------------------------|-----------------------|
    magic op  hash128(name.ns_id,consensus hash) hash160(data)
    """

    rc = update_sanity_test( name, consensus_hash, data_hash )
    if not rc:
        raise Exception("Invalid update data")
    
    hex_name = hash256_trunc128( name + consensus_hash )
    
    readable_script = 'NAME_UPDATE 0x%s 0x%s' % (hex_name, data_hash)
    hex_script = blockstack_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script)

    return packaged_script


def make_outputs( data, inputs, change_address, tx_fee, pay_fee=True, dust_included = False ):
    """
    Make outputs for an update.
    Raise ValueError if there are not enough inputs to make the transaction
    """

    dust_fee = None
    op_fee = None
    dust_value = None

    total_tx_fee = tx_fee
    if pay_fee:
        if not dust_included:
            total_tx_fee += (len(inputs) + 1) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
        op_fee = DEFAULT_DUST_FEE
        dust_value = DEFAULT_DUST_FEE
    else:
        # will be subsidized
        total_tx_fee = 0
        op_fee = 0
        dust_value = 0

    return [
        # main output
        {"script": virtualchain.make_data_script(str(data)),
         "value": 0},

        # change output
        {"script": virtualchain.make_payment_script(change_address),
         "value": virtualchain.calculate_change_amount(inputs, op_fee, total_tx_fee)}
    ]


def make_transaction(name, data_hash, consensus_hash, owner_addr, blockchain_client,
                     tx_fee=0, subsidize=False, safety=True, dust_included = False):
    """
    Write a name update into the blockchain.
    Returns a JSON object with 'data' set to the nulldata and 'transaction_hash' set to the transaction hash on success.
    """

    name = str(name)
    data_hash = str(data_hash)
    consensus_hash = str(consensus_hash)
    owner_addr = str(owner_addr)
    tx_fee = int(tx_fee)

    assert len(consensus_hash) == LENGTH_CONSENSUS_HASH * 2
    assert is_name_valid(name)

    # sanity check
    pay_fee = True
    if subsidize:
        pay_fee = False

    inputs = tx_get_unspents( owner_addr, blockchain_client )
    if safety:
        assert len(inputs) > 0, "No UTXOs for {}".format(owner_addr)

    nulldata = build(name, consensus_hash, data_hash=data_hash)
    outputs = make_outputs( nulldata, inputs, owner_addr, tx_fee, pay_fee=pay_fee,
                            dust_included = dust_included )

    return (inputs, outputs)


def get_fees( inputs, outputs ):
    """
    Given a transaction's outputs, look up its fees:
    * there should be two outputs: the OP_RETURN and change address
    
    Return (dust fees, operation fees) on success 
    Return (None, None) on invalid output listing
    """
    if len(outputs) != 2:
        log.debug("Got %s outputs, not 2" % len(outputs))
        return (None, None)
    
    # 0: op_return
    if not virtualchain.tx_output_has_data( outputs[0] ):
        log.debug("Not an OP_RETURN output: %s" % outputs[0])
        return (None, None) 
    
    if outputs[0]["value"] != 0:
        log.debug("Outputs[0] has non-zero value")
        return (None, None)
    
    # 1: change address 
    if virtualchain.script_hex_to_address( outputs[1]["script"] ) is None:
        return (None, None)
    
    # should match make_outputs()
    # the +1 comes from one new output
    dust_fee = (len(inputs) + 1) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
    op_fee = 0
    
    return (dust_fee, op_fee)


def snv_consensus_extras( name_rec, block_id, blockchain_name_data ):
    """
    Given a name record most recently affected by an instance of this operation, 
    find the dict of consensus-affecting fields from the operation that are not
    already present in the name record.
    """
    
    ret_op = {}

    # reconstruct name_hash
    ret_op['name_consensus_hash'] = hash256_trunc128( str(name_rec['name']) + str(name_rec['consensus_hash']) )
    return ret_op

