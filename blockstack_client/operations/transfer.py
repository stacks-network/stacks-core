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

from ..constants import (
    DEFAULT_DUST_FEE, DEFAULT_OP_RETURN_FEE,
    TRANSFER_KEEP_DATA, TRANSFER_REMOVE_DATA, LENGTH_MAX_NAME,
    LENGTH_CONSENSUS_HASH, NAME_TRANSFER, NAME_PREORDER)

import os

from ..b40 import is_b40
from ..scripts import (
    hash256_trunc128,
    blockstack_script_to_hex,
    add_magic_bytes,
    is_name_valid,
    tx_get_unspents,
    hash256_trunc128
)

from ..logger import get_logger

import virtualchain
log = get_logger("blockstack-client")


def transfer_sanity_check( name, consensus_hash ):
    """
    Verify that data for a transfer is valid.

    Return True on success
    Raise Exception on error
    """
    if name is not None and (not is_b40( name ) or "+" in name or name.count(".") > 1):
       raise Exception("Name '%s' has non-base-38 characters" % name)
    
    # without the scheme, name must be 37 bytes 
    if name is not None and len(name) > LENGTH_MAX_NAME:
       raise Exception("Name '%s' is too long; expected %s bytes" % (name, LENGTH_MAX_NAME))
    
    return True


def build(name, keepdata, consensus_hash):
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
    hex_script = blockstack_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script)
    
    return packaged_script


def make_outputs( data, inputs, new_name_owner_address, change_address, tx_fee=0, pay_fee=True,
                  dust_included = False):
    """
    Builds the outputs for a name transfer operation.
    Raise ValueError if there are not enough inputs to make the transaction
    """

    dust_fee = None
    op_fee = None
    dust_value = DEFAULT_DUST_FEE

    if pay_fee:
        total_tx_fee = tx_fee
        if not dust_included:
            total_tx_fee += (len(inputs) + 2) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
        op_fee = DEFAULT_DUST_FEE
    else:
        total_tx_fee = 0
        op_fee = 0

    return [
        # main output
        {"script": virtualchain.make_data_script(str(data)),
         "value": 0},
        # new name owner output
        {"script": virtualchain.make_payment_script(new_name_owner_address),
         "value": dust_value},
        # change output
        {"script": virtualchain.make_payment_script(change_address),
         "value": virtualchain.calculate_change_amount(inputs, op_fee, total_tx_fee)}
    ]


def make_transaction(name, destination_address, keepdata, consensus_hash,
                     old_owner_addr, blockchain_client, tx_fee=0, subsidize=False, safety=True,
                     dust_included = False):

    name = str(name)
    destination_address = str(destination_address)
    consensus_hash = str(consensus_hash)
    old_owner_addr = str(old_owner_addr)
    tx_fee = int(tx_fee)

    assert len(consensus_hash) == LENGTH_CONSENSUS_HASH * 2
    assert is_name_valid(name)

    # sanity check
    pay_fee = True
    if subsidize:
        pay_fee = False

    inputs = tx_get_unspents( old_owner_addr, blockchain_client )
    if safety:
        assert len(inputs) > 0, "No UTXOs for {}".format(old_owner_addr)

    nulldata = build(name, keepdata, consensus_hash)
    outputs = make_outputs(nulldata, inputs, destination_address,
                           old_owner_addr, tx_fee, pay_fee=pay_fee,
                           dust_included = dust_included)

    return (inputs, outputs)


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
    if not virtualchain.tx_output_has_data( outputs[0] ):
        return (None, None) 
    
    if outputs[0]["value"] != 0:
        return (None, None) 
    
    # 1: transfer address 
    if virtualchain.script_hex_to_address( outputs[1]["script"] ) is None:
        return (None, None)
    
    # 2: change address 
    if virtualchain.script_hex_to_address( outputs[2]["script"] ) is None:
        return (None, None)
    
    # should match make_outputs()
    # the +2 comes from 2 new outputs
    dust_fee = (len(inputs) + 2) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
    op_fee = DEFAULT_DUST_FEE
    
    return (dust_fee, op_fee)


def find_last_transfer_consensus_hash( name_rec, block_id, vtxindex ):
    """
    Given a name record, find the last non-NAME_TRANSFER consensus hash.
    Return None if not found.
    """

    from ..proxy import nameop_restore_from_history

    history_keys = name_rec['history'].keys()
    history_keys.sort()
    history_keys.reverse()

    for hk in history_keys:
        name_history = name_rec['history']
        history_states = nameop_restore_from_history( name_rec, name_history, hk )

        for history_state in reversed(history_states):
            if history_state['block_number'] > block_id or (history_state['block_number'] == block_id and history_state['vtxindex'] > vtxindex):
                # from the future
                continue

            if history_state['op'][0] == NAME_TRANSFER:
                # skip NAME_TRANSFERS
                continue

            if history_state['op'][0] == NAME_PREORDER:
                # out of history
                return None

            if name_rec['consensus_hash'] is not None:
                return name_rec['consensus_hash']

    return None


def snv_consensus_extras( name_rec, block_id, blockchain_name_data, transfer_send_block_id_consensus_hash=None ):
    """
    Given a name record most recently affected by an instance of this operation, 
    find the dict of consensus-affecting fields from the operation that are not
    already present in the name record.

    Specific to NAME_TRANSFER:
    The consensus hash is a field that we snapshot when we discover the transfer,
    but it is not a field that we preserve.  It will instead be present in the
    snapshots database, indexed by the block number in `transfer_send_block_id`.

    (This is an artifact of a design quirk of a previous version of the system).
    """
    
    from ..proxy import get_consensus_at 

    ret_op = {}
    
    # reconstruct the recipient information
    ret_op['recipient'] = str(name_rec['sender'])
    ret_op['recipient_address'] = str(name_rec['address'])

    # reconstruct name_hash, consensus_hash, keep_data
    keep_data = None
    try:
        assert len(name_rec['op']) == 2, "Invalid op sequence '%s'" % (name_rec['op'])
        
        if name_rec['op'][-1] == TRANSFER_KEEP_DATA:
            keep_data = True
        elif name_rec['op'][-1] == TRANSFER_REMOVE_DATA:
            keep_data = False
        else:
            raise Exception("Invalid op sequence '%s'" % (name_rec['op']))

    except Exception, e:
        log.exception(e)
        log.error("FATAL: invalid transfer op sequence")
        os.abort()

    ret_op['keep_data'] = keep_data
    ret_op['name_hash128'] = hash256_trunc128( str(name_rec['name']) )
    ret_op['sender_pubkey'] = None

    if blockchain_name_data is None:

       consensus_hash = find_last_transfer_consensus_hash( name_rec, block_id, name_rec['vtxindex'] )
       ret_op['consensus_hash'] = consensus_hash

    else:
       ret_op['consensus_hash'] = blockchain_name_data['consensus_hash']
      
    if ret_op['consensus_hash'] is None:
       # no prior consensus hash; must be the one in the name operation itself 
       if transfer_send_block_id_consensus_hash is None:
           # go look it up
           ret_op['consensus_hash'] = get_consensus_at( name_rec['transfer_send_block_id'] )
       else:
           # caller already knows it
           log.debug("consensus hash for %s is caller-given: %s" % (name_rec['transfer_send_block_id'], transfer_send_block_id_consensus_hash))
           ret_op['consensus_hash'] = transfer_send_block_id_consensus_hash

    return ret_op

