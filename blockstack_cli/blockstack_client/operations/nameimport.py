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
from pybitcoin import embed_data_in_blockchain, \
    analyze_private_key, serialize_sign_and_broadcast, make_op_return_script, \
    make_pay_to_address_script, b58check_encode, b58check_decode, serialize_transaction, get_unspents

 
from pybitcoin.transactions.outputs import calculate_change_amount
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40, is_b40
from ..config import *
from ..scripts import *

import virtualchain
log = virtualchain.get_logger("blockstack-client")


def build(name):
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
    hex_script = blockstack_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script)
    
    return packaged_script


def make_outputs( data, inputs, recipient_address, sender_address, update_hash_b58, tx_fee):
    """
    Builds the outputs for a name import:
    * [0] is the OP_RETURN 
    * [1] is the new owner (recipient)
    * [2] is the update hash
    * [3] is the change sent to the original owner

    Raise ValueError if there are not enough inputs to make the transaction
    """
    
    dust_fee = DEFAULT_OP_RETURN_FEE + (len(inputs) + 3) * DEFAULT_DUST_FEE + tx_fee
    op_fee = 2 * DEFAULT_DUST_FEE
    dust_value = DEFAULT_DUST_FEE
    
    return [
        # main output
        {"script_hex": make_op_return_script(str(data), format='hex'),
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


def make_transaction(name, recipient_address, update_hash, payment_addr, blockchain_client, tx_fee=0):
  
    name = str(name)
    recipient_address = str(recipient_address)
    update_hash = str(update_hash)
    payment_addr = str(payment_addr)
    tx_fee = int(tx_fee)

    assert is_name_valid(name)
    assert len(update_hash) == LENGTHS['update_hash'] * 2

    nulldata = build(name)
    
    # convert update_hash from a hex string so it looks like an address
    update_hash_b58 = b58check_encode( unhexlify(update_hash) )
    inputs = get_unspents( payment_addr, blockchain_client )
    outputs = make_outputs(nulldata, inputs, recipient_address, payment_addr, update_hash_b58, tx_fee)

    return (inputs, outputs)


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
    Blockstack currently does not allow 
    the subsidization of namespaces.
    """
    return (None, None)

