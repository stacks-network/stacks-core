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

"""
A note on code organization...
A multi-register is still considered to be a kind of register;
it's just that it can contain multiple names.  For the sake of avoiding
breaking-consensus changes, we treat a multi-name register like 
a 1-name register as much as possible:
    * we break a multi-register into a sequence of registers
    * we use the exact same consensus fields (modulo a slightly longer op-bytecode)

Unlike NAME_TRANSFER (which also comes in two flavors), the logic for building, 
broadcasting, and parsing multi-name preorders is different enough that it warrants
its own file (this one).  However, this code should not be construed as representing
a wholly separate op-code; it's still considered to be part of the NAME_PREORDER 
op-code logic.
"""

from pybitcoin import embed_data_in_blockchain, serialize_transaction, \
    analyze_private_key, serialize_sign_and_broadcast, make_op_return_script, \
    make_pay_to_address_script, b58check_encode, b58check_decode, BlockchainInfoClient, hex_hash160, \
    BitcoinPrivateKey, get_unspents, script_hex_to_address

from pybitcoin.transactions.outputs import calculate_change_amount
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40, is_b40
from ..config import *
from ..scripts import *
from ..hashing import hash256_trunc128
from ..nameset import NAMEREC_FIELDS

from register import get_registration_recipient_from_outputs

import virtualchain

if not globals().has_key('log'):
    log = virtualchain.session.log

FIELDS = [
    'names',                # the names registered
    'value_hashes',         # the hashes of the name's associated profile
    'sender',               # the scriptPubKey hex that owns this name (identifies ownership)
    'sender_pubkey',        # (OPTIONAL) the public key 
    'address',              # the address of the sender
    
    'block_number',         # the block number when the names were created (preordered for the first time--will refer to a NAME_PREORDER_MULTI)
    'preorder_block_number', # the block number when this names were preordered (will refer to the NAME_PREORDER_MULTI)
    'first_registered',     # the block number when the names were registered (this op's block number)

    'op',                   # byte sequence describing the last operation to affect this name (will be NAME_REGISTER_MULTI)
    'txid',                 # the ID of the last transaction to affect this name
    'vtxindex',             # the index in the block of the transaction.
    'op_fee',               # the value of the last Blockstore-specific burn fee paid for this name (i.e. from preorder or renew)

    'recipient_list',          # scriptPubKey hex script that identifies the principal to own this name
    'recipient_address_list'   # principal's address from the scriptPubKey in the transaction
]


def get_registration_multi_recipients_from_outputs( outputs ):
    raise Exception("Not yet implemented")

def build(names, update_hashes, testset=False):
    """
    Takes in the name that was preordered, including the namespace ID (but not the id: scheme)
    Returns a hex string representing up to LENGTHS['blockchain_id_name'] bytes.
    
    Record format:
    
    0    2  3             23               43                                80
    |----|--|-------------|----------------|----------------------------------|
    magic op  update_hash    update_hash    name1.id, name2.id
    
    """

    if len(names) != 2 or len(update_hashes) != 2:
        raise Exception("Need two names and update hashes")

    if len(name_list) != len(set(name_list)):
        raise Exception("Name list has duplicate names")

    for name in names:
        if not is_name_valid( name ):
            raise Exception("Invalid name '%s'" % name)

    for h in update_hashes:
        if not is_hex( h ):
            raise Exception("Invalid update hash '%s'" % h )

        if len(h) != 2*20:
            raise Exception("Not a 160-bit hash: '%s'" % h)

    if sum([len(n) for n in names]) > 36:
        raise Exception("Names exceed maximum combined length")

    update_hashes = "%s%s" % (update_hashes[0], update_hashes[1])
    names = "%s,%s" % (names[0], names[1])

    readable_script = "NAME_REGISTRATION_MULTI 0x%s 0x%s" % (update_hashes, hexlify(names))
    hex_script = blockstore_script_to_hex( readable_script )
    packaged_script = add_magic_bytes( hex_script, testset=testset )
    return packaged_script
 

def tx_extract( payload, senders, inputs, outputs ):
    """
    Extract and return a dict of fields from the underlying blockchain transaction data
    that are useful to this operation.

    Required:
    sender:  the script_pubkey (as a hex string) of the principal that sent the name preorder-multi transaction
    address:  the address from the sender script
    recipient_list:  the list of script_pubkey strings (as hex strings) of the principals that are meant to receive each name
    recipient_address:  the addresses from the recipient scripts

    Optional:
    sender_pubkey_hex: the public key of the sender
    """
  
    sender = None 
    sender_address = None 
    sender_pubkey_hex = None

    recipient_list = None
    recipient_address_list = None 

    try:
       recipient_list = get_registration_multi_recipients_from_outputs( outputs )
       assert recipient_list is not None 

       recipient_address_list = []
       for r in recipient_list:
          addr = pybitcoin.script_hex_to_address( r )
          assert addr is not None

          recipient_address_list.append( addr )

       # by construction, the first input comes from the principal
       # who sent the registration transaction...
       assert len(senders) > 0
       assert 'script_pubkey' in senders[0].keys()
       assert 'addresses' in senders[0].keys()

       sender = str(senders[0]['script_pubkey'])
       sender_address = str(senders[0]['addresses'][0])

       assert sender is not None 
       assert sender_address is not None

       if str(senders[0]['script_type']) == 'pubkeyhash':
          sender_pubkey_hex = get_public_key_hex_from_tx( inputs, sender_address )

    except Exception, e:
       log.exception(e)
       raise Exception("Failed to extract")

    parsed_payload = parse( payload )
    assert parsed_payload is not None

    ret = {
       "sender": sender,
       "address": sender_address,
       "recipient_list": recipient_list,
       "recipient_address_list": recipient_address_list
    }

    ret.update( parsed_payload )

    if sender_pubkey_hex is not None:
        ret['sender_pubkey'] = sender_pubkey_hex

    return ret


def make_outputs( data, change_inputs, register_addrs, change_addr, pay_fee=True, format='bin' ):
    """
    Make outputs for a register:
    [0] OP_RETURN with the names and update hashes
    [1] pay-to-address with the first name's *register_addr*, not the sender's address
    [2] pay-to-address with the second name's *register_addr*, not the sender's address
    [2] change address with the NAME_PREORDER_MULTI sender's address
    """

    bill = 0    # cost of outputs
    if pay_fee:
        bill = 2*DEFAULT_DUST_FEE
    
    outputs = [
        # main output
        {"script_hex": make_op_return_script(data, format=format),
         "value": 0},
    
        # register address #1
        {"script_hex": make_pay_to_address_script(register_addrs[0]),
         "value": DEFAULT_DUST_FEE},

        # register address #2 
        {"script_hex": make_pay_to_address_script(register_addrs[1]),
         "value": DEFAULT_DUST_FEE},
        
        # change address (can be the subsidy address)
        {"script_hex": make_pay_to_address_script(change_addr),
         "value": calculate_change_amount(change_inputs, 0, 0)},
    ]
    
    if pay_fee:
        dust_fee = tx_dust_fee_from_inputs_and_outputs( change_inputs, outputs )
        outputs[3]['value'] = calculate_change_amount( change_inputs, bill, dust_fee )

    return outputs
  

def broadcast(name_list, private_key, register_addrs, update_hashes, blockchain_client, \
        renewal_fee=None, blockchain_broadcaster=None, tx_only=False, user_public_key=None, subsidy_public_key=None, testset=False):
    
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
    
    from_address = None 
    change_inputs = None
    private_key_obj = None
    subsidized_renewal = False
    
    if subsidy_public_key is not None:
        # subsidizing
        pubk = BitcoinPublicKey( subsidy_public_key )
        
        if user_public_key is not None and renewal_fee is not None:
            # renewing, and subsidizing the renewal
            from_address = BitcoinPublicKey( user_public_key ).address() 
            subsidized_renewal = True

        else:
            # registering or renewing under the subsidy key
            from_address = pubk.address()

        change_inputs = get_unspents( from_address, blockchain_client )

    elif private_key is not None:
        # ordering directly
        pubk = BitcoinPrivateKey( private_key ).public_key()
        public_key = pubk.to_hex()
        
        # get inputs and from address using private key
        private_key_obj, from_address, change_inputs = analyze_private_key(private_key, blockchain_client)
        
    nulldata = build(name_list, update_hashes, testset=testset)
    outputs = make_outputs(nulldata, change_inputs, register_addrs, from_address, renewal_fee=renewal_fee, pay_fee=(not subsidized_renewal), format='hex')
   
    if tx_only:
        
        unsigned_tx = serialize_transaction( change_inputs, outputs )
        return {"unsigned_tx": unsigned_tx}
    
    else:
        
        # serialize, sign, and broadcast the tx
        response = serialize_sign_and_broadcast(change_inputs, outputs, private_key_obj, blockchain_broadcaster)
        response.update({'data': nulldata})
        return response


def parse(bin_payload):
    """
    Interpret a block's nulldata back into names and update hashes.  The first three bytes (2 magic + 1 opcode)
    will not be present in bin_payload.
    
    The name will be directly represented by the bytes given.
    """
   
    if len(bin_payload) < 2*LENGTHS['update_hash'] + 2*LENGTHS['fqn_min']:
        log.error("Not a NAME_REGISTRATION_MULTI")
        return None 

    update_hashes = []
    for i in xrange(0, 1):
        update_hashes.append( hexlify(bin_payload[ i*LENGTHS['update_hash'] : (i+1)*LENGTHS['update_hash'] ]) )

    name_buf = bin_payload[ 2*LENGTHS['update_hash']: ]
    if name_buf.count(',') != 1:
        log.error("Missing or invalid name delimiter")
        return None 

    names = name_buf.split(',')
    for name in names:
        if not is_name_valid( name ):
            log.error("Invalid name")
            return None
    
    return {
        'opcode': 'NAME_REGISTRATION_MULTI',
        'names': names,
        'update_hashes': update_hashes
    }


def decompose( nameop, name ):
    """
    Decompose a NAME_REGISTRATION_MULTI into a NAME_REGISTRATION with the given name.
    """

    try:
        i = nameop['names'].index(name)
    except:
        log.debug("No name: %s" % name)
        raise

    ret = copy.deepcopy(nameop)
    ret['opcode'] = 'NAME_REGISTRATION'
    ret['op'] = NAME_REGISTRATION
    ret['name'] = name
    ret['recipient'] = nameop['recipient_list'][i]
    ret['recipient_address'] = nameop['recipient_address_list'][i]

    del ret['names']
    del ret['update_hashes']
    del ret['recipient_list']
    del ret['recipient_address_list']

    return ret


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
        
        if addr_hash != BLOCKSTORE_BURN_PUBKEY_HASH:
            return (None, None)
    
        dust_fee = (len(inputs) + 3) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
        op_fee = outputs[3]["value"]
        
    else:
        dust_fee = (len(inputs) + 2) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
    
    return (dust_fee, op_fee)
   

def restore_delta( name_rec, block_number, history_index, untrusted_db, testset=False ):
    """
    Find the fields in a name record that were changed by an instance of this operation, at the 
    given (block_number, history_index) point in time in the past.  The history_index is the
    index into the list of changes for this name record in the given block.

    Return the fields that were modified on success.
    Return None on error.
    """

    from ..nameset import BlockstoreDB
    
    name_rec_script = build( str(name_rec['names']), testset=testset )
    name_rec_payload = unhexlify( name_rec_script )[3:]
    ret_op = parse( name_rec_payload )

    recipients = []
    recipient_addrs = []

    # go find the two names we registered...
    untrusted_name_recs = []
    for name in name_rec['names']:

        untrusted_name_rec = untrusted_db.get_name( str(name) )
        recipients.append( str(name_rec['sender']) )
        recipient_addrs.append( str(name_rec['address']) )

        # find this name's sender and address
        name_rec['history'] = untrusted_name_rec['history']

        if history_index > 0:
            name_rec_prev = BlockstoreDB.restore_from_history( name_rec, block_number )[ history_index - 1 ]
        else:
            name_rec_prev = BlockstoreDB.restore_from_history( name_rec, block_number - 1 )[ history_index - 1 ]

        sender = name_rec_prev['sender']
        address = name_rec_prev['address']

        ret_op['sender'] = sender
        ret_op['address'] = address

        del name_rec['history']

    name_rec['recipient_list'] = recipients 
    name_rec['recipient_address_list'] = recipient_addrs

    return ret_op
