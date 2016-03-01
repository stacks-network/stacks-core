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

from pybitcoin import embed_data_in_blockchain, make_op_return_tx, make_op_return_outputs, \
        make_op_return_script, broadcast_transaction, serialize_transaction, \
        script_hex_to_address, get_unspents
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40, is_b40
from ..config import *
from ..scripts import *

# consensus hash fields (none for announcements)
FIELDS = []

# fields that this operation changes (none)
MUTATE_FIELDS = []

# fields that should be backed up when applying this operation (none)
BACKUP_FIELDS = []


def build(message_hash, testset=False):
    """
     
    Record format:
    
    0    2  3                             23
    |----|--|-----------------------------|
    magic op   message hash (160-bit)
    
    """
   
    if len(message_hash) != 40:
        raise Exception("Invalid hash: not 20 bytes")

    if not is_hex(message_hash):
        raise Exception("Invalid hash: not hex")

    readable_script = "ANNOUNCE 0x%s" % (message_hash)
    hex_script = blockstack_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script, testset=testset)
    
    return packaged_script 


def process_announcement( op ):
    """
    If the announcement is valid, then immediately record it.
    """
    # valid announcement
    announce_hash = op['message_hash']
    announcer_id = op['announcer_id']

    # go get the text...
    announcement_text = get_announcement( announce_hash ) 
    log.critical("ANNOUNCEMENT (from %s): %s\n------BEGIN MESSAGE------\n%s\n------END MESSAGE------\n" % (announcer_id, announce_hash, announcement_text))
             
    store_announcement( announce_hash, announcement_text )


def check( state_engine, nameop, block_id, checked_ops ):
    """
    Log an announcement from the blockstack developers.
    Return True if the announcement came from the announce IDs whitelist
    Return False otherwise
    """

    sender = nameop['sender']
    sending_blockchain_id = None
    found = False

    for blockchain_id in state_engine.get_announce_ids():
        blockchain_namerec = state_engine.get_name( blockchain_id )
        if blockchain_namerec is None:
            # this name doesn't exist yet, or is expired or revoked
            continue

        if str(sender) == str(blockchain_namerec['sender']):
            # yup!
            found = True
            sending_blockchain_id = blockchain_id
            break

    if not found:
        log.debug("Announcement not sent from our whitelist of blockchain IDs")
        return False

    nameop['announcer_id'] = sending_blockchain_id
    process_announcement( nameop )
    return True


def tx_extract( payload, senders, inputs, outputs, block_id, vtxindex, txid ):
    """
    Extract and return a dict of fields from the underlying blockchain transaction data
    that are useful to this operation.

    Required (+ parse):
    sender:  the script_pubkey (as a hex string) of the principal that sent the name preorder transaction
    address:  the address from the sender script

    Optional:
    sender_pubkey_hex: the public key of the sender
    """
  
    sender_script = None 
    sender_address = None 
    sender_pubkey_hex = None

    try:

       # by construction, the first input comes from the principal
       # who sent the registration transaction...
       assert len(senders) > 0
       assert 'script_pubkey' in senders[0].keys()
       assert 'addresses' in senders[0].keys()

       sender_script = str(senders[0]['script_pubkey'])
       sender_address = str(senders[0]['addresses'][0])

       assert sender_script is not None 
       assert sender_address is not None

       if str(senders[0]['script_type']) == 'pubkeyhash':
          sender_pubkey_hex = get_public_key_hex_from_tx( inputs, sender_address )

    except Exception, e:
       log.exception(e)
       raise Exception("Failed to extract")

    parsed_payload = parse( payload )
    assert parsed_payload is not None 

    ret = {
       "sender": sender_script,
       "address": sender_address,
       "block_number": block_id,
       "vtxindex": vtxindex,
       "txid": txid,
       "op": ANNOUNCE
    }

    ret.update( parsed_payload )

    if sender_pubkey_hex is not None:
        ret['sender_pubkey'] = sender_pubkey_hex

    return ret


def make_outputs( data, inputs, change_address, pay_fee=True ):
    """
    Make outputs for an announcement.
    """

    dust_fee = None
    op_fee = None
    dust_value = None 
    
    outputs = [
        # main output
        {"script_hex": make_op_return_script(data, format='hex'),
         "value": 0},
        
        # change output
        {"script_hex": make_pay_to_address_script(change_address),
         "value": calculate_change_amount(inputs, 0, 0)}
    ]

    dust_fee = tx_dust_fee_from_inputs_and_outputs( inputs, outputs )

    if pay_fee:
        outputs[1]['value'] = calculate_change_amount( inputs, 0, dust_fee )

    return outputs


def broadcast(message_hash, private_key, blockchain_client, testset=False, blockchain_broadcaster=None, user_public_key=None, tx_only=False):
    
    # sanity check 
    pay_fee = True
    if user_public_key is not None:
        pay_fee = False
        tx_only = True

    if user_public_key is None and private_key is None:
        raise Exception("Missing both public and private key")
    
    if not tx_only and private_key is None:
        raise Exception("Need private key for broadcasting")
    
    if len(message_hash) != 40:
        raise Exception("Invalid message hash: not 20 bytes")

    if not is_hex( message_hash ):
        raise Exception("Invalid message hash: not hex")

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
        
        private_key_obj, from_address, inputs = analyze_private_key(private_key, blockchain_client)
         
    nulldata = build(message_hash, testset=testset)
    outputs = make_outputs( nulldata, inputs, from_address, pay_fee=pay_fee )
   
    if tx_only:
       
        unsigned_tx = serialize_transaction( inputs, outputs )
        return {'unsigned_tx': unsigned_tx}

    else:
       
        signed_tx = tx_serialize_and_sign( inputs, outputs, private_key_obj )
        response = broadcast_transaction( signed_tx, blockchain_broadcaster )
        response.update({'data': nulldata})
        return response


def parse(bin_payload):    
    """
    Interpret a block's nulldata back into a SHA256.  The first three bytes (2 magic + 1 opcode)
    will not be present in bin_payload.
    """
    
    message_hash = hexlify(bin_payload)
    if not is_hex( message_hash ):
        log.error("Not a message hash")
        return None 

    if len(message_hash) != 40:
        log.error("Not a 160-bit hash")
        return None 

    return {
       'opcode': 'ANNOUNCE',
       'message_hash': message_hash
    }


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
    if not tx_output_is_op_return( outputs[0] ):
        return (None, None) 
    
    if outputs[0]["value"] != 0:
        return (None, None) 
    
    # 1: change address 
    if script_hex_to_address( outputs[1]["script_hex"] ) is None:
        return (None, None)
    
    dust_fee = (len(inputs) + 1) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
    op_fee = 0
    
    return (dust_fee, op_fee)


def restore_delta( name_rec, block_number, history_index, untrusted_db, testset=False ):
    """
    Find the fields in a name record that were changed by an instance of this operation, at the 
    given (block_number, history_index) point in time in the past.  The history_index is the
    index into the list of changes for this name record in the given block.

    Return the fields that were modified on success.
    Return None on error.
    """
    return {}


def snv_consensus_extras( name_rec, block_id, commit, db ):
    """
    Calculate any derived missing data that goes into the check() operation,
    given the block number, the name record at the block number, and the db.
    """
    return {}
