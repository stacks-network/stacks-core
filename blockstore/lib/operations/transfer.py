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


def tx_extract( payload, senders, inputs, outputs ):
    """
    Extract and return a dict of fields from the underlying blockchain transaction data
    that are useful to this operation.

    Required:
    sender:  the script_pubkey (as a hex string) of the principal that sent the transfer transaction
    address:  the address from the sender script
    recipient:  the script_pubkey (as a hex string) of the principal that is meant to receive the name
    recipient_address:  the address from the recipient script

    Optional:
    sender_pubkey_hex: the public key of the sender
    """
  
    sender = None 
    sender_address = None 
    sender_pubkey_hex = None

    recipient = None 
    recipient_address = None 

    try:
       recipient = get_transfer_recipient_from_outputs( outputs )
       recipient_address = pybitcoin.script_hex_to_address( recipient )

       assert recipient is not None 
       assert recipient_address is not None

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

    parsed_payload = parse( payload, recipient )
    assert parsed_payload is not None 

    ret = {
       "sender": sender,
       "address": sender_address,
       "recipient": recipient,
       "recipient_address": recipient_address
    }

    ret.update( parsed_payload )

    if sender_pubkey_hex is not None:
        ret['sender_pubkey'] = sender_pubkey_hex

    return ret


def make_outputs( data, inputs, new_name_owner_address, change_address, pay_fee=True, format='bin' ):
    """
    Builds the outputs for a name transfer operation.
    """
    
    dust_fee = None
    op_fee = None
    dust_value = DEFAULT_DUST_FEE
    
    outputs = [
        # main output
        {"script_hex": make_op_return_script(data, format=format),
         "value": 0},
        # new name owner output
        {"script_hex": make_pay_to_address_script(new_name_owner_address),
         "value": dust_value},
        # change output
        {"script_hex": make_pay_to_address_script(change_address),
         "value": calculate_change_amount(inputs, 0, 0)}
    ]

    if pay_fee:
        dust_fee = tx_dust_fee_from_inputs_and_outputs( inputs, outputs )
        outputs[-1]['value'] = calculate_change_amount( inputs, dust_value, dust_fee )

    return outputs


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


def restore_delta( name_rec, block_number, history_index, untrusted_db, testset=False ):
    """
    Find the fields in a name record that were changed by an instance of this operation, at the 
    given (block_number, history_index) point in time in the past.  The history_index is the
    index into the list of changes for this name record in the given block.

    Return the fields that were modified on success.
    Return None on error.
    """

    from ..nameset import BlockstoreDB 

    # reconstruct the transfer op...
    KEEPDATA_OP = "%s%s" % (NAME_TRANSFER, TRANSFER_KEEP_DATA)
    keep_data = None 

    if name_rec['op'] == KEEPDATA_OP:
        keep_data = True
    else:
        keep_data = False

    # what was the previous owner?
    recipient = str(name_rec['sender'])
    recipient_address = str(name_rec['address'])

    # restore history temporarily...
    untrusted_name_rec = untrusted_db.get_name( str(name_rec['name']) )
    name_rec['history'] = untrusted_name_rec['history']

    # get the previous owner by finding the previous state of the record
    # (which has the previous owner)
    if history_index > 0:
        # prior name change in the same block
        name_rec_prev = BlockstoreDB.restore_from_history( name_rec, block_number )[history_index - 1]
    else:
        # prior name change in an earlier block
        name_rec_prev = BlockstoreDB.restore_from_history( name_rec, block_number - 1 )[history_index - 1]

    sender = name_rec_prev['sender']
    address = name_rec_prev['address']
    consensus_hash = untrusted_db.get_consensus_at( block_number - 1 )
    
    del name_rec['history']

    name_rec_script = build( str(name_rec['name']), keep_data, consensus_hash, testset=testset )
    name_rec_payload = unhexlify( name_rec_script )[3:]
    ret_op = parse( name_rec_payload, recipient )

    # reconstruct recipient and sender 
    ret_op['recipient'] = recipient 
    ret_op['recipient_address'] = recipient_address 
    ret_op['sender'] = sender 
    ret_op['address'] = address
    ret_op['consensus_hash'] = consensus_hash
    ret_op['keep_data'] = keep_data

    return ret_op


def snv_consensus_extras( name_rec, block_id, db ):
    """
    Given a name record most recently affected by an instance of this operation, 
    find the dict of consensus-affecting fields from the operation that are not
    already present in the name record.
    """
    
    ret_op = {}

    # reconstruct the recipient information
    ret_op['recipient'] = str(name_rec['sender'])
    ret_op['recipient_address'] = str(name_rec['address'])

    # reconstruct name_hash, consensus_hash, keep_data
    keep_data = None
    if name_rec['op'][-1] == TRANSFER_KEEP_DATA:
        keep_data = True
    else:
        keep_data = False

    prev_consensus_hash = None

    if 'history' in name_rec.keys():
        # get the previous consensus hash.
        # NOTE: The consensus hash that gets fed into a transfer comes from the last saved consensus hash
        # in the history that is not a PREORDER, if there is a consensus-bearing command earlier in the history.
        # Otherwise, it comes from the hash at the previous the block.
        # This is an artifact from an oversight in the original
        # design of the system, but we have to adjust to it here to return the right consensus data.
        # Search the name record's history backwards for that prior consensus hash.
        for i in xrange(block_id, 0, -1):

            if not name_rec['history'].has_key(i):
                continue

            for h in xrange(len(name_rec['history'][i])-1, -1, -1):

                # log.debug("consider (%s, %s)" % (i, h))

                hist = name_rec['history'][i][h]
                if i == block_id and hist.has_key('vtxindex') and hist['vtxindex'] > name_rec['vtxindex']:
                    # same block, but later update 
                    # log.debug("skip later (%s, %s)" % (i, h))
                    continue 

                if not hist.has_key('consensus_hash'):
                    # log.debug("no consensus hash at (%s, %s)" % (i, h))
                    continue
               
                if hist['opcode'] == "NAME_PREORDER":
                    # out of history
                    # log.debug("out of history at (%s, %s)" % (i, h))
                    break
                
                prev_consensus_hash = hist['consensus_hash']
                break

            if prev_consensus_hash is not None:
                break

    ret_op['keep_data'] = keep_data

    if prev_consensus_hash is not None:
        ret_op['consensus_hash'] = prev_consensus_hash
    else:
        # no prior consensus hash that would have been fed into the transfer
        ret_op['consensus_hash'] = db.get_consensus_at( block_id - 1 )

    ret_op['name_hash'] = hash256_trunc128( str(name_rec['name']) )
    return ret_op


