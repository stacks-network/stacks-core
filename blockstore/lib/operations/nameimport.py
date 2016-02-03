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

from pybitcoin import embed_data_in_blockchain, \
    analyze_private_key, serialize_sign_and_broadcast, make_op_return_script, \
    make_pay_to_address_script, b58check_encode, b58check_decode, serialize_transaction
 
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
    'recipient',            # scriptPubKey hex that identifies the name recipient 
    'recipient_address'     # address of the recipient
]


def get_import_recipient_from_outputs( outputs ):
    """
    Given the outputs from a name import operation,
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


def get_import_update_hash_from_outputs( outputs, recipient ):
    """
    This is meant for NAME_IMPORT operations, which 
    have five outputs:  the OP_RETURN, the sender (i.e.
    the namespace owner), the name's recipient, the
    name's update hash, and the burn output.
    This method extracts the name update hash from
    the list of outputs.
    
    By construction, the update hash address in 
    the NAME_IMPORT operation is the first 
    non-OP_RETURN output that is *not* the recipient.
    It is also a pay-to-pubkey-hash script
    """
    
    ret = None
    count = 0
    for output in outputs:
       
        output_script = output['scriptPubKey']
        output_asm = output_script.get('asm')
        output_hex = output_script.get('hex')
        output_addresses = output_script.get('addresses')
        
        if output_asm[0:9] != 'OP_RETURN' and output_hex is not None and output_hex != recipient:
           
            assert len(output_addresses) == 1, "Not a single-address transaction"
            ret = hexlify( b58check_decode( str(output_addresses[0]) ) )
            break
            
    if ret is None:
       raise Exception("No update hash found")
    
    return ret 


def build(name, testset=False):
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
    hex_script = blockstore_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script, testset=testset)
    
    return packaged_script


def tx_extract( payload, senders, inputs, outputs ):
    """
    Extract and return a dict of fields from the underlying blockchain transaction data
    that are useful to this operation.

    Required (+ parse)
    sender:  the script_pubkey (as a hex string) of the principal that sent the name import transaction
    address:  the address from the sender script
    recipient:  the script_pubkey (as a hex string) of the principal that is meant to receive the name
    recipient_address:  the address from the recipient script
    import_update_hash:  the hash of the data belonging to the recipient

    Optional:
    sender_pubkey_hex: the public key of the sender
    """
  
    sender = None 
    sender_address = None 
    sender_pubkey_hex = None

    recipient = None 
    recipient_address = None 

    import_update_hash = None

    try:
       recipient = get_import_recipient_from_outputs( outputs )
       recipient_address = pybitcoin.script_hex_to_address( recipient )

       assert recipient is not None 
       assert recipient_address is not None
       
       import_update_hash = get_import_update_hash_from_outputs( outputs, recipient )
       assert import_update_hash is not None
       assert is_hex( import_update_hash )

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

    parsed_payload = parse( payload, recipient, import_update_hash )
    assert parsed_payload is not None 

    ret = {
       "sender": sender,
       "address": sender_address,
       "recipient": recipient,
       "recipient_address": recipient_address,
       "update_hash": import_update_hash
    }

    ret.update( parsed_payload )

    if sender_pubkey_hex is not None:
        ret['sender_pubkey'] = sender_pubkey_hex

    return ret


def make_outputs( data, inputs, recipient_address, sender_address, update_hash_b58, format='bin'):
    """
    Builds the outputs for a name import:
    * [0] is the OP_RETURN 
    * [1] is the new owner (recipient)
    * [2] is the update hash
    * [3] is the change sent to the original owner
    """
    
    dust_value = DEFAULT_DUST_FEE
    
    outputs = [
        # main output
        {"script_hex": make_op_return_script(data, format=format),
         "value": 0},
    
        # recipient output
        {"script_hex": make_pay_to_address_script(recipient_address),
         "value": dust_value},
        
        # update hash output
        {"script_hex": make_pay_to_address_script(update_hash_b58),
         "value": dust_value},
        
        # change output
        {"script_hex": make_pay_to_address_script(sender_address),
         "value": calculate_change_amount(inputs, 0, 0)}
    ]

    dust_fee = tx_dust_fee_from_inputs_and_outputs( inputs, outputs )
    outputs[-1]['value'] = calculate_change_amount( inputs, 2*dust_value, dust_fee )
    return outputs
    


def broadcast(name, recipient_address, update_hash, private_key, blockchain_client, blockchain_broadcaster=None, tx_only=False, testset=False):
   
    if blockchain_broadcaster is None:
        blockchain_broadcaster = blockchain_client 
    
    nulldata = build(name, testset=testset)
    
    # convert update_hash from a hex string so it looks like an address
    update_hash_b58 = b58check_encode( unhexlify(update_hash) )
    
    # get inputs and from address
    private_key_obj, from_address, inputs = analyze_private_key(private_key, blockchain_client)
    
    # NAME_IMPORT outputs
    outputs = make_outputs(nulldata, inputs, recipient_address, from_address, update_hash_b58, format='hex')
    
    if tx_only:
        
        unsigned_tx = serialize_transaction( inputs, outputs )
        return {"unsigned_tx": unsigned_tx}
    
    else:
        # serialize, sign, and broadcast the tx
        response = serialize_sign_and_broadcast(inputs, outputs, private_key_obj, blockchain_broadcaster)
        
        # response = {'success': True }
        response.update({'data': nulldata})
        
        # return the response
        return response


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
    Blockstore currently does not allow 
    the subsidization of namespaces.
    """
    return (None, None)


def restore_delta( name_rec, block_number, history_index, untrusted_db, testset=False ):
    """
    Find the fields in a name record that were changed by an instance of this operation, at the 
    given (block_number, history_index) point in time in the past.  The history_index is the
    index into the list of changes for this name record in the given block.

    Return the fields that were modified on success.
    Return None on error.
    """

    # sanity check... 
    if 'importer' not in name_rec.keys() or 'importer_address' not in name_rec.keys():
        raise Exception("Name was not imported")

    recipient = str(name_rec['sender'])
    recipient_address = str(name_rec['address'])
    sender = str(name_rec['importer'])
    address = str(name_rec['importer_address'])

    name_rec_script = build( str(name_rec['name']), testset=testset )
    name_rec_payload = unhexlify( name_rec_script )[3:]
    ret_op = parse( name_rec_payload, recipient, str(name_rec['value_hash']) )

    # reconstruct recipient and sender...
    ret_op['recipient'] = recipient
    ret_op['recipient_address'] = recipient_address 
    ret_op['sender'] = sender 
    ret_op['address'] = address

    return ret_op


def consensus_extras( name_rec, block_id, db ):
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


