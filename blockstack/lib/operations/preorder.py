#!/usr/bin/env python2
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

from ..config import *
from ..hashing import *
from ..scripts import *
from ..nameset import *
from binascii import hexlify, unhexlify

import blockstack_client
from blockstack_client.operations import *

# consensus hash fields (ORDER MATTERS!)
FIELDS = [
     'preorder_hash',       # hash(name,sender,register_addr) 
     'consensus_hash',      # consensus hash at time of send
     'sender',              # scriptPubKey hex that identifies the principal that issued the preorder
     'sender_pubkey',       # if sender is a pubkeyhash script, then this is the public key
     'address',             # address from the sender's scriptPubKey
     'block_number',        # block number at which this name was preordered for the first time

     'op',                  # blockstack bytestring describing the operation
     'txid',                # transaction ID
     'vtxindex',            # the index in the block where the tx occurs
     'op_fee',              # blockstack fee (sent to burn address)
]

# fields this operation changes
MUTATE_FIELDS = FIELDS[:]

# fields to back up when processing this operation 
BACKUP_FIELDS = [
    "__all__",
    'burn_address'
]


@state_preorder("check_preorder_collision")
def check( state_engine, nameop, block_id, checked_ops ):
    """
    Verify that a preorder of a name at a particular block number is well-formed

    NOTE: these *can't* be incorporated into namespace-imports,
    since we have no way of knowning which namespace the
    nameop belongs to (it is blinded until registration).
    But that's okay--we don't need to preorder names during
    a namespace import, because we will only accept names
    sent from the importer until the NAMESPACE_REVEAL operation
    is sent.

    Return True if accepted
    Return False if not.
    """

    from .register import get_num_names_owned

    preorder_name_hash = nameop['preorder_hash']
    consensus_hash = nameop['consensus_hash']
    sender = nameop['sender']

    # must be unique in this block
    # NOTE: now checked externally in the @state_preorder decorator

    # must be unique across all pending preorders
    if not state_engine.is_new_preorder( preorder_name_hash ):
        log.debug("Name hash '%s' is already preordered" % preorder_name_hash )
        return False

    # must have a valid consensus hash
    if not state_engine.is_consensus_hash_valid( block_id, consensus_hash ):
        log.debug("Invalid consensus hash '%s'" % consensus_hash )
        return False

    # sender must be beneath quota
    num_names = get_num_names_owned( state_engine, checked_ops, sender ) 
    if num_names >= MAX_NAMES_PER_SENDER:
        log.debug("Sender '%s' exceeded name quota of %s" % (sender, MAX_NAMES_PER_SENDER ))
        return False 

    # burn fee must be present
    if not 'op_fee' in nameop:
        log.debug("Missing preorder fee")
        return False

    return True


def get_preorder_burn_info( outputs ):
    """
    Given the set of outputs, find the fee sent 
    to our burn address.
    
    Return the fee and burn address on success as {'op_fee': ..., 'burn_address': ...}
    Return None if not found
    """
     
    if len(outputs) != 3:
        # not a well-formed preorder 
        return None 
    
    assert outputs[0].has_key('scriptPubKey')
    assert outputs[2].has_key('scriptPubKey')

    data_scriptpubkey = outputs[0]['scriptPubKey']
    burn_scriptpubkey = outputs[2]['scriptPubKey']

    assert data_scriptpubkey.has_key('asm')
    assert burn_scriptpubkey.has_key('hex')
    assert outputs[2].has_key('value')

    if data_scriptpubkey['asm'][0:9] != 'OP_RETURN':
        # not a well-formed preorder
        return None

    if virtualchain.script_hex_to_address(burn_scriptpubkey['hex']) is None:
        # not a well-formed preorder
        return None

    op_fee = int(outputs[2]['value'] * (10**8))
    burn_address = virtualchain.script_hex_to_address(burn_scriptpubkey['hex'])

    return {'op_fee': op_fee, 'burn_address': burn_address}
   

def tx_extract( payload, senders, inputs, outputs, block_id, vtxindex, txid ):
    """
    Extract and return a dict of fields from the underlying blockchain transaction data
    that are useful to this operation.

    Required (+ parse):
    sender:  the script_pubkey (as a hex string) of the principal that sent the name preorder transaction
    address:  the address from the sender script
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

    burn_info = get_preorder_burn_info(outputs)
    if burn_info is None:
        # nope 
        raise Exception("No burn outputs")

    ret = {
       "sender": sender_script,
       "address": sender_address,
       "block_number": block_id,
       "vtxindex": vtxindex,
       "txid": txid,
       "op": NAME_PREORDER
    }

    ret.update( parsed_payload )
    ret.update( burn_info )

    if sender_pubkey_hex is not None:
        ret['sender_pubkey'] = sender_pubkey_hex
    else:
        ret['sender_pubkey'] = None

    return ret


def parse(bin_payload):
    """
    Parse a name preorder.
    NOTE: bin_payload *excludes* the leading 3 bytes (magic + op) returned by build.
    """
    
    if len(bin_payload) != LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash']:
        return None 

    name_hash = hexlify( bin_payload[0:LENGTHS['preorder_name_hash']] )
    consensus_hash = hexlify( bin_payload[LENGTHS['preorder_name_hash']:] )
    
    return {
        'opcode': 'NAME_PREORDER',
        'preorder_hash': name_hash,
        'consensus_hash': consensus_hash
    }


def restore_delta( name_rec, block_number, history_index, working_db, untrusted_db ):
    """
    Find the fields in a name record that were changed by an instance of this operation, at the 
    given (block_number, history_index) point in time in the past.  The history_index is the
    index into the list of changes for this name record in the given block.

    Return the fields that were modified on success.
    Return None on error.
    """

    # reconstruct the previous fields of the preorder op...
    name_rec_script = build_preorder( None, None, None, str(name_rec['consensus_hash']), \
                                      name_hash=str(name_rec['preorder_hash']) )

    name_rec_payload = unhexlify( name_rec_script )[3:]
    ret_delta = parse( name_rec_payload )

    ret_delta['burn_address'] = name_rec['burn_address']
    return ret_delta


def snv_consensus_extras( name_rec, block_id, blockchain_name_data, db ):
    """
    Calculate any derived missing data that goes into the check() operation,
    given the block number, the name record at the block number, and the db.
    """
    return blockstack_client.operations.preorder.snv_consensus_extras( name_rec, block_id, blockchain_name_data )
    '''
    return {}
    '''
