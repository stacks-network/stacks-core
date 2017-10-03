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
from ..scripts import *
from ..hashing import *
from ..nameset import *

import blockstack_client
from blockstack_client.operations import *
from binascii import hexlify, unhexlify

# consensus hash fields (ORDER MATTERS!) 
FIELDS = [
    'preorder_hash',        # hash(namespace_id,sender,reveal_addr)
    'consensus_hash',       # consensus hash at the time issued
    'op',                   # bytecode describing the operation (not necessarily 1 byte)
    'op_fee',               # fee paid for the namespace to the burn address
    'txid',                 # transaction ID
    'vtxindex',             # the index in the block where the tx occurs
    'block_number',         # block number at which this transaction occurred
    'sender',               # scriptPubKey hex from the principal that issued this preorder (identifies the preorderer)
    'sender_pubkey',        # if sender is a p2pkh script, this is the public key
    'address'               # address from the scriptPubKey
]

# save everything
MUTATE_FIELDS = FIELDS[:]

# fields to back up when this operation is applied
BACKUP_FIELDS = [
    "__all__",
    'burn_address'
]

@state_preorder("check_preorder_collision")
def check( state_engine, nameop, block_id, checked_ops ):
    """
    Given a NAMESPACE_PREORDER nameop, see if we can preorder it.
    It must be unqiue.

    Return True if accepted.
    Return False if not.
    """

    namespace_id_hash = nameop['preorder_hash']
    consensus_hash = nameop['consensus_hash']

    # cannot be preordered already
    if not state_engine.is_new_namespace_preorder( namespace_id_hash ):
        log.debug("Namespace preorder '%s' already in use" % namespace_id_hash)
        return False

    # has to have a reasonable consensus hash
    if not state_engine.is_consensus_hash_valid( block_id, consensus_hash ):

        valid_consensus_hashes = state_engine.get_valid_consensus_hashes( block_id )
        log.debug("Invalid consensus hash '%s': expected any of %s" % (consensus_hash, ",".join( valid_consensus_hashes )) )
        return False

    # has to have paid a fee
    if not 'op_fee' in nameop:
        log.debug("Missing namespace preorder fee")
        return False

    return True


def get_namespace_preorder_burn_info( outputs ):
    """
    Given the set of outputs, find the fee sent 
    to our burn address.
    
    Return the fee and burn address on success as {'op_fee': ..., 'burn_address': ...}
    Return None if not found
    """
    
    if len(outputs) < 3:
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

    Optional:
    sender_pubkey_hex: the public key of the sender
    """
  
    sender_script = None 
    sender_address = None 
    sender_pubkey_hex = None
    burn_info = None

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

       burn_info = get_namespace_preorder_burn_info(outputs)
       assert burn_info

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
       "op": NAMESPACE_PREORDER
    }

    ret.update( parsed_payload )
    ret.update( burn_info )

    if sender_pubkey_hex is not None:
        ret['sender_pubkey'] = sender_pubkey_hex
    
    else:
        ret['sender_pubkey'] = None

    return ret


def parse( bin_payload ):
   """
   NOTE: the first three bytes will be missing
   """
   
   if len(bin_payload) != LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash']:
       log.error("Invalid namespace preorder payload length %s" % len(bin_payload))
       return None

   namespace_id_hash = bin_payload[ :LENGTHS['preorder_name_hash'] ]
   consensus_hash = bin_payload[ LENGTHS['preorder_name_hash']: LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash'] ]
   
   namespace_id_hash = hexlify( namespace_id_hash )
   consensus_hash = hexlify( consensus_hash )
   
   return {
      'opcode': 'NAMESPACE_PREORDER',
      'preorder_hash': namespace_id_hash,
      'consensus_hash': consensus_hash
   }


def restore_delta( rec, block_number, history_index, working_db, untrusted_db ):
    """
    Find the fields in a name record that were changed by an instance of this operation, at the 
    given (block_number, history_index) point in time in the past.  The history_index is the
    index into the list of changes for this name record in the given block.

    Return the fields that were modified on success.
    Return None on error.
    """

    from ..nameset import BlockstackDB 

    name_rec_script = build_namespace_preorder( None, None, None, str(rec['consensus_hash']), namespace_id_hash=str(rec['preorder_hash']) )
    name_rec_payload = unhexlify( name_rec_script )[3:]
    ret_op = parse(name_rec_payload)

    ret_op['burn_address'] = rec['burn_address']
    return ret_op


def snv_consensus_extras( name_rec, block_id, blockchain_name_data, db ):
    """
    Calculate any derived missing data that goes into the check() operation,
    given the block number, the name record at the block number, and the db.
    """
    return blockstack_client.operations.namespacepreorder.snv_consensus_extras( name_rec, block_id, blockchain_name_data )
