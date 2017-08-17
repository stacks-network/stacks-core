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

from ..b40 import *
from ..config import *
from ..hashing import *
from ..scripts import *
from ..nameset import *

from binascii import hexlify, unhexlify

import blockstack_client
from blockstack_client.operations import *

import virtualchain
log = virtualchain.get_logger("blockstack-server")

from namespacereveal import FIELDS as NAMESPACE_REVEAL_FIELDS

# consensus hash fields (ORDER MATTERS!) 
FIELDS = NAMESPACE_REVEAL_FIELDS[:] + [
    'ready_block',      # block number at which the namespace was readied
]

# fields this operation changes
MUTATE_FIELDS = NAMEREC_MUTATE_FIELDS[:] + [
    'ready_block',
    'sender'
]

# fields to back up when applying this operation 
BACKUP_FIELDS = NAMESPACE_REVEAL_FIELDS + MUTATE_FIELDS


@state_transition("namespace_id", "namespaces")
def check( state_engine, nameop, block_id, checked_ops ):
    """
    Verify the validity of a NAMESPACE_READY operation.
    It is only valid if it has been imported by the same sender as
    the corresponding NAMESPACE_REVEAL, and the namespace is still
    in the process of being imported.
    """

    namespace_id = nameop['namespace_id']
    sender = nameop['sender']

    # must have been revealed
    if not state_engine.is_namespace_revealed( namespace_id ):
       log.debug("Namespace '%s' is not revealed" % namespace_id )
       return False

    # must have been sent by the same person who revealed it
    revealed_namespace = state_engine.get_namespace_reveal( namespace_id )
    if revealed_namespace['recipient'] != sender:
       log.debug("Namespace '%s' is not owned by '%s' (but by %s)" % (namespace_id, sender, revealed_namespace['recipient']))
       return False

    # can't be ready yet
    if state_engine.is_namespace_ready( namespace_id ):
       # namespace already exists
       log.debug("Namespace '%s' is already registered" % namespace_id )
       return False

    # preserve from revealed 
    nameop['sender_pubkey'] = revealed_namespace['sender_pubkey']
    nameop['address'] = revealed_namespace['address']

    # can commit imported nameops
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
       "ready_block": block_id,
       "vtxindex": vtxindex,
       "txid": txid,
       "op": NAMESPACE_READY
    }

    ret.update( parsed_payload )

    if sender_pubkey_hex is not None:
        ret['sender_pubkey'] = sender_pubkey_hex

    return ret


def parse( bin_payload ):
   """
   NOTE: the first three bytes will be missing
   NOTE: the first byte in bin_payload is a '.'
   """
  
   if len(bin_payload) == 0:
       log.error("empty namespace")
       return None 

   if bin_payload[0] != '.':
       log.error("Missing namespace delimiter '.'")
       return None 

   namespace_id = bin_payload[ 1: ]
   
   # sanity check
   if not is_b40( namespace_id ) or "+" in namespace_id or namespace_id.count(".") > 0:
       log.error("Invalid namespace ID '%s'" % namespace_id)
       return None

   if len(namespace_id) <= 0 or len(namespace_id) > LENGTHS['blockchain_id_namespace_id']:
       log.error("Invalid namespace of length %s" % len(namespace_id))
       return None 

   return {
      'opcode': 'NAMESPACE_READY',
      'namespace_id': namespace_id
   }


def restore_delta( name_rec, block_number, history_index, working_db, untrusted_db ):
    """
    Find the fields in a name record that were changed by an instance of this operation, at the 
    given (block_number, history_index) point in time in the past.  The history_index is the
    index into the list of changes for this name record in the given block.

    Return the fields that were modified on success.
    Return None on error.
    """

    name_rec_script = build_namespace_ready( str(name_rec['namespace_id']) )
    name_rec_payload = unhexlify( name_rec_script )[3:]
    ret_op = parse( name_rec_payload )
    return ret_op


def snv_consensus_extras( name_rec, block_id, blockchain_name_data, db ):
    """
    Calculate any derived missing data that goes into the check() operation,
    given the block number, the name record at the block number, and the db.
    """
    return blockstack_client.operations.namespaceready.snv_consensus_extras( name_rec, block_id, blockchain_name_data )
    '''
    return {}
    '''
