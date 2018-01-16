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
FIELDS = NAMEREC_FIELDS[:]

# fields that this operation changes
MUTATE_FIELDS = NAMEREC_MUTATE_FIELDS[:] + [
    'revoked',
    'value_hash'
]

# fields to back up when applying this operation 
BACKUP_FIELDS = NAMEREC_NAME_BACKUP_FIELDS[:] + MUTATE_FIELDS[:] + [
    'consensus_hash'
]


@state_transition("name", "name_records")
def check( state_engine, nameop, block_id, checked_ops ):
    """
    Revoke a name--make it available for registration.
    * it must be well-formed
    * its namespace must be ready.
    * the name must be registered
    * it must be sent by the name owner

    NAME_REVOKE isn't allowed during an import, so the name's namespace must be ready.

    Return True if accepted
    Return False if not
    """

    name = nameop['name']
    sender = nameop['sender']
    namespace_id = get_namespace_from_name( name )

    # name must be well-formed
    if not is_b40( name ) or "+" in name or name.count(".") > 1:
        log.debug("Malformed name '%s': non-base-38 characters" % name)
        return False

    # name must exist
    name_rec = state_engine.get_name( name )
    if name_rec is None:
        log.debug("Name '%s' does not exist" % name)
        return False

    # namespace must be ready
    if not state_engine.is_namespace_ready( namespace_id ):
       log.debug("Namespace '%s' is not ready" % namespace_id )
       return False

    # name must not be revoked
    if state_engine.is_name_revoked( name ):
        log.debug("Name '%s' is revoked" % name)
        return False

    # name must not be expired as of *this* block
    if state_engine.is_name_expired( name, block_id ):
        log.debug("Name '%s' is expired" % name)
        return False

    # name must not be in grace period in this block
    if state_engine.is_name_in_grace_period(name, block_id):
        log.debug("Name '{}' is in the renewal grace period.  It can only be renewed at this time.".format(name))
        return False

    # the name must be registered
    if not state_engine.is_name_registered( name ):
       log.debug("Name '%s' is not registered" % name )
       return False

    # the sender must own this name
    if not state_engine.is_name_owner( name, sender ):
       log.debug("Name '%s' is not owned by %s" % (name, sender))
       return False

    # apply state transition 
    nameop['revoked'] = True
    nameop['value_hash'] = None
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
       "txid": txid,
       "vtxindex": vtxindex,
       "op": NAME_REVOKE
    }

    ret.update( parsed_payload )
   
    """
    if sender_pubkey_hex is not None:
        ret['sender_pubkey'] = sender_pubkey_hex
    else:
        ret['sender_pubkey'] = None
    """

    return ret


def parse(bin_payload):    
    """
    Interpret a block's nulldata back into a name.  The first three bytes (2 magic + 1 opcode)
    will not be present in bin_payload.
    
    The name will be directly represented by the bytes given.
    """
    
    fqn = bin_payload
    if not is_name_valid( fqn ):
        return None 

    return {
       'opcode': 'NAME_REVOKE',
       'name': fqn
    }


def restore_delta( name_rec, block_number, history_index, working_db, untrusted_db ):
    """
    Find the fields in a name record that were changed by an instance of this operation, at the 
    given (block_number, history_index) point in time in the past.  The history_index is the
    index into the list of changes for this name record in the given block.

    Return the fields that were modified on success.
    Return None on error.
    """
    
    from ..nameset import BlockstackDB

    name_rec_script = build_revoke( str(name_rec['name']) )
    name_rec_payload = unhexlify( name_rec_script )[3:]
    ret_op = parse( name_rec_payload )

    return ret_op


def snv_consensus_extras( name_rec, block_id, blockchain_name_data, db ):
    """
    Calculate any derived missing data that goes into the check() operation,
    given the block number, the name record at the block number, and the db.
    """
    return blockstack_client.operations.revoke.snv_consensus_extras( name_rec, block_id, blockchain_name_data )
    '''
    ret_op = {}
    return ret_op
    '''

