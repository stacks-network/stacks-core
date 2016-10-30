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

from ..b40 import *
from ..config import *
from ..hashing import *
from ..scripts import *
from ..nameset import *
from binascii import hexlify, unhexlify

import virtualchain
log = virtualchain.get_logger("blockstack-server")

import blockstack_client
from blockstack_client.operations import *

# consensus hash fields (ORDER MATTERS!) 
FIELDS = NAMEREC_FIELDS[:] + [
    'name_consensus_hash',  # hash(name,consensus_hash)
    'consensus_hash'        # consensus hash when this update was sent
]

# fields this operation mutates
MUTATE_FIELDS = NAMEREC_MUTATE_FIELDS[:] + [
    'value_hash',
    'consensus_hash'
]

# fields to back up when applying this operation 
BACKUP_FIELDS = NAMEREC_NAME_BACKUP_FIELDS[:] + MUTATE_FIELDS[:]


def update_sanity_test( name, consensus_hash, data_hash ):
    """
    Verify the validity of an update's data

    Return True if valid
    Raise exception if not
    """
    
    if name is not None and (not is_b40( name ) or "+" in name or name.count(".") > 1):
       raise Exception("Name '%s' has non-base-38 characters" % name)
   
    if data_hash is not None and not is_hex( data_hash ):
       raise Exception("Invalid hex string '%s': not hex" % (data_hash))
    
    if len(data_hash) != 2 * LENGTHS['value_hash']:
       raise Exception("Invalid hex string '%s': bad length" % (data_hash))

    return True


@state_transition("name", "name_records")
def check(state_engine, nameop, block_id, checked_ops ):
    """
    Verify the validity of an update to a name's associated data.
    Use the nameop's 128-bit name hash to find the name itself.

    NAME_UPDATE isn't allowed during an import, so the name's namespace must be ready.

    Return True if accepted
    Return False if not.
    """

    name_consensus_hash = nameop['name_consensus_hash']
    sender = nameop['sender']

    # deny updates if we exceed quota--the only legal operations are to revoke or transfer.
    sender_names = state_engine.get_names_owned_by_sender( sender )
    if len(sender_names) > MAX_NAMES_PER_SENDER:
        log.debug("Sender '%s' has exceeded quota: only transfers or revokes are allowed" % (sender))
        return False

    name, consensus_hash = state_engine.get_name_from_name_consensus_hash( name_consensus_hash, sender, block_id )

    # name must exist
    if name is None or consensus_hash is None:
       log.debug("Unable to resolve name consensus hash '%s' to a name owned by '%s'" % (name_consensus_hash, sender))
       # nothing to do--write is stale or on a fork
       return False

    namespace_id = get_namespace_from_name( name )
    name_rec = state_engine.get_name( name )

    if name_rec is None:
       log.debug("Name '%s' does not exist" % name)
       return False

    # namespace must be ready
    if not state_engine.is_namespace_ready( namespace_id ):
       # non-existent namespace
       log.debug("Namespace '%s' is not ready" % (namespace_id))
       return False

    # name must not be revoked
    if state_engine.is_name_revoked( name ):
        log.debug("Name '%s' is revoked" % name)
        return False

    # name must not be expired
    if state_engine.is_name_expired( name, state_engine.lastblock ):
        log.debug("Name '%s' is expired" % name)
        return False

    # the name must be registered
    if not state_engine.is_name_registered( name ):
        # doesn't exist
        log.debug("Name '%s' is not registered" % name )
        return False

    # the name must be owned by the same person who sent this nameop
    if not state_engine.is_name_owner( name, sender ):
        # wrong owner
        log.debug("Name '%s' is not owned by '%s'" % (name, sender))
        return False

    # remember the name and consensus hash, so we don't have to re-calculate it...
    nameop['name'] = name
    nameop['consensus_hash'] = consensus_hash
    nameop['sender_pubkey'] = name_rec['sender_pubkey']

    # not stored, but re-calculateable
    del nameop['name_consensus_hash']

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
       "vtxindex": vtxindex,
       "txid": txid,
       "op": NAME_UPDATE
    }

    ret.update( parsed_payload )

    if sender_pubkey_hex is not None:
        ret['sender_pubkey'] = sender_pubkey_hex

    return ret


def parse(bin_payload):
    """
    Parse a payload to get back the name and update hash.
    NOTE: bin_payload excludes the leading three bytes.
    """
    
    if len(bin_payload) != LENGTHS['name_consensus_hash'] + LENGTHS['value_hash']:
        log.error("Invalid update length %s" % len(bin_payload))
        return None 

    name_consensus_hash_bin = bin_payload[:LENGTHS['name_consensus_hash']]
    value_hash_bin = bin_payload[LENGTHS['name_consensus_hash']:]
    
    name_consensus_hash = hexlify( name_consensus_hash_bin )
    value_hash = hexlify( value_hash_bin )
  
    try:
        rc = update_sanity_test( None, name_consensus_hash, value_hash )
        if not rc:
            raise Exception("Invalid update data")
    except Exception, e:
        log.error("Invalid update data")
        return None

    return {
        'opcode': 'NAME_UPDATE',
        'name_consensus_hash': name_consensus_hash,
        'value_hash': value_hash
    }


def restore_delta( name_rec, block_number, history_index, working_db, untrusted_db ):
    """
    Find the fields in a name record that were changed by an instance of this operation, at the 
    given (block_number, history_index) point in time in the past.  The history_index is the
    index into the list of changes for this name record in the given block.

    Return the fields that were modified on success.
    Return None on error.
    """
    
    data_hash = None
    if name_rec['value_hash'] is not None:
       data_hash = str(name_rec['value_hash'])

    name_rec_script = build_update( str(name_rec['name']), str(name_rec['consensus_hash']), data_hash=data_hash )
    name_rec_payload = unhexlify( name_rec_script )[3:]
    ret_op = parse(name_rec_payload)

    return ret_op


def snv_consensus_extras( name_rec, block_id, blockchain_name_data, db ):
    """
    Given a name record most recently affected by an instance of this operation, 
    find the dict of consensus-affecting fields from the operation that are not
    already present in the name record.
    """
    return blockstack_client.operations.update.snv_consensus_extras( name_rec, block_id, blockchain_name_data )
    '''
    ret_op = {}

    # reconstruct name_hash
    ret_op['name_consensus_hash'] = hash256_trunc128( str(name_rec['name']) + str(name_rec['consensus_hash']) )
    return ret_op
    '''


