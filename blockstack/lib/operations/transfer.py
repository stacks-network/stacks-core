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

import blockstack_client
from blockstack_client.operations import *

# consensus hash fields (ORDER MATTERS!) 
FIELDS = NAMEREC_FIELDS[:] + [
    'name_hash128',         # hash(name)
    'consensus_hash',       # consensus hash when this operation was sent
    'keep_data'             # whether or not to keep the profile data associated with the name when transferred
]

# fields this operation mutates
# NOTE: due to an earlier quirk in the design of this system,
# we do NOT write the consensus hash (but we should have)
MUTATE_FIELDS = NAMEREC_MUTATE_FIELDS[:] + [
    'sender',
    'address',
    'sender_pubkey',
    'value_hash',
]

# fields to back up when applying this operation 
BACKUP_FIELDS = NAMEREC_NAME_BACKUP_FIELDS[:] + MUTATE_FIELDS[:] + [
    'consensus_hash'
]


def get_transfer_recipient_from_outputs( outputs ):
    """
    Given the outputs from a name transfer operation,
    find the recipient's script hex.
    
    By construction, it will be the first non-OP_RETURN 
    output (i.e. the second output).

    This also applies to a NAME_IMPORT.
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


def find_last_transfer_consensus_hash( name_rec, block_id, vtxindex ):
    """
    Given a name record, find the last non-NAME_TRANSFER consensus hash.
    Return None if not found.
    """

    from ..nameset import BlockstackDB

    history_keys = name_rec['history'].keys()
    history_keys.sort()
    history_keys.reverse()

    for hk in history_keys:
        history_states = BlockstackDB.restore_from_history( name_rec, hk )

        for history_state in reversed(history_states):
            if history_state['block_number'] > block_id or (history_state['block_number'] == block_id and history_state['vtxindex'] > vtxindex):
                # from the future
                continue

            if history_state['op'][0] == NAME_TRANSFER:
                # skip NAME_TRANSFERS
                continue

            if history_state['op'][0] == NAME_PREORDER:
                # out of history
                return None

            if name_rec['consensus_hash'] is not None:
                return name_rec['consensus_hash']

    return None


@state_transition( "name", "name_records", always_set=['transfer_send_block_id', 'consensus_hash'] )
def check( state_engine, nameop, block_id, checked_ops ):
    """
    Verify the validity of a name's transferrance to another private key.
    The name must exist, not be revoked, and be owned by the sender.
    The recipient must not exceed the maximum allowed number of names per keypair,
    and the recipient cannot own an equivalent name.

    NAME_TRANSFER isn't allowed during an import, so the name's namespace must be ready.

    Return True if accepted
    Return False if not
    """

    name_hash = nameop['name_hash128']
    name = state_engine.get_name_from_name_hash128( name_hash )

    consensus_hash = nameop['consensus_hash']
    sender = nameop['sender']
    recipient_address = nameop['recipient_address']
    recipient = nameop['recipient']
    transfer_send_block_id = None

    if name is None:
       # invalid
       log.debug("No name found for '%s'" % name_hash )
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

    if not state_engine.is_consensus_hash_valid( block_id, consensus_hash ):
       # invalid concensus hash
       log.debug("Invalid consensus hash '%s'" % consensus_hash )
       return False

    if sender == recipient:
       # nonsensical transfer
       log.debug("Sender is the same as the Recipient (%s)" % sender )
       return False

    if not state_engine.is_name_registered( name ):
       # name is not registered
       log.debug("Name '%s' is not registered" % name)
       return False

    if not state_engine.is_name_owner( name, sender ):
       # sender doesn't own the name
       log.debug("Name '%s' is not owned by %s (but %s)" % (name, sender, state_engine.get_name_owner(name)))
       return False

    names_owned = state_engine.get_names_owned_by_sender( recipient )
    if name in names_owned:
        # recipient already owns it 
        log.debug("Recipient %s already owns '%s'" % (recipient, name))
        return False

    if len(names_owned) >= MAX_NAMES_PER_SENDER:
        # exceeds quota 
        log.debug("Recipient %s has exceeded name quota" % recipient)
        return False

    # sender cannot be a p2sh script until we're in an epoch that supports multisig.
    # this is to preserve compatibility with 0.13.
    if virtualchain.is_p2sh_script( sender ) and not epoch_has_multisig( block_id ):
        log.debug("Sender %s is a p2sh script, but multisig is not enabled in epoch %s" % (sender, get_epoch_number(block_id)))
        return False

    # QUIRK: we use either the consensus hash from the last non-NAME_TRANSFER
    # operation, or if none exists, we use the one from the NAME_TRANSFER itself.
    transfer_consensus_hash = find_last_transfer_consensus_hash( name_rec, block_id, nameop['vtxindex'] )
    transfer_send_block_id = state_engine.get_block_from_consensus( nameop['consensus_hash'] )
    if transfer_send_block_id is None:
        # wrong consensus hash 
        log.debug("Unrecognized consensus hash '%s'" % nameop['consensus_hash'] )
        return False 

    # remember the name, so we don't have to look it up later
    nameop['name'] = name

    # carry out transition, putting the operation into the state to be committed
    nameop['sender'] = recipient
    nameop['address'] = recipient_address
    nameop['sender_pubkey'] = None
    nameop['transfer_send_block_id'] = transfer_send_block_id
    nameop['consensus_hash'] = transfer_consensus_hash

    if not nameop['keep_data']:
        nameop['value_hash'] = None
        nameop['op'] = "%s%s" % (NAME_TRANSFER, TRANSFER_REMOVE_DATA)
    else:
        # preserve 
        nameop['value_hash'] = name_rec['value_hash']
        nameop['op'] = "%s%s" % (NAME_TRANSFER, TRANSFER_KEEP_DATA)

    del nameop['recipient']
    del nameop['recipient_address']
    del nameop['keep_data']
    del nameop['name_hash128']

    return True


def tx_extract( payload, senders, inputs, outputs, block_id, vtxindex, txid ):
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
       recipient_address = virtualchain.script_hex_to_address( recipient )

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
       "recipient_address": recipient_address,
       "vtxindex": vtxindex,
       "txid": txid,
       "op": NAME_TRANSFER
    }

    ret.update( parsed_payload )

    if sender_pubkey_hex is not None:
        ret['sender_pubkey'] = sender_pubkey_hex
    else:
        ret['sender_pubkey'] = None

    return ret


def parse(bin_payload, recipient):
    """
    # NOTE: first three bytes were stripped
    """
    
    if len(bin_payload) != 1 + LENGTHS['name_hash'] + LENGTHS['consensus_hash']:
        log.error("Invalid transfer payload length %s" % len(bin_payload))
        return None 

    disposition_char = bin_payload[0:1]
    name_hash128 = bin_payload[1:1+LENGTHS['name_hash']]
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
        'name_hash128': hexlify( name_hash128 ),
        'consensus_hash': hexlify( consensus_hash ),
        'recipient': recipient,
        'keep_data': disposition
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

    # reconstruct the transfer op...
    KEEPDATA_OP = "%s%s" % (NAME_TRANSFER, TRANSFER_KEEP_DATA)
    REMOVEDATA_OP = "%s%s" % (NAME_TRANSFER, TRANSFER_REMOVE_DATA)
    keep_data = None 

    try:
        if name_rec['op'] == KEEPDATA_OP:
            keep_data = True
        elif name_rec['op'] == REMOVEDATA_OP:
            keep_data = False
        else:
            raise Exception("Invalid transfer op sequence '%s'" % name_rec['op'])
    except Exception, e:
        log.exception(e)
        log.error("FATAL: invalid op transfer sequence")
        os.abort()

    # what was the previous owner?
    recipient = str(name_rec['sender'])
    recipient_address = str(name_rec['address'])

    # when was the NAME_TRANSFER sent?
    if not name_rec.has_key('transfer_send_block_id'):
        log.error("FATAL: Obsolete database: no 'transfer_send_block_id' defined")
        os.abort()

    transfer_send_block_id = name_rec['transfer_send_block_id']
    if transfer_send_block_id is None:
        log.error("FATAL: no transfer-send block ID set")
        os.abort()

    # restore history temporarily...
    name_rec_prev = BlockstackDB.get_previous_name_version( name_rec, block_number, history_index, untrusted_db )

    sender = name_rec_prev['sender']
    address = name_rec_prev['address']
    consensus_hash = working_db.get_consensus_at( transfer_send_block_id )
   
    if consensus_hash is None:
        log.error("FATAL: no consensus hash at %s (last block is %s)" % (transfer_send_block_id, working_db.lastblock) )
        log.error("consensus hashes:\n%s" % (json.dumps(working_db.consensus_hashes, indent=4, sort_keys=True)))
        os.abort()

    name_rec_script = build_transfer( str(name_rec['name']), keep_data, consensus_hash )

    name_rec_payload = unhexlify( name_rec_script )[3:]
    ret_op = parse( name_rec_payload, recipient )

    # reconstruct recipient and sender 
    ret_op['recipient'] = recipient 
    ret_op['recipient_address'] = recipient_address 
    ret_op['sender'] = sender 
    ret_op['address'] = address
    ret_op['keep_data'] = keep_data

    if consensus_hash is not None:
        # only set if we have it; otherwise use the one that's in the name record
        # that this delta will be applied over
        ret_op['consensus_hash'] = consensus_hash

    return ret_op


def snv_consensus_extras( name_rec, block_id, blockchain_name_data, db ):
    """
    Given a name record most recently affected by an instance of this operation, 
    find the dict of consensus-affecting fields from the operation that are not
    already present in the name record.

    Specific to NAME_TRANSFER:
    The consensus hash is a field that we snapshot when we discover the transfer,
    but it is not a field that we preserve.  It will instead be present in the
    snapshots database, indexed by the block number in `transfer_send_block_id`.

    (This is an artifact of a design quirk of a previous version of the system).
    """
    
    from __init__ import op_commit_consensus_override

    transfer_send_block_id_consensus_hash = db.get_consensus_at( name_rec['transfer_send_block_id'] )
    assert transfer_send_block_id_consensus_hash is not None, "No transfer send block ID"

    ret_op = blockstack_client.operations.transfer.snv_consensus_extras( name_rec, block_id, blockchain_name_data, transfer_send_block_id_consensus_hash=transfer_send_block_id_consensus_hash )

    # 'consensus_hash' will be different than what we recorded in the db
    op_commit_consensus_override( ret_op, 'consensus_hash' )
    return ret_op

    '''
    from __init__ import op_commit_consensus_override
    from ..nameset import BlockstackDB

    ret_op = {}
    
    # reconstruct the recipient information
    ret_op['recipient'] = str(name_rec['sender'])
    ret_op['recipient_address'] = str(name_rec['address'])

    # reconstruct name_hash, consensus_hash, keep_data
    keep_data = None
    try:
        assert len(name_rec['op']) == 2, "Invalid op sequence '%s'" % (name_rec['op'])
        
        if name_rec['op'][-1] == TRANSFER_KEEP_DATA:
            keep_data = True
        elif name_rec['op'][-1] == TRANSFER_REMOVE_DATA:
            keep_data = False
        else:
            raise Exception("Invalid op sequence '%s'" % (name_rec['op']))

    except Exception, e:
        log.exception(e)
        log.error("FATAL: invalid transfer op sequence")
        os.abort()

    ret_op['keep_data'] = keep_data
    ret_op['name_hash128'] = hash256_trunc128( str(name_rec['name']) )
    ret_op['sender_pubkey'] = None

    if blockchain_name_data is None:

       consensus_hash = find_last_transfer_consensus_hash( name_rec, block_id, name_rec['vtxindex'] )
       ret_op['consensus_hash'] = consensus_hash

    else:
       ret_op['consensus_hash'] = blockchain_name_data['consensus_hash']
      
    if ret_op['consensus_hash'] is None:
       # no prior consensus hash; must be the one in the name operation itself 
       ret_op['consensus_hash'] = db.get_consensus_at( name_rec['transfer_send_block_id'] )
    
    # 'consensus_hash' will be different than what we recorded in the db
    op_commit_consensus_override( ret_op, 'consensus_hash' ) 
    return ret_op
    '''
   
