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

from ..config import *
from ..scripts import *
from ..hashing import *
from ..nameset import *
from utilitybelt import is_hex

import blockstack_client
from binascii import hexlify, unhexlify

# consensus hash fields (none for announcements)
FIELDS = []

# fields that this operation changes (none)
MUTATE_FIELDS = []

# fields that should be backed up when applying this operation (none)
BACKUP_FIELDS = []


def process_announcement( op ):
    """
    If the announcement is valid, then immediately record it.
    """
    # valid announcement
    announce_hash = op['message_hash']
    announcer_id = op['announcer_id']

    # go get the text...
    announcement_text = blockstack_client.storage.get_announcement( announce_hash )
    if announcement_text is None:
        log.critical( "\n\n(INTERNAL ERROR): Failed to fetch announcement with hash %s from '%s'\n\n" % (announce_hash, announcer_id))

    else:
        log.critical("ANNOUNCEMENT (from %s): %s\n------BEGIN MESSAGE------\n%s\n------END MESSAGE------\n" % (announcer_id, announce_hash, announcement_text))         
        store_announcement( announce_hash, announcement_text )


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


def check( state_engine, nameop, block_id, checked_ops ):
    """
    Log an announcement from the blockstack developers,
    but first verify that it is correct.
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


def restore_delta( name_rec, block_number, history_index, working_db, untrusted_db ):
    """
    Find the fields in a name record that were changed by an instance of this operation, at the 
    given (block_number, history_index) point in time in the past.  The history_index is the
    index into the list of changes for this name record in the given block.

    Return the fields that were modified on success.
    Return None on error.
    """
    return {}


def snv_consensus_extras( new_name_rec, block_id, blockchain_name_data, db ):
    """
    Calculate any derived missing data that goes into the check() operation,
    given the block number, the name record at the block number, and the db.
    """
    return blockstack_client.operations.announce.snv_consensus_extras( new_name_rec, block_id, blockchain_name_data )
    '''
    return {}
    '''
