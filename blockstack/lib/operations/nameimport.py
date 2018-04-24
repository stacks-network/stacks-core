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

import keylib
from binascii import hexlify, unhexlify

from ..config import *
from ..scripts import *
from ..hashing import *
from ..nameset import *

# consensus hash fields (ORDER MATTERS!) 
FIELDS = NAMEREC_FIELDS[:] + [
    'sender',            # scriptPubKey hex that identifies the name recipient
    'address'            # address of the recipient
]

# fields that change when applying this operation 
MUTATE_FIELDS = NAMEREC_MUTATE_FIELDS[:] + [
    'value_hash',
    'sender',
    'sender_pubkey',
    'address',
    'importer',
    'importer_address',
    'preorder_hash',
    'preorder_block_number',
    'first_registered',
    'last_renewed',
    'revoked',
    'block_number',
    'namespace_block_number',
    'op_fee',
    'last_creation_op',
]

def get_import_recipient_from_outputs( outputs ):
    """
    Given the outputs from a name import operation,
    find the recipient's script hex.
    
    By construction, it will be the first non-OP_RETURN 
    output (i.e. the second output).
    """
    
    if len(outputs) < 2:
        raise Exception("No recipients found")

    return outputs[1]['script']


def get_import_update_hash_from_outputs( outputs ):
    """
    This is meant for NAME_IMPORT operations, which 
    have five outputs:  the OP_RETURN, the sender (i.e.
    the namespace owner), the name's recipient, the
    name's update hash, and the burn output.
    This method extracts the name update hash from
    the list of outputs.
    
    By construction, the update hash address is the 3rd output. 
    """
    
    if len(outputs) < 3:
        raise Exception("No update hash found")

    update_addr = None
    try:
        update_addr = virtualchain.script_hex_to_address(outputs[2]['script'])
        assert update_addr
    except:
        log.error("Invalid update output: {}".format(outputs[2]['script']))
        raise Exception("No update hash found")

    return hexlify(keylib.b58check.b58check_decode(update_addr))


def get_prev_imported( state_engine, checked_ops, name ):
    """
    See if a name has been imported previously--either in 
    this block, or in the last operation on this name.
    Check the DB *and* current ops.
    Make sure the returned record has the name history
    """
    '''
    imported = find_by_opcode( checked_ops, "NAME_IMPORT" )
    for opdata in reversed(imported):
        if opdata['name'] == name:
            hist = state_engine.get_name_history(name)
            ret = copy.deepcopy(opdata)
            ret['history'] = hist
            return ret
    '''
    name_rec = state_engine.get_name( name )
    return name_rec


def is_earlier_than( nameop1, block_id, vtxindex ):
    """
    Does nameop1 come before bock_id and vtxindex?
    """
    return nameop1['block_number'] < block_id or (nameop1['block_number'] == block_id and nameop1['vtxindex'] < vtxindex)


@state_create( "name", "name_records", "check_noop_collision", always_set=["consensus_hash"] )
def check( state_engine, nameop, block_id, checked_ops ):
    """
    Given a NAME_IMPORT nameop, see if we can import it.
    * the name must be well-formed
    * the namespace must be revealed, but not ready
    * the name cannot have been imported yet
    * the sender must be the same as the namespace's sender

    Set the __preorder__ and __prior_history__ fields, since this
    is a state-creating operation.

    Return True if accepted
    Return False if not
    """

    from ..nameset import BlockstackDB

    name = str(nameop['name'])
    sender = str(nameop['sender'])
    sender_pubkey = None
    recipient = str(nameop['recipient'])
    recipient_address = str(nameop['recipient_address'])

    preorder_hash = hash_name( nameop['name'], sender, recipient_address )
    log.debug("preorder_hash = %s (%s, %s, %s)" % (preorder_hash, nameop['name'], sender, recipient_address))

    preorder_block_number = block_id
    name_block_number = block_id 
    name_first_registered = block_id
    name_last_renewed = block_id
    # transfer_send_block_id = None

    if not nameop.has_key('sender_pubkey'):
        log.debug("Name import requires a sender_pubkey (i.e. use of a p2pkh transaction)")
        return False

    # name must be well-formed
    if not is_name_valid( name ):
        log.debug("Malformed name '%s'" % name)
        return False

    name_without_namespace = get_name_from_fq_name( name )
    namespace_id = get_namespace_from_name( name )

    # namespace must be revealed, but not ready
    if not state_engine.is_namespace_revealed( namespace_id ):
        log.debug("Namespace '%s' is not revealed" % namespace_id )
        return False

    namespace = state_engine.get_namespace_reveal( namespace_id )

    # sender p2pkh script must use a public key derived from the namespace revealer's public key
    sender_pubkey_hex = str(nameop['sender_pubkey'])
    sender_pubkey = virtualchain.BitcoinPublicKey( str(sender_pubkey_hex) )
    sender_address = sender_pubkey.address()

    import_addresses = BlockstackDB.load_import_keychain( state_engine.working_dir, namespace['namespace_id'] )
    if import_addresses is None:

        # the first name imported must be the revealer's address
        if sender_address != namespace['recipient_address']:
            log.debug("First NAME_IMPORT must come from the namespace revealer's address")
            return False

        # need to generate a keyring from the revealer's public key
        log.debug("Generating %s-key keychain for '%s'" % (NAME_IMPORT_KEYRING_SIZE, namespace_id))
        import_addresses = BlockstackDB.build_import_keychain( state_engine.working_dir, namespace['namespace_id'], sender_pubkey_hex )

    # sender must be the same as the the person who revealed the namespace
    # (i.e. sender's address must be from one of the valid import addresses)
    if sender_address not in import_addresses:
        log.debug("Sender address '%s' is not in the import keychain" % (sender_address))
        return False

    # we can overwrite, but emit a warning
    # search *current* block as well as last block
    prev_name_rec = get_prev_imported( state_engine, checked_ops, name )
    if prev_name_rec is not None and is_earlier_than( prev_name_rec, block_id, nameop['vtxindex'] ):

        log.warning("Overwriting already-imported name '%s'" % name)

        # propagate preorder block number and hash...
        preorder_block_number = prev_name_rec['preorder_block_number']
        name_block_number = prev_name_rec['block_number']
        name_first_registered = prev_name_rec['first_registered']
        name_last_renewed = prev_name_rec['last_renewed']

        log.debug("use previous preorder_hash = %s" % prev_name_rec['preorder_hash'])
        preorder_hash = prev_name_rec['preorder_hash']

    # can never have been preordered
    state_create_put_preorder( nameop, None )

    # carry out the transition 
    del nameop['recipient']
    del nameop['recipient_address']

    nameop['sender'] = recipient
    nameop['address'] = recipient_address
    nameop['importer'] = sender
    nameop['importer_address'] = sender_address
    nameop['op_fee'] = price_name( name_without_namespace, namespace, block_id )
    nameop['namespace_block_number'] = namespace['block_number']
    nameop['consensus_hash'] = None 
    nameop['preorder_hash'] = preorder_hash
    nameop['block_number'] = name_block_number
    nameop['first_registered'] = name_first_registered
    nameop['last_renewed'] = name_last_renewed
    nameop['preorder_block_number'] = preorder_block_number
    nameop['opcode'] = "NAME_IMPORT"

    # not required for consensus, but for SNV
    nameop['last_creation_op'] = NAME_IMPORT

    # good!
    return True


def tx_extract( payload, senders, inputs, outputs, block_id, vtxindex, txid ):
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
       recipient_address = virtualchain.script_hex_to_address( recipient )

       assert recipient is not None 
       assert recipient_address is not None
       
       # import_update_hash = get_import_update_hash_from_outputs( outputs, recipient )
       import_update_hash = get_import_update_hash_from_outputs( outputs )
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
       "value_hash": import_update_hash,
       "revoked": False,
       "vtxindex": vtxindex,
       "txid": txid,
       "first_registered": block_id,        # NOTE: will get deleted if this is a re-import
       "last_renewed": block_id,            # NOTE: will get deleted if this is a re-import
       "op": NAME_IMPORT,
       "opcode": "NAME_IMPORT"
    }

    ret.update( parsed_payload )

    if sender_pubkey_hex is not None:
        ret['sender_pubkey'] = sender_pubkey_hex

    return ret


def parse(bin_payload, recipient, update_hash ):
    """
    # NOTE: first three bytes were stripped
    """
    
    fqn = bin_payload
    if not is_name_valid( fqn ): 
        log.error("Name '%s' is invalid" % fqn)
        return None 

    return {
        'opcode': 'NAME_IMPORT',
        'name': fqn,
        'recipient': recipient,
        'value_hash': update_hash
    }


def canonicalize(parsed_op):
    """
    Get the "canonical form" of this operation, putting it into a form where it can be serialized
    to form a consensus hash.  This method is meant to preserve compatibility across blockstackd releases.

    For NAME_IMPORT, this means:
    * make sure the fee is a float
    """
    assert 'op_fee' in parsed_op
    parsed_op['op_fee'] = float(parsed_op['op_fee'])
    return parsed_op

