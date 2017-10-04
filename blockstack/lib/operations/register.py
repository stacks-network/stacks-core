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

import virtualchain
log = virtualchain.get_logger("blockstack-server")

# consensus hash fields (ORDER MATTERS!)
FIELDS = NAMEREC_FIELDS + [
    'sender',     # scriptPubKey hex script that identifies the principal to own this name
    'address'     # principal's address from the scriptPubKey in the transaction
]

# fields this operation changes
REGISTER_MUTATE_FIELDS = NAMEREC_MUTATE_FIELDS + [
    'last_renewed',
    'first_registered',
    'revoked',
    'sender',
    'address',
    'sender_pubkey',
    'name',
    'value_hash',
    'importer',
    'importer_address',
    'preorder_hash',
    'preorder_block_number',
    'consensus_hash',
    'op_fee',
    'last_creation_op'
]

# fields renewal changes
RENEWAL_MUTATE_FIELDS = NAMEREC_MUTATE_FIELDS + [
    'last_renewed',
    'sender',
    'address',
    'sender_pubkey',
    'value_hash',
    'op_fee'
]

# fields to back up when applying this operation 
REGISTER_BACKUP_FIELDS = NAMEREC_NAME_BACKUP_FIELDS[:] + REGISTER_MUTATE_FIELDS[:] + ['burn_address']

RENEWAL_BACKUP_FIELDS = NAMEREC_NAME_BACKUP_FIELDS[:] + RENEWAL_MUTATE_FIELDS[:] + [
    'consensus_hash'
]


def get_registration_recipient_from_outputs( outputs ):
    """
    There are three or four outputs:  the OP_RETURN, the registration 
    address, the change address (i.e. from the name preorderer), and 
    (for renwals) the burn address for the renewal fee.
    
    Given the outputs from a name register operation,
    find the registration address's script hex.
    
    By construction, it will be the first non-OP_RETURN 
    output (i.e. the second output).
    """

    if len(outputs) < 2:
        raise Exception("Malformed registration outputs: less than 2")
    
    assert outputs[0].has_key('scriptPubKey')
    assert outputs[1].has_key('scriptPubKey')

    data_scriptpubkey = outputs[0]['scriptPubKey']
    recipient_scriptpubkey = outputs[1]['scriptPubKey']

    assert data_scriptpubkey.has_key('asm')
    assert recipient_scriptpubkey.has_key('hex')

    if data_scriptpubkey['asm'][0:9] != 'OP_RETURN':
        raise Exception("Malformed registration outputs: first output is not an OP_RETURN")

    return recipient_scriptpubkey['hex']


def get_renew_burn_info( outputs ):
    """
    There are four poutputs: the OP_RETURN, the registration (owner)
    address, the change address (i.e. from the preorderer), and the
    burn address with the renewal fee.

    Get the burn address and value
    """
    if len(outputs) < 4:
        raise Exception("Malformed renew outputs: don't have 4")

    assert outputs[0].has_key('scriptPubKey')
    assert outputs[3].has_key('scriptPubKey')

    data_scriptpubkey = outputs[0]['scriptPubKey']
    burn_scriptpubkey = outputs[3]['scriptPubKey']

    assert data_scriptpubkey.has_key('asm')
    assert burn_scriptpubkey.has_key('hex')

    if data_scriptpubkey['asm'][0:9] != 'OP_RETURN':
        raise Exception("Malformed renew outputs: first output is not an OP_RETURN")

    addr = virtualchain.script_hex_to_address(burn_scriptpubkey['hex'])
    if addr is None:
        raise Exception("Malformed renew outputs: last output has a nonstandard script")

    op_fee = int(outputs[3]['value'] * (10**8))
    return {'burn_address': addr, 'op_fee': op_fee}


def get_num_names_owned( state_engine, checked_ops, sender ):
    """
    Find out how many preorders a given sender (i.e. a script)
    actually owns, as of this transaction.
    """
    
    count = 0
    registers = find_by_opcode( checked_ops, "NAME_REGISTRATION" )

    for reg in registers:
        if reg['sender'] == sender:
            count += 1

    count += len( state_engine.get_names_owned_by_sender( sender ) )
    log.debug("Sender '%s' owns %s names" % (sender, count))
    return count


def check_burn_address(namespace, burn_address, block_id):
    """
    Verify that the burn fee went to the right address
    """
    # fee must be paid to the right address.
    # pre F-day 2017: this *must* be the burn address, and the namespace *must* be version 1
    # post F-day 2017: this *may* be the namespace creator's address
    epoch_features = get_epoch_features(block_id)
    receive_fees_period = get_epoch_namespace_receive_fees_period(block_id, namespace['namespace_id'])
    expected_burn_address = None

    if EPOCH_FEATURE_NAMESPACE_BURN_TO_CREATOR in epoch_features:
        if (namespace['version'] & NAMESPACE_VERSION_PAY_TO_CREATOR):
            # can only burn to namespace if the namespace is young enough (starts counting from NAMESPACE_REVEAL)
            if namespace['reveal_block'] + receive_fees_period >= block_id:
                log.debug("Register must pay to v2 namespace address {}".format(namespace['address']))
                expected_burn_address = namespace['address']
            else:
                log.debug("Register must pay to burn address, since the namespace has passed its fee-capture period")
                expected_burn_address = BLOCKSTACK_BURN_ADDRESS
        else:
            log.debug("Register must pay to burn address, since the namespace does not support pay-to-creator")
            expected_burn_address = BLOCKSTACK_BURN_ADDRESS

    else:
        log.debug("Register must pay to burn address, since the pay-to-creator is not supported in this epoch")
        expected_burn_address = BLOCKSTACK_BURN_ADDRESS

    if expected_burn_address != burn_address:
        log.debug("Register/renew sends fee to {}, but namespace expects {}".format(burn_address, expected_burn_address))
        return False
    else:
        log.debug("Sending register/renewal fee to {}".format(burn_address))

    return True


@state_create( "name", "name_records", "check_name_collision" )
def check_register( state_engine, nameop, block_id, checked_ops ):
    """
    Verify the validity of a registration nameop.
    * the name must be well-formed
    * the namespace must be ready
    * the name does not collide
    * either the name was preordered by the same sender, or the name exists and is owned by this sender (the name cannot be registered and owned by someone else)
    * the mining fee must be high enough.
    * if the name was expired, then merge the preorder information from the expired preorder (since this is a state-creating operation,
    we set the __preorder__ and __prior_history__ fields to preserve this).

    NAME_REGISTRATION is not allowed during a namespace import, so the namespace must be ready.

    Return True if accepted.
    Return False if not.
    """

    from ..nameset import BlockstackDB 

    name = nameop['name']
    sender = nameop['sender']

    # address mixed into the preorder
    register_addr = nameop.get('recipient_address', None)
    if register_addr is None:
        log.debug("No registration address given")
        return False

    recipient = nameop.get('recipient', None)
    if recipient is None:
        log.debug("No recipient script given")
        return False

    epoch_features = get_epoch_features(block_id)

    name_fee = None
    namespace = None
    preorder_hash = None
    preorder_block_number = None 
    name_block_number = None
    consensus_hash = None
    transfer_send_block_id = None
    fee_block_id = None         # block ID at which the fee was paid
    burn_address = None         # preorder/renew burn address
    opcode = nameop['opcode']
    first_registered = nameop['first_registered']

    # name must be well-formed
    if not is_b40( name ) or "+" in name or name.count(".") > 1:
        log.debug("Malformed name '%s': non-base-38 characters" % name)
        return False

    # name must not be revoked
    if state_engine.is_name_revoked( name ):
        log.debug("Name '%s' is revoked" % name)
        return False

    namespace_id = get_namespace_from_name( name )

    # namespace must exist and be ready
    if not state_engine.is_namespace_ready( namespace_id ):
        log.debug("Namespace '%s' is not ready" % namespace_id)
        return False

    # get namespace...
    namespace = state_engine.get_namespace( namespace_id )

    # cannot exceed quota
    num_names = get_num_names_owned( state_engine, checked_ops, recipient )
    if num_names >= MAX_NAMES_PER_SENDER:
        log.debug("Recipient '%s' has exceeded quota" % recipient)
        return False

    # if multisig is not enabled in this epoch, and the recipient
    # address is a p2sh address, then reject the transaction.
    # this if for compatibility with 0.13
    if virtualchain.is_multisig_address( register_addr ) and not epoch_has_multisig( block_id ):
        log.debug("Multisig registration address %s, but this epoch (%s) does not support multisig" % (register_addr, get_epoch_number(block_id)))
        return False

    # get preorder...
    preorder = state_engine.get_name_preorder( name, sender, register_addr )
    old_name_rec = state_engine.get_name( name, include_expired=True )

    if preorder is not None:
        # Case 1(a-b): registering or re-registering from a preorder

        # can't be registered already 
        if state_engine.is_name_registered( name ):
            log.debug("Name '%s' is already registered" % name)
            return False 

        # name can't be registered if it was reordered before its namespace was ready
        if not namespace.has_key('ready_block') or preorder['block_number'] < namespace['ready_block']:
           log.debug("Name '%s' preordered before namespace '%s' was ready" % (name, namespace_id))
           return False

        # name must be preordered by the same sender
        if preorder['sender'] != sender:
           log.debug("Name '%s' was not preordered by %s" % (name, sender))
           return False

        # fee was included in the preorder
        if not 'op_fee' in preorder:
           log.debug("Name '%s' preorder did not pay the fee" % (name))
           return False

        name_fee = preorder['op_fee']
        preorder_hash = preorder['preorder_hash']
        preorder_block_number = preorder['block_number']
        fee_block_id = preorder_block_number
        burn_address = preorder['burn_address']

        # pass along the preorder
        state_create_put_preorder( nameop, preorder )

        if old_name_rec is None:
            # Case 1(a): registered for the first time ever 
            log.debug("Registering name '%s'" % name)
            name_block_number = preorder['block_number']
            state_create_put_prior_history( nameop, None )
        
        else:
            # Case 1(b): name expired, and is now re-registered
            log.debug("Re-registering name '%s'" % name )
        
            # push back preorder block number to the original preorder
            name_block_number = old_name_rec['block_number']
            transfer_send_block_id = old_name_rec['transfer_send_block_id']

            # re-registering
            prior_hist = prior_history_create( nameop, old_name_rec, preorder_block_number, state_engine, extra_backup_fields=['consensus_hash','preorder_hash','transfer_send_block_id','op_fee','last_creation_op']) 
            state_create_put_prior_history( nameop, prior_hist )


    elif state_engine.is_name_registered( name ):
        # Case 2: we're renewing
        assert 'burn_address' in nameop, 'BUG: no burn address set in nameop'

        # pre F-day 2017: name must be owned by the recipient already
        # post F-day 2017: recipient can be anybody
        if EPOCH_FEATURE_OP_RENEW_TRANSFER_UPDATE not in epoch_features:
            # pre F-day 2017
            if not state_engine.is_name_owner( name, recipient ):
                log.debug("Renew: Name '%s' is registered but not owned by recipient %s" % (name, recipient))
                return False

        # name must be owned by the sender
        if not state_engine.is_name_owner( name, sender ):
            log.debug("Renew: Name '%s' is registered but not owned by sender %s" % (name, sender))
            return False

        # fee borne by the renewal
        if not 'op_fee' in nameop or nameop['op_fee'] is None:
            log.debug("Renew: Name '%s' is registered but renewal did not pay the fee" % (name))
            return False
        
        log.debug("Renewing name '%s'" % name )
        if not state_engine.is_name_owner( name, recipient ):
            log.debug("Transferring name '{}' to {}".format(name, recipient))

        prev_name_rec = state_engine.get_name( name )
        
        first_registered = prev_name_rec['first_registered']
        preorder_block_number = prev_name_rec['preorder_block_number']
        name_block_number = prev_name_rec['block_number']
        name_fee = nameop['op_fee']
        preorder_hash = prev_name_rec['preorder_hash']
        transfer_send_block_id = prev_name_rec['transfer_send_block_id']
        fee_block_id = block_id

        burn_address = nameop['burn_address']
        opcode = "NAME_RENEWAL"     # will cause this operation to be re-checked under check_renewal()

        # pass along prior history 
        prior_hist = prior_history_create( nameop, old_name_rec, block_id, state_engine, extra_backup_fields=['consensus_hash','preorder_hash','transfer_send_block_id','op_fee','last_creation_op'])
        state_create_put_prior_history( nameop, prior_hist )
        state_create_put_preorder( nameop, None ) 

    else:
        # Case 3: has never existed, and not preordered
        log.debug("Name '%s' does not exist, or is not preordered by %s" % (name, sender))
        return False

    assert name_fee is not None

    # check name fee
    name_without_namespace = get_name_from_fq_name( name )

    # fee must be high enough (either the preorder paid the right fee at the preorder block height,
    # or the renewal paid the right fee at the renewal height)
    if name_fee < price_name( name_without_namespace, namespace, fee_block_id ):
        log.debug("Name '%s' costs %s, but paid %s" % (name, price_name( name_without_namespace, namespace, block_id ), name_fee ))
        return False
 
    # fee must be paid to the right address, at the right time.
    # pre F-day 2017: this *must* be the burn address, and the namespace *must* be version 1
    # post F-day 2017: this *may* be the namespace creator's address
    if not check_burn_address(namespace, burn_address, fee_block_id):
        log.debug("Invalid burn address {}".format(burn_address))
        return False

    nameop['opcode'] = opcode
    nameop['op_fee'] = name_fee
    nameop['preorder_hash'] = preorder_hash
    nameop['importer'] = None
    nameop['importer_address'] = None
    nameop['consensus_hash'] = consensus_hash
    nameop['revoked'] = False
    nameop['namespace_block_number'] = namespace['block_number']
    nameop['first_registered'] = first_registered
    nameop['last_renewed'] = block_id
    nameop['preorder_block_number'] = preorder_block_number
    nameop['block_number'] = name_block_number

    # not consensus-bearing, but required for SNV
    nameop['transfer_send_block_id'] = transfer_send_block_id
    nameop['last_creation_op'] = NAME_PREORDER 

    # propagate new sender information
    nameop['sender'] = nameop['recipient']
    nameop['address'] = nameop['recipient_address']
    del nameop['recipient']
    del nameop['recipient_address']

    value_hash = nameop['value_hash']

    if value_hash is not None:
        # deny value hash if we're not in an epoch that supports register/update in one nameop
        if opcode == 'NAME_REGISTRATION' and EPOCH_FEATURE_OP_REGISTER_UPDATE not in epoch_features:
            log.debug("Name '{}' has a zone file hash, but this is not supported in this epoch".format(nameop['name']))
            return False

        log.debug("Adding value hash {} for name '{}'".format(value_hash, nameop['name']))
        
    nameop['value_hash'] = value_hash

    if opcode == 'NAME_REGISTRATION' and 'burn_address' in nameop: 
        # not used in NAME_REGISTRATION (but is used in NAME_RENEWAL)
        del nameop['burn_address']

    # regster/renewal
    return True


@state_transition( "name", "name_records")
def check_renewal( state_engine, nameop, block_id, checked_ops ):
    """
    Verify the validity of a renewal nameop.
    * the name must be well-formed
    * the namespace must be ready
    * the request must be sent by the owner.
    * the mining fee must be high enough.
    * the name must not be expired

    Return True if accepted.
    Return False if not.
    """

    name = nameop['name']
    sender = nameop['sender']
    address = nameop['address']

    epoch_features = get_epoch_features(block_id)

    # address mixed into the preorder
    recipient_addr = nameop.get('recipient_address', None)
    if recipient_addr is None:
        log.debug("No registration address given")
        return False

    recipient = nameop.get('recipient', None)
    if recipient is None:
        log.debug("No recipient given")
        return False

    # pre F-day 2017, on renewal, the sender and recipient must be the same 
    # post F-day 2017, the recipient and sender can differ 
    if sender != recipient:
        if EPOCH_FEATURE_OP_RENEW_TRANSFER_UPDATE not in epoch_features:
            log.debug("Sender '%s' is not the recipient '%s'" % (sender, recipient))
            return False 

        else:
            log.debug("Transferring '{}' to '{}'".format(sender, recipient))

    if recipient_addr != address:
        if EPOCH_FEATURE_OP_RENEW_TRANSFER_UPDATE not in epoch_features:
            log.debug("Sender address '%s' is not the recipient address '%s'" % (address, recipient_addr))
            return False

        else:
            log.debug("Transferring '{}' to '{}'".format(address, recipient_addr))
                
    name_fee = None
    namespace = None
    preorder_hash = None
    preorder_block_number = None 
    name_block_number = None
    opcode = nameop['opcode']

    # name must be well-formed
    if not is_b40( name ) or "+" in name or name.count(".") > 1:
        log.debug("Malformed name '%s': non-base-38 characters" % name)
        return False

    # name must not be revoked
    if state_engine.is_name_revoked( name ):
        log.debug("Name '%s' is revoked" % name)
        return False

    namespace_id = get_namespace_from_name( name )

    # namespace must exist and be ready
    if not state_engine.is_namespace_ready( namespace_id ):
        log.debug("Namespace '%s' is not ready" % namespace_id)
        return False

    # get namespace...
    namespace = state_engine.get_namespace( namespace_id )

    # cannot exceed quota
    num_names = get_num_names_owned( state_engine, checked_ops, recipient )
    if num_names >= MAX_NAMES_PER_SENDER:
        log.debug("Recipient '%s' has exceeded quota" % recipient)
        return False

    # name must be registered already 
    if not state_engine.is_name_registered( name ):
        log.debug("Name '%s' is not registered" % name)
        return False

    # pre F-day 2017: name must be owned by the recipient already
    # post F-day 2017: doesn't matter
    if not state_engine.is_name_owner( name, recipient ):
        if EPOCH_FEATURE_OP_RENEW_TRANSFER_UPDATE not in epoch_features:
            log.debug("Renew: Name '%s' not owned by recipient %s" % (name, recipient))
            return False

    # name must be owned by the sender
    if not state_engine.is_name_owner( name, sender ):
        log.debug("Renew: Name '%s' not owned by sender %s" % (name, sender))
        return False

    # fee borne by the renewal
    if not 'op_fee' in nameop:
        log.debug("Name '%s' renewal did not pay the fee" % (name))
        return False
    
    prev_name_rec = state_engine.get_name( name )
    
    first_registered = prev_name_rec['first_registered']
    preorder_block_number = prev_name_rec['preorder_block_number']
    name_block_number = prev_name_rec['block_number']
    name_fee = nameop['op_fee']
    preorder_hash = prev_name_rec['preorder_hash']
    value_hash = prev_name_rec['value_hash']        # use previous name record's value hash by default
    burn_address = nameop['burn_address']

    assert name_fee is not None

    # check name fee
    name_without_namespace = get_name_from_fq_name( name )

    # fee must be high enough
    if name_fee < price_name( name_without_namespace, namespace, block_id ):
        log.debug("Name '%s' costs %s, but paid %s" % (name, price_name( name_without_namespace, namespace, block_id ), name_fee ))
        return False
 
    # fee must be paid to the right address.
    # pre F-day 2017: this *must* be the burn address, and the namespace *must* be version 1
    # post F-day 2017: this *may* be the namespace creator's address
    if not check_burn_address(namespace, burn_address, block_id):
        log.debug("Invalid burn address {}".format(burn_address))
        return False
 
    # if we're in an epoch that allows us to include a value hash in the renewal, and one is given, then set it 
    # instead of the previous name record's value hash.
    if EPOCH_FEATURE_OP_RENEW_TRANSFER_UPDATE in epoch_features:
        if nameop.has_key('value_hash') and nameop['value_hash'] is not None:
            log.debug("Adding value hash {} for name '{}'".format(value_hash, nameop['name']))
            value_hash = nameop['value_hash']

    nameop['op'] = "%s:" % (NAME_REGISTRATION,)
    nameop['opcode'] = "NAME_RENEWAL"
    nameop['op_fee'] = name_fee
    nameop['preorder_hash'] = preorder_hash
    nameop['namespace_block_number'] = namespace['block_number']
    nameop['first_registered'] = first_registered
    nameop['preorder_block_number'] = preorder_block_number
    nameop['block_number'] = name_block_number
    nameop['value_hash'] = value_hash

    # renewal
    nameop['last_renewed'] = block_id

    # propagate new sender information
    nameop['sender'] = nameop['recipient']
    nameop['address'] = nameop['recipient_address']
    nameop['sender_pubkey'] = prev_name_rec['sender_pubkey']

    del nameop['recipient']
    del nameop['recipient_address']
    del nameop['burn_address']

    # renewal!
    return True


def tx_extract( payload, senders, inputs, outputs, block_id, vtxindex, txid ):
    """
    Extract and return a dict of fields from the underlying blockchain transaction data
    that are useful to this operation.

    Required (+ parse):
    sender:  the script_pubkey (as a hex string) of the principal that sent the name preorder transaction
    address:  the address from the sender script
    recipient:  the script_pubkey (as a hex string) of the principal that is meant to receive the name
    recipient_address:  the address from the recipient script

    Optional:
    sender_pubkey_hex: the public key of the sender
    """
  
    sender_script = None 
    sender_address = None 
    sender_pubkey_hex = None

    recipient = None 
    recipient_address = None 
    burn_address = None
    op_fee = None

    try:
       recipient = get_registration_recipient_from_outputs( outputs )
       recipient_address = virtualchain.script_hex_to_address( recipient )

       assert recipient is not None 
       assert recipient_address is not None

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

       if len(outputs) >= 4:
          # renewing
          burn_info = get_renew_burn_info(outputs)
          burn_address = burn_info['burn_address']
          op_fee = burn_info['op_fee']

    except Exception, e:
       log.exception(e)
       raise Exception("Failed to extract")

    parsed_payload = parse( payload, block_id )
    assert parsed_payload is not None 

    ret = {
       "value_hash": None,
       "sender": sender_script,
       "address": sender_address,
       "recipient": recipient,
       "recipient_address": recipient_address,
       "revoked": False,
       "last_renewed": block_id,
       "vtxindex": vtxindex,
       "txid": txid,
       "first_registered": block_id,        # NOTE: will get deleted if this is a renew
       "last_renewed": block_id,            # NOTE: will get deleted if this is a renew
       "burn_address": burn_address,        # NOTE: will get deleted if this is a renew
       'op_fee': op_fee,                    # meant for NAME_RENEWAL
       "op": NAME_REGISTRATION
    }

    # adds name, value_hash
    ret.update( parsed_payload )

    # NOTE: will get deleted if this is a renew
    if sender_pubkey_hex is not None:
        ret['sender_pubkey'] = sender_pubkey_hex
    else:
        ret['sender_pubkey'] = None

    return ret


def parse(bin_payload, block_height):
    """
    Interpret a block's nulldata back into a name.  The first three bytes (2 magic + 1 opcode)
    will not be present in bin_payload.
    
    The name will be directly represented by the bytes given.
    """
    
    # pre F-day 2017: bin_payload is the name.
    # post F-day 2017: bin_payload is the name and possibly the update hash
    epoch_features = get_epoch_features(block_height)
    fqn = None
    value_hash = None

    if EPOCH_FEATURE_OP_REGISTER_UPDATE in epoch_features or EPOCH_FEATURE_OP_RENEW_TRANSFER_UPDATE in epoch_features:
        # payload is possibly name + update hash.
        # if so, it's guaranteed to be max_name_len + value_hash_len bytes long.
        if len(bin_payload) == LENGTHS['blockchain_id_name'] + LENGTHS['value_hash']:
            value_hash = bin_payload[-20:].encode('hex')
            fqn = bin_payload[:LENGTHS['blockchain_id_name']]

            # strip trailing 0's
            fqn = fqn.rstrip('\x00')

        else:
            fqn = bin_payload

    else:
        # payload is only the name
        fqn = bin_payload
 
    if not is_name_valid( fqn ):
        log.debug("Invalid name: {} ({})".format(fqn, fqn.encode('hex')))
        return None

    return {
       'opcode': 'NAME_REGISTRATION',
       'name': fqn,
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

    from ..nameset import BlockstackDB

    namespace_id = get_namespace_from_name(name_rec['name'])
    epoch_features = get_epoch_features(block_number)
    value_hash = None
    receive_fees_period = get_epoch_namespace_receive_fees_period(block_number, namespace_id)

    # restore history to find previous sender, address, public key
    name_rec_prev = BlockstackDB.get_previous_name_version( name_rec, block_number, history_index, untrusted_db )
    
    # restore zone file hash, if this is supported in this epoch
    if EPOCH_FEATURE_OP_RENEW_TRANSFER_UPDATE in epoch_features and op_get_opcode_name(name_rec['op']) == 'NAME_RENEWAL' and name_rec.has_key('value_hash'):
        value_hash = name_rec['value_hash']

    if EPOCH_FEATURE_OP_REGISTER_UPDATE in epoch_features and op_get_opcode_name(name_rec['op']) == 'NAME_REGISTRATION' and name_rec.has_key('value_hash'):
        value_hash = name_rec['value_hash']

    name_rec_script = build_registration( str(name_rec['name']), value_hash=value_hash )
    name_rec_payload = unhexlify( name_rec_script )[3:]
    ret_op = parse( name_rec_payload, block_number )

    # reconstruct the registration/renewal op's recipient info
    ret_op['recipient'] = str(name_rec['sender'])
    ret_op['recipient_address'] = str(name_rec['address'])

    sender = name_rec_prev['sender']
    address = name_rec_prev['address']

    sender_pubkey = None
    opcode_name = None
    if op_get_opcode_name(name_rec['op']) == "NAME_RENEWAL":
        opcode_name = 'NAME_RENEWAL'
        log.debug("NAME_RENEWAL: sender_pubkey = '%s'" % name_rec['sender_pubkey'])
        sender_pubkey = name_rec['sender_pubkey']
    else:
        opcode_name = 'NAME_REGISTRATION'
        log.debug("NAME_REGISTRATION: sender_pubkey = '%s'" % name_rec_prev['sender_pubkey'])
        sender_pubkey = name_rec_prev['sender_pubkey']
    
    namespace = untrusted_db.get_namespace(namespace_id)
    assert namespace

    ret_op['sender'] = sender
    ret_op['address'] = address
    ret_op['revoked'] = False
    ret_op['sender_pubkey'] = sender_pubkey

    if (namespace['version'] & NAMESPACE_VERSION_PAY_TO_CREATOR):
        fee_block_number = None
        if opcode_name == 'NAME_RENEWAL':
            fee_block_number = block_number
        else:
            fee_block_number = name_rec['preorder_block_number']

        if namespace['reveal_block'] + receive_fees_period >= fee_block_number:
            # still in the fee capture interval
            ret_op['burn_address'] = namespace['address']
        else:
            ret_op['burn_address'] = BLOCKSTACK_BURN_ADDRESS
    else:
        ret_op['burn_address'] = BLOCKSTACK_BURN_ADDRESS

    return ret_op


def snv_consensus_extras( name_rec, block_id, blockchain_name_data, db ):
    """
    Given a name record most recently affected by an instance of this operation, 
    find the dict of consensus-affecting fields from the operation that are not
    already present in the name record.
    """
    return blockstack_client.operations.register.snv_consensus_extras( name_rec, block_id, blockchain_name_data )


