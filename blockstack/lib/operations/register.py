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
    'token_fee',
    'last_creation_op'
]

# fields renewal changes
RENEWAL_MUTATE_FIELDS = NAMEREC_MUTATE_FIELDS + [
    'last_renewed',
    'sender',
    'address',
    'sender_pubkey',
    'value_hash',
    'op_fee',
    'token_fee'
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
    
    return outputs[1]['script']


def get_renew_burn_info( outputs ):
    """
    There are four poutputs: the OP_RETURN, the registration (owner)
    address, the change address (i.e. from the preorderer), and the
    burn address with the renewal fee.

    Get the burn address and value
    """
    if len(outputs) < 4:
        raise Exception("Malformed renew outputs: don't have 4")

    burn_addr = virtualchain.script_hex_to_address(outputs[3]['script'])
    if burn_addr is None:
        raise Exception("Malformed renew inputs: burn output is a nonstandard script")

    op_fee = outputs[3]['value']
    return {'burn_address': burn_addr, 'op_fee': op_fee}


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
        if (namespace['version'] == NAMESPACE_VERSION_PAY_TO_CREATOR):
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
        log.warning("Register/renew sends fee to {}, but namespace expects {}".format(burn_address, expected_burn_address))
        return False
    else:
        log.debug("Sending register/renewal fee to {}".format(burn_address))

    return True


def check_payment(state_engine, state_op_type, nameop, namespace, name_fee, token_fee, fee_block_id, fee_vtxindex, burn_address, token_address, block_id):
    """
    Verify that the right payment was made, in the right cryptocurrency units.
    Set the account payment information in nameop if this is a state-transition (i.e. a NAME_RENEWAL)

    NOTE: you will need to have called state_create_put_preorder() before calling this method!

    Returns {'status': True, 'tokens_paid': tokens_paid} if the payment information is correct.
    Returns {'status': False} if not
    """
    
    assert state_op_type in ['NAME_REGISTRATION', 'NAME_RENEWAL'], 'Invalid op type {}'.format(state_op_type)

    epoch_features = get_epoch_features(block_id)
    name = nameop['name']

    assert name_fee is not None
    name_without_namespace = get_name_from_fq_name( name )

    tokens_paid = 0
    token_units = None

    # check name fee
    # * if the namespace is denominated in BTC, then check against BTC price
    # * if the namespace is denominated in STACKs, then check against STACK price
    if namespace['version'] in [NAMESPACE_VERSION_PAY_TO_BURN, NAMESPACE_VERSION_PAY_TO_CREATOR]:
        # priced in BTC
        # fee must be high enough (either the preorder paid the right fee at the preorder block height,
        # or the renewal paid the right fee at the renewal height)
        if name_fee < price_name( name_without_namespace, namespace, fee_block_id ):
            log.warning("Name '%s' costs %s, but paid %s" % (name, price_name( name_without_namespace, namespace, block_id ), name_fee ))
            return {'status': False}

        # we are *not* paying with STACKs
        if state_op_type == 'NAME_RENEWAL':
            state_transition_put_account_payment_info(nameop, None, None, None)
        
    else:
        # need to be in the right epoch--i.e. need STACKs to exist
        if EPOCH_FEATURE_NAMESPACE_PAY_WITH_STACKS not in epoch_features:
            log.warning("Name '{}' was created in namespace '{}', with version bits 0x{:x}, which is not supported in this epoch".format(name, namespace['namespace_id'], namespace['version']))
            return {'status': False}

        if namespace['version'] in [NAMESPACE_VERSION_PAY_WITH_STACKS]:
            # priced in STACKs
            # how much is this name in STACKs?
            token_name_fee = price_name(name_without_namespace, namespace, block_id)
            token_name_fee = int(token_name_fee)

            # find out how many STACKs (if any) were paid
            if state_op_type == 'NAME_REGISTRATION':
                # STACKs were already paid by a preorder.
                # find out how much.
                preorder = state_create_get_preorder(nameop)
                assert preorder, 'BUG: no preorder set'
                assert isinstance(preorder['token_fee'], (int,long)), 'Not an int: {}'.format(preorder['token_fee'])

                token_units = preorder['token_units']
                tokens_paid = preorder['token_fee']

                if token_units != TOKEN_TYPE_STACKS:
                    log.warning("Account paid in {}, but this namespace expects {}".format(token_units, TOKEN_TYPE_STACKS))
                    return {'status': False}

            elif state_op_type == 'NAME_RENEWAL':
                # what are this namespace's token units?
                # since this is a pay-with-STACKs namespace, we had to have paid in STACKs
                token_units = TOKEN_TYPE_STACKS

                if token_fee is None:
                    # no tokens paid
                    log.warning("No tokens paid by {} for {}".format(token_address, nameop['name']))
                    return {'status': False}

                # paying in STACKs right now
                account_info = state_engine.get_account(token_address, TOKEN_TYPE_STACKS)
                if account_info is None:
                    # no account!
                    log.warning("Name buyer {} does not have an account".format(token_address))
                    return {'status': False}

                # can this account afford it?
                account_balance = state_engine.get_account_balance(account_info)
                if account_balance < token_fee:
                    # not enough balance
                    log.warning("Address {} does not have enough {} tokens for {} (need at least {}, but only have {})".format(token_address, TOKEN_TYPE_STACKS, name, token_fee, account_balance))
                    return {'status': False}

                # how much was paid?
                tokens_paid = token_fee
               
            # did the preorder/renewer pay the *right* tokens?
            # TODO: alter this conditional once we support per-namespace tokens
            if token_units != TOKEN_TYPE_STACKS:
                log.warning('Account {} paid in {}, but this namespace only accepts {}'.format(token_address, token_units, TOKEN_TYPE_STACKS))
                return {'status': False}

            log.debug("Account {} paid {} {}s for {} at ({},{})".format(token_address, tokens_paid, TOKEN_TYPE_STACKS, nameop['name'], fee_block_id, fee_vtxindex))

            tokens_paid = int(tokens_paid)
            if tokens_paid < token_name_fee:
                # not enough!
                log.warning("Name buyer {} paid {} {}s, but '{}' costs {} {}s".format(token_address, tokens_paid, TOKEN_TYPE_STACKS, name, token_name_fee, TOKEN_TYPE_STACKS))
                return {'status': False}

            # charge the price of this name when we commit this state-transition
            if state_op_type == 'NAME_RENEWAL':
                state_transition_put_account_payment_info(nameop, token_address, TOKEN_TYPE_STACKS, tokens_paid)

        else:
            # unrecognized namespace rules
            log.warning("Namespace {} has version bits 0x{:x}, which has unknown registration rules".format(namespace['namespace_id'], namespace['version']))
            return {'status': False}

    # fee must be paid to the right address, at the right time.
    # pre F-day 2017: this *must* be the burn address, and the namespace *must* be version 1
    # post F-day 2017: this *may* be the namespace creator's address
    if not check_burn_address(namespace, burn_address, fee_block_id):
        log.warning("Invalid burn address {}".format(burn_address))
        return {'status': False}

    return {'status': True, 'tokens_paid': tokens_paid, 'units': token_units}


@state_create( "name", "name_records", "check_name_collision" )
def check_register( state_engine, nameop, block_id, checked_ops ):
    """
    Verify the validity of a registration nameop.
    * the name must be well-formed
    * the namespace must be ready
    * the name does not collide
    * either the name was preordered by the same sender, or the name exists and is owned by this sender (the name cannot be registered and owned by someone else)
    * the mining fee must be high enough.
    * if the name was expired, then merge the preorder information from the expired preorder
    * the preorder burned the right amount of tokens, if this name is registered in a pay-with-tokens namespace

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
        log.warning("No registration address given")
        return False

    recipient = nameop.get('recipient', None)
    if recipient is None:
        log.warning("No recipient script given")
        return False

    # name must be well-formed
    if not is_name_valid( name ):
        log.warning("Malformed name '%s'" % name)
        return False

    epoch_features = get_epoch_features(block_id)

    name_fee = None
    namespace = None
    preorder_hash = None
    preorder_block_number = None 
    name_block_number = None
    consensus_hash = None
    fee_block_id = None         # block ID at which the fee was paid
    fee_vtxindex = None         # vtxindex at which the fee was paid
    burn_address = None         # preorder/renew burn address
    token_address = None        # if we're paying in tokens, this is the token account to debit
    opcode = nameop['opcode']
    first_registered = nameop['first_registered']

    # name must be well-formed
    if not is_b40( name ) or "+" in name or name.count(".") > 1:
        log.warning("Malformed name '%s': non-base-38 characters" % name)
        return False

    # name must not be revoked
    if state_engine.is_name_revoked( name ):
        log.warning("Name '%s' is revoked" % name)
        return False

    namespace_id = get_namespace_from_name( name )

    # namespace must exist and be ready
    if not state_engine.is_namespace_ready( namespace_id ):
        log.warning("Namespace '%s' is not ready" % namespace_id)
        return False

    # get namespace...
    namespace = state_engine.get_namespace( namespace_id )

    # cannot exceed quota
    num_names = get_num_names_owned( state_engine, checked_ops, recipient )
    if num_names >= MAX_NAMES_PER_SENDER:
        log.warning("Recipient '%s' has exceeded quota" % recipient)
        return False

    # if multisig is not enabled in this epoch, and the recipient
    # address is a p2sh address, then reject the transaction.
    # this if for compatibility with 0.13
    if virtualchain.is_multisig_address( register_addr ) and not epoch_has_multisig( block_id ):
        log.warning("Multisig registration address %s, but this epoch (%s) does not support multisig" % (register_addr, get_epoch_number(block_id)))
        return False

    # get preorder...
    preorder = state_engine.get_name_preorder( name, sender, register_addr )
    old_name_rec = state_engine.get_name( name, include_expired=True )

    if preorder is not None:
        # Case 1(a-b): registering or re-registering from a preorder

        # bugfix?
        if EPOCH_FEATURE_FIX_PREORDER_EXPIRE in epoch_features:
            # preorder must not be expired
            if preorder['block_number'] + NAME_PREORDER_EXPIRE < block_id:
                log.warning("Preorder {} is expired".format(preorder['preorder_hash']))
                return False

        # can't be registered already 
        if state_engine.is_name_registered( name ):
            log.warning("Name '%s' is already registered" % name)
            return False 

        # name can't be registered if it was reordered before its namespace was ready
        if not namespace.has_key('ready_block') or preorder['block_number'] < namespace['ready_block']:
           log.warning("Name '%s' preordered before namespace '%s' was ready" % (name, namespace_id))
           return False

        # name must be preordered by the same sender
        if preorder['sender'] != sender:
           log.warning("Name '%s' was not preordered by %s" % (name, sender))
           return False

        # fee was included in the preorder (even if it's just dust)
        if not 'op_fee' in preorder:
           log.warning("Name '%s' preorder did not pay the fee" % (name))
           return False

        name_fee = preorder['op_fee']
        preorder_hash = preorder['preorder_hash']
        preorder_block_number = preorder['block_number']
        fee_block_id = preorder_block_number
        fee_vtxindex = preorder['vtxindex']

        burn_address = preorder['burn_address']
        token_address = preorder['address']     # note that the *preorderer* pays for a registration in tokens, just as it is with BTC

        # pass along the preorder
        state_create_put_preorder( nameop, preorder )

        if old_name_rec is None:
            # Case 1(a): registered for the first time ever 
            log.debug("Registering name '%s'" % name)
            name_block_number = preorder['block_number']
        
        else:
            # Case 1(b): name expired, and is now re-registered
            log.debug("Re-registering name '%s'" % name )
        
            # push back preorder block number to the original preorder
            name_block_number = old_name_rec['block_number']

        '''
        # indent back 4 spaces
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
            fee_block_id = block_id

            burn_address = nameop['burn_address']
            token_address = nameop['address']   # note that the renewer *owner* pays for the renewal in tokens

            opcode = "NAME_RENEWAL"     # will cause this operation to be re-checked under check_renewal()

            state_create_put_preorder( nameop, None ) 
        '''
    else:
        # Case 2: has never existed, and not preordered
        log.warning("Name '%s' does not exist, or is not preordered by %s" % (name, sender))
        return False

    # check name payment
    payment_res = check_payment(state_engine, "NAME_REGISTRATION", nameop, namespace, name_fee, None, fee_block_id, fee_vtxindex, burn_address, token_address, block_id)
    if not payment_res['status']:
        log.warning("Name '{}' did not receive the appropriate payment".format(name))
        return False

    # will be None if we paid in BTC
    token_fee = payment_res['tokens_paid']
    assert token_fee is not None

    nameop['opcode'] = opcode
    nameop['op_fee'] = name_fee
    nameop['token_fee'] = '{}'.format(token_fee)   # NOTE: use a string to prevent integer overflow
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
    nameop['last_creation_op'] = NAME_PREORDER 

    # propagate new sender information
    nameop['sender'] = nameop['recipient']
    nameop['address'] = nameop['recipient_address']
    del nameop['recipient']
    del nameop['recipient_address']

    value_hash = nameop['value_hash']

    if value_hash is not None:
        # deny value hash if we're not in an epoch that supports register/update in one nameop
        # if opcode == 'NAME_REGISTRATION' and EPOCH_FEATURE_OP_REGISTER_UPDATE not in epoch_features:
        if EPOCH_FEATURE_OP_REGISTER_UPDATE not in epoch_features:
            log.warning("Name '{}' has a zone file hash, but this is not supported in this epoch".format(nameop['name']))
            return False

        log.debug("Adding value hash {} for name '{}'".format(value_hash, nameop['name']))
        
    nameop['value_hash'] = value_hash

    '''
    if opcode == 'NAME_REGISTRATION' and 'burn_address' in nameop: 
        # not used in NAME_REGISTRATION (but is used in NAME_RENEWAL)
        del nameop['burn_address']
    '''

    # regster/renewal
    return True


@state_transition( "name", "name_records", may_spend_tokens=True)
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
        log.warning("No registration address given")
        return False

    recipient = nameop.get('recipient', None)
    if recipient is None:
        log.warning("No recipient given")
        return False

    # name must be well-formed
    if not is_name_valid( name ):
        log.warning("Malformed name '%s'" % name)
        return False

    # pre F-day 2017, on renewal, the sender and recipient must be the same 
    # post F-day 2017, the recipient and sender can differ 
    if sender != recipient:
        if EPOCH_FEATURE_OP_RENEW_TRANSFER_UPDATE not in epoch_features:
            log.warning("Sender '%s' is not the recipient '%s'" % (sender, recipient))
            return False 

        else:
            log.debug("Transferring '{}' to '{}'".format(sender, recipient))

    if recipient_addr != address:
        if EPOCH_FEATURE_OP_RENEW_TRANSFER_UPDATE not in epoch_features:
            log.warning("Sender address '%s' is not the recipient address '%s'" % (address, recipient_addr))
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
        log.warning("Malformed name '%s': non-base-38 characters" % name)
        return False

    # name must not be revoked
    if state_engine.is_name_revoked( name ):
        log.warning("Name '%s' is revoked" % name)
        return False

    namespace_id = get_namespace_from_name( name )

    # namespace must exist and be ready
    if not state_engine.is_namespace_ready( namespace_id ):
        log.warning("Namespace '%s' is not ready" % namespace_id)
        return False

    # get namespace...
    namespace = state_engine.get_namespace( namespace_id )

    # cannot exceed quota
    num_names = get_num_names_owned( state_engine, checked_ops, recipient )
    if num_names >= MAX_NAMES_PER_SENDER:
        log.warning("Recipient '%s' has exceeded quota" % recipient)
        return False

    # name must be registered already 
    if not state_engine.is_name_registered( name ):
        log.warning("Name '%s' is not registered" % name)
        return False

    # pre F-day 2017: name must be owned by the recipient already
    # post F-day 2017: doesn't matter
    if not state_engine.is_name_owner( name, recipient ):
        if EPOCH_FEATURE_OP_RENEW_TRANSFER_UPDATE not in epoch_features:
            log.warning("Renew: Name '%s' not owned by recipient %s" % (name, recipient))
            return False

    # name must be owned by the sender
    if not state_engine.is_name_owner( name, sender ):
        log.warning("Renew: Name '%s' not owned by sender %s" % (name, sender))
        return False

    # fee borne by the renewal
    if not 'op_fee' in nameop or nameop['op_fee'] is None:
        log.warning("Name '%s' renewal did not pay the fee" % (name))
        return False
   
    prev_name_rec = state_engine.get_name( name )
    
    first_registered = prev_name_rec['first_registered']
    preorder_block_number = prev_name_rec['preorder_block_number']
    name_block_number = prev_name_rec['block_number']
    name_fee = nameop['op_fee']
    preorder_hash = prev_name_rec['preorder_hash']
    value_hash = prev_name_rec['value_hash']        # use previous name record's value hash by default
    burn_address = nameop['burn_address']

    fee_block_id = block_id         # fee for this name is paid now
    fee_vtxindex = nameop['vtxindex']   # fee for this name is paid now
    token_address = address         # current owner pays tokens to renew
    tokens_paid = nameop['token_fee']
    assert tokens_paid is not None
    
    # check name payment
    payment_res = check_payment(state_engine, "NAME_RENEWAL", nameop, namespace, name_fee, tokens_paid, fee_block_id, fee_vtxindex, burn_address, token_address, block_id)
    if not payment_res['status']:
        log.warning("Name '{}' did not receive the appropriate payment".format(name))
        return False
 
    # if we're in an epoch that allows us to include a value hash in the renewal, and one is given, then set it 
    # instead of the previous name record's value hash.
    if EPOCH_FEATURE_OP_RENEW_TRANSFER_UPDATE in epoch_features:
        if nameop.has_key('value_hash') and nameop['value_hash'] is not None:
            log.debug("Adding value hash {} for name '{}'".format(value_hash, nameop['name']))
            value_hash = nameop['value_hash']

    # nameop['op'] = "%s:" % (NAME_REGISTRATION,)
    # nameop['opcode'] = "NAME_RENEWAL"
    nameop['op_fee'] = name_fee
    nameop['token_fee'] = '{}'.format(tokens_paid)      # NOTE: use a string to prevent integer overflow
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

    op = NAME_REGISTRATION
    opcode = 'NAME_REGISTRATION'

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

          op = '{}{}'.format(NAME_RENEWAL, NAME_RENEWAL)
          opcode = 'NAME_RENEWAL'

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
       "op": op,
       "opcode": opcode,
    }

    if opcode == 'NAME_REGISTRATION':
        # registration
        if parsed_payload['token_fee'] is not None:
            # registration shouldn't have this field
            assert parsed_payload['token_fee'] == 0

        ret.update({ 
           'name': parsed_payload['name'],
           'value_hash': parsed_payload['value_hash'],
           "first_registered": block_id,
           "last_renewed": block_id,
         })


    else:
        # renewal
        assert parsed_payload['token_fee'] is not None
        ret.update({
           'name': parsed_payload['name'],
           'value_hash': parsed_payload['value_hash'],
           'op_fee': op_fee,
           "burn_address": burn_address,
           'token_fee': parsed_payload['token_fee'],
        })

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
    
    This works for registrations and renewals.

    Record format (pre F-day 2017):
    
    0    2  3                                  39
    |----|--|----------------------------------|
    magic op   name.ns_id (up to 37 bytes)


    Record format (post F-day 2017):
    
    0    2  3                                  39                  59
    |----|--|----------------------------------|-------------------|
    magic op   name.ns_id (37 bytes, 0-padded)    zone file hash


    Record format (STACKs phase 1):
    (for register, tokens burned is ignored)
    (for renew, tokens burned is the number of tokens to burn)
    
    0    2  3                                  39                  59                             67
    |----|--|----------------------------------|-------------------|------------------------------|
    magic op   name.ns_id (37 bytes, 0-padded)     zone file hash    tokens burned (little-endian)

    """
    
    # pre F-day 2017: bin_payload is the name.
    # post F-day 2017: bin_payload is the name and possibly the update hash
    # STACKs phase 1: bin_payload possibly has a token burn attached to the end
    epoch_features = get_epoch_features(block_height)
    fqn = None
    value_hash = None
    tokens_burned = 0

    if EPOCH_FEATURE_OP_REGISTER_UPDATE in epoch_features or EPOCH_FEATURE_OP_RENEW_TRANSFER_UPDATE in epoch_features:
        # payload is possibly name + zonefile hash, or name + zonefile hash + tokens
        # if so, it's guaranteed to be max_name_len + value_hash_len bytes long.
        name_value_len = LENGTHS['blockchain_id_name'] + LENGTHS['value_hash']
        if len(bin_payload) >= name_value_len:
            # has name and value hash, and possibly a token burn
            # get name and value hash
            value_hash = bin_payload[LENGTHS['blockchain_id_name']: LENGTHS['blockchain_id_name'] + LENGTHS['value_hash']].encode('hex')
            fqn = bin_payload[:LENGTHS['blockchain_id_name']]
            fqn = fqn.rstrip('\x00')

            if EPOCH_FEATURE_NAMEOPS_COST_TOKENS in epoch_features:
                # might have tokens burned.  If so, it's all or nothing.
                if len(bin_payload) == name_value_len + LENGTHS['tokens_burnt']:
                    # we have a token count (this is a name renewal)
                    bin_tokens = bin_payload[name_value_len: name_value_len + LENGTHS['tokens_burnt']]
                    tokens_burned = int(bin_tokens.encode('hex'), 16)    # NOTE: little-endian

                else:
                    # must not have any bits dangling off the end 
                    if len(bin_payload) != name_value_len:
                        log.warning('Invalid payload {}: expected {} bytes or {} bytes'.format(bin_payload.encode('hex'), name_value_len, name_value_len + LENGTHS['tokens_burnt']))
                        return None 

                    # no token count (might be a register)
                    tokens_burned = None

            else:
                # tokens are not active in this epoch.
                # payload must be *exactly* name + value hash.
                if len(bin_payload) != name_value_len:
                    log.warning("Invalid payload {}: expected {} bytes".format(bin_payload.encode('hex'), name_value_len))
                    return None

        else:
            # payload is just a name
            fqn = bin_payload

    else:
        # payload is only the name
        fqn = bin_payload
 
    if not is_name_valid( fqn ):
        log.warning("Invalid name: {} ({})".format(fqn, fqn.encode('hex')))
        return None

    return {
       'opcode': 'NAME_REGISTRATION',       # NOTE: could be NAME_RENEWAL
       'name': fqn,
       'value_hash': value_hash,
       'token_fee': tokens_burned,
    }
 
