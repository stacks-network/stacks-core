#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org
    
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
    along with Blockstack.  If not, see <http://www.gnu.org/licenses/>.
"""

import sys
import os

from ..config import OPCODE_CREATION_OPS, op_get_opcode_name

import virtualchain
log = virtualchain.get_logger("blockstack-server")


# fields that *must* be present 
CONSENSUS_FIELDS_REQUIRED = [
    'op',
    'txid',
    'vtxindex'
]

# fields that *must* be present in token operations,
# *in addition* to CONSENSUS_FIELDS_REQUIRED above
CONSENSUS_FIELDS_REQUIRED_TOKENS = [
    'address'
]

# all fields common to a name record
# NOTE: this order must be preserved for all eternity
NAMEREC_FIELDS = [
    'name',                 # the name itself
    'value_hash',           # the hash of the name's associated profile
    'sender',               # the scriptPubKey hex that owns this name (identifies ownership)
    'sender_pubkey',        # (OPTIONAL) the public key 
    'address',              # the address of the sender
    
    'block_number',         # the block number when this name record was created (preordered for the first time)
    'preorder_block_number', # the block number when this name was last preordered
    'first_registered',     # the block number when this name was registered by the current owner
    'last_renewed',         # the block number when this name was renewed by the current owner
    'revoked',              # whether or not the name is revoked

    'op',                   # byte sequence describing the last operation to affect this name
    'txid',                 # the ID of the last transaction to affect this name
    'vtxindex',             # the index in the block of the transaction.
    'op_fee',               # the value of the last Blockstack-specific burn fee paid for this name (i.e. from preorder or renew)

    'importer',             # (OPTIONAL) if this name was imported, this is the importer's scriptPubKey hex
    'importer_address',     # (OPTIONAL) if this name was imported, this is the importer's address
]

# common set of fields that will get changed when applying an operation 
NAMEREC_MUTATE_FIELDS = [
    'txid',
    'vtxindex',
    'op'
]


def state_preorder_invariant_tags():
    """
    Get a list of state-preorder invariant tags
    """
    return [
        '__account_payment_info__'
    ]


def state_create_invariant_tags():
    """
    Get a list of state-create invariant tags.
    """
    return [
        '__preorder__',
        '__table__',
        '__history_id_key__',
        '__state_create__',
    ]


# check for collisions
def state_check_collisions( state_engine, nameop, history_id_key, block_id, checked_ops, collision_checker ):
    """
    See that there are no state-creating or state-preordering collisions at this block, for this history ID.
    Return True if collided; False if not
    """

    # verify no collisions against already-accepted names
    collision_check = getattr( state_engine, collision_checker, None )
    try:
        assert collision_check is not None, "Collision-checker '%s' not defined" % collision_checker
        assert hasattr( collision_check, "__call__" ), "Collision-checker '%s' is not callable" % collision_checker
        assert history_id_key in nameop.keys(), "History ID key '%s' not in name operation" % (history_id_key)
        assert 'op' in nameop.keys(), "BUG: no op in nameop"
    except Exception, e:
        log.exception(e)
        log.error("FATAL: incorrect state_create() decorator")
        sys.exit(1)

    rc = collision_check( nameop[history_id_key], block_id, checked_ops )
    return rc


# sanity check decorator for state-preordering operations 
def state_preorder(collision_checker):
    """
    Decorator for the check() method on a state-preordering operation.
    Make sure that there are no duplicate preorders anywhere--either in this
    block, or in any previous blocks.
    """
    def wrap( check ):
        def wrapped_check( state_engine, nameop, block_id, checked_ops ):
            rc = check( state_engine, nameop, block_id, checked_ops )
            if rc:
                # verify no duplicates 
                history_id_key = "preorder_hash"
                rc = state_check_collisions( state_engine, nameop, history_id_key, block_id, checked_ops, collision_checker )
                if rc:
                    log.debug("COLLISION on %s '%s'" % (history_id_key, nameop[history_id_key]))
                    rc = False 
                else:
                    # no collision
                    rc = True

                # sanity check---we need to have the appropriate metadata for this operation
                invariant_tags = state_preorder_invariant_tags()
                for tag in invariant_tags:
                    assert tag in nameop, "BUG: missing invariant tag '%s'" % tag

                # sanity check---all required consensus fields must be present
                for required_field in CONSENSUS_FIELDS_REQUIRED:
                    assert required_field in nameop, 'BUG: missing required consensus field {}'.format(required_field)

            return rc
        return wrapped_check
    return wrap


# sanity check decorator for state-creating operations 
def state_create(history_id_key, table_name, collision_checker, always_set=[]):
    """
    Decorator for the check() method on state-creating operations.
    Makes sure that:
    * there is a __preorder__ field set, which contains the state-creating operation's associated preorder
    * there is a __table__ field set, which contains the table into which to insert this state into
    * there is a __history_id_key__ field set, which identifies the table's primary key name
    * there are no unexpired, duplicate instances of this state with this history id.
    (i.e. if we're preordering a name that had previously expired, we need to preserve its history)
    """

    def wrap( check ):
        def wrapped_check( state_engine, nameop, block_id, checked_ops ):
            rc = check( state_engine, nameop, block_id, checked_ops )

            # pretty sure this isn't necessary any longer, but leave this is an assert just in case
            assert op_get_opcode_name(nameop['op']) in OPCODE_CREATION_OPS, 'BUG: opcode became {}'.format(nameop['op'])

            # succeeded?
            if rc:

                # ensure that there's now a __preorder__ 
                try:
                    assert '__preorder__' in nameop.keys(), "Missing __preorder__"
                except Exception, e:
                    log.exception(e)
                    log.error("FATAL: missing fields")
                    os.abort()

                # propagate __table__ and __history_id_key__
                nameop['__table__'] = table_name
                nameop['__history_id_key__'] = history_id_key
                nameop['__state_create__'] = True
                nameop['__always_set__'] = always_set

                # sanity check---we need to have the appropriate metadata for this operation
                invariant_tags = state_create_invariant_tags()
                for tag in invariant_tags:
                    assert tag in nameop, "BUG: missing invariant tag '%s'" % tag

                # sanity check---all required consensus fields must be present
                for required_field in CONSENSUS_FIELDS_REQUIRED:
                    assert required_field in nameop, 'BUG: missing required consensus field {}'.format(required_field)

                # verify no duplicates
                rc = state_check_collisions( state_engine, nameop, history_id_key, block_id, checked_ops, collision_checker )
                if rc:
                    # this is a duplicate!
                    log.debug("COLLISION on %s '%s'" % (history_id_key, nameop[history_id_key]))
                    rc = False
                else:
                    # no collision
                    rc = True

            return rc
        return wrapped_check
    return wrap


def state_transition_invariant_tags():
    """
    Get a list of possible state-transition invariant tags
    """
    return [
        '__table__',
        '__history_id_key__',
        '__state_transition__',
        '__always_set__',
    ]


# sanity check decorator for state-transition operations 
def state_transition(history_id_key, table_name, always_set=[], may_spend_tokens=False):
    """
    Decorator for the check() method on state-transition operations.
    Make sure that:
    * there is a __table__ field set, which names the table in which this record is stored.
    * there is a __history_id_key__ field set, which identifies the table record's primary key.

    Any fields named in @always_set will always be set when the transition is applied.
    That is, fields set here *must* be set on transition, and *will* be set in the database, even if
    they have prior values in the affected name record that might constrain which rows to update.
    """

    def wrap( check ):
        def wrapped_check( state_engine, nameop, block_id, checked_ops ):
            rc = check( state_engine, nameop, block_id, checked_ops )
            if rc:
                # put fields in place 
                nameop['__table__'] = table_name
                nameop['__history_id_key__'] = history_id_key 
                nameop['__state_transition__'] = True
                nameop['__always_set__'] = always_set

                if not may_spend_tokens:
                    state_transition_put_account_payment_info(nameop, None, None, None)

                elif '__account_payment_info__' not in nameop:
                    raise Exception('Operation spends tokens, but no payment account information is set')

                # sanity check
                invariant_tags = state_transition_invariant_tags()
                for tag in invariant_tags:
                    assert tag in nameop, "BUG: missing invariant tag '%s'" % tag

                # sanity check---all required consensus fields must be present
                for required_field in CONSENSUS_FIELDS_REQUIRED:
                    assert required_field in nameop, 'BUG: missing required consensus field {}'.format(required_field)

            return rc
        return wrapped_check
    return wrap


def token_operation_invariant_tags():
    """
    Get a list of possible token transfer invariant tags
    """
    return [
        '__table__',
        '__account_payment_info__',
        '__account_credit_info__',
    ]


# sanity check decorator for token operations
def token_operation(table_name):
    """
    Decorator for the check() method on token operations.
    Make sure that there is a __account_payment_info__ and __account_credit_info__ set.
    """
    def wrap( check ):
        def wrapped_check( state_engine, token_op, block_id, checked_ops ):
            rc = check( state_engine, token_op, block_id, checked_ops )
            if rc:
                token_op['__table__'] = table_name
                invariant_tags = token_operation_invariant_tags()
                for tag in invariant_tags:
                    assert tag in token_op, 'BUG: missing token operation invariant tag {}'.format(tag)

                # sanity check---all required consensus fields must be present
                for required_field in CONSENSUS_FIELDS_REQUIRED:
                    assert required_field in token_op, 'BUG: missing required consensus field {}'.format(required_field)

                # sanity check---all required consensus fields for tokens must be present
                for required_field in CONSENSUS_FIELDS_REQUIRED_TOKENS:
                    assert required_field in token_op, 'BUG: missing token-specific required consensus field {}'.format(required_field)

            return rc
        return wrapped_check
    return wrap


def get_state_invariant_tags():
    """
    Get the set of state invariant tags for a given opcode
    """
    return list(set( state_create_invariant_tags() + state_transition_invariant_tags() + state_preorder_invariant_tags() + token_operation_invariant_tags() ))


def state_preorder_get_account_payment_info( nameop ):
    """
    Get the payment information for an account.  Can be None if no account payments are needed
    """
    return nameop['__account_payment_info__']


def state_preorder_put_account_payment_info( nameop, account_addr, token_type, amount ):
    """
    Call this in a @state_create-decorated method.
    Identifies the account that must be debited.
    """
    assert amount is None or isinstance(amount, (int,long)), 'Amount is {} (type {})'.format(amount, type(amount))
    assert account_addr is None or isinstance(account_addr, (str,unicode))
    assert token_type is None or isinstance(token_type, (str,unicode))
    nameop['__account_payment_info__'] = {
            'address': str(account_addr) if account_addr is not None else None,
            'type': str(token_type) if token_type is not None else None,
            'amount': int(amount) if amount is not None else None
    }


def state_create_put_preorder( nameop, preorder ):
    """
    Call this in a @state_create-decorated method.
    Identifies the preorder record for this state.
    """
    nameop['__preorder__'] = preorder


def state_create_is_valid( nameop ):
    """
    Is a nameop a valid state-preorder operation?
    """
    assert '__state_create__' in nameop, "Not tagged with @state_create"
    assert nameop['__state_create__'], "BUG: tagged False by @state_create"
    assert '__preorder__' in nameop, "No preorder"
    assert '__table__' in nameop, "No table given"
    assert '__history_id_key__' in nameop, "No history ID key given"
    assert nameop['__history_id_key__'] in nameop, "No history ID given"
    assert '__always_set__' in nameop, "No always-set fields given"

    return True 


def state_create_get_preorder( nameop ):
    """
    Get the preorder record for a state-creating operation
    """
    return nameop['__preorder__']


def state_create_get_table( nameop ):
    """
    Get the table of a state-creating operation
    """
    return nameop['__table__']


def state_create_get_history_id_key( nameop ):
    """
    Get the key to the history ID of a state-create name operation
    """
    return nameop['__history_id_key__']


def state_create_get_always_set( nameop ):
    """
    Get thie list of fields we will always set on create.
    """
    return nameop['__always_set__']


def state_transition_is_valid( nameop ):
    """
    Is this a valid state transition?
    """
    assert '__state_transition__' in nameop, "Not tagged with @state_transition"
    assert nameop['__state_transition__'], "BUG: @state_transition tagged False"
    assert '__history_id_key__' in nameop, "Missing __history_id_key__"
    history_id_key = nameop['__history_id_key__']
    assert history_id_key in ["name", "namespace_id"], "Invalid history ID key '%s'" % history_id_key
    assert '__table__' in nameop, "Missing __table__"
    assert '__always_set__' in nameop, "No always-set fields given"
    assert '__account_payment_info__' in nameop, 'No account payment information present'

    return True


def state_transition_put_account_payment_info( nameop, account_addr, token_type, amount ):
    """
    Call this in a @state_create-decorated method.
    Identifies the account that must be debited.
    """
    assert amount is None or isinstance(amount, (int,long)), 'BUG: amount is {} (type {})'.format(amount, type(amount))
    assert account_addr is None or isinstance(account_addr, (str,unicode))
    assert token_type is None or isinstance(token_type, (str,unicode))
    nameop['__account_payment_info__'] = {
            'address': str(account_addr) if account_addr is not None else None,
            'type': str(token_type) if token_type is not None else None,
            'amount': int(amount) if amount is not None else None
    }


def state_transition_get_table( nameop ):
    """
    Get the table of a state-transition operation
    """
    return nameop['__table__']


def state_transition_get_account_payment_info( nameop ):
    """
    Get the payment information for an account.  Can be None if no account payments are needed
    """
    return nameop['__account_payment_info__']


def state_transition_get_history_id_key( nameop ):
    """
    Get the key of the history ID of a state-transition name operation
    """
    return nameop['__history_id_key__']


def state_transition_get_always_set( nameop ):
    """
    Get thie list of fields we will always set on state transition
    """
    return nameop['__always_set__']


def token_operation_put_account_payment_info(token_op, account_addr, token_type, amount):
    """
    Call this in a @token_operation-decorated method.
    Identifies the account to be debited
    """
    assert isinstance(amount, (int,long)), "BUG: amount is {} (type {})".format(amount, type(amount))
    assert isinstance(account_addr, (str,unicode)), 'BUG: account is {} (type {})'.format(account_addr, type(account_addr))
    assert isinstance(token_type, (str,unicode)), 'BUG: token_type is {} (type {})'.format(token_type, type(token_type))
    token_op['__account_payment_info__'] = {
            'address': str(account_addr),
            'type': str(token_type),
            'amount': int(amount)
    }


def token_operation_put_account_credit_info(token_op, account_addr, token_type, amount):
    """
    Call this in a @token_operation-decorated method.
    Identifies the account to be credited
    """
    assert isinstance(amount, (int,long)), 'BUG: amount is {} (type {})'.format(amount, type(amount))
    assert isinstance(account_addr, (str,unicode)), 'BUG: amount is {} (type {})'.format(account_addr, type(account_addr))
    assert isinstance(token_type, (str,unicode)), 'BUG: token_type is {} (type {})'.format(token_type, type(token_type))
    token_op['__account_credit_info__'] = {
            'address': str(account_addr),
            'type': str(token_type),
            'amount': int(amount)
    }


def token_operation_is_valid(token_op):
    """
    Is a token operation well-formed?
    """
    for tag in token_operation_invariant_tags() + ['opcode']:
        assert tag in token_op, 'Missing {}'.format(tag)

    return True


def token_operation_get_account_payment_info(token_op):
    """
    Get the payment information for an account.
    """
    ret = token_op['__account_payment_info__']
    assert ret is not None, 'BUG: no account payment info set'
    return ret


def token_operation_get_account_credit_info(token_op):
    """
    Get the credit information from a token op
    """
    ret = token_op['__account_credit_info__']
    assert ret is not None, 'BUG: no account credit info set'
    return ret


def token_operation_get_table(token_op):
    """
    Get the table affected
    """
    ret = token_op['__table__']
    assert ret is not None, 'BUG: no table set'
    return ret


import namedb 
import virtualchain_hooks

from .namedb import BlockstackDB, DISPOSITION_RO, DISPOSITION_RW

# this module is suitable to be a virtualchain state engine implementation 
from .virtualchain_hooks import *
