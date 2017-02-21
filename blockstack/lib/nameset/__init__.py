#!/usr/bin/env python
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

from ..config import OPCODE_CREATION_OPS, OPCODE_TRANSITION_OPS, op_get_opcode_name

import virtualchain
log = virtualchain.get_logger("blockstack-server")


# fields that *must* be present 
CONSENSUS_FIELDS_REQUIRED = [
    'op',
    'txid',
    'vtxindex'
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

# common set of fields that will need to be backed up to a name's history when applying an operation 
NAMEREC_BACKUP_FIELDS = NAMEREC_MUTATE_FIELDS[:]

NAMEREC_NAME_BACKUP_FIELDS = [
    'transfer_send_block_id'
]

# fields that are not fed into the consensus hash, but are used to generate
# consensus-affecting fields.  They must be present when restoring a prior
# version of a name.
NAMEREC_INDIRECT_CONSENSUS_FIELDS = [
    'opcode',
    'transfer_send_block_id'
]

def state_create_invariant_tags():
    """
    Get a list of state-create invariant tags.
    """
    return [
        '__preorder__',
        '__prior_history__',
        '__table__',
        '__history_id_key__',
        '__state_create__'
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

            return rc
        return wrapped_check
    return wrap


# sanity check decorator for state-creating operations 
def state_create(history_id_key, table_name, collision_checker, always_set=[]):
    """
    Decorator for the check() method on state-creating operations.
    Makes sure that:
    * there is a __preorder__ field set, which contains the state-creating operation's associated preorder
    * there is a __prior_history__ field set, which contains the state-creating operation's associated prior state history
    * there is a __table__ field set, which contains the table into which to insert this state into
    * there is a __history_id_key__ field set, which identifies the table's primary key name
    * there are no unexpired, duplicate instances of this state with this history id.
    (i.e. if we're preordering a name that had previously expired, we need to preserve its history)
    """

    def wrap( check ):
        def wrapped_check( state_engine, nameop, block_id, checked_ops ):
            rc = check( state_engine, nameop, block_id, checked_ops )

            # succeeded, and still a state-creating operation?
            if rc and op_get_opcode_name( nameop['op'] ) in OPCODE_CREATION_OPS:

                # ensure that there's now a __preorder__ and a __prior_history__
                try:
                    assert '__preorder__' in nameop.keys(), "Missing __preorder__"
                    assert '__prior_history__' in nameop.keys(), "Missing __prior_history__"
                except Exception, e:
                    log.exception(e)
                    log.error("FATAL: missing fields")
                    sys.exit(1)

                # propagate __table__ and __history_id_key__
                nameop['__table__'] = table_name
                nameop['__history_id_key__'] = history_id_key
                nameop['__state_create__'] = True
                nameop['__always_set__'] = always_set

                # sanity check
                invariant_tags = state_create_invariant_tags()
                for tag in invariant_tags:
                    assert tag in nameop, "BUG: missing invariant tag '%s'" % tag

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
        '__always_set__'
    ]


# sanity check decorator for state-transition operations 
def state_transition(history_id_key, table_name, always_set=[]):
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

                # sanity check
                invariant_tags = state_transition_invariant_tags()
                for tag in invariant_tags:
                    assert tag in nameop, "BUG: missing invariant tag '%s'" % tag

            return rc
        return wrapped_check
    return wrap


def get_state_invariant_tags():
    """
    Get the set of state invariant tags for a given opcode
    """
    return list(set( state_create_invariant_tags() + state_transition_invariant_tags() ))


def state_create_put_preorder( nameop, preorder ):
    """
    Call this in a @state_create-decorated method.
    """
    nameop['__preorder__'] = preorder


def state_create_put_prior_history( nameop, prior_history_rec ):
    """
    Call this in a @state_create-decorated method.
    """
    nameop['__prior_history__'] = prior_history_rec


def state_create_is_valid( nameop ):
    """
    Is a nameop a valid state-preorder operation?
    """
    assert '__state_create__' in nameop, "Not tagged with @state_create"
    assert nameop['__state_create__'], "BUG: tagged False by @state_create"
    assert '__preorder__' in nameop, "No preorder"
    assert '__prior_history__' in nameop, "No prior history"
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


def state_create_get_prior_history( nameop ):
    """
    Get the prior history for a state-creating operation
    """
    return nameop['__prior_history__']


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

    return True


def state_transition_get_table( nameop ):
    """
    Get the table of a state-transition operation
    """
    return nameop['__table__']


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


def prior_history_create( op_data, old_rec, block_number, state_engine, extra_backup_fields=[] ):
    """
    Given a state-creating operation and the older version of
    of said state (possibly expired, or previously-imported, etc.),
    create a history for it.
    """

    from ..operations import SERIALIZE_FIELDS, op_snv_consensus_extra

    opcode = op_get_opcode_name( op_data['op'] ) 
    try:
        serialize_fields = SERIALIZE_FIELDS.get( opcode, None )
        assert serialize_fields is not None, "Undefined opcode '%s'" % opcode
    except Exception, e:
        log.exception(e)
        log.error("FATAL: missing fields")
        sys.exit(1)

    try:
        assert 'history' in old_rec.keys()
    except Exception, e:
        log.exception(e)
        log.error("FATAL: missing prior hitsory")
        sys.exit(1)

    hist = {}
    for field in list(set(serialize_fields + extra_backup_fields)):
        hist[field] = old_rec.get(field, None)

    hist['history'] = old_rec['history']
    state_engine.add_all_snv_consensus_values( op_get_opcode_name(hist['op']), hist, block_number ) 
    hist['history_snapshot'] = True

    del hist['history']
    prior_history = {
        block_number: [hist]
    }

    return prior_history


def prior_history_is_valid( prior_history_rec ):
    """
    Is the given dict a valid prior history, 
    created by "prior_history"?
    """

    assert type(prior_history_rec) == dict, "Not a dict"
    assert len(prior_history_rec.keys()) == 1, "Invalid number of history blocks"
    assert len(prior_history_rec[ prior_history_rec.keys()[0] ]) == 1, "Invalid number of history snapshots"
    return True


def prior_history_block_number( prior_history_rec ):
    """
    Get the block number of a prior history.
    """
    assert prior_history_is_valid( prior_history_rec )
    return prior_history_rec.keys()[0]


import namedb 
import virtualchain_hooks

from .namedb import BlockstackDB, DISPOSITION_RO, DISPOSITION_RW

# this module is suitable to be a virtualchain state engine implementation 
from .virtualchain_hooks import *

from db import sqlite3_find_tool, sqlite3_backup

