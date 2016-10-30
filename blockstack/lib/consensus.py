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

import logging
import os
import sys
import json
import datetime
import traceback
import time
import math
import random
import shutil
import tempfile
import binascii
import copy
import threading
import errno

import virtualchain
import blockstack_client

log = virtualchain.get_logger("blockstack-server")

import pybitcoin

import nameset as blockstack_state_engine
import nameset.virtualchain_hooks as virtualchain_hooks

import config

from .b40 import *
from .config import *
from .scripts import *
from .hashing import *
from .storage import *

from .nameset import *
from .operations import *

def rec_to_virtualchain_op( name_rec, block_number, history_index, working_db, untrusted_db ):
    """
    Given a record from the blockstack database,
    convert it into the virtualchain operation that
    was used to create/alter it at the given point
    in the past (i.e. (block_number, history_index)).
    
    @history_index is the index into the name_rec's 
    history that encodes the prior state of the 
    desired virtualchain operation.

    @untrusted_db is the database at 
    the state of the block_number.
    """

    # apply opcodes so we can consume them with virtualchain
    opcode_name = op_get_opcode_name( name_rec['op'] )
    assert opcode_name is not None, "Unrecognized opcode '%s'" % name_rec['op'] 

    ret_op = {}

    if name_rec.has_key('expired') and name_rec['expired']:
        # don't care--wasn't sent at this time
        return None

    ret_op = op_make_restore_diff( opcode_name, name_rec, block_number, history_index, working_db, untrusted_db ) 
    if ret_op is None:
        raise Exception("Failed to restore %s at (%s, %s)" % (opcode_name, block_number, history_index))

    # restore virtualchain fields
    ret_op = virtualchain.virtualchain_set_opfields( ret_op, \
                                                     virtualchain_opcode=getattr( config, opcode_name ), \
                                                     virtualchain_txid=str(name_rec['txid']), \
                                                     virtualchain_txindex=int(name_rec['vtxindex']) )

    ret_op['opcode'] = opcode_name

    # apply the operation.
    # don't worry about ancilliary fields from the name_rec--they'll be ignored.
    merged_ret_op = copy.deepcopy( name_rec )
    merged_ret_op.update( ret_op )
    return merged_ret_op


def rec_restore_snv_consensus_fields( name_rec, block_id ):
    """
    Given a name record at a given point in time, ensure
    that all of its consensus fields are present.
    Because they can be reconstructed directly from the record,
    but they are not always stored in the db, we have to do so here.
    """

    opcode_name = op_get_opcode_name( name_rec['op'] )
    assert opcode_name is not None, "Unrecognized opcode '%s'" % name_rec['op']

    ret_op = {}
    db = get_db_state()

    ret_op = op_snv_consensus_extra( opcode_name, name_rec, block_id, db )

    db.close()

    if ret_op is None:
        raise Exception("Failed to derive extra consensus fields for '%s'" % opcode_name)
   
    ret_op['opcode'] = opcode_name

    merged_op = copy.deepcopy( name_rec )
    merged_op.update( ret_op )

    return merged_op


def block_to_virtualchain_ops( block_id, working_db, untrusted_db ):
    """
    convert a block's name ops to virtualchain ops.
    This is needed in order to recreate the virtualchain
    transactions that generated the block's name operations,
    such as for re-building the db or serving SNV clients.

    Returns the list of virtualchain ops.
    """

    # all records altered at this block, in tx order, as they were
    prior_recs = untrusted_db.get_all_ops_at( block_id )
    log.debug("Records at %s: %s" % (block_id, len(prior_recs)))
    virtualchain_ops = []

    # process records in order by vtxindex
    prior_recs = sorted( prior_recs, key=lambda op: op['vtxindex'] )

    # each name record has its own history, and their interleaving in tx order
    # is what makes up prior_recs.  However, when restoring a name record to
    # a previous state, we need to know the *relative* order of operations
    # that changed it during this block.  This is called the history index,
    # and it maps names to a dict, which maps the the virtual tx index (vtxindex)
    # to integer h such that prior_recs[name][vtxindex] is the hth update to the name
    # record.

    history_index = {}
    for i in xrange(0, len(prior_recs)):
        rec = prior_recs[i]

        if 'name' not in rec.keys():
            continue

        name = str(rec['name'])
        if name not in history_index.keys():
            history_index[name] = { i: 0 }

        else:
            history_index[name][i] = max( history_index[name].values() ) + 1


    for i in xrange(0, len(prior_recs)):

        # only trusted fields
        opcode_name = op_get_opcode_name( prior_recs[i]['op'] )
        assert opcode_name is not None, "Unrecognized opcode '%s'" % prior_recs[i]['op']

        consensus_fields = SERIALIZE_FIELDS.get( opcode_name, None )
        if consensus_fields is None:
            raise Exception("BUG: no consensus fields defined for '%s'" % opcode_name )

        # coerce string, not unicode
        for k in prior_recs[i].keys():
            if type(prior_recs[i][k]) == unicode:
                prior_recs[i][k] = str(prior_recs[i][k])

        # remove virtualchain-specific fields--they won't be trusted
        prior_recs[i] = untrusted_db.sanitize_op( prior_recs[i] )

        for field in prior_recs[i].keys():

            # remove untrusted fields, except for indirect consensus fields
            if field not in consensus_fields and field not in NAMEREC_INDIRECT_CONSENSUS_FIELDS:
                log.debug("OP '%s': Removing untrusted field '%s'" % (opcode_name, field))
                del prior_recs[i][field]

        try:
            # recover virtualchain op from name record
            h = 0
            if 'name' in prior_recs[i]:
                if prior_recs[i]['name'] in history_index:
                    h = history_index[ prior_recs[i]['name'] ][i]

            log.debug("Recover %s" % op_get_opcode_name( prior_recs[i]['op'] ))
            virtualchain_op = rec_to_virtualchain_op( prior_recs[i], block_id, h, working_db, untrusted_db )
        except:
            print json.dumps( prior_recs[i], indent=4, sort_keys=True )
            raise

        if virtualchain_op is not None:
            virtualchain_ops.append( virtualchain_op )

    return virtualchain_ops


def rebuild_database( target_block_id, untrusted_db_path, working_db_path=None, resume_dir=None, start_block=None, expected_snapshots={} ):
    """
    Given a target block ID and a path to an (untrusted) db, reconstruct it in a temporary directory by
    replaying all the nameops it contains.

    Optionally check that the snapshots in @expected_snapshots match up as we verify.
    @expected_snapshots maps str(block_id) to str(consensus hash)

    Return the consensus hash calculated at the target block.
    Return None on verification failure (i.e. we got a different consensus hash than one for the same block in expected_snapshots)
    """

    # reconfigure the virtualchain to use a temporary directory,
    # so we don't interfere with this instance's primary database
    working_dir = None
    if resume_dir is None:
        working_dir = tempfile.mkdtemp( prefix='blockstack-verify-database-' )
    else:
        working_dir = resume_dir

    blockstack_state_engine.working_dir = working_dir

    virtualchain.setup_virtualchain( impl=blockstack_state_engine )

    if resume_dir is None:
        # not resuming
        start_block = virtualchain.get_first_block_id()
    else:
        # resuming
        old_start_block = start_block
        start_block = get_lastblock()
        if start_block is None:
            start_block = old_start_block

    log.debug( "Rebuilding database from %s to %s" % (start_block, target_block_id) )

    # feed in operations, block by block, from the untrusted database
    untrusted_db = BlockstackDB( untrusted_db_path, DISPOSITION_RO )

    # working db, to build up the operations in the untrusted db block-by-block
    working_db = None
    if working_db_path is None:
        working_db_path = virtualchain.get_db_filename()

    working_db = BlockstackDB( working_db_path, DISPOSITION_RW )

    # map block ID to consensus hashes
    consensus_hashes = {}

    for block_id in xrange( start_block, target_block_id+1 ):

        untrusted_db.lastblock = block_id
        virtualchain_ops = block_to_virtualchain_ops( block_id, working_db, untrusted_db )

        # feed ops to virtualchain to reconstruct the db at this block
        consensus_hash = working_db.process_block( block_id, virtualchain_ops )
        log.debug("VERIFY CONSENSUS(%s): %s" % (block_id, consensus_hash))

        consensus_hashes[block_id] = consensus_hash
        if block_id in expected_snapshots:
            if expected_snapshots[block_id] != consensus_hash:
                log.error("DATABASE IS NOT CONSISTENT AT %s: %s != %s" % (block_id, expected_snashots[block_id], consensus_hash))
                return None


    # final consensus hash
    return consensus_hashes[ target_block_id ]


def verify_database( trusted_consensus_hash, consensus_block_id, untrusted_db_path, working_db_path=None, start_block=None, expected_snapshots={} ):
    """
    Verify that a database is consistent with a
    known-good consensus hash.

    This algorithm works by creating a new database,
    parsing the untrusted database, and feeding the untrusted
    operations into the new database block-by-block.  If we
    derive the same consensus hash, then we can trust the
    database.
    """

    final_consensus_hash = rebuild_database( consensus_block_id, untrusted_db_path, working_db_path=working_db_path, start_block=start_block, expected_snapshots=expected_snapshots )

    # did we reach the consensus hash we expected?
    if final_consensus_hash is not None and final_consensus_hash == trusted_consensus_hash:
        return True

    else:
        log.error("Unverifiable database state stored in '%s'" % blockstack_state_engine.working_dir )
        return False

