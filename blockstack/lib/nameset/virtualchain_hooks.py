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

# Hooks to the virtual chain's state engine that bind our namedb to the virtualchain package.

import os
import gc

from .namedb import *

from ..config import *
from ..scripts import *

import virtualchain
log = virtualchain.get_logger("blockstack-log")

def get_virtual_chain_name():
   """
   (required by virtualchain state engine)
   
   Get the name of the virtual chain we're building.
   """
   return "blockstack-server"


def get_virtual_chain_version():
   """
   (required by virtualchain state engine)
   
   Get the version string for this virtual chain.
   """
   return VERSION


def get_opcodes():
   """
   (required by virtualchain state engine)
   
   Get the list of opcodes we're looking for.
   """
   return OPCODES 


def get_op_processing_order():
   """
   (required by virtualchain state engine)
   
   Give a hint as to the order in which we process operations 
   """
   return OPCODES 


def get_magic_bytes():
   """
   (required by virtualchain state engine)
   
   Get the magic byte sequence for our OP_RETURNs
   """
   return MAGIC_BYTES


def get_first_block_id():
   """
   (required by virtualchain state engine)
   
   Get the id of the first block to start indexing.
   """ 
   start_block = FIRST_BLOCK_MAINNET
   return start_block


def get_last_block():
    """
    Get the last block processed
    Return the integer on success
    Return None on error
    """
 
    # make this usable even if we haven't explicitly configured virtualchain 
    impl = virtualchain.get_implementation()
    if impl is None:
       impl = sys.modules[__name__]

    lastblock_filename = virtualchain.get_lastblock_filename(impl=impl)
    if os.path.exists( lastblock_filename ):
       try:
           with open(lastblock_filename, "r") as f:
               lastblock = int( f.read().strip() )
               return lastblock

       except Exception, e:
           # this can't ever happen
           log.exception(e)
           return None

    return None


def get_snapshots():
    """
    Read the virtualchain snapshots
    Returns the dict of {snapshots: {$block_height: $consensus_hash}} on success
    Returns None on error
    """
    # make this usable even if we haven't explicitly configured virtualchain 
    impl = virtualchain.get_implementation()
    if impl is None:
       impl = sys.modules[__name__]

    snapshots_filename = virtualchain.get_snapshots_filename(impl=impl)
    if os.path.exists(snapshots_filename):
        try:
            with open(snapshots_filename, 'r') as f:
                snapshots_bin = f.read()
                snapshots = json.loads(snapshots_bin)
                return snapshots

        except Exception as e:
            log.exception(e)
            return None

    return None


def get_db_state( disposition=DISPOSITION_RO ):
   """
   (required by virtualchain state engine)
   
   Callback to the virtual chain state engine.
   Get a handle to our state engine implementation
   (i.e. our name database).

   Note that in this implementation, the database
   handle returned will only support read-only operations by default.
   NO COMMITS WILL BE ALLOWED.
   """
   
   # make this usable even if we haven't explicitly configured virtualchain 
   impl = virtualchain.get_implementation()
   if impl is None:
       impl = sys.modules[__name__]
   
   db_filename = virtualchain.get_db_filename(impl=impl)
   lastblock_filename = virtualchain.get_lastblock_filename(impl=impl)
   lastblock = None
   firstcheck = True 

   for path in [db_filename, lastblock_filename]:
       if os.path.exists( path ):
           # have already created the db
           firstcheck = False

   if not firstcheck and not os.path.exists( lastblock_filename ):
       # this can't ever happen 
       log.error("FATAL: no such file or directory: %s" % lastblock_filename )
       os.abort()

   # verify that it is well-formed, if it exists
   elif os.path.exists( lastblock_filename ):
       try:
           with open(lastblock_filename, "r") as f:
               lastblock = int( f.read().strip() )

       except Exception, e:
           # this can't ever happen
           log.error("FATAL: failed to parse: %s" % lastblock_filename)
           log.exception(e)
           os.abort()

   db_inst = BlockstackDB( db_filename, disposition )

   return db_inst


def db_parse( block_id, txid, vtxindex, op, data, senders, inputs, outputs, fee, db_state=None ):
   """
   (required by virtualchain state engine)
   
   Parse a blockstack operation from a transaction's nulldata (data) and a list of outputs, as well as 
   optionally the list of transaction's senders and the total fee paid.  Use the operation-specific
   extract_${OPCODE}() method to get the data, and make sure the operation-defined fields are all set.

   Return None on error
   
   NOTE: the transactions that our tools put have a single sender, and a single output address.
   This is assumed by this code.
   """

   # basic sanity checks 
   if len(senders) == 0:
       raise Exception("No senders given")
   
   # make sure each op has all the right fields defined 
   try:
       opcode = op_get_opcode_name( op )
       assert opcode is not None, "Unrecognized opcode '%s'"  % op
   except Exception, e:
       log.exception(e)
       log.error("Skipping unrecognized opcode")
       return None

   log.debug("PARSE %s at (%s, %s): %s" % (opcode, block_id, vtxindex, data.encode('hex')))

   # get the data
   op = None
   try:
       op = op_extract( opcode, data, senders, inputs, outputs, block_id, vtxindex, txid )
   except Exception, e:
       log.exception(e)
       op = None

   if op is not None:

       # propagate tx data 
       op['vtxindex'] = int(vtxindex)
       op['txid'] = str(txid)

   else:
       log.error("Unparseable op '%s'" % opcode)

   return op


def check_mutate_fields( op, op_data ):
    """
    Verify that all mutate fields are present.
    """

    mutate_fields = op_get_mutate_fields( op )
    assert mutate_fields is not None, "No mutate fields defined for %s" % op

    missing = []
    for field in mutate_fields:
        if not op_data.has_key(field):
            missing.append(field)

    assert len(missing) == 0, "Missing mutation fields for %s: %s" % (op, ",".join(missing))
    return True


def db_scan_block( block_id, op_list, db_state=None ):
    """
    (required by virtualchain state engine)

    Given the block ID and the list of virtualchain operations in the block,
    do block-level preprocessing:
    * find the state-creation operations we will accept
    * make sure there are no collisions.
    """

    try:
        assert db_state is not None, "BUG: no state given"
    except Exception, e:
        log.exception(e)
        log.error("FATAL: no state given")
        os.abort()

    checked_ops = []
    for op_data in op_list:

        try:
            opcode = op_get_opcode_name( op_data['op'] ) 
            assert opcode is not None, "BUG: unknown op '%s'" % op
        except Exception, e:
            log.exception(e)
            log.error("FATAL: invalid operation")
            os.abort()

        if opcode not in OPCODE_CREATION_OPS:
            continue 

        # make sure there are no collisions:
        # build up our collision table in db_state.
        op_check( db_state, op_data, block_id, checked_ops )
        checked_ops.append( op_data )


    # get collision information for this block
    collisions = db_state.find_collisions( checked_ops )

    # reject all operations that will collide 
    db_state.put_collisions( block_id, collisions )
    


def db_check( block_id, new_ops, op, op_data, txid, vtxindex, checked_ops, db_state=None ):
    """
    (required by virtualchain state engine)
   
    Given the block ID and a parsed operation, check to see if this is a *valid* operation.
    Is this operation consistent with blockstack's rules?
   
    checked_ops is a list of operations already checked by
    this method for this block.
   
    A name or namespace can be affected at most once per block.  If it is 
    affected more than once, then the opcode priority rules take effect, and
    the lower priority opcodes are rejected.

    Return True if it's valid; False if not.
    """

    accept = True 

    if db_state is not None:
        
        try:
            assert 'txid' in op_data, "Missing txid from op"
            assert 'vtxindex' in op_data, "Missing vtxindex from op"
            opcode = op_get_opcode_name( op )
            assert opcode is not None, "BUG: unknown op '%s'" % op
        except Exception, e:
            log.exception(e)
            log.error("FATAL: invalid operation")
            os.abort()

        log.debug("CHECK %s at (%s, %s)" % (opcode, block_id, vtxindex))
        rc = op_check( db_state, op_data, block_id, checked_ops )
        if rc:

            try:
                opcode = op_data.get('opcode', None)
                assert opcode is not None, "BUG: op_check did not set an opcode"
            except Exception, e:
                log.exception(e)
                log.error("FATAL: no opcode set")
                os.abort()

            # verify that all mutate fields are present 
            rc = check_mutate_fields( opcode, op_data )
            if not rc:
                log.error("FATAL: bug in '%s' check() method did not return all mutate fields" % opcode)
                os.abort()

        else:
            accept = False 

    return accept
   
   
def db_commit( block_id, op, op_data, txid, vtxindex, db_state=None ):
    """
    (required by virtualchain state engine)

    Advance the state of the state engine: get a list of all
    externally visible state transitions.
   
    Given a block ID and checked opcode, record it as 
    part of the database.  This does *not* need to write 
    the data to persistent storage, since save() will be 
    called once per block processed.
  
    Returns one or more new name operations on success, which will 
    be fed into virtualchain to translate into a string
    to be used to generate this block's consensus hash.
    """

    if db_state is not None:
        if op_data is not None:

            try:
                assert 'txid' in op_data, "BUG: No txid given"
                assert 'vtxindex' in op_data, "BUG: No vtxindex given"
                assert op_data['txid'] == txid, "BUG: txid mismatch"
                assert op_data['vtxindex'] == vtxindex, "BUG: vtxindex mismatch"
                # opcode = op_get_opcode_name( op_data['op'] )
                opcode = op_data.get('opcode', None)
                assert opcode in OPCODE_PREORDER_OPS + OPCODE_CREATION_OPS + OPCODE_TRANSITION_OPS + OPCODE_STATELESS_OPS, \
                                "BUG: uncategorized opcode '%s'" % opcode

            except Exception, e:
                log.exception(e)
                log.error("FATAL: failed to commit operation")
                os.abort()

            if opcode in OPCODE_STATELESS_OPS:
                # state-less operation 
                return []

            else:
                op_seq = db_state.commit_operation( op_data, block_id )
                return op_seq

        else:
            # final commit for this block 
            try:
                db_state.commit_finished( block_id )
            except Exception, e:
                log.exception(e)
                log.error("FATAL: failed to commit at block %s" % block_id )
                os.abort()

            return None

    else:
        log.error("FATAL: no state engine given")
        os.abort()



def db_save( block_id, consensus_hash, pending_ops, filename, db_state=None ):
   """
   (required by virtualchain state engine)
   
   Save all persistent state to stable storage.
   Called once per block.
   
   Return True on success
   Return False on failure.
   """

   from ..atlas import atlasdb_sync_zonefiles 

   if db_state is not None:
    
        try:
            # pre-calculate the ops hash for SNV
            ops_hash = BlockstackDB.calculate_block_ops_hash( db_state, block_id )
            db_state.store_block_ops_hash( block_id, ops_hash )
        except Exception, e:
            log.exception(e)
            log.error("FATAL: failed to calculate ops hash at block %s" % block_id )
            os.abort()

        try:
            # flush the database
            db_state.commit_finished( block_id )
        except Exception, e:
            log.exception(e)
            log.error("FATAL: failed to commit at block %s" % block_id )
            os.abort()

        try:
            # sync block data to atlas, if enabled
            blockstack_opts = get_blockstack_opts()
            if blockstack_opts.get('atlas', False):
                log.debug("Synchronize Atlas DB for %s" % (block_id-1))
                zonefile_dir = blockstack_opts.get('zonefiles', get_zonefile_dir())

                gc.collect()
                atlasdb_sync_zonefiles( db_state, block_id-1, zonefile_dir=zonefile_dir )
                gc.collect()

        except Exception, e:
            log.exception(e)
            log.error("FATAL: failed to update Atlas db at %s" % block_id )
            os.abort()

        return True

   else:
       log.error("FATAL: no state engine given")
       os.abort()


def db_continue( block_id, consensus_hash ):
    """
    (required by virtualchain state engine)

    Called when virtualchain has synchronized all state for this block.
    Blockstack uses this as a preemption point where it can safely
    exit if the user has so requested.
    """

    # every so often, clean up
    if (block_id % 20) == 0:
        log.debug("Pre-emptive garbage collection at %s" % block_id)
        gc.collect(2)

    return is_running() or os.environ.get("BLOCKSTACK_TEST") == "1"


def sync_blockchain( bt_opts, last_block, expected_snapshots={}, **virtualchain_args ):
    """
    synchronize state with the blockchain.
    Return True on success
    Return False if we're supposed to stop indexing
    Abort on error
    """
 
    # make this usable even if we haven't explicitly configured virtualchain 
    impl = sys.modules[__name__]
    if virtualchain.get_implementation() is not None:
       impl = None

    log.info("Synchronizing database up to block %s" % last_block)

    db_filename = virtualchain.get_db_filename(impl=impl)

    # NOTE: this is the only place where a read-write handle should be created,
    # since this is the only place where the db should be modified.
    new_db = BlockstackDB.borrow_readwrite_instance( db_filename, last_block, expected_snapshots=expected_snapshots )
    rc = virtualchain.sync_virtualchain( bt_opts, last_block, new_db, expected_snapshots=expected_snapshots, **virtualchain_args )
    BlockstackDB.release_readwrite_instance( new_db, last_block )

    return rc
