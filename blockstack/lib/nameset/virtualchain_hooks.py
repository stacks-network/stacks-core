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
import copy

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


def get_opfields():
    """
    (required by virtaulchain state engine)
    Get a dict that maps each opcode to the list of transaction fields to serialize
    """
    return BlockstackDB.make_opfields()


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


def get_blockchain():
    """
    (required by virtualchain state engine)

    Which blockchain do we index?
    """
    return "bitcoin"


def get_valid_transaction_window():
    """
    (required by virtualchain state engine)

    How many blocks is a transaction good for?
    """
    return 24


def get_initial_snapshots():
    """
    (required by virtualchain state engine)

    What are the initial consensus hashes?
    """
    return GENESIS_SNAPSHOT


def get_last_block(working_dir):
    """
    Get the last block processed
    Return the integer on success
    Return None on error
    """

    # make this usable even if we haven't explicitly configured virtualchain 
    impl = sys.modules[__name__]
    return BlockstackDB.get_lastblock(impl, working_dir)


def get_snapshots(working_dir, start_block=None, end_block=None):
    """
    Read the virtualchain snapshots
    Returns the dict of {snapshots: {$block_height: $consensus_hash}} on success
    Returns None on error
    """

    # make this usable even if we haven't explicitly configured virtualchain 
    impl = sys.modules[__name__]
    return BlockstackDB.get_consensus_hashes(impl, working_dir, start_block_height=start_block, end_block_height=end_block)


def get_db_state(working_dir):
    """
    Callback to the virtual chain state engine.
    Get a *read-only* handle to our state engine implementation
    (i.e. our name database).

    Note that in this implementation, the database
    handle returned will only support read-only operations by default.
    Attempts to save state with the handle will lead to program abort.

    Returns the handle on success
    Raises on error
    """
    impl = sys.modules[__name__]
    db_inst = BlockstackDB.get_readonly_instance(working_dir)
    assert db_inst, 'Failed to instantiate database handle'
    return db_inst


def get_or_instantiate_db_state(working_dir):
    """
    Get a read-only handle to the DB.
    Instantiate it first if it doesn't exist.

    DO NOT CALL WHILE INDEXING

    Returns the handle on success
    Raises on error
    """

    # instantiates
    new_db = BlockstackDB.borrow_readwrite_instance(working_dir, -1)
    BlockstackDB.release_readwrite_instance(new_db, -1)

    return get_db_state(working_dir)


def db_parse( block_id, txid, vtxindex, op, data, senders, inputs, outputs, fee, db_state=None, **virtualchain_hints ):
   """
   (required by virtualchain state engine)
   
   Parse a blockstack operation from a transaction.  The transaction fields are as follows:
   * `block_id` is the blockchain height at which this transaction occurs
   * `txid` is the transaction ID
   * `data` is the scratch area of the transaction that contains the actual virtualchain operation (e.g. "id[opcode][payload]")
   * `senders` is a list in 1-to-1 correspondence with `inputs` that contains information about what funded the inputs
   * `inputs` are the list of inputs to the transaction.  Some blockchains (like Bitcoin) support multiple inputs, whereas others (like Ethereum) support only 1.
   * `outputs` are the list of outputs of the transaction.  Some blockchains (like Bitcoin) support multiple outputs, whereas others (like Ethereum) support only 1.
   * `fee` is the transaction fee.

   `db_state` is the StateEngine-derived class.  This is a BlockstackDB instance.
   `**virtualchain_hints` is a dict with extra virtualchain hints that may be relevant.  We require:
   * `raw_tx`: the hex-encoded string containing the raw transaction.

   Returns a dict with the parsed operation on success.
   Return None on error
   """
   # basic sanity checks 
   if len(senders) == 0:
       raise Exception("No senders given")

   # this virtualchain instance must give the 'raw_tx' hint
   assert 'raw_tx' in virtualchain_hints, 'BUG: incompatible virtualchain: requires raw_tx support'

   # internal sanity check 
   raw_tx = virtualchain_hints['raw_tx']
   btc_tx_data = virtualchain.btc_tx_deserialize(raw_tx)
   test_btc_tx = virtualchain.btc_tx_serialize({'ins': inputs, 'outs': outputs, 'locktime': btc_tx_data['locktime'], 'version': btc_tx_data['version']})
   assert raw_tx == test_btc_tx, 'TX mismatch: {} != {}'.format(raw_tx, test_btc_tx)

   # make sure each op has all the right fields defined 
   try:
       opcode = op_get_opcode_name(op)
       assert opcode is not None, "Unrecognized opcode '%s'"  % op
   except Exception, e:
       log.exception(e)
       log.error("Skipping unrecognized opcode")
       return None

   log.debug("PARSE %s at (%s, %s): %s" % (opcode, block_id, vtxindex, data.encode('hex')))

   # get the data
   op_data = None
   try:
       op_data = op_extract( opcode, data, senders, inputs, outputs, block_id, vtxindex, txid )
   except Exception, e:
       log.exception(e)
       op_data = None

   if op_data is not None:
       try:
           assert 'op' in op_data, 'BUG: missing op'
       except Exception as e:
           log.exception(e)
           log.error("BUG: missing op")
           os.abort()

       original_op_data = copy.deepcopy(op_data)

       # propagate tx data 
       op_data['vtxindex'] = int(vtxindex)
       op_data['txid'] = str(txid)
       op_data['__original_op_data__'] = original_op_data

   else:
       log.error("Unparseable op '%s'" % opcode)

   return op_data


def check_mutate_fields( op, op_data ):
    """
    Verify that all mutate fields are present.
    Return True if so.
    Raise an exception (AssertionError) if not.
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

    This modifies op_list, but returns nothing.
    This aborts on runtime error.
    """

    try:
        assert db_state is not None, "BUG: no state given"
    except Exception, e:
        log.exception(e)
        log.error("FATAL: no state given")
        os.abort()

    log.debug("SCAN BEGIN: {} ops at block {}".format(len(op_list), block_id))
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
    log.debug("SCAN END: {} ops at block {} ({} collisions)".format(len(op_list), block_id, len(collisions)))


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

    Return True if it's valid
    Return False if not.
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
   

def check_quirks(block_id, block_op, db_state):
    """
    Check that all serialization compatibility quirks have been preserved.
    Used primarily for testing.
    """
    if op_get_opcode_name(block_op['op']) in OPCODE_NAME_NAMEOPS and op_get_opcode_name(block_op['op']) not in OPCODE_NAME_STATE_PREORDER:
        assert 'last_creation_op' in block_op, 'QUIRK BUG: missing last_creation_op in {}'.format(op_get_opcode_name(block_op['op']))

        if block_op['last_creation_op'] == NAME_IMPORT:
            # the op_fee will be a float if the name record was created with a NAME_IMPORT
            assert isinstance(block_op['op_fee'], float), 'QUIRK BUG: op_fee is not a float when it should be'
   
    return

   
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
    try:
        assert db_state is not None
    except:
        log.error("FATAL: no state given")
        os.abort()

    if op != 'virtualchain_final':
        # ongoing processing.
        # do sanity checks
        try:
            assert '__original_op_data__' in op_data, 'BUG: no __original_op_data__'
            assert 'txid' in op_data, "BUG: No txid given"
            assert 'vtxindex' in op_data, "BUG: No vtxindex given"
            assert op_data['txid'] == txid, "BUG: txid mismatch"
            assert op_data['vtxindex'] == vtxindex, "BUG: vtxindex mismatch"
            
            opcode = op_data.get('opcode', None)
            assert opcode in OPCODE_PREORDER_OPS + OPCODE_CREATION_OPS + OPCODE_TRANSITION_OPS + OPCODE_STATELESS_OPS, \
                            "BUG: uncategorized opcode '%s'" % opcode

        except Exception, e:
            log.exception(e)
            log.error("FATAL: failed to commit operation")
            os.abort()

        # from db_parse
        original_op_data = op_data['__original_op_data__']
        del op_data['__original_op_data__']

        # save, and get the sequence of committed operations
        consensus_ops = []
        if opcode in OPCODE_STATELESS_OPS:
            # state-less operation 
            consensus_ops = []

        else:
            consensus_op = db_state.commit_operation(original_op_data, op_data, block_id)
            
            # make sure compatibility quirks are preserved
            check_quirks(block_id, consensus_op, db_state)

            consensus_ops = [consensus_op]
        
        return consensus_ops

    else:
        # final commit for this block 
        try:
            db_state.commit_finished( block_id )
        except Exception, e:
            log.exception(e)
            log.error("FATAL: failed to commit at block %s" % block_id )
            os.abort()

        return None


def db_save( block_height, consensus_hash, ops_hash, accepted_ops, virtualchain_ops_hints, db_state=None ):
   """
   (required by virtualchain state engine)
   
   Save all persistent state to stable storage.
   Called once per block.

   In Blockstack's case, we save transactions as we process them.
   The only thing to do here is to synchronize the Atlas DB and clean up the 
   BlockstackDB instance in preparation for receiving the next blocks' transactions.

   Return True on success
   Return False on failure.
   """
   from ..atlas import atlasdb_sync_zonefiles 

   if db_state is not None:

        blockstack_opts = get_blockstack_opts()
        new_zonefile_infos = None

        try:
            # flush the database
            db_state.commit_finished( block_height )
        except Exception as e:
            log.exception(e)
            log.error("FATAL: failed to commit at block %s" % block_height )
            os.abort()
        
        try:
            atlas_state = None
            if hasattr(db_state, 'atlas_state') and db_state.atlas_state is not None:
                # normal course of action 
                atlas_state = db_state.atlas_state

            # sync block data to atlas, if enabled
            if is_atlas_enabled(blockstack_opts):
                log.debug("Synchronize Atlas DB for {}".format(block_height))
                zonefile_dir = blockstack_opts['zonefiles']
                atlasdb_path = blockstack_opts['atlasdb_path']

                # NOTE: set end_block explicitly since db_state.lastblock still points to the previous block height
                gc.collect()
                new_zonefile_infos = atlasdb_sync_zonefiles(db_state, block_height, zonefile_dir, atlas_state, path=atlasdb_path, end_block=block_height+1)
                gc.collect()

        except Exception as e:
            log.exception(e)
            log.error("FATAL: failed to update Atlas db at %s" % block_height )
            os.abort()
        
        try:
            # sync subdomain state for this block range, if enabled
            if is_subdomains_enabled(blockstack_opts):
                subdomain_index = None
                instantiated = False

                if hasattr(db_state, 'subdomain_index') and db_state.subdomain_index is not None:
                    # normal course of action
                    subdomain_index = db_state.subdomain_index
                else:
                    # verifying a database
                    from ..subdomains import SubdomainIndex
                    log.warning("Instantiating subdomain index")
                    subdomain_index = SubdomainIndex(blockstack_opts['subdomaindb_path'], blockstack_opts=blockstack_opts)
                    instantiated = True
               
                log.debug("Synchronize subdomain index for {}".format(block_height))

                gc.collect()
                subdomain_index.index(block_height, block_height+1)
                gc.collect()

                if instantiated:
                    # invalidate 
                    subdomain_index.close()
                    subdomain_index = None

        except Exception as e:
            log.exception(e)
            log.error("FATAL: failed to update subdomains db at {}".format(block_height))
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


def sync_blockchain( working_dir, bt_opts, last_block, server_state, expected_snapshots={}, **virtualchain_args ):
    """
    synchronize state with the blockchain.
    Return True on success
    Return False if we're supposed to stop indexing
    Abort on error
    """
    
    subdomain_index = server_state['subdomains']
    atlas_state = server_state['atlas']
    
    # make this usable even if we haven't explicitly configured virtualchain 
    impl = sys.modules[__name__]
    log.info("Synchronizing database {} up to block {}".format(working_dir, last_block))

    # NOTE: this is the only place where a read-write handle should be created,
    # since this is the only place where the db should be modified.
    new_db = BlockstackDB.borrow_readwrite_instance(working_dir, last_block, expected_snapshots=expected_snapshots)

    # propagate runtime state to virtualchain callbacks
    new_db.subdomain_index = subdomain_index
    new_db.atlas_state = atlas_state
    
    rc = virtualchain.sync_virtualchain(bt_opts, last_block, new_db, expected_snapshots=expected_snapshots, **virtualchain_args)
    
    BlockstackDB.release_readwrite_instance(new_db, last_block)

    return rc
