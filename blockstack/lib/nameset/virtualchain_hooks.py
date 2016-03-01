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

# Hooks to the virtual chain's state engine that bind our namedb to the virtualchain package.

import os
from binascii import hexlify, unhexlify
import time
import sys

import pybitcoin 
import traceback
import json
import copy
import threading

from .namedb import BlockstackDB, DISPOSITION_RO, DISPOSITION_RW

from ..config import *
from ..operations import *

import virtualchain

from ..scripts import get_burn_fee_from_outputs

if not globals().has_key('log'):
    log = virtualchain.session.log


def get_virtual_chain_name(testset=False):
   """
   (required by virtualchain state engine)
   
   Get the name of the virtual chain we're building.
   """
   
   if testset:
       return "blockstack-server-test"
   
   else:
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
    
   # make this usable even if we haven't explicitly configured virtualchain 
   impl = sys.modules[__name__]
   if virtualchain.get_implementation() is not None:
      impl = None

   blockstack_opts = default_blockstack_opts( virtualchain.get_config_filename(impl=impl) )
   if blockstack_opts['testset']:
       return MAGIC_BYTES_TESTSET
   
   else:
       return MAGIC_BYTES_MAINSET


def get_first_block_id():
   """
   (required by virtualchain state engine)
   
   Get the id of the first block to start indexing.
   """ 
    
   # make this usable even if we haven't explicitly configured virtualchain 
   impl = sys.modules[__name__]
   if virtualchain.get_implementation() is not None:
      impl = None

  
   blockstack_opts = default_blockstack_opts( virtualchain.get_config_filename(impl=impl) )
   start_block = None
   
   if TESTNET:
       if blockstack_opts['testset']:
           start_block = FIRST_BLOCK_TESTNET_TESTSET
       else:
           start_block = FIRST_BLOCK_TESTNET
   else:
       if blockstack_opts['testset']:
           start_block = FIRST_BLOCK_MAINNET_TESTSET
       else:
           start_block = FIRST_BLOCK_MAINNET

   return start_block


def get_db_state():
   """
   (required by virtualchain state engine)
   
   Callback to the virtual chain state engine.
   Get a handle to our state engine implementation
   (i.e. our name database).
   """
   
   global blockstack_db, blockstack_db_mtime, blockstack_db_lock, blockstack_db_lastblock

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
       sys.exit(1)

   elif os.path.exists( lastblock_filename ):
       try:
           with open(lastblock_filename, "r") as f:
               lastblock = int( f.read().strip() )

       except Exception, e:
           # this can't ever happen
           log.error("FATAL: failed to parse: %s" % lastblock_filename)
           log.exception(e)
           sys.exit(1)

   db_inst = BlockstackDB( db_filename, DISPOSITION_RO )

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

   TODO: refactor--move into individual operations
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

   op_fee = get_burn_fee_from_outputs( outputs )

   log.debug("PARSE %s at (%s, %s): %s" % (opcode, block_id, vtxindex, data.encode('hex')))

   # get the data
   op = op_extract( opcode, data, senders, inputs, outputs, block_id, vtxindex, txid )
   if op is not None:

       # propagate fees
       if op_fee is not None:
          op['op_fee'] = op_fee

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
        sys.exit(1)

    checked_ops = []
    for op_data in op_list:

        try:
            opcode = op_get_opcode_name( op_data['op'] ) 
            assert opcode is not None, "BUG: unknown op '%s'" % op
        except Exception, e:
            log.exception(e)
            log.error("FATAL: invalid operation")
            sys.exit(1)

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
    


def db_check( block_id, op, op_data, txid, vtxindex, checked_ops, db_state=None ):
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
            sys.exit(1)

        # log.debug("CHECK %s at (%s, %s)" % (opcode, block_id, vtxindex))
        rc = op_check( db_state, op_data, block_id, checked_ops )
        if rc:

            try:
                opcode = op_data.get('opcode', None)
                assert opcode is not None, "BUG: op_check did not set an opcode"
            except Exception, e:
                log.exception(e)
                log.error("FATAL: no opcode set")
                sys.exit(1)

            # verify that all mutate fields are present 
            rc = check_mutate_fields( opcode, op_data )
            if not rc:
                log.error("FATAL: bug in '%s' check() method did not return all mutate fields" % opcode)
                sys.exit(1)

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
                sys.exit(1)

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
                sys.exit(1)

            return None

    else:
        log.error("FATAL: no state engine given")
        sys.exit(1)



def db_save( block_id, consensus_hash, pending_ops, filename, db_state=None ):
   """
   (required by virtualchain state engine)
   
   Save all persistent state to stable storage.
   Clear out expired names in the process.
   Called once per block.
   
   Return True on success
   Return False on failure.
   """
 
   if db_state is not None:

       try:
           db_state.commit_finished( block_id )
       except Exception, e:
           log.exception(e)
           log.error("FATAL: failed to commit at block %s" % block_id )
           sys.exit(1)

       return True

   else:
       log.error("FATAL: no state engine given")
       sys.exit(1)


def sync_blockchain( bt_opts, last_block ):
    """
    synchronize state with the blockchain.
    build up the next blockstack_db
    """
 
    # make this usable even if we haven't explicitly configured virtualchain 
    impl = sys.modules[__name__]
    if virtualchain.get_implementation() is not None:
       impl = None

    log.info("Synchronizing database up to block %s" % last_block)

    db_filename = virtualchain.get_db_filename(impl=impl)

    new_db = BlockstackDB.borrow_readwrite_instance( db_filename, lastblock )

    virtualchain.sync_virtualchain( bt_opts, last_block, new_db )

    BlockstackDB.release_readwrite_instance( new_db, lastblock )


def stop_sync_blockchain():
    """
    stop synchronizing with the blockchain
    """
    global blockstack_db, blockstack_db_lock

    blockstack_db_lock.acquire()
    if blockstack_db is None:
        return 

    blockstack_db.stop_build()
    blockstack_db_lock.release()

