#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org
    
    This file is part of Blockstore
    
    Blockstore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    Blockstore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore.  If not, see <http://www.gnu.org/licenses/>.
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

from .namedb import BlockstoreDB

from ..config import *
from ..operations import *

import virtualchain

from ..scripts import get_burn_fee_from_outputs

if not globals().has_key('log'):
    log = virtualchain.session.log

blockstore_db = None
blockstore_db_mtime = None
blockstore_db_lastblock = None
blockstore_db_lock = threading.Lock()


def get_virtual_chain_name(testset=False):
   """
   (required by virtualchain state engine)
   
   Get the name of the virtual chain we're building.
   """
   
   if testset:
       return "blockstore-test"
   
   else:
       return "blockstore"


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

   blockstore_opts = default_blockstore_opts( virtualchain.get_config_filename(impl=impl) )
   if blockstore_opts['testset']:
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

  
   blockstore_opts = default_blockstore_opts( virtualchain.get_config_filename(impl=impl) )
   start_block = None
   
   if TESTNET:
       if blockstore_opts['testset']:
           start_block = FIRST_BLOCK_TESTNET_TESTSET
       else:
           start_block = FIRST_BLOCK_TESTNET
   else:
       if blockstore_opts['testset']:
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

   Callers in Blockstore should use this method as well,
   since it ensures that there is at most one copy of 
   the db in RAM.
   """
   
   global blockstore_db, blockstore_db_mtime, blockstore_db_lock, blockstore_db_lastblock

   # make this usable even if we haven't explicitly configured virtualchain 
   impl = virtualchain.get_implementation()
   if impl is None:
       impl = sys.modules[__name__]
   
   db_filename = virtualchain.get_db_filename(impl=impl)
   lastblock_filename = virtualchain.get_lastblock_filename(impl=impl)
   db_mtime = None
   lastblock = None
   firstcheck = True 

   for path in [db_filename, lastblock_filename]:
       if os.path.exists( path ):
           firstcheck = False

   if os.path.exists( db_filename ):
       try:
           db_mtime = os.stat( db_filename ).st_mtime 
       except Exception, e:
           # this can't ever happen 
           log.error("FATAL: failed to stat: %s" % db_mtime)
           log.exception(e)
           sys.exit(1)

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

   blockstore_db_lock.acquire()

   if db_mtime is None or lastblock is None or db_mtime != blockstore_db_mtime or lastblock != blockstore_db_lastblock:
      # was modified since loaded 
      # force a reload
      log.info("Invalidating cached db state (%s changed)" % db_filename)
      blockstore_db = None

   if blockstore_db is not None:
      # not invalidated yet
      blockstore_db_lock.release()
      return blockstore_db 
   
   log.info("(Re)Loading blockstore state from '%s'" % db_filename )
   blockstore_db = BlockstoreDB( db_filename )
   blockstore_db_mtime = db_mtime
   blockstore_db_lastblock = lastblock

   blockstore_db_lock.release()
   return blockstore_db


def invalidate_cached_db( needlock=True ):
    """
    Clear out the global cached copy of the db
    """

    global blockstore_db, blockstore_db_lock

    if needlock:
        blockstore_db_lock.acquire()

    del blockstore_db
    blockstore_db = None

    if needlock:
        blockstore_db_lock.release()


def db_parse( block_id, txid, vtxindex, opcode, data, senders, inputs, outputs, fee, db_state=None ):
   """
   (required by virtualchain state engine)
   
   Parse a blockstore operation from a transaction's nulldata (data) and a list of outputs, as well as 
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
   opcode_name = OPCODE_NAMES.get(opcode, None)
   if opcode_name is None:
       raise Exception("Unrecognized opcode '%s'" % opcode)

   op_fee = get_burn_fee_from_outputs( outputs )

   # get the data
   op = op_extract( opcode_name, data, senders, inputs, outputs )
   if op is not None:

       # propagate fees
       if fee is not None:
          op['fee'] = fee 
         
       if op_fee is not None:
          op['op_fee'] = op_fee

       # propagate tx data 
       op['vtxindex'] = int(vtxindex)
       op['txid'] = str(txid)

   else:
       log.error("Unparseable op '%s'" % opcode)

   return op


def db_check( block_id, checked_ops, opcode, op, txid, vtxindex, db_state=None ):
   """
   (required by virtualchain state engine)
   
   Given the block ID and a parsed operation, check to see if this is a *valid* operation.
   Is this operation consistent with blockstore's rules?
   
   checked_ops is a dict that maps opcodes to operations already checked by
   this method for this block.
   
   A name or namespace can be affected at most once per block.  If it is 
   affected more than once, then the opcode priority rules take effect, and
   the lower priority opcodes are rejected.

   Return True if it's valid; False if not.
   """

   if db_state is not None:
    
      db = db_state
      rc = False
    
      all_ops = checked_ops['virtualchain_all_ops']

      # find any collisions and mark them
      colliding_names, colliding_namespaces = db.log_prescan_find_collisions( checked_ops, all_ops, block_id )
      
      # sanity check...
      if opcode not in OPCODES:
         log.error("Unrecognized opcode '%s'" % (opcode))
         return False 
     
      if not op.has_key('txid'):
         log.error("Op '%s' is missing 'txid'" % (opcode))
         return False 

      if not op.has_key('vtxindex'):
         log.error("Op '%s' is missing 'vtxindex'" % (opcode))
         return False 

      # check op for correctness
      if opcode == NAME_PREORDER:
         rc = db.log_preorder( checked_ops, op, block_id )

      elif opcode == NAME_PREORDER_MULTI:
         # multiple preorders at once 
         rc = db.log_preorder_multi( checked_ops, op, block_id )

      elif opcode == NAME_REGISTRATION:
         if op['name'] not in colliding_names:
             rc = db.log_registration( checked_ops, op, block_id )
         else:
             rc = False
             log.error("COLLISION %s" % op['name'])

      elif opcode == NAME_REGISTRATION_MULTI:
         rc = True
         for name in op['names']:
             if name in colliding_names:
                 rc = False 
                 log.error("COLLISION %s" % name)

         if rc:
            rc = db.log_registration_multi( checked_ops, op, block_id )
         
      elif opcode == NAME_UPDATE:
         rc = db.log_update( checked_ops, op, block_id )
      
      elif opcode == NAME_TRANSFER:
         rc = db.log_transfer( checked_ops, op, block_id )
      
      elif opcode == NAME_REVOKE:
         rc = db.log_revoke( checked_ops, op, block_id )
      
      elif opcode == NAME_IMPORT:
         rc = db.log_name_import( checked_ops, op, block_id )
         
      elif opcode == NAMESPACE_PREORDER:
         rc = db.log_namespace_preorder( checked_ops, op, block_id )
      
      elif opcode == NAMESPACE_REVEAL:
         if op['namespace_id'] not in colliding_namespaces:
             rc = db.log_namespace_reveal( checked_ops, op, block_id )
         else:
             rc = False 
             log.error("COLLISION %s" % op['namespace_id'])
      
      elif opcode == NAMESPACE_READY:
         rc = db.log_namespace_ready( checked_ops, op, block_id )
         
      elif opcode == ANNOUNCE:
         rc, announcer_id = db.log_announce( checked_ops, op, block_id )
         if rc:
             # valid announcement
             announce_hash = op['message_hash']

             # go get the text...
             announcement_text = get_announcement( announce_hash ) 
             log.critical("ANNOUNCEMENT (from %s): %s\n------BEGIN MESSAGE------\n%s\n------END MESSAGE------\n" % (announcer_id, announce_hash, announcement_text))
             
             store_announcement( announce_hash, announcement_text )

         # we do not process ANNOUNCEs, since they won't be fed into the consensus hash
         return False 

      debug_op = copy.deepcopy( op )
      if debug_op.has_key('history'):
         del debug_op['history']

      if rc:
         log.debug("ACCEPT op '%s' (%s)" % (opcode, json.dumps(debug_op, sort_keys=True)))

      else:
         log.debug("REJECT op '%s' (%s)" % (opcode, json.dumps(debug_op, sort_keys=True)))
         
      return rc
   
   else:
      log.error("No state engine defined")
      return False
   
   
def db_commit( block_id, opcode, op, txid, vtxindex, db_state=None ):
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
   

   op_seq = None    # sequence of resulting operations from this tx
   if db_state is not None:
      
      db = db_state
      
      if op is not None:

        # committing an operation
        # pass along tx info
        if not op.has_key('txid'):
            raise Exception("op '%s' does not have txid" % op['opcode'])

        if op['txid'] != txid:
            raise Exception("op '%s' txid mismatch: %s (%s) != %s %s)" % (op['opcode'], op['txid'], type(op['txid']), txid, type(txid)))

        if not op.has_key('vtxindex'):
            raise Exception("op '%s' does not have vtxid" % op['vtxindex'])

        if op['vtxindex'] != vtxindex:
            raise Exception("op '%s' vtxindex mismatch: %s (%s) != %s (%s)" % (op['opcode'], op['vtxindex'], type(op['vtxindex']), vtxindex, type(vtxindex)))

        op_seq = None

        if opcode == NAME_PREORDER:
            op_seq = db.commit_preorder( op, block_id )

        elif opcode == NAME_PREORDER_MULTI:
            op_seq = db.commit_preorder_multi( op, block_id )

        elif opcode == NAME_REGISTRATION:
            op_seq = db.commit_registration( op, block_id )

        elif opcode == NAME_REGISTRATION_MULTI:
            op_seq = db.commit_registration_multi( op, block_id )

        elif opcode == NAME_UPDATE:
            op_seq = db.commit_update( op, block_id )

        elif opcode == NAME_TRANSFER:
            op_seq = db.commit_transfer( op, block_id )

        elif opcode == NAME_REVOKE:
            op_seq = db.commit_revoke( op, block_id )
            
        elif opcode == NAME_IMPORT:
            op_seq = db.commit_name_import( op, block_id )
            
        elif opcode == NAMESPACE_PREORDER:
            op_seq = db.commit_namespace_preorder( op, block_id )
            
        elif opcode == NAMESPACE_REVEAL:
            op_seq = db.commit_namespace_reveal( op, block_id )

        elif opcode == NAMESPACE_READY:
            op_seq = db.commit_namespace_ready( op, block_id )
     
        if type(op_seq) != list:
            op_seq = [op_seq]

        if op_seq and op_seq[0]:

            for commit_op in op_seq:
                debug_op = copy.deepcopy( commit_op )
                if debug_op.has_key('history'):
                    del debug_op['history']

                log.debug("COMMIT op '%s' (%s)" % (opcode, json.dumps(debug_op, sort_keys=True)))

      else:

        # final commit before save
        # do expirations
        log.debug("Clear all expired names at %s" % block_id )
        db.commit_name_expire_all( block_id )
        
        log.debug("Clear all expired preorders at %s" % block_id )
        db.commit_preorder_expire_all( block_id )
        
        log.debug("Clear all expired namespace preorders at %s" % block_id )
        db.commit_namespace_preorder_expire_all( block_id )
        
        log.debug("Clear all expired partial namespace imports at %s" % block_id )
        db.commit_namespace_reveal_expire_all( block_id )

        # reset for next block
        db.log_prescan_reset()
        
   else:
      log.error("No state engine defined")
      return None
  
   return op_seq


def db_save( block_id, consensus_hash, pending_ops, filename, db_state=None ):
   """
   (required by virtualchain state engine)
   
   Save all persistent state to stable storage.
   Clear out expired names in the process.
   Called once per block.
   
   Return True on success
   Return False on failure.
   """
   
   global blockstore_db_lock, blockstore_db
   db = db_state 
   
   # remove expired names before saving
   if db is not None:
      
      # see if anything actually changed
      if len(pending_ops.get('virtualchain_ordered', [])) > 0:

          # state has changed 
          log.debug("Save database %s" % filename)

          blockstore_db_lock.acquire()

          rc = db.save_db( filename )
          invalidate_cached_db(needlock=False)

          blockstore_db_lock.release()
          return rc
      
      else:
          
          log.debug("No new operations")
          # all good
          return True
   
   else:
      log.error("No state defined")
      return False 


def sync_blockchain( bt_opts, last_block ):
    """
    synchronize state with the blockchain.
    build up the next blockstore_db
    """
 
    # make this usable even if we haven't explicitly configured virtualchain 
    impl = sys.modules[__name__]
    if virtualchain.get_implementation() is not None:
       impl = None

    log.info("Synchronizing database up to block %s" % last_block)
    db_filename = virtualchain.get_db_filename(impl=impl)
    new_db = BlockstoreDB( db_filename )

    virtualchain.sync_virtualchain( bt_opts, last_block, new_db )

    invalidate_cached_db()


def stop_sync_blockchain():
    """
    stop synchronizing with the blockchain
    """
    global blockstore_db, blockstore_db_lock

    blockstore_db_lock.acquire()
    if blockstore_db is None:
        return 

    blockstore_db.stop_build()
    blockstore_db_lock.release()

