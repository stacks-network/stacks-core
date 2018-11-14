#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016-2018 by Blockstack.org

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

import json
import traceback
import keychain
import os
import copy
import threading
import gc

from . import *
from ..config import *
from ..operations import *
from ..hashing import *
from ..scripts import get_namespace_from_name
from ..util import parse_DID

import virtualchain
from db import *

log = virtualchain.get_logger("blockstack-server")

DISPOSITION_RO = "readonly"
DISPOSITION_RW = "readwrite"

# singleton read/write instance
blockstack_db = None
blockstack_db_lastblock = None
blockstack_db_lock = threading.Lock()


def autofill(*autofill_fields):
    """
    Decorator to automatically fill in extra useful fields
    that aren't stored in the db.
    """
    def wrap( reader ):
        def wrapped_reader( *args, **kw ):
            rec = reader( *args, **kw )
            if rec is not None:
                for field in autofill_fields:
                    if field == "opcode" and 'opcode' not in rec.keys():
                        assert 'op' in rec.keys(), "BUG: record is missing 'op'"
                        rec['opcode'] = op_get_opcode_name(rec['op'])
                    else:
                        raise Exception("Unknown autofill field '%s'" % field)

            return rec
        return wrapped_reader
    return wrap


class BlockstackDB(virtualchain.StateEngine):
    """
    State engine implementation for blockstack.
    """

    def __init__(self, db_filename, disposition, working_dir, genesis_block, expected_snapshots={}):
        """
        Construct the Blockstack State Engine
        from locally-cached db state.

        DO NOT CALL THIS DIRECTLY.  Use borrow_readwrite_instance() or get_readonly_instance()
        """
        import virtualchain_hooks

        if not os.path.exists(db_filename):
            log.debug("Initialize database from '%s'" % db_filename )
        else:
            log.debug("Connect to database '%s'" % db_filename)

        self.db = None

        # instantiate/acquire the database
        self.db_filename = db_filename
        if os.path.exists(db_filename):
            self.db = namedb_open(db_filename)
        else:
            self.db = namedb_create(db_filename, genesis_block)

        self.disposition = disposition

        self.genesis_block = copy.deepcopy(genesis_block)

        # announcers to track
        blockstack_opts = default_blockstack_opts(working_dir, virtualchain.get_config_filename(virtualchain_hooks, working_dir))
        self.announce_ids = blockstack_opts['announcers'].split(",")

        # collision detection 
        # map block_id --> history_id_key --> list of history ID values
        self.collisions = {}

        # vesting flags for blocks
        self.vesting = {}

        read_only = (disposition == DISPOSITION_RO)

        super( BlockstackDB, self ).__init__( virtualchain_hooks,
                                              working_dir,
                                              state=self,
                                              expected_snapshots=expected_snapshots,
                                              read_only=read_only )
    

        # backup settings
        self.set_backup_frequency( blockstack_opts['backup_frequency'] )
        self.set_backup_max_age( blockstack_opts['backup_max_age'] )


    @classmethod
    def get_readonly_instance(cls, working_dir, expected_snapshots={}):
        """
        Get a read-only handle to the blockstack-specific name db.
        Multiple read-only handles may exist.

        Returns the handle on success.
        Returns None on error
        """
        import virtualchain_hooks
        db_path = virtualchain.get_db_filename(virtualchain_hooks, working_dir)
        db = BlockstackDB(db_path, DISPOSITION_RO, working_dir, get_genesis_block(), expected_snapshots={})
        rc = db.db_setup()
        if not rc:
            log.error("Failed to set up virtualchain state engine")
            return None
        
        return db

    
    @classmethod
    def get_readwrite_instance(cls, working_dir, restore=False, restore_block_height=None):
        """
        Get a read/write instance to the db, without the singleton check.
        Used for low-level operations like db restore.
        Not used in the steady state behavior of the system.
        """
        log.warning("!!! Getting raw read/write DB instance !!!")

        import virtualchain_hooks
        db_path = virtualchain.get_db_filename(virtualchain_hooks, working_dir)
        db = BlockstackDB(db_path, DISPOSITION_RW, working_dir, get_genesis_block())
        rc = db.db_setup()
        if not rc:
            if restore:
                # restore from backup instead of bailing out
                log.debug("Restoring from unclean shutdown")
                rc = db.db_restore(block_number=restore_block_height)
                if rc:
                    return db
                else:
                    log.error("Failed to restore from unclean shutdown")

            db.close()
            raise Exception("Failed to set up db")

        return db


    @classmethod 
    def borrow_readwrite_instance(cls, working_dir, block_number, expected_snapshots={}):
        """
        Get a read/write database handle to the blockstack db.
        At most one such handle can exist within the program.

        When the caller is done with the handle, it should call release_readwrite_instance()

        Returns the handle on success
        Returns None if we can't set up the db.
        Aborts if there is another read/write handle out there somewhere.
        """

        global blockstack_db, blockstack_db_lastblock, blockstack_db_lock

        import virtualchain_hooks
        db_path = virtualchain.get_db_filename(virtualchain_hooks, working_dir)
        
        blockstack_db_lock.acquire()

        try:
            assert blockstack_db is None, "Borrowing violation"
        except Exception, e:
            log.exception(e)
            log.error("FATAL: Borrowing violation")
            os.abort()

        db = BlockstackDB(db_path, DISPOSITION_RW, working_dir, get_genesis_block(), expected_snapshots=expected_snapshots)
        rc = db.db_setup()
        if not rc:
            db.close()
            blockstack_db_lock.release()
            log.error("Failed to set up virtualchain state engine")
            return None

        blockstack_db = db
        blockstack_db_lastblock = block_number
        blockstack_db_lock.release()

        return blockstack_db


    @classmethod
    def release_readwrite_instance( cls, db_inst, block_number ):
        """
        Release the read/write instance of the blockstack db.
        This must be called after borrow_readwrite_instance, with the same block number.
        After this method completes, it's possible to call borrow_readwrite_instance again.

        Returns True on success
        Aborts on error
        """

        global blockstack_db, blockstack_db_lastblock, blockstack_db_lock 

        blockstack_db_lock.acquire()

        try:
            assert blockstack_db is not None, "Borrowing return violation: db is None"
            assert blockstack_db == db_inst, "Borrowing return violation: different instances"
            assert blockstack_db_lastblock == block_number, "Borrowing return violation: different blocks"
        except Exception, e:
            log.exception(e)
            log.error("FATAL: Borrowing-release violation")
            os.abort()

        blockstack_db.close()

        del blockstack_db
        del db_inst

        db_inst = None
        blockstack_db = None
        blockstack_db_lastblock = None 

        blockstack_db_lock.release()
        return True


    @classmethod 
    def make_opfields( cls ):
        """
        Calculate the virtulachain-required opfields dict.
        """
        # construct fields 
        opfields = {}
        for opname in SERIALIZE_FIELDS.keys():
            opcode = NAME_OPCODES[opname]
            opfields[opcode] = SERIALIZE_FIELDS[opname]

        return opfields


    @classmethod
    def get_state_paths(cls, impl, working_dir):
        """
        Get the paths to the relevant db files to back up
        """
        return super(BlockstackDB, cls).get_state_paths(impl, working_dir) + [
                os.path.join(working_dir, 'atlas.db'), 
                os.path.join(working_dir, 'subdomains.db'),
                os.path.join(working_dir, 'subdomains.db.queue')
            ]


    def get_db_path( self ):
        """
        Get db file path
        """
        return self.db_filename

    
    def close( self ):
        """
        Close the db and release memory
        """
        if self.db is not None:
            self.db.commit()
            self.db.close()
            self.db = None

        return


    def export_db(self, dirpath):
        """
        Copy all database info to a given directory.
        Used primarily for testing; production users
        should just pull a backup db from ~/.blockstack-server/backups
        (or whatever the working directory is)
        """
        if self.db is not None:
            self.db.commit()
            
        import virtualchain_hooks
        
        db_path = os.path.join(dirpath, os.path.basename(self.get_db_path()))
        snapshots_path = os.path.join(dirpath, os.path.basename(virtualchain.get_snapshots_filename(virtualchain_hooks, self.working_dir)))
        atlas_path = os.path.join(dirpath, 'atlas.db')
        subdomain_path = os.path.join(dirpath, 'subdomains.db')
        subdomain_queue_path = os.path.join(dirpath, 'subdomains.db.queue')

        src_atlas_path = os.path.join(self.working_dir, 'atlas.db')
        src_subdomain_path = os.path.join(self.working_dir, 'subdomains.db')
        src_subdomain_queue_path = os.path.join(self.working_dir, 'subdomains.db.queue')
        
        virtualchain.sqlite3_backup(self.get_db_path(), db_path)
        virtualchain.sqlite3_backup(virtualchain.get_snapshots_filename(virtualchain_hooks, self.working_dir), snapshots_path)

        if os.path.exists(src_atlas_path):
            virtualchain.sqlite3_backup(src_atlas_path, atlas_path)

        if os.path.exists(src_subdomain_path):
            virtualchain.sqlite3_backup(src_subdomain_path, subdomain_path)

        if os.path.exists(src_subdomain_queue_path):
            virtualchain.sqlite3_backup(src_subdomain_queue_path, subdomain_queue_path)
  

    @classmethod
    def get_import_keychain_path( cls, keychain_dir, namespace_id ):
        """
        Get the path to the import keychain
        """
        cached_keychain = os.path.join( keychain_dir, "{}.keychain".format(namespace_id) )
        return cached_keychain


    @classmethod
    def build_import_keychain( cls, keychain_dir, namespace_id, pubkey_hex ):
        """
        Generate all possible NAME_IMPORT addresses from the NAMESPACE_REVEAL public key
        """

        pubkey_addr = virtualchain.BitcoinPublicKey(str(pubkey_hex)).address()

        # do we have a cached one on disk?
        cached_keychain = cls.get_import_keychain_path(keychain_dir, namespace_id)
        if os.path.exists( cached_keychain ):

            child_addrs = []
            try:
                lines = []
                with open(cached_keychain, "r") as f:
                    lines = f.readlines()

                child_attrs = [l.strip() for l in lines]

                log.debug("Loaded cached import keychain for '%s' (%s)" % (pubkey_hex, pubkey_addr))
                return child_attrs

            except Exception, e:
                log.exception(e)
                pass

        pubkey_hex = str(pubkey_hex)
        public_keychain = keychain.PublicKeychain.from_public_key( pubkey_hex )
        child_addrs = []

        for i in xrange(0, NAME_IMPORT_KEYRING_SIZE):
            public_child = public_keychain.child(i)
            public_child_address = public_child.address()

            # if we're on testnet, then re-encode as a testnet address 
            if virtualchain.version_byte == 111:
                old_child_address = public_child_address
                public_child_address = virtualchain.hex_hash160_to_address( virtualchain.address_to_hex_hash160( public_child_address ) )
                log.debug("Re-encode '%s' to '%s'" % (old_child_address, public_child_address))

            child_addrs.append( public_child_address )

            if i % 20 == 0 and i != 0:
                log.debug("%s children..." % i)

        # include this address
        child_addrs.append( pubkey_addr )

        log.debug("Done building import keychain for '%s' (%s)" % (pubkey_hex, pubkey_addr))

        # cache
        try:
            with open(cached_keychain, "w+") as f:
                for addr in child_addrs:
                    f.write("%s\n" % addr)

                f.flush()

            log.debug("Cached keychain to '%s'" % cached_keychain)
        except Exception, e:
            log.exception(e)
            log.error("Unable to cache keychain for '%s' (%s)" % (pubkey_hex, pubkey_addr))

        return child_addrs


    @classmethod
    def load_import_keychain( cls, working_dir, namespace_id ):
        """
        Get an import keychain from disk.
        Return None if it doesn't exist.
        """
      
        # do we have a cached one on disk?
        cached_keychain = os.path.join(working_dir, "%s.keychain" % namespace_id)
        if os.path.exists( cached_keychain ):

            log.debug("Load import keychain '%s'" % cached_keychain)
            child_addrs = []
            try:
                lines = []
                with open(cached_keychain, "r") as f:
                    lines = f.readlines()
 
                child_attrs = [l.strip() for l in lines]
 
                log.debug("Loaded cached import keychain for '%s'" % namespace_id)
                return child_attrs
 
            except Exception, e:
                log.exception(e)
                log.error("FATAL: uncaught exception loading the import keychain")
                os.abort()
 
        else:
            log.debug("No import keychain at '%s'" % cached_keychain)

        return None

    
    def commit_get_cursor( self, block_number ):
        """
        Get a database cursor for a commit on this block number.
        """

        return self.db.cursor()


    def commit_finished( self, block_id ):
        """
        Called when the block is finished.
        Commits all data.
        """

        self.db.commit()

        # NOTE: tokens vest for the *next* block in order to make the immediately usable
        assert block_id+1 in self.vesting, 'BUG: failed to vest at {}'.format(block_id)

        self.clear_collisions( block_id )
        self.clear_vesting(block_id+1)

    
    def log_accept( self, block_id, vtxindex, op, op_data ):
        """
        Log an accepted operation
        """

        opcode = op_data.get('opcode', None)
        debug_op = self.sanitize_op( op_data )
        if 'history' in debug_op:
            del debug_op['history'] 

        log.debug("ACCEPT %s at (%s, %s) data: %s", opcode, block_id, vtxindex, 
                ", ".join( ["%s='%s'" % (k, debug_op[k]) for k in sorted(debug_op.keys())] ) )

        return

 
    def log_commit( self, block_id, vtxindex, op, opcode, op_data ):
        """
        Log a committed operation
        """

        debug_op = self.sanitize_op( op_data )
        if 'history' in debug_op:
            del debug_op['history'] 

        log.debug("COMMIT %s (%s) at (%s, %s) data: %s", opcode, op, block_id, vtxindex, 
                ", ".join( ["%s='%s'" % (k, debug_op[k]) for k in sorted(debug_op.keys())] ) )

        return


    def log_reject( self, block_id, vtxindex, op, op_data ):
        """
        Log a rejected operation
        """

        debug_op = self.sanitize_op( op_data )
        if 'history' in debug_op:
            del debug_op['history']

        log.debug("REJECT %s at (%s, %s) data: %s", op_get_opcode_name( op ), block_id, vtxindex,
                ", ".join( ["%s='%s'" % (k, debug_op[k]) for k in sorted(debug_op.keys())] ))

        return


    def sanitize_op( self, op_data ):
        """
        Remove unnecessary fields for an operation, i.e. prior to committing it.
        This includes any invariant tags we've added with our invariant decorators
        (such as @state_create or @state_transition).
        
        TODO: less ad-hoc way to do this
        """
        
        op_data = super(BlockstackDB, self).sanitize_op(op_data)

        # remove invariant tags (i.e. added by our invariant state_* decorators)
        to_remove = get_state_invariant_tags()
        for tag in to_remove:
            if tag in op_data.keys():
                del op_data[tag]

        # NOTE: this is called the opcode family, because
        # different operation names can have the same operation code
        # (such as NAME_RENEWAL and NAME_REGISTRATION).  They must
        # have the same mutation fields.
        opcode_family = op_get_opcode_name( op_data['op'] )

        # for each column in the appropriate state table,
        # if the column is not identified in the operation's
        # MUTATE_FIELDS list, then set it to None here.
        mutate_fields = op_get_mutate_fields( opcode_family )
        for mf in mutate_fields:
            if not op_data.has_key( mf ):
                log.debug("Adding NULL mutate field '%s.%s'" % (opcode_family, mf ))
                op_data[mf] = None

        # TODO: less ad-hoc
        for extra_field in ['opcode']:
            if extra_field in op_data:
                del op_data[extra_field]

        return op_data


    @classmethod
    def check_collision_state( cls, collision_state, history_id_key, history_id, block_id, checked_ops, affected_opcodes ):
        """
        Given a history ID, see if it already exists
        at the given block ID (i.e. it's not expired),
        using the given collision state.
        Return True if so; False if not.
        If there is a collision, set the __collided__ field in each checked_ops that
        has a matching history_id value and has an opcode in affected_opcodes.
        """

        # seen before in this block?
        if collision_state.has_key( block_id ):
            if collision_state[block_id].has_key(history_id_key):
                if history_id in collision_state[block_id][history_id_key]:
                    rc = True

                else:
                    collision_state[block_id][history_id_key].append( history_id )
                    rc = False

            else:
                collision_state[block_id][history_id_key] = [history_id]
                rc = False

        else:
            collision_state[block_id] = { history_id_key: [history_id] }
            rc = False

        if not rc:
            # no collision 
            return rc

        # find and mark collided operations 
        for prev_op in checked_ops:

            prev_opcode = op_get_opcode_name( prev_op['op'] )
            if prev_opcode not in affected_opcodes:
                # not affected
                continue 

            if history_id_key not in prev_op:
                # won't match
                continue

            if prev_op[history_id_key] == history_id:
                # collision 
                cls.nameop_set_collided( prev_op, history_id_key, history_id )

        return True


    def find_collisions( self, checked_ops ):
        """
        Given a list of checked operations, find the ones that collide.
        Return a dict structured as history_id_key --> [history_id]
        """

        collisions = {}
        for op in checked_ops:
            if BlockstackDB.nameop_is_collided( op ):
                BlockstackDB.nameop_put_collision( collisions, op )

        return collisions


    def put_collisions( self, block_id, collisions ):
        """
        Put collision state for a particular block.
        Any operations checked at this block_id that collide 
        with the given collision state will be rejected.
        """
        self.collisions[ block_id ] = copy.deepcopy( collisions )

    
    def clear_collisions( self, block_id ):
        """
        Clear out all collision state for a given block number
        """
        if block_id in self.collisions:
            del self.collisions[block_id]
       

    def clear_vesting(self, block_id):
        """
        Clear out all vesting state for a given block number
        """
        if block_id in self.vesting:
            del self.vesting[block_id]


    def check_collision( self, history_id_key, history_id, block_id, checked_ops, affected_opcodes ):
        """
        Given a history ID, see if it already exists
        at the given block ID (i.e. it's not expired).
        Return True if so; False if not.
        If there is a collision, set the __collided__ field in each checked_ops that
        has a matching history_id value and has an opcode in affected_opcodes.
        """

        return BlockstackDB.check_collision_state( self.collisions, history_id_key, history_id, block_id, checked_ops, affected_opcodes )


    def check_preorder_collision( self, preorder_hash, block_id, checked_ops ):
        """
        Are there any colliding preorders in this block?
        Set the '__collided__' flag and related flags if so, so we don't commit them.

        Not called directly; called by the @state_preorder() decorator in blockstack.lib.operations.preorder and blockstack.lib.operations.namespacepreorder
        """

        return self.check_collision( "preorder_hash", preorder_hash, block_id, checked_ops, OPCODE_PREORDER_OPS )


    def check_name_collision( self, name, block_id, checked_ops ):
        """
        Are there any colliding names in this block?
        Set the '__collided__' flag and related flags if so, so we don't commit them.
        
        Not called directly; called by the @state_create() decorator in blockstack.lib.operations.register
        """

        return self.check_collision( "name", name, block_id, checked_ops, OPCODE_NAME_STATE_CREATIONS )

    
    def check_namespace_collision( self, namespace_id, block_id, checked_ops ):
        """
        Are there any colliding namespaces in this block?
        Set the '__collided__' flag and related flags if so, so we don't commit them
        
        Not called directly; called by the @state_create() decorator in blockstack.lib.operations.namespacereveal
        """

        return self.check_collision( "namespace_id", namespace_id, block_id, checked_ops, OPCODE_NAMESPACE_STATE_CREATIONS )


    def check_noop_collision( self, name, block_id, checked_ops ):
        """
        No-op collision detector.
        Meant for name-import (used by its @state_create() decorator)
        """
        log.warn("No-op collision detection for '%s'" % name)
        return False


    @autofill( "opcode" )
    def get_namespace( self, namespace_id, include_history=True ):
        """
        Given a namespace ID, get the ready namespace op for it.

        Return the dict with the parameters on success.
        Return None if the namespace has not yet been revealed.
        """

        cur = self.db.cursor()
        return namedb_get_namespace_ready( cur, namespace_id, include_history=include_history )


    @autofill( "opcode" )
    def get_namespace_op_state( self, namespace_id, block_number, include_expired=False ):
        """
        Given a namespace ID and block number, get the current namespace op (revealed or ready) for it
        if the namespace existed after that block.  Optionally return the namespace
        record even if it's a NAMESPACE_REVEAL and it expired.

        Return the dict with the parameters on success.
        Return None if the namespace has not yet been revealed.
        """

        cur = self.db.cursor()
        return namedb_get_namespace( cur, namespace_id, block_number, include_expired=include_expired )

    
    @autofill( "opcode" )
    def get_namespace_by_preorder( self, preorder_hash ):
        """
        Given a namespace preorder hash, get the associated namespace
        reveal or ready (it may be expired).
        """
        cur = self.db.cursor()
        return namedb_get_namespace_by_preorder_hash( cur, preorder_hash )


    @autofill( "opcode" )
    def get_name_by_preorder( self, preorder_hash ):
        """
        Given a name preorder hash, get the associated name record.
        (It may be expired or revoked)
        """
        cur = self.db.cursor()
        return namedb_get_name_by_preorder_hash( cur, preorder_hash )


    @autofill( "opcode" )
    def get_name( self, name, lastblock=None, include_expired=False, include_history=True ):
        """
        Given a name, return the latest version and history of
        the metadata gleaned from the blockchain.
        Name must be fully-qualified (i.e. name.ns_id)
        Return None if no such name is currently registered.

        NOTE: returns names that are revoked
        """

        if lastblock is None:
            lastblock = self.lastblock

        cur = self.db.cursor()
        name_rec = namedb_get_name( cur, name, lastblock, include_expired=include_expired, include_history=include_history )
        return name_rec


    def get_name_DID_info(self, name, lastblock=None):
        """
        Given a name, find its DID (decentralized identifier) information.
        Returns {'address': ..., 'index': ...}
        Returns None if there is no such name
        """
        if lastblock is None:
            lastblock = self.lastblock

        cur = self.db.cursor()
        did_info = namedb_get_name_DID_info(cur, name, lastblock)
        if did_info is None:
            return None

        return did_info


    def get_DID_name(self, did):
        """
        Given a DID, get the name
        Return None if not found, or if the name was revoked
        Raise if the DID is invalid
        """
        did = str(did)
        did_info = None
        try:
            did_info = parse_DID(did)
            assert did_info['name_type'] == 'name'
        except Exception as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            raise ValueError("Invalid DID: {}".format(did))

        cur = self.db.cursor()
        historic_name_info = namedb_get_historic_names_by_address(cur, did_info['address'], offset=did_info['index'], count=1)
        if historic_name_info is None:
            # no such name
            return None

        name = historic_name_info[0]['name']
        block_height = historic_name_info[0]['block_id']
        vtxindex = historic_name_info[0]['vtxindex']
                    
        log.debug("DID {} refers to {}-{}-{}".format(did, name, block_height, vtxindex))

        name_rec = self.get_name(name, include_history=True, include_expired=True)
        if name_rec is None:
            # dead
            return None

        name_rec_latest = None
        found = False

        for height in sorted(name_rec['history'].keys()):
            if found:
                break

            if height < block_height:
                continue

            for state in name_rec['history'][height]:
                if height == block_height and state['vtxindex'] < vtxindex:
                    # too soon
                    continue

                if state['op'] == NAME_PREORDER:
                    # looped to the next iteration of this name
                    found = True
                    break

                if state['revoked']:
                    # revoked
                    log.debug("DID {} refers to {}-{}-{}, which is revoked at {}-{}".format(did, name, block_height, vtxindex, height, state['vtxindex']))
                    return None

                name_rec_latest = state

        return name_rec_latest
     

    def get_account_tokens(self, address):
        """
        Get the list of tokens that this address owns
        """
        cur = self.db.cursor()
        return namedb_get_account_tokens(cur, address)

    
    def get_account(self, address, token_type):
        """
        Get the state of an account for a given token type
        """
        cur = self.db.cursor()
        return namedb_get_account(cur, address, token_type)


    def get_account_balance(self, account):
        """
        What's the balance of an account?
        Aborts if its negative
        """
        balance = namedb_get_account_balance(account)
        assert isinstance(balance, (int,long)), 'BUG: account balance of {} is {} (type {})'.format(account['address'], balance, type(balance))
        return balance


    def get_account_delta(self, address, token_type, block_id, vtxindex):
        """
        Get two consecutive account states---the one at (block_id, vtxindex), and the one prior.
        """
        cur = self.db.cursor()
        return namedb_get_account_delta(cur, address, token_type, block_id, vtxindex)


    def get_account_diff(self, current, prior):
        """
        Get the difference in balances between two accounts
        """
        return namedb_get_account_diff(current, prior)


    def get_account_history(self, address, offset=None, count=None):
        """
        Get the history of account transactions over a block range
        Returns a dict keyed by blocks, which map to lists of account state transitions
        """
        cur = self.db.cursor()
        return namedb_get_account_history(cur, address, offset=offset, count=count)


    def get_all_account_addresses(self):
        """
        TESTING ONLY
        Get all account addresses
        """
        assert BLOCKSTACK_TEST, 'BUG: this method can only be accessed in test mode'
        cur = self.db.cursor()
        return namedb_get_all_account_addresses(cur)


    def get_name_at( self, name, block_number, include_expired=False ):
        """
        Generate and return the sequence of of states a name record was in
        at a particular block number.
        """
        cur = self.db.cursor()
        return namedb_get_name_at(cur, name, block_number, include_expired=include_expired)


    def get_namespace_at( self, namespace_id, block_number ):
        """
        Generate and return the sequence of states a namespace record was in
        at a particular block number.

        Includes expired namespaces by default.
        """
        cur = self.db.cursor() 
        return namedb_get_namespace_at(cur, namespace_id, block_number, include_expired=True)


    def get_account_at(self, address, block_number):
        """
        Get the sequence of states an account was in at a given block.
        Returns a list of states
        """
        cur = self.db.cursor()
        return namedb_get_account_at(cur, address, block_number)


    def get_name_history( self, name, offset=None, count=None, reverse=False):
        """
        Get the historic states for a name, grouped by block height.
        """
        cur = self.db.cursor()
        name_hist = namedb_get_history( cur, name, offset=offset, count=count, reverse=reverse )
        return name_hist
   

    def is_name_zonefile_hash(self, name, zonefile_hash):
        """
        Was a zone file sent by a name?
        """
        cur = self.db.cursor()
        return namedb_is_name_zonefile_hash(cur, name, zonefile_hash)


    def get_all_blockstack_ops_at( self, block_number, offset=None, count=None, include_history=None, restore_history=None ):
        """
        Get all name, namespace, and account records affected at a particular block,
        in the state they were at the given block number.
        
        Paginate if offset, count are given.
        """
        if include_history is not None:
            log.warn("DEPRECATED use of include_history")

        if restore_history is not None:
            log.warn("DEPRECATED use of restore_history")

        log.debug("Get all accepted operations at %s in %s" % (block_number, self.db_filename))
        recs = namedb_get_all_blockstack_ops_at( self.db, block_number, offset=offset, count=count )

        # include opcode 
        for rec in recs:
            assert 'op' in rec
            rec['opcode'] = op_get_opcode_name(rec['op'])

        return recs
       

    def get_num_blockstack_ops_at( self, block_number ):
        """
        Get the number of blockstack operations accepted at a particular block.
        """
        count = namedb_get_num_blockstack_ops_at( self.db, block_number )
        return count


    def get_name_from_name_hash128( self, name ):
        """
        Get the name from a name hash
        """
        cur = self.db.cursor()
        name = namedb_get_name_from_name_hash128( cur, name, self.lastblock )
        return name


    def get_names_owned_by_address( self, address ):
        """
        Get the set of names owned by a particular address.
        NOTE: only works for cases where we could extract an address.
        """
        cur = self.db.cursor()
        names = namedb_get_names_owned_by_address( cur, address, self.lastblock )
        return names

    
    def get_historic_names_by_address( self, address, offset=None, count=None ):
        """
        Get the list of names owned by an address throughout history (used for DIDs)
        Return a list of {'name': ..., 'block_id': ..., 'vtxindex': ...}
        """
        cur = self.db.cursor()
        names = namedb_get_historic_names_by_address( cur, address, offset=offset, count=count )
        return names


    def get_num_historic_names_by_address( self, address ):
        """
        Get the number of names historically owned by an address
        """
        cur = self.db.cursor()
        count = namedb_get_num_historic_names_by_address( cur, address )
        return count


    def get_names_owned_by_sender( self, sender_pubkey, lastblock=None ):
        """
        Get the set of names owned by a particular script-pubkey.
        """
        cur = self.db.cursor()
        if lastblock is None:
            lastblock = self.lastblock 

        names = namedb_get_names_by_sender( cur, sender_pubkey, lastblock )
        return names

    
    def get_num_names( self, include_expired=False ):
        """
        Get the number of names that exist.
        """
        cur = self.db.cursor()
        return namedb_get_num_names( cur, self.lastblock, include_expired=include_expired )


    def get_all_names( self, offset=None, count=None, include_expired=False ):
        """
        Get the set of all registered names, with optional pagination
        Returns the list of names.
        """
        if offset is not None and offset < 0:
            offset = None

        if count is not None and count < 0:
            count = None 

        cur = self.db.cursor()
        names = namedb_get_all_names( cur, self.lastblock, offset=offset, count=count, include_expired=include_expired )
        return names


    def get_num_names_in_namespace( self, namespace_id ):
        """
        Get the number of names in a namespace
        """
        cur = self.db.cursor()
        return namedb_get_num_names_in_namespace( cur, namespace_id, self.lastblock )
    
    
    def get_names_in_namespace( self, namespace_id, offset=None, count=None ):
        """
        Get the set of all registered names in a particular namespace.
        Returns the list of names.
        """
        if offset is not None and offset < 0:
            offset = None 

        if count is not None and count < 0:
            count = None 

        cur = self.db.cursor()
        names = namedb_get_names_in_namespace( cur, namespace_id, self.lastblock, offset=offset, count=count )
        return names


    def get_all_namespace_ids( self ):
        """
        Get the set of all existing, READY namespace IDs.
        """
        cur = self.db.cursor()
        namespace_ids = namedb_get_all_namespace_ids( cur )
        return namespace_ids
       

    def get_all_revealed_namespace_ids( self ):
        """
        Get all revealed namespace IDs that have not expired.
        """
        cur = self.db.cursor()
        namespace_ids = namedb_get_all_revealed_namespace_ids( cur, self.lastblock )
        return namespace_ids


    def get_all_preordered_namespace_hashes( self ):
        """
        Get all oustanding namespace preorder hashes that have not expired.
        Used for testing
        """
        cur = self.db.cursor()
        namespace_hashes = namedb_get_all_preordered_namespace_hashes( cur, self.lastblock )
        return namespace_hashes 


    def get_all_importing_namespace_hashes( self ):
        """
        Get the set of all preordered and revealed namespace hashes that have not expired.
        """
        cur = self.db.cursor()
        namespace_hashes = namedb_get_all_importing_namespace_hashes( cur, self.lastblock )
        return namespace_hashes
        

    def get_name_from_name_consensus_hash( self, name_consensus_hash, sender_script_pubkey, block_id ):
        """
        Find the name.ns_id from hash( name.ns_id, consensus_hash ), given the sender and
        block_id, and assuming that name.ns_id is already registered.

        There are only a small number of values this hash can take, so test all of them to
        see if the hash matches one of them.

        This is used for name updates--we need to ensure that updates have timely consensus
        hashes, and are on the majority blockchian fork.

        Return (fully-qualified name, consensus hash) on success
        Return (None, None) if not found.
        """
        import virtualchain_hooks

        cur = self.db.cursor()
        names = namedb_get_names_by_sender( cur, sender_script_pubkey, self.lastblock )
        
        if names is None:
            log.error("Sender script '%s' owns no names" % sender_script_pubkey )
            return (None, None)

        possible_consensus_hashes = []
        for i in range( block_id - virtualchain_hooks.get_valid_transaction_window(), block_id+1 ):
            consensus_hash = self.get_consensus_at( i )
            if consensus_hash is not None and consensus_hash not in possible_consensus_hashes:
                possible_consensus_hashes.append( str(consensus_hash) )
    
        for name in names:
            for consensus_hash in possible_consensus_hashes:
                # what would have been the name/consensus_hash?
                test_name_consensus_hash = hash256_trunc128( str(name) + consensus_hash )
                if test_name_consensus_hash == name_consensus_hash:
                    # found!
                    return name, consensus_hash

        return None, None


    @autofill( "opcode" )
    def get_name_preorder( self, name, sender_script_pubkey, register_addr, include_failed=False ):
        """
        Get the current preorder for a name, given the name, the sender's script pubkey, and
        the registration address used to calculate the preorder hash.

        Return the preorder record on success.
        Return None if not found, or the preorder is already registered and not expired (even if revoked).

        NOTE: possibly returns an expired preorder (by design, so as to prevent someone
        from re-sending the same preorder with the same preorder hash).
        """
        # name registered and not expired?
        name_rec = self.get_name( name )
        if name_rec is not None and not include_failed:
            return None

        # what namespace are we in?
        namespace_id = get_namespace_from_name(name)
        namespace = self.get_namespace(namespace_id)
        if namespace is None:
            return None

        # isn't currently registered, or we don't care
        preorder_hash = hash_name(name, sender_script_pubkey, register_addr=register_addr)
        preorder = namedb_get_name_preorder( self.db, preorder_hash, self.lastblock )
        if preorder is None:
            # doesn't exist or expired
            return None

        # preorder must be younger than the namespace lifetime
        # (otherwise we get into weird conditions where someone can preorder
        # a name before someone else, and register it after it expires)
        namespace_lifetime_multiplier = get_epoch_namespace_lifetime_multiplier( self.lastblock, namespace_id )
        if preorder['block_number'] + (namespace['lifetime'] * namespace_lifetime_multiplier) <= self.lastblock:
            log.debug("Preorder is too old (accepted at {}, namespace lifetime is {}, current block is {})".format(preorder['block_number'], namespace['lifetime'] * namespace_lifetime_multiplier, self.lastblock))
            return None

        return preorder 

    
    @autofill( "opcode" )
    def get_namespace_preorder( self, namespace_id_hash ):
        """
        Given the hash(namesapce_id, sender_script_pubkey, reveal_addr) for a 
        namespace that is being imported, get its associated NAMESPACE_PREORDER
        record.

        Return the namespace preorder record on success.
        Return None if not found, if the namespace is currently not preordered, or if the preorder record is expired.
        """
        namespace_preorder = namedb_get_namespace_preorder( self.db, namespace_id_hash, self.lastblock ) 
        return namespace_preorder


    def get_name_owner( self, name ):
        """
        Given a name, get its associated sender pubkey script.

        Return the string on success
        Return None if the name doesn't exist.
        """
        name_rec = self.get_name( name )
        if name_rec is None:
            return None

        else:
            return name_rec['sender']


    def get_names_with_value_hash( self, value_hash ):
        """
        Get the list of names with the given value hash, at the current block height.
        This excludes revoked names and expired names.

        Return None if there are no such names
        """
        cur = self.db.cursor()
        names = namedb_get_names_with_value_hash( cur, value_hash, self.lastblock )
        return names


    def get_atlas_zonefile_info_at( self, block_id ):
        """
        Get the blockchain-ordered sequence of names, value hashes, and txids.
        added at the given block height.  The order will be
        in tx-order.

        Return [{'name': name, 'value_hash': value_hash, 'txid': txid}]
        """
        nameops = self.get_all_blockstack_ops_at( block_id )
        ret = []
        for nameop in nameops:
            if nameop.has_key('op') and op_get_opcode_name(nameop['op']) in ['NAME_UPDATE', 'NAME_IMPORT', 'NAME_REGISTRATION', 'NAME_RENEWAL']:

                assert nameop.has_key('value_hash')
                assert nameop.has_key('name')
                assert nameop.has_key('txid')

                if nameop['value_hash'] is not None:
                    ret.append( {'name': nameop['name'], 'value_hash': nameop['value_hash'], 'txid': nameop['txid']} )

        return ret


    def get_name_value_hash_txid( self, name, value_hash ):
        """
        Given a name and a value hash (i.e. the zone file hash), return the txid for the value hash.
        Return None if the name doesn't exist, or is revoked, or did not
        receive a NAME_UPDATE since it was last preordered.
        """
        rec = self.get_name( name )
        if rec is None:
            return None 

        if rec['revoked']:
            return None
        
        # find the txid of the given value hash
        if rec['value_hash'] == value_hash:
            return rec['txid']

        else:
            # search backwards for it 
            hist = rec['history']
            flat_hist = namedb_flatten_history( hist )
            for i in xrange(len(flat_hist)-1, 0, -1):
                delta = flat_hist[i]
                if delta['op'] == NAME_PREORDER:
                    # this name was re-registered. skip
                    return None 

                if delta['value_hash'] == value_hash:
                    # this is the txid that affected it 
                    return delta['txid']

            # not found
            return None
        
    
    @autofill( "opcode" )
    def get_namespace_reveal( self, namespace_id, include_history=True ):
        """
        Given the name of a namespace, get it if it is currently
        being revealed.

        Return the reveal record on success.
        Return None if it is not being revealed, or is expired.
        """
        cur = self.db.cursor()
        namespace_reveal = namedb_get_namespace_reveal( cur, namespace_id, self.lastblock, include_history=include_history )
        return namespace_reveal


    def get_announce_ids( self ):
        """
        Get the set of announce IDs
        """
        return self.announce_ids


    def is_name_expired( self, name, block_number ):
        """
        Given a name and block number, determine if it is expired at that block.
        * names in revealed but not ready namespaces are never expired, unless the namespace itself is expired;
        * names in ready namespaces expire once max(ready_block, renew_block) + lifetime blocks passes

        Return True if so
        Return False if not, or if the name doesn't exist
        """
        cur = self.db.cursor()
        return namedb_get_name( cur, name, block_number ) is None


    @classmethod
    def get_name_deadlines( self, name_rec, namespace_rec, block_number ):
        """
        Get the expiry and renewal deadlines for a (registered) name.

        NOTE: expire block here is NOT the block at which the owner loses the name, but the block at which lookups fail.
        The name owner has until renewal_deadline to renew the name.

        Return {'expire_block': ..., 'renewal_deadline': ...} on success
        Return None if the namespace isn't ready yet
        """
        if namespace_rec['op'] != NAMESPACE_READY:
            # name cannot be in grace period, since the namespace is not ready 
            return None

        namespace_id = namespace_rec['namespace_id']
        namespace_lifetime_multiplier = get_epoch_namespace_lifetime_multiplier( block_number, namespace_id )
        namespace_lifetime_grace_period = get_epoch_namespace_lifetime_grace_period( block_number, namespace_id )

        expire_block = max(namespace_rec['ready_block'], name_rec['last_renewed']) + (namespace_rec['lifetime'] * namespace_lifetime_multiplier)
        renewal_deadline = expire_block + namespace_lifetime_grace_period

        return {'expire_block': expire_block, 'renewal_deadline': renewal_deadline}


    def is_name_in_grace_period(self, name, block_number):
        """
        Given a name and block number, determine if it is in the renewal grace period at that block.
        * names in revealed but not ready namespaces are never expired, unless the namespace itself is expired;
        * names in ready namespaces enter the grace period once max(ready_block, renew_block) + lifetime - grace_period blocks passes

        Return True if so
        Return False if not, or if the name does not exist.
        """
        cur = self.db.cursor()
        name_rec = namedb_get_name(cur, name, block_number, include_expired=False)
        if name_rec is None:
            # expired already or doesn't exist
            return False

        namespace_id = get_namespace_from_name(name)
        namespace_rec = namedb_get_namespace(cur, namespace_id, block_number, include_history=False)
        if namespace_rec is None:
            return False

        grace_info = BlockstackDB.get_name_deadlines(name_rec, namespace_rec, block_number)
        if grace_info is None:
            # namespace isn't ready yet
            return False

        return (block_number >= grace_info['expire_block'] and block_number < grace_info['renewal_deadline'])
        

    def is_name_registered( self, name ):
        """
        Given the fully-qualified name, is it registered, not revoked, and not expired
        at the current block?
        """
        name_rec = self.get_name( name )    # won't return the name if expired
        if name_rec is None:
            return False 

        if name_rec['revoked']:
            return False

        return True


    def is_namespace_ready( self, namespace_id ):
        """
        Given a namespace ID, determine if the namespace is ready
        at the current block.
        """
        namespace = self.get_namespace( namespace_id )
        if namespace is not None:
            return True
        else:
            return False


    def is_namespace_preordered( self, namespace_id_hash ):
        """
        Given a namespace preorder hash, determine if it is preordered
        at the current block.
        """
        namespace_preorder = self.get_namespace_preorder(namespace_id_hash)
        if namespace_preorder is None:
            return False 
        else:
            return True


    def is_namespace_revealed( self, namespace_id ):
        """
        Given the name of a namespace, has it been revealed but not made ready
        at the current block?
        """
        namespace_reveal = self.get_namespace_reveal( namespace_id )
        if namespace_reveal is not None:
            return True
        else:
            return False


    def is_name_owner( self, name, sender_script_pubkey ):
        """
        Given the fully-qualified name and a sender's script pubkey,
        determine if the sender owns the name.

        The name must exist and not be revoked or expired at the
        current block.
        """
        if not self.is_name_registered( name ):
            # no one owns it 
            return False 

        owner = self.get_name_owner( name )
        if owner != sender_script_pubkey:
            return False 
        else:
            return True


    def is_new_preorder( self, preorder_hash, lastblock=None ):
        """
        Given a preorder hash of a name, determine whether or not it is unseen before.
        """
        if lastblock is None:
            lastblock = self.lastblock 

        preorder = namedb_get_name_preorder( self.db, preorder_hash, lastblock )
        if preorder is not None:
            return False
        else:
            return True


    def is_new_namespace_preorder( self, namespace_id_hash, lastblock=None ):
        """
        Given a namespace preorder hash, determine whether or not is is unseen before.
        """
        if lastblock is None:
            lastblock = self.lastblock 

        preorder = namedb_get_namespace_preorder( self.db, namespace_id_hash, lastblock )
        if preorder is not None:
            return False 
        else:
            return True


    def is_name_revoked( self, name ):
        """
        Determine if a name is revoked at this block.
        """
        name = self.get_name( name )
        if name is None:
            return False 

        if name['revoked']:
            return True
        else:
            return False

    
    def is_current_value_hash( self, value_hash ):
        """
        Is the given hash currently mapped to a name in the database?
        """
        return self.get_names_with_value_hash( value_hash ) is not None


    def get_value_hash_txids(self, value_hash):
        """
        Get the list of txids by value hash
        """
        cur = self.db.cursor()
        return namedb_get_value_hash_txids(cur, value_hash)


    def is_token_type_supported(self, token_type):
        """
        Is this particular token type supported?
        i.e. does it refer to an extant token type?
        """
        # only STACKs for now
        # wait for Phase 2
        return token_type in [TOKEN_TYPE_STACKS]


    @classmethod
    def nameop_set_collided( cls, nameop, history_id_key, history_id ):
        """
        Mark a nameop as collided
        """
        nameop['__collided__'] = True
        nameop['__collided_history_id_key__'] = history_id_key 
        nameop['__collided_history_id__'] = history_id


    @classmethod
    def nameop_is_collided( cls, nameop ):
        """
        Is this nameop collided?
        """
        return '__collided__' in nameop and nameop['__collided__']


    @classmethod 
    def nameop_put_collision( cls, collisions, nameop ):
        """
        Record a nameop as collided with another nameop in this block.
        """
        # these are supposed to have been put here by nameop_set_collided
        history_id_key = nameop.get('__collided_history_id_key__', None)
        history_id = nameop.get('__collided_history_id__', None)

        try:
            assert cls.nameop_is_collided( nameop ), "Nameop not collided"
            assert history_id_key is not None, "Nameop missing collision info"
            assert history_id is not None, "Nameop missing collision info"
        except Exception, e:
            log.exception(e)
            log.error("FATAL: BUG: bad collision info")
            os.abort()

        if not collisions.has_key(history_id_key):
            collisions[history_id_key] = [history_id]
        else:
            collisions[history_id_key].append( history_id )


    def extract_consensus_op(self, opcode, op_data, processed_op_data, current_block_number):
        """
        Using the operation data extracted from parsing the virtualchain operation (@op_data),
        and the checked, processed operation (@processed_op_data), return a dict that contains
        (1) all of the consensus fields to snapshot this operation, and
        (2) all of the data fields that we need to store for the name record (i.e. quirk fields)
        """
        ret = {}

        consensus_fields = op_get_consensus_fields(opcode)
        quirk_fields = op_get_quirk_fields(opcode)
        for field in consensus_fields + quirk_fields:

            try:
                # assert field in processed_op_data or field in op_data, 'Missing consensus field "{}"'.format(field)
                assert field in processed_op_data, 'Missing consensus field "{}"'.format(field)
            except Exception as e:
                # should NEVER happen
                log.exception(e)
                log.error("FATAL: BUG: missing consensus field {}".format(field))
                log.error("op_data:\n{}".format(json.dumps(op_data, indent=4, sort_keys=True)))
                log.error("processed_op_data:\n{}".format(json.dumps(op_data, indent=4, sort_keys=True)))
                os.abort()
            
            ret[field] = processed_op_data[field]

        return ret


    def commit_operation( self, input_op_data, accepted_nameop, current_block_number ):
        """
        Commit an operation, thereby carrying out a state transition.

        Returns a dict with the new db record fields
        """
   
        # have to have read-write disposition 
        if self.disposition != DISPOSITION_RW:
            log.error("FATAL: borrowing violation: not a read-write connection")
            traceback.print_stack()
            os.abort()

        cur = self.db.cursor()
        canonical_op = None
        op_type_str = None      # for debugging
        opcode = accepted_nameop.get('opcode', None)

        try:
            assert opcode is not None, "Undefined op '%s'" % accepted_nameop['op']
        except Exception, e:
            log.exception(e)
            log.error("FATAL: unrecognized op '%s'" % accepted_nameop['op'] )
            os.abort()

        if opcode in OPCODE_PREORDER_OPS:
            # preorder
            canonical_op = self.commit_state_preorder( accepted_nameop, current_block_number )
            op_type_str = "state_preorder"
            
        elif opcode in OPCODE_CREATION_OPS:
            # creation
            canonical_op = self.commit_state_create( accepted_nameop, current_block_number )
            op_type_str = "state_create"
           
        elif opcode in OPCODE_TRANSITION_OPS:
            # transition 
            canonical_op = self.commit_state_transition( accepted_nameop, current_block_number )
            op_type_str = "state_transition"
       
        elif opcode in OPCODE_TOKEN_OPS:
            # token operation 
            canonical_op = self.commit_token_operation(accepted_nameop, current_block_number)
            op_type_str = "token_operation"

        else:
            raise Exception("Unknown operation {}".format(opcode))

        if canonical_op is None:
            log.error("FATAL: no canonical op generated (for {})".format(op_type_str))
            os.abort()
        
        log.debug("Extract consensus fields for {} in {}, as part of a {}".format(opcode, current_block_number, op_type_str))
        consensus_op = self.extract_consensus_op(opcode, input_op_data, canonical_op, current_block_number)
        return consensus_op

    
    def commit_account_debit(self, opcode, account_payment_info, current_block_number, current_vtxindex, current_txid):
        """
        Given the account info set by a state-create or state-transition or a token-operation,
        debit the relevant account.
        
        Do not call this directly.

        Return True on success
        Abort on error
        """
        account_address = account_payment_info['address']
        account_payment = account_payment_info['amount']
        account_token_type = account_payment_info['type']

        if account_address is not None and account_payment is not None and account_token_type is not None:
            # sanity check 
            try:
                assert account_payment >= 0, 'Negative account payment {}'.format(account_payment)
                assert self.is_token_type_supported(account_token_type), 'Unsupported token type {}'.format(account_token_type)
            except Exception as e:
                log.exception(e)
                log.fatal("Sanity check failed")
                os.abort()

            # have to debit this account
            cur = self.db.cursor()
            rc = namedb_account_debit(cur, account_address, account_token_type, account_payment, current_block_number, current_vtxindex, current_txid)
            if not rc:
                traceback.print_stack()
                log.fatal("Failed to debit address {} {} {}".format(account_address, account_payment, account_token_type))
                os.abort()

            log.debug("COMMIT DEBIT ACCOUNT {} for {} units of {}(s) for {}".format(account_address, account_payment, account_token_type, opcode))

        return True


    def commit_account_credit(self, opcode, account_credit_info, current_block_number, current_vtxindex, current_txid):
        """
        Given the account info set by a state-create or state-transition or a token-operation,
        debit the relevant account.
        
        Do not call this directly.

        Return True on success
        Abort on error
        """
        account_address = account_credit_info['address']
        account_credit = account_credit_info['amount']
        account_token_type = account_credit_info['type']

        if account_address is not None and account_credit is not None and account_token_type is not None:
            # sanity check 
            try:
                assert account_credit >= 0, 'Non-positive account credit {}'.format(account_credit)
                assert self.is_token_type_supported(account_token_type), 'Unsupported token type {}'.format(account_token_type)
            except Exception as e:
                log.exception(e)
                log.fatal("Sanity check failed")
                os.abort()

            # have to debit this account
            cur = self.db.cursor()
            rc = namedb_account_credit(cur, account_address, account_token_type, account_credit, current_block_number, current_vtxindex, current_txid)
            if not rc:
                traceback.print_stack()
                log.fatal("Failed to debit address {} {} {}".format(account_address, account_credit, account_token_type))
                os.abort()

            log.debug("COMMIT CREDIT ACCOUNT {} for {} units of {}(s) for {}".format(account_address, account_credit, account_token_type, opcode))

        return True


    def commit_state_preorder( self, nameop, current_block_number ):
        """
        Commit a state preorder (works for namespace_preorder and name_preorder),

        DO NOT CALL THIS DIRECTLY
        """

        # have to have read-write disposition 
        if self.disposition != DISPOSITION_RW:
            log.error("FATAL: borrowing violation: not a read-write connection")
            traceback.print_stack()
            os.abort()
        
        opcode = None
        try:
            opcode = nameop.get('opcode')
            assert opcode is not None, 'BUG: no preorder opcode'
        except Exception as e:
            log.exception(e)
            log.error("FATAL: no opcode in preorder")
            os.abort()

        # did we pay any tokens for this state?
        account_payment_info = state_preorder_get_account_payment_info(nameop)

        cur = self.db.cursor()

        # cannot have collided 
        if BlockstackDB.nameop_is_collided( nameop ):
            log.debug("Not commiting '%s', since it collided" % nameop)
            self.log_reject(current_block_number, nameop['vtxindex'], nameop['op'], nameop)
            return []

        self.log_accept( current_block_number, nameop['vtxindex'], nameop['op'], nameop )

        commit_preorder = self.sanitize_op( nameop )
        rc = namedb_preorder_insert( cur, commit_preorder )
        if not rc:
            log.error("FATAL: failed to commit preorder '%s'" % commit_preorder['preorder_hash'] )
            os.abort()

        # debit tokens, if present
        self.commit_account_debit(opcode, account_payment_info, current_block_number, nameop['vtxindex'], nameop['txid'])

        self.db.commit()
        return commit_preorder 


    def commit_state_create( self, nameop, current_block_number ):
        """
        Commit a state-creation operation (works for name_registration,
        namespace_reveal, name_import).

        Returns the sequence of dicts of fields to serialize.

        DO NOT CALL THIS DIRECTLY
        """

        # have to have read-write disposition 
        if self.disposition != DISPOSITION_RW:
            log.error("FATAL: borrowing violation: not a read-write connection")
            traceback.print_stack()
            os.abort()

        cur = self.db.cursor()
        opcode = nameop.get('opcode', None)

        try:
            assert state_create_is_valid( nameop ), "Invalid state-creation"
            assert opcode is not None, "BUG: did not set opcode"
            
            preorder = state_create_get_preorder( nameop )
        except Exception, e:
            log.exception(e)
            log.error("FATAL: missing preorder and/or prior history and/or opcode")
            os.abort()

        initial_state = self.sanitize_op( nameop )
        table = state_create_get_table( nameop )
        history_id_key = state_create_get_history_id_key( nameop )
        history_id = nameop[history_id_key]
        constraints_ignored = state_create_get_always_set( nameop )

        # cannot have collided 
        if BlockstackDB.nameop_is_collided( nameop ):
            # TODO: is this reachable?
            log.debug("Not commiting '%s' since we're collided" % history_id)
            self.log_reject( current_block_number, nameop['vtxindex'], nameop['op'], nameop )
            return {}

        self.log_accept( current_block_number, nameop['vtxindex'], nameop['op'], nameop )
        
        canonical_opdata = None

        if preorder is not None:
            # preordered a name or a namespace, possibly not for the first time even.
            try:
                assert 'preorder_hash' in preorder, 'BUG: missing preorder-hash'
            except Exception as e:
                log.exception(e)
                log.error("FATAL: invalid preorder")
                os.abort()

            canonical_opdata = namedb_state_create(cur, opcode, initial_state, current_block_number,
                                                   initial_state['vtxindex'], initial_state['txid'],
                                                   history_id, preorder, table, constraints_ignored=constraints_ignored)

            if not canonical_opdata:
                log.error("FATAL: failed to create '{}'".format(history_id))
                self.db.rollback()
                os.abort()

            self.db.commit()
        
        else:
            # importing a name
            try:
                assert opcode in OPCODE_NAME_STATE_IMPORTS, "BUG: not an import operation"
            except Exception, e:
                log.exception(e)
                log.error("FATAL: invalid import operation")
                os.abort()

            canonical_opdata = namedb_state_create_as_import(self.db, opcode, initial_state, 
                                                             current_block_number, initial_state['vtxindex'], initial_state['txid'],
                                                             history_id, table, constraints_ignored=constraints_ignored)

            if not canonical_opdata:
                log.error("FATAL: failed to create '{}' as import".format(history_id))
                self.db.rollback()
                os.abort()

            self.db.commit()
        
        return canonical_opdata


    def commit_state_transition( self, nameop, current_block_number ):
        """
        Commit a state transition (update, transfer, revoke, renew, namespace_ready).
        
        Returns the new canonicalized record (with all compatibility quirks preserved)

        DO NOT CALL THIS DIRECTLY
        """

        # have to have read-write disposition 
        if self.disposition != DISPOSITION_RW:
            log.error("FATAL: borrowing violation: not a read-write connection")
            traceback.print_stack()
            os.abort()

        cur = self.db.cursor()
        opcode = nameop.get('opcode', None)
        constraints_ignored = state_transition_get_always_set( nameop )
        transition = self.sanitize_op( nameop )
        
        try:
            assert state_transition_is_valid( nameop ), "Invalid state-transition"
            assert opcode is not None, "No opcode given"
        except Exception, e:
            log.exception(e)
            log.error("FATAL: failed to commit state transition")
            self.db.rollback()
            os.abort()

        table = state_transition_get_table( nameop )
        history_id_key = state_transition_get_history_id_key( nameop )
        account_payment_info = state_transition_get_account_payment_info(nameop)
        history_id = nameop[history_id_key]

        # record must exist...
        if history_id_key == "name":
            cur_record = namedb_get_name( cur, history_id, current_block_number, include_history=False, include_expired=True )

        elif history_id_key == "namespace_id":
            cur_record = namedb_get_namespace( cur, history_id, current_block_number, include_history=False, include_expired=True )

        else:
            raise Exception("Unknown history ID key '%s'" % history_id_key)

        try:
            assert cur_record is not None, "No such record: %s" % history_id
        except Exception, e:
            # should have been caught earlier
            log.exception(e)
            log.error("FATAL: failed to lookup existing record '%s'" % history_id)
            self.db.rollback()
            os.abort()

        self.log_accept( current_block_number, nameop['vtxindex'], nameop['op'], nameop )

        canonical_op = namedb_state_transition( cur, opcode, transition, current_block_number, transition['vtxindex'], transition['txid'],
                                                 history_id, cur_record, table, constraints_ignored=constraints_ignored )
        if not canonical_op:
            log.error("FATAL: failed to update '%s'" % history_id)
            self.db.rollback()
            os.abort()
        
        self.commit_account_debit(opcode, account_payment_info, current_block_number, transition['vtxindex'], transition['txid'])

        return canonical_op


    def commit_token_operation(self, token_op, current_block_number):
        """
        Commit a token operation that debits one account and credits another

        Returns the new canonicalized record (with all compatibility quirks preserved)

        DO NOT CALL THIS DIRECTLY
        """
        # have to have read-write disposition 
        if self.disposition != DISPOSITION_RW:
            log.error("FATAL: borrowing violation: not a read-write connection")
            traceback.print_stack()
            os.abort()

        cur = self.db.cursor()
        opcode = token_op.get('opcode', None)
        clean_token_op = self.sanitize_op(token_op)
       
        try:
            assert token_operation_is_valid(token_op), 'Invalid token operation'
            assert opcode is not None, 'No opcode given'
            assert 'txid' in token_op, 'No txid'
            assert 'vtxindex' in token_op, 'No vtxindex'
        except Exception as e:
            log.exception(e)
            log.error('FATAL: failed to commit token operation')
            self.db.rollback()
            os.abort()

        table = token_operation_get_table(token_op)
        account_payment_info = token_operation_get_account_payment_info(token_op)
        account_credit_info = token_operation_get_account_credit_info(token_op)

        # fields must be set
        try:
            for key in account_payment_info:
                assert account_payment_info[key] is not None, 'BUG: payment info key {} is None'.format(key)

            for key in account_credit_info:
                assert account_credit_info[key] is not None, 'BUG: credit info key {} is not None'.format(key)

            # NOTE: do not check token amount and type, since in the future we want to support converting
            # between tokens
        except Exception as e:
            log.exception(e)
            log.error("FATAL: invalid token debit or credit info")
            os.abort()
        
        self.log_accept(current_block_number, token_op['vtxindex'], token_op['op'], token_op)
        
        # NOTE: this code is single-threaded, but this code must be atomic
        self.commit_account_debit(token_op, account_payment_info, current_block_number, token_op['vtxindex'], token_op['txid'])
        self.commit_account_credit(token_op, account_credit_info, current_block_number, token_op['vtxindex'], token_op['txid'])

        namedb_history_save(cur, opcode, token_op['address'], None, None, current_block_number, token_op['vtxindex'], token_op['txid'], clean_token_op)
        return clean_token_op

    
    def commit_account_vesting(self, block_height):
        """
        vest any tokens at this block height
        """
        # save all state
        log.debug("Commit all database state before vesting")
        self.db.commit()

        if block_height in self.vesting:
            traceback.print_stack()
            log.fatal("Tried to vest tokens twice at {}".format(block_height))
            os.abort()

        # commit all vesting in one transaction
        cur = self.db.cursor()
        namedb_query_execute(cur, 'BEGIN', ())
        res = namedb_accounts_vest(cur, block_height)
        namedb_query_execute(cur, 'END', ())

        self.vesting[block_height] = True
        return True


    def get_block_ops_hash( self, block_id ):
        """
        Get the block's operations hash
        """
        return self.get_ops_hash_at(block_id)

