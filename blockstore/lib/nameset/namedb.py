#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

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
    along with Blockstore. If not, see <http://www.gnu.org/licenses/>.
"""

import json
import traceback
import binascii
import hashlib
import math
import keychain
import pybitcoin
import os
import copy
import shutil

from collections import defaultdict
from ..config import NAMESPACE_DEFAULT, MIN_OP_LENGTHS, OPCODES, MAX_NAMES_PER_SENDER, \
    NAME_PREORDER, NAMESPACE_PREORDER, NAME_REGISTRATION, NAME_UPDATE, NAME_TRANSFER, TRANSFER_KEEP_DATA, \
    TRANSFER_REMOVE_DATA, NAME_REVOKE, NAME_IMPORT, NAME_PREORDER_EXPIRE, \
    NAMESPACE_PREORDER_EXPIRE, NAMESPACE_REVEAL_EXPIRE, NAMESPACE_REVEAL, BLOCKSTORE_VERSION, \
    NAMESPACE_1_CHAR_COST, NAMESPACE_23_CHAR_COST, NAMESPACE_4567_CHAR_COST, NAMESPACE_8UP_CHAR_COST, NAME_COST_UNIT, \
    TESTSET_NAMESPACE_1_CHAR_COST, TESTSET_NAMESPACE_23_CHAR_COST, TESTSET_NAMESPACE_4567_CHAR_COST, TESTSET_NAMESPACE_8UP_CHAR_COST, NAME_COST_UNIT, \
    NAME_IMPORT_KEYRING_SIZE, GENESIS_SNAPSHOT, GENESIS_SNAPSHOT_TESTSET, default_blockstore_opts, NAMESPACE_READY

from ..operations import build_namespace_reveal
from ..hashing import *
from ..b40 import is_b40

import virtualchain

if not globals().has_key('log'):
    log = virtualchain.session.log


class BlockstoreDB( virtualchain.StateEngine ):
   """
   State engine implementatoin for blockstore.
   Tracks the set of names and namespaces, as well as the
   latest hash of their profile data (which in turn resolves
   to JSON in ancillary storage that contains the pointers
   to their mutable data).

   NOTE: this only works with small-ish datasets (~10 million names or less)
   before things get too slow.  At that point, we'll need
   to upgrade to an actual database.
   """

   def __init__(self, db_filename ):
      """
      Construct a blockstore state engine, optionally from locally-cached
      blockstore database state.
      """

      import virtualchain_hooks
      blockstore_opts = default_blockstore_opts( virtualchain.get_config_filename() )
      initial_snapshots = None

      if blockstore_opts['testset']:
          initial_snapshots = GENESIS_SNAPSHOT_TESTSET

      else:
          initial_snapshots = GENESIS_SNAPSHOT


      super( BlockstoreDB, self ).__init__( virtualchain_hooks.get_magic_bytes(), OPCODES, impl=virtualchain_hooks, initial_snapshots=initial_snapshots, state=self )

      self.announce_ids = blockstore_opts['announcers'].split(",")

      self.db_filename = db_filename

      self.name_records = {}                  # map name.ns_id to a dict containing the name record
                                              # in addition to containing all of the NAME_REC fields, it contains
                                              # a 'history' dict that maps a block ID to the old values of fields changed at that block,

      self.preorders = {}                     # map preorder name.ns_id+script_pubkey hash (as a hex string) to its first "preorder" nameop
      self.namespaces = {}                    # map namespace ID to first instance of NAMESPACE_REVEAL op (a dict) combined with the namespace ID and sender script_pubkey
      self.namespace_preorders = {}           # map namespace ID hash (as the hex string of ns_id+script_pubkey hash) to its NAMESPACE_PREORDER operation
      self.namespace_reveals = {}             # map namesapce ID to its NAMESPACE_REVEAL operation

      self.owner_names = defaultdict(list)    # secondary index: map sender_script_pubkey hex string to list of names owned by the principal it represents
      self.hash_names = {}                    # secondary index: map hex_hash160(name) to name

      self.namespace_id_to_hash = {}          # secondary index: map the namespace ID of a revealed namespace to its namespace hash.  Entries here only exist until the namespace is ready

      self.block_name_expires = defaultdict(list)  # secondary index: map a block ID to the list of names that expire at that block.

      self.name_consensus_hash_name = {}      # secondary index: temporary table for mapping the hash(name + consensus_hash) in an update to its name

      self.import_addresses = {}              # secondary index: temporary table for mapping a NAMESPACE_REVEAL's root public key address to the set of all derived public key addresses.
                                              # each NAME_IMPORT must come from one of these derived public key addresses.

      self.address_names = defaultdict(list)  # secondary index: map each address to the list of names registered to it.
                                              # valid only for names where there is exactly one address (i.e. the sender is a p2pkh script)

      # default namespace (empty string)
      self.namespaces[""] = NAMESPACE_DEFAULT
      self.namespaces[None] = NAMESPACE_DEFAULT

      if db_filename:
         try:
            with open(db_filename, 'r') as f:

               db_dict = json.loads(f.read())

               if 'registrations' in db_dict:
                  self.name_records = db_dict['registrations']

               if 'namespaces' in db_dict:
                  self.namespaces = db_dict['namespaces']

                  # translate empty namesapce ID from json-ized format
                  if "null" in self.namespaces.keys():
                     self.namespaces[None] = self.namespaces["null"]
                     del self.namespaces["null"]

               if 'namespace_preorders' in db_dict:
                  self.namespace_preorders = db_dict['namespace_preorders']

               if 'namespace_reveals' in db_dict:
                  self.namespace_reveals = db_dict['namespace_reveals']

               if 'preorders' in db_dict:
                  self.preorders = db_dict['preorders']

         except Exception as e:
            log.warning("Failed to open '%s'; creating a new database" % db_filename)
            pass

      for name, name_record in self.name_records.items():

         # build up our reverse indexes on names
         ns_id = get_namespace_from_name( name )
         namespace = self.namespaces.get( ns_id, None )
         if namespace is None:
             # maybe its revealing?
             namespace = self.namespace_reveals.get( ns_id, None )
             if namespace is None:
                 raise Exception("Name with no namespace: '%s'" % name)

         expires = name_record['last_renewed'] + namespace['lifetime']

         # build expiration dates
         if not self.block_name_expires.has_key( expires ):
             self.block_name_expires[ expires ] = [name]
         else:
             self.block_name_expires[ expires ].append( name )

         # build sender --> names
         if not self.owner_names.has_key( name_record['sender'] ):
             self.owner_names[ name_record['sender'] ] = [name]
         else:
             self.owner_names[ name_record['sender'] ].append( name )

         # build hash --> name
         self.hash_names[ hash256_trunc128( name ) ] = name

         # build address --> names
         if name_record.has_key('address'):
             if not self.address_names.has_key( name_record['address'] ):
                 self.address_names[ name_record['address'] ] = [name]
             else:
                 self.address_names[ name_record['address'] ].append( name )

         # convert history to int
         self.name_records[name]['history'] = BlockstoreDB.sanitize_history( self.name_records[name]['history'] )

         # convert vtxindex
         self.name_records[name]['vtxindex'] = int(self.name_records[name]['vtxindex'])


      for (namespace_id, namespace_reveal) in self.namespace_reveals.items():

         # build up our reverse indexes on reveals
         self.namespace_id_to_hash[ namespace_reveal['namespace_id'] ] = namespace_reveal['namespace_id_hash']

         if namespace_id in (None, ""):
             continue

         pubkey_hex = None
         pubkey_addr = None

         # find a revealed name whose sender's address matches the namespace recipient's
         for name, name_record in self.name_records.items():
             if not name.endswith( namespace_id ):
                 continue

             if not name_record.has_key('sender_pubkey'):
                 continue

             pubkey_hex = name_record['sender_pubkey']
             pubkey_addr = pybitcoin.BitcoinPublicKey( str(pubkey_hex) ).address()

             if pubkey_addr != namespace_reveal['recipient_address']:
                 continue

             break

         if pubkey_hex is not None:
            log.debug("Deriving %s children of %s ('%s') for '%s'" % (NAME_IMPORT_KEYRING_SIZE, pubkey_addr, pubkey_hex, namespace_id))

            # generate all possible addresses from this public key
            self.import_addresses[ namespace_id ] = BlockstoreDB.build_import_keychain( pubkey_hex )

         # convert history to int
         self.namespace_reveals[namespace_id]['history'] = BlockstoreDB.sanitize_history( namespace_reveal['history'] )

      for (namespace_id, namespace) in self.namespaces.items():

         # sanitize history on import
         self.namespaces[namespace_id]['history'] = BlockstoreDB.sanitize_history( namespace['history'] )

      self.prescanned = False


   def save_db(self, filename):
      """
      Cache the set of blockstore operations to disk,
      so we don't have to go build them up again from
      the blockchain.
      """

      try:
         with open(filename, 'w') as f:

            db_dict = {
               'registrations': self.name_records,
               'preorders': self.preorders,
               'namespaces': self.namespaces,
               'namespace_preorders': self.namespace_preorders,
               'namespace_reveals': self.namespace_reveals
            }

            f.write(json.dumps(db_dict))
            f.flush()

      except Exception as e:
         log.exception(e)
         return False

      return True


   def get_db_path( self ):
      """
      Get db file path
      """
      return self.db_filename


   def export_db( self, path ):
      """
      Copy the database to the given location.
      """
      shutil.copyfile( self.get_db_path(), path )


   @classmethod
   def sanitize_history( cls, history ):
      """
      Given a record's history dict, sanitize it:
      * convert string-ified block numbers to ints.
      """

      block_number_strs = history.keys()
      for block_number_str in block_number_strs:
          history_rec = history[block_number_str]
          del history[block_number_str]
          history[int(block_number_str)] = history_rec

      return history


   @classmethod
   def build_import_keychain( cls, pubkey_hex ):
      """
      Generate all possible NAME_IMPORT addresses from the NAMESPACE_REVEAL public key
      """

      pubkey_addr = pybitcoin.BitcoinPublicKey( str(pubkey_hex) ).address()

      # do we have a cached one on disk?
      cached_keychain = os.path.join( virtualchain.get_working_dir(), "%s.keychain" % pubkey_addr)
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


   def is_name_expired( self, name, block_number ):
      """
      Given a name, determine if it is expired.
      * names in revealed but not ready namespaces are never expired
      * names in ready namespaces expire once max(ready_block, renew_block) + lifetime blocks passes

      Return True if so
      Return False if not, or if the name doesn't exist
      """

      namerec = self.name_records.get( name, None )
      if namerec is None:
          # doesn't exist
          return False

      ns_id = get_namespace_from_name( name )
      ns = self.get_namespace( ns_id )
      if ns is None:
          # maybe revealed?
          ns = self.get_namespace_reveal( ns_id )
          if ns is None:
              # doesn't exist
              return True
          else:
              # imported into non-ready namespace
              return False

      else:
          if max( ns['ready_block'], namerec['last_renewed'] ) + ns['lifetime'] < block_number:
              # expired
              return True
          else:
              return False


   def get_name( self, name, include_expired=False ):
      """
      Given a name, return the latest version and history of
      the metadata gleaned from the blockchain.
      Name must be fully-qualified (i.e. name.ns_id)
      Return None if no such name is registered.
      """

      if name not in self.name_records.keys():
         return None

      else:
         # don't return expired names
         if not include_expired and self.is_name_expired( name, self.lastblock ):
             return None

         else:
             return self.name_records[name]


   def get_name_at( self, name, block_number ):
      """
      Generate and return the sequence of of states a name record was in
      at a particular block number.
      """

      name_rec = self.get_name( name )

      # trivial reject
      if name_rec is None:
          # never existed
          return None

      if block_number < name_rec['block_number']:
          # didn't exist then
          return None

      historical_recs = BlockstoreDB.restore_from_history( name_rec, block_number )
      return historical_recs


   def get_namespace_at( self, namespace_id, block_number ):
      """
      Generate and return the sequence of states a namespace record was in
      at a particular block number.
      """

      namespace_rec = self.get_namespace( namespace_id )
      if namespace_rec is None:
          return None

      if block_number < namespace_rec['block_number']:
          return None

      historical_recs = BlockstoreDB.restore_from_history( namespace_rec, block_number )
      return historical_recs


   def get_name_history( self, name, start_block, end_block ):
      """
      Get the sequence of states of a name over a given point in time.

      TODO: this is not particularly efficient
      """

      name_rec = self.get_name( name )
      if name_rec is None:
          return None

      name_snapshots = []

      update_points = sorted( name_rec['history'].keys() )
      for update_point in update_points:
          if update_point >= start_block and update_point < end_block:
             historical_recs = self.get_name_at( name, update_point )
             name_snapshots += historical_recs

      return name_snapshots


   def get_names_owned_by_address( self, address ):
      """
      Get the set of names owned by a particular address.
      Only valid if the name was sent by a p2pkh script.
      """

      if self.address_names.has_key( address ):
          return self.address_names[address]
      else:
          return None


   def _rec_dup( self, rec ):
      """
      (private method)
      Duplicate a name record, and strip out all
      unnecessary information.
      """
      ret = copy.deepcopy( rec )
      del ret['history']
      return ret


   def get_all_nameops_at( self, block_id ):
      """
      Given a block number, get the set of sequences name operations
      created or altered at that block number.

      Return the list of names, in the order their transactions occurred.
      """

      ret = []

      # all name records
      for (name, name_rec) in self.name_records.items():
          if block_id < name_rec['block_number'] or block_id not in (name_rec['history'].keys() + [name_rec['block_number']]):
              # neither created nor altered at this block
              continue

          recs = BlockstoreDB.restore_from_history( name_rec, block_id )
          ret += recs

      # all current preorders
      for (name_hash, preorder) in self.preorders.items():
          if block_id == preorder['block_number']:

              rec = self._rec_dup( preorder )
              ret.append( rec )

      # all namespaces
      for (namespace_id, namespace) in self.namespaces.items():

          # null namespaces don't exist
          if namespace_id is None or len(namespace_id) == 0:
              continue

          if block_id < namespace['block_number'] or block_id not in (namespace['history'].keys() + [namespace['block_number']]):
              # neither created nor altered at this block
              continue

          recs = BlockstoreDB.restore_from_history( namespace, block_id )
          ret += recs

      # all current namespace preorders
      for (namespace_id_hash, namespace_preorder) in self.namespace_preorders.items():
          if block_id == namespace_preorder['block_number']:

              rec = self._rec_dup( namespace_preorder )
              ret.append( rec )

      # all current namespace reveals
      for (namespace_id, namespace_reveal) in self.namespace_reveals.items():

          if block_id < namespace_reveal['block_number'] or block_id not in namespace_reveal['history'].keys() + [namespace_reveal['block_number']]:
              continue

          recs = BlockstoreDB.restore_from_history( namespace_reveal, block_id )
          ret += recs

      return sorted( ret, key=lambda n: n['vtxindex'] )


   def get_all_names( self, offset=None, count=None ):
      """
      Get the set of all registered names, with optional pagination
      Returns the list of names.
      TODO: this is somewhat inefficient with offsets, since we have
      to sort the name set first.
      """

      if offset is None:
          offset = 0

      if offset < 0:
         raise Exception("Invalid offset %s" % offset)

      if offset >= len(self.name_records.keys()):
         return []

      names = []
      if count is None:
         names = self.name_records.keys()[:]
         names.sort()

      else:
         names = sorted(self.name_records.keys())[offset:min(offset+count, len(self.name_records.keys()))]
         names.sort()

      #return dict( zip( names, [self.name_records[name] for name in names] ) )
      return names

   def get_names_in_namespace( self, namespace_id, offset=None, count=None ):
      """
      Get the current set of all registered names in a particular namespace
      TODO: this is somewhat inefficient since we have to scan through
      the whole name set.
      """

      if offset is None:
          offset = 0

      if offset < 0:
          raise Exception("Invalid offset %s" % offset)

      if offset >= len(self.name_records.keys()):
          return []

      all_names = self.name_records.keys()[:]
      all_names.sort()

      namespace_names = []

      for name in all_names:
          if get_namespace_from_name( name ) != namespace_id:
              continue

          if offset == 0:
              namespace_names.append( name )
              if len(namespace_names) >= count:
                  break

          else:
              offset -= 1

      data = {}
      data['results'] = namespace_names

      # old format that returned data on individual records as well
      #return dict( zip( namespace_names, [self.name_records[name] for name in namespace_names] ) )
      return data



   def get_namespace( self, namespace_id ):
      """
      Given a namespace ID, get the namespace op for it.

      Return the dict with the parameters on success.
      Return None if the namespace does not exist.
      """

      return self.namespaces.get( namespace_id, None )


   def get_all_namespace_ids( self ):
      """
      Get the set of all namespace IDs
      """

      return self.namespaces.keys()


   def get_all_preordered_namespace_hashes( self ):
      """
      Get all outstanding namespace hashes
      """
      namespace_hashes = self.namespace_preorders.keys()
      ret = []
      for nh in namespace_hashes:
          if self.namespace_preorders[nh]['block_number'] + NAMESPACE_PREORDER_EXPIRE > self.lastblock:
              # not expired
              ret.append( nh )

      return ret


   def get_all_revealed_namespace_ids( self ):
      """
      Get the IDs of all outsanding revealed namespaces.
      """
      namespace_ids = self.namespace_reveals.keys()
      ret = []
      for nsid in namespace_ids:
          if self.namespace_reveals[nsid]['reveal_block'] + NAMESPACE_REVEAL_EXPIRE > self.lastblock:
              # not expired
              ret.append( nsid )

      return ret


   def get_all_importing_namespace_hashes( self ):
      """
      Get the set of all preordered and revealed namespace hashes.
      """

      revealed_namespace_hashes = []
      for (namespace_id, revealed_namespace) in self.namespace_reveals.items():

          # skip expired namespace reveals
          if self.namespace_reveals[namespace_id]['expired']:
              continue

          revealed_namespace_hashes.append( revealed_namespace['namespace_id_hash'] )

      return self.namespace_preorders.keys() + revealed_namespace_hashes


   def get_name_from_name_consensus_hash( self, name_consensus_hash, sender, block_id ):
      """
      Find the name.ns_id from hash( name.ns_id, consensus_hash ), given the sender and block_id,
      and assuming that name.ns_id is already registered.
      There are only a small number of possible values this can take, so test them all to see
      if the hash matches one of them.

      This is useful for name updates--we need to ensure that updates are timely, and on
      the majority fork of the blockchain.

      Return the (fully-qualified name, consensus hash) on success
      Return (None, None) if not found
      """

      names = self.owner_names.get( sender, None )
      if names is None:

         log.error("Sender %s owns no names" % sender)
         # invalid name owner
         return None, None

      possible_consensus_hashes = []

      for i in xrange( block_id - virtualchain.config.BLOCKS_CONSENSUS_HASH_IS_VALID, block_id+1 ):
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


   def get_name_preorder( self, name, sender_script_pubkey, register_addr ):
      """
      Get the preorder for a name, given the name, the sender's script_pubkey string, and the
      registration address used to calculate the preorder hash.
      Return the nameop on success
      Return None if not found, or if the preorder is expired, or if the preorder is already registered.
      """

      # name registered and not expired?
      name_rec = self.get_name( name )
      if name_rec is not None:
          return None

      preorder_hash = hash_name(name, sender_script_pubkey, register_addr=register_addr)
      if preorder_hash not in self.preorders.keys():
          return None

      else:
          return self.preorders[ preorder_hash ]


   def get_namespace_preorder( self, namespace_id_hash ):
      """
      Given the hash(namespace_id, sender_script_pubkey) for a namespace that is
      being imported, get its assocated NAMESPACE_PREORDER operation.

      Return the op as a dict on success
      Return None on error
      """

      if namespace_id_hash not in self.namespace_preorders.keys():
         return None

      return self.namespace_preorders[ namespace_id_hash ]


   def get_name_owner( self, name ):
      """
      Get the script_pubkey hex string of the user that
      owns the given name.

      Return the string on success
      Return None if not found.
      """
      if name in self.name_records.keys() and 'sender' in self.name_records[name]:
         return self.name_records[name]['sender']

      else:
         return None


   def get_namespace_reveal( self, namespace_id ):
      """
      Given the name of a namespace, go get its NAMESPACE_REVEAL operation.
      Check the set of readied namespaces, and then check the list of
      pending imports.

      Return the nameop on success
      Return None if not found
      """

      return self.namespace_reveals.get( namespace_id, None )


   def find_expiring_at( self, block_id ):
      """
      Find all names that will expire at a particular block.

      Returns a list of names on success (which can be empty)
      """
      return self.block_name_expires.get( block_id, [] )


   def is_name_registered(self, name):
      """
      Is the given fully-qualified name (name.ns_id) registered and available?
      Return True if so.
      Return False if not.
      """

      if name not in self.name_records.keys():
          return False

      if self.name_records[name].has_key('revoked') and self.name_records[name]['revoked']:
          return False

      if self.is_name_expired( name, self.lastblock ):
          return False

      return True


   def is_namespace_ready( self, namespace_id ):
      """
      Has a namepace with the given human-readable ID been declared?
      Return True if so.
      Return False if not.
      """
      return namespace_id in self.namespaces.keys()


   def is_namespace_preordered( self, namespace_id_hash ):
      """
      Has the given namespace been preordered?

      Return True if so.
      Return False if not.
      """

      namespace_preorder = self.get_namespace_preorder( namespace_id_hash )
      if namespace_preorder is None:
         return False

      return True


   def is_namespace_revealed( self, namespace_id ):
      """
      Given the name of a namespace, has it been revealed yet but not yet readied?

      Return True if so
      Return False if not.
      """
      return self.get_namespace_reveal( namespace_id ) is not None


   def is_name_owner( self, name, sender_script_pubkey ):
      """
      Given the fully-qualified name (name.ns_id) and a list of senders'
      script_pubkey hex strings, see if the sender is the name owner.
      Return True if so.
      Return False if not.
      """
      if name in self.name_records.keys() and 'sender' in self.name_records[name]:
         if self.name_records[name]['sender'] == sender_script_pubkey:
            return True

      return False


   def is_new_preorder( self, name_hash ):
      """
      Given the preorder hash of a name, determine whether or not the name is in the process of being ordered already.
      Return True if so.
      Return False if not.
      """
      return (name_hash not in self.preorders.keys())


   def is_new_namespace_preorder( self, namespace_id_hash ):
      """
      Given the preorder hash of a namespace's ID, determine whether or not the namespace is in the process of being ordered already.

      Return True if so.
      Return False if not.
      """
      return (self.get_namespace_preorder(namespace_id_hash) is None)


   def is_name_revoked( self, name ):
      """
      Given a name, is it revoked?

      Return True if so
      Return False if not, or if the name does not exist
      """

      if not name in self.name_records.keys():
          return False

      return self.name_records[name]['revoked']


   @classmethod
   def restore_from_history( cls, rec, block_number ):
      """
      Given a name or a namespace record, replay its
      history diffs "back in time" to a particular block
      number.

      Return the sequence of states the name record went
      through at that block number, starting from the beginning
      of the block.

      Return None if the record does not exist at that point in time

      The returned records will *not* have a 'history' key.
      """

      block_history = list( reversed( sorted( rec['history'].keys() ) ) )

      historical_rec = copy.deepcopy( rec )
      del historical_rec['history']

      if block_number > block_history[0]:
          # current record is valid
          return historical_rec

      if block_number < rec['block_number']:
          # doesn't yet exist
          return None

      # find the latest block prior to block_number
      last_block = len(block_history)
      for i in xrange( 0, len(block_history) ):
          if block_number >= block_history[i]:
              last_block = i
              break

      i = 0
      while i < last_block:

          try:
              diff_list = list( reversed( rec['history'][ block_history[i] ] ) )
          except:
              print json.dumps( rec['history'][block_history[i]] )
              raise

          for diff in diff_list:

              if diff.has_key('history_snapshot'):
                  # wholly new state
                  historical_rec = copy.deepcopy( diff )
                  del historical_rec['history_snapshot']

              else:
                  # delta in current state
                  # no matter what, 'block_number' cannot be altered (unless it's a history snapshot)
                  if diff.has_key('block_number'):
                      del diff['block_number']

                  historical_rec.update( diff )

          i += 1

      # if this isn't the earliest history element, and the next-earliest
      # one (at last block) has multiple entries, then generate the sequence
      # of updates for all but the first one.  This is because all but the
      # first one were generated in the same block (i.e. the block requested).
      updates = [ copy.deepcopy( historical_rec ) ]

      if i < len(block_history):

          try:
              diff_list = list( reversed( rec['history'][ block_history[i] ] ) )
          except:
              print json.dumps( rec['history'][block_history[i]] )
              raise

          if len(diff_list) > 1:
              for diff in diff_list[:-1]:

                  # no matter what, 'block_number' cannot be altered
                  if diff.has_key('block_number'):
                      del diff['block_number']

                  if diff.has_key('history_snapshot'):
                      # wholly new state
                      historical_rec = copy.deepcopy( diff )
                      del historical_rec['history_snapshot']

                  else:
                      # delta in current state
                      historical_rec.update( diff )

                  updates.append( copy.deepcopy(historical_rec) )

      return list( reversed( updates ) )


   @classmethod
   def save_diff( self, rec, block_id, field_list ):
      """
      Back up a set of fields that will change for a given record.
      Update the record to include the modified fields in its
      'history' dict.  Add the 'history' dict if it doesn't exist.

      NOTE: only call this *once* per record--records should only
      be updated at most once per block!
      """

      diff_rec = {}
      for field in field_list:
          if field in rec:
              diff_rec[field] = copy.deepcopy( rec[field] )

      if not rec.has_key('history'):
          rec['history'] = {}

      if rec['history'].has_key( block_id ):
          rec['history'][block_id].append( diff_rec )

      else:
          rec['history'][block_id] = [diff_rec]

      return rec


   def save_name_diff( self, name, block_id, field_list):
      """
      Back up a set of fields that will change for a name record.
      This is to be done whenever the name undergoes a state change,
      so we can later reconstruct the name at a particular block ID.
      """

      if not self.name_records.has_key(name):
          return False

      self.name_records[name] = BlockstoreDB.save_diff( self.name_records[name], block_id, field_list )


   def commit_name_expire( self, name, block_id ):
      """
      Remove an expired name.
      The caller must verify that the expiration criteria have been met.
      Return True if expired
      Return False if not
      """

      name_hash = hash256_trunc128( name )

      owner = None

      if not self.name_records.has_key( name ):
         return False

      # anyone can claim the name now
      self.name_records[name]['revoked'] = False

      owner = self.name_records[name].get('sender', None)
      address = self.name_records[name].get('address', None)

      # update secondary indexes
      if owner is not None and self.owner_names.has_key( owner ) and name in self.owner_names[owner]:
         self.owner_names[ owner ].remove( name )
         if len(self.owner_names[owner]) == 0:
             del self.owner_names[owner]

      if address is not None and self.address_names.has_key( address ) and name in self.address_names[address]:
         self.address_names[ address ].remove( name )
         if len(self.address_names[address]) == 0:
             del self.address_names[address]

      if self.hash_names.has_key( name_hash ):
         del self.hash_names[ name_hash ]

      return True


   def commit_preorder_expire_all( self, block_id ):
      """
      Given the block ID, go find and remove all expired preorders

      Return the list of expired name hashes
      """

      expired = []
      for (name_hash, nameop) in self.preorders.items():
          if nameop['block_number'] + NAME_PREORDER_EXPIRE == block_id:
              # expired
              log.debug("Expire name preorder '%s'" % name_hash)
              expired.append( name_hash )

      return expired


   def commit_namespace_preorder_expire_all( self, block_id ):
      """
      Given the block ID, go find and remove all expired namespace preorders

      Return the list of expired namespace hashes
      """

      expired = []
      for (namespace_id_hash, preorder_nameop) in self.namespace_preorders.items():

          if preorder_nameop['block_number'] + NAMESPACE_PREORDER_EXPIRE == block_id:
              # expired
              log.debug("Expire namespace preorder '%s'" % namespace_id_hash)
              expired.append( namespace_id_hash )

      return expired


   def commit_namespace_reveal_expire_all( self, block_id ):
      """
      Given the block ID, go find and remove all expired namespace reveals
      that have not been made ready.  Remove their associated name imports.

      Return a dict that maps an expired namespace_id to the list of names expired.
      """

      expired = {}
      for (namespace_id, reveal_op) in self.namespace_reveals.items():

          if reveal_op['block_number'] + NAMESPACE_REVEAL_EXPIRE == block_id:

              # expired
              log.debug("Expire incomplete namespace '%s'" % namespace_id)
              del self.namespace_reveals[ namespace_id ]
              del self.namespace_id_to_hash[ namespace_id ]
              del self.import_addresses[ namespace_id ]

              expired[namespace_id] = []

              for name in self.name_records.keys():

                 if namespace_id == get_namespace_from_name( name ):
                     # part of this namespace
                     log.debug("Expire imported name '%s'" % name)
                     self.commit_name_expire( name, block_id )

                     expired[namespace_id].append( name )

      return expired



   def commit_name_expire_all( self, block_id ):
      """
      Given a block ID, remove all name records that expired
      at this block.

      Return the list of expired names.
      """

      expired_names = self.find_expiring_at( block_id )
      for name in expired_names:
         log.debug("Expire name '%s'" % name)
         self.commit_name_expire( name, block_id )

      if block_id in self.block_name_expires.keys():
         del self.block_name_expires[ block_id ]

      return expired_names


   def commit_remove_preorder( self, name, script_pubkey, register_addr ):
      """
      Given the fully-qualified name (name.ns_id) and a script_pubkey hex string,
      remove the preorder.

      Return the old preorder
      """
      try:
         name_hash = hash_name(name, script_pubkey, register_addr=register_addr)
      except ValueError:
         return None
      else:
         if self.preorders.has_key(name_hash):
            old_preorder = self.preorders[name_hash]
            del self.preorders[name_hash]
            return old_preorder

         else:
            log.error("BUG: No preorder found for '%s' from '%s'" % (name, script_pubkey))
            raise Exception("BUG: no preorder found for '%s' from '%s'" % (name, script_pubkey))


   def commit_remove_namespace_import( self, namespace_id, namespace_id_hash ):
      """
      Given the namespace ID, go remove the namespace preorder and reveal.
      (i.e. call this on a NAMESPACE_READY commit).
      """

      if self.namespace_preorders.has_key( namespace_id_hash ):
          del self.namespace_preorders[ namespace_id_hash ]

      if self.namespace_reveals.has_key( namespace_id ):
          del self.namespace_reveals[ namespace_id ]

      if self.namespace_id_to_hash.has_key( namespace_id ):
          del self.namespace_id_to_hash[ namespace_id ]

      if self.import_addresses.has_key( namespace_id ):
          del self.import_addresses[ namespace_id ]

      return


   def commit_preorder( self, nameop, current_block_number ):
      """
      Record that a name was preordered.
      """

      name_hash = nameop['preorder_name_hash']
      commit_nameop = self.sanitize_op( nameop )
      commit_nameop['block_number'] = current_block_number
      commit_nameop['history'] = {}
      commit_nameop['op'] = NAME_PREORDER
      self.preorders[ name_hash ] = commit_nameop

      # propagate information back to virtualchain for snapshotting
      nameop.update( self.preorders[name_hash] )
      return nameop


   def commit_registration( self, nameop, current_block_number ):
      """
      Record a name registration to have taken place at a particular
      block number.
      This removes the preorder for the name as well, and updates
      expiration and hash-to-name indexes.
      """

      name = nameop['name']
      sender = nameop['sender']
      address = nameop['address']

      # NOTE: on renewals, these fields should match the above two fields.
      recipient = nameop['recipient']
      recipient_address = nameop['recipient_address']

      # is this a renewal?
      if self.is_name_registered( name ):

          self.commit_renewal( nameop, current_block_number )

      else:

          # registered!
          preorder = self.commit_remove_preorder( name, sender, recipient_address )
          del preorder['history']

          # preorder becomes a history snapshot
          preorder = self.sanitize_op( preorder )
          preorder['history_snapshot'] = True

          prior_history = {}
          prior_block_number = preorder['block_number']

          # if we're replacing an expired name, merge this preorder into the name's history
          if self.name_records.get( name ) is not None:
              name_rec = self.name_records[name]
              prior_history = name_rec['history']
              prior_block_number = name_rec['block_number']

              # name changed
              preorder['name'] = name

              # preserve name historical information at the point just before the preorder
              prior_history[ preorder['block_number'] ] = [{
                 "name": name_rec['name'],
                 "value_hash": name_rec['value_hash'],
                 "sender": name_rec['sender'],
                 "sender_pubkey": name_rec.get('sender_pubkey', None),
                 "address": name_rec['address'],
                 "block_number": name_rec['block_number'],
                 "preorder_block_number": name_rec['preorder_block_number'],
                 "revoked": name_rec['revoked'],
                 "op": name_rec['op'],
                 "opcode": name_rec['opcode'],
                 "txid": name_rec['txid'],
                 "vtxindex": int(name_rec['vtxindex']),
                 "op_fee": name_rec['op_fee'],
                 "importer": name_rec['importer'],
                 "importer_address": name_rec['importer_address'],
                 "history_snapshot": True
              }]

              if 'consensus_hash' in name_rec.keys():
                  prior_history[ preorder['block_number'] ][0]['consensus_hash'] = name_rec['consensus_hash']


          name_record = {
            'name': name,
            'value_hash': None,             # i.e. the hex hash of profile data in immutable storage.
            'sender': str(recipient),       # the recipient is the expected future sender
            'sender_pubkey': nameop.get('sender_pubkey', None),
            'address': str(recipient_address),

            'block_number': prior_block_number,
            'preorder_block_number': preorder['block_number'],
            'first_registered': current_block_number,
            'last_renewed': current_block_number,
            'revoked': False,

            'op': NAME_REGISTRATION,
            'txid': str(nameop['txid']),
            'vtxindex': int(nameop['vtxindex']),
            'opcode': str(nameop['opcode']),
            'op_fee': int(preorder['op_fee']),

            # (not imported)
            'importer': None,
            'importer_address': None,

            'history': {
                # history of this name so far: its preorder
                current_block_number: [preorder]
            }
          }

          # merge prior history...
          name_record['history'].update( prior_history )

          ns_id = get_namespace_from_name( name )
          namespace = self.namespaces.get( ns_id, None )
          if namespace is None:
              raise Exception("Name with no namespace: '%s'" % name)

          expires = current_block_number + namespace['lifetime']

          self.name_records[ name ] = name_record

          # update secondary indexes
          self.owner_names[ recipient ].append( str(name) )
          self.address_names[ recipient_address ].append( str(name) )
          self.hash_names[ hash256_trunc128( name ) ] = name

          if not self.block_name_expires.has_key( expires ):
              self.block_name_expires[ expires ] = [name]
          else:
              self.block_name_expires[ expires ].append( name )

      # propagate information back to virtualchain for snapshotting
      nameop.update( self.name_records[ name ] )
      return nameop


   def commit_renewal( self, nameop, current_block_number ):
      """
      Commit a name renewal.  Push back its expiration.
      """

      name = nameop['name']
      txid = nameop['txid']
      op = "%s:" % NAME_REGISTRATION
      block_last_renewed = self.name_records[name]['last_renewed']

      ns_id = get_namespace_from_name( name )
      namespace = self.namespaces.get( ns_id, None )
      if namespace is None:
          raise Exception("Name with no namespace: '%s'" % name)

      old_expires = block_last_renewed + namespace['lifetime']
      expires = current_block_number + namespace['lifetime']

      # name no longer expires at the current expiry time
      if self.block_name_expires.has_key( old_expires ):
          if name in self.block_name_expires[ old_expires ]:
              self.block_name_expires[ old_expires ].remove( name )

      if not self.block_name_expires.has_key( expires ):
          self.block_name_expires[ expires ] = [name]
      else:
          self.block_name_expires[ expires ].append( name )

      # save diff
      self.save_name_diff( name, current_block_number, ['last_renewed', 'txid', 'vtxindex', 'op', 'opcode', 'consensus_hash'] )

      # apply diff
      self.name_records[name]['last_renewed'] = current_block_number
      self.name_records[name]['txid'] = txid
      self.name_records[name]['vtxindex'] = nameop['vtxindex']
      self.name_records[name]['op'] = op
      self.name_records[name]['opcode'] = nameop['opcode']
      if self.name_records.has_key('consensus_hash'):
          del self.name_records['consensus_hash']

      # propagate information back to virtualchian for snapshotting
      nameop.update( self.name_records[name] )
      return nameop


   def commit_update( self, nameop, current_block_number ):
      """
      Commit an update to a name's profile data.
      NOTE: nameop['name'] will have been defined by log_update.
      """

      name_consensus_hash = nameop['name_hash']
      txid = nameop['txid']

      try:
         name = nameop['name']
      except:
         log.error( "No 'name' in nameop: %s" % nameop )
         name = self.name_consensus_hash_name[ name_consensus_hash ]
         del self.name_consensus_hash_name[ name_consensus_hash ]

      # save diff
      self.save_name_diff( name, current_block_number, ['value_hash', 'txid', 'vtxindex', 'opcode', 'op', 'consensus_hash'] )

      # apply diff
      self.name_records[name]['value_hash'] = nameop['update_hash']
      self.name_records[name]['txid'] = txid
      self.name_records[name]['vtxindex'] = nameop['vtxindex']
      self.name_records[name]['opcode'] = nameop['opcode']
      self.name_records[name]['op'] = NAME_UPDATE

      # NOTE: obtained from log_update
      self.name_records[name]['consensus_hash'] = nameop['consensus_hash']

      # propagate information back to virtualchain for snapshotting
      nameop.update( self.name_records[name] )
      return nameop


   def commit_transfer( self, nameop, current_block_number ):
      """
      Commit a transfer--update the name record to indicate the recipient of the
      transaction as the new owner.
      """

      name = nameop['name']
      sender = nameop['sender']
      address = nameop.get('address', None)
      recipient = nameop['recipient']
      recipient_address = nameop['recipient_address']
      keep_data = nameop['keep_data']
      txid = nameop['txid']
      opcode = nameop['opcode']

      op = TRANSFER_KEEP_DATA
      if not keep_data:
          op = TRANSFER_REMOVE_DATA

      log.debug("Name '%s': %s >%s %s" % (name, sender, op, recipient))

      # save diff
      changed = ['sender', 'address', 'txid', 'vtxindex', 'opcode', 'op', 'sender_pubkey', 'consensus_hash']
      if not keep_data:
          changed.append( 'value_hash' )

      self.save_name_diff( name, current_block_number, changed )

      # apply diff
      self.name_records[name]['sender'] = recipient
      self.name_records[name]['sender_pubkey'] = None
      self.name_records[name]['address'] = recipient_address
      self.name_records[name]['txid'] = txid
      self.name_records[name]['vtxindex'] = nameop['vtxindex']
      self.name_records[name]['opcode'] = opcode
      self.name_records[name]['op'] = "%s%s" % (NAME_TRANSFER, op)

      if not keep_data:
         self.name_records[name]['value_hash'] = None

      # update secondary indexes
      if self.owner_names.has_key(sender) and name in self.owner_names[sender]:
          self.owner_names[sender].remove( name )
          if len(self.owner_names[sender]) == 0:
              del self.owner_names[sender]

      if self.address_names.has_key(address) and name in self.address_names[address]:
          self.address_names[address].remove( name )
          if len(self.address_names[address]) == 0:
              del self.address_names[address]

      self.owner_names[recipient].append( name )
      self.address_names[recipient_address].append( name )

      # propagate information back to virtualchain for snapshotting
      nameop.update( self.name_records[name] )
      return nameop


   def commit_revoke( self, nameop, current_block_number ):
      """
      Commit a revocation--blow away the name
      """

      name = nameop['name']
      txid = nameop['txid']
      sender = nameop['sender']
      address = nameop.get('address', None)
      opcode = nameop['opcode']
      op = NAME_REVOKE

      # save diff
      self.save_name_diff( name, current_block_number, ['revoked', 'txid', 'vtxindex', 'opcode', 'op', 'value_hash', 'consensus_hash'] )

      # apply diff
      self.name_records[name]['revoked'] = True
      self.name_records[name]['txid'] = txid
      self.name_records[name]['vtxindex'] = nameop['vtxindex']
      self.name_records[name]['opcode'] = opcode
      self.name_records[name]['op'] = op
      self.name_records[name]['value_hash'] = None

      # update secondary indexes
      if self.owner_names.has_key( sender ) and name in self.owner_names[sender]:
          self.owner_names[sender].remove( name )
          if len(self.owner_names[sender]) == 0:
              del self.owner_names[sender]

      if self.address_names.has_key( address ) and name in self.address_names[address]:
          self.address_names[address].remove( name )
          if len(self.address_names[address]) == 0:
              del self.address_names[address]

      # propagate information back to virtualchain for snapshotting
      nameop.update( self.name_records[name] )
      return nameop


   def commit_name_import( self, nameop, current_block_number ):
      """
      Commit a name import--register it and set the owner and update hash.
      """

      name = str(nameop['name'])
      recipient = str(nameop['recipient'])
      recipient_address = str(nameop['recipient_address'])
      importer = nameop['sender']
      if type(importer) == list:
          importer = importer[0]

      importer = str(importer)
      importer_address = str(nameop['address'])
      update_hash = str(nameop['update_hash'])

      name_without_namespace = get_name_from_fq_name( name )
      namespace_id = get_namespace_from_name( name )
      namespace = self.get_namespace_reveal( namespace_id )
      if namespace is None:
          raise Exception("Name without revealed namespace: '%s'" % name )

      old_recipient = None
      old_recipient_address = None

      if self.name_records.has_key( name ):

          name_rec_fields = [
            'value_hash',
            'sender',
            'sender_pubkey',
            'address',
            'txid',
            'vtxindex',
            'importer',
            'importer_address',
            'consensus_hash'
          ]

          # save diff
          self.save_name_diff( name, current_block_number, name_rec_fields )

          old_recipient = self.name_records[name]['sender']
          old_recipient_address = self.name_records[name]['address']

          # apply diff
          self.name_records[name]['value_hash'] = update_hash
          self.name_records[name]['sender'] = recipient                             # expected future sender
          self.name_records[name]['sender_pubkey'] = str(nameop['sender_pubkey'])   # NOTE: this is the *importer's* public key
          self.name_records[name]['address'] = recipient_address
          self.name_records[name]['txid'] = str(nameop['txid'])
          self.name_records[name]['vtxindex'] = nameop['vtxindex']
          self.name_records[name]['importer'] = importer
          self.name_records[name]['importer_address'] = str(nameop['address'])

      else:

          # nameop becomes a history snapshot
          nameop = self.sanitize_op( nameop )
          nameop['history_snapshot'] = True

          # fix up nameop to be the first history item
          nameop['value_hash'] = nameop['update_hash']
          del nameop['update_hash']

          nameop['importer'] = importer
          nameop['importer_address'] = importer_address

          name_record = {
            # snapshotted data
            'name': name,
            'value_hash': update_hash,
            'sender': recipient,                            # recipient is expected future sender
            'sender_pubkey': str(nameop['sender_pubkey']),  # NOTE: this is the *importer's* public key
            'address': recipient_address,

            'block_number': current_block_number,
            'preorder_block_number': current_block_number,  # NOTE: an import is considered to be an atomic preorder/register
            'first_registered': current_block_number,
            'last_renewed': current_block_number,
            'revoked': False,

            'op': NAME_IMPORT,
            'txid': str(nameop['txid']),
            'vtxindex': str(nameop['vtxindex']),
            'op_fee': price_name( name_without_namespace, namespace ),

            'importer': importer,
            'importer_address': importer_address,

            # ancillary data
            'history': {

                 # history for this nameop starts at this block number
                 current_block_number: [copy.deepcopy( nameop )]
            },

            'opcode': str(nameop['opcode'])
          }

          self.name_records[ name ] = name_record

      # update secondary indexes...
      self.owner_names[ recipient ].append( str(name) )
      if old_recipient is not None:
          if self.owner_names.has_key( old_recipient ) and name in self.owner_names[old_recipient]:
              self.owner_names[ old_recipient ].remove( name )
              if len(self.owner_names[old_recipient]) == 0:
                  del self.owner_names[old_recipient]

      self.address_names[ recipient_address ].append( str(name) )
      if old_recipient_address is not None:
          if self.address_names.has_key( old_recipient_address ) and name in self.address_names[old_recipient_address]:
              self.address_names[ old_recipient_address ].remove( name )
              if len(self.address_names[old_recipient_address]) == 0:
                  del self.address_names[old_recipient_address]

      self.hash_names[ hash256_trunc128( name ) ] = name

      expires = current_block_number + namespace['lifetime']
      if not self.block_name_expires.has_key( expires ):
          self.block_name_expires[ expires ] = [name]
      else:
          self.block_name_expires[ expires ].append( name )

      # propagate information back to virtualchain for snapshotting
      nameop.update( self.name_records[name] )
      return nameop


   def commit_namespace_preorder( self, nameop, block_number ):
      """
      Commit a NAMESPACE_PREORER, so we can subsequently accept
      a namespace reveal from the sender.

      The namespace will be preordered, but not yet defined
      (i.e. we know it exists, but we don't know its parameters).
      """

      namespace_id_hash = nameop['namespace_id_hash']
      sender = nameop['sender']
      nameop['history'] = {}
      nameop['block_number'] = block_number
      nameop['op'] = NAMESPACE_PREORDER

      # this namespace is preordered, but not yet defined
      # store non-virtualchian fields
      self.namespace_preorders[ namespace_id_hash ] = self.sanitize_op( nameop )

      # propagate information back to virtualchain for snapshotting
      return nameop


   def commit_namespace_reveal( self, nameop, block_number ):
      """
      Commit a NAMESPACE_REVEAL nameop, so we can subsequently accept
      a sequence of preordered names from the sender.

      The namespace will be revealed, but not yet ready
      (i.e. we know its parameters, but only the sender can operate on its names)

      The namespace will be owned by the recipient, not the sender.
      """

      # collision?
      if nameop.get('collision'):
          return False

      namespace_id = nameop['namespace_id']
      namespace_id_hash = nameop['namespace_id_hash']

      self.namespace_reveals[ namespace_id ] = self.sanitize_op( nameop )
      self.namespace_id_to_hash[ nameop['namespace_id'] ] = namespace_id_hash

      if namespace_id_hash in self.namespace_preorders:
          # preserve the old namespace preorder
          old_preorder = self.namespace_preorders[namespace_id_hash]
          del old_preorder['history']

          # old preorder becomes a history snapshot
          old_preorder = self.sanitize_op( old_preorder )
          old_preorder['history_snapshot'] = True

          self.namespace_reveals[ namespace_id ]['history'] = {
             block_number: [old_preorder]
          }

          self.namespace_reveals[ namespace_id ]['block_number'] = old_preorder['block_number']
          self.namespace_reveals[ namespace_id ]['reveal_block'] = block_number
          self.namespace_reveals[ namespace_id ]['op'] = NAMESPACE_REVEAL

          del self.namespace_preorders[namespace_id_hash]

          # propagate information back to virtualchain for snapshotting
          nameop.update( self.namespace_reveals[ namespace_id ] )
          return nameop

      else:
          log.error("BUG: no namespace preorder for '%s' (hash '%s')" % (namespace_id, namespace_id_hash))
          raise Exception("BUG: no namespace preorder for '%s' (hash '%s')" % (namespace_id, namespace_id_hash))


   def commit_namespace_ready( self, nameop, block_number ):
      """
      Mark a namespace as ready for external name registrations.
      The given nameop is a NAMESPACE_READY nameop.
      """

      namespace_id = nameop['namespace_id']
      sender = nameop['sender']

      namespace = self.namespace_reveals[ namespace_id ]

      # save to history (duplicate it)
      namespace_reveal = copy.deepcopy( namespace )
      history = namespace_reveal['history']
      del namespace_reveal['history']

      # namespace reveal becomes history snapshot
      namespace_reveal = self.sanitize_op( namespace_reveal )
      namespace_reveal['history_snapshot'] = True

      if history.has_key( block_number ):
          history[block_number].append( namespace_reveal )
      else:
          history[block_number] = [namespace_reveal]

      namespace['history'] = history
      namespace['opcode'] = nameop['opcode']
      namespace['op'] = NAMESPACE_READY
      namespace['ready_block'] = block_number
      namespace['sender'] = sender
      namespace['txid'] = nameop['txid']
      namespace['vtxindex'] = nameop['vtxindex']

      self.commit_remove_namespace_import( namespace_id, namespace['namespace_id_hash'] )

      # namespace is ready!
      self.namespaces[ namespace_id ] = namespace

      # propagate information back to virtualchain for snapshotting
      nameop.update( self.namespaces[ namespace_id ] )
      return nameop


   def log_prescan_find_collisions( self, pending_ops, all_nameops, block_id ):
      """
      Do a pass over all operations in this block to find colliding operations:
      * check all 'NAME_REGISTRATION' operations, and if
      two or more for a given name are valid, then mark all
      the NAME_REGISTRATIONs for that name as invalid.
      * check all 'NAMESPACE_REVEAL' operations, and if
      two or more for a given namespace are valid, then mark
      all NAMESPACE_REVEALs for that namespace as invald.

      Return ([list of colliding names], [list of colliding namespace_ids])
      """

      if not self.prescanned:

          valid_registrations = {}  # map name to indexes in all_nameops
          valid_namespaces = {}

          # find all name collisions
          for i in xrange(0, len(all_nameops)):
              nameop = all_nameops[i]
              if nameop['opcode'] != 'NAME_REGISTRATION':
                  continue

              valid = self.log_registration( pending_ops, nameop, block_id )
              if valid:
                  if nameop['name'] in valid_registrations.keys():

                      # mark all as collided
                      valid_registrations[nameop['name']].append( i )

                  else:

                      # valid, but not yet collided
                      valid_registrations[nameop['name']] = [i]


          # find all namespace collisions
          for i in xrange(0, len(all_nameops)):
              nameop = all_nameops[i]
              if nameop['opcode'] != 'NAMESPACE_REVEAL':
                  continue

              valid = self.log_namespace_reveal( pending_ops, nameop, block_id )
              if valid:
                  if nameop['namespace_id'] in valid_namespaces.keys():

                      # mark all as collided
                      valid_namespaces[nameop['namespace_id']].append( i )

                  else:

                      # valid, not yet collided
                      valid_namespaces[nameop['namespace_id']] = [i]

          colliding_names = []
          colliding_namespaces = []

          for name, namelist in valid_registrations.items():
              if len(namelist) > 1:
                  # all collided
                  for i in namelist:
                      colliding_names.append( all_nameops[i]['name'] )


          for namespace_id, namespacelist in valid_namespaces.items():
              if len(namespacelist) > 1:
                  # all collided
                  for i in namespacelist:
                      colliding_namespaces.append( all_nameops[i]['namespace_id'] )


          self.prescanned = True
          self.colliding_names = colliding_names
          self.colliding_namespaces = colliding_namespaces

      return (self.colliding_names, self.colliding_namespaces)


   def log_prescan_reset( self ):
      """
      Reset the db for scanning.
      """
      self.prescanned = False
      self.colliding_names = None
      self.colliding_namespaces = None


   def log_announce( self, pending_nameops, nameop, block_id ):
      """
      Log an announcement from the blockstore developers.
      Return (True, blockchain_id) if it is well-formed, and came from one of the blockchain IDs
      listed in the config file.
      Return (False, None) otherwise.
      """

      sender = nameop['sender']
      sending_blockchain_id = nameop['sender']
      found = False

      for blockchain_id in self.announce_ids:
          blockchain_namerec = self.get_name( blockchain_id )
          if blockchain_namerec is None:
              # this name doesn't exist yet, or is expired or revoked
              continue

          if str(sender) == str(blockchain_namerec['sender']):
              # yup!
              found = True
              sending_blockchain_id = blockchain_id
              break

      if not found:
          log.debug("Announcement not sent from our whitelist of blockchain IDs")
          return (False, None)

      return (True, str(sending_blockchain_id))


   def log_preorder( self, pending_nameops, nameop, block_id ):
      """
      Log a preorder of a name at a particular block number.

      NOTE: these *can't* be incorporated into namespace-imports,
      since we have no way of knowning which namespace the
      nameop belongs to (it is blinded until registration).
      But that's okay--we don't need to preorder names during
      a namespace import, because we will only accept names
      sent from the importer until the NAMESPACE_REVEAL operation
      is sent.

      Return True if accepted
      Return False if not.
      """

      preorder_name_hash = nameop['preorder_name_hash']
      consensus_hash = nameop['consensus_hash']
      sender = nameop['sender']

      # must be unique in this block
      for pending_preorders in pending_nameops[ NAME_PREORDER ]:
         if pending_preorders['preorder_name_hash'] == preorder_name_hash:
            log.debug("Name hash '%s' is already preordered" % preorder_name_hash)
            return False

      # must be unique across all pending preorders
      if not self.is_new_preorder( preorder_name_hash ):
          log.debug("Name hash '%s' is already preordered" % preorder_name_hash )
          return False

      # must have a valid consensus hash
      if not self.is_consensus_hash_valid( block_id, consensus_hash ):
          log.debug("Invalid consensus hash '%s'" % consensus_hash )
          return False

      # sender must be beneath quota
      if len( self.owner_names.get( sender, [] ) ) >= MAX_NAMES_PER_SENDER:
          log.debug("Sender '%s' exceeded name quota of %s" % (sender, MAX_NAMES_PER_SENDER ))
          return False

      # burn fee must be present
      if not 'op_fee' in nameop:
          log.debug("Missing preorder fee")
          return False

      return True


   def log_registration( self, pending_nameops, nameop, block_id ):
      """
      Progess a registration nameop.
      * the name must be well-formed
      * the namespace must be ready
      * the name does not collide
      * either the name was preordered by the same sender, or the name exists and is owned by this sender (the name cannot be registered and owned by someone else)
      * the mining fee must be high enough.

      NAME_REGISTRATION is not allowed during a namespace import, so the namespace must be ready.

      NOTE: it is *imperative* that this method does *not* modify nameop.

      Return True if accepted.
      Return False if not.
      """

      name = nameop['name']
      sender = nameop['sender']

      # address mixed into the preorder
      register_addr = nameop.get('recipient_address', None)
      if register_addr is None:
          log.debug("No registration address given")
          return False

      recipient = nameop.get('recipient', None)
      if recipient is None:
          log.debug("No recipient p2pkh given")
          return False

      name_fee = None
      namespace = None

      # name must be well-formed
      if not is_b40( name ) or "+" in name or name.count(".") > 1:
          log.debug("Malformed name '%s': non-base-38 characters" % name)
          return False

      # name must not be revoked
      if self.is_name_revoked( name ):
          log.debug("Name '%s' is revoked" % name)
          return False

      namespace_id = get_namespace_from_name( name )

      # namespace must exist and be ready
      if not self.is_namespace_ready( namespace_id ):
          log.debug("Namespace '%s' is not ready" % namespace_id)
          return False

      # get namespace...
      namespace = self.get_namespace( namespace_id )

      # preordered?
      name_preorder = self.get_name_preorder( name, sender, register_addr )
      if name_preorder is not None:

          # name must be preordered by the same sender
          if name_preorder['sender'] != sender:
             log.debug("Name '%s' was not preordered by %s" % (name, sender))
             return False

          # name can't be registered if it was reordered before its namespace was ready
          if not namespace.has_key('ready_block') or name_preorder['block_number'] < namespace['ready_block']:
             log.debug("Name '%s' preordered before namespace '%s' was ready" % (name, namespace_id))
             return False

          # fee was included in the preorder
          if not 'op_fee' in name_preorder:
             log.debug("Name '%s' preorder did not pay the fee" % (name))
             return False

          name_fee = name_preorder['op_fee']


      elif self.is_name_registered( name ):

          # name must be owned by the recipient already
          if not self.is_name_owner( name, recipient ):
              log.debug("Renew: Name '%s' not owned by recipient %s" % (name, recipient))
              return False

          # name must be owned by the sender
          if not self.is_name_owner( name, sender ):
              log.debug("Renew: Name '%s' not owned by sender %s" % (name, sender))
              return False

          # fee borne by the renewal
          if not 'op_fee' in nameop:
              log.debug("Name '%s' renewal did not pay the fee" % (name))
              return False

          name_fee = nameop['op_fee']

      else:

          # does not exist and not preordered
          log.debug("Name '%s' does not exist, or is not preordered by %s" % (name, sender))
          return False

      # cannot exceed quota
      if len( self.owner_names.get( recipient, [] ) ) >= MAX_NAMES_PER_SENDER:
          log.debug("Recipient '%s' has exceeded quota" % recipient)
          return False

      # check name fee
      name_without_namespace = get_name_from_fq_name( name )

      # fee must be high enough
      if name_fee < price_name( name_without_namespace, namespace ):
          log.debug("Name '%s' costs %s, but paid %s" % (name, price_name( name_without_namespace, namespace ), name_fee ))
          return False

      # regster/renewal
      return True


   def log_update(self, pending_nameops, nameop, block_id ):
      """
      Log an update to a name's associated data.
      Use the nameop's 128-bit name hash to find the name itself.

      NAME_UPDATE isn't allowed during an import, so the name's namespace must be ready.

      Return True if accepted
      Return False if not.
      """

      name_consensus_hash = nameop['name_hash']
      sender = nameop['sender']

      # deny updates if we exceed quota--the only legal operations are to revoke or transfer.
      names = self.owner_names.get( sender, [] )
      if len(names) > MAX_NAMES_PER_SENDER:
          log.debug("Sender '%s' has exceeded quota: only transfers or revokes are allowed" % (sender))
          return False

      name, consensus_hash = self.get_name_from_name_consensus_hash( name_consensus_hash, sender, block_id )

      # name must exist
      if name is None or consensus_hash is None:
         log.debug("Unable to resolve name consensus hash '%s' to a name owned by '%s'" % (name_consensus_hash, sender))
         # nothing to do--write is stale or on a fork
         return False

      namespace_id = get_namespace_from_name( name )

      if self.name_records.get(name, None) is None:
         log.debug("Name '%s' does not exist" % name)
         return False

      # namespace must be ready
      if not self.is_namespace_ready( namespace_id ):
         # non-existent namespace
         log.debug("Namespace '%s' is not ready" % (namespace_id))
         return False

      # name must not be revoked
      if self.is_name_revoked( name ):
          log.debug("Name '%s' is revoked" % name)
          return False

      # name must not be expired
      if self.is_name_expired( name, self.lastblock ):
          log.debug("Name '%s' is expired" % name)
          return False

      # the name must be registered
      if not self.is_name_registered( name ):
          # doesn't exist
          log.debug("Name '%s' is not registered" % name )
          return False

      # the name must be owned by the same person who sent this nameop
      if not self.is_name_owner( name, sender ):
          # wrong owner
          log.debug("Name '%s' is not owned by '%s'" % (name, sender))
          return False

      # remember the name and consensus hash, so we don't have to re-calculate it...
      self.name_consensus_hash_name[ name_consensus_hash ] = name
      nameop['name'] = name
      nameop['consensus_hash'] = consensus_hash

      return True


   def log_transfer( self, pending_nameops, nameop, block_id ):
      """
      Log a name's transferrance to another private key.
      The name must exist, not be revoked, and be owned by the sender.
      The recipient must not exceed the maximum allowed number of names per keypair,
      and the recipient cannot own an equivalent name.

      NAME_TRANSFER isn't allowed during an import, so the name's namespace must be ready.

      Return True if accepted
      Return False if not
      """

      name_hash = nameop['name_hash']
      name = self.hash_names.get( name_hash )

      consensus_hash = nameop['consensus_hash']
      sender = nameop['sender']
      recipient = nameop['recipient']

      if name is None:
         # invalid
         log.debug("No name found for '%s'" % name_hash )
         return False

      namespace_id = get_namespace_from_name( name )

      if self.name_records.get( name, None ) is None:
          log.debug("Name '%s' does not exist" % name)
          return False

      # namespace must be ready
      if not self.is_namespace_ready( namespace_id ):
         # non-existent namespace
         log.debug("Namespace '%s' is not ready" % (namespace_id))
         return False

      # name must not be revoked
      if self.is_name_revoked( name ):
          log.debug("Name '%s' is revoked" % name)
          return False

      # name must not be expired
      if self.is_name_expired( name, self.lastblock ):
          log.debug("Name '%s' is expired" % name)
          return False

      if not self.is_consensus_hash_valid( block_id, consensus_hash ):
         # invalid concensus hash
         log.debug("Invalid consensus hash '%s'" % consensus_hash )
         return False

      if sender == recipient:
         # nonsensical transfer
         log.debug("Sender is the same as the Recipient (%s)" % sender )
         return False

      if not self.is_name_registered( name ):
         # name is not registered
         log.debug("Name '%s' is not registered" % name)
         return False

      if not self.is_name_owner( name, sender ):
         # sender doesn't own the name
         log.debug("Name '%s' is not owned by %s (but %s)" % (name, sender, self.get_name_owner(name)))
         return False

      if recipient in self.owner_names.keys():

         # recipient already has names...
         recipient_names = self.owner_names[ recipient ]
         if name in recipient_names:
            # recipient already owns the name
            log.debug("Recipient %s already owns '%s'" % (recipient, name))
            return False

         if len(recipient_names) >= MAX_NAMES_PER_SENDER:
            # transfer would exceed quota
            log.debug("Recipient %s has exceeded name quota" % recipient)
            return False

      # remember the name, so we don't have to look it up later
      nameop['name'] = name
      return True


   def log_revoke( self, pending_nameops, nameop, block_id ):
      """
      Revoke a name--make it available for registration.
      * it must be well-formed
      * its namespace must be ready.
      * the name must be registered
      * it must be sent by the name owner

      NAME_TRANSFER isn't allowed during an import, so the name's namespace must be ready.

      Return True if accepted
      Return False if not
      """

      name = nameop['name']
      sender = nameop['sender']
      namespace_id = get_namespace_from_name( name )

      # name must be well-formed
      if not is_b40( name ) or "+" in name or name.count(".") > 1:
          log.debug("Malformed name '%s': non-base-38 characters" % name)
          return False

      # name must exist
      if self.name_records.get( name, None ) is None:
          log.debug("Name '%s' does not exist" % name)
          return False

      # namespace must be ready
      if not self.is_namespace_ready( namespace_id ):
         log.debug("Namespace '%s' is not ready" % namespace_id )
         return False

      # name must not be revoked
      if self.is_name_revoked( name ):
          log.debug("Name '%s' is revoked" % name)
          return False

      # name must not be expired
      if self.is_name_expired( name, self.lastblock ):
          log.debug("Name '%s' is expired" % name)
          return False

      # the name must be registered
      if not self.is_name_registered( name ):
         log.debug("Name '%s' is not registered" % name )
         return False

      # the sender must own this name
      if not self.is_name_owner( name, sender ):
         log.debug("Name '%s' is not owned by %s" % (name, sender))
         return False

      return True


   def log_name_import( self, pending_nameops, nameop, block_id ):
      """
      Given a NAME_IMPORT nameop, see if we can import it.
      * the name must be well-formed
      * the namespace must be revealed, but not ready
      * the name cannot have been imported yet
      * the sender must be the same as the namespace's sender

      Return True if accepted
      Return False if not
      """

      name = str(nameop['name'])
      sender = str(nameop['sender'])
      sender_pubkey = None

      if not nameop.has_key('sender_pubkey'):
         log.debug("Name import requires a sender_pubkey (i.e. use of a p2pkh transaction)")
         return False

      # name must be well-formed
      if not is_b40( name ) or "+" in name or name.count(".") > 1:
          log.debug("Malformed name '%s': non-base-38 characters" % name)
          return False

      namespace_id = get_namespace_from_name( name )

      # namespace must be revealed, but not ready
      if not self.is_namespace_revealed( namespace_id ):
          log.debug("Namespace '%s' is not revealed" % namespace_id )
          return False

      namespace = self.get_namespace_reveal( namespace_id )

      # sender p2pkh script must use a public key derived from the namespace revealer's public key
      sender_pubkey_hex = str(nameop['sender_pubkey'])
      sender_pubkey = pybitcoin.BitcoinPublicKey( str(sender_pubkey_hex) )
      sender_address = sender_pubkey.address()

      import_addresses = self.import_addresses.get(namespace_id, None)

      if import_addresses is None:

          # the first name imported must be the revealer's address
          if sender_address != namespace['recipient_address']:
              log.debug("First NAME_IMPORT must come from the namespace revealer's address")
              return False

          # need to generate a keyring from the revealer's public key
          log.debug("Generating %s-key keychain for '%s'" % (NAME_IMPORT_KEYRING_SIZE, namespace_id))
          import_addresses = BlockstoreDB.build_import_keychain( sender_pubkey_hex )
          self.import_addresses[namespace_id] = import_addresses

      # sender must be the same as the the person who revealed the namespace
      # (i.e. sender's address must be from one of the valid import addresses)
      if sender_address not in import_addresses:
          log.debug("Sender address '%s' is not in the import keychain" % (sender_address))
          return False

      # we can overwrite, but emit a warning
      if self.is_name_registered( name ):
          log.warning("Overwriting already-imported name '%s'" % name)

      # good!
      return True


   def log_namespace_preorder( self, pending_nameops, nameop, block_id ):
      """
      Given a NAMESPACE_PREORDER nameop, see if we can preorder it.
      It must be unqiue.

      Return True if accepted.
      Return False if not.
      """

      namespace_id_hash = nameop['namespace_id_hash']
      consensus_hash = nameop['consensus_hash']

      # namespace must not exist
      for pending_namespace_preorder in pending_nameops[ NAMESPACE_PREORDER ]:
         if pending_namespace_preorder['namespace_id_hash'] == namespace_id_hash:
            log.debug("Namespace hash '%s' is already preordered" % namespace_id_hash)
            return False

      # cannot be preordered already
      if not self.is_new_namespace_preorder( namespace_id_hash ):
          log.debug("Namespace preorder '%s' already in use" % namespace_id_hash)
          return False

      # has to have a reasonable consensus hash
      if not self.is_consensus_hash_valid( block_id, consensus_hash ):

          valid_consensus_hashes = self.get_valid_consensus_hashes( block_id )
          log.debug("Invalid consensus hash '%s': expected any of %s" % (consensus_hash, ",".join( valid_consensus_hashes )) )
          return False

      # has to have paid a fee
      if not 'op_fee' in nameop:
          log.debug("Missing namespace preorder fee")
          return False

      return True


   def log_namespace_reveal( self, pending_nameops, nameop, block_id ):
      """
      Log a NAMESPACE_REVEAL operation to the name database.
      It is only valid if it is the first such operation
      for this namespace, and if it was sent by the same
      sender who sent the NAMESPACE_PREORDER.

      It is *imperative* that this method not modify nameop

      Return True if accepted
      Return False if not
      """

      namespace_id = nameop['namespace_id']
      namespace_id_hash = nameop['namespace_id_hash']
      sender = nameop['sender']
      namespace_preorder = None

      if not nameop.has_key('sender_pubkey'):
         log.debug("Namespace reveal requires a sender_pubkey (i.e. a p2pkh transaction)")
         return False

      if not nameop.has_key('recipient'):
         log.debug("No recipient p2kh for namespace '%s'" % namespace_id)
         return False

      if not nameop.has_key('recipient_address'):
         log.debug("No recipient_address for namespace '%s'" % namespace_id)
         return False

      # well-formed?
      if not is_b40( namespace_id ) or "+" in namespace_id or namespace_id.count(".") > 0:
         log.debug("Malformed namespace ID '%s': non-base-38 characters")
         return False

      # can't be revealed already
      if self.is_namespace_revealed( namespace_id ):
         # this namespace was already revealed
         log.debug("Namespace '%s' is already revealed" % namespace_id )
         return False

      # can't be ready already
      if self.is_namespace_ready( namespace_id ):
         # this namespace already exists (i.e. was already begun)
         log.debug("Namespace '%s' is already registered" % namespace_id )
         return False

      # must currently be preordered
      namespace_preorder = self.get_namespace_preorder( namespace_id_hash )
      if namespace_preorder is None:
         # not preordered
         log.debug("Namespace '%s' is not preordered" % namespace_id )
         return False

      # must be sent by the same principal who preordered it
      if namespace_preorder['sender'] != sender:
         # not sent by the preorderer
         log.debug("Namespace '%s' is not preordered by '%s'" % (namespace_id, sender))

      # must be a version we support
      if int(nameop['version']) != BLOCKSTORE_VERSION:
         log.debug("Namespace '%s' requires version %s, but this blockstore is version %s" % (namespace_id, nameop['version'], BLOCKSTORE_VERSION))
         return False

      # check fee...
      if not 'op_fee' in namespace_preorder:
         log.debug("Namespace '%s' preorder did not pay the fee" % (namespace_id))
         return False

      namespace_fee = namespace_preorder['op_fee']

      # must have paid enough
      if namespace_fee < price_namespace( namespace_id ):
         # not enough money
         log.debug("Namespace '%s' costs %s, but sender paid %s" % (namespace_id, price_namespace(namespace_id), namespace_fee ))
         return False

      # can begin import
      return True


   def log_namespace_ready( self, pending_nameops, nameop, block_id ):
      """
      Log a NAMESPACE_READY operation to the name database.
      It is only valid if it has been imported by the same sender as
      the corresponding NAMESPACE_REVEAL, and the namespace is still
      in the process of being imported.
      """

      namespace_id = nameop['namespace_id']
      sender = nameop['sender']

      # must have been revealed
      if not self.is_namespace_revealed( namespace_id ):
         log.debug("Namespace '%s' is not revealed" % namespace_id )
         return False

      # must have been sent by the same person who revealed it
      revealed_namespace = self.get_namespace_reveal( namespace_id )
      if revealed_namespace['recipient'] != sender:
         log.debug("Namespace '%s' is not owned by '%s' (but by %s)" % (namespace_id, sender, revealed_namespace['recipient']))
         return False

      # can't be ready yet
      if self.is_namespace_ready( namespace_id ):
         # namespace already exists
         log.debug("Namespace '%s' is already registered" % namespace_id )
         return False

      # can commit imported nameops
      return True


def get_namespace_from_name( name ):
   """
   Get a fully-qualified name's namespace, if it has one.
   It's the sequence of characters after the last "." in the name.
   If there is no "." in the name, then it belongs to the null
   namespace (i.e. the empty string will be returned)
   """
   if "." not in name:
      # empty namespace
      return ""

   return name.split(".")[-1]


def get_name_from_fq_name( name ):
   """
   Given a fully-qualified name, get the name part.
   It's the sequence of characters before the last "." in the name.

   Return None if malformed
   """
   if "." not in name:
      # malformed
      return None

   return name.split(".")[0]


def price_name( name, namespace ):
   """
   Calculate the price of a name (without its namespace ID), given the
   namespace parameters.

   The minimum price is 1 satoshi
   """

   base = namespace['base']
   coeff = namespace['coeff']
   buckets = namespace['buckets']

   bucket_exponent = 0
   discount = 1.0

   if len(name) < len(buckets):
       bucket_exponent = buckets[len(name)-1]
   else:
       bucket_exponent = buckets[-1]

   # no vowel discount?
   if sum( [name.lower().count(v) for v in ["a", "e", "i", "o", "u", "y"]] ) == 0:
       # no vowels!
       discount = max( discount, namespace['no_vowel_discount'] )

   # non-alpha discount?
   if sum( [name.lower().count(v) for v in ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "-", "_"]] ) > 0:
       # non-alpha!
       discount = max( discount, namespace['nonalpha_discount'] )

   price = (float(coeff * (base ** bucket_exponent)) / float(discount)) * NAME_COST_UNIT
   if price < NAME_COST_UNIT:
       price = NAME_COST_UNIT

   return price


def price_namespace( namespace_id ):
   """
   Calculate the cost of a namespace.
   """

   testset = default_blockstore_opts( virtualchain.get_config_filename() )['testset']

   if len(namespace_id) == 1:
       if testset:
           return TESTSET_NAMESPACE_1_CHAR_COST
       else:
           return NAMESPACE_1_CHAR_COST

   elif len(namespace_id) in [2, 3]:
       if testset:
           return TESTSET_NAMESPACE_23_CHAR_COST
       else:
           return NAMESPACE_23_CHAR_COST

   elif len(namespace_id) in [4, 5, 6, 7]:
       if testset:
           return TESTSET_NAMESPACE_4567_CHAR_COST
       else:
           return NAMESPACE_4567_CHAR_COST

   else:
       if testset:
           return TESTSET_NAMESPACE_8UP_CHAR_COST
       else:
           return NAMESPACE_8UP_CHAR_COST

