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

import json
import traceback
import binascii
import hashlib 
import math

from collections import defaultdict
from ..config import NAMESPACE_DEFAULT, MIN_OP_LENGTHS, OPCODES, MAGIC_BYTES, TESTSET, MAX_NAMES_PER_SENDER, EXPIRATION_PERIOD, NAME_PREORDER, NAMESPACE_PREORDER, NAME_REGISTRATION, NAME_UPDATE
from ..operations import build_namespace_define
from ..hashing import *

import virtualchain
log = virtualchain.session.log

class BlockstoreDBIterator(object):
   """
   Iterator class for BlockstoreDB.  Iterates over all records 
   for which we want to generate a consensus hash.
   
   Iterates over serialized name records in lexical order, 
   and then serialized namespaces in lexical order,
   and then serialized pending namespace imports in *import* order.
  
   A serialized name record incorporates the name, the owner's
   script_pubkey, and the profile hash.
   
   A serialized namespace record incorporates the namespace ID,
   its rules, and creator's script_pubkey.
   
   A serialized pending namespace (i.e. one that has been 
   defined but not begun) includes hash( namespace_id, sender_script_pubkey )
   and its rules.
   
   A serialized pending import includes the hash of the namespace ID and 
   the sender's script_pubkey, as well as the hash over the sequence 
   of import operations (including the NAMESPACE_PREORDER and NAMESPACE_DEFINE,
   if given), such that each operation is serialized in a stable manner 
   (e.g. in key1:value1, key2:value2,... strings that have been stable-sorted).
   """
   
   def __init__( self, blockstore_db ):
      self.db = blockstore_db 
      
      self.sorted_names = None
      self.next_name = 0
      
      self.sorted_namespaces = None
      self.next_namespace = 0
      
      self.sorted_importing_namespaces = None
      self.next_import_namespace = 0
      
   def __iter__(self):
      return self 
   
   
   def serialize_name_record( self, name, name_record ):
      """
      Serialize a name record:
      make it sortable on the name (names are unique, so this imposes 
      a total order on the set of serialized name records), and include the 
      owner's script_pubkey, profile hash, and revocation status.
      """
      
      profile_hash = name_record.get('value_hash', "")
      revoked_string = ""
      
      if profile_hash is None:
         profile_hash = ""
      
      if name_record['revoked']:
         revoked_string = "-revoked"
         
      name_string = (name + name_record['sender'] + profile_hash + revoked_string).encode('utf8')
      
      return name_string
   
   
   def serialize_namespace_record( self, namespace_id, namespace_record ):
      """
      Serialize a namespace record:
      make it sortable on the namespace ID (namespace IDs are unique, so 
      this imposes a total order on the set of serialized name records), and
      include the owner's script_pubkey and rules
      """
      
      rules_string = build_namespace_define( "", namespace_record['lifetime'], namespace_record['cost'], namespace_record['price_decay'], testset=TESTSET )
      sender = namespace_record['sender']
      
      if sender is None:
         sender = ""
         
      if namespace_id is None:
         namespace_id = ""
         
      try:
         namespace_string = (namespace_id + rules_string + sender).encode('utf8')
      except Exception, e:
         raise e
      
      return namespace_string 
   
   
   def hash_namespace_records( self, namespace_imports ):
      """
      Stable serialization of a namespace import record:
      concatenate key:value pairs in order by key, and 
      hash them in order of import.
      
      Return the hexstring hash (sha256)
      """
      
      h = hashlib.sha256()
      
      for namespace_import_record in namespace_imports:
         
         serialized_pairs = []
         sorted_keys = sorted( namespace_import_record.keys() )
         
         for k in sorted_keys:
            serialized_pairs.append( (k + ":" + str(namespace_import_record[k])).encode('utf8') )
         
         serialized_record = ",".join( serialized_pairs )
         h.update( serialized_record )
      
      return h.hexdigest()
   
   
   def serialize_importing_namespace( self, namespace_id_hash, namespace_imports ):
      """
      Serialize an importing namespace:
      * make it sortable on namespace_id_hash (globally unique --> total ordering)
      * include hash over sequence of operations, ordered in sequence
      * serialize each operation by concatenating key:value, ordered by key
      """
      
      namespace_imports_hash = self.hash_namespace_records( namespace_imports )
      return (namespace_id_hash + namespace_imports_hash).encode('utf8')
      
   
   def next_name_record( self ):
      """
      Get the next serialized name record.
      Return None if we're out of names 
      """
      
      if self.sorted_names is None:
         # have not done names yet 
         self.sorted_names = sorted( self.db.get_all_names() )
         self.next_name = 0
      
      if self.next_name < len(self.sorted_names):
         
         name = self.sorted_names[ self.next_name ]
         self.next_name += 1
         
         serialized_name_record = self.serialize_name_record( name, self.db.get_name( name ) )
         
         log.debug("   Serialized name record: '%s' (%s)" % (serialized_name_record, name) )
         return serialized_name_record
      
      # out of names 
      self.sorted_names = []
      return None
   
   
   def next_namespace_record( self ):
      """
      Get the next serialized namespace record.
      Return None if we're out of namespaces.
      """
      
      if self.sorted_namespaces is None:
         # have not done namespaces yet 
         self.sorted_namespaces = sorted( self.db.get_all_namespaces() )
         self.next_namespace = 0
      
      if self.next_namespace < len(self.sorted_namespaces):
         
         namespace_id = self.sorted_namespaces[ self.next_namespace ]
         self.next_namespace += 1
         
         serialized_namespace_record = self.serialize_namespace_record( namespace_id, self.db.get_namespace( namespace_id ) )
         
         log.debug("   Serialized namespace record: '%s' (%s)" % (serialized_namespace_record, namespace_id) )
         return serialized_namespace_record
      
      # out of namespaces 
      self.sorted_namespaces = []
      return None 
   
   
   def next_import_namespace_record( self ):
      """
      Get the next serialized namespace import record.
      Return None if we're out of importing namespaces.
      """
      
      if self.sorted_importing_namespaces is None:
         # have not done importing namespaces yet 
         self.sorted_importing_namespaces = sorted( self.db.get_all_importing_namespaces() )
         self.next_import_namespace = 0
         
      if self.next_import_namespace < len(self.sorted_importing_namespaces):
         
         namespace_id_hash = self.sorted_importing_namespaces[ self.next_import_namespace ]
         self.next_import_namespace += 1
         
         serialized_importing_namespace = self.serialize_importing_namespace( namespace_id_hash, self.db.get_importing_namespace_raw( namespace_id_hash ) )
         
         log.debug("   Serialized import record: '%s' (%s)" % (serialized_importing_namespace, namespace_id_hash) )
         return serialized_importing_namespace
      
      # out of importing namespaces 
      self.sorted_importing_namespaces = []
      return None 
      
      
   def next(self):
      """
      Iterate over the *serialized* names, namespaces, and importing namespaces.
      Do so in a stable order.
      """
      
      serialized_record = None 
      
      serialized_record = self.next_name_record()
      if serialized_record is not None:
         return serialized_record
      
      serialized_record = self.next_namespace_record()
      if serialized_record is not None:
         return serialized_record
      
      serialized_record = self.next_import_namespace_record()
      if serialized_record is not None:
         return serialized_record
      
      # done!
      raise StopIteration()
   
   

class BlockstoreDB( virtualchain.StateEngine ):
   """
   State engine implementatoin for blockstore.
   Tracks the set of names and namespaces, as well as the 
   latest hash of their profile data (which in turn resolves 
   to JSON in ancillary storage that contains the pointers 
   to their mutable data).
   """
   
   def __init__(self, db_filename ):
      """
      Construct a blockstore state engine, optionally from locally-cached 
      blockstore database state.
      """
      
      import virtualchain_hooks
      
      super( BlockstoreDB, self ).__init__( MAGIC_BYTES, OPCODES, impl=virtualchain_hooks, state=self )
      
      self.db_filename = db_filename 
      
      self.name_records = {}                  # map name.ns_id to dict of
                                              # { "owner": hex string of script_pubkey,
                                              #   "first_registered": block when registered,
                                              #   "last_renewed": block when last renewed,
                                              #   "address": bitcoin public key of the sender
                                              #   "value_hash": hex string of hash of profile JSON
                                              #   "revoked": True if this name was revoked; False if not}

      self.owner_names = defaultdict(list)    # map sender_script_pubkey hex string to list of names owned by the principal it represents
      self.hash_names = {}                    # map hex_hash160(name) to name
      self.preorders = {}                     # map preorder name.ns_id+script_pubkey hash (as a hex string) to its first "preorder" nameop
      self.namespaces = {}                    # map namespace ID to first instance of NAMESPACE_DEFINE op (a dict) combined with the namespace name and sender script_pubkey
      self.pending_imports = {}               # map an in-progress namespace import (as the hex string of ns_id+script_pubkey hash) to a list of nameops.
                                              # The first element is always the NAMESPACE_PREORDER nameop.
                                              # The second element is always the NAMESPACE_DEFINE nameop.
      
      self.block_name_renewals = defaultdict(list)        # map a block ID to the list of names that were renewed at that block.  Used to find expired names.
      
      self.name_consensus_hash_name = {}      # temporary table for mapping the hash(name + consensus_hash) in an update to its name
      
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
                  
               if 'pending_imports' in db_dict:
                  self.pending_imports = db_dict['pending_imports']
                  
               if 'preorders' in db_dict:
                  self.preorders = db_dict['preorders']
                  
         except Exception as e:
            log.exception(e)
            pass

      # build up our reverse indexes
      for name, name_record in self.name_records.items():
         self.block_name_renewals[ name_record['last_renewed'] ] = name
         self.owner_names[ name_record['sender'] ].append( name )
         self.hash_names[ hash256_trunc128( name ) ] = name

      # load up consensus hash for this block 
      self.snapshot( self.lastblock )
      

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
               'pending_imports': self.pending_imports,
            }
            
            f.write(json.dumps(db_dict))
            
      except Exception as e:
         log.exception(e)
         return False
      
      return True
   
   
   def get_name( self, name ):
      """
      Given a name, return its metadata gleaned from the blockchain.
      Name must be fully-qualified (i.e. name.ns_id)
      Return None if no such name is registered.
      """
      
      if name not in self.name_records.keys():
         return None 
      
      else:
         return self.name_records[name]
      
      
   def get_all_names( self ):
      """
      Get the set of all regisered names
      """
      
      return self.name_records.keys()
   
   
   def get_namespace( self, namespace_id ):
      """
      Given a namespace ID, get the namespace op for it.
      
      Return the dict with the parameters on success.
      Return None if the namespace does not exist.
      """
      
      return self.namespaces.get( namespace_id, None )
      
      
   def get_all_namespaces( self ):
      """
      Get the set of all namespaces.
      """
      
      return self.namespaces.keys()
   
   
   def get_all_importing_namespaces( self ):
      """
      Get the set of all importing namespace hashes.
      """
      
      return self.pending_imports.keys()
   
      
   def get_name_from_name_consensus_hash( self, name_consensus_hash, sender, block_id ):
      """
      Find the name.ns_id from hash( name.ns_id, consensus_hash ), given the sender and block_id,
      and assuming that name.ns_id is already registered.
      There are only a small number of possible values this can take, so test them all to see
      if the hash matches one of them.
      
      This is useful for name updates--we need to ensure that updates are timely, and on 
      the majority fork of the blockchain.
      
      Return the fully-qualified name on success
      Return None if not found.
      """
      
      names = self.owner_names.get( sender, None )
      if names is None:
         
         # invalid name owner
         return None 
      
      possible_consensus_hashes = []
      
      for i in xrange( block_id - virtualchain.config.BLOCKS_CONSENSUS_HASH_IS_VALID, block_id ):
         consensus_hash = self.get_consensus_at( i )
         if consensus_hash is not None:
            possible_consensus_hashes.append( consensus_hash )
      
      for name in names:
         for consensus_hash in possible_consensus_hashes:
            
            test_name_consensus_hash = hash256_trunc128( name + consensus_hash )
            if test_name_consensus_hash == name_consensus_hash:
               
               # found!
               return name 
      
      return None
   
   
   def get_importing_namespace_preorder( self, namespace_id_hash ):
      """
      Given the hash(namespace_id, sender_script_pubkey) for a namespace that is 
      being imported, get its assocated NAMESPACE_PREORDER operation.
      
      Return the op as a dict on success
      Return None on error 
      """
      
      if namespace_id_hash not in self.pending_imports.keys():
         return None 
      
      if len( self.pending_imports[namespace_id_hash] ) < 1:
         return None 
      
      return self.pending_imports[ namespace_id_hash ][0]
      

   def get_importing_namespace_define( self, namespace_id_hash ):
      """
      Given the hash(namespace_id, sender_script_pubkey) for a namespace that is 
      being imported, get its associated NAMESPACE_DEFINE operation.
      
      Return the op as a dict on success.
      Return None on error 
      """
      
      if namespace_id_hash not in self.pending_imports.keys():
         return None 
      
      if len( self.pending_imports[namespace_id_hash] ) < 2:
         return None 
      
      return self.pending_imports[ namespace_id_hash ][1]
   
   
   def get_importing_namespace_ops( self, namespace_id_hash ):
      """
      Given the hash(namespace_id, sender_script_pubkey) for a namespace 
      that is being imported, get the list of nameops that constitute the 
      import.
      
      Return the list of nameops (as dicts) on success
      Return None on error.
      """
      
      if namespace_id_hash not in self.pending_imports.keys():
         return None 
      
      if len(self.pending_imports[namespace_id_hash] ) < 2:
         return None 
      
      return self.pending_imports[namespace_id_hash][2:]
   
   
   def get_importing_namespace_raw( self, namespace_id_hash ):
      """
      Given the hash(namespace_id, sender_script_pubkey) for a 
      namespace that is being imported, get the list of *all*
      nameops that constitute the import.  This includes the 
      namespace's NAMESPACE_PREORDER and NAMESPACE_DEFINE operations,
      if they have been committed yet (they will be the first 
      two records).
      
      Return the list of ops on success
      Return None on error.
      """
      
      if namespace_id_hash not in self.pending_imports.keys():
         return None
      
      return self.pending_imports[ namespace_id_hash ]
   
   
   def find_renewed_at( self, block_id ):
      """
      Find all names registered at a particular block.
      
      Returns a list of names on success (which can be empty)
      """
      return self.block_name_renewals.get( block_id, [] )
   
   
   def is_name_registered(self, name):
      """
      Is the given fully-qualified name (name.ns_id) registered?
      Return True if so.
      Return False if not.
      """
      return name in self.name_records.keys()


   def is_namespace_registered( self, namespace_id ):
      """
      Has a namepace with the given human-readable ID been declared?
      Return True if so.
      Return False if not.
      """
      return namespace_id in self.namespaces.keys()
   
   
   def is_namespace_preordered( self, namespace_id_hash, sender_script_pubkey ):
      """
      Has the given namespace been preordered by the given sender?
      
      Return True if so.
      Return False if not.
      """
      
      namespace_preorder = self.get_importing_namespace_preorder( namespace_id_hash )
      if namespace_preorder is None:
         return False 
      
      if namespace_preorder['sender'] != sender_script_pubkey:
         return False
      
      return True
   
   
   def is_namespace_importing_hash( self, namespace_id_hash ):
      """
      Given the hash(namespace_id, script_pubkey), are we in the process of importing the 
      namespace named by namespace_id?
      
      Return True if so
      Return False if not
      """
      
      if len(self.pending_imports) < 2:
         # not yet defined 
         return False 
      
      if namespace_id_hash not in self.pending_imports.keys():
         return False 
      
      namespace_define = self.get_importing_namespace_define( namespace_id_hash )
      if namespace_define is None:
         return False 
      
      return (namespace_id_hash == namespace_define['namespace_id_hash'])
   
   
   def is_namespace_importing( self, namespace_id, sender_script_pubkey ):
      """
      Are we in the process of importing a namespace?
      
      Return True if so 
      Return False if not.
      """
      namespace_id_hash = None 
      try:
         namespace_id_hash = hash_name( namespace_id, sender_script_pubkey )
      except Exception, e:
         return False 
      
      return self.is_namespace_importing_hash( namespace_id_hash )
   

   def has_defined_namespace( self, namespace_id, sender_script_pubkey ):
      """
      Given the human-readable namespace ID and the sender's script_pubkey 
      hex string, did the owner of the public key define the namespace?
      Return True if so
      Return False if not.
      """
      try:
         namespace_id_hash = hash_name( namespace_id, sender_script_pubkey )
      except ValueError:
         return False 
      
      if namespace_id_hash in self.pending_imports.keys():
         
         namespace_define_nameop = self.get_importing_namespace_define( namespace_id_hash )
         
         if namespace_define_nameop is not None and sender_script_pubkey == namespace_define_nameop['sender']:
            return True 
         
      return False 
   
   
   def has_preordered_name( self, name, sender_script_pubkey ):
      """
      Given the fully-qualified name (name.ns_id) and a sender's script_pubkey 
      hex string, see if the sender did in fact preorder this name.
      Return True if so.
      Return False if not.
      """
      try:
         name_hash = hash_name(name, sender_script_pubkey)
      except ValueError:
         raise 
         return False

      if name_hash in self.preorders.keys():
         
         log.info( "%s: %s" % (name_hash, self.preorders[name_hash]) )
         if sender_script_pubkey == self.preorders[name_hash]['sender']:
            
            return True
         else:
            self.log( "requester: %s; preorderer: %s" % (sender_script_pubkey, self.preorders[name_hash]['sender']) )
            return False
         
      else:
         log.info("%s not found" % name_hash)
 
      return False


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
      return (self.get_importing_namespace_preorder(namespace_id_hash) is None)
   
   
   def is_name_imported( self, name, sender_script_pubkey ):
      """
      Given a name and a sender script_pubkey hex string, determine if the given name is part of a namespace import.
      The name must have been sent by the same sender who sent the NAMESPACE_DEFINE
      
      Return True if so
      Return False if not.
      """
      
      namespace_id = get_namespace_from_name( name )
         
      try:
         namespace_id_hash = hash_name( namespace_id, sender_script_pubkey )
      except Exception, e:
         return False 
      
      return self.is_namespace_importing_hash( namespace_id_hash )
      
      
   def is_name_revoked( self, name ):
      """
      Given a name, determine whether or not it was revoked.
      If the name was not registered in the first place, then it was not revoked.
      
      Return True if so
      Return False if not 
      """
      
      if name not in self.name_records.keys():
         # doesn't exist, so not revoked
         return False 
      
      return self.name_records[name]['revoked']
      
   
   def is_name_expired_at( self, name, block_id ):
      """
      Given a name and a block ID, is the name flagged to 
      expire at exactly EXPIRATION_PERIOD blocks ago.
      
      Return True if so
      Return False if not.
      """
      
      expiring_block_number = block_id - EXPIRATION_PERIOD
      names_expiring = self.find_renewed_at( expiring_block_number )
      return (name in names_expiring)
   
   
   def commit_name_expire( self, name ):
      """
      Remove a name that has expired.
      """
      
      name_hash = hash256_trunc128( name )
      
      owner = None
      
      if not self.name_records.has_key( name ):
         return None
      
      owner = self.name_records[name]['sender']
      
      del self.name_records[ name ]
      
      if self.owner_names.has_key( owner ):
         del self.owner_names[ owner ]
      
      if self.hash_names.has_key( name_hash ):
         del self.hash_names[ name_hash ]
         
   
   def commit_name_expire_all( self, block_id ):
      """
      Given a block ID, remove all name records that expired 
      exactly EXPIRATION_PERIOD blocks ago.
      """
      
      expiring_block_number = block_id - EXPIRATION_PERIOD
      expired_names = self.find_renewed_at( expiring_block_number )
      for name in expired_names:
         
         self.commit_name_expire( name )
      
      if expiring_block_number in self.block_name_renewals.keys():
         del self.block_name_renewals[ expiring_block_number ]
      

   def commit_remove_preorder( self, name, script_pubkey ):
      """
      Given the fully-qualified name (name.ns_id) and a script_pubkey hex string,
      remove the preorder.
      """
      try:
         name_hash = hash_name(name, script_pubkey)
      except ValueError:
         return None
      else:
         del self.preorders[name_hash]


   def commit_remove_namespace_import( self, namespace_id_hash ):
      """
      Given the hash(namespace_id, sender's script pubkey),
      remove the pending name imports for this namespace.
      
      Return True if removed 
      Return False if not 
      """
      
      if self.pending_imports.has_key( namespace_id_hash ):
         
         del self.pending_imports[ namespace_id_hash ]
         return True
      
      else:
         return False
      
      
   def commit_preorder( self, nameop, current_block_number ):
      """
      Record that a name was preordered.
      """
      
      name_hash = nameop['preorder_name_hash']
      self.preorders[ name_hash ] = nameop
      

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
      
      if self.is_name_imported( name, sender ):
         # this is part of a namespace import
         self.commit_namespace_import( nameop, current_block_number )
      
      else:
         
         # is this a renewal?
         if self.is_name_registered( name ):
            
            self.commit_renewal( nameop, current_block_number )
            
         else:
            
            # registered!
            self.commit_remove_preorder( name, sender )
            
            name_record = {
               'value_hash': None,             # i.e. the hex hash of profile data in immutable storage.
               'sender': str(sender),
               'first_registered': current_block_number,
               'last_renewed': current_block_number,
               'address': address,
               'revoked': False
            }
            
            self.name_records[ name ] = name_record 
            self.owner_names[ sender ].append( str(name) )
            self.hash_names[ hash256_trunc128( name ) ] = name 
            self.block_name_renewals[ current_block_number ].append( name )
      
      
   def commit_renewal( self, nameop, current_block_number ):
      """
      Commit a name renewal.  Push back its expiration.
      """
      
      name = nameop['name']
      block_last_renewed = self.name_records[name]['last_renewed']
      
      # name no longer expires at last renewal time...
      self.block_name_renewals[ block_last_renewed ].remove( name )
      self.block_name_renewals[ current_block_number ].append( name )
      
      self.name_records[name]['last_renewed'] = current_block_number
      
   
   def commit_update( self, nameop, current_block_number ):
      """
      Commit an update to a name's immutable profile data.
      NOTE: nameop['name'] will have been defined by log_update.
      """
      
      sender = nameop['sender']
      name_consensus_hash = nameop['name_hash']
      
      try:
         name = nameop['name']
      except:
         print "\n\nnameop: %s\n\n" % nameop
         name = self.name_consensus_hash_name[ name_consensus_hash ]
         del self.name_consensus_hash_name[ name_consensus_hash ]
      
      if self.is_name_imported( name, sender ):
         # this is part of a namespace import
         self.commit_namespace_import( nameop, current_block_number )
      
      else:
         
         self.name_records[name]['value_hash'] = nameop['update_hash']
      
      
   def commit_transfer( self, nameop, current_block_number ):
      """
      Commit a transfer--update the name record to indicate the recipient of the 
      transaction as the new owner.
      """
      
      name = nameop['name']
      owner = nameop['sender']
      recipient = nameop['recipient']
      keep_data = nameop['keep_data']
      
      self.name_records[name]['sender'] = recipient
      
      self.owner_names[owner].remove( name )
      self.owner_names[recipient].append( name )
      
      if not keep_data:
         self.name_records[name]['value_hash'] = None
      
   
   def commit_revoke( self, nameop, current_block_number ):
      """
      Commit a revocation--update the name record.
      """
      
      name = nameop['name']
      self.name_records[name]['revoked'] = True 
      
   
   def commit_namespace_preorder( self, nameop, block_number ):
      """
      Commit a NAMESPACE_PREORER, so we can subsequently accept 
      a namespace definition from the sender.
      
      The namespace will be preordered, but not yet defined
      (i.e. we know it exists, but we don't know its parameters).
      """
      
      namespace_id_hash = nameop['namespace_id_hash']
      sender = nameop['sender']
      
      # this namespace is preordered, but not yet defined
      self.pending_imports[ namespace_id_hash ] = [nameop]
   
   
   def commit_namespace_define( self, nameop, block_number ):
      """
      Commit a NAMESPACE_DEFINE nameop, so we can subsequently accept 
      and batch-commit a set of name registrations in it.
      
      The namespace will be preordered, but not yet defined
      (i.e. we know it exists, but we don't know its parameters).
      """
      
      namespace_id_hash = nameop['namespace_id_hash']
      sender = nameop['sender']
      
      self.pending_imports[ namespace_id_hash ].append( nameop )
   

   def commit_namespace_import( self, nameop, block_id ):
      """
      Given a nameop, add it to a namespace that 
      is being imported.  i.e. if it was sent by the same sender as 
      the person who sent the namespace_define opeation.
      
      The operations committed to this namespace's list of imports
      will be committed as a batch by commit_namespace_begin().
      """
      
      name = nameop['name']
      sender = nameop['sender']         # hex-encoded script_pubkey
      namespace_id = get_namespace_from_name( name )
      
      try:
         namespace_id_hash = hash_name( namespace_id, sender )
      except Exception, e:
         return None
      
      self.pending_imports[ namespace_id_hash ].append( nameop )
         
    
   def commit_namespace_begin( self, nameop, block_number ):
      """
      Commit a namespace and all of the names it has imported.
      The given nameop is a NAMESPACE_BEGIN nameop.
      """
      
      namespace_id = nameop['namespace_id']
      sender = nameop['sender']
      
      try:
         namespace_id_hash = hash_name( namespace_id, sender )
      except Exception, e:
         return False 
      
      # find the corresponding definition.
      namespace_define_nameop = self.get_importing_namespace_define( namespace_id_hash )
      op_sequence = self.get_importing_namespace_ops( namespace_id_hash )
      
      # no longer importing 
      self.commit_remove_namespace_import( namespace_id_hash )
      
      # tag each op with its opcode (to keep virtualchain happy)
      # also, tag each op so the log/commit methods know that this is part of an import 
      for op in op_sequence:
         self.force_opcode( op, eval(op['opcode']) )
         op['namespace_import'] = True
      
      # import each operation for this namespace
      # (i.e. as if they were all in this block)
      pending_ops = self.log_pending_ops( block_number, op_sequence )
      self.commit_pending_ops( block_number, pending_ops )
      
      # record namespace rules
      namespace_record = {}
      namespace_record.update( namespace_define_nameop )
      
      # remember owner
      namespace_record['sender'] = sender 
      
      self.namespaces[ namespace_id ] = namespace_record


   def log_preorder( self, pending_nameops, nameop, block_id ):
      """
      Log a preorder of a name at a particular block number.
      NOTE: these *can't* be incorporated into namespace-imports, 
      since we have no way of knowning which namespace the 
      nameop belongs to (it is blinded until registration).
      But that's okay--we don't need to preorder names during 
      a namespace import, because we will only accept names 
      sent from the importer until the NAMESPACE_BEGIN operation 
      is sent.
      
      Return True if accepted 
      Return False if not.
      """
      
      preorder_name_hash = nameop['preorder_name_hash']
      consensus_hash = nameop['consensus_hash']
      
      for pending_preorders in pending_nameops[ NAME_PREORDER ]:
         if pending_preorders['preorder_name_hash'] == preorder_name_hash:
            return False
         
      if self.is_new_preorder(preorder_name_hash) and self.is_consensus_hash_valid( block_id, consensus_hash ):
         # new hash and right consensus 
         return True 
      
      else:
         return False 


   def log_registration( self, pending_nameops, nameop, block_id ):
      """
      Progess a registration nameop.
      * If the name's namespace is being imported, and it was sent by the same sender
      as the sender who started the namespace, then import it into that namespace.
      * Verify that there was a preorder for it that was owned by the same 
      sender for this operation.
      
      Return True if accepted.
      Return False if not.
      """
      
      name = nameop['name']
      sender = nameop['sender']
      namespace_id = get_namespace_from_name( name )
      
      if self.log_namespace_import( pending_nameops, NAME_REGISTRATION, nameop, block_id ):
         # this registration will be part of a namespace to be imported.
         # will add to the namespace's list of imports.
         return True
      
      elif nameop.get('namespace_import'):
         # we're sending this nameop as part of a namespace import.
         # don't need to consider mining fees or preorders; just keep the first instance.
         if not self.is_name_registered( name ):
            
            # accept 
            return True 
         else:
            
            # collision
            return False
      
      else:
         
         namespace = self.get_namespace( namespace_id )
         if namespace is None:
            # there is no namespace for this name.
            return False 
         
         # sender exceeded maximum number of names?
         if len( self.owner_names.get( name, [] ) ) >= MAX_NAMES_PER_SENDER:
            return False
         
         namespace_base_price = namespace['cost']
         namespace_price_decay = namespace['price_decay']
         
         # is this registration valid?
         if not self.is_name_registered( name ) and self.has_preordered_name( name, sender ) and is_mining_fee_sufficient( name, nameop['fee'], namespace_base_price, namespace_price_decay ):
            
            # registration
            return True
         
         elif self.is_name_registered( name ) and self.is_name_owner( name, sender ) and is_mining_fee_sufficient( name, nameop['fee'], namespace_base_price, namespace_price_decay ):
            
            # renewal
            return True 
         
         else:
            
            # invalid 
            return False
   
   
   def log_update(self, pending_nameops, nameop, block_id ):
      """
      Log an update to a name's associated data.
      Use the nameop's 128-bit name hash to find the name itself.
      
      Return True if accepted
      Return False if not.
      """
      
      name_consensus_hash = nameop['name_hash']
      sender = nameop['sender']
      
      name = self.get_name_from_name_consensus_hash( name_consensus_hash, sender, block_id )
      
      if name is None:
         
         # nothing to do--write is stale or on a fork
         return False
      
      # remember the name, so we don't have to re-calculate it (either in log_namespace_import, or in commit_update)
      self.name_consensus_hash_name[ name_consensus_hash ] = name
      nameop['name'] = name
      
      if self.log_namespace_import( pending_nameops, NAME_UPDATE, nameop, block_id ):
         # this update is part of a namespace import 
         # will add to the namespace's list of imports.
         return True
      
      else:
         
         if not self.is_name_registered( name ):
            # doesn't exist 
            return False 
         
         if self.is_name_revoked( name ):
            # revoked 
            return False 
         
         if self.is_name_owner( name, sender ):
            
            # update is sent by the owner of the name, so accept 
            return True 
         
         else:
            return False


   def log_transfer( self, pending_nameops, nameop, block_id ):
      """
      Log a name's transferrance to another private key.
      The name must exist, not be revoked, and be owned by the sender.
      The recipient must not exceed the maximum allowed number of names per keypair,
      and the recipient cannot own an equivalent name.
      
      Return True if accepted
      Return False if not
      """
      
      name_hash = nameop['name_hash']
      name = self.hash_names.get( name_hash )
      
      if name is None:
         # invalid 
         return False 
      
      consensus_hash = nameop['consensus_hash']
      sender = nameop['sender']
      recipient = nameop['recipient']
      
      if not self.is_consensus_hash_valid( consensus_hash, block_id ):
         # nope 
         return False
         
      if sender == recipient:
         # nonsensical 
         return False 
      
      if not self.is_name_registered( name ):
         return False
      
      if not self.is_name_owner( name, sender ):
         return False 
      
      if self.is_name_revoked( name ):
         # name exists and was revoked 
         return False 
      
      if recipient in self.owner_names.keys():
         
         # recipient already has names...
         recipient_names = self.owner_names[ recipient ]
         if name in recipient_names:
            # shouldn't happen, ever, since names are unique
            return False 
         
         if len(recipient_names) >= MAX_NAMES_PER_SENDER:
            # transfer would exceed quota
            return False
         
      return True


   def log_revoke( self, pending_nameops, nameop, block_id ):
      """
      Revoke a name.  It will still exist, but no future 
      updates or transfers on it will be accepted.
      The sender must own the name, and the name must be registered.
      
      Return True if accepted
      Return False if not
      """
      
      name = nameop['name']
      sender = nameop['sender']
      
      if self.log_namespace_import( pending_nameops, NAME_REVOKE, nameop, block_id ):
         # this update is part of a namespace import 
         # will add to the namespace's list of imports.
         return True
      
      if not self.is_name_registered( name ):
         return False 
      
      if not self.is_name_owner( name, sender ):
         return False 
      
      if self.is_name_revoked( name ):
         # name was already revoked 
         return False 
      
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
      
      # block duplicate preorders
      for pending_namespace_preorder in pending_nameops[ NAMESPACE_PREORDER ]:
         if pending_namespace_preorder['namespace_id_hash'] == namespace_id_hash:
            return False
      
      if self.is_new_namespace_preorder(namespace_id_hash) and self.is_consensus_hash_valid( block_id, consensus_hash ):
         # new hash and right consensus 
         return True 
      
      else:
         return False 


   def log_namespace_import( self, pending_nameops, opcode, nameop, block_id ):
      """
      Determine if a nameop is supposed to be part of a namespace import.
      
      Return True if so, and update nameop to record the block ID at which it was added.
      Return False if not.
      Raises an exception if there is no 'name' field in nameop.
      """
      
      name = nameop.get('name', None)
      sender = nameop['sender']
      
      if name is None:
         raise Exception("BUG: no name given in name operation at block %s: %s" % (block_id, nameop) )
      
      if self.is_name_imported( name, sender ):
         nameop['block_number'] = block_id
         return True
      
      else:
         return False
         


   def log_namespace_define( self, pending_nameops, nameop, block_id ):
      """
      Log a NAMESPACE_DEFINE operation to the name database.
      It is only valid if it is the first such operation 
      for this namespace, and if it was sent by the same 
      sender who sent the NAMESPACE_PREORDER.
      
      Return True if accepted 
      Return False if not
      """
      
      namespace_id = nameop['namespace_id']
      namespace_id_hash = nameop['namespace_id_hash']
      sender = nameop['sender']
      
      if not self.is_namespace_preordered( namespace_id_hash, sender ):
         # this sender did not preorder this namespace
         return False 
      
      if self.is_namespace_importing_hash( namespace_id_hash ):
         # this namespace was already defined
         return False
      
      if self.is_namespace_registered( namespace_id ):
         # this namespace already exists (i.e. was already begun)
         return False 
      
      # can begin import
      return True 
      
      
   def log_namespace_begin( self, pending_nameops, nameop, block_id ):
      """
      Log a NAMESPACE_BEGIN operation to the name database.
      It is only valid if it has been imported by the same sender as
      the corresponding NAMESPACE_DEFINE, and the namespace is still 
      in the process of being imported.
      """
      
      namespace_id = nameop['namespace_id']
      sender = nameop['sender']
      
      if not self.is_namespace_importing( namespace_id, sender ):
         # namespace is not importing, and/or this is not the right sender
         return False
      
      if self.is_namespace_registered( namespace_id ):
         # namespace already exists 
         return False 
      
      # can commit imported nameops 
      return True
      
      
   def __iter__(self):
      """
      Get a BlockstoreDBIterator for this db.
      """
      return BlockstoreDBIterator( self )
   
     
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


def price_name( name, namespace_base_price, namespace_decay ):
   """
   Calculate the price of a name, given the 
   namespace base price and price decay exponent.

   The minimum price is 1 satoshi
   """

   # establish the base price (in satoshis)
   price = float(namespace_base_price)

   # adjust the price by a factor X for every character beyond the first
   price = math.ceil( price / (namespace_decay**(len(name)-1)) )

   # price cannot be lower than 1 satoshi
   if price < 1:
      price = 1

   return int(price)


def is_mining_fee_sufficient( name, mining_fee, namespace_base_price, namespace_decay ):
   """
   Given a name, its mining fee, and the namespace 
   pricing parameters, is the fee sufficient?
   
   Return True if so
   Return False if not.
   """
   
   name_price = price_name(name, namespace_base_price, namespace_decay)
   return (mining_fee >= name_price)
