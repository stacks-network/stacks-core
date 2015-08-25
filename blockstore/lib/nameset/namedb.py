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
from ..config import NAMESPACE_DEFAULT, MIN_OP_LENGTHS, OPCODES, MAGIC_BYTES, TESTSET, MAX_NAMES_PER_SENDER, \
    EXPIRATION_PERIOD, NAME_PREORDER, NAMESPACE_PREORDER, NAME_REGISTRATION, NAME_UPDATE, TRANSFER_KEEP_DATA, \
    TRANSFER_REMOVE_DATA, NAME_REVOKE, NAMESPACE_BASE_COST, NAMESPACE_COST_DECAY, NAME_PREORDER_EXPIRE, \
    NAMESPACE_PREORDER_EXPIRE, NAMESPACE_REVEAL_EXPIRE, NAMESPACE_REVEAL

from ..operations import build_namespace_reveal
from ..hashing import *
from ..b40 import is_b40

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
   of import operations (including the NAMESPACE_PREORDER and NAMESPACE_REVEAL,
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
          
      name_string = (name + name_record['sender'] + profile_hash + revoked_string).encode('utf8')
      
      return name_string
   
   
   def serialize_namespace_record( self, namespace_id, namespace_record ):
      """
      Serialize a namespace record--either a ready or revealed one
      make it sortable on the namespace ID (namespace IDs are unique, so 
      this imposes a total order on the set of serialized name records), and
      include the owner's script_pubkey and rules
      """
      
      rules_string = build_namespace_reveal( "", namespace_record['lifetime'], namespace_record['cost'], namespace_record['price_decay'], testset=TESTSET )
      sender = namespace_record.get('sender', "")
      
      if sender is None:
         sender = ""
         
      if namespace_id is None:
         namespace_id = ""
         
      try:
         namespace_string = (namespace_id + rules_string + sender).encode('utf8')
      except Exception, e:
         raise e
      
      return namespace_string 
      
   
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
      Get the next serialized namespace record (both revealed and ready namespaces)
      Return None if we're out of namespaces.
      """
      
      if self.sorted_namespaces is None:
         # have not done namespaces yet 
         self.sorted_namespaces = sorted( self.db.get_all_namespace_ids() + self.db.get_all_revealed_namespace_ids() )
         self.next_namespace = 0
      
      if self.next_namespace < len(self.sorted_namespaces):
         
         namespace_id = self.sorted_namespaces[ self.next_namespace ]
         self.next_namespace += 1
         
         # either revealed or ready...
         namespace = self.db.get_namespace( namespace_id )
         if namespace is None:
             
             namespace = self.db.get_namespace_reveal( namespace_id )
             if namespace is None:
                 raise Exception("BUG: no data for namespace '%s'" % namespace_id)
             
         serialized_namespace_record = self.serialize_namespace_record( namespace_id, namespace )
         
         log.debug("   Serialized namespace record: '%s' (%s)" % (serialized_namespace_record, namespace_id) )
         return serialized_namespace_record
      
      # out of namespaces 
      self.sorted_namespaces = []
      return None 
      
      
   def next(self):
      """
      Iterate over the *serialized* names, namespaces, and importing namespaces.
      Do so in a stable order.
      """
      
      serialized_record = None 
      
      # all registered names
      serialized_record = self.next_name_record()
      if serialized_record is not None:
         return serialized_record
      
      # all ready namespaces
      serialized_record = self.next_namespace_record()
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
      self.namespaces = {}                    # map namespace ID to first instance of NAMESPACE_REVEAL op (a dict) combined with the namespace ID and sender script_pubkey
      self.namespace_preorders = {}           # map namespace ID hash (as the hex string of ns_id+script_pubkey hash) to its NAMESPACE_PREORDER operation 
      self.namespace_reveals = {}             # map namesapce ID to its NAMESPACE_REVEAL operation 
      
      self.namespace_hash_to_id = {}          # map the namespace ID of a revealed namespace to its namespace hash.  Entries here only exist until the namespace is ready 
      
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
                  
               if 'namespace_preorders' in db_dict:
                  self.namespace_preorders = db_dict['namespace_preorders']
                  
               if 'namespace_reveals' in db_dict:
                  self.namespace_reveals = db_dict['namespace_reveals']
                  
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

      for (namespace_id, namespace_reveal) in self.namespace_reveals.items():
         self.namespace_hash_to_id[ namespace_reveal['namespace_id_hash'] ] = namespace_id
         

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
               'namespace_preorders': self.namespace_preorders,
               'namespace_reveals': self.namespace_reveals
            }
            
            f.write(json.dumps(db_dict))
            f.flush()
            
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
      
      
   def get_name_preorder( self, name, sender_script_pubkey ):
      """
      Get the preorder for a name, given the name and the sender's script_pubkey string.
      Return the nameop on success
      Return None if not found.
      """
      preorder_hash = hash_name(name, sender_script_pubkey)
      if preorder_hash not in self.preorders.keys():
          return None
      
      else:
          return self.preorders[ preorder_hash ]
      
       
      
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
      
      
   def get_all_namespace_ids( self ):
      """
      Get the set of all namespace IDs
      """
      
      return self.namespaces.keys()
   
   
   def get_all_revealed_namespace_ids( self ):
      """
      Get the IDs of all revealed namespaces.
      """
      
      return self.namespace_reveals.keys()
   
   def get_all_importing_namespace_hashes( self ):
      """
      Get the set of all preordered and revealed namespace hashes.
      """
      
      revealed_namespace_hashes = []
      for (namespace_id, revealed_namespace) in self.namespace_reveals.items():
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
         if consensus_hash is not None and consensus_hash not in possible_consensus_hashes:
            possible_consensus_hashes.append( consensus_hash )
      
      for name in names:
         for consensus_hash in possible_consensus_hashes:
            
            # what would have been the name/consensus_hash?
            test_name_consensus_hash = hash256_trunc128( name + consensus_hash )
            if test_name_consensus_hash == name_consensus_hash:
               
               # found!
               return name 
      
      return None
   
   
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
      
      if namespace_id_hash in self.namespace_preorders.keys():
         
         namespace_reveal_nameop = self.get_importing_namespace_reveal( namespace_id )
         
         if namespace_reveal_nameop is not None and sender_script_pubkey == namespace_reveal_nameop['sender']:
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
      return (self.get_namespace_preorder(namespace_id_hash) is None)
  
   
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
      Remove an expired name.
      The caller must verify that the expiration criteria have been met.
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
   
   
   def commit_preorder_expire_all( self, block_id ):
      """
      Given the block ID, go find and remove all expired preorders
      """
      for (name_hash, nameop) in self.preorders.items():
          if nameop['block_number'] + NAME_PREORDER_EXPIRE <= block_id:
              # expired 
              log.debug("Expire name preorder '%s'" % name_hash)
              del self.preorders[name_hash]
      
      
   def commit_namespace_preorder_expire_all( self, block_id ):
      """
      Given the block ID, go find and remove all expired namespace preorders
      """
      for (namespace_id_hash, nameop_list) in self.namespace_preorders.items():
          if len(nameop_list) != 1:
              continue 
          
          # just a preorder
          preorder_nameop = nameop_list[0]
          if preorder_nameop['block_number'] + NAMESPACE_PREORDER_EXPIRE <= block_id:
              # expired 
              log.debug("Expire namespace preorder '%s'" % namespace_id_hash)
              del self.namespace_preorders[ namespace_id_hash ]
              
              
   def commit_namespace_reveal_expire_all( self, block_id ):
      """
      Given the block ID, go find and remove all expired namespace reveals 
      that have not been made ready.  Remove their associated name imports.
      """
      for (namespace_id, reveal_op) in self.namespace_reveals.items():
          
          if reveal_op['block_number'] + NAMESPACE_REVEAL_EXPIRE <= block_id:
              
              # expired 
              log.debug("Expire incomplete namespace '%s'" % namespace_id)
              del self.namespace_reveals[ namespace_id ]
              del self.namespace_hash_to_id[ namespace_id ]
                     
              for (name, nameop) in self.name_records:
                 
                 if namespace_id == get_namespace_from_name( name ):
                     # part of this namespace 
                     log.debug("Expire imported name '%s'" % name)
                     self.commit_name_expire( name )
                
                
   
   def commit_name_expire_all( self, block_id ):
      """
      Given a block ID, remove all name records that expired 
      exactly EXPIRATION_PERIOD blocks ago.
      """
      
      expiring_block_number = block_id - EXPIRATION_PERIOD
      expired_names = self.find_renewed_at( expiring_block_number )
      for name in expired_names:
         log.debug("Expire name '%s'" % name)
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
         if self.preorders.has_key(name_hash):
            del self.preorders[name_hash]


   def commit_remove_namespace_import( self, namespace_id, sender ):
      """
      Given the namespace ID, go remove the namespace preorder and reveal.
      (i.e. call this on a NAMESPACE_READY commit).
      """
      
      namespace_id_hash = hash_name( namespace_id, sender )
      if self.namespace_preorders.has_key( namespace_id_hash ):
          del self.namespace_preorders[ namespace_id_hash ]
      
      if self.namespace_reveals.has_key( namespace_id ):
          del self.namespace_reveals[ namespace_id ]
      
      if self.namespace_hash_to_id.has_key( namespace_id_hash ):
          del self.namespace_hash_to_id[ namespace_id_hash ]
      
      return
      
      
   def commit_preorder( self, nameop, current_block_number ):
      """
      Record that a name was preordered.
      """
      
      name_hash = nameop['preorder_name_hash']
      nameop['block_number'] = current_block_number
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
      
      # did this name collide with another name?
      if nameop.get('collision') is not None:
         # do nothing--this name collided 
         return 

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
      Commit an update to a name's profile data.
      NOTE: nameop['name'] will have been defined by log_update.
      """
      
      sender = nameop['sender']
      name_consensus_hash = nameop['name_hash']
      
      try:
         name = nameop['name']
      except:
         log.error( "No 'name' in nameop: %s" % nameop )
         name = self.name_consensus_hash_name[ name_consensus_hash ]
         del self.name_consensus_hash_name[ name_consensus_hash ]
      
      self.name_records[name]['value_hash'] = nameop['update_hash']
      
      
   def commit_transfer( self, nameop, current_block_number ):
      """
      Commit a transfer--update the name record to indicate the recipient of the 
      transaction as the new owner.
      """
      
      name = nameop['name']
      owner = nameop['sender']
      recipient = nameop['recipient']
      recipient_address = nameop['recipient_address']
      keep_data = nameop['keep_data']
      
      op = TRANSFER_KEEP_DATA
      if not keep_data:
          op = TRANSFER_REMOVE_DATA
          
      log.debug("Name '%s': %s >%s %s" % (name, owner, op, recipient))
      
      self.name_records[name]['sender'] = recipient
      self.name_records[name]['address'] = recipient_address
      self.owner_names[owner].remove( name )
      self.owner_names[recipient].append( name )
      
      if not keep_data:
         self.name_records[name]['value_hash'] = None
      
   
   def commit_revoke( self, nameop, current_block_number ):
      """
      Commit a revocation--blow away the name 
      """
      
      name = nameop['name']
      
      self.commit_name_expire( name )
      
      
   def commit_name_import( self, nameop, current_block_number ):
      """
      Commit a name import--register it and set the owner and update hash.
      """
      
      name = nameop['name']
      recipient = nameop['recipient']
      recipient_address = nameop['recipient_address']
      update_hash = nameop['update_hash']
    
      name_record = {
        'value_hash': update_hash,
        'sender': recipient,
        'first_registered': current_block_number,
        'last_renewed': current_block_number,
        'address': recipient_address
      }

      self.name_records[ name ] = name_record 
      self.owner_names[ recipient ].append( str(name) )
      self.hash_names[ hash256_trunc128( name ) ] = name 
      self.block_name_renewals[ current_block_number ].append( name )
      
   
   def commit_namespace_preorder( self, nameop, block_number ):
      """
      Commit a NAMESPACE_PREORER, so we can subsequently accept 
      a namespace reveal from the sender.
      
      The namespace will be preordered, but not yet defined
      (i.e. we know it exists, but we don't know its parameters).
      """
      
      namespace_id_hash = nameop['namespace_id_hash']
      sender = nameop['sender']
      
      nameop['block_number'] = block_number
      
      # this namespace is preordered, but not yet defined
      self.namespace_preorders[ namespace_id_hash ] = nameop
   
   
   def commit_namespace_reveal( self, nameop, block_number ):
      """
      Commit a NAMESPACE_REVEAL nameop, so we can subsequently accept 
      a sequence of preordered names from the sender.
      
      The namespace will be revealed, but not yet ready
      (i.e. we know its parameters, but only the sender can operate on its names)
      """
      
      # collision?
      if nameop.get('collision'):
          return 
      
      namespace_id = nameop['namespace_id']
      namespace_id_hash = nameop['namespace_id_hash']
      sender = nameop['sender']
      
      nameop['block_number'] = block_number
      self.namespace_reveals[ namespace_id ] = nameop
      self.namespace_hash_to_id[ nameop['namespace_id'] ] = namespace_id_hash
   
      if namespace_id_hash in self.namespace_preorders:
          del self.namespace_preorders[namespace_id_hash]
          

   def commit_namespace_ready( self, nameop, block_number ):
      """
      Mark a namespace as ready for external name registrations.
      The given nameop is a NAMESPACE_READY nameop.
      """
      
      namespace_id = nameop['namespace_id']
      sender = nameop['sender']
      namespace = self.namespace_reveals[ namespace_id ]
      
      self.commit_remove_namespace_import( namespace_id, sender )
      
      # namespace is ready!
      self.namespaces[ namespace_id ] = namespace 
      

   def is_name_collision( self, pending_nameops, name ):
      """
      Go through the list of pending nameops, and see if this given 
      name collides with any of them.
      
      Return True on success 
      Return False on error 
      """
      
      for registration_op in pending_nameops:
          if registration_op['name'] == name:
              return True 
      
      return False
  
  
   def is_namespace_collision( self, pending_nameops, namespace_id ):
      """
      Go through the list of pending nameops, and see if this given 
      namespace ID collides with any of them.
      
      Return True on success 
      Return False on error 
      """
      
      for registration_op in pending_nameops:
          if registration_op['namespace_id'] == namespace_id:
              return True 
      
      return False
      
      
   def disallow_registration( self, pending_nameops, name ):
      """
      Given the list of pending nameops, disallow this name from 
      being registered on commit.  This is achieved by tagging 
      the operation with data that commit_registration will use 
      to NACK the request.
      
      Always succeeds.
      """
      
      for i in xrange(0, len(pending_ops)):
          
          if pending_nameops[i]['name'] == name:
              pending_nameops[i]['collision'] = True
      
      return
      
   
   def disallow_reveal( self, pending_nameops, namespace_id ):
      """
      Given the list of pending nameops, disallow this namespace from 
      being revealed on commit.  This is achieved by tagging 
      the operation with data that commit_namespace_reveal will use 
      to NACK the request.
      
      Always succeeds.
      """
      
      for i in xrange(0, len(pending_ops)):
          
          if pending_nameops[i]['namespace_id'] == namespace_id:
              pending_nameops[i]['collision'] = True
      
      return
  
   
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
      
      return True 
  
      
   def log_registration( self, pending_nameops, nameop, block_id ):
      """
      Progess a registration nameop.
      * the name must be well-formed 
      * the namespace must be ready
      * either the name was preordered by the same sender, or the name exists and is owned by this sender (the name cannot be registered and owned by someone else)
      * if we're finishing a preorder, then there cannot be another NAME_REGISTRATION operation in pending_nameops
      * the mining fee must be high enough.
      
      NAME_REGISTRATION is not allowed during a namespace import, so the namespace must be ready.
      
      Return True if accepted.
      Return False if not.
      """
      
      name = nameop['name']
      sender = nameop['sender']
      name_fee = None
      namespace = None
      
      # name must be well-formed
      if not is_b40( name ) or "+" in name or name.count(".") > 1:
          log.debug("Malformed name '%s': non-base-38 characters" % name)
          return False
      
      namespace_id = get_namespace_from_name( name )
      
      # namespace must exist and be ready 
      if not is_namespace_ready( namespace_id ):
          log.debug("Namespace '%s' is not ready" % namespace_id)
          return False
        
      # preordered?
      name_preorder = self.get_name_preorder( name, sender )
      if name_preorder is not None:
          
          # name must be preordered by the same sender 
          if name_preorder['sender'] != sender:
             log.debug("Name '%s' was not preordered by %s" % (name, sender))
             return False
          
          # name can't be registered in this block--two or more preorderers are racing
          if self.is_name_collision( pending_nameops[ NAME_REGISTRATION ], name ):
             log.debug("Name '%s' has multiple registrations in this block" % name)
             self.disallow_registration( pending_nameops[ NAME_REGISTRATION ], name )
             return False
      
      
      elif self.is_name_registered( name ):
          
          # name must be owned by this sender 
          if not self.is_name_owner( name, sender ):
              log.debug("Name '%s' not owned by %s" % (name, sender))
              return False 
          
      else:
          
          # does not exist and not preordered
          log.debug("Name '%s' was not preordered" % name)
          return False 
      
      
      namespace = self.get_namespace( namespace_id )
      name_fee = name_preorder['fee']
      
      # check name fee 
      namespace_base_price = namespace['cost']
      namespace_price_decay = namespace['price_decay']
      
      name_without_namespace = get_name_from_fq_name( name )
      
      # fee must be high enough
      if name_fee < price_name( name_without_namespace, namespace_base_price, namespace_price_decay ):
          log.debug("Name '%s' costs %s, but sender paid %s" % (name, price_name( name_without_namespace, namespace_base_price, namespace_price_decay ), name_fee ))
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
      
      name = self.get_name_from_name_consensus_hash( name_consensus_hash, sender, block_id )
      
      if name is None:
         log.debug("Unable to resolve name consensus hash '%s' to name" % name_consensus_hash)
         # nothing to do--write is stale or on a fork
         return False
      
      namespace_id = get_namespace_from_name( name )
      
      # the namespace must be ready 
      if not self.is_namespace_ready( namespace_id ):
          log.debug("Namespace '%s' is not ready" % namespace_id)
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
      
      # remember the name, so we don't have to re-calculate it...
      self.name_consensus_hash_name[ name_consensus_hash ] = name
      nameop['name'] = name
      
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
      
      if not self.is_namespace_ready( namespace_id ):
         # non-existent namespace
         log.debug("Namespace '%s' is not ready" % (namespace_id))
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
      
      # name must be well-formed
      if not is_b40( name ) or "+" in name or name.count(".") > 1:
          log.debug("Malformed name '%s': non-base-38 characters" % name)
          return False
      
      namespace_id = get_namespace_from_name( name )
      
      # namespace must be ready 
      if not self.is_namespace_ready( namespace_id ):
         log.debug("Namespace '%s' is not ready" % namespace_id )
         return False 
         
      # the name must be registered 
      if not self.is_name_registered( name ):
         log.debug("Name '%s' is not registered" % name )
         return False 
          
      # the sender must own this name 
      if not self.is_name_owner( name, sender ):
         log.debug("Name '%s' is not owned by %s (but %s)" % (name, sender, self.get_name_owner(name)))
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
      
      name = nameop['name']
      sender = nameop['sender']
      
      # name must be well-formed
      if not is_b40( name ) or "+" in name or name.count(".") > 1:
          log.debug("Malformed name '%s': non-base-38 characters" % name)
          return False
      
      namespace_id = get_namespace_from_name( name )
      
      # namespace must be revealed 
      if not self.is_namespace_revealed( namespace_id ):
          log.debug("Namespace '%s' is not revealed" % namespace_id )
          return False 
      
      namespace = self.get_namespace_reveal( namespace_id )
      
      # name can't exist 
      if self.is_name_registered( name ):
          log.debug("Name '%s' already exists" % name )
          return False
      
      # sender must be the same as the namespace's sender
      if sender != namespace['sender']:
          log.debug("Name '%s' is not sent by the namespace owner")
          return False 
      
      # sender must have paid enough 
      name_fee = nameop['fee']
      
      # check name fee 
      namespace_base_price = namespace['cost']
      namespace_price_decay = namespace['price_decay']
      
      name_without_namespace = get_name_from_fq_name( name )
      
      # fee must be high enough
      if name_fee < price_name( name_without_namespace, namespace_base_price, namespace_price_decay ):
          log.debug("Name '%s' costs %s, but sender paid %s" % (name, price_name( name_without_namespace, namespace_base_price, namespace_price_decay ), name_fee ))
          return False
      
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
            log.debug("Namespace hash '%s' is already preordered")
            return False
      
      # cannot be preordered already
      if not self.is_new_namespace_preorder( namespace_id_hash ):
          log.debug("Namespace preorder '%s' already in use" % namespace_id_hash)
          return False
      
      # has to have a reasonable consensus hash
      if not self.is_consensus_hash_valid( block_id, consensus_hash ):
          log.debug("Invalid consensus hash '%s'" % consensus_hash )
          return False 
      
      return True 


   def log_namespace_reveal( self, pending_nameops, nameop, block_id ):
      """
      Log a NAMESPACE_REVEAL operation to the name database.
      It is only valid if it is the first such operation 
      for this namespace, and if it was sent by the same 
      sender who sent the NAMESPACE_PREORDER.
      
      Return True if accepted 
      Return False if not
      """
      
      namespace_id = nameop['namespace_id']
      namespace_id_hash = nameop['namespace_id_hash']
      sender = nameop['sender']
      namespace = None
      
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
      namespace = self.get_namespace_preorder( namespace_id_hash )
      if namespace is None:
         # not preordered 
         log.debug("Namespace '%s' is not preordered" % namespace_id )
         return False 
     
      # must be sent by the same person who preordered it
      if namespace['sender'] != sender:
         # not sent by the preorderer 
         log.debug("Namespace '%s' is not preordered by '%s'" % (namespace_id, sender))
      
      # can't be revealed in this block 
      if self.is_namespace_collision( pending_nameops[ NAMESPACE_REVEAL ], namespace_id ):
         log.debug("Namespace '%s' revealed multiple times in this block" % namespace_id )
         self.disallow_reveal( pending_nameops[ NAMESPACE_REVEAL ], namespace_id )
         return False
      
      # check fee...
      namespace_preorder = self.get_namespace_preorder( namespace_id_hash )
      namespace_fee = namespace_preorder['fee']
      
      # must have paid enough 
      if namespace_fee < price_name( namespace_id, NAMESPACE_BASE_COST, NAMESPACE_COST_DECAY ):
         # not enough money 
         log.debug("Namespace '%s' costs %s, but sender paid %s" % (namespace_id, price_name(namespace_id, NAMESPACE_BASE_COST, NAMESPACE_COST_DECAY), namespace_fee ))
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
      
      # must have been sent by the same person who revealed it (and thus preordered it)
      revealed_namespace = self.get_namespace_reveal( namespace_id )
      if revealed_namespace['sender'] != sender:
         log.debug("Namespace '%s' is not owned by '%s'" % (namespace_id, sender))
         return False 
      
      # can't be ready yet
      if self.is_namespace_ready( namespace_id ):
         # namespace already exists 
         log.debug("Namespace '%s' is already registered" % namespace_id )
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


def price_name( name, namespace_base_price, namespace_decay ):
   """
   Calculate the price of a name (without its namespace ID), given the 
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


def is_name_mining_fee_sufficient( name, mining_fee, namespace_base_price, namespace_decay ):
   """
   Given a name (without its namespace ID), its mining fee, and the namespace 
   pricing parameters, is the fee sufficient?
   
   Return True if so
   Return False if not.
   """
   
   name_price = price_name(name, namespace_base_price, namespace_decay)
   return (mining_fee >= name_price)


def is_namespace_mining_fee_sufficient( namespace_id, mining_fee ):
   """
   Given a namespace ID and its mining fee, is the fee sufficient?
   
   Return True if so
   Return False if not.
   """
   
   name_price = price_name(namespace_id, NAMESPACE_BASE_COST, NAMESPACE_COST_DECAY)
   return (mining_fee >= name_price)
