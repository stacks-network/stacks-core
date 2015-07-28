import json
import traceback

from collections import defaultdict
from ..config import NAMESPACE_DEFAULT

class NameDb():
    """
    Client to the blockstore database of names and storage operations, constructed and  
    kept synchronized with records in the underlying blockchain.  If the blockchain 
    is the ledger of all name and storage operations to have ever been committed 
    (including invalid and fraudulent ones), then this databse represents the 
    current state of all valid names, namespaces, and storage operations.
    
    Constructing the database is an iterative process.  Blockstore data are 
    encoded in OP_RETURN transactions within the underlying cryptocurrency (Bitcoin).
    Each block in the blockchain must be fed into the database, and the blocks' 
    blockstore operations extracted, validated, and accounted for.  As such, at block N,
    the blockstore database represents the current state of names and storage at block N.
    
    Because the underlying cryptocurrency blockchain can fork, blockstore peers need to 
    determine that they are on the smae fork so they will know which blockstore operations 
    to process.  To do so, the blockstore database calculates a Merkle tree over its 
    current state at the current block, and encodes the root hash in each operation.  Then,
    one peer can tell that the other peer's operations were calculated on the same blockchain 
    fork simply by ensuring that the operation had the right Merkle root hash for that block.
    These Merkle root hashes are called "consensus hashes."
    """
    
    def __init__(self, db_filename, consensus_snapshots_filename):
        """
        Construct a blockstore database client, optionally from locally-cached 
        blockstore database state and the set of previously-calculated consensus 
        hashes for each block.
        """
        
        self.name_records = {}                  # map name.ns_id to dict of
                                                # { "owner": hex string of script_pubkey,
                                                #   "first_registered": block when registered,
                                                #   "last_renewed": block when last renewed,
                                                #   "value_hash": hex string of hash of last update }
                                                
        self.index_hash_name = {}               # map 128-bit hash (as a hex string) to name.ns_id, to look up updates and data signatures
        self.preorders = {}                     # map preorder name.ns_id+script_pubkey hash (as a hex string) to its first "preorder" nameop
        self.imports = {}                       # map an in-progress namespace import (as the hex string of ns_id+script_pubkey hash) to a list of nameops.  The first element is the namespace_define nameop
        self.namespaces = {}                    # map namespace ID to first instance of NAMESPACE_BEGIN op
        self.signed_data = {}                   # map name to set of hashes of data
        
        # the set of operations witnessed for the current block the client is processing.
        self.pending_registrations = defaultdict(list)
        self.pending_updates = defaultdict(list)
        self.pending_transfers = defaultdict(list)
        self.pending_renewals = defaultdict(list)
        self.pending_data_puts = defaultdict(list)
        self.pending_data_deletes = defaultdict(list)
        self.pending_imports = defaultdict(list)        # map namespace_id to list of [namespace_define] + [nameops], but such that each nameop has a 'block_number'
        
        self.block_expirations = defaultdict(dict)

        self.consensus_hashes = defaultdict(dict)

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
                       
                    if 'imports' in db_dict:
                        self.imports = db_dict['imports']
                        
                    if 'preorders' in db_dict:
                        self.preorders = db_dict['preorders']
                        
                    if 'index_hash_name' in db_dict:
                        self.index_hash_name = db_dict['index_hash_name']
                        
                    if 'signed_data' in db_dict:
                        self.signed_data = db_dict['signed_data']
                        
                        # convert to sets 
                        for (name, hash_list) in self.signed_data.items():
                           self.signed_data[name] = set(hash_list)
                        
            except Exception as e:
                pass

        if consensus_snapshots_filename:
            try:
                with open(snapshots_filename, 'r') as f:
                    db_dict = json.loads(f.read())
                    if 'snapshots' in db_dict:
                        self.consensus_hashes = db_dict['snapshots']
            except Exception as e:
                pass
             

    def save_names(self, filename):
       
        # serialize signed data to lists 
        serialized_signed_data = {}
        for (name, hash_set) in self.signed_data.items():
           serialized_signed_data[name] = list(hash_set)
        
        try:
            with open(filename, 'w') as f:
                db_dict = {
                    'registrations': self.name_records,
                    'index_hash_name': self.index_hash_name,
                    'preorders': self.preorders,
                    'namespaces': self.namespaces,
                    'imports': self.imports,
                    'signed_data': serialized_signed_data
                }
                f.write(json.dumps(db_dict))
        except Exception as e:
            traceback.print_exc()
            return False
        return True

    def save_snapshots(self, filename):
        try:
            with open(filename, 'w') as f:
                db_dict = {
                    'snapshots': self.consensus_hashes
                }
                f.write(json.dumps(db_dict))
        except Exception as e:
            traceback.print_exc()
            return False
        return True


def get_value_hash_for_name(name, db):
    if name in db.name_records and 'value_hash' in db.name_records[name]:
        value_hash = db.name_records[name]['value_hash']
        return value_hash
    return None


def get_name_from_hash128( hash128, db ):
    """
    Find the name from its 128-bit hash.
    """
    if hash128 in db.index_hash_name.keys():
       return db.index_hash_name[ hash128 ]
    else:
       return None


def get_storage_owner_name( data_hash, db ):
    """
    Get the name of the user that wrote 
    a piece of data.
    
    Return the name if successful
    Return None if not
    """
    
    name_hash = data_hash.get( 'name_hash', None )
    if name_hash is None:
       return None
    
    name = get_name_from_hash128( name_hash, db )
    if name is None: 
       return None 
    
    return name
    

def get_namespace_from_name( name ):
   """
   Get a name's namespace, if it has one.
   It's the sequence of characters after the last "." in the name.
   """
   if "." not in name:
      # invalid 
      return None 
   
   return name.split(".")[-1]


def put_signed_data( owner_name, data_hash, db ):
   """
   Remember that a particular principal (identified by name)
   owns a piece of data.
   
   NOTE: this doesn't verify that the name is valid; the caller must do so.
   """
   
   print "user %s owns %s" % (owner_name, data_hash)
   
   if db.signed_data.has_key( owner_name ):
      db.signed_data[owner_name].update( set([data_hash]) )
   
   else:
      db.signed_data[owner_name] = set([data_hash])
      

def verify_signed_data( owner_name, data_hash, db ):
   """
   Confirm that a given user wrote a particular piece of data.
   
   Return True if so; False if not 
   """
  
   debug_str = "" 
   if not db.signed_data.has_key( owner_name ):
      # user has written nothing 
      debug_str = "user %s does not own anything" % owner_name
      return {"debug": debug_str, "result": False} 
   
   debug_str = "user %s owns %s? %s" % (owner_name, data_hash, data_hash in db.signed_data[owner_name])
   return {"debug": debug_str, "result":  data_hash in db.signed_data[ owner_name ] }


def delete_signed_data( owner_name, data_hash, db ):
   """
   Remove signed data written by a particular principal (identified by name)
   """
   
   if db.signed_data.has_key( owner_name ):
      if data_hash in db.signed_data[owner_name]:
         db.signed_data[owner_name].remove( data_hash )
         

def lookup_name(name, db):
    value_hash = get_value_hash_for_name(name, db)

    if value_hash in db.content:
        return db.content[value_hash]
    return None
