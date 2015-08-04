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
    encoded in transactions data within the underlying cryptocurrency (i.e. OP_RETURNs in Bitcoin).
    Each block in the blockchain must be fed into the database, and the blocks' 
    blockstore operations extracted, validated, and accounted for.  As such, at block N,
    the blockstore database represents the current state of names and storage at block N.
    
    Because the underlying cryptocurrency blockchain can fork, blockstore peers need to 
    determine that they are on the smae fork so they will know which blockstore operations 
    to process.  To do so, the blockstore database calculates a Merkle tree over its 
    current state (i.e. the set of names) at the current block, and encodes the root
    hash in each operation.  Then, one peer can tell that the other peer's operations
    were calculated on the same blockchain fork simply by ensuring that the operation had
    the right Merkle root hash for that block.  These Merkle root hashes are called
    "consensus hashes."
    
    Processing a block happens in five stages: "parse", "check", "log", "commmit", and "snapshot"
    * "Parsing" a block transaction's nulldata (i.e. from an OP_RETURN) means translating 
    the OP_RETURN data into a blockstore operation.  Relevant methods are in ..parsing.
    * "Checking" an operation means ensuring the operation is consistent with the state of the 
    database constructed thus far.  Relevant methods are in .check.
    * "Logging" an operation means staging an operation to be included in the database,
    at the point of processing block N.  Relevant methods are in .log.
    * "Committing" an operation means adding a logged operation to the current state of the 
    database.
    * "Snapshotting" means calculating the consensus hash of the database at block N.
    """
    
    def __init__(self, db_filename, consensus_snapshots_filename, lastblock_filename):
        """
        Construct a blockstore database client, optionally from locally-cached 
        blockstore database state and the set of previously-calculated consensus 
        hashes for each block.
        """
        
        self.db_filename = db_filename 
        self.consensus_snapshots_filename = consensus_snapshots_filename
        self.lastblock_filename = lastblock_filename
        
        self.name_records = {}                  # map name.ns_id to dict of
                                                # { "owner": hex string of script_pubkey,
                                                #   "first_registered": block when registered,
                                                #   "last_renewed": block when last renewed,
                                                #   "value_hash": hex string of hash of profile JSON }
                                                
        self.index_hash_name = {}               # map 128-bit hash (as a hex string) to name.ns_id, to look up updates and data signatures
        self.preorders = {}                     # map preorder name.ns_id+script_pubkey hash (as a hex string) to its first "preorder" nameop
        self.imports = {}                       # map an in-progress namespace import (as the hex string of ns_id+script_pubkey hash) to a list of nameops.  The first element is the namespace_define nameop
        self.namespaces = {}                    # map namespace ID to first instance of NAMESPACE_BEGIN op
        
        # the set of operations witnessed for the current block the client is processing.
        self.pending_registrations = defaultdict(list)
        self.pending_updates = defaultdict(list)
        self.pending_transfers = defaultdict(list)
        self.pending_renewals = defaultdict(list)
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
        """
        Cache the set of blockstore operations to disk,
        so we don't have to go build them up again from 
        the blockchain.
        """
        
        try:
            with open(filename, 'w') as f:
                db_dict = {
                    'registrations': self.name_records,
                    'index_hash_name': self.index_hash_name,
                    'preorders': self.preorders,
                    'namespaces': self.namespaces,
                    'imports': self.imports
                }
                f.write(json.dumps(db_dict))
        except Exception as e:
            traceback.print_exc()
            return False
        return True

    def save_snapshots(self, filename):
        """
        Save the set of consensus hashes to disk, so 
        we don't have to go built them up again from 
        the blockchain.
        """
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
    
    
    def clear_pending( self ):
      """
      Once we finish processing a block
      """
      pass 

    def save(self, current_block_number):
      """
      Save the state of the database to the files given in the constructor.
      """
      tmp_db_filename = self.db_filename + ".tmp"
      tmp_snapshot_filename = self.consensus_snapshots_filename + ".tmp"
      tmp_block_number = self.lastblock_filename + ".tmp"
      
      rc = self.save_names( tmp_db_filename )
      if not rc:
         
         try:
            os.unlink( tmp_db_filename )
         except:
            pass 
         
         return False
         
      rc = self.save_snapshots( tmp_snapshot_filename )
      if not rc:
         
         try:
            os.unlink( tmp_db_filename )
            os.unlink( tmp_snapshot_filename )
         except:
            pass 
         
         return False
      
      with open(tmp_block_number, "w") as lastblock_f:
         lastblock_f.write("%s" % current_block_number)
      
      for tmp_filename, filename in zip( [tmp_db_filename, tmp_snapshot_filename, tmp_block_number], \
                                          [self.db_filename, self.consensus_snapshots_filename, self.lastblock_filename] ):
            
            try:
               # NOTE: rename fails on Windows if the destination exists 
               if sys.platform == 'win32':
                  os.unlink( filename )
                  
               os.rename( tmp_db_filename, self.db_filename )
            except:
               os.unlink( tmp_db_filename )
               os.unlink( tmp_snapshot_filename )
               return False 
      
      try:
         # NOTE: rename fails on Windows if the destination exists 
         if sys.platform == 'win32':
            os.unlink( self.consensus_snapshots_filename )
            
         os.rename( tmp_snapshot_filename, self.consensus_snapshots_filename )
      except:
         os.unlink( tmp_db_filename )
         os.unlink( tmp_snapshot_filename )
         return False 
      
      # clean up 
      os.unlink( tmp_db_filename )
      os.unlink( tmp_snapshot_filename )
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

def get_namespace_from_name( name ):
   """
   Get a name's namespace, if it has one.
   It's the sequence of characters after the last "." in the name.
   """
   if "." not in name:
      # invalid 
      return None 
   
   return name.split(".")[-1]

def lookup_name(name, db):
    value_hash = get_value_hash_for_name(name, db)

    if value_hash in db.content:
        return db.content[value_hash]
    return None
