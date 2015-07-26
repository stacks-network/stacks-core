from .check import name_not_registered, has_preordered_name, \
    is_name_owner, is_preorder_hash_unique, name_registered, \
    is_consensus_hash_valid, is_storageop_from_registered_name, \
    namespace_importing
from ..fees import is_mining_fee_sufficient
from .namedb import get_name_from_hash128, put_signed_data, get_namespace_from_name
from ..hashing import hash256_trunc128, hash_name


def log_import( db, nameop, block_number ):
   """
   Log an op as part of a namespace import 
   """
   
   name = nameop['name']
   namespace_id = get_namespace_from_name( name )
   
   nameop['block_number'] = block_number
   db.imports[ namespace_id ].append( nameop )
   
   
def log_registration(db, nameop, block_number):
    """
    Log a name registration.
    """
    
    name = nameop['name']
    namespace_id = get_namespace_from_name( name )
    
    # part of an import?
    if namespace_importing( db, namespace_id ):
        # yup--remember which block, to avoid conflicts
        log_import( db, nameop, block_number )
    
    else:
        
        namespace = get_namespace( db, namespace_id )
        
        # check if this registration is a valid one
        if (name_not_registered(db, name) and has_preordered_name(db, name, nameop['sender']) and is_mining_fee_sufficient(name, nameop['fee'])):
           # we're good - log the registration!
           db.pending_registrations[name].append(nameop)
        
        # check if this registration is actually a valid renewal
        if (name_registered(db, name) and is_name_owner(db, name, nameop['sender']) and is_mining_fee_sufficient(name, nameop['fee'])):
           # we're good - log the renewal!
           db.pending_renewals[name].append(nameop)


def log_update(db, nameop, block_number):
    """
    Log an update to a name's associated data.
    Use the nameop's 128-bit name hash to find the name itself.
    """
    name_hash128 = nameop['name_hash']
    name = get_name_from_hash128( name_hash128, db )
    
    if name is None:
       # nothing to do 
       return
    
    namespace_id = get_namespace_from_name( name )
    
    # part of an import?
    if namespace_importing( db, namespace_id ):
       # yup--remember which block, to avoid conflicts 
       log_import( db, nameop, block_number )
    
    else:
       if is_name_owner(db, name, nameop['sender']):
          # we're good - log it!
          db.pending_updates[name].append(nameop)


def log_transfer(db, nameop, block_number):
    """
    Log a transfer for this name to the nameop's 'sender' script_pubkey
    """
    name = nameop['name']
    namespace_id = get_namespace_from_name( name )
    
    # part of an import?
    if namespace_importing( db, namespace_id ):
       # yup--remember which block, to avoid conflicts
       log_import( db, nameop, block_number )
    
    else:
       
       if is_name_owner(db, name, nameop['sender']):
          # we're good - log it!
          db.pending_transfers[name].append(nameop)


def log_preorder(db, nameop, block_number):
    """
    Log a preorder of a name at a particular block number.
    NOTE: these can't be incorporated into namespace-imports, 
    since we have no way of knowning which namespace the 
    nameop belongs to.
    """
    
    preorder_name_hash = nameop['preorder_name_hash']
    consensus_hash = nameop['consensus_hash']
    
    if (is_preorder_hash_unique(db, preorder_name_hash) and is_consensus_hash_valid(db, consensus_hash, block_number)):
        # we're good - log it!
        db.preorders[ preorder_name_hash ] = nameop


def log_namespace_define(db, nameop, block_number):
    """
    Log a "namespace define" operation to the name database.
    It is only valid if it is the first such operation 
    for this namespace.
    """
    
    namespace_id_hash = nameop['namespace_id_hash']
    
    if not namespace_registered( db, namespace_id_hash ) and not namespace_importing( db, namespace_id_hash ):
       # can begin the import 
       db.imports[ namespace_id_hash ] = defaultdict(list)
       db.imports[ namespace_id_hash ].append( nameop )
 
 
def log_namespace_begin(db, nameop, block_number):
    """
    Log a "namespace begin" operation to the name database.
    All pending operations will be incorporated into the same consensus hash.
    """
    
    namespace_id = nameop['namespace_id']
    
    if not namespace_registered( db, namespace_id ) and namespace_importing( db, namespace_id ) and has_defined_namespace( db, namespace_id, nameop['sender'] ):
       # can merge on next commit. this namespace is no longer importing.
       db.pending_imports[ namespace_id ] = db.imports[ namespace_id_hash ]
       del db.imports[ namespace_id_hash ]
 
 
def log_putdata( db, storageop, block_number ):
    """
    Log that someone stored data.
    Data can only be written by users with registered names.
    """
    
    data_hash = storageop['data_hash']
    
    if is_storageop_from_registered_name( storageop ):
       
       name_hash = storageop['name_hash']
       name = get_name_from_hash128( name_hash )
       
       if name is not None:
         db.pending_data_puts[name].append( data_hash )
       
    
def log_deletedata( db, storageop, block_number ):
    """
    Log that someone deleted data.
    Data can only be deleted by the user that put it.
    """
    
    data_hash = storageop['data_hash']
    
    if is_storageop_from_registered_name( storageop ):
       
       name_hash = storageop['name_hash']
       name = get_name_from_hash128( name_hash )
       
       if name is not None and data_hash in db.signed_data[name]:
          # user owns this data
          db.pending_data_deletes[name].append( data_hash )
    
    