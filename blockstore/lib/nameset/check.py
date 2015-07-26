from ..hashing import hash_name, hash256_trunc128
from ..config import BLOCKS_CONSENSUS_HASH_IS_VALID


def name_registered(db, name):
    if name in db.name_records:
        return True
    return False


def name_not_registered(db, name):
    return (not name_registered(db, name))


def namespace_registered( db, namespace ):
   """
   Has a namespace been declared?
   """
   if namespace in db.namespaces.keys():
      return True 
   else:
      return False
   
def namespace_importing( db, namespace ):
   """
   Is a namespace in the process of being defined?
   """
   try:
      namespace_id_hash = hash_name(namespace_id, sender_script_pubkey)
   except ValueError:
      return False
   
   if namespace_id_hash in db.imports.keys():
      return True 
   else:
      return False


def has_defined_namespace( db, namespace_id, sender_script_pubkey ):
   """
   Has the given user (identified by the sender_script_pubkey) defined this namespace?
   """
   try:
      namespace_id_hash = hash_name(namespace_id, sender_script_pubkey)
   except ValueError:
      return False
   
   if namespace_id_hash in db.imports.keys():
      if sender_script_pubkey == db.imports[namespace_id_hash]['sender']:
         return True 
   
   return False


def no_pending_higher_priority_registration(db, name, mining_fee):
    if name in db.pending_registrations:
        del db.pending_registrations[name]
        return False
    return True


def has_preordered_name(db, name, sender_script_pubkey):
    try:
        name_hash = hash_name(name, sender_script_pubkey)
    except ValueError:
        return False

    if name_hash in db.preorders:
        if sender_script_pubkey == db.preorders[name_hash]['sender']:
            return True
    return False


def is_name_owner(db, name, senders):
    if name in db.name_records and 'owner' in db.name_records[name]:
        if db.name_records[name]['owner'] in senders:
            return True
    return False


def is_name_admin(db, name, senders):
    if name in db.name_records and 'admin' in db.name_records[name]:
        if db.name_records[name]['admin'] in senders:
            return True
    return False


def is_preorder_hash_unique(db, name_hash):
    return (name_hash not in db.preorders)


def is_consensus_hash_valid(db, consensus_hash, current_block_number):
    first_block_to_check = current_block_number - BLOCKS_CONSENSUS_HASH_IS_VALID
    for block_number in range(first_block_to_check, current_block_number):
        if str(block_number) not in db.consensus_hashes:
            continue
        if str(consensus_hash) == str(db.consensus_hashes[str(block_number)]):
            return True
    return False


def is_storageop_from_registered_name( db, storageop ):
    """
    Determine if a storage operation came from a valid registered name.
    """
    
    name_hash = storageop['name_hash']
    data_hash = storageop['data_hash']
   
    name = get_name_from_hash128( name_hash, db )
    if name is None:
      # name does not exist 
      return False 
    
    # name must be registered
    if not name_registered( db, name ):
      return 
    
    # storageop must have a sender 
    if 'sender' not in storageop:
      return 
   
    # storageop's sender must be the same as the name owner 
    name_owner = db.name_records[name]['owner']
    if name_owner != storageop['sender']:
      return False
    
    