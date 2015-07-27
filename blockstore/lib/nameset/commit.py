from ..hashing import hash_name, hash256_trunc128
from .namedb import get_name_from_hash128, put_signed_data

def remove_preorder(db, name, script_pubkey):
    try:
        name_hash = hash_name(name, script_pubkey)
    except ValueError:
        return False
    else:
        del db.preorders[name_hash]
        return True


def commit_registration(db, nameop, current_block_number):
    """
    Construct a name registration record, and update:
    * name_records
    * block_expirations
    * index_hash_name
    """
    name = nameop['name']
    name_hash128 = hash256_trunc128( name )
    remove_preorder(db, name, nameop['sender'])
    db.name_records[name] = {
        'value_hash': None,
        'owner': str(nameop['sender']),                 # i.e. the hex string of the script_pubkey
        'first_registered': current_block_number,
        'last_renewed': current_block_number
    }
    db.block_expirations[current_block_number][name] = True
    db.index_hash_name[ name_hash128 ] = name


def commit_renewal(db, nameop, current_block_number):
    """
    Commit a name renewal, and update:
    * block_expirations
    * name_records
    """
    name = nameop['name']
    # grab the block the name was last renewed to find the old expiration timer
    block_last_renewed = db.name_records[name]['last_renewed']
    # remove the old expiration timer
    db.block_expirations[block_last_renewed].pop(name, None)
    # add in the new expiration timer
    db.block_expirations[current_block_number][name] = True
    # update the block that the name was last renewed in the name record
    db.name_records[name]['last_renewed'] = current_block_number


def commit_update(db, nameop):
    """
    Commit an update to a name's data, and update:
    * name_records (value_hash)
    """
    name = get_name_from_hash128( nameop['name_hash'], db )
    db.name_records[name]['value_hash'] = nameop['update_hash']


def commit_transfer(db, nameop):
    """
    Commit a transfer: change the name's owner in name_records to the nameop's 'recipient' script_pubkey
    """
    db.name_records[nameop['name']]['owner'] = str(nameop['recipient'])


def commit_namespace( db, nameop, block_number ):
   """
   Commit a namespace and its imports.
   nameop is a NAMESPACE_BEGIN nameop
   """
   
   namespace_id = nameop['namespace_id']
   
   namespace_define_nameop = db.pending_imports[ namespace_id ][0]
   op_sequence = db.pending_imports[ namespace_id ][1:]
   
   namespace_id_hash = namespace_define_nameop['namespace_id_hash']
   
   # no longer importing 
   del db.imports[ namespace_id_hash ]
   del db.pending_imports[ namespace_id ]
   
   # merge each operation to pending
   for op in op_sequence:
      log_blockstore_op( db, op, op['block_number'] )


 
def commit_putdata( db, storageop ):
   """
   Store signed data hash, owned by the principal that put the storage op.
   """
   
   name_hash = storageop['name_hash']
   data_hash = storageop['data_hash']
   
   name = get_name_from_hash128( name_hash, db )
   put_signed_data( name, data_hash, db )
   

def commit_deletedata( db, storageop):
   """
   Delete a signed data hash.
   """
   
   name_hash = storageop['name_hash']
   data_hash = storageop['data_hash']
   
   name = get_name_from_hash128( name_hash, db )
   remove_signed_data( name, data_hash, db )
   
