from ..hashing import hash_name

def remove_preorder(db, name, salt):
    try:
        name_hash = hash_name(name, salt)
    except ValueError:
        return False
    else:
        del db.preorders[name_hash]
        return True

def commit_preorder(db, nameop):
    db.preorders[nameop['hash']] = nameop

def commit_registration(db, nameop, current_block_number):
    name = nameop['name']
    remove_preorder(db, name, nameop['salt'])
    db.names[name] = {
        'value_hash': None,
        'owner': str(nameop['sender']),
        'block_first_registered': current_block_number,
        'block_last_renewed': current_block_number
    }
    db.block_expirations[current_block_number][name] = True

def commit_renewal(db, nameop, current_block_number):
    name = nameop['name']
    # grab the block the name was last renewed to find the old expiration timer
    block_last_renewed = db.names[name]['block_last_renewed']
    # remove the old expiration timer
    db.block_expirations[block_last_renewed].pop(name, None)
    # add in the new expiration timer
    db.block_expirations[current_block_number][name] = True
    # update the block that the name was last renewed in the name record
    db.names[name]['block_last_renewed'] = current_block_number

def commit_update(db, nameop):
    db.names[nameop['name']]['value_hash'] = nameop['update']

def commit_transfer(db, nameop):
    db.names[nameop['name']]['owner'] = nameop['recipient']