from ..hashing import hash_name

def name_registered(db, name):
    if name in db.names:
        return True
    return False

def name_not_registered(db, name):
    return (not name_registered(db, name))

def no_pending_higher_priority_registration(db, name, mining_fee):
    if name in db.pending_registrations:
        del db.pending_registrations[name]
        return False
    return True

def has_preordered_name(db, name, salt, sender):
    try:
        name_hash = hash_name(name, salt)
    except ValueError:
        return False

    if name_hash in db.preorders:
        if sender == db.preorders[name_hash]['sender']:
            return True
    return False

def is_name_owner(db, name, senders):
    if name in db.names and 'owner' in db.names[name]:
        if db.names[name]['owner'] in senders:
            return True
    return False

def is_name_admin(db, name, senders):
    if name in db.names and 'admin' in db.names[name]:
        if db.names[name]['admin'] in senders:
            return True
    return False

def is_preorder_hash_unique(db, name_hash):
    return (name_hash not in db.preorders)
