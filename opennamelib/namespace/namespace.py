from collections import defaultdict

from ..hashing import hash_name
from ..fees import is_mining_fee_sufficient
from ..parsing import parse_nameop
from ..config import *

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

def remove_preorder(db, name, salt):
    try:
        name_hash = hash_name(name, salt)
    except ValueError:
        return False
    else:
        del db.preorders[name_hash]
        return True

def is_preorder_hash_unique(db, name_hash):
    return name_hash not in db.preorders

# filtering and logging of name operations in a block

def log_registration(db, nameop):
    name = nameop['name']
    # check if this registration is a valid one
    if (name_not_registered(db, name)
        and has_preordered_name(db, name, nameop['salt'], nameop['sender'])
        and is_mining_fee_sufficient(name, nameop['fee'])):
        # we're good - log the registration!
        db.pending_registrations[name].append(nameop)
    # check if this registration is actually a valid renewal
    if (name_registered(db, name)
        and is_name_owner(db, name, nameop['sender'])
        and is_mining_fee_sufficient(name, nameop['fee'])):
        # we're good - log the renewal!
        db.pending_renewals[name].append(nameop)

def log_update(db, nameop):
    name = nameop['name']
    if is_name_owner(db, name, nameop['sender']):
        # we're good - log it!
        db.pending_updates[name].append(nameop)

def log_transfer(db, nameop):
    name = nameop['name']
    if is_name_owner(db, name, nameop['sender']):
        # we're good - log it!
        db.pending_transfers[name].append(nameop)

def log_preorder(db, nameop):
    if is_preorder_hash_unique(db, nameop['hash']):
        # we're good - log it!
        commit_preorder(db, nameop)

# commiting of name operations in a lbock

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

# processing logged registrations, updates, and transfers

def process_pending_nameops_in_block(db, current_block_number):
    # commit the pending registrations
    for name, nameops in db.pending_registrations.items():
        if len(nameops) == 1:
            commit_registration(db, nameops[0], current_block_number)
    # commit the pending updates
    for name, nameops in db.pending_updates.items():
        if len(nameops) == 1:
            commit_update(db, nameops[0])
    # commit the pending transfers
    for name, nameops in db.pending_transfers.items():
        if len(nameops) == 1:
            commit_transfer(db, nameops[0])
    # commit the pending renewals
    for name, nameops in db.pending_renewals.items():
        if len(nameops) == 1:
            commit_renewal(db, nameops[0], current_block_number)

    db.pending_registrations = defaultdict(list)
    db.pending_updates = defaultdict(list)
    db.pending_transfers = defaultdict(list)
    db.pending_renewals = defaultdict(list)

def clean_out_expired_names(db, current_block_number):
    expiring_block_number = current_block_number - EXPIRATION_PERIOD
    names_expiring = db.block_expirations[expiring_block_number]
    for name, _ in names_expiring.items():
        del db.names[name]

def record_nameop(db, nameop):
    opcode = eval(nameop['opcode'])
    if opcode == NAME_PREORDER:
        log_preorder(db, nameop)
    elif opcode == NAME_REGISTRATION:
        log_registration(db, nameop)
    elif opcode == NAME_UPDATE:
        log_update(db, nameop)
    elif opcode == NAME_TRANSFER:
        log_transfer(db, nameop)

def build_namespace(db, nulldata_txs, first_block, last_block):
    block_numbers = sorted(nulldata_txs)
    for block_number in range(first_block, last_block+1):
        #print "="*20 + str(block_number) + "="*20
        if str(block_number) in nulldata_txs:
            block = nulldata_txs[str(block_number)]
            for tx in block:
                nameop = parse_nameop(str(tx['data']), tx['outputs'],
                    tx['senders'], tx['mining_fee'])
                #print nameop
                if nameop:
                    try:
                        record_nameop(db, nameop)
                    except Exception as e:
                        traceback.print_exc()
                        continue
            process_pending_nameops_in_block(db, block_number)
        clean_out_expired_names(db, block_number)

