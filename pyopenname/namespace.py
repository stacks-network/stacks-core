from collections import defaultdict

from .hashing import hash_name
from .fees import is_mining_fee_sufficient
from .parsing import parse_nameop
from .configs import *

def name_not_registered(db, name):
    if name in db.names:
        return False
    return True

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
    if (name_not_registered(db, name) and \
        has_preordered_name(db, name, nameop['salt'], nameop['sender']) and \
        is_mining_fee_sufficient(name, nameop['fee'])):
        # we're good - log it!
        db.pending_registrations[name].append(nameop)

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

def commit_registration(db, nameop):
    remove_preorder(db, nameop['name'], nameop['salt'])
    db.names[nameop['name']] = { 'value_hash': None, 'owner': nameop['sender'] }

def commit_update(db, nameop):
    db.names[nameop['name']]['value_hash'] = nameop['update']

def commit_transfer(db, nameop):
    db.names[nameop['name']]['owner'] = nameop['recipient']

# processing logged registrations, updates, and transfers

def process_pending_nameops_in_block(db):
    for name, nameops in db.pending_registrations.items():
        if len(nameops) == 1:
            nameop = nameops[0]
            commit_registration(db, nameop)

    for name, nameops in db.pending_updates.items():
        if len(nameops) == 1:
            nameop = nameops[0]
            commit_update(db, nameop)

    for name, nameops in db.pending_transfers.items():
        if len(nameops) == 1:
            nameop = nameops[0]
            commit_transfer(db, nameop)

    db.pending_registrations = defaultdict(list)
    db.pending_updates = defaultdict(list)
    db.pending_transfers = defaultdict(list)

def record_nameop(db, nameop):
    opcode = eval(nameop['opcode'])
    if opcode == NAME_PREORDER:
        log_preorder(db, nameop)
    elif opcode == NAME_CLAIM:
        log_registration(db, nameop)
    elif opcode == NAME_UPDATE:
        log_update(db, nameop)
    elif opcode == NAME_TRANSFER:
        log_transfer(db, nameop)

def build_namespace(db, nulldata_txs):
    block_numbers = sorted(nulldata_txs)
    for block_number in block_numbers:
        print "="*20 + str(block_number) + "="*20
        block = nulldata_txs[block_number]
        for tx in block:
            nameop = parse_nameop(str(tx['data']), tx['outputs'],
                tx['senders'], tx['mining_fee'])
            print nameop
            if nameop:
                try:
                    record_nameop(db, nameop)
                except Exception as e:
                    traceback.print_exc()
                    continue
        process_pending_nameops_in_block(db)

