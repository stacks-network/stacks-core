from .check import name_not_registered, has_preordered_name, \
    is_name_owner, is_preorder_hash_unique, name_registered, \
    is_consensus_hash_valid
from ..fees import is_mining_fee_sufficient
from .commit import commit_preorder


def log_registration(db, nameop):
    name = nameop['name']
    # check if this registration is a valid one
    if (name_not_registered(db, name)
            and has_preordered_name(db, name, nameop['sender'])
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


def log_preorder(db, nameop, block_number):
    consensus_hash = nameop['consensus_hash']
    if (is_preorder_hash_unique(db, nameop['name_hash'])
            and is_consensus_hash_valid(db, consensus_hash, block_number)):
        # we're good - log it!
        commit_preorder(db, nameop)
