import traceback
from collections import defaultdict
from binascii import hexlify, unhexlify

from .check import *
from .commit import commit_registration, commit_update, commit_transfer, \
    commit_renewal
from .log import log_preorder, log_registration, log_update, log_transfer

from ..fees import is_mining_fee_sufficient
from ..parsing import parse_nameop
from ..config import *
from ..hashing import double_sha256
from ..merkle import MerkleTree

def process_pending_nameops_in_block(db, current_block_number):
    """ process logged registrations, updates, and transfers
    """
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
    """ clean out expired names
    """
    expiring_block_number = current_block_number - EXPIRATION_PERIOD
    names_expiring = db.block_expirations[expiring_block_number]
    for name, _ in names_expiring.items():
        del db.name_records[name]

def record_nameop(db, nameop):
    """ record nameop
    """
    opcode = eval(nameop['opcode'])
    if opcode == NAME_PREORDER:
        log_preorder(db, nameop)
    elif opcode == NAME_REGISTRATION:
        log_registration(db, nameop)
    elif opcode == NAME_UPDATE:
        log_update(db, nameop)
    elif opcode == NAME_TRANSFER:
        log_transfer(db, nameop)

def name_record_to_string(name, name_record):
    value_hash = name_record.get('value_hash', '')
    name_string = (name + name_record['owner'] + value_hash).encode('utf8')
    return name_string

def calculate_merkle_snapshot(db):
    names = sorted(db.name_records)
    hashes = []
    for name in names:
        name_string = name_record_to_string(name, db.name_records[name])
        name_string_hash = hexlify(double_sha256(name_string))
        hashes.append(name_string_hash)
    merkle_tree = MerkleTree(hashes)
    merkle_root = merkle_tree.root()
    return merkle_root

def build_namespace(db, nulldata_txs, first_block, last_block):
    """ build the namespace
    """
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
    merkle_snapshot = calculate_merkle_snapshot(db)
    return merkle_snapshot

