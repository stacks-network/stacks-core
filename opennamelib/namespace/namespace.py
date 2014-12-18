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
from ..hashing import double_sha256, calculate_consensus_hash128
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

def record_nameop(db, nameop, block_number):
    """ record nameop
    """
    opcode = eval(nameop['opcode'])
    if opcode == NAME_PREORDER:
        log_preorder(db, nameop, block_number)
    elif opcode == NAME_REGISTRATION:
        log_registration(db, nameop)
    elif opcode == NAME_UPDATE:
        log_update(db, nameop)
    elif opcode == NAME_TRANSFER:
        log_transfer(db, nameop)

def name_record_to_string(name, name_record):
    value_hash = name_record.get('value_hash', '')
    if value_hash is None:
        value_hash = ''
    name_string = (name + name_record['owner'] + value_hash).encode('utf8')
    return name_string

def calculate_merkle_snapshot(db):
    names = sorted(db.name_records)
    hashes = []
    for name in names:
        name_string = name_record_to_string(name, db.name_records[name])
        name_string_hash = hexlify(double_sha256(name_string))
        hashes.append(name_string_hash)
    if len(hashes) == 0:
        hashes.append(hexlify(double_sha256("")))
    merkle_tree = MerkleTree(hashes)
    merkle_root = merkle_tree.root()
    return merkle_root

def record_consensus_hash(db, consensus_hash, block_number):
    db.consensus_hashes[block_number] = consensus_hash

def process_tx_for_nameop(db, tx, block_number):
    nameop = parse_nameop(
        str(tx['data']), tx['outputs'], tx['senders'], tx['mining_fee'])
    if nameop:
        try:
            record_nameop(db, nameop, block_number)
        except Exception as e:
            traceback.print_exc()
        #else:
        #    print nameop

def process_nameops_in_block(db, nulldata_txs, block_number):
    #print "="*20 + str(block_number) + "="*20
    # process all the nulldata transactions in the block
    if str(block_number) in nulldata_txs:
        block = nulldata_txs[str(block_number)]
        for tx in block:
            process_tx_for_nameop(db, tx, block_number)
        process_pending_nameops_in_block(db, block_number)

def build_namespace(db, nulldata_txs, first_block, last_block=None):
    """ build the namespace
    """
    for block_number in range(first_block, last_block+1):
        # process the nameops in the block
        process_nameops_in_block(db, nulldata_txs, block_number)
        # clean out expired names
        clean_out_expired_names(db, block_number)
        # calculate the merkle consensus hash
        merkle_snapshot = calculate_merkle_snapshot(db)
        consensus_hash128 = calculate_consensus_hash128(merkle_snapshot)
        # record the merkle consensus hash
        record_consensus_hash(db, consensus_hash128, block_number)
    db.consensus_hashes['current'] = merkle_snapshot
    return merkle_snapshot
