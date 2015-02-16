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
from ..hashing import bin_double_sha256, calculate_consensus_hash128

from coinkit import MerkleTree


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

    # delete all the pending operations
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


def log_nameop(db, nameop, block_number):
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
        name_string_hash = hexlify(bin_double_sha256(name_string))
        hashes.append(name_string_hash)
    if len(hashes) == 0:
        hashes.append(hexlify(bin_double_sha256("")))
    merkle_tree = MerkleTree(hashes)
    merkle_root = merkle_tree.root()
    consensus_hash128 = calculate_consensus_hash128(merkle_root)
    return consensus_hash128


def record_consensus_hash(db, consensus_hash, block_number):
    db.consensus_hashes[str(block_number)] = consensus_hash


def build_nameset(db, nameop_sequence):
    # set the current consensus hash
    first_block_number = nameop_sequence[0][0]
    db.consensus_hashes[str(first_block_number)] = calculate_merkle_snapshot(db)

    for block_number, nameops in nameop_sequence:
        # log the pending nameops
        for nameop in nameops:
            try:
                log_nameop(db, nameop, block_number)
            except Exception as e:
                traceback.print_exc()
        # process and tentatively commit the pending nameops
        process_pending_nameops_in_block(db, block_number)
        # clean out the expired names
        clean_out_expired_names(db, block_number)
        # calculate the merkle snapshot consensus hash
        consensus_hash128 = calculate_merkle_snapshot(db)
        # record the merkle consensus hash
        record_consensus_hash(db, consensus_hash128, block_number)

    # set the current consensus hash
    db.consensus_hashes['current'] = consensus_hash128
    # return the current consensus hash
    return consensus_hash128

from ..blockchain import get_nulldata_txs_in_block


def nulldata_txs_to_nameops(txs):
    nameops = []
    for tx in txs:
        try:
            nameop = parse_nameop(
                tx['nulldata'], tx['vout'], senders=tx['senders'],
                fee=tx['fee'])
        except:
            pass
        else:
            if nameop:
                nameops.append(nameop)
    return nameops


def get_nameops_in_block(bitcoind, block_number):
    current_nulldata_txs = get_nulldata_txs_in_block(bitcoind, block_number)
    nameops = nulldata_txs_to_nameops(current_nulldata_txs)
    return nameops


def get_nameops_in_block_range(bitcoind, first_block=0, last_block=None):
    nameop_sequence = []

    if not last_block:
        last_block = bitcoind.getblockcount()

    for block_number in range(first_block, last_block + 1):
        block_nameops = get_nameops_in_block(bitcoind, block_number)
        nameop_sequence.append((block_number, block_nameops))

    return nameop_sequence
