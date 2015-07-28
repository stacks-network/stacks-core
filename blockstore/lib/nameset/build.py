import traceback
from collections import defaultdict
from binascii import hexlify, unhexlify

from .check import *
from .commit import commit_registration, commit_update, commit_transfer, \
    commit_renewal, commit_namespace, commit_putdata, commit_deletedata
from .log import log_preorder, log_registration, log_update, log_transfer, log_namespace_define, log_namespace_begin, log_putdata, log_deletedata

from ..fees import is_mining_fee_sufficient
from ..parsing import parse_blockstore_op
from ..config import *
from ..hashing import bin_double_sha256, calculate_consensus_hash128

from coinkit import MerkleTree
from ..blockchain import get_nulldata_txs_in_block, get_nulldata_txs_in_blocks

def process_pending_ops_in_block(db, current_block_number):
    """
    Process logged blockstore operations for this block.
    For name operations, if there are duplicates for a given name, then they are all ignored 
    (i.e. clients will need to try again).  This does not apply to storage operations--a name 
    can put multiple storage operations per block.
    """
    
    # move nameops in pending imports to their respective lists of pending operations,
    # so we can go on to process them as pending registrations, transfers, etc.
    for namespace_id, nameops in db.pending_imports.items():
       commit_namespace( db, namespace_id, nameops )
    
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

    # commit all pending data-signature writes for each name
    for name, storageops in db.pending_data_puts.items():
       for storageop in storageops:
          commit_putdata( db, storageop )
               
    # commit all pending data-deletions for each name
    for name, storageops in db.pending_data_deletes.items():
        for storageop in storageops:
          commit_deletedata( db, storageop )
            
    # delete all the pending operations
    db.pending_registrations = defaultdict(list)
    db.pending_updates = defaultdict(list)
    db.pending_transfers = defaultdict(list)
    db.pending_renewals = defaultdict(list)
    db.pending_data_puts = defaultdict(list)
    db.pending_data_deletes = defaultdict(list)
    db.pending_imports = defaultdict(list)
    

def clean_out_expired_names(db, current_block_number):
    """
    Clear out expired names, as well as all signed data committed by them.
    """
    
    expiring_block_number = current_block_number - EXPIRATION_PERIOD
    names_expiring = db.block_expirations[expiring_block_number]
    for name, _ in names_expiring.items():
        del db.name_records[name]
        del db.signed_data[name]


def log_blockstore_op(db, blockstore_op, block_number):
    """
    record blockstore operations
    """
    opcode = eval(blockstore_op['opcode'])
    
    if opcode == NAME_PREORDER:
        log_preorder(db, blockstore_op, block_number)
        
    elif opcode == NAME_REGISTRATION:
        log_registration(db, blockstore_op, block_number)
        
    elif opcode == NAME_UPDATE:
        log_update(db, blockstore_op, block_number)
        
    elif opcode == NAME_TRANSFER:
        log_transfer(db, blockstore_op, block_number)
        
    elif opcode == NAMESPACE_DEFINE:
        log_namespace_define(db, blockstore_op, block_number)
        
    elif opcode == NAMESPACE_BEGIN:
        log_namespace_begin(db, blockstore_op, block_number)
        
    elif opcode == DATA_PUT:
        log_putdata( db, blockstore_op, block_number )
    
    elif opcode == DATA_DELETE:
        log_deletedata( db, blockstore_op, block_number )


def name_record_to_string(name, name_record):
    """
    Convert a name and its metadata into a UTF8 string that 
    represents the name, namespace ID, owner, and latest associated value.
    """
    
    value_hash = name_record.get('value_hash', '')
    if value_hash is None:
        value_hash = ''
        
    name_string = (name + name_record['owner'] + value_hash).encode('utf8')
    return name_string


def calculate_merkle_snapshot(db):
    """
    Calculate the current Merkle snapshot of the set of blockstore operations.
    The Merkle tree is constructed by joining the lists of [hash(name.ns_id.script_pubkey.value_hash), hash1, hash2, ...],
    ordered by name.nsid.  The sequence of hash1, hash2, ... are sorted alphanumerically.
    
    The intuition behind generating a Merkle tree is that it represents the global state 
    of all name and storage operations that have occurred at this point in the database.
    This is useful for detecting forks in the underlying blockchain--if peers' snapshots diverge,
    then there is a fork going on.  However, it is critical that the Merkle tree covers *all* blockstore
    operations; otherwise, it is possible for the sequence of storage operations to diverge from the 
    sequence of name operations undetected (leading to inconsistencies, like data randomly disappearing or 
    getting transferred to another user).
    """
    
    names = sorted(db.name_records)
    signed_data = sorted(db.signed_data)
    
    hashes = []
    
    for name in names:
        
        name_string = name_record_to_string(name, db.name_records[name])
        name_string_hash = hexlify(bin_double_sha256(name_string))
        hashes.append(name_string_hash)
        
        # data this name owns 
        data_hashes = sorted( db.signed_data.get( name, [] ) )
        hashes += data_hashes
    
    if len(hashes) == 0:
        hashes.append(hexlify(bin_double_sha256("")))
        
    merkle_tree = MerkleTree(hashes)
    merkle_root = merkle_tree.root()
    
    consensus_hash128 = calculate_consensus_hash128(merkle_root)
    
    return consensus_hash128


def record_consensus_hash(db, consensus_hash, block_number):
    """
    Record the consensus hash for a particular block number.
    """
    db.consensus_hashes[str(block_number)] = consensus_hash


def build_nameset(db, blockstore_op_sequence):
    """
    Process the sequence of blockstore operations to derive the 
    current set of all such operations.
    
    blockstore_op_sequence must be a list of (block number, blockstore operation dict)
    """
    
    # set the current consensus hash
    first_block_number = blockstore_op_sequence[0][0]
    db.consensus_hashes[str(first_block_number)] = calculate_merkle_snapshot(db)

    for block_number, blockstore_ops in blockstore_op_sequence:
        
        # accumulate all blockstore operations in this block
        for blockstore_op in blockstore_ops:
            try:
                log_blockstore_op(db, blockstore_op, block_number)
            except Exception as e:
                traceback.print_exc()
                
        # process and tentatively commit the pending operations
        process_pending_ops_in_block(db, block_number)
        
        # clean out the expired names and their associated data
        clean_out_expired_names(db, block_number)
        
        # calculate the merkle snapshot consensus hash
        consensus_hash128 = calculate_merkle_snapshot(db)
        
        # record the merkle consensus hash
        record_consensus_hash(db, consensus_hash128, block_number)

    # set the current consensus hash for the set of names
    db.consensus_hashes['current'] = consensus_hash128
    
    # return the current consensus hash
    return consensus_hash128


def nulldata_txs_to_blockstore_ops(txs):
    """
    Given a list of transactions, extract the nulldata from the transaction's script 
    and construct a blockstore operation.  Importantly, obtain the fee and list of senders.
    
    Return a list of blockstore operations, where each blockstore operation is a dict which optionally has:
      * "sender": the hex string of the primary sender's script_pubkey
      * "fee": the total amount paid
    """
    
    ops = []
    for tx in txs:
        blockstore_op = None
        try:
            blockstore_op = parse_blockstore_op( tx['nulldata'], tx['vout'], senders=tx['senders'], fee=tx['fee'] )
        except Exception, e:
            traceback.print_exc()
            pass
        else:
            if blockstore_op is not None:
                ops.append(blockstore_op)
                
    return ops
 

def get_blockstore_ops_in_blocks( workpool, blocks ):
    """
    Get the full list of blockstore operations for a set of blocks (where 'blocks' is a list of integer block IDs)
    Return the list of blockstore operations, extracted from transaction nulldata.
    """
    
    current_nulldata_txs = get_nulldata_txs_in_blocks( workpool, blocks )
    all_blockstore_ops = []
    
    for (block_number, txs) in current_nulldata_txs:
       blockstore_ops = nulldata_txs_to_blockstore_ops(txs)
       all_blockstore_ops += [(block_number, blockstore_ops)]
       
    return all_blockstore_ops
 
"""
def get_nameops_in_block( bitcoind, block_number ):
    current_nulldata_txs = get_nulldata_txs_in_block( bitcoind, block_number )
    nameops = nulldata_txs_to_nameops(current_nulldata_txs)
    return nameops
"""


"""
# DEPRECATED 
def get_nameops_in_block_range(bitcoind, first_block=0, last_block=None):
    nameop_sequence = []

    if not last_block:
        last_block = bitcoind.getblockcount()

    for block_number in range(first_block, last_block + 1):
        block_nameops = get_nameops_in_block(bitcoind, block_number)
        nameop_sequence.append((block_number, block_nameops))

    return nameop_sequence
"""
