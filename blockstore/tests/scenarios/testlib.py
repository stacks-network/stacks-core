#!/usr/bin/env python

# test lib to bind a test scenario to blockstore 

import os
import sys
import tempfile
import errno
import shutil

# hack around absolute paths
current_dir =  os.path.abspath(os.path.dirname(__file__) + "/../../..")
sys.path.insert(0, current_dir)

import blockstore.blockstored as blockstored
import pybitcoin

class Wallet(object):
    def __init__(self, pk_wif, value_str ):
        pk = pybitcoin.BitcoinPrivateKey( pk_wif )

        self._pk = pk
        self.privkey = pk_wif
        self.pubkey_hex = pk.public_key().to_hex()
        self.addr = pk.public_key().address()
        self.value = int(value_str)

# store the database after each block, under this directory
snapshots_dir = None

# consensus hash at each block
all_consensus_hashes = {}

def log_consensus( **kw ):
    """
    Log the consensus hash at the current block.
    """
    global all_consensus_hashes 

    block_id = get_current_block( **kw ) 
    ch = get_consensus_at( block_id, **kw )
    all_consensus_hashes[ block_id ] = ch


def blockstore_name_preorder( name, privatekey, register_addr, tx_only=False, pay_fee=True, subsidy_key=None, public_key=None, testset=False, consensus_hash=None ):
    resp = blockstored.blockstore_name_preorder( name, privatekey, register_addr, tx_only=tx_only, pay_fee=pay_fee, subsidy_key=subsidy_key, public_key=public_key, testset=testset, consensus_hash=consensus_hash )
    return resp


def blockstore_name_register( name, privatekey, register_addr, renewal_fee=None, tx_only=False, pay_fee=True, subsidy_key=None, public_key=None, testset=False, consensus_hash=None ):
    resp = blockstored.blockstore_name_register( name, privatekey, register_addr, renewal_fee=renewal_fee, tx_only=tx_only, pay_fee=pay_fee, subsidy_key=subsidy_key, public_key=public_key, testset=testset, consensus_hash=consensus_hash)
    return resp


def blockstore_name_update( name, data_hash, privatekey, tx_only=False, pay_fee=True, public_key=None, subsidy_key=None, testset=False, consensus_hash=None ):
    resp = blockstored.blockstore_name_update( name, data_hash, privatekey, tx_only=tx_only, pay_fee=pay_fee, subsidy_key=subsidy_key, public_key=public_key, testset=testset, consensus_hash=consensus_hash )
    return resp


def blockstore_name_transfer( name, address, keepdata, privatekey, public_key=None, subsidy_key=None, tx_only=False, pay_fee=True, testset=False, consensus_hash=None ):
    resp = blockstored.blockstore_name_transfer( name, address, keepdata, privatekey, tx_only=tx_only, pay_fee=pay_fee, subsidy_key=subsidy_key, public_key=public_key, testset=testset, consensus_hash=consensus_hash )
    return resp


def blockstore_name_renew( name, privatekey, tx_only=False, pay_fee=True, subsidy_key=None, public_key=None, testset=False, consensus_hash=None ):
    resp = blockstored.blockstore_name_renew( name, privatekey, tx_only=tx_only, pay_fee=pay_fee, subsidy_key=subsidy_key, public_key=public_key, testset=testset, consensus_hash=consensus_hash )
    return resp


def blockstore_name_revoke( name, privatekey, tx_only=False, pay_fee=True, subsidy_key=None, public_key=None, testset=False, consensus_hash=None ):
    resp = blockstored.blockstore_name_revoke( name, privatekey, tx_only=tx_only, pay_fee=pay_fee, subsidy_key=subsidy_key, public_key=public_key, testset=testset, consensus_hash=consensus_hash )
    return resp


def blockstore_name_import( name, recipient_address, update_hash, privatekey, tx_only=False, testset=False, consensus_hash=None ):
    resp = blockstored.blockstore_name_import( name, recipient_address, update_hash, privatekey, tx_only=tx_only, testset=testset, consensus_hash=consensus_hash )
    return resp


def blockstore_namespace_preorder( namespace_id, register_addr, privatekey, tx_only=False, testset=False, consensus_hash=None ):
    resp = blockstored.blockstore_namespace_preorder( namespace_id, register_addr, privatekey, tx_only=tx_only, testset=testset, consensus_hash=consensus_hash )
    return resp


def blockstore_namespace_reveal( namespace_id, register_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, privatekey, tx_only=False, testset=False, consensus_hash=None ):
    resp = blockstored.blockstore_namespace_reveal( namespace_id, register_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, privatekey, tx_only=tx_only, testset=testset, consensus_hash=consensus_hash )
    return resp


def blockstore_namespace_ready( namespace_id, privatekey, tx_only=False, testset=False, consensus_hash=None ):
    resp = blockstored.blockstore_namespace_ready( namespace_id, privatekey, tx_only=tx_only, testset=testset, consensus_hash=consensus_hash )
    return resp


def blockstore_verify_database( consensus_hash, consensus_block_id, db_path, working_db_path=None, start_block=None, testset=False ):
    return blockstored.verify_database( consensus_hash, consensus_block_id, db_path, working_db_path=working_db_path, start_block=start_block, testset=testset )


def blockstore_export_db( path, **kw ):
    db = kw['state_engine']
    try:
        db.export_db( path )
    except IOError, ie:
        if ie.errno == errno.ENOENT:
            pass
        else:
            raise


def get_all_transactions( **kw ):
    """
    Get all bitcoind transactions.
    Requires:
    * bitcoind: the mock bitcoind
    """
    return kw['bitcoind'].getrawtransactions( 1 )


def next_block( **kw ):
    """
    Advance the mock blockchain by one block.
    Required keyword arguments:
    * bitcoind: the mock bitcoind
    * sync_virtualchain_upcall: a no-argument callable that will sync
    the blockstore db with the virtual chain
    """

    global snapshots_dir 
    
    if snapshots_dir is None:
        snapshots_dir = tempfile.mkdtemp( prefix='blockstore-test-databases-' )

    # flush all transactions
    kw['bitcoind'].flush_transactions() 
    kw['sync_virtualchain_upcall']()

    # snapshot the database
    blockstore_export_db( os.path.join( snapshots_dir, "blockstore.db.%s" % get_current_block( **kw )), **kw )
    log_consensus( **kw )

   
def get_consensus_at( block_id, **kw ):
    """
    Get the consensus hash at a particular block id.
    Required keyword arguments:
    * state_engine:  a reference to the virtualchain state engine.
    """

    return kw['state_engine'].get_consensus_at( block_id )


def get_current_block( **kw ):
    """
    Get the current block id.
    Required keyword arguments:
    * state_engine:  a reference to the virtualchain state engine.
    """
    
    return kw['state_engine'].get_current_block()


def cleanup():
    """
    Clean up temporary test state.
    """
    
    global snapshots_dir
    global all_consensus_hashes 

    shutil.rmtree( snapshots_dir )
    snapshots_dir = None
    all_consensus_hashes = {}
    

def check_history( state_engine ):
    """
    Verify that the database is reconstructable and 
    consistent at each point in its history.
    """

    global all_consensus_hashes
    global snapshots_dir

    block_ids = sorted( all_consensus_hashes.keys() )
    db_path = state_engine.get_db_path()

    for block_id in block_ids:
    
        state_engine.lastblock = block_ids[0]
        expected_consensus_hash = all_consensus_hashes[ block_id ]
        untrusted_db_path = os.path.join( snapshots_dir, "blockstore.db.%s" % block_id )
        
        print "\n\nverify %s - %s (%s), expect %s\n\n" % (block_ids[0], block_id+1, untrusted_db_path, expected_consensus_hash)

        valid = blockstore_verify_database( expected_consensus_hash, block_id, untrusted_db_path )
        if not valid:
            print "Invalid at block %s" % block_id 
            return False

    return True


