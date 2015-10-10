#!/usr/bin/env python

# test lib to bind a test scenario to blockstore 

import os
import sys

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


def next_block( **kw ):
    """
    Advance the mock blockchain by one block.
    Required keyword arguments:
    * bitcoind: the mock bitcoind
    * sync_virtualchain_upcall: a no-argument callable that will sync
    the blockstore db with the virtual chain
    """
    
    kw['bitcoind'].flush_transactions() 
    kw['sync_virtualchain_upcall']()

   
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
