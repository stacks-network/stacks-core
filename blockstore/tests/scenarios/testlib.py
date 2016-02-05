#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstore

    Blockstore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore. If not, see <http://www.gnu.org/licenses/>.
"""

# test lib to bind a test scenario to blockstore 

import os
import sys
import tempfile
import errno
import shutil
import bitcoin
import sys
import copy
import json

# hack around absolute paths
current_dir =  os.path.abspath(os.path.dirname(__file__) + "/../../..")
sys.path.insert(0, current_dir)

import blockstore.blockstored as blockstored

import blockstore_client
import blockstore
import pybitcoin

import virtualchain

if not globals().has_key('log'):
    log = virtualchain.session.log

class Wallet(object):
    def __init__(self, pk_wif, value_str ):
        pk = pybitcoin.BitcoinPrivateKey( pk_wif )

        self._pk = pk
        self.privkey = pk_wif
        self.pubkey_hex = pk.public_key().to_hex()
        self.addr = pk.public_key().address()
        self.value = int(value_str)


class APICallRecord(object):
    def __init__(self, method, name, result ):
        self.block_id = max(all_consensus_hashes.keys()) + 1
        self.name = name
        self.method = method
        self.result = result


class TestAPIProxy(object):
    def __init__(self):
        global utxo_opts
        self.api = blockstore.blockstored.BlockstoredRPC()
        self.conf = {
            "start_block": blockstore.FIRST_BLOCK_MAINNET,
            "initial_utxos": utxo_opts
        }
        self.spv_headers_path = utxo_opts['spv_headers_path']

    def __getattr__(self, name):
        
        if hasattr( self.api, "jsonrpc_" + name):
            def inner(*args, **kw):
                c = getattr( self.api, "jsonrpc_" + name)
                r = c(*args, **kw)
                return [r]

            return inner
        else:
            raise Exception("No such attribute or API call: '%s'" % name)


# store the database after each block, under this directory
snapshots_dir = None

# bitcoind connection 
bitcoind = None 

# utxo connection
utxo_client = None

# initial utxos and options 
utxo_opts = None

# state engine ref
state_engine = None

# consensus hash at each block
all_consensus_hashes = {}

# API call history 
api_call_history = []

# names we expect will fail SNV 
snv_fail = []

def log_consensus( **kw ):
    """
    Log the consensus hash at the current block.
    """
    global all_consensus_hashes 

    block_id = get_current_block( **kw ) 
    ch = get_consensus_at( block_id, **kw )
    all_consensus_hashes[ block_id ] = ch


def expect_snv_fail( name ):
    """
    Record that this name will not be SNV-lookup-able
    """
    global snv_fail
    snv_fail.append( name )


def make_proxy():
    """
    Create a blockstore client API proxy
    """
    global utxo_opts
    proxy = blockstore_client.client.session( server_host="localhost", server_port=6264, storage_drivers="disk", \
                                              metadata_dir=None, spv_headers_path=utxo_opts['spv_headers_path'] )

    return proxy


def blockstore_name_preorder( name, privatekey, register_addr, tx_only=False, subsidy_key=None, testset=False, consensus_hash=None ):

    global api_call_history 

    test_proxy = make_proxy()
    blockstore_client.client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.preorder_tx( name, privatekey, register_addr )
    elif subsidy_key is not None:
        resp = test_proxy.preorder_tx_subsidized( name, register_addr, subsidy_key )
    else:
        resp = test_proxy.preorder( name, privatekey, register_addr )

    api_call_history.append( APICallRecord( "preorder", name, resp ) )
    return resp


def blockstore_name_preorder_multi( names, privatekey, register_addrs, tx_only=False, subsidy_key=None, testset=False, consensus_hash=None ):
    
    test_proxy = make_proxy()
    blockstore_client.client.set_default_proxy( test_proxy )
    
    if tx_only:
        resp = test_proxy.preorder_multi_tx( names, privatekey, register_addrs )
    elif subsidy_key is not None:
        resp = test_proxy.preorder_multi_tx_subsidized( names, None, register_addrs, subsidy_key )
    else:
        resp = test_proxy.preorder_multi( names, privatekey, register_addrs )

    api_call_history.append( APICallRecord( "preorder_multi", name, resp ) )
    return resp


def blockstore_name_register( name, privatekey, register_addr, renewal_fee=None, tx_only=False, subsidy_key=None, user_public_key=None, testset=False, consensus_hash=None ):
    
    test_proxy = make_proxy()
    blockstore_client.client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.register_tx( name, privatekey, register_addr )
    elif subsidy_key is not None:
        resp = test_proxy.register_tx_subsidized( name, privatekey, register_addr, subsidy_key )
    else:
        resp = test_proxy.register( name, privatekey, register_addr )

    api_call_history.append( APICallRecord( "register", name, resp ) )
    return resp


def blockstore_name_update( name, data_hash, privatekey, user_public_key=None, tx_only=False, subsidy_key=None, testset=False, consensus_hash=None, test_api_proxy=True ):
    
    test_proxy = make_proxy()
    blockstore_client.client.set_default_proxy( test_proxy )

    if not test_api_proxy:
        resp = blockstored.blockstore_name_update( name, data_hash, privatekey, tx_only=tx_only, subsidy_key=subsidy_key, user_public_key=user_public_key, testset=testset, consensus_hash=consensus_hash )

    else:
        if tx_only:
            resp = test_proxy.update_tx( name, data_hash, privatekey )
        elif subsidy_key is not None:
            resp = test_proxy.update_tx_subsidized( name, data_hash, user_public_key, subsidy_key )
        else:
            resp = test_proxy.update( name, data_hash, privatekey )

    api_call_history.append( APICallRecord( "update", name, resp ) )
    return resp


def blockstore_name_transfer( name, address, keepdata, privatekey, tx_only=False, user_public_key=None, subsidy_key=None, testset=False, consensus_hash=None ):
     
    test_proxy = make_proxy()
    blockstore_client.client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.transfer_tx( name, address, keepdata, privatekey )
    elif subsidy_key is not None:
        resp = test_proxy.transfer_tx_subsidized( name, address, keepdata, user_public_key, subsidy_key )
    else:
        resp = test_proxy.transfer( name, address, keepdata, privatekey )

    api_call_history.append( APICallRecord( "transfer", name, resp ) )
    return resp


def blockstore_name_renew( name, privatekey, register_addr=None, tx_only=False, subsidy_key=None, user_public_key=None, testset=False, consensus_hash=None ):
    
    test_proxy = make_proxy()
    blockstore_client.client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.renew_tx( name, privatekey )
    elif subsidy_key is not None:
        resp = test_proxy.renew_tx_subsidized( name, user_public_key, subsidy_key )
    else:
        resp = test_proxy.renew( name, privatekey )

    api_call_history.append( APICallRecord( "renew", name, resp ) )
    return resp


def blockstore_name_revoke( name, privatekey, tx_only=False, subsidy_key=None, user_public_key=None, testset=False, consensus_hash=None ):
    
    test_proxy = make_proxy()
    blockstore_client.client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.revoke_tx( name, privatekey )
    elif subsidy_key is not None:
        resp = test_proxy.revoke_tx_subsidized( name, user_public_key, subsidy_key )
    else:
        resp = test_proxy.revoke( name, privatekey )

    api_call_history.append( APICallRecord( "revoke", name, resp ) )
    return resp


def blockstore_name_import( name, recipient_address, update_hash, privatekey, tx_only=False, testset=False, consensus_hash=None ):
    
    test_proxy = make_proxy()
    blockstore_client.client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.name_import_tx( name, recipient_address, update_hash, privatekey )
    else:
        resp = test_proxy.name_import( name, recipient_address, update_hash, privatekey )

    api_call_history.append( APICallRecord( "name_import", name, resp ) )
    return resp


def blockstore_namespace_preorder( namespace_id, register_addr, privatekey, tx_only=False, testset=False, consensus_hash=None ):
    
    test_proxy = make_proxy()
    blockstore_client.client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.namespace_preorder_tx( namespace_id, register_addr, privatekey )
    else:
        resp = test_proxy.namespace_preorder( namespace_id, register_addr, privatekey )

    api_call_history.append( APICallRecord( "namespace_preorder", namespace_id, resp ) )
    return resp


def blockstore_namespace_reveal( namespace_id, register_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, privatekey, tx_only=False, testset=False, consensus_hash=None ):
    
    test_proxy = make_proxy()
    blockstore_client.client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.namespace_reveal_tx( namespace_id, register_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, privatekey )
    else:
        resp = test_proxy.namespace_reveal( namespace_id, register_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, privatekey )

    api_call_history.append( APICallRecord( "namespace_reveal", namespace_id, resp ) )
    return resp


def blockstore_namespace_ready( namespace_id, privatekey, tx_only=False, testset=False, consensus_hash=None ):
    
    test_proxy = make_proxy()
    blockstore_client.client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.namespace_ready_tx( namespace_id, privatekey )
    else:
        resp = test_proxy.namespace_ready( namespace_id, privatekey )

    api_call_history.append( APICallRecord( "namespace_ready", namespace_id, resp ) )
    return resp


def blockstore_announce( message, privatekey, tx_only=False, user_public_key=None, subsidy_key=None, testset=False ):
    
    test_proxy = make_proxy()
    blockstore_client.client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.announce_tx( message, privatekey )
    elif subsidy_key is not None:
        resp = test_proxy.announce_tx_subsidized( message, user_public_key, subsidy_key )
    else:
        resp = test_proxy.announce( message, privatekey )

    api_call_history.append( APICallRecord( "announce", message, resp ) )
    return resp


def blockstore_verify_database( consensus_hash, consensus_block_id, db_path, working_db_path=None, start_block=None, testset=False ):
    return blockstored.verify_database( consensus_hash, consensus_block_id, db_path, working_db_path=working_db_path, start_block=start_block, testset=testset )


def blockstore_export_db( path, **kw ):
    global state_engine
    try:
        state_engine.export_db( path )
    except IOError, ie:
        if ie.errno == errno.ENOENT:
            pass
        else:
            raise


def tx_sign_all_unsigned_inputs( tx_hex, privkey ):
    """
    Sign a serialized transaction's unsigned inputs
    """
    inputs, outputs, locktime, version = blockstore.tx_deserialize( tx_hex )
    for i in xrange( 0, len(inputs)):
        if len(inputs[i]['script_sig']) == 0:
            tx_hex = bitcoin.sign( tx_hex, i, privkey )

    return tx_hex


def sendrawtransaction( tx_hex, **kw ):
    """
    Send a raw transaction to the mock bitcoind
    """
    global bitcoind
    return bitcoind.sendrawtransaction( tx_hex )


def getrawtransaction( txid, verbose, **kw ):
    """
    Get a raw transaction from the mock bitcoind
    """
    global bitcoind
    return bitcoind.getrawtransaction( txid, verbose )


def get_all_transactions( **kw ):
    """
    Get all bitcoind transactions.
    Requires:
    * bitcoind: the mock bitcoind
    """
    global bitcoind
    return bitcoind.getrawtransactions( 1 )


def next_block( **kw ):
    """
    Advance the mock blockchain by one block.
    Required keyword arguments:
    * bitcoind: the mock bitcoind
    * sync_virtualchain_upcall: a no-argument callable that will sync
    the blockstore db with the virtual chain
    """

    global snapshots_dir, bitcoind
    
    if snapshots_dir is None:
        snapshots_dir = tempfile.mkdtemp( prefix='blockstore-test-databases-' )

    # flush all transactions
    bitcoind.flush_transactions() 
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
    global state_engine
    return state_engine.get_consensus_at( block_id )


def get_current_block( **kw ):
    """
    Get the current block id.
    Required keyword arguments:
    * state_engine:  a reference to the virtualchain state engine.
    """
    global state_engine
    return state_engine.get_current_block()


def get_working_dir( **kw ):
    """
    Get the current working directory.
    Requires:
    * working_dir
    """
    return str(kw['working_dir'])


def cleanup():
    """
    Clean up temporary test state.
    """
    
    global snapshots_dir
    global all_consensus_hashes 

    if snapshots_dir is not None:
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

    if snapshots_dir is None:
        # no snapshots to deal with 
        return True

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


def snv_all_names( state_engine ):
    """
    Verify that we can use the consensus hash from each consensus-bearing operation
    to verify all prior name operations.
    """
    global all_consensus_hashes 
    global api_call_history
    global snv_fail

    test_proxy = TestAPIProxy()
    blockstore_client.client.set_default_proxy( test_proxy )

    all_names = {}  # map name to {"block_id":..., "consensus_hash":...}

    for api_call in api_call_history:

        log.debug("API call: %s %s" % (api_call.method, api_call.name))

        name = None
        opcode = None

        if api_call.method.startswith("register") and not api_call.method.startswith("register_multi"):
            name = api_call.name
            opcode = "NAME_REGISTRATION"

        elif api_call.method.startswith("name_import"):
            name = api_call.name
            opcode = "NAME_IMPORT"
            
        if name is not None:
            block_id = api_call.block_id 
            consensus_hash = all_consensus_hashes[ block_id ]

            all_names[ name ] = {
                "block_id": block_id,
                "consensus_hash": consensus_hash,
                "opcode": opcode
            }

            if api_call.result.has_key('transaction_hash'):
                all_names[name]['txid'] = api_call.result['transaction_hash']


    log.debug("SNV verify %s names" % len(all_names.keys()))

    for name in all_names.keys():

        log.debug("SNV verify %s" % name)

        block_id = all_names[name]['block_id']
        consensus_hash = all_names[name]['consensus_hash']
        txid = all_names[name].get('txid', None)
        opcode = all_names[name].get('opcode', None)

        for i in xrange( block_id + 1, max(all_consensus_hashes.keys()) + 1 ):

            trusted_block_id = i
            trusted_consensus_hash = all_consensus_hashes[i]

            snv_rec = blockstore_client.client.snv_lookup( name, block_id, trusted_consensus_hash, proxy=test_proxy )
            if 'error' in snv_rec:
                if name in snv_fail:
                    log.debug("SNV lookup %s failed as expected" % name)
                    continue 

                print json.dumps(snv_rec, indent=4 )
                return False 

            if snv_rec['name'] != name:
                print "mismatch name"
                print json.dumps(snv_rec, indent=4 )
                return False 

            if opcode is not None and snv_rec['opcode'] != opcode:
                print "mismatch opcode"
                print json.dumps(snv_rec, indent=4 )
                return False 

            if name in snv_fail:
                print "looked up name '%s' that was supposed to fail SNV" % name
                return False 

            log.debug("SNV verified %s with (%s,%s) back to (%s,%s)" % (name, trusted_block_id, trusted_consensus_hash, block_id, consensus_hash ))

    return True


def get_unspents( addr ):
    """
    Get the list of unspent outputs for an address.
    """
    global utxo_client
    return pybitcoin.get_unspents( addr, utxo_client )


def broadcast_transaction( tx_hex ):
    """
    Send out a raw transaction to the mock framework.
    """
    global utxo_client
    return pybitcoin.broadcast_transaction( tx_hex, utxo_client )


def decoderawtransaction( tx_hex ):
    """
    Decode a raw transaction 
    """
    global bitcoind
    return bitcoind.decoderawtransaction( tx_hex )

# setters for the test enviroment
def set_utxo_client( c ):
    global utxo_client
    utxo_client = c

def set_utxo_opts( opts ):
    global utxo_opts 
    utxo_opts = opts

def set_bitcoind( b ):
    global bitcoind
    bitcoind = b

def set_state_engine( s ):
    global state_engine
    state_engine = s

# getters for the test environment
def get_utxo_client():
    global utxo_client
    return utxo_client

def get_bitcoind():
    global bitcoind
    return bitcoind

def get_state_engine():
    global state_engine
    return state_engine
