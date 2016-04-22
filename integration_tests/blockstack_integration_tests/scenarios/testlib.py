#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack

    Blockstack is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
"""

# test lib to bind a test scenario to blockstack 

import os
import sys
import tempfile
import errno
import shutil
import bitcoin
import sys
import copy
import json
import gnupg

import blockstack.blockstackd as blockstackd

import blockstack_client
from blockstack_client.actions import *
import blockstack
import pybitcoin
from pybitcoin.transactions.outputs import calculate_change_amount

import virtualchain

log = virtualchain.get_logger("testlib")

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

        client_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
        assert client_path is not None

        client_config = blockstack_client.get_config(client_path)
        
        self.client = blockstack_client.BlockstackRPCClient( client_config['server'], client_config['port'] )
        self.config_path = client_path
        self.conf = {
            "start_block": blockstack.FIRST_BLOCK_MAINNET,
            "initial_utxos": utxo_opts,
            "storage_drivers": client_config['storage_drivers'],
            "metadata": client_config['metadata']
        }
        self.spv_headers_path = utxo_opts['spv_headers_path']

        if not os.path.exists(self.conf['metadata']):
            os.makedirs(self.conf['metadata'], 0700)

    def __getattr__(self, name):
        
        try:
            def inner(*args, **kw):
                c = getattr( self.client, name)
                r = c(*args, **kw)
                return [r]

            return inner
        except Exception, e:
            log.exception(e)
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

# names we expect will fail SNV, at a particular block 
snv_fail_at = {}

class CLIArgs(object):
    pass

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


def expect_snv_fail_at( name, block_id ):
    """
    Record that this name will not be SNV-lookup-able
    """
    global snv_fail_at

    if name not in snv_fail_at.keys():
        snv_fail_at[block_id] = [name]
    else:
        snv_fail_at[block_id].append(name)


def make_proxy():
    """
    Create a blockstack client API proxy
    """
    global utxo_opts

    client_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    assert client_path is not None

    client_config = blockstack_client.get_config(client_path)

    proxy = blockstack_client.session( server_host=client_config['server'], server_port=client_config['port'], storage_drivers=client_config['storage_drivers'], \
                                       metadata_dir=client_config['metadata'], spv_headers_path=utxo_opts['spv_headers_path'] )

    proxy.config_path = client_path
    return proxy


def blockstack_name_preorder( name, privatekey, register_addr, tx_only=False, subsidy_key=None, testset=False, consensus_hash=None ):

    global api_call_history 

    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.preorder_tx( name, privatekey, register_addr )
    elif subsidy_key is not None:
        resp = test_proxy.preorder_tx_subsidized( name, register_addr, subsidy_key )
    else:
        resp = test_proxy.preorder( name, privatekey, register_addr )

    api_call_history.append( APICallRecord( "preorder", name, resp ) )
    return resp


def blockstack_name_preorder_multi( names, privatekey, register_addrs, tx_only=False, subsidy_key=None, testset=False, consensus_hash=None ):
    
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )
    
    if tx_only:
        resp = test_proxy.preorder_multi_tx( names, privatekey, register_addrs )
    elif subsidy_key is not None:
        resp = test_proxy.preorder_multi_tx_subsidized( names, None, register_addrs, subsidy_key )
    else:
        resp = test_proxy.preorder_multi( names, privatekey, register_addrs )

    api_call_history.append( APICallRecord( "preorder_multi", name, resp ) )
    return resp


def blockstack_name_register( name, privatekey, register_addr, renewal_fee=None, tx_only=False, subsidy_key=None, user_public_key=None, testset=False, consensus_hash=None ):
    
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.register_tx( name, privatekey, register_addr )
    elif subsidy_key is not None:
        resp = test_proxy.register_tx_subsidized( name, privatekey, register_addr, subsidy_key )
    else:
        resp = test_proxy.register( name, privatekey, register_addr )

    api_call_history.append( APICallRecord( "register", name, resp ) )
    return resp


def blockstack_name_update( name, data_hash, privatekey, user_public_key=None, tx_only=False, subsidy_key=None, testset=False, consensus_hash=None, test_api_proxy=True ):
    
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    if not test_api_proxy:
        resp = blockstackd.blockstack_name_update( name, data_hash, privatekey, tx_only=tx_only, subsidy_key=subsidy_key, user_public_key=user_public_key, testset=testset, consensus_hash=consensus_hash )

    else:
        if tx_only:
            resp = test_proxy.update_tx( name, data_hash, privatekey )
        elif subsidy_key is not None:
            resp = test_proxy.update_tx_subsidized( name, data_hash, user_public_key, subsidy_key )
        else:
            resp = test_proxy.update( name, data_hash, privatekey )

    api_call_history.append( APICallRecord( "update", name, resp ) )
    return resp


def blockstack_name_transfer( name, address, keepdata, privatekey, tx_only=False, user_public_key=None, subsidy_key=None, testset=False, consensus_hash=None ):
     
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.transfer_tx( name, address, keepdata, privatekey )
    elif subsidy_key is not None:
        resp = test_proxy.transfer_tx_subsidized( name, address, keepdata, user_public_key, subsidy_key )
    else:
        resp = test_proxy.transfer( name, address, keepdata, privatekey )

    api_call_history.append( APICallRecord( "transfer", name, resp ) )
    return resp


def blockstack_name_renew( name, privatekey, register_addr=None, tx_only=False, subsidy_key=None, user_public_key=None, testset=False, consensus_hash=None ):
    
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.renew_tx( name, privatekey )
    elif subsidy_key is not None:
        resp = test_proxy.renew_tx_subsidized( name, user_public_key, subsidy_key )
    else:
        resp = test_proxy.renew( name, privatekey )

    api_call_history.append( APICallRecord( "renew", name, resp ) )
    return resp


def blockstack_name_revoke( name, privatekey, tx_only=False, subsidy_key=None, user_public_key=None, testset=False, consensus_hash=None ):
    
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.revoke_tx( name, privatekey )
    elif subsidy_key is not None:
        resp = test_proxy.revoke_tx_subsidized( name, user_public_key, subsidy_key )
    else:
        resp = test_proxy.revoke( name, privatekey )

    api_call_history.append( APICallRecord( "revoke", name, resp ) )
    return resp


def blockstack_name_import( name, recipient_address, update_hash, privatekey, tx_only=False, testset=False, consensus_hash=None ):
    
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.name_import_tx( name, recipient_address, update_hash, privatekey )
    else:
        resp = test_proxy.name_import( name, recipient_address, update_hash, privatekey )

    api_call_history.append( APICallRecord( "name_import", name, resp ) )
    return resp


def blockstack_namespace_preorder( namespace_id, register_addr, privatekey, tx_only=False, testset=False, consensus_hash=None ):
    
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.namespace_preorder_tx( namespace_id, register_addr, privatekey )
    else:
        resp = test_proxy.namespace_preorder( namespace_id, register_addr, privatekey )

    api_call_history.append( APICallRecord( "namespace_preorder", namespace_id, resp ) )
    return resp


def blockstack_namespace_reveal( namespace_id, register_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, privatekey, tx_only=False, testset=False, consensus_hash=None ):
    
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.namespace_reveal_tx( namespace_id, register_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, privatekey )
    else:
        resp = test_proxy.namespace_reveal( namespace_id, register_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, privatekey )

    api_call_history.append( APICallRecord( "namespace_reveal", namespace_id, resp ) )
    return resp


def blockstack_namespace_ready( namespace_id, privatekey, tx_only=False, testset=False, consensus_hash=None ):
    
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.namespace_ready_tx( namespace_id, privatekey )
    else:
        resp = test_proxy.namespace_ready( namespace_id, privatekey )

    api_call_history.append( APICallRecord( "namespace_ready", namespace_id, resp ) )
    return resp


def blockstack_announce( message, privatekey, tx_only=False, user_public_key=None, subsidy_key=None, testset=False ):
    
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    if tx_only:
        resp = test_proxy.announce_tx( message, privatekey )
    elif subsidy_key is not None:
        resp = test_proxy.announce_tx_subsidized( message, user_public_key, subsidy_key )
    else:
        resp = test_proxy.announce( message, privatekey )

    api_call_history.append( APICallRecord( "announce", message, resp ) )
    return resp


def blockstack_client_initialize_wallet( master_privkey_wif, password, transfer_amount ):
    """
    Set up the client wallet
    """
    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    assert config_path is not None

    pk_hex = pybitcoin.BitcoinPrivateKey( master_privkey_wif ).to_hex()

    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join( config_dir, blockstack_client.config.WALLET_PATH )

    blockstack_client.wallet.initialize_wallet( password=password, hex_privkey=pk_hex, interactive=False, wallet_path=wallet_path )
    
    # fund the payment address
    payment_addr_info = blockstack_client.get_payment_addresses( wallet_path=wallet_path )
    payment_addr = str(payment_addr_info[0]['address'])
    master_pkey = pybitcoin.BitcoinPrivateKey( master_privkey_wif )
    master_addr = master_pkey.public_key().address()

    inputs = get_unspents( master_addr )
    change = calculate_change_amount( inputs, transfer_amount, 8000 )

    outputs = [
        {
            "script_hex": pybitcoin.make_pay_to_address_script(payment_addr),
            "value": transfer_amount
        },
        {
            "script_hex": pybitcoin.make_pay_to_address_script(master_addr),
            "value": change
        }
    ]

    tx_data = blockstack.tx_serialize_and_sign( inputs, outputs, master_pkey )
    broadcast_transaction( tx_data )
    
    return True
   

def blockstack_client_get_wallet():
    """
    Get the wallet from the running RPC daemon
    """
    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    assert config_path is not None

    wallet = blockstack_client.wallet.get_wallet( config_path )
    return wallet


def blockstack_client_queue_state():
    """
    Get queue information from the client backend
    """
    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    assert config_path is not None
   
    conf = blockstack_client.get_config(config_path)
    queue_info = blockstack_client.backend.queue.get_queue_state( path=conf['queue_path'])
    return queue_info


def blockstack_rpc_register( name, password ):
    """
    Register a name, using the backend RPC endpoint
    """
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    args = CLIArgs()
    args.name = name
    resp = cli_register( args, config_path=test_proxy.config_path, password=password, interactive=False, proxy=test_proxy )
    return resp


def blockstack_verify_database( consensus_hash, consensus_block_id, db_path, working_db_path=None, start_block=None, testset=False ):
    return blockstackd.verify_database( consensus_hash, consensus_block_id, db_path, working_db_path=working_db_path, start_block=start_block, testset=testset )


def blockstack_export_db( path, **kw ):
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
    inputs, outputs, locktime, version = blockstack.tx_deserialize( tx_hex )
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
    the blockstack db with the virtual chain
    """

    global snapshots_dir, bitcoind
    
    if snapshots_dir is None:
        snapshots_dir = tempfile.mkdtemp( prefix='blockstack-test-databases-' )

    # flush all transactions
    bitcoind.flush_transactions() 
    kw['sync_virtualchain_upcall']()

    # snapshot the database
    blockstack_export_db( os.path.join( snapshots_dir, "blockstack.db.%s" % get_current_block( **kw )), **kw )
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
        untrusted_db_path = os.path.join( snapshots_dir, "blockstack.db.%s" % block_id )

        working_db_dir = os.path.join( snapshots_dir, "work.%s" % block_id )
        os.makedirs( working_db_dir )

        os.environ["VIRTUALCHAIN_WORKING_DIR"] = working_db_dir
        working_db_path = os.path.join( working_db_dir, "blockstack.db.%s" % block_id )
        
        print "\n\nverify %s - %s (%s), expect %s\n\n" % (block_ids[0], block_id+1, untrusted_db_path, expected_consensus_hash)

        valid = blockstack_verify_database( expected_consensus_hash, block_id, untrusted_db_path, working_db_path=working_db_path, start_block=block_ids[0] )
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
    global snv_fail_at

    test_proxy = TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )

    all_names = {}  # map name to {"block_id":..., "consensus_hash":...}

    for api_call in api_call_history:

        log.debug("API call: %s %s at %s" % (api_call.method, api_call.name, api_call.block_id))

        name = None
        opcode = None

        if api_call.method.startswith("register") and not api_call.method.startswith("register_multi"):
            name = api_call.name
            opcode = "NAME_REGISTRATION"

        elif api_call.method.startswith("name_import"):
            name = api_call.name
            opcode = "NAME_IMPORT"
            
        if name is not None:
            block_id = int(api_call.block_id)
            consensus_hash = all_consensus_hashes[ block_id ]

            if not all_names.has_key( name ):
                all_names[name] = {}
                
            all_names[name][block_id] = {
                "consensus_hash": consensus_hash,
                "opcode": opcode
            }

            if api_call.result.has_key('transaction_hash'):
                all_names[name][block_id]['txid'] = api_call.result['transaction_hash']


    log.debug("SNV verify %s names" % len(all_names.keys()))

    for name in all_names.keys():

        for block_id in all_names[name].keys():

            consensus_hash = all_names[name][block_id]['consensus_hash']
            txid = all_names[name][block_id].get('txid', None)
            opcode = all_names[name][block_id].get('opcode', None)

            log.debug("SNV verify %s (from %s)" % (name, block_id))

            for i in xrange( block_id + 1, max(all_consensus_hashes.keys()) + 1 ):

                trusted_block_id = i
                trusted_consensus_hash = all_consensus_hashes[i]

                snv_rec = blockstack_client.snv_lookup( name, block_id, trusted_consensus_hash, proxy=test_proxy )
                if 'error' in snv_rec:
                    if name in snv_fail:
                        log.debug("SNV lookup %s failed as expected" % name)
                        continue 

                    if name in snv_fail_at.get(block_id, []):
                        log.debug("SNV lookup %s failed at %s as expected" % (name, block_id))
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

                # QUIRK: if imported, then the fee must be a float.  otherwise, it must be an int 
                if snv_rec['opcode'] == 'NAME_IMPORT' and type(snv_rec['op_fee']) != float:
                    print "QUIRK: NAME_IMPORT: fee isn't a float"
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

def gpg_key_dir( **kw ):
    return os.path.join( kw['working_dir'], "keys" )

def make_gpg_test_keys(num_keys, **kw ):
    """
    Set up a test gpg keyring directory.
    Return the list of key fingerprints.
    """
    keydir = gpg_key_dir( **kw )
    gpg = gnupg.GPG( gnupghome=keydir )
    ret = []

    for i in xrange(0, num_keys):
        print "Generating GPG key %s" % i
        key_input = gpg.gen_key_input()
        key_res = gpg.gen_key( key_input )
        ret.append( key_res.fingerprint )

    return ret

def get_gpg_key( key_id, **kw ):
    """
    Get the GPG key 
    """
    keydir = os.path.join(kw['working_dir'], "keys")
    gpg = gnupg.GPG( gnupghome=keydir )
    keydat = gpg.export_keys( [key_id] )
    return keydat
    

def put_test_data( relpath, data, **kw ):
    """
    Put test-specific data to disk
    """
    path = os.path.join( kw['working_dir'], relpath )
    with open(relpath, 'w') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

    return True
