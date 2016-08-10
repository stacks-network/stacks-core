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
import blockstack_zones
import time

import blockstack.blockstackd as blockstackd

import blockstack_client
from blockstack_client.actions import *
from blockstack_client.keys import *
import blockstack
import pybitcoin
import keylib
from pybitcoin.transactions.outputs import calculate_change_amount

import virtualchain

log = virtualchain.get_logger("testlib")

class Wallet(object):
    def __init__(self, pk_wif, value_str ):

        pk = virtualchain.BitcoinPrivateKey( pk_wif )

        self._pk = pk

        if pk_wif.startswith("c"):
            # already a private key 
            self.privkey = pk_wif
        else:
            self.privkey = pk.to_wif()

        self.pubkey_hex = pk.public_key().to_hex()                          # coordinate (uncompressed) EC public key
        self.ec_pubkey_hex = keylib.ECPrivateKey(pk_wif).public_key().to_hex()  # parameterized (compressed) EC public key
        self.addr = pk.public_key().address()
        self.value = int(value_str)

        log.debug("Wallet %s (%s)" % (self.privkey, self.addr))


class MultisigWallet(object):
    def __init__(self, m, *pks ):

        self.privkey = virtualchain.make_multisig_info( m, pks )
        self.m = m
        self.n = len(pks)

        self.addr = self.privkey['address']
        self.value = 0

        log.debug("Multisig wallet %s" % (self.addr))


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
            # "initial_utxos": utxo_opts,
            "storage_drivers": client_config['storage_drivers'],
            "metadata": client_config['metadata'],
            "path": client_path
        }
        self.spv_headers_path = utxo_opts['spv_headers_path']

        if not os.path.exists(self.conf['metadata']):
            os.makedirs(self.conf['metadata'], 0700)

    def __getattr__(self, name):
        
        try:
            def inner(*args, **kw):
                rc = None
                # use the UTXO client and mock bitcoind in RAM
                if name == 'get_unspents':
                    r = get_unspents(*args, **kw)

                elif name == 'broadcast_transaction':
                    r = broadcast_transaction(*args, **kw)

                else:
                    c = getattr( self.client, name)
                    r = c(*args, **kw)

                return r

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

# default payment wallet 
default_payment_wallet = None

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


def get_unspents( *args, **kw ):
    utxo_client = get_utxo_client()
    return utxo_client.get_unspents( *args, **kw )


def broadcast_transaction( *args, **kw ):
    utxo_client = get_utxo_client()
    return utxo_client.broadcast_transaction( *args, **kw )


def make_proxy():
    """
    Create a blockstack client API proxy
    """
    client_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    assert client_path is not None

    client_config = blockstack_client.get_config(client_path)
    proxy = blockstack_client.session( conf=client_config )

    proxy.config_path = client_path

    # add in some UTXO goodness 
    proxy.get_unspents = get_unspents
    proxy.broadcast_transaction = broadcast_transaction

    return proxy


def blockstack_name_preorder( name, privatekey, register_addr, wallet=None, subsidy_key=None, consensus_hash=None, safety_checks=False ):

    global api_call_history 

    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    name_cost_info = test_proxy.get_name_cost( name )
    assert 'satoshis' in name_cost_info, "error getting cost of %s: %s" % (name, name_cost_info)

    register_addr = virtualchain.address_reencode(register_addr)

    register_privkey_params = (1,1)
    if wallet is not None:
        register_privkey_params = get_privkey_info_params( wallet.privkey )

    log.debug("Preorder '%s' for %s satoshis" % (name, name_cost_info['satoshis']))

    resp = blockstack_client.do_preorder( name, privatekey, register_addr, name_cost_info['satoshis'], test_proxy, test_proxy, owner_privkey_params=register_privkey_params, consensus_hash=consensus_hash, config_path=test_proxy.config_path, proxy=test_proxy, safety_checks=safety_checks )

    api_call_history.append( APICallRecord( "preorder", name, resp ) )
    return resp


def blockstack_name_register( name, privatekey, register_addr, wallet=None, renewal_fee=None, subsidy_key=None, user_public_key=None, safety_checks=False ):
    
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    register_addr = virtualchain.address_reencode(register_addr)

    register_privkey_params = (1,1)
    if wallet is not None:
        register_privkey_params = get_privkey_info_params( wallet.privkey )

    resp = blockstack_client.do_register( name, privatekey, register_addr, test_proxy, test_proxy, owner_privkey_params=register_privkey_params, renewal_fee=renewal_fee, config_path=test_proxy.config_path, proxy=test_proxy, safety_checks=safety_checks )
    api_call_history.append( APICallRecord( "register", name, resp ) )
    return resp


def blockstack_name_update( name, data_hash, privatekey, user_public_key=None, subsidy_key=None, consensus_hash=None, test_api_proxy=True, safety_checks=False ):
    
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    payment_key = get_default_payment_wallet().privkey
    if subsidy_key is not None:
        payment_key = subsidy_key

    resp = blockstack_client.do_update( name, data_hash, privatekey, payment_key, test_proxy, test_proxy, consensus_hash=consensus_hash, config_path=test_proxy.config_path, proxy=test_proxy, safety_checks=safety_checks )
    api_call_history.append( APICallRecord( "update", name, resp ) )
    return resp


def blockstack_name_transfer( name, address, keepdata, privatekey, user_public_key=None, subsidy_key=None, consensus_hash=None, safety_checks=False ):
     
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    payment_key = get_default_payment_wallet().privkey
    if subsidy_key is not None:
        payment_key = subsidy_key 

    resp = blockstack_client.do_transfer( name, address, keepdata, privatekey, payment_key, test_proxy, test_proxy, consensus_hash=consensus_hash, config_path=test_proxy.config_path, proxy=test_proxy, safety_checks=safety_checks)
    api_call_history.append( APICallRecord( "transfer", name, resp ) )
    return resp


def blockstack_name_renew( name, privatekey, register_addr=None, subsidy_key=None, user_public_key=None, safety_checks=False ):
    
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    name_cost_info = test_proxy.get_name_cost( name )
    if register_addr is None:
        register_addr = get_privkey_info_address(privatekey)
    else:
        assert register_addr == get_privkey_info_address(privatekey)

    payment_key = get_default_payment_wallet().privkey
    if subsidy_key is not None:
        payment_key = subsidy_key 

    log.debug("Renew %s for %s satoshis" % (name, name_cost_info['satoshis']))
    resp = blockstack_client.do_renewal( name, privatekey, payment_key, name_cost_info['satoshis'], test_proxy, test_proxy, config_path=test_proxy.config_path, proxy=test_proxy, safety_checks=safety_checks )

    api_call_history.append( APICallRecord( "renew", name, resp ) )
    return resp


def blockstack_name_revoke( name, privatekey, tx_only=False, subsidy_key=None, user_public_key=None, safety_checks=False ):
    
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    payment_key = get_default_payment_wallet().privkey
    if subsidy_key is not None:
        payment_key = subsidy_key

    resp = blockstack_client.do_revoke( name, privatekey, payment_key, test_proxy, test_proxy, config_path=test_proxy.config_path, proxy=test_proxy, safety_checks=safety_checks )
    api_call_history.append( APICallRecord( "revoke", name, resp ) )
    return resp


def blockstack_name_import( name, recipient_address, update_hash, privatekey, safety_checks=False ):
    
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    resp = blockstack_client.do_name_import( name, privatekey, recipient_address, update_hash, test_proxy, test_proxy, config_path=test_proxy.config_path, proxy=test_proxy, safety_checks=safety_checks )
    api_call_history.append( APICallRecord( "name_import", name, resp ) )
    return resp


def blockstack_namespace_preorder( namespace_id, register_addr, privatekey, consensus_hash=None, safety_checks=False ):
    
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    register_addr = virtualchain.address_reencode(register_addr)

    namespace_cost = test_proxy.get_namespace_cost( namespace_id )
    resp = blockstack_client.do_namespace_preorder( namespace_id, namespace_cost['satoshis'], privatekey, register_addr, test_proxy, test_proxy, consensus_hash=consensus_hash, config_path=test_proxy.config_path, proxy=test_proxy, safety_checks=safety_checks )
    api_call_history.append( APICallRecord( "namespace_preorder", namespace_id, resp ) )
    return resp


def blockstack_namespace_reveal( namespace_id, register_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, privatekey, safety_checks=False ):
    
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    register_addr = virtualchain.address_reencode(register_addr)

    resp = blockstack_client.do_namespace_reveal( namespace_id, register_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, privatekey, test_proxy, test_proxy, config_path=test_proxy.config_path, proxy=test_proxy)
    api_call_history.append( APICallRecord( "namespace_reveal", namespace_id, resp ) )
    return resp


def blockstack_namespace_ready( namespace_id, privatekey, safety_checks=False ):
    
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )
    
    resp = blockstack_client.do_namespace_ready( namespace_id, privatekey, test_proxy, test_proxy, config_path=test_proxy.config_path, proxy=test_proxy, safety_checks=safety_checks ) 
    api_call_history.append( APICallRecord( "namespace_ready", namespace_id, resp ) )
    return resp


def blockstack_announce( message, privatekey, user_public_key=None, subsidy_key=None, safety_checks=False ):
    
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    resp = blockstack_client.do_announce( message, privatekey, test_proxy, test_proxy, config_path=test_proxy.config_path, proxy=test_proxy, safety_checks=safety_checks )
    api_call_history.append( APICallRecord( "announce", message, resp ) )
    return resp


def blockstack_client_initialize_wallet( password, payment_privkey, owner_privkey, data_privkey ):
    """
    Get the wallet from the running RPC daemon
    """
    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    assert config_path is not None

    wallet_path = os.path.join( os.path.dirname(config_path), blockstack_client.config.WALLET_FILENAME )

    wallet = blockstack_client.wallet.make_wallet( password, payment_privkey_info=payment_privkey, owner_privkey_info=owner_privkey, data_privkey_info=data_privkey )
    blockstack_client.wallet.write_wallet( wallet, path=wallet_path )
    return wallet


def blockstack_client_get_wallet():
    """
    Get the wallet from the running RPC daemon
    """
    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    assert config_path is not None

    wallet = blockstack_client.wallet.get_wallet( config_path )
    return wallet


def blockstack_client_set_wallet( password, payment_privkey, owner_privkey, data_privkey ):
    """
    Set the wallet to a runnin RPC daemon
    """
    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    assert config_path is not None

    config_dir = os.path.dirname(config_path)

    wallet = blockstack_client_initialize_wallet( password, payment_privkey, owner_privkey, data_privkey )

    print "\nrestarting RPC daemon\n"
    blockstack_client.rpc.local_rpc_stop(config_dir=config_dir)
    blockstack_client.rpc.local_rpc_ensure_running(config_dir=config_dir, password=password)

    print "\nrestarted RPC daemon; waiting 5 seconds for it to boot\n"

    time.sleep(5)
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


def blockstack_rpc_update( name, zonefile_json, password ):
    """
    Update a name's value hash to point to the new zonefile
    """
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    args = CLIArgs()
    args.name = name
    args.data = zonefile_json 

    resp = cli_update( args, config_path=test_proxy.config_path, password=password )
    return resp


def blockstack_rpc_transfer( name, new_owner_address, password ):
    """
    transfer a name to a new address
    """
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    args = CLIArgs()
    args.name = name
    args.address = new_owner_address

    resp = cli_transfer( args, config_path=test_proxy.config_path, password=password )
    return resp


def blockstack_rpc_renew( name, password ):
    """
    Renew a name, using the backend RPC endpoint
    """
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    args = CLIArgs()
    args.name = name

    resp = cli_renew( args, config_path=test_proxy.config_path, password=password, interactive=False, proxy=test_proxy )
    return resp


def blockstack_rpc_revoke( name, password ):
    """
    Revoke a name, using the backend RPC endpoint
    """
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    args = CLIArgs()
    args.name = name

    resp = cli_revoke( args, config_path=test_proxy.config_path, password=password, interactive=False, proxy=test_proxy )
    return resp


def blockstack_rpc_names():
    """
    Get the list of nams owned by the local wallet
    """
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    args = CLIArgs()
    resp = cli_names( args, config_path=test_proxy.config_path )
    return resp


def blockstack_get_zonefile( zonefile_hash ):
    """
    Get a zonefile from the RPC endpoint
    Return None if not given
    MEANT FOR DIAGNOSTIC PURPOSES ONLY
    """
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    zonefile_result = test_proxy.get_zonefiles( [zonefile_hash] )
    if 'error' in zonefile_result:
        return None

    if zonefile_hash not in zonefile_result['zonefiles'].keys():
        return None

    zonefile = blockstack_zones.parse_zone_file( zonefile_result['zonefiles'][zonefile_hash] )

    # verify
    if zonefile_hash != blockstack_client.hash_zonefile( zonefile ):
        return None

    return blockstack_zones.parse_zone_file( zonefile_result['zonefiles'][zonefile_hash] )


def blockstack_get_profile( name ):
    """
    Get a profile from the RPC endpoint
    Return None if not given
    MEANT FOR DIAGNOSTIC PURPOSES ONLY
    """
    test_proxy = make_proxy()
    blockstack_client.set_default_proxy( test_proxy )

    profile_result = test_proxy.get_profile( name )
    if 'error' in profile_result:
        return None

    if 'profile' not in profile_result or 'status' not in profile_result or not profile_result['status']:
        return None 

    return profile_result['profile']


def blockstack_verify_database( consensus_hash, consensus_block_id, db_path, working_db_path=None, start_block=None ):
    return blockstackd.verify_database( consensus_hash, consensus_block_id, db_path, working_db_path=working_db_path, start_block=start_block )


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
    kw['next_block_upcall']()
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

    for block_id, name_list in snv_fail_at.items():
        log.debug("Expect SNV fail on %s at %s" % (",".join(name_list), block_id))

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

                elif type(snv_rec['op_fee']) not in [int,long]:
                    print "QUIRK: %s: fee isn't an int" % snv_rec['opcode']

                log.debug("SNV verified %s with (%s,%s) back to (%s,%s)" % (name, trusted_block_id, trusted_consensus_hash, block_id, consensus_hash ))

    return True


def get_unspents( addr ):
    """
    Get the list of unspent outputs for an address.
    """
    utxo_provider = get_utxo_client()
    return pybitcoin.get_unspents( addr, utxo_provider )


def broadcast_transaction( tx_hex ):
    """
    Send out a raw transaction to the mock framework.
    """
    utxo_provider = get_utxo_client()
    return pybitcoin.broadcast_transaction( tx_hex, utxo_provider )


def decoderawtransaction( tx_hex ):
    """
    Decode a raw transaction 
    """
    global bitcoind
    return bitcoind.decoderawtransaction( tx_hex )

# setters for the test enviroment
def set_utxo_opts( opts ):
    global utxo_opts 
    utxo_opts = opts

def set_bitcoind( b ):
    global bitcoind
    bitcoind = b

def set_state_engine( s ):
    global state_engine
    state_engine = s

def set_default_payment_wallet( w ):
    global default_payment_wallet
    default_payment_wallet = w

# getters for the test environment
def get_utxo_client():
    utxo_provider = pybitcoin.BitcoindClient("blockstack", "blockstacksystem", port=18332, version_byte=virtualchain.version_byte )
    return utxo_provider

def get_bitcoind():
    global bitcoind
    return bitcoind

def get_state_engine():
    global state_engine
    return state_engine

def get_default_payment_wallet():
    global default_payment_wallet
    return default_payment_wallet

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


def migrate_profile( name, proxy=None, wallet_keys=None ):
    """
    Migrate a user's profile from the legacy format to the profile/zonefile format.
    Broadcast an update transaction with the zonefile hash.
    Replicate the zonefile and profile.

    Return {'status': True, 'zonefile': ..., 'profile': ..., 'transaction_hash': ...} on success, if the profile was migrated
    Return {'status': True} on success, if the profile is already migrated
    Return {'error': ...} on error
    """
    legacy = False
    value_hash = None

    if proxy is None:
        proxy = make_proxy()
        blockstack_client.set_default_proxy( proxy )

    user_profile, user_zonefile, legacy = blockstack_client.get_and_migrate_profile( name, create_if_absent=True, proxy=proxy, wallet_keys=wallet_keys )
    if 'error' in user_profile:
        log.debug("Unable to load user zonefile for '%s': %s" % (name, user_profile['error']))
        return user_profile

    if not legacy:
        return {'status': True}
    
    payment_privkey_info = blockstack_client.get_payment_privkey_info( wallet_keys=wallet_keys, config_path=proxy.conf['path'] )
    owner_privkey_info = blockstack_client.get_owner_privkey_info( wallet_keys=wallet_keys, config_path=proxy.conf['path'] )
    data_privkey_info = blockstack_client.get_data_privkey_info( user_zonefile, wallet_keys=wallet_keys, config_path=proxy.conf['path'] )

    if data_privkey_info is None:
        log.warn("No data private key set; falling back to owner private key")
        data_privkey_info = owner_privkey_info

    if not blockstack_client.keys.is_singlesig(data_privkey_info):
        log.error("We only support single-signature private key info for data at this time.")
        return {'error': 'Invalid data key'}

    user_zonefile_hash = blockstack_client.hash_zonefile( user_zonefile )
    
    # replicate the profile
    rc = storage.put_mutable_data( name, user_profile, data_privkey_info )
    if not rc:
        return {'error': 'Failed to move legacy profile to profile zonefile'}

    # do the update 
    res = blockstack_client.do_update( name, user_zonefile_hash, owner_privkey_info, payment_privkey_info, proxy, proxy, config_path=proxy.config_path, proxy=proxy )
    api_call_history.append( APICallRecord( "update", name, res ) )

    if 'error' in res:
        return {'error': 'Failed to send update transaction: %s' % res['error']}

    # replicate the zonefile
    rc, new_hash = blockstack_client.profile.store_name_zonefile( name, user_zonefile, res['transaction_hash'] )
    if not rc:
        return {'error': 'Failed to replicate zonefile'}

    result = {
        'status': True,
        'zonefile_hash': user_zonefile_hash,
        'transaction_hash': res['transaction_hash'],
        'zonefile': user_zonefile,
        'profile': user_profile
    }

    return result
