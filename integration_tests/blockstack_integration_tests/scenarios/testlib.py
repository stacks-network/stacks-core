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
import sys
import copy
import json
import time
import blockstack_zones
import base64
import binascii
import urllib
import urlparse
import subprocess
import signal
import atexit

import blockstack.blockstackd as blockstackd

import blockstack_client
from blockstack_client.actions import *
from blockstack_client.keys import *
from blockstack_client.app import *
from blockstack_client.config import atlas_inventory_to_string
from blockstack_client.backend.crypto import aes_encrypt

import blockstack
import keylib

import virtualchain

log = virtualchain.get_logger("testlib")

class Wallet(object):
    def __init__(self, pk_wif, ignored ):

        pk = virtualchain.BitcoinPrivateKey( pk_wif )

        self._pk = pk

        if pk_wif.startswith("c"):
            # already a private key 
            self.privkey = keylib.ECPrivateKey(pk_wif).to_hex()
        else:
            self.privkey = pk.to_hex()

        self.pubkey_hex = pk.public_key().to_hex()
        self.addr = pk.public_key().address()

        log.debug("Wallet %s (%s)" % (self.privkey, self.addr))


class MultisigWallet(object):
    def __init__(self, m, *pks ):

        self.privkey = virtualchain.make_multisig_info( m, pks )
        self.m = m
        self.n = len(pks)
        self.pks = pks

        self.addr = self.privkey['address']

        log.debug("Multisig wallet %s" % (self.addr))
        log.debug(json.dumps(self.privkey, indent=4, sort_keys=True))


class APICallRecord(object):
    def __init__(self, method, name, result ):
        self.block_id = max(all_consensus_hashes.keys()) + 1
        self.name = name
        self.method = method
        self.result = result

        assert 'transaction_hash' in result.keys() or 'error' in result.keys()


class TestAPIProxy(object):
    def __init__(self):
        global utxo_opts

        client_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
        assert client_path is not None

        client_config = blockstack_client.get_config(client_path)
        
        log.debug("Connect to Blockstack node at {}:{}".format(client_config['server'], client_config['port']))
        self.client = blockstack_client.BlockstackRPCClient( client_config['server'], client_config['port'] )
        self.config_path = client_path
        self.conf = {
            "start_block": blockstack.FIRST_BLOCK_MAINNET,
            "storage_drivers": client_config['storage_drivers'],
            "metadata": client_config['metadata'],
            "path": client_path,
            "queue_path": client_config['queue_path'],
            "server": client_config['server'],
            "port": client_config['port'],
            "api_endpoint_port": int(client_config['api_endpoint_port']),
            'bitcoind_spv_path': utxo_opts['spv_headers_path'],
            "api_password": client_config['api_password'],
        }
        self.spv_headers_path = utxo_opts['spv_headers_path']

        if not os.path.exists(self.conf['metadata']):
            os.makedirs(self.conf['metadata'], 0700)


    def __getattr__(self, name):
        
        try:
            def inner(*args, **kw):
                rc = None
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

# zonefiles that should be stored, since we pushed them 
atlas_zonefiles_present = []

# default payment wallet 
default_payment_wallet = None

# all scenario wallets
wallets = None

# map data URLs to the data they put
data_urls = {}

# map data IDs to the URLs the put
data_ids = {}

# deleted data 
deleted_urls = []

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


def expect_atlas_zonefile( zonefile_hash ):
    """
    Expect that this zonefile is replicated and
    in the Atlas system
    """
    global atlas_zonefiles_present
    atlas_zonefiles_present.append( zonefile_hash )


def get_unspents( *args, **kw ):
    utxo_client = get_utxo_client()
    return utxo_client.get_unspents( *args, **kw )


def broadcast_transaction( *args, **kw ):
    utxo_client = get_utxo_client()
    return utxo_client.broadcast_transaction( *args, **kw )


def make_proxy(password=None, config_path=None):
    """
    Create a blockstack client API proxy
    """
    client_path = None
    if config_path is None:
        client_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
        assert client_path is not None

    else:
        client_path = config_path

    client_config = blockstack_client.get_config(client_path)
    proxy = blockstack_client.session( conf=client_config, wallet_password=password )
    assert proxy

    proxy.config_path = client_path

    # add in some UTXO goodness 
    proxy.get_unspents = get_unspents
    proxy.broadcast_transaction = broadcast_transaction

    return proxy


def blockstack_name_preorder( name, privatekey, register_addr, wallet=None, subsidy_key=None, consensus_hash=None, safety_checks=True, config_path=None ):

    global api_call_history 

    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    owner_privkey_info = find_wallet(register_addr).privkey
    register_addr = virtualchain.address_reencode(register_addr)

    name_cost_info = test_proxy.get_name_cost( name )
    assert 'satoshis' in name_cost_info, "error getting cost of %s: %s" % (name, name_cost_info)

    log.debug("Preorder '%s' for %s satoshis" % (name, name_cost_info['satoshis']))

    resp = blockstack_client.do_preorder( name, privatekey, owner_privkey_info, name_cost_info['satoshis'], test_proxy, test_proxy, consensus_hash=consensus_hash, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks )

    api_call_history.append( APICallRecord( "preorder", name, resp ) )
    return resp


def blockstack_name_register( name, privatekey, register_addr, wallet=None, subsidy_key=None, user_public_key=None, safety_checks=True, config_path=None ):
    
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    owner_privkey_info = find_wallet(register_addr).privkey
    register_addr = virtualchain.address_reencode(register_addr)

    resp = blockstack_client.do_register( name, privatekey, owner_privkey_info, test_proxy, test_proxy, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks )
    api_call_history.append( APICallRecord( "register", name, resp ) )
    return resp


def blockstack_name_update( name, data_hash, privatekey, user_public_key=None, subsidy_key=None, consensus_hash=None, test_api_proxy=True, safety_checks=True, config_path=None ):
    
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    payment_key = get_default_payment_wallet().privkey
    if subsidy_key is not None:
        payment_key = subsidy_key

    resp = blockstack_client.do_update( name, data_hash, privatekey, payment_key, test_proxy, test_proxy, consensus_hash=consensus_hash, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks )
    api_call_history.append( APICallRecord( "update", name, resp ) )
    return resp


def blockstack_name_transfer( name, address, keepdata, privatekey, user_public_key=None, subsidy_key=None, consensus_hash=None, safety_checks=True, config_path=None ):
     
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    payment_key = get_default_payment_wallet().privkey
    if subsidy_key is not None:
        payment_key = subsidy_key 

    resp = blockstack_client.do_transfer( name, address, keepdata, privatekey, payment_key, test_proxy, test_proxy, consensus_hash=consensus_hash, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks)
    api_call_history.append( APICallRecord( "transfer", name, resp ) )
    return resp


def blockstack_name_renew( name, privatekey, register_addr=None, subsidy_key=None, user_public_key=None, safety_checks=True, config_path=None ):
    
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    name_cost_info = test_proxy.get_name_cost( name )
    if register_addr is None:
        register_addr = virtualchain.get_privkey_address(privatekey)
    else:
        assert register_addr == virtualchain.get_privkey_address(privatekey)

    payment_key = get_default_payment_wallet().privkey
    if subsidy_key is not None:
        payment_key = subsidy_key 

    log.debug("Renew %s for %s satoshis" % (name, name_cost_info['satoshis']))
    resp = blockstack_client.do_renewal( name, privatekey, payment_key, name_cost_info['satoshis'], test_proxy, test_proxy, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks )

    api_call_history.append( APICallRecord( "renew", name, resp ) )
    return resp


def blockstack_name_revoke( name, privatekey, tx_only=False, subsidy_key=None, user_public_key=None, safety_checks=True, config_path=None ):
    
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    payment_key = get_default_payment_wallet().privkey
    if subsidy_key is not None:
        payment_key = subsidy_key

    resp = blockstack_client.do_revoke( name, privatekey, payment_key, test_proxy, test_proxy, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks )
    api_call_history.append( APICallRecord( "revoke", name, resp ) )
    return resp


def blockstack_name_import( name, recipient_address, update_hash, privatekey, safety_checks=True, config_path=None ):
    
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path
    
    tx_fee = None
    if not safety_checks:
        tx_fee = 3000

    resp = blockstack_client.do_name_import( name, privatekey, recipient_address, update_hash, test_proxy, test_proxy, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks, tx_fee=tx_fee )
    api_call_history.append( APICallRecord( "name_import", name, resp ) )
    return resp


def blockstack_namespace_preorder( namespace_id, register_addr, privatekey, consensus_hash=None, safety_checks=True, config_path=None ):
    
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    register_addr = virtualchain.address_reencode(register_addr)

    namespace_cost = test_proxy.get_namespace_cost( namespace_id )
    if 'error' in namespace_cost:
        log.error("Failed to get namespace cost for '%s': %s" % (namespace_id, namespace_cost['error']))
        return {'error': 'Failed to get namespace costs'}

    resp = blockstack_client.do_namespace_preorder( namespace_id, namespace_cost['satoshis'], privatekey, register_addr, test_proxy, test_proxy, consensus_hash=consensus_hash, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks )
    api_call_history.append( APICallRecord( "namespace_preorder", namespace_id, resp ) )
    return resp


def blockstack_namespace_reveal( namespace_id, register_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, privatekey, safety_checks=True, config_path=None ):
    
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    register_addr = virtualchain.address_reencode(register_addr)

    resp = blockstack_client.do_namespace_reveal( namespace_id, register_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, privatekey, test_proxy, test_proxy, config_path=config_path, proxy=test_proxy)
    api_call_history.append( APICallRecord( "namespace_reveal", namespace_id, resp ) )
    return resp


def blockstack_namespace_ready( namespace_id, privatekey, safety_checks=True, config_path=None ):
    
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path
    
    resp = blockstack_client.do_namespace_ready( namespace_id, privatekey, test_proxy, test_proxy, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks ) 
    api_call_history.append( APICallRecord( "namespace_ready", namespace_id, resp ) )
    return resp


def blockstack_announce( message, privatekey, user_public_key=None, subsidy_key=None, safety_checks=True, config_path=None ):
    
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    resp = blockstack_client.do_announce( message, privatekey, test_proxy, test_proxy, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks )
    api_call_history.append( APICallRecord( "announce", message, resp ) )
    return resp


def blockstack_client_initialize_wallet( password, payment_privkey, owner_privkey, data_privkey, exception=True, start_rpc=True, config_path=None ):
    """
    Set up a wallet on disk.  Private keys can be single private keys or multisig bundles
    Optionally save it somewhere besides the default config path
    """
    if config_path is None:
        config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
        assert config_path is not None

    config_dir = os.path.dirname(config_path)
    conf = blockstack_client.get_config(config_path)
    assert conf

    wallet_path = os.path.join( os.path.dirname(config_path), blockstack_client.config.WALLET_FILENAME )

    test_legacy = False
    if payment_privkey is None or owner_privkey is None or data_privkey is None:
        test_legacy = True

    encrypted_wallet = blockstack_client.wallet.make_wallet( password, payment_privkey_info=payment_privkey,
                                                   owner_privkey_info=owner_privkey, data_privkey_info=data_privkey, test_legacy=test_legacy )

    if 'error' in encrypted_wallet:
        log.error("Failed to make wallet: %s" % encrypted_wallet['error'])
        if exception:
            raise Exception("Failed to make wallet")

        return {'error': 'Failed to make wallet'}

    print '\n{}\n'.format(json.dumps(encrypted_wallet, indent=4, sort_keys=True))

    res = blockstack_client.wallet.write_wallet(encrypted_wallet, path=wallet_path, test_legacy=test_legacy)
    if 'error' in res:
        if exception:
            raise Exception("Failed to write wallet")

        return res

    res = blockstack_client.wallet.wallet_setup(config_path=config_path, wallet_path=wallet_path, password=password, test_legacy=test_legacy)
    if 'error' in res:
        if exception:
            raise Exception("failed to set up wallet: {}".format(res['error']))
        else:
            return res

    wallet = res['wallet']

    if start_rpc:

        print '\n{}\n'.format(json.dumps(wallet, indent=4, sort_keys=True))

        print "\nstopping API daemon\n"

        res = blockstack_client.rpc.local_api_stop(config_dir=config_dir)

        print "\nstarting API daemon\n"

        res = blockstack_client.rpc.local_api_start(api_pass=conf['api_password'], port=int(conf['api_endpoint_port']), config_dir=os.path.dirname(config_path), password="0123456789abcdef")
        if not res:
            if exception:
                raise Exception("Failed to start API daemon")

            return res

    return wallet


def blockstack_client_get_wallet(config_path=None):
    """
    Get the wallet from the running RPC daemon
    """
    if config_path is None:
        config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
        assert config_path is not None

    wallet = blockstack_client.wallet.get_wallet( config_path )
    if 'error' in wallet:
        log.error("Failed to get wallet: %s" % wallet['error'])
        raise Exception("Failed to get wallet")

    return wallet


def blockstack_client_set_wallet( password, payment_privkey, owner_privkey, data_privkey, config_path=None):
    """
    Set the wallet to a runnin RPC daemon
    """
    if config_path is None:
        config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
        assert config_path is not None

    conf = blockstack_client.get_config(config_path)
    assert conf

    config_dir = os.path.dirname(config_path)

    wallet = blockstack_client_initialize_wallet( password, payment_privkey, owner_privkey, data_privkey, start_rpc=False, config_path=None )
    if 'error' in wallet:
        log.error("Failed to initialize wallet: %s" % wallet['error'])
        raise Exception("Failed to initialize wallet")

    return wallet


def blockstack_client_queue_state(config_path=None):
    """
    Get queue information from the client backend
    """
    if config_path is None:
        config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
        assert config_path is not None
   
    conf = blockstack_client.get_config(config_path)
    queue_info = blockstack_client.backend.queue.get_queue_state( path=conf['queue_path'])
    return queue_info


def blockstack_cli_namespace_preorder( namespace_id, namespace_privkey, reveal_privkey, config_path=None ):
    """
    Preorder a namespace
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    args.namespace_id = namespace_id
    args.payment_privkey = namespace_privkey
    args.reveal_privkey = reveal_privkey

    resp = cli_namespace_preorder(args, config_path=config_path, interactive=False, proxy=test_proxy)
    if 'error' not in resp:
        assert 'transaction_hash' in resp

    return resp


def blockstack_cli_namespace_reveal( namespace_id, payment_privkey, reveal_privkey, lifetime, coeff, base, buckets, nonalpha_disc, no_vowel_disc, config_path=None ):
    """
    reveal a namespace
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    args.namespace_id = namespace_id
    args.payment_privkey = payment_privkey
    args.reveal_privkey = reveal_privkey
    args.lifetime = lifetime
    args.coeff = coeff
    args.base = base
    args.buckets = buckets
    args.nonalpha_discount = nonalpha_disc
    args.no_vowel_discount = no_vowel_disc

    resp = cli_namespace_reveal(args, config_path=config_path, interactive=False, proxy=test_proxy)
    if 'error' not in resp:
        assert 'transaction_hash' in resp

    return resp


def blockstack_cli_namespace_ready( namespace_id, reveal_privkey, config_path=None ):
    """
    launch a namespace
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    args.namespace_id = namespace_id
    args.reveal_privkey = reveal_privkey

    resp = cli_namespace_ready(args, config_path=config_path, interactive=False, proxy=test_proxy)
    if 'error' not in resp:
        assert 'transaction_hash' in resp

    return resp


def blockstack_cli_register( name, password, recipient_address=None, zonefile=None, config_path=None):
    """
    Register a name, using the backend RPC endpoint
    """
    test_proxy = make_proxy(password=password, config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    args.name = name
    args.recipient = recipient_address
    args.zonefile = zonefile

    resp = cli_register( args, config_path=config_path, password=password, interactive=False, proxy=test_proxy )
    if 'error' not in resp:
        assert 'transaction_hash' in resp

    return resp


def blockstack_cli_update( name, zonefile_json, password, nonstandard=True, config_path=None):
    """
    Update a name's value hash to point to the new zonefile
    """
    global atlas_zonefiles_present

    test_proxy = make_proxy(password=password, config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    fd, path = tempfile.mkstemp()
    os.write(fd, zonefile_json)
    os.close(fd)

    log.debug("Stored JSON to {}".format(path))

    args = CLIArgs()
    args.name = name
    args.data = path

    resp = cli_update( args, config_path=config_path, password=password, interactive=False, nonstandard=nonstandard )

    try:
        os.unlink(path)
    except:
        pass

    if 'value_hash' in resp:
        atlas_zonefiles_present.append( resp['value_hash'] )
    
    if 'error' not in resp:
        assert 'transaction_hash' in resp

    return resp


def blockstack_cli_transfer( name, new_owner_address, password, config_path=None):
    """
    transfer a name to a new address
    """
    test_proxy = make_proxy(password=password, config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    args.name = name
    args.address = new_owner_address

    resp = cli_transfer( args, config_path=config_path, password=password )
    if 'error' not in resp:
        assert 'transaction_hash' in resp

    return resp


def blockstack_cli_renew( name, password, config_path=None):
    """
    Renew a name, using the backend RPC endpoint
    """
    test_proxy = make_proxy(password=password, config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    args.name = name

    resp = cli_renew( args, config_path=config_path, password=password, interactive=False, proxy=test_proxy )
    if 'error' not in resp:
        assert 'transaction_hash' in resp

    return resp


def blockstack_cli_revoke( name, password, config_path=None):
    """
    Revoke a name, using the backend RPC endpoint
    """
    test_proxy = make_proxy(password=password, config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    args.name = name

    resp = cli_revoke( args, config_path=config_path, password=password, interactive=False, proxy=test_proxy )
    if 'error' not in resp:
        assert 'transaction_hash' in resp

    return resp


def blockstack_cli_name_import( name, address, zonefile_txt, importer_privkey, config_path=None):
    """
    Import a name
    """
    global atlas_zonefiles_present

    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    fd, path = tempfile.mkstemp()
    os.write(fd, zonefile_txt)
    os.close(fd)

    log.debug("Stored JSON to {}".format(path))

    args = CLIArgs()
    args.name = name
    args.address = address
    args.zonefile_path = path
    args.privatekey = importer_privkey

    resp = cli_name_import( args, config_path=config_path, interactive=False)

    try:
        os.unlink(path)
    except:
        pass

    if 'value_hash' in resp:
        atlas_zonefiles_present.append( resp['value_hash'] )
   
    if 'error' not in resp:
        assert 'transaction_hash' in resp

    return resp


def blockstack_cli_names(config_path=None):
    """
    Get the list of nams owned by the local wallet
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    resp = cli_names( args, config_path=config_path )
    return resp

 
def blockstack_cli_set_zonefile_hash( name, zonefile_hash, config_path=None):
    """
    Set the zonefile hash directly
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    args.name = name
    args.zonefile_hash = zonefile_hash

    resp = cli_set_zonefile_hash( args, config_path=config_path )
    return resp


def blockstack_cli_sync_zonefile( name, zonefile_string=None, txid=None, interactive=False, nonstandard=True, config_path=None):
    """
    Forcibly synchronize the zonefile
    """
    global atlas_zonefiles_present

    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    path = None
    if zonefile_string:
        fd, path = tempfile.mkstemp()
        os.write(fd, zonefile_string)
        os.close(fd)

        log.debug("Stored JSON to {}".format(path))

    args = CLIArgs()
    args.name = name
    args.zonefile = path
    args.txid = txid

    resp = cli_sync_zonefile( args, config_path=config_path, proxy=test_proxy, interactive=interactive, nonstandard=nonstandard )

    if path:
        try:
            os.unlink(path)
        except:
            pass

    if 'value_hash' in resp:
        atlas_zonefiles_present.append( resp['value_hash'] )

    return resp


def blockstack_cli_balance(config_path=None):
    """
    Get the balance
    """
    args = CLIArgs()
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    return cli_balance( args, config_path=config_path )


def blockstack_cli_info(config_path=None):
    """
    Get the queue state
    """
    args = CLIArgs()
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    return cli_info( args, config_path=config_path, password=password )


def blockstack_cli_price( name, password, config_path=None):
    """
    Get the price of a name
    """
    args = CLIArgs()
    test_proxy = make_proxy(password=password, config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args.name = name
    return cli_price( args, config_path=config_path, proxy=test_proxy, password=password )


def blockstack_cli_deposit(config_path=None):
    """
    Get the deposit information
    """
    args = CLIArgs()
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    return cli_deposit( args, config_path=config_path )


def blockstack_cli_import(config_path=None):
    """
    Get name import information
    """
    args = CLIArgs()
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    return cli_import( args, config_path=config_path )


def blockstack_cli_info(config_path=None):
    """
    Get name and server information
    """
    args = CLIArgs()
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    return cli_info( args, config_path=config_path )
    

def blockstack_cli_whois( name, config_path=None):
    """
    Get the WHOIS information for a name
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    args.name = name

    resp = cli_whois( args, config_path=config_path )
    return resp


def blockstack_cli_ping(config_path=None):
    """
    Ping the running server
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    return cli_ping( args, config_path=config_path )


def blockstack_cli_lookup( name, config_path=None):
    """
    Look up a name's zonefile/profile
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.name = name

    return cli_lookup( args, config_path=config_path )


def blockstack_cli_migrate( name, password, force=False, config_path=None):
    """
    Migrate from legacy zonefile to new zonefile
    """
    test_proxy = make_proxy(password=password, config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
   
    args.name = name

    return cli_migrate( args, config_path=config_path, proxy=test_proxy, password=password, interactive=False, force=force )
    

def blockstack_cli_import_wallet( password, payment_privkey, owner_privkey, data_privkey=None, force=False, config_path=None):
    """
    Import a wallet
    """
    test_proxy = make_proxy(password=password, config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.payment_privkey = payment_privkey
    args.owner_privkey = owner_privkey
    args.data_privkey = data_privkey

    return cli_import_wallet( args, config_path=config_path, password=password, force=force )


def blockstack_cli_setup_wallet( password, config_path=None):
    """
    Upgrade wallet
    """
    test_proxy = make_proxy(password=password, config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    return cli_setup_wallet(args, config_path=config_path, password=password )


def blockstack_cli_list_accounts( name, config_path=None):
    """
    list a name's accounts
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.name = name

    return cli_list_accounts( args, config_path=config_path, proxy=test_proxy )


def blockstack_cli_get_account( name, service, identifier, config_path=None):
    """
    get an account by name/service/serviceID
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.name = name
    args.service = service
    args.identifier = identifier

    return cli_get_account( args, config_path=config_path, proxy=test_proxy )


def blockstack_cli_put_account( name, service, identifier, content_url, password, extra_data=None, wallet_keys=None, config_path=None):
    """
    put an account
    """
    test_proxy = make_proxy(password=password, config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.name = name
    args.service = service
    args.identifier = identifier
    args.content_url = content_url
    args.extra_data = extra_data

    return cli_put_account( args, config_path=config_path, proxy=test_proxy, password=password, wallet_keys=wallet_keys )


def blockstack_cli_delete_account( name, service, identifier, password, wallet_keys=None, config_path=None):
    """
    delete an account
    """
    test_proxy = make_proxy(password=password, config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.name = name
    args.service = service
    args.identifier = identifier

    return cli_delete_account( args, config_path=config_path, proxy=test_proxy, password=password, wallet_keys=wallet_keys )


def blockstack_cli_wallet( password, config_path=None):
    """
    get the wallet
    """
    test_proxy = make_proxy(password=password, config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    try:
        return cli_wallet( args, config_path=config_path, password=password )
    except NameError:
        # 0.14.0.x
        return cli_advanced_wallet( args, config_path=config_path, password=password )
    

def blockstack_cli_consensus( height=None, config_path=None):
    """
    get consensus
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    
    args.block_height = height

    return cli_consensus( args, config_path=config_path )


def blockstack_cli_rpcctl( command, config_path=None):
    """
    control-command to the RPC daemon
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.command = command

    try:
        return cli_rpcctl( args, config_path=config_path )
    except NameError:
        # 0.14.0.x
        return cli_advanced_rpcctl( args, config_path=config_path )


def blockstack_cli_rpc( method, rpc_args=None, rpc_kw=None, config_path=None):
    """
    send an RPC command to the RPC daemon
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.method = method
    args.args = rpc_args
    args.kwargs = rpc_kw

    return cli_rpc( args, config_path=config_path )


def blockstack_cli_put_mutable( name, data_id, data_json_str, password=None, config_path=None):
    """
    put mutable data
    """
    global data_urls
    global data_ids

    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    fd, path = tempfile.mkstemp()
    os.write(fd, data_json_str)
    os.close(fd)

    args.name = name
    args.data_id = data_id
    args.data = path

    res = cli_put_mutable( args, config_path=config_path, password=password )

    try:
        os.unlink(path)
    except:
        pass

    if 'error' in res:
        return res

    """
    assert 'url' in res, "Missing URL"
   
    url = res['url']

    # overwrite data
    url_no_version = '#'.join(url.split('#')[:-1])
    replace_url = None
    for existing_url in data_urls.keys():
        existing_url_no_version = '#'.join(existing_url.split('#')[:-1])
        if url_no_version == existing_url_no_version:
            replace_url = existing_url
            break

    if replace_url:
        log.debug("Replace {} with {}".format(replace_url, url))
        del data_urls[replace_url]

    data_urls[url] = data_json_str
    data_ids[data_id] = url
    """
    return res


def blockstack_cli_put_immutable( name, data_id, data_json_str, password=None, config_path=None):
    """
    put immutable data
    """
    global data_urls
    global data_ids

    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    fd, path = tempfile.mkstemp()
    os.write(fd, data_json_str)
    os.close(fd)

    args.name = name
    args.data_id = data_id
    args.data = path

    res = cli_put_immutable( args, config_path=config_path, password=password )

    try:
        os.unlink(path)
    except:
        pass

    if 'error' in res:
        return res


    """
    assert 'url' in res, "Missing URL"
    assert 'hash' in res, "Missing hash"
    
    url = res['url']
    up = urlparse.urlparse(url)

    # process overwrite
    for did in data_ids.keys():
        if data_ids[did] == url:
            del data_ids[did]

    for u in data_urls.keys():
        p = urlparse.urlparse(u)
        if p.netloc == up.netloc:
            # overwriting data 
            del data_urls[u]

    data_urls[url] = data_json_str
    data_ids[data_id] = url
    data_ids[res['hash']] = url
    """
    return res



def blockstack_cli_get_mutable( name, data_id, config_path=None):
    """
    get mutable data
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.name = name
    args.data_id = data_id

    return cli_get_mutable( args, config_path=config_path )


def blockstack_cli_get_immutable( name, data_id_or_hash, config_path=None):
    """
    get immutable data
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.name = name
    args.data_id_or_hash = data_id_or_hash

    return cli_get_immutable( args, config_path=config_path )


def blockstack_cli_get_data( url, config_path=None):
    """
    get data by url
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    
    args.url = url

    return cli_get_data( args, config_path=config_path )


def blockstack_cli_list_update_history( name, config_path=CONFIG_PATH):
    """
    list value hash history
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    
    args.name = name
    return cli_list_update_history( args, config_path=config_path )


def blockstack_cli_list_zonefile_history( name, config_path=CONFIG_PATH):
    """
    list zonefile history
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.name = name
    return cli_list_zonefile_history( args, config_path=config_path )


def blockstack_cli_list_immutable_data_history( name, data_id, config_path=CONFIG_PATH):
    """
    list immutable data history
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.name = name
    args.data_id = data_id
    return cli_list_immutable_data_history( args, config_path=config_path )
    

def blockstack_cli_delete_immutable( name, hash_str, config_path=CONFIG_PATH, password=None):
    """
    delete immutable
    """
    global data_urls
    global data_ids
    global deleted_urls

    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.name = name
    args.data_id = hash_str
    res = cli_delete_immutable( args, config_path=config_path, password=password )
    if 'error' in res:
        return res

    # clean up
    url = data_ids.get(hash_str)
    if url is not None:
        if url in data_urls.keys():
            # don't expect this
            del data_urls[url]
            
        deleted_urls.append(url)
    
    return res


def blockstack_cli_delete_mutable( name, data_id, config_path=CONFIG_PATH, password=None):
    """
    delete mutable
    """
    global data_urls
    global data_ids
    global deleted_urls

    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.name = name
    args.data_id = data_id
    res = cli_delete_mutable( args, config_path=config_path, password=password )
    if 'error' in res:
        return res

    # clean up 
    url = data_ids.get(data_id)
    if url is not None:
        if url in data_urls.keys():
            # don't expect this
            del data_urls[url]

        deleted_urls.append(url)

    return res
    

def blockstack_cli_get_name_blockchain_record( name, config_path=CONFIG_PATH):
    """
    get name blockchain record
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.name = name
    return cli_get_name_blockchain_record( args, config_path=config_path )


def blockstack_cli_get_name_blockchain_history( name, start_block=None, end_block=None, config_path=CONFIG_PATH):
    """
    get name blockchain history
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.name = name
    args.start_block = start_block
    args.end_block = end_block

    return cli_get_name_blockchain_history(  args, config_path=config_path )


def blockstack_cli_get_namespace_blockchain_record( namespace_id, config_path=CONFIG_PATH):
    """
    get namespace blockchain record
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.namespace_id = namespace_id
    return cli_get_namespace_blockchain_record( args, config_path=config_path )


def blockstack_cli_lookup_snv( name, block_id, trust_anchor, config_path=CONFIG_PATH):
    """
    SNV lookup
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.name = name
    args.block_id = block_id
    args.trust_anchor = trust_anchor

    return cli_lookup_snv( args, config_path=config_path )


def blockstack_cli_get_name_zonefile( name, config_path=CONFIG_PATH, json=False):
    """
    get name zonefile
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.name = name
    args.json = "True" if json else "False"

    return cli_get_name_zonefile( args, config_path=config_path )


def blockstack_cli_get_names_owned_by_address( address, config_path=CONFIG_PATH):
    """
    get names owned by address
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.address = address
    return cli_get_names_owned_by_address( args, config_path=config_path )


def blockstack_cli_get_namespace_cost( namespace_id, config_path=CONFIG_PATH):
    """
    get namespace cost
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.namespace_id = namespace_id
    return cli_get_namespace_cost( args, config_path=config_path )


def blockstack_cli_get_all_names( offset=None, count=None, config_path=CONFIG_PATH):
    """
    get all names
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.offset = offset
    args.count = count

    return cli_get_all_names( args, config_path=config_path )


def blockstack_cli_get_names_in_namespace( namespace_id, offset=None, count=None, config_path=CONFIG_PATH):
    """
    get names in a particular namespace
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.namespace_id = namespace_id
    args.offset = offset
    args.count = count

    return cli_get_names_in_namespace( args, config_path=config_path )


def blockstack_cli_get_records_at( block_id, config_path=CONFIG_PATH):
    """
    get name records at a block height
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.block_id = block_id

    return cli_get_records_at( args, config_path=config_path )


def blockstack_cli_set_zonefile_hash( name, zonefile_hash, config_path=CONFIG_PATH, password=None):
    """
    set the zonefile hash directly
    """
    test_proxy = make_proxy(password=password, config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.name = name
    args.zonefile_hash = zonefile_hash
    
    return cli_set_zonefile_hash( args, config_path=config_path, password=password )


def blockstack_cli_unqueue( name, queue_id, txid, config_path=CONFIG_PATH, password=None):
    """
    unqueue from the registrar queue
    """
    test_proxy = make_proxy(password=password, config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.name = name
    args.queue_id = queue_id
    args.txid = txid

    return cli_unqueue( args, config_path=config_path, password=password )


def blockstack_cli_set_name_profile( name, data_json_str, password=None, config_path=None):
    """
    set the profile directly, by name
    """
    test_proxy = make_proxy(password=password, config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.name = name
    args.data = data_json_str

    return cli_set_name_profile( args, config_path=config_path, password=password, proxy=test_proxy )


def blockstack_cli_set_user_profile( user_id, data_json_str, config_path=None):
    """
    set a user profile directly
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    
    args.user_id = user_id
    args.data = data_json_str 

    return cli_set_user_profile( args, config_path=config_path, proxy=test_proxy )


def blockstack_cli_convert_legacy_profile( path, config_path=CONFIG_PATH):
    """
    convert a legacy profile
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.path = path

    return cli_convert_legacy_profile( args, config_path=config_path )


def blockstack_cli_app_publish( blockchain_id, app_domain, methods, index_file, urls=None, drivers=None, interactive=False, password=None, config_path=None):
    """
    publish a blockstack application
    """
    test_proxy = make_proxy(password=password, config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.blockchain_id = blockchain_id
    args.app_domain = app_domain
    args.methods = methods
    args.index_file = index_file
    args.urls = urls
    args.drivers = drivers
    
    return cli_app_publish( args, config_path=config_path, interactive=interactive, password=password, proxy=test_proxy )


def blockstack_cli_app_get_config( blockchain_id, app_domain, interactive=False, config_path=None):
    """
    get app config
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.blockchain_id = blockchain_id
    args.app_domain = app_domain 

    return cli_app_get_config( args, config_path=config_path, interactive=interactive, proxy=test_proxy )
    

def blockstack_cli_app_get_resource( blockchain_id, app_domain, res_path, interactive=False, config_path=None):
    """
    Get application resource
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.blockchain_id = blockchain_id
    args.app_domain = app_domain
    args.res_path = res_path

    return cli_app_get_resource( args, config_path=config_path, interactive=interactive, proxy=test_proxy )


def blockstack_cli_app_put_resource( blockchain_id, app_domain, res_path, res_file_path, interactive=False, password=None, config_path=None):
    """
    Get application resource
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.blockchain_id = blockchain_id
    args.app_domain = app_domain
    args.res_path = res_path
    args.res_file = res_file_path

    return cli_app_put_resource( args, config_path=config_path, interactive=interactive, password=password, proxy=test_proxy )


def blockstack_cli_app_signin( app_privkey, app_domain, api_methods, config_path=None ):
    """
    sign in and get a token
    """
    if config_path is None:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.app_domain = app_domain
    args.api_methods = ','.join(api_methods)
    args.privkey = app_privkey

    return cli_app_signin( args, config_path=config_path )


def blockstack_cli_create_datastore(datastore_privkey, drivers, config_path=None):
    """
    create_datastore
    """
    if config_path is None:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.privkey = datastore_privkey
    args.drivers = ",".join(drivers)

    return cli_create_datastore( args, config_path=config_path)


def blockstack_cli_delete_datastore(datastore_privkey, force=False, config_path=None):
    """
    delete datastore
    """
    if config_path is None:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    args.privkey = datastore_privkey
    args.force = '1' if force else '0'

    return cli_delete_datastore( args, config_path=config_path )


def blockstack_cli_datastore_mkdir(datastore_privkey, path, config_path=None, interactive=False ):
    """
    mkdir
    """
    if config_path is None:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.path = path
    args.privkey = datastore_privkey

    return cli_datastore_mkdir( args, config_path=config_path, interactive=interactive )


def blockstack_cli_datastore_rmdir( datastore_privkey, path, config_path=None, force=False, interactive=False ):
    """
    rmdir
    """
    if config_path is None:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.path = path
    args.privkey = datastore_privkey
    args.force = '1' if force else '0'

    return cli_datastore_rmdir( args, config_path=config_path, interactive=interactive )


def blockstack_cli_datastore_rmtree( datastore_privkey, path, config_path=None, interactive=False ):
    """
    rmtree
    """
    if config_path is None:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    args.path = path
    args.privkey = datastore_privkey

    return cli_datastore_rmtree( args, config_path=config_path, interactive=interactive )


def blockstack_cli_datastore_listdir(datastore_id, path, config_path=None, force=False, interactive=False ):
    """
    listdir
    """
    if config_path is None:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    
    args.datastore_id = datastore_id
    args.path = path 
    args.force = '1' if force else '0'

    return cli_datastore_listdir( args, config_path=config_path, interactive=interactive )


def blockstack_cli_datastore_stat( datastore_id, path, config_path=None, force=False, interactive=False ):
    """
    stat
    """
    if config_path is None:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    
    args.datastore_id = datastore_id
    args.path = path 
    args.force = '1' if force else '0'

    return cli_datastore_stat( args, config_path=config_path, interactive=interactive )


def blockstack_cli_datastore_getfile( datastore_id, path, config_path=None, force=False, interactive=False ):
    """
    getfile
    """
    if config_path is None:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    
    args.datastore_id = datastore_id
    args.path = path
    args.force = '1' if force else '0'

    data = cli_datastore_getfile( args, config_path=config_path, interactive=interactive )

    # backwards-compatibility
    if json_is_error(data):
        return data

    else:
        res = {
            'status': True,
            'file': {
                'idata': data
            },
        }
        return res



def blockstack_cli_datastore_putfile( datastore_privkey, path, data, data_path=None, interactive=False, force=False, proxy=None, config_path=None):
    """
    putfile
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    
    args.privkey = datastore_privkey
    args.path = path 
    args.data = data
    args.data_path = data_path
    args.force = '1' if force else '0'

    return cli_datastore_putfile( args, config_path=config_path, interactive=interactive )


def blockstack_cli_datastore_deletefile( datastore_privkey, path, interactive=False, force=False, proxy=None, config_path=None):
    """
    deletefile
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    
    args.privkey = datastore_privkey
    args.path = path 
    args.force = '1' if force else '0'

    return cli_datastore_deletefile( args, config_path=config_path, interactive=interactive )


def blockstack_cli_datastore_get_id( datastore_privkey, interactive=False, proxy=None, config_path=None ):
    """
    get datastore ID
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    args.datastore_privkey = datastore_privkey 
    return cli_datastore_get_id( args, config_path=config_path, interactive=interactive )
    

def blockstack_cli_list_device_ids( config_path=None ):
    """
    list device IDs
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    return cli_list_device_ids( args, config_path=config_path )


def blockstack_cli_get_device_id( config_path=None ):
    """
    get device ID
    """ 
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()

    return cli_get_device_id( args, config_path=config_path )


def blockstack_cli_add_device_id( device_id, config_path=None ):
    """
    add device
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    args.device_id = device_id

    return cli_add_device_id( args, config_path=config_path )


def blockstack_cli_remove_device_id( device_id, config_path=None ):
    """
    remove device
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    args = CLIArgs()
    args.device_id = device_id

    return cli_remove_device_id( device_id, config_path=config_path )
     

def blockstack_rpc_set_zonefile_hash( name, zonefile_hash, config_path=None ):
    """
    Set the zonefile hash directly
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path


    args = CLIArgs()
    args.name = name
    args.zonefile_hash = zonefile_hash

    resp = cli_set_zonefile_hash( args, config_path=config_path )
    return resp


def blockstack_rpc_sync_zonefile( name, zonefile_string=None, txid=None, config_path=None ):
    """
    Forcibly synchronize the zonefile
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path


    args = CLIArgs()
    args.name = name

    if zonefile_string is not None:
        args.zonefile = zonefile_string

    if txid is not None:
        args.txid = txid

    resp = cli_sync_zonefile( args, config_path=config_path, proxy=test_proxy )
    return resp


def blockstack_get_zonefile( zonefile_hash, parse=True, config_path=None ):
    """
    Get a zonefile from the RPC endpoint
    Return None if not given
    MEANT FOR DIAGNOSTIC PURPOSES ONLY
    """

    # TODO: sync with API
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    zonefile_result = test_proxy.get_zonefiles( [zonefile_hash] )
    if 'error' in zonefile_result:
        return None

    if zonefile_hash not in zonefile_result['zonefiles'].keys():
        return None

    zonefile_txt = base64.b64decode( zonefile_result['zonefiles'][zonefile_hash] )

    if parse:
        zonefile = blockstack_zones.parse_zone_file( zonefile_txt )

        # verify
        if zonefile_hash != blockstack_client.hash_zonefile( zonefile ):
            return None

        return zonefile

    else:
        return zonefile_txt


def blockstack_get_profile( name, config_path=None ):
    """
    Get a profile from the RPC endpoint
    Return None if not given
    MEANT FOR DIAGNOSTIC PURPOSES ONLY
    """

    # TODO: sync with API
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path


    profile_result = test_proxy.get_profile( name )
    if 'error' in profile_result:
        return None

    if 'profile' not in profile_result or 'status' not in profile_result or not profile_result['status']:
        return None 

    return profile_result['profile']


def blockstack_app_session( app_domain, methods, config_path=None ):
    """
    Make a session for the given application
    Returns {'error': ...} on error
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    api_pass = test_proxy.conf['api_password']
    api_port = int(test_proxy.conf['api_endpoint_port'])

    req = {
        'app_domain': app_domain,
        'methods': methods,
    }
    
    privk = '0a324d66e9d23de40e5455c5d95507b4641cdbef08a473954586790cf78a80c701'

    signer = jsontokens.TokenSigner()
    token = signer.sign( req, privk )

    url = 'http://localhost:{}/v1/auth?authRequest={}'.format(api_port, token)
    resp = requests.get( url, headers={'Authorization': 'bearer {}'.format(api_pass)} )
    if resp.status_code != 200:
        log.error("GET {} status code {}".format(url, resp.status_code))
        return {'error': 'Failed to get session'}

    payload = resp.json()
    ses = payload['token']
    return {'ses': ses}


def blockstack_REST_call( method, route, session, api_pass=None, app_fqu=None, appname=None, data=None, raw_data=None, config_path=None, **query_fields ):
    """
    Low-level call to an API route
    Returns {'http_status': http status, 'response': json}
    """
    test_proxy = make_proxy(config_path=config_path)
    blockstack_client.set_default_proxy( test_proxy )
    config_path = test_proxy.config_path if config_path is None else config_path

    api_port = int(test_proxy.conf['api_endpoint_port'])

    if app_fqu:
        query_fields['name'] = app_fqu

    if appname:
        query_fields['appname'] = appname

    qs = '&'.join('{}={}'.format(urllib.quote(k), urllib.quote(v)) for (k, v) in query_fields.items())
    if len(qs) > 0:
        qs = '?{}'.format(qs)

    resp = None
    url = "http://localhost:{}{}{}".format(api_port, route, qs)

    log.debug("REST call: {} {}".format(method, url))

    headers = {}
    if session:
        headers['authorization'] = 'bearer {}'.format(session)
    elif api_pass:
        headers['authorization'] = 'bearer {}'.format(api_pass)

    assert not (data and raw_data), "Multiple data given"

    if data is not None:
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

    if raw_data is not None:
        data = raw_data
        headers['content-type'] = 'application/octet-stream'

    resp = requests.request( method, url, headers=headers, data=data )
   
    response = None
    try:
        response = resp.json()
    except:
        log.debug("Failed to parse: '{}'".format(resp.text))
        response = None

    return {
        'http_status': resp.status_code,
        'response': response,
        'raw': resp.text
    }


def blockstack_test_setenv(key, value):
    """
    Set an environment variable on a running API daemon via the test interface
    """
    res = blockstack_REST_call('POST', '/v1/test/envar?{}={}'.format(urllib.quote(key), urllib.quote(value)), None)
    if res['http_status'] != 200:
        res['error'] = 'Failed to issue test RPC call'
        return res

    return res


def blockstack_verify_database( consensus_hash, consensus_block_id, db_path, working_db_path=None, start_block=None ):
    return blockstackd.verify_database( consensus_hash, consensus_block_id, db_path, working_db_path=working_db_path, start_block=start_block )


def blockstack_export_db( path, block_height, **kw ):
    global state_engine
    try:
        state_engine.export_db( path + (".%s" % block_height)  )
    except IOError, ie:
        if ie.errno == errno.ENOENT:
            log.error("no such file or directory: %s" % path)
            pass
        else:
            raise

    # save atlasdb too 
    # TODO: this is hacky; find a generic way to find the atlas db path
    atlas_path = os.path.join( os.path.dirname(state_engine.get_db_path()), "atlas.db" )
    if os.path.exists(atlas_path):
        shutil.copy( atlas_path, os.path.join( os.path.dirname(path), "atlas.db.%s" % block_height ) )


def make_legacy_wallet( master_private_key, password ):
    """
    make a legacy pre-0.13 wallet with a single master private key
    """
    master_private_key = virtualchain.BitcoinPrivateKey(master_private_key).to_hex()
    hex_password = binascii.hexlify(password)

    legacy_wallet = {
        'encrypted_master_private_key': aes_encrypt( master_private_key, hex_password )
    }

    return legacy_wallet



def encrypt_multisig_info(multisig_info, password):
    """
    Given a multisig info dict,
    encrypt the sensitive fields.

    LEGACY WALLET TESTING ONLY

    Returns {'encrypted_private_keys': ..., 'encrypted_redeem_script': ..., **other_fields}
    """
    enc_info = {
        'encrypted_private_keys': None,
        'encrypted_redeem_script': None
    }

    hex_password = hexlify(password)

    assert virtualchain.is_multisig(multisig_info), 'Invalid multisig keys'

    enc_info['encrypted_private_keys'] = []
    for pk in multisig_info['private_keys']:
        pk_ciphertext = aes_encrypt(pk, hex_password)
        enc_info['encrypted_private_keys'].append(pk_ciphertext)

    enc_info['encrypted_redeem_script'] = aes_encrypt(multisig_info['redeem_script'], hex_password)

    # preserve any other fields
    for k, v in multisig_info.items():
        if k not in ['private_keys', 'redeem_script']:
            enc_info[k] = v

    return enc_info


def encrypt_private_key_info(privkey_info, password):
    """
    Encrypt private key info.

    LEGACY WALLET TESTING ONLY

    Return {'status': True, 'encrypted_private_key_info': {'address': ..., 'private_key_info': ...}} on success
    Returns {'error': ...} on error
    """

    ret = {}
    if virtualchain.is_multisig(privkey_info):
        ret['address'] = virtualchain.address_reencode( virtualchain.make_p2sh_address( privkey_info['redeem_script'] ))
        ret['private_key_info'] = encrypt_multisig_info(privkey_info, password)

        return {'status': True, 'encrypted_private_key_info': ret}

    if virtualchain.is_singlesig(privkey_info):
        ret['address'] = virtualchain.address_reencode( ecdsa_private_key(privkey_info).public_key().address() )

        hex_password = hexlify(password)
        ret['private_key_info'] = aes_encrypt(privkey_info, hex_password)

        return {'status': True, 'encrypted_private_key_info': ret}

    return {'error': 'Invalid private key info'}


def make_legacy_013_wallet( owner_privkey, payment_privkey, password ):
    """
    make a legacy 0.13 wallet with an owner and payment private key
    """
    assert virtualchain.is_singlesig(owner_privkey)
    assert virtualchain.is_singlesig(payment_privkey)

    decrypted_legacy_wallet = blockstack_client.keys.make_wallet_keys(owner_privkey=owner_privkey, payment_privkey=payment_privkey)
    encrypted_legacy_wallet = {
        'owner_addresses': decrypted_legacy_wallet['owner_addresses'],
        'encrypted_owner_privkey': blockstack_client.keys.encrypt_private_key_info(owner_privkey, password)['encrypted_private_key_info']['private_key_info'],
        'payment_addresses': decrypted_legacy_wallet['payment_addresses'],
        'encrypted_payment_privkey': blockstack_client.keys.encrypt_private_key_info(payment_privkey, password)['encrypted_private_key_info']['private_key_info'],
    }
    return encrypted_legacy_wallet


def make_legacy_014_wallet( owner_privkey, payment_privkey, data_privkey, password ):
    """
    make a legacy 0.14 wallet with the owner, payment, and data keys
    """
    assert virtualchain.is_singlesig(owner_privkey)
    assert virtualchain.is_singlesig(payment_privkey)
    assert virtualchain.is_singlesig(data_privkey)

    decrypted_legacy_wallet = blockstack_client.keys.make_wallet_keys(data_privkey=data_privkey, owner_privkey=owner_privkey, payment_privkey=payment_privkey)
    encrypted_legacy_wallet = {
        'data_pubkey': ECPrivateKey(data_privkey).public_key().to_hex(),
        'data_pubkeys': [ECPrivateKey(data_privkey).public_key().to_hex()],
        'data_privkey': blockstack_client.keys.encrypt_private_key_info(data_privkey, password)['encrypted_private_key_info']['private_key_info'],
        'owner_addresses': decrypted_legacy_wallet['owner_addresses'],
        'encrypted_owner_privkey': blockstack_client.keys.encrypt_private_key_info(owner_privkey, password)['encrypted_private_key_info']['private_key_info'],
        'payment_addresses': decrypted_legacy_wallet['payment_addresses'],
        'encrypted_payment_privkey': blockstack_client.keys.encrypt_private_key_info(payment_privkey, password)['encrypted_private_key_info']['private_key_info'],
        'version': '0.14.0'
    }
    return encrypted_legacy_wallet


def store_wallet( wallet_dict ):
    """
    Write a wallet directly
    """
    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    assert config_path is not None

    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, "wallet.json")
    with open(wallet_path, "w") as f:
        f.write(json.dumps(wallet_dict))


def delete_wallet():
    """
    Delete the local wallet
    """
    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    assert config_path is not None

    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, "wallet.json")
    try:
        os.unlink(wallet_path)
    except:
        pass


def list_wallet_backups():
    """
    list the local wallet backups
    """
    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    assert config_path is not None

    config_dir = os.path.dirname(config_path)
    files = os.listdir(config_dir)
    backup_paths = [os.path.join(config_dir, fn) for fn in filter(lambda x: x.startswith("wallet.json."), files)]
    return backup_paths


def start_api(password):
    """
    Start the API server
    """
    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG")
    assert config_path is not None
    
    config_dir = os.path.dirname(config_path)

    conf = blockstack_client.get_config(config_path)
    port = int(conf['api_endpoint_port'])
    api_pass = conf['api_password']

    res = blockstack_client.rpc.local_api_stop(config_dir=config_dir)

    res = blockstack_client.rpc.local_api_start(api_pass=api_pass, port=port, config_dir=config_dir, password=password)
    if not res:
        return {'error': 'Failed to start API server'}

    return {'status': True}

    
def instantiate_wallet():
    """
    Load the current wallet's addresses into bitcoin.
    This also starts up the background daemon.
    Return {'owner_address': ..., 'payment_address': ...} on success
    Return {'error': ...} on error
    """
    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG")
    assert config_path is not None

    conf = blockstack_client.get_config(config_path)
    port = int(conf['api_endpoint_port'])
    api_pass = conf['api_password']

    res = blockstack_client.rpc.local_api_start(api_pass=api_pass, port=port, config_dir=os.path.dirname(config_path), password="0123456789abcdef")
    if not res:
        return {'error': 'Failed to start API server'}

    wallet_info = blockstack_client.actions.get_wallet_with_backoff(config_path)
    if 'error' in wallet_info:
        return wallet_info

    if 'owner_address' not in wallet_info:
        return {'error': 'missing owner_address'}

    if 'payment_address' not in wallet_info:
        return {'error': 'missing payment_address'}

    owner_address = str(wallet_info['owner_address'])
    payment_address = str(wallet_info['payment_address'])

    # also track owner address outputs 
    bitcoind = get_bitcoind()
    try:
        bitcoind.importaddress(owner_address, "", True)
    except virtualchain.JSONRPCException, je:
        if je.code == -4:
            # key already loaded; this isn't a problem 
            pass
        else:
            raise

    return {'owner_address': owner_address, 'payment_address': payment_address}


def get_balance( addr ):
    """
    Get the address balance
    """
    inputs = blockstack_client.backend.blockchain.get_utxos(addr)
    return sum([inp['value'] for inp in inputs])


def send_funds_tx( privkey, satoshis, payment_addr ):
    """
    Make a signed transaction that will send the given number
    of satoshis to the given payment address
    """
    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    assert config_path is not None

    payment_addr = str(payment_addr)
    log.debug("Send {} to {}".format(satoshis, payment_addr))

    bitcoind = get_bitcoind()

    try:
        bitcoind.importaddress(payment_addr, "", True)
    except virtualchain.JSONRPCException, je:
        if je.code == -4:
            # key already loaded
            pass
        else:
            raise

    send_addr = virtualchain.BitcoinPrivateKey(privkey).public_key().address()
    
    inputs = blockstack_client.backend.blockchain.get_utxos(send_addr)
    outputs = [
        {"script": virtualchain.make_payment_script(payment_addr),
         "value": satoshis},
        
        {"script": virtualchain.make_payment_script(send_addr),
         "value": virtualchain.calculate_change_amount(inputs, satoshis, 5500)},
    ]

    serialized_tx = blockstack_client.tx.serialize_tx(inputs, outputs)
    signed_tx = blockstack_client.tx.sign_tx(serialized_tx, privkey)
    return signed_tx


def send_funds( privkey, satoshis, payment_addr ):
    """
    Send funds from a private key (in satoshis) to an address
    """
    signed_tx = send_funds_tx(privkey, satoshis, payment_addr)
    return blockstack_client.tx.broadcast_tx(signed_tx)


def sendrawtransaction( tx_hex, **kw ):
    """
    Send a raw transaction to the regtest bitcoind
    """
    global bitcoind
    return bitcoind.sendrawtransaction( tx_hex )


def getrawtransaction( txid, verbose, **kw ):
    """
    Get a raw transaction from the regtest bitcoind
    """
    global bitcoind
    return bitcoind.getrawtransaction( txid, verbose )


def getbalance( addr, **kw ):
    """
    Get the balance of an address
    """
    global bitcoind
    return bitcoind.getbalance( addr )


def next_block( **kw ):
    """
    Advance the mock blockchain by one block.
    Required keyword arguments:
    * bitcoind: the regtest bitcoind connection
    * sync_virtualchain_upcall: a no-argument callable that will sync
    the blockstack db with the virtual chain
    """

    global snapshots_dir, state_engine
    
    if snapshots_dir is None:
        snapshots_dir = tempfile.mkdtemp( prefix='blockstack-test-databases-' )

    del state_engine

    # flush all transactions, and re-set state engine
    kw['next_block_upcall']()
    kw['sync_virtualchain_upcall']()
    
    # snapshot the database
    blockstack_export_db( os.path.join( snapshots_dir, "blockstack.db" ), get_current_block(**kw), **kw )
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
    Get the current block height.
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

    old_working_dir = os.environ['VIRTUALCHAIN_WORKING_DIR']
    for block_id in block_ids:
    
        state_engine.lastblock = block_ids[0]
        expected_consensus_hash = all_consensus_hashes[ block_id ]
        untrusted_db_path = os.path.join( snapshots_dir, "blockstack.db.%s" % block_id )
        atlasdb_path = os.path.join( snapshots_dir, "atlas.db.%s" % block_id)

        working_db_dir = os.path.join( snapshots_dir, "work.%s" % block_id )
        working_atlasdb_path = os.path.join( working_db_dir, "atlas.db" )

        os.makedirs( working_db_dir )
        shutil.copy( atlasdb_path, working_atlasdb_path )

        os.environ["VIRTUALCHAIN_WORKING_DIR"] = working_db_dir
        working_db_path = os.path.join( working_db_dir, "blockstack.db.%s" % block_id )
        
        print "\n\nverify %s - %s (%s), expect %s\n\n" % (block_ids[0], block_id+1, untrusted_db_path, expected_consensus_hash)

        valid = blockstack_verify_database( expected_consensus_hash, block_id, untrusted_db_path, working_db_path=working_db_path, start_block=block_ids[0] )
        if not valid:
            print "Invalid at block %s" % block_id 
            os.environ["VIRTUALCHAIN_WORKING_DIR"] = old_working_dir
            return False

    os.environ["VIRTUALCHAIN_WORKING_DIR"] = old_working_dir
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

        if api_call.method == "register":
            name = api_call.name
            opcode = "NAME_REGISTRATION"

        elif api_call.method == "name_import":
            name = api_call.name
            opcode = "NAME_IMPORT"
           
        elif api_call.method == "update":
            name = api_call.name
            opcode = "NAME_UPDATE"
        
        elif api_call.method == "transfer":
            name = api_call.name
            opcode = "NAME_TRANSFER"

        elif api_call.method == "revoke":
            name = api_call.name
            opcode = "NAME_REVOKE"

        if name is not None:
            block_id = int(api_call.block_id)
            consensus_hash = all_consensus_hashes.get( block_id, None )
            txid = api_call.result.get('transaction_hash', None)
            err = api_call.result.get('error', None)

            if consensus_hash is None:
                log.error("Missing consensus hash at %s" % block_id)
                log.error("all consensus hashes:\n%s" % json.dumps(all_consensus_hashes, indent=4, sort_keys=True))
                raise Exception("Missing consensus hash")

            if txid is None and not api_call.result.has_key('error'):
                log.error("Missing transaction_hash for '%s' on '%s' in %s" % (api_call.method, api_call.name, block_id))
                raise Exception("Missing txid")

            if not all_names.has_key( name ):
                all_names[name] = {}
                
            if not all_names[name].has_key(block_id):
                all_names[name][block_id] = {
                    'consensus_hash': consensus_hash,
                    'opcode_sequence': [opcode],
                    'txid_sequence': [txid],
                    'error_sequence': [err]
                }
            
            else:
                # multiple opcodes in this block 
                all_names[name][block_id]['opcode_sequence'].append(opcode)
                all_names[name][block_id]['txid_sequence'].append(txid)
                all_names[name][block_id]['error_sequence'].append(err)


    for block_id, name_list in snv_fail_at.items():
        log.debug("Expect SNV fail on %s at %s" % (",".join(name_list), block_id))

    log.debug("SNV verify %s names" % len(all_names.keys()))

    for name in all_names.keys():

        for block_id in all_names[name].keys():

            consensus_hash = all_names[name][block_id]['consensus_hash']
            txid_sequence = all_names[name][block_id]['txid_sequence']
            opcode_sequence = all_names[name][block_id]['opcode_sequence']
            error_sequence = all_names[name][block_id]['error_sequence']

            log.debug("SNV verify %s (from %s)" % (name, block_id))
            log.debug("opcodes: %s" % opcode_sequence)
            log.debug("txids: %s" % txid_sequence)
            log.debug("errors: %s" % error_sequence)

            for j in xrange(0, len(txid_sequence)):
                
                opcode = opcode_sequence[j]
                txid = txid_sequence[j]
                err = error_sequence[j]

                if err is not None:
                    raise Exception("Test misconfigured: error '%s' at block %s" % (err, block_id))

                log.debug("Verify %s %s" % (opcode, txid))
                for i in xrange( block_id + 1, max(all_consensus_hashes.keys()) + 1 ):

                    trusted_block_id = i

                    try:
                        trusted_consensus_hash = all_consensus_hashes[i]
                    except KeyError:
                        print json.dumps(all_consensus_hashes, indent=4, sort_keys=True)
                        os.abort()

                    snv_recs = blockstack_client.snv_lookup( name, block_id, trusted_consensus_hash, proxy=test_proxy, trusted_txid=txid )
                    if 'error' in snv_recs:
                        if name in snv_fail:
                            log.debug("SNV lookup %s failed as expected" % name)
                            continue 

                        if name in snv_fail_at.get(block_id, []):
                            log.debug("SNV lookup %s failed at %s as expected" % (name, block_id))
                            continue 

                        print json.dumps(snv_recs, indent=4, sort_keys=True )
                        return False 

                    if len(snv_recs) > 1:
                        print "snv_lookup(%s, %s, %s, %s)" % (name, block_id, trusted_consensus_hash, txid)
                        print json.dumps(snv_recs, indent=4, sort_keys=True)
                        return False

                    assert len(snv_recs) <= 1, "Multiple SNV records returned"
                    snv_rec = snv_recs[0]

                    if snv_rec['name'] != name:
                        print "mismatch name"
                        print json.dumps(snv_rec, indent=4, sort_keys=True )
                        return False 

                    if snv_rec['txid'] != txid:
                        print "mismatch txid at %s: expected %s, got %s" % (j, txid, snv_rec['txid'])
                        print json.dumps(snv_rec, indent=4, sort_keys=True)
                        return False

                    if opcode is not None and snv_rec['opcode'] != opcode:
                        print "mismatch opcode at %s: expected %s, got %s" % (j, opcode, snv_rec['opcode'])
                        print json.dumps(snv_rec, indent=4, sort_keys=True )
                        return False 

                    if name in snv_fail:
                        print "looked up name '%s' that was supposed to fail SNV" % name
                        return False 

                    # QUIRK: if imported, then the fee must be a float.  otherwise, it must be an int 
                    if snv_rec['opcode'] == 'NAME_IMPORT' and type(snv_rec['op_fee']) != float:
                        print "QUIRK: NAME_IMPORT: fee isn't a float"
                        return False 

                    elif type(snv_rec['op_fee']) not in [int,long]:
                        print "QUIRK: %s: fee isn't an int (but a %s: %s)" % (snv_rec['opcode'], type(snv_rec['op_fee']), snv_rec['op_fee'])

                    log.debug("SNV verified %s with (%s,%s) back to (%s,%s)" % (name, trusted_block_id, trusted_consensus_hash, block_id, consensus_hash ))

    return True


def check_atlas_zonefiles( state_engine, atlasdb_path ):
    """
    Verify that all zonefile hashes have been added
    to the atlas peer, for each NAME_UPDATE and NAME_IMPORT
    """

    global api_call_history
    global snv_fail 
    global snv_fail_at
    global atlas_zonefiles_present

    atlas_zonefiles_present = list(set(atlas_zonefiles_present))

    for api_call in api_call_history:
        if api_call.method not in ["update", "name_import"]:
            continue
     
        name = api_call.name
        block_id = api_call.block_id
        value_hash = api_call.result['value_hash']
 
        if name in snv_fail:
            continue

        if name in snv_fail_at.get(block_id, []):
            continue

        log.debug("Verify Atlas zonefile hash %s for %s in '%s' at %s" % (value_hash, name, api_call.method, block_id))

        zfinfo = blockstack.atlasdb_get_zonefile( value_hash, path=atlasdb_path )
        if zfinfo is None or len(zfinfo) == 0:
            log.error("Zonefile %s is not present in the Atlas DB at %s" % (value_hash, atlasdb_path))
            return False

        if value_hash in atlas_zonefiles_present and not zfinfo['present']:
            log.error("Zonefile %s should be present, but isn't" % (value_hash))
            return False
       
    for value_hash in atlas_zonefiles_present:

        zfinfo = blockstack.atlasdb_get_zonefile( value_hash, path=atlasdb_path )
        if zfinfo is None or len(zfinfo) == 0:
            log.error("Expected zonefile hash %s" % value_hash)
            return False

        if not zfinfo['present']:
            log.error("Expected zonefile %s to be present" % value_hash)
            return False

    return True 
        

def check_data_urls():
    """
    Verify that all data URLs generated over the course
    of adding data result in the designated data.
    """

    global data_urls
    global deleted_urls

    for data_url, expected_data in data_urls.iteritems():
        log.debug("Verify URL {}".format(data_url))
        data = blockstack_cli_get_data(data_url)
        if 'error' in data:
            log.error("Failed to get {}: {}".format(data_url, data['error']))
            return False

        if data['data'] != expected_data:
            log.error("Wrong data for {}: {} ({}) != {} ({})".format(data_url, expected_data, type(expected_data), data['data'], type(data['data'])))
            return False

    for data_url in deleted_urls:
        log.debug("Verify deleted URL {}".format(data_url))
        data = blockstack_cli_get_data(data_url)
        if 'error' not in data:
            log.error("Succeeded in getting deleted data {}".format(data_url))
            return False

    return True


def get_unspents( addr ):
    """
    Get the list of unspent outputs for an address.
    """
    utxo_provider = get_utxo_client()
    return blockstack_client.backend.utxo.get_unspents(addr, utxo_provider)


def broadcast_transaction( tx_hex ):
    """
    Send out a raw transaction to the mock framework.
    """
    utxo_provider = get_utxo_client()
    return blockstack_client.backend.utxo.broadcast_transaction(tx_hex, utxo_provider)


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
    utxo_provider = blockstack_client.backend.utxo.bitcoind_utxo.BitcoindClient("blockstack", "blockstacksystem", port=18332, version_byte=virtualchain.version_byte )
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

def set_wallets(ws):
    global wallets
    wallets = ws

def find_wallet(addr):
    global wallets
    for w in wallets:
        if w.addr == addr:
            return w

    raise Exception("No wallet for {}".format(addr))

def gpg_key_dir( **kw ):
    return os.path.join( kw['working_dir'], "keys" )

def working_dir( **kw ):
    return kw['working_dir']

def last_block( **kw ):
    global state_engine
    return state_engine.lastblock


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


def migrate_profile( name, proxy=None, wallet_keys=None, zonefile_has_data_key=True, config_path=None ):
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
        proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( proxy )

    assert wallet_keys
    config_path = proxy.config_path if config_path is None else config_path

    user_profile = None
    user_zonefile = None

    res = blockstack_cli_lookup(name, config_path=config_path)
    if 'error' in res:

        name_rec = blockstack_cli_get_name_blockchain_record(name, config_path=config_path)
        if 'error' in name_rec:
            return name_rec

        # empty
        user_profile = blockstack_client.user.make_empty_user_profile()
        user_zonefile = blockstack_client.zonefile.make_empty_zonefile(name, wallet_keys['data_pubkey'])

    else:
        user_profile = res['profile']
        user_zonefile_txt = res['zonefile']

        try:
            user_zonefile_json = json.loads(user_zonefile_txt)
            if blockstack_profiles.is_profile_in_legacy_format(user_zonefile_json):
                user_profile = blockstack_profiles.get_person_from_legacy_format(user_zonefile_json)
                
            user_zonefile = blockstack_client.zonefile.make_empty_zonefile(name, wallet_keys['data_pubkey'])
        except Exception as e:
            log.exception(e)
            user_zonefile = blockstack_zones.parse_zone_file(user_zonefile_txt)

    if not zonefile_has_data_key:
        # remove the TXT record with the public key
        log.debug("Remvoe zonefile public key")
        user_zonefile = blockstack_client.user.user_zonefile_remove_data_pubkey(user_zonefile)

    payment_privkey_info = blockstack_client.get_payment_privkey_info( wallet_keys=wallet_keys, config_path=proxy.conf['path'] )
    owner_privkey_info = blockstack_client.get_owner_privkey_info( wallet_keys=wallet_keys, config_path=proxy.conf['path'] )
    data_privkey_info = blockstack_client.get_data_privkey_info( user_zonefile, wallet_keys=wallet_keys, config_path=proxy.conf['path'] )

    assert data_privkey_info is not None
    assert 'error' not in data_privkey_info, str(data_privkey_info)

    assert virtualchain.is_singlesig(data_privkey_info)

    user_zonefile_hash = blockstack_client.hash_zonefile( user_zonefile )
    
    # replicate the profile
    # TODO: this is onename-specific

    rc = blockstack_client.profile.put_profile(name, user_profile, blockchain_id=name,
                                              user_data_privkey=data_privkey_info, user_zonefile=user_zonefile,
                                              proxy=proxy, wallet_keys=wallet_keys )

    if 'error' in rc:
        log.error("Failed to put profile: {}".format(rc['error']))
        return {'error': 'Failed to move legacy profile to profile zonefile'}

    # do the update 
    res = blockstack_client.do_update( name, user_zonefile_hash, owner_privkey_info, payment_privkey_info, proxy, proxy, config_path=proxy.config_path, proxy=proxy )
    api_call_history.append( APICallRecord( "update", name, res ) )

    if 'error' in res:
        return {'error': 'Failed to send update transaction: %s' % res['error']}

    # replicate the zonefile
    rc, new_hash = blockstack_client.zonefile.store_name_zonefile( name, user_zonefile, res['transaction_hash'] )
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


def peer_make_config( peer_port, dirp, seed_relations={}, blacklist_relations={}, extra_fields={} ):
    """
    Make a config directory for a peer blockstack server
    """
    hostport = "localhost:%s" % peer_port

    # generate server config
    blockstack_conf = blockstack.default_blockstack_opts()
    virtualchain_bitcoin_conf = virtualchain.get_bitcoind_config()

    virtualchain_bitcoin_conf['bitcoind_port'] = 18332
    virtualchain_bitcoin_conf['bitcoind_p2p_port'] = 18444 
    virtualchain_bitcoin_conf['bitcoind_server'] = 'localhost'
    virtualchain_bitcoin_conf['bitcoind_regtest'] = True
    virtualchain_bitcoin_conf['bitcoind_spv_path'] = os.path.join( dirp, "spv_headers.dat" )

    blockstack_conf['rpc_port'] = peer_port
    blockstack_conf['server_version'] = '0.14.1'
    blockstack_conf['zonefiles'] = os.path.join( dirp, 'zonefiles' )
    blockstack_conf['atlas_seeds'] = ",".join( ["localhost:%s" % p for p in seed_relations.get(peer_port, []) ] )
    blockstack_conf['atlas_blacklist'] = ",".join( ["localhost:%s" % p for p in blacklist_relations.get(peer_port, [])] )
    blockstack_conf['atlasdb_path'] = os.path.join( dirp, 'atlas.db' )
    blockstack_conf['atlas_hostname'] = 'localhost'

    bitcoin_conf = {}
    for key in virtualchain_bitcoin_conf.keys():
        if key.startswith("bitcoind_"):
            newkey = key[len('bitcoind_'):]
            bitcoin_conf[newkey] = virtualchain_bitcoin_conf[key]

    conf = {
        'bitcoind': bitcoin_conf,
        'blockstack': blockstack_conf
    }

    conf_path = os.path.join( dirp, 'blockstack-server.ini' )
    log.debug("Save server config for localhost:%s to %s" % (peer_port, conf_path))

    if not os.path.exists(dirp):
        os.makedirs(dirp)

    blockstack_client.config.write_config_file( conf, conf_path )

    # copy over client config
    client_config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG")
    client_conf = blockstack_client.config.configure( config_file=client_config_path, force=False, interactive=False )

    for f in ['path', 'dir']:
        if f in client_conf['blockstack-client']:
            del client_conf['blockstack-client'][f]

    # update...
    client_conf['blockstack-client']['queue_path'] = os.path.join(dirp, 'queues.db')
    client_conf['blockstack-client']['metadata'] = os.path.join(dirp, 'metadata')
    client_conf['blockstack-client']['blockchain_headers'] = virtualchain_bitcoin_conf['bitcoind_spv_path']
    client_conf['blockstack-client']['api_endpoint_port'] = peer_port + 10000
    client_conf['blockstack-client']['port'] = peer_port

    new_conf = {
        'blockstack-client': client_conf['blockstack-client'],
        'bitcoind': client_conf['bitcoind'],
        'blockchain-reader': client_conf['blockchain-reader'],
        'blockchain-writer': client_conf['blockchain-writer']
    }

    new_conf.update(extra_fields)

    log.debug("Save client for localhost:%s's to %s" % (peer_port, os.path.join(dirp, 'client.ini')))
    blockstack_client.config.write_config_file( new_conf, os.path.join(dirp, "client.ini") )
    return True


def peer_start( working_dir, port=None, command='start', args=['--foreground']):
    """
    Start up a peer blockstack subprocess
    to communicate on the given network server.
    Return a dict with the peer information.
    """
    args = ['blockstack-core', command] + args
    if port:
        args += ['--port', str(port)]

    output = os.path.join(working_dir, "blockstack-server.out")

    env = {}

    # preserve test environment variables
    for envar in os.environ.keys():
        if envar.startswith("BLOCKSTACK_") and envar not in ['BLOCKSTACK_CLIENT_CONFIG', 'BLOCKSTACK_SERVER_CONFIG']:
            log.debug("Env: '%s' = '%s'" % (envar, os.environ[envar]))
            env[envar] = os.environ[envar]

    env['VIRTUALCHAIN_WORKING_DIR'] = working_dir
    env['BLOCKSTACK_ATLAS_NETWORK_SIMULATION'] = "1"
    env['BLOCKSTACK_ATLAS_NETWORK_SIMULATION_PEER'] = "1"
    env['BLOCKSTACK_SERVER_CONFIG'] = os.path.join(working_dir, 'blockstack-server.ini')
    env['BLOCKSTACK_CLIENT_CONFIG'] = os.path.join(working_dir, 'client/client.ini')

    env['PATH'] = os.environ['PATH']

    fd = open(output, "w")

    proc = subprocess.Popen( args, stdout=fd, stderr=fd, shell=False, env=env )

    peer_info = {
        'proc': proc,
        'port': port
    }

    return peer_info


def peer_rpc( peer_info ):
    """
    Get an RPC client to the running peer
    """
    rpc = blockstack_client.BlockstackRPCClient( 'localhost', peer_info['port'], timeout=5 )
    return rpc


def peer_has_zonefiles( peer_info, lastblock, num_zonefiles ):
    """
    Is this peer synchronized up to the number of zone files?
    Return True if the peer caught up
    Return False if not
    Return None on error
    """

    # see how far we've gotten 
    rpc = peer_rpc( peer_info )
    info = None
    peer_inv = None

    try:
        info = rpc.getinfo()
    except Exception, e:
        log.exception(e)
        log.error("Peer localhost:%s is down" % (peer_info['port']))
        return False

    if info['last_block_processed'] < lastblock:
        log.debug("Peer localhost:%s is at %s (but we're at %s)" % (peer_info['port'], info['last_block_processed'], lastblock))
        return False

    try:
        peer_inv_info = rpc.get_zonefile_inventory( 0, num_zonefiles )
        peer_inv = atlas_inventory_to_string( base64.b64decode(peer_inv_info['inv']) )
    except Exception, e:
        log.exception(e)
        log.error("Peer localhost:%s is down" % (peer_info['port']))
        return False

    log.debug("inv for localhost:%s is %s.  Require %s zonefiles" % (peer_info['port'], peer_inv, num_zonefiles))
    zonefile_count = 0

    for i in xrange(0, min(len(peer_inv), num_zonefiles)):
        if peer_inv[i] == '1':
            zonefile_count += 1

    if zonefile_count < num_zonefiles:
        return False

    return True


def peer_join( peer_info ):
    """
    Stop an blockstack peer
    """
    proc = peer_info['proc']
    proc.send_signal( signal.SIGTERM )

    time.sleep(0.5)

    rc = proc.returncode
    if rc is None:
        # still running
        time.sleep(1.0)
        if proc.returncode is None:
            try:
                proc.send_signal( signal.SIGKILL )
            except:
                pass


def peer_working_dir( index ):
    """
    Get the working dir for a peer
    """
    working_dir = os.environ.get("VIRTUALCHAIN_WORKING_DIR", None)
    assert working_dir
    peer_wd = os.path.join(working_dir, 'peer-{}'.format(index))
    return peer_wd


def peer_setup( index ):
    """
    Set up the ith peer
    Return {'working_dir': ..., 'device_id': ..., 'config_path': ...} on success
    Return {'error': ...} on error 
    """
    # set up a new peer
    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    assert config_path

    config_dir = os.path.dirname(config_path)

    peer_wd = peer_working_dir(index)
    peer_config_dir = os.path.join(peer_wd, 'client')

    os.makedirs(peer_wd)
    os.makedirs(peer_config_dir)

    config_path_2 = os.path.join(peer_config_dir, 'client.ini')
    if os.path.exists(config_path_2):
        raise Exception("Config already exists for client {}".format(index))

    res = peer_make_config(16300 + index, peer_wd)
    if 'error' in res:
        print "failed to set up {}".format(peer_wd)
        return {'error': 'failed to set up config dir'}

    return {'working_dir': peer_wd, 'device_id': res['device_id'], 'config_path': config_path_2}


def list_working_dirs():
    """
    Find all working directories
    """
    working_dir = os.environ.get("VIRTUALCHAIN_WORKING_DIR", None)
    assert working_dir

    ret = [working_dir]

    # account for all peers too 
    for name in os.listdir(working_dir):
        if name.startswith("peer-"):
            ret.append(os.path.join(working_dir, name))

    return ret


def make_client_device( index ):
    """
    Make another client device, and add it to all other devices.
    Return {'status': True, 'config_path': config path} on success
    Return {'error': ...} on failure
    """
    # set up a second peer
    res = peer_setup( index )
    if 'error' in res:
        return res

    config_path_2 = res['config_path']
    my_device_id = res['device_id']

    all_working_dirs = list_working_dirs()
    all_config_paths = [os.path.join(wd, 'client/client.ini') for wd in all_working_dirs]

    # add this device to all other devices
    for dev_config_path in all_config_paths:
        if os.path.exists(dev_config_path):

            device_id_info = blockstack_cli_get_device_id(config_path=dev_config_path)
            if 'error' in device_id_info:
                continue

            device_id = device_id_info['device_id']
            if my_device_id != device_id:
                # add here 
                res = blockstack_cli_add_device_id(device_id, config_path=dev_config_path)
                if 'error' in res:
                    print "failed to add device {} to {}".format(device_id, dev_config_path)
                    return res

    return {'status': True}


def verify_in_queue( ses, name, queue_name, tx_hash, expected_length=1 ):
    """
    Verify that a name (optionally with the given tx hash) is in the given queue
    """
    # verify that it's in the queue 
    res = blockstack_REST_call('GET', '/v1/blockchains/bitcoin/pending', ses )
    if 'error' in res:
        res['test'] = 'Failed to get queues'
        print json.dumps(res)
        error = True
        return False

    res = res['response']

    # needs to be in the queue 
    if not res.has_key('queues'):
        res['test'] = 'Missing queues'
        print json.dumps(res)
        error = True
        return False

    if not res['queues'].has_key(queue_name):
        res['test'] = 'Missing {} queue'.format(queue_name)
        print json.dumps(res)
        error = True
        return False
    
    if len(res['queues'][queue_name]) != expected_length:
        res['test'] = 'invalid preorder queue'
        print json.dumps(res)
        error = True
        return False

    found = False
    for queue_entry in res['queues'][queue_name]:
        if queue_entry['name'] != name:
            continue

        found = True

        if tx_hash is not None and queue_entry['tx_hash'] != tx_hash:
            res['test'] = 'tx hash mismatch: expected {}'.format(tx_hash)
            print json.dumps(res)
            error = True
            return False

        break

    if not found:
        print "name {} not found in queues".format(name)
        print json.dumps(res)
        return False

    # verify that it's name resolves to the right queue state 
    res = blockstack_REST_call("GET", "/v1/names/{}".format(name), ses)
    if 'error' in res:
        res['test'] = 'Failed to query name'
        print json.dumps(res)
        error = True
        return False

    if res['http_status'] != 200 and res['http_status'] != 404:
        res['test'] = 'HTTP status {}, response = {}'.format(res['http_status'], res['response'])
        print json.dumps(res)
        error = True
        return False

    # should be in the preorder queue at some point 
    if res['response']['operation'] != queue_name:
        return False


    return True


def nodejs_cleanup(dirp):
    """
    Clean up nodejs test
    """
    if not os.path.exists(dirp):
        return True

    print "Clean up Node install at {}".format(dirp)
    shutil.rmtree(dirp)
    return True


def nodejs_setup():
    """
    Set up a working directory for testing Blockstack node.js packages
    """
    for prog in ['npm', 'node', 'babel', 'browserify']:
        rc = os.system('which {}'.format(prog))
        if rc != 0:
            raise Exception("Could not find program {}".format(prog))

    tmpdir = tempfile.mkdtemp()
    atexit.register(nodejs_cleanup, tmpdir)
    
    print "Node install at {}".format(tmpdir)
    return tmpdir


def nodejs_copy_package( testdir, package_name ):
    """
    Copy the contents of a package into the test directory
    """
    node_package_path = '/usr/lib/node_modules/{}'.format(package_name)
    if not os.path.exists(node_package_path):
        raise Exception("Missing node package {}: no directory {}".format(package_name, node_package_path))

    rc = os.system('cp -a "{}"/* "{}"'.format(node_package_path, testdir))
    if rc != 0:
        raise Exception("Failed to copy {} to {}".format(node_package_path, testdir))

    return True


def nodejs_link_package( testdir, package_name ):
    """
    Link a dependency to a package
    """
    rc = os.system('cd "{}" && npm link "{}"'.format(testdir, package_name))
    if rc != 0:
        raise Exception("Failed to link {} to {}".format(package_name, testdir))
    
    return True


def nodejs_run_test( testdir, test_name="core-test" ):
    """
    Run a nodejs test
    """
    rc = os.system('cd "{}" && npm run {}'.format(testdir, test_name))
    if rc != 0:
        raise Exception("Test {} failed".format(test_name))

    return True


