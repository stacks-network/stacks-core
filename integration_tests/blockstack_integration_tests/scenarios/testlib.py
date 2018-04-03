#!/usr/bin/env python2
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
import re
from decimal import Decimal
import blockstack.blockstackd as blockstackd
import blockstack.lib.client as blockstackd_client
import blockstack.lib.snv as snv_client

import blockstack
import keylib

import virtualchain

log = virtualchain.get_logger("testlib")

import blockstack_client

SATOSHIS_PER_COIN = 10**8

TX_MIN_CONFIRMATIONS = 6
if os.environ.get("BLOCKSTACK_TEST", None) is not None:
    # test environment
    TX_MIN_CONFIRMATIONS = 0
    print 'TEST ACTIVE: TX_MIN_CONFIRMATIONS = {}'.format(TX_MIN_CONFIRMATIONS)

if os.environ.get("BLOCKSTACK_MIN_CONFIRMATIONS", None) is not None:
    TX_MIN_CONFIRMATIONS = int(os.environ['BLOCKSTACK_MIN_CONFIRMATIONS'])
    print >> sys.stderr, "Set TX_MIN_CONFIRMATIONS to {}".format(TX_MIN_CONFIRMATIONS)


class Wallet(object):
    def __init__(self, pk_wif, tokens_granted, vesting_schedule={} ):

        pk = virtualchain.BitcoinPrivateKey( pk_wif )

        self._pk = pk
        self._token_grant = tokens_granted
        self._vesting_schedule = vesting_schedule

        if pk_wif.startswith("c"):
            # already a private key 
            self.privkey = keylib.ECPrivateKey(pk_wif).to_hex()
        else:
            self.privkey = pk.to_hex()

        self.pubkey_hex = pk.public_key().to_hex()
        self.addr = pk.public_key().address()
        self.segwit = False

        if os.environ.get('BLOCKSTACK_TEST_FORCE_SEGWIT') == '1':
            self.segwit = True
            self.privkey = virtualchain.make_segwit_info(pk_wif)
            log.debug("P2SH-P2WPKH Wallet %s (%s)" % (self.privkey, self.addr))

        else:
            log.debug("Wallet %s (%s)" % (self.privkey, self.addr))

            # for consensus history checker  
            log.debug("BLOCKSTACK_SERIALIZATION_CHECK_WALLET: {}".format(json.dumps({
                'type': 'singlesig',
                'public_key': self.pubkey_hex
            })))


class MultisigWallet(object):
    def __init__(self, m, *pks, **kwargs ):

        self.privkey = virtualchain.make_multisig_info( m, pks )
        self.m = m
        self.n = len(pks)
        self.pks = pks
        self.segwit = False
        self._token_grant = kwargs.get('tokens_granted', 0)
        self._vesting_schedule = kwargs.get('vesting_schedule', {})

        self.addr = self.privkey['address']

        if os.environ.get('BLOCKSTACK_TEST_FORCE_SEGWIT') == '1':
            self.segwit = True
            self.privkey = virtualchain.make_multisig_segwit_info( m, pks )
            log.debug("Multisig P2SH-P2WSH wallet %s" % (self.addr))

        else:
            log.debug("Multisig wallet %s" % (self.addr))


class SegwitWallet(object):
    def __init__(self, pk_wif, tokens_granted=0, vesting_schedule={} ):

        self.privkey = virtualchain.make_segwit_info( pk_wif )
        pk = virtualchain.BitcoinPrivateKey( pk_wif )

        self._pk = pk
        self.segwit = True
        self._token_grant = tokens_granted
        self._vesting_schedule = vesting_schedule

        self.pubkey_hex = pk.public_key().to_hex()
        self.addr = self.privkey['address']
        
        log.debug("P2SH-P2WPKH Wallet %s (%s)" % (self.privkey, self.addr))


class MultisigSegwitWallet(object):
    def __init__(self, m, *pks ):

        self.privkey = virtualchain.make_multisig_segwit_info( m, pks )
        self.m = m
        self.n = len(pks)
        self.pks = pks
        self.segwit = True

        self.addr = self.privkey['address']

        log.debug("Multisig P2SH-P2WSH wallet %s" % (self.addr))
       

class APICallRecord(object):
    def __init__(self, method, name, address, result, token_record=None):
        self.block_id = max(all_consensus_hashes.keys()) + 1
        self.name = name
        self.method = method
        self.result = result
        self.address = address
        self.token_record = token_record
        self.success = True
        assert 'transaction_hash' in result.keys() or 'error' in result.keys()


# for auditing expenditures
class TokenOperation(object):
    def __init__(self, opcode, token_type, token_cost, account_addr):
        self.opcode = opcode
        self.token_type = token_type
        self.token_cost = token_cost
        self.account_addr = account_addr

class TokenNamespacePreorder(TokenOperation):
    def __init__(self, namespace_id, payment_addr):
        blockstackd_url = 'http://localhost:16264'
        namespace_cost_info = blockstackd_client.get_namespace_cost(namespace_id, hostport=blockstackd_url)
        super(TokenNamespacePreorder, self).__init__("NAMESPACE_PREORDER", namespace_cost_info['units'], namespace_cost_info['amount'], payment_addr)


class TokenNamePreorder(TokenOperation):
    def __init__(self, name, preorder_addr):
        blockstackd_url = 'http://localhost:16264'
        name_cost_info = blockstackd_client.get_name_cost(name, hostport=blockstackd_url)
        super(TokenNamePreorder, self).__init__('NAME_PREORDER', name_cost_info['units'], name_cost_info['amount'], preorder_addr)


class TokenNameRenewal(TokenOperation):
    def __init__(self, name, owner_addr):
        blockstackd_url = 'http://localhost:16264'
        name_cost_info = blockstackd_client.get_name_cost(name, hostport=blockstackd_url)
        super(TokenNameRenewal, self).__init__('NAME_RENEWAL', name_cost_info['units'], name_cost_info['amount'], owner_addr)


class TestAPIProxy(object):
    def __init__(self):
        global utxo_opts

        client_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
        assert client_path is not None

        client_config = blockstack_client.get_config(client_path)

        log.debug("Connect to Blockstack node at {}:{}".format(client_config['server'], client_config['port']))
        self.client = blockstack.lib.client.BlockstackRPCClient(
            client_config['server'], client_config['port'], protocol = client_config['protocol'])

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
        self.min_confirmations = TX_MIN_CONFIRMATIONS

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

# server state 
server_state = None

# is the test running
test_running = True

# where's the node.js CLI?
NODEJS_CLI_PATH = None

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

    if block_id not in snv_fail_at.keys():
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
    proxy.min_confirmations = int(os.environ.get("BLOCKSTACK_MIN_CONFIRMATIONS", blockstack_client.constants.TX_MIN_CONFIRMATIONS))

    return proxy


def blockstack_get_name_cost(name, config_path=None):
    blockstackd_url = 'http://localhost:16264'
    name_cost_info = blockstackd_client.get_name_cost(name, hostport=blockstackd_url)
    return name_cost_info['amount']


def has_nodejs_cli():
    """
    Do we have the node.js CLI installed, which uses blockstack.js?
    """
    global NODEJS_CLI_PATH
    if NODEJS_CLI_PATH:
        return True

    p = subprocess.Popen('which blockstack-cli', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    retcode = p.returncode
    if retcode != 0:
        return False

    NODEJS_CLI_PATH = out.strip()
    return True


def nodejs_cli(*args, **kw):
    """
    Run the node.js CLI tool
    Returns the last line of output
    """
    safety_checks = kw.get('safety_checks', True)
    consensus_hash = kw.get('consensus_hash', None)
    tx_fee = kw.get('tx_fee', None)
    burn_address = kw.get('burn_addr', None)
    pattern = kw.get('pattern', None)
    full_output = kw.get('full_output', False)

    if NODEJS_CLI_PATH is None:
        if not has_nodejs_cli():
            raise Exception("No node.js CLI found")

    base_cmd = [NODEJS_CLI_PATH, '-t']
    if not safety_checks:
        base_cmd += ['-U']

    if consensus_hash:
        base_cmd += ['-C', consensus_hash]

    if burn_address:
        base_cmd += ['-B', burn_address]

    base_cmd_save = base_cmd[:]

    if tx_fee:
        base_cmd += ['-x']      # don't send just yet; get the size and then update the fee rate
    
    saved_out = [None]
    saved_err = [None]

    def run(cmd_opts, cmd_args):
        cmd = cmd_opts + cmd_args
        log.debug('\n$ {}\n'.format(' '.join(cmd)))

        p = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        res = p.returncode
        if res != 0:
            print err

            print 'Sleeping for 10 minutes so you can experiment with what went wrong'
            time.sleep(600)
            raise Exception("Exit code {}: {}".format(res, cmd))

        ret = None
        if full_output:
            ret = out
        else:
            ret = out.strip().split('\n')[-1]

        saved_out[0] = out
        saved_err[0] = err
        return ret

    ret = run(base_cmd, list(args))
    if not tx_fee:
        if pattern:
            assert re.match(pattern, ret), 'Output does not match {}: {}\nfull output:\n{}\nerror:\n{}'.format(pattern, ret, saved_out[0], saved_err[0])

        return ret

    # ret will be a transaction in full
    txlen = len(ret)/2
    tx_fee_rate = int(round(float(tx_fee)/txlen))
    
    # do it again with this fee
    base_cmd = base_cmd_save + ['-F', tx_fee_rate]
    ret = run(base_cmd, list(args))
    if pattern:
        assert re.match(pattern, ret), 'Output does not match {}: {}\nfull output:\n{}\nerror:\n{}'.format(pattern, ret, saved_out[0], saved_err[0])

    return ret


def blockstack_name_preorder( name, privatekey, register_addr, wallet=None, burn_addr=None, consensus_hash=None, tx_fee=None, safety_checks=True, config_path=None ):

    global api_call_history 

    payment_addr = virtualchain.address_reencode(virtualchain.get_privkey_address(privatekey))
    register_addr = virtualchain.address_reencode(register_addr)
     
    resp = None
    if has_nodejs_cli() and wallet is None and virtualchain.is_singlesig(privatekey):
        txid = nodejs_cli('preorder', name, register_addr, privatekey, burn_addr=burn_addr, consensus_hash=consensus_hash, tx_fee=tx_fee, safety_checks=safety_checks, pattern='^[0-9a-f]{64}$')
        resp = {
            'status': True,
            'transaction_hash': txid
        }

    else:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path

        owner_privkey_info = None
        try:
            owner_privkey_info = find_wallet(register_addr).privkey
        except:
            if safety_checks:
                raise

        blockstackd_url = 'http://localhost:16264'
        name_cost_info = blockstackd_client.get_name_cost(name, hostport=blockstackd_url)
        assert 'amount' in name_cost_info, 'error getting cost of {}: {}'.format(name,name_cost_info)

        cost = name_cost_info['amount']
        units = name_cost_info['units']

        log.debug("Name {} cost {} units of {}".format(name, units, cost))

        resp = blockstack_client.do_preorder( name, privatekey, owner_privkey_info, units, cost, test_proxy, test_proxy, tx_fee=tx_fee,
                burn_address=burn_addr, owner_address=register_addr, consensus_hash=consensus_hash, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks )

    token_record = TokenNamePreorder(name, payment_addr)
    api_call_history.append( APICallRecord( "preorder", name, payment_addr, resp, token_record=token_record ) )
    return resp


def blockstack_name_register( name, privatekey, register_addr, zonefile_hash=None, wallet=None, safety_checks=True, config_path=None, tx_fee=None ):
    
    global api_call_history
    resp = None
    register_addr = virtualchain.address_reencode(register_addr)

    if has_nodejs_cli() and wallet is None and virtualchain.is_singlesig(privatekey):
        txid = None
        if zonefile_hash is not None:
            txid = nodejs_cli('register', name, register_addr, privatekey, 'ignored', zonefile_hash, safety_checks=safety_checks, tx_fee=tx_fee, pattern='^[0-9a-f]{64}$')
        else:
            txid = nodejs_cli('register', name, register_addr, privatekey, safety_checks=safety_checks, tx_fee=tx_fee, pattern='^[0-9a-f]{64}$')

        resp = {
            'status': True,
            'transaction_hash': txid
        }

    else:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path

        owner_privkey_info = None
        try:
            owner_privkey_info = find_wallet(register_addr).privkey
        except:
            if safety_checks:
                raise

        payment_addr = virtualchain.lib.ecdsalib.ecdsa_private_key(privatekey).public_key().address()

        kwargs = {}
        if not safety_checks:
            if tx_fee is None:
                tx_fee = 1

            kwargs = {'tx_fee' : tx_fee} # regtest shouldn't care about the tx_fee

        resp = blockstack_client.do_register( name, privatekey, owner_privkey_info, test_proxy, test_proxy, 
                zonefile_hash=zonefile_hash, owner_address=register_addr, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks, **kwargs )

    api_call_history.append( APICallRecord( "register", name, register_addr, resp ) )
    return resp


def blockstack_name_update( name, data_hash, privatekey, consensus_hash=None, test_api_proxy=True, safety_checks=True, config_path=None, tx_fee=None ):
    
    global api_call_history
    
    payment_key = get_default_payment_wallet().privkey
    resp = None

    if has_nodejs_cli() and virtualchain.is_singlesig(privatekey) and virtualchain.is_singlesig(payment_key):
        txid = nodejs_cli('update', name, 'ignored', privatekey, payment_key, data_hash, safety_checks=safety_checks, consensus_hash=consensus_hash, tx_fee=tx_fee, pattern='^[0-9a-f]{64}$')
        resp = {
            'status': True,
            'transaction_hash': txid
        }

    else:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path

        resp = blockstack_client.do_update( name, data_hash, privatekey, payment_key, test_proxy, test_proxy,
                consensus_hash=consensus_hash, tx_fee=tx_fee, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks )

    api_call_history.append( APICallRecord( "update", name, None, resp ) )
    return resp


def blockstack_name_transfer( name, address, keepdata, privatekey, consensus_hash=None, safety_checks=True, config_path=None, tx_fee=None ):
     
    global api_call_history

    payment_key = get_default_payment_wallet().privkey
    resp = None

    if has_nodejs_cli() and virtualchain.is_singlesig(privatekey) and virtualchain.is_singlesig(payment_key):
        txid = nodejs_cli('transfer', name, address, '{}'.format(keepdata).lower(), privatekey, payment_key, safety_checks=safety_checks, consensus_hash=consensus_hash, tx_fee=tx_fee, pattern='^[0-9a-f]{64}$')
        resp = {
            'status': True,
            'transaction_hash': txid
        }

    else:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path

        resp = blockstack_client.do_transfer( name, address, keepdata, privatekey, payment_key, test_proxy, test_proxy,
                tx_fee=tx_fee, consensus_hash=consensus_hash, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks )

    api_call_history.append( APICallRecord( "transfer", name, address, resp ) )
    return resp


def blockstack_name_renew( name, privatekey, recipient_addr=None, burn_addr=None, safety_checks=True, config_path=None, zonefile_hash=None, tx_fee=0, tx_fee_per_byte=None ):
    
    global api_call_history
    
    owner_addr = virtualchain.address_reencode(virtualchain.get_privkey_address(privatekey))
    payment_key = get_default_payment_wallet().privkey
    resp = None

    if has_nodejs_cli() and virtualchain.is_singlesig(privatekey) and virtualchain.is_singlesig(payment_key):
        txid = None
        if recipient_addr is not None:
            if zonefile_hash is not None:
                txid = nodejs_cli('renew', name, privatekey, payment_key, recipient_addr, 'ignored', zonefile_hash, safety_checks=safety_checks, burn_address=burn_addr, tx_fee=tx_fee, pattern='^[0-9a-f]{64}$')
            else:
                txid = nodejs_cli('renew', name, privatekey, payment_key, recipient_addr, safety_checks=safety_checks, burn_address=burn_addr, tx_fee=tx_fee, pattern='^[0-9a-f]{64}$')
        else:
            txid = nodejs_cli('renew', name, privatekey, payment_key, safety_checks=safety_checks, burn_address=burn_addr, tx_fee=tx_fee)

        resp = {
            'status': True,
            'transaction_hash': txid
        }

    else:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path

        blockstackd_url = 'http://localhost:16264'
        name_cost_info = blockstackd_client.get_name_cost(name, hostport=blockstackd_url)

        log.debug("Renew %s for %s units of %s" % (name, name_cost_info['amount'], name_cost_info['units']))
        resp = blockstack_client.do_renewal( name, privatekey, payment_key, name_cost_info['units'], name_cost_info['amount'], test_proxy, test_proxy, tx_fee=tx_fee, tx_fee_per_byte=tx_fee_per_byte,
                burn_address=burn_addr, zonefile_hash=zonefile_hash, recipient_addr=recipient_addr, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks )

    token_record = TokenNameRenewal(name, owner_addr)
    api_call_history.append( APICallRecord( "renew", name, virtualchain.address_reencode(recipient_addr) if recipient_addr is not None else None, resp, token_record=token_record) )
    return resp


def blockstack_name_revoke( name, privatekey, safety_checks=True, config_path=None, tx_fee=None ):
    
    global api_call_history

    payment_key = get_default_payment_wallet().privkey
    resp = None

    if has_nodejs_cli() and virtualchain.is_singlesig(privatekey) and virtualchain.is_singlesig(payment_key):
        txid = nodejs_cli('revoke', name, privatekey, payment_key, safety_checks=safety_checks, tx_fee=tx_fee, pattern='^[0-9a-f]{64}$')
        resp = {
            'status': True,
            'transaction_hash': txid
        }

    else:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path

        resp = blockstack_client.do_revoke( name, privatekey, payment_key, test_proxy, test_proxy, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks, tx_fee=tx_fee )

    api_call_history.append( APICallRecord( "revoke", name, None, resp ) )
    return resp


def blockstack_name_import( name, recipient_address, update_hash, privatekey, safety_checks=True, config_path=None ):
    
    global api_call_history
    
    resp = None
    if has_nodejs_cli() and virtualchain.is_singlesig(privatekey):
        txid = nodejs_cli('name_import', name, recipient_address, update_hash, privatekey)
        resp = {
            'status': True,
            'transaction_hash': txid
        }

    else:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path
    
        resp = blockstack_client.do_name_import( name, privatekey, recipient_address, update_hash, test_proxy, test_proxy, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks )

    api_call_history.append( APICallRecord( "name_import", name, virtualchain.address_reencode(recipient_address), resp ) )
    return resp


def blockstack_namespace_preorder( namespace_id, register_addr, privatekey, consensus_hash=None, safety_checks=True, config_path=None ):
    
    global api_call_history
    resp = None
    payment_addr = virtualchain.address_reencode(virtualchain.get_privkey_address(privatekey))

    if has_nodejs_cli() and virtualchain.is_singlesig(privatekey):
        txid = nodejs_cli('namespace_preorder', namespace_id, register_addr, privatekey, consensus_hash=consensus_hash, safety_checks=safety_checks, pattern='^[0-9a-f]{64}$')
        resp = {
            'status': True,
            'transaction_hash': txid
        }
        
    else:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path
        register_addr = virtualchain.address_reencode(register_addr)

        blockstackd_url = 'http://localhost:16264'
        namespace_cost = blockstackd_client.get_namespace_cost(namespace_id, hostport=blockstackd_url)
        if 'error' in namespace_cost:
            log.error("Failed to get namespace cost for '%s': %s" % (namespace_id, namespace_cost['error']))
            return {'error': 'Failed to get namespace costs'}
        
        resp = blockstack_client.do_namespace_preorder( namespace_id, namespace_cost['units'], namespace_cost['amount'], privatekey, register_addr, test_proxy, test_proxy,
                consensus_hash=consensus_hash, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks )

    token_record = TokenNamespacePreorder(namespace_id, payment_addr)
    api_call_history.append( APICallRecord( "namespace_preorder", namespace_id, virtualchain.address_reencode(virtualchain.get_privkey_address(privatekey)), resp, token_record=token_record) )
    return resp


def blockstack_namespace_reveal( namespace_id, register_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, privatekey, version_bits=1, safety_checks=True, config_path=None ):
    
    global api_call_history
    resp = None
    register_addr = virtualchain.address_reencode(register_addr)

    if has_nodejs_cli() and virtualchain.is_singlesig(privatekey):
        txid = nodejs_cli('namespace_reveal', namespace_id, register_addr, '{}'.format(version_bits), '{}'.format(lifetime), '{}'.format(coeff), '{}'.format(base), 
                ','.join(['{}'.format(bucket) for bucket in bucket_exponents]), '{}'.format(nonalpha_discount), '{}'.format(no_vowel_discount), privatekey, safety_checks=safety_checks, pattern='^[0-9a-f]{64}$')
        resp = {
            'status': True,
            'transaction_hash': txid
        }

    else:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path

        resp = blockstack_client.do_namespace_reveal( namespace_id, version_bits, register_addr, lifetime, coeff, base, bucket_exponents,
                nonalpha_discount, no_vowel_discount, privatekey, test_proxy, test_proxy, config_path=config_path, proxy=test_proxy)

    api_call_history.append( APICallRecord( "namespace_reveal", namespace_id, virtualchain.address_reencode(register_addr), resp ) )
    return resp


def blockstack_namespace_ready( namespace_id, privatekey, safety_checks=True, config_path=None ):
    
    global api_call_history
    resp = None

    if has_nodejs_cli() and virtualchain.is_singlesig(privatekey):
        txid = nodejs_cli('namespace_ready', namespace_id, privatekey, safety_checks=safety_checks, pattern='^[0-9a-f]{64}$')
        resp = {
            'status': True,
            'transaction_hash': txid
        }

    else:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path
        
        resp = blockstack_client.do_namespace_ready( namespace_id, privatekey, test_proxy, test_proxy, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks ) 

    api_call_history.append( APICallRecord( "namespace_ready", namespace_id, virtualchain.address_reencode(virtualchain.get_privkey_address(privatekey)), resp ) )
    return resp


def blockstack_announce( message, privatekey, safety_checks=True, config_path=None ):
    
    global api_call_history

    resp = None

    if has_nodejs_cli() and virtualchain.is_singlesig(privatekey):
        message_hash = blockstack.lib.storage.get_zonefile_data_hash(message)
        txid = nodejs_cli('announce',  message_hash, privatekey)
        resp = {
            'status': True,
            'transaction_hash': txid
        }

    else:
        test_proxy = make_proxy(config_path=config_path)
        blockstack_client.set_default_proxy( test_proxy )
        config_path = test_proxy.config_path if config_path is None else config_path

        resp = blockstack_client.do_announce( message, privatekey, test_proxy, test_proxy, config_path=config_path, proxy=test_proxy, safety_checks=safety_checks )

    api_call_history.append( APICallRecord( "announce", message, None, resp ) )
    return resp


def expect_api_call_failure():
    """
    Expect the last API call to fail
    """
    global api_call_history
    if len(api_call_history) == 0:
        return

    api_call_history[-1].success = False


def serialize_privkey_info(payment_privkey):
    """
    serialize a wallet private key into a CLI-parseable string
    """
    payment_privkey_str = None
    if isinstance(payment_privkey, (str,unicode)):
        payment_privkey_str = payment_privkey
    else:
        if payment_privkey['segwit']:
            m = payment_privkey['m']
            n = len(payment_privkey['private_keys'])

            if n > 1:
                payment_privkey_str = 'segwit:{},{},{}'.format(m, n, ','.join(payment_privkey['private_keys']))
            else:
                payment_privkey_str = 'segwit:{}'.format(payment_privkey['private_keys'][0])
        else:
            m, pubks = virtualchain.parse_multisig_redeemscript(payment_privkey['redeem_script'])
            n = len(payment_privkey['private_keys'])
            payment_privkey_str = '{},{},{}'.format(m, n, ','.join(payment_privkey['private_keys']))

    return payment_privkey_str


def blockstack_cli_namespace_preorder( namespace_id, payment_privkey, reveal_privkey, config_path=None ):
    """
    Preorder a namespace
    """
    return blockstack_namespace_preorder(namespace_id, virtualchain.get_privkey_address(reveal_privkey), payment_privkey)


def blockstack_cli_namespace_reveal( namespace_id, payment_privkey, reveal_privkey, lifetime, coeff, base, buckets, nonalpha_disc, no_vowel_disc, preorder_txid=None, config_path=None, version_bits=None ):
    """
    reveal a namespace
    """
    return blockstack_namespace_reveal(namespace_id, virtualchain.get_privkey_address(reveal_privkey), lifetime, coeff, base, buckets, nonalpha_disc, no_vowel_disc, payment_privkey, version_bits=version_bits)


def blockstack_cli_namespace_ready( namespace_id, reveal_privkey, config_path=None ):
    """
    launch a namespace
    """
    return blockstack_namespace_ready(namespace_id, reveal_privkey)
  

def blockstack_cli_whois( name, config_path=None):
    """
    Get the WHOIS information for a name
    """
    if not has_nodejs_cli():
        raise Exception("Missing blocktack-cli")

    resp = nodejs_cli('whois', name)
    return json.loads(resp)


def blockstack_cli_lookup( name, config_path=None):
    """
    Look up a name's zonefile/profile
    """
    if not has_nodejs_cli():
        raise Exception("Missing blockstack-cli")

    resp = nodejs_cli('lookup', name)
    return json.loads(resp)


def blockstack_cli_sign_profile(path, private_key, config_path=None):
    """
    sign profile
    """
    if not has_nodejs_cli():
        raise Exception("Missing blockstack-cli")

    resp = nodejs_cli('profile_sign', path, private_key)
    return json.loads(resp)


def blockstack_cli_verify_profile(path, pubkey_or_addr, config_path=None):
    """
    Verify profile
    """
    if not has_nodejs_cli():
        raise Exception("Missing blockstack-cli")

    resp = nodejs_cli('profile_verify', path, pubkey_or_addr)
    return json.loads(s)


def blockstack_cli_get_name_blockchain_record( name, config_path=None):
    """
    get name blockchain record
    """
    if not has_nodejs_cli():
        raise Exception("Missing blockstack-cli")

    resp = nodejs_cli('get_name_blockchain_record', name)
    return json.loads(resp)


def blockstack_cli_get_name_blockchain_history( name, start_block=None, end_block=None, config_path=None):
    """
    get name blockchain history
    """
    if not has_nodejs_cli():
        raise Exception("Missing blockstack-cli")

    resp = None
    if start_block is not None and end_block is not None:
        resp = nodejs_cli('get_name_blockchain_history', name, start_block, end_block)
    elif start_block is not None:
        resp = nodejs_cli('get_name_blockchain_history', name, start_block)
    else:
        resp = nodejs_cli('get_name_blockchain_history', name)

    return json.loads(resp)


def blockstack_cli_get_namespace_blockchain_record( namespace_id, config_path=None):
    """
    get namespace blockchain record
    """
    if not has_nodejs_cli():
        raise Exception("Missing blockstack-cli")

    resp = nodejs_cli('get_namespace_blockchain_record', namespace_id)
    return json.loads(resp)



def blockstack_cli_get_name_zonefile( name, config_path=None, json=False, raw=True):
    """
    get name zonefile
    """
    if not has_nodejs_cli():
        raise Exception("Missing blockstack-cli")

    resp = nodejs_cli('get_name_zonefile', name, full_output=True)
    if json or not raw:
        return json.loads(resp.strip().split('\n')[-1])
    
    return resp


def blockstack_cli_get_names_owned_by_address( address, config_path=None):
    """
    get names owned by address
    """
    if not has_nodejs_cli():
        raise Exception("Missing blockstack-cli")

    resp = nodejs_cli('names', address)
    return json.loads(resp)


def url_to_uri_record(url, datum_name=None):
    """
    Convert a URL into a DNS URI record
    """
    try:
        scheme, _ = url.split('://')
    except ValueError:
        msg = 'BUG: invalid storage driver implementation: no scheme given in "{}"'
        raise Exception(msg.format(url))

    scheme = scheme.lower()
    proto = None

    # tcp or udp?
    try:
        port = socket.getservbyname(scheme, 'tcp')
        proto = 'tcp'
    except socket.error:
        try:
            port = socket.getservbyname(scheme, 'udp')
            proto = 'udp'
        except socket.error:
            # this is weird--maybe it's embedded in the scheme?
            try:
                assert len(scheme.split('+')) == 2
                scheme, proto = scheme.split('+')
            except (AssertionError, ValueError):
                msg = 'WARN: Scheme "{}" has no known transport protocol'
                log.debug(msg.format(scheme))

    name = None
    if proto is not None:
        name = '_{}._{}'.format(scheme, proto)
    else:
        name = '_{}'.format(scheme)

    if datum_name is not None:
        name = '{}.{}'.format(name, str(datum_name))

    ret = {
        'name': name,
        'priority': 10,
        'weight': 1,
        'target': url,
    }

    return ret


def make_empty_zonefile(username, address, urls=None):
    """
    Create an empty zone file
    """

    # make a URI record for every mutable storage provider
    if urls is None:
        urls = ['http://localhost:4000/hub/{}/profile.json'.format(virtualchain.address_reencode(addr, network='mainnet'))]

    user = {
        'txt': [],
        'uri': [],
        '$origin': username,
        '$ttl': 3600,
    }

    for url in urls:
        urirec = url_to_uri_record(url)
        user['uri'].append(urirec)

    return blockstack_zones.make_zone_file(user)


def blockstack_register_user(name, privkey, addr, **kw):
    """
    Register a user in the test framework
    Give the user an empty profile and zone file.

    Generates 2 blocks
    """
    DEFAULT_PROFILE = {'type': '@Person', 'account': []}

    profile = kw.get('profile', DEFAULT_PROFILE)

    blockstack_name_preorder(name, privkey, addr)
    next_block(**kw)

    zonefile_txt = make_emtpy_zonefile(name, addr)
    zonefile_hash = blockstack.lib.storage.get_zonefile_data_hash(zonefile_txt)

    blockstack_name_register(name, privkey, addr, zonefile_hash=zonefile_hash)
    next_block(**kw)

    blockstack_put_zonefile(zonefile_txt)
    profile_data = blockstack_make_profile(profile, privkey)
    blockstack_put_profile(name, profile_data, privkey)
    return True


def blockstack_import_user(name, privkey, addr, **kw):
    """
    Import a user in the test framework
    Give the user an empty profile and zone file.

    Generates 1 block
    """
    DEFAULT_PROFILE = {'type': '@Person', 'account': []}
    
    profile = kw.get('profile', DEFAULT_PROFILE)
    profile_url = 'http://localhost:4000/hub/{}/profile.json'.format(virtualchain.address_reencode(addr, network='mainnet'))
    zonefile_txt = "$ORIGIN {}\n$TTL 3600\n_http URI 10 1 {}".format(name, profile_url)

    zonefile_hash = blockstack.lib.storage.get_zonefile_data_hash(zonefile_txt)

    blockstack_name_import(name, addr, zonefile_hash, privkey)
    next_block(**kw)

    blockstack_put_zonefile(zonefile_txt)
    profile_data = blockstack_make_profile(profile, privkey)
    blockstack_put_profile(name, profile_data, privkey)
    return True


def blockstack_renew_user(name, privkey, new_addr, **kw):
    """
    Renew a user in the test framework
    Give the user an empty profile and zone file.

    Generates 1 block
    """
    DEFAULT_PROFILE = {'type': '@Person', 'account': []}
    
    profile = kw.get('profile', DEFAULT_PROFILE)
    profile_url = 'http://localhost:4000/hub/{}/profile.json'.format(virtualchain.address_reencode(new_addr, network='mainnet'))
    zonefile_txt = "$ORIGIN {}\n$TTL 3600\n_http URI 10 1 {}".format(name, profile_url)

    zonefile_hash = blockstack.lib.storage.get_zonefile_data_hash(zonefile_txt)

    blockstack_name_renew(name, privkey, recipient_addr=addr, zonefile_hash=zonefile_hash)
    next_block(**kw)

    blockstack_put_zonefile(zonefile_txt)
    profile_data = blockstack_make_profile({'type': '@Person', 'account': []}, privkey)
    blockstack_put_profile(name, profile_data, privkey)
    return True


def blockstack_get_zonefile( zonefile_hash, parse=True, config_path=None ):
    """
    Get a zonefile from the RPC endpoint
    Return None if not given
    MEANT FOR DIAGNOSTIC PURPOSES ONLY
    """
    blockstackd_url = 'http://localhost:16264'
    zonefile_result = blockstackd_client.get_zonefiles(blockstackd_url, [zonefile_hash])
    if 'error' in zonefile_result:
        return None

    if zonefile_hash not in zonefile_result['zonefiles'].keys():
        return None

    zonefile_txt = base64.b64decode( zonefile_result['zonefiles'][zonefile_hash] )

    # verify
    if zonefile_hash != blockstack.lib.storage.get_zonefile_data_hash(zonefile_txt):
        return None

    if parse:
        zonefile = blockstack_zones.parse_zone_file(zonefile_txt)
        return zonefile

    else:
        return zonefile_txt


def blockstack_put_zonefile(zonefile_txt, config_path=None):
    """
    Store zonefile data to the RPC endpoint.
    MEANT FOR DIAGNOSTIC PURPOSS ONLY

    Return True on success
    Return False on error
    """
    global atlas_zonefiles_present
    if has_nodejs_cli():
        res = nodejs_cli('zonefile_push', zonefile_txt)
        print res
        res = json.loads(res)

        if res['status']:
            atlas_zonefiles_present.append(blockstack.lib.storage.get_zonefile_data_hash(zonefile_txt))

        return res['status']

    else:
        raise Exception("Need blockstack-cli")


def blockstack_make_profile( profile_data, privkey ):
    """
    Make a signed profile
    """
    privkey = virtualchain.ecdsalib.ecdsa_private_key(privkey).to_hex()
    if has_nodejs_cli():
        fd, path = tempfile.mkstemp('-blockstack-profile')
        os.write(fd, json.dumps(profile_data))
        os.close(fd)

        profile_token = nodejs_cli('profile_sign', path, privkey)
        os.unlink(path)

        return profile_token

    else:
        raise Exception("Need blockstack-cli")


def blockstack_put_profile(name, profile_token, privkey):
    """
    Store a signed profile token
    """
    if has_nodejs_cli():
        fd, path = tempfile.mkstemp('-blockstack-profile-store')
        os.write(fd, profile_token)
        os.close(fd)

        res = nodejs_cli('profile_store', name, path, privkey)
        os.unlink(path)

        return json.loads(res)['profileUrls']
    
    else:
        raise Exception("blockstack-cli is required")


def blockstack_get_profile( name, config_path=None ):
    """
    Get a profile.
    Used to be that the blockstackd node had a get_profile endpoint.
    It no longer does.  This method is just around for compatibility.

    MEANT FOR DIAGNOSTIC PURPOSES ONLY
    """
    if has_nodejs_cli():
        res = nodejs_cli('lookup', name)
        return json.loads(res)

    else:
        raise Exception("blockstack_cli is required")


def blockstack_REST_call( method, route, api_pass=None, data=None, raw_data=None, config_path=None, **query_fields ):
    """
    Low-level call to an API route
    Returns {'http_status': http status, 'response': json}
    """
    api_port = 16268

    qs = '&'.join('{}={}'.format(urllib.quote(k), urllib.quote(v)) for (k, v) in query_fields.items())
    if len(qs) > 0:
        qs = '?{}'.format(qs)

    resp = None
    url = "http://localhost:{}{}{}".format(api_port, route, qs)

    log.debug("REST call: {} {}".format(method, url))

    headers = {}
    if api_pass:
        headers['authorization'] = 'bearer {}'.format(api_pass)
        headers['origin'] = 'http://localhost:3000'

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
    res = blockstack_REST_call('POST', '/v1/test/envar?{}={}'.format(urllib.quote(key), urllib.quote(value)))
    if res['http_status'] != 200:
        res['error'] = 'Failed to issue test RPC call'
        return res

    return res


def blockstack_verify_database( consensus_hash, consensus_block_id, untrusted_db_dir, new_db_dir, working_db_path=None, start_block=None, genesis_block={} ):
    return blockstackd.verify_database( consensus_hash, consensus_block_id, untrusted_db_dir, new_db_dir, start_block=start_block, genesis_block=genesis_block)


def blockstack_export_db( snapshots_dir, block_height, **kw ):
    global state_engine

    export_dir = os.path.join(snapshots_dir, 'snapshot.{}'.format(block_height))
    os.makedirs(export_dir)

    try:
        state_engine.export_db(export_dir)
    except IOError, ie:
        if ie.errno == errno.ENOENT:
            log.error("no such file or directory: %s" % path)
            pass
        else:
            raise

    # save atlasdb too 
    # TODO: this is hacky; find a generic way to find the atlas db path
    atlas_path = os.path.join(os.path.dirname(state_engine.get_db_path()), "atlas.db")
    if os.path.exists(atlas_path):
        virtualchain.sqlite3_backup(atlas_path, os.path.join(export_dir, 'atlas.db'))

    # save subdomaindb too
    # TODO: this is hacky; find a generic way to find the atlas db path
    subdomain_path = os.path.join(os.path.dirname(state_engine.get_db_path()), 'subdomains.db')
    if os.path.exists(subdomain_path):
        virtualchain.sqlite3_backup(subdomain_path, os.path.join(export_dir, 'subdomains.db'))

'''
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
        'encrypted_owner_privkey': encrypt_private_key_info(owner_privkey, password)['encrypted_private_key_info']['private_key_info'],
        'payment_addresses': decrypted_legacy_wallet['payment_addresses'],
        'encrypted_payment_privkey': encrypt_private_key_info(payment_privkey, password)['encrypted_private_key_info']['private_key_info'],
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
        'data_pubkey': keylib.ECPrivateKey(data_privkey).public_key().to_hex(),
        'data_pubkeys': [keylib.ECPrivateKey(data_privkey).public_key().to_hex()],
        'data_privkey': encrypt_private_key_info(data_privkey, password)['encrypted_private_key_info']['private_key_info'],
        'owner_addresses': decrypted_legacy_wallet['owner_addresses'],
        'encrypted_owner_privkey': encrypt_private_key_info(owner_privkey, password)['encrypted_private_key_info']['private_key_info'],
        'payment_addresses': decrypted_legacy_wallet['payment_addresses'],
        'encrypted_payment_privkey': encrypt_private_key_info(payment_privkey, password)['encrypted_private_key_info']['private_key_info'],
        'version': '0.14.0'
    }
    return encrypted_legacy_wallet
'''

def format_unspents(unspents):
    return [{
        "transaction_hash": s["txid"],
        "outpoint": {
            'hash': s['txid'],
            'index': s["vout"],
        },
        "value": int(Decimal(s["amount"]*SATOSHIS_PER_COIN)),
        "out_script": s["scriptPubKey"],
        "confirmations": s["confirmations"]
        }
        for s in unspents
    ]


def get_unspents(address, bitcoind):
    """
    Get the spendable transaction outputs, also known as UTXOs or
    unspent transaction outputs.

    NOTE: this will only return unspents if the address provided is present
    in the bitcoind server.
    """
    addresses = [address]
    
    min_confirmations = 0
    max_confirmation = 2000000000  # just a very large number for max
    unspents = bitcoind.listunspent(min_confirmations, max_confirmation, addresses)

    if len(unspents) == 0:
        try:
            bitcoind.importaddress(str(address))
            unspents = bitcoind.listunspent(min_confirmations, max_confirmation, addresses)
        except Exception as e:
            return format_unspents([])

    return format_unspents(unspents)


def get_balance( addr ):
    """
    Get the address balance
    """
    inputs = get_utxos(addr)
    log.debug("UTXOS of {} are {}".format(addr, inputs))
    return sum([inp['value'] for inp in inputs])


def get_utxos( addr ):
    """
    Get the address balance
    """
    global bitcoind
    return get_unspents(addr, bitcoind)


def serialize_tx(inputs, outputs):
    """
    Given the inputs and outputs to a transaction, serialize them
    to the appropriate blockchain format.

    Return the hex-string containing the transaction
    """

    # TODO: expand beyond bitcoin
    txobj = {
        'ins': inputs,
        'outs': outputs,
        'locktime': 0,
        'version': 1
    }

    # log.debug("serialize tx: {}".format(json.dumps(txobj, indent=4, sort_keys=True)))
    txstr = virtualchain.btc_tx_serialize(txobj)
    return txstr


def send_funds_tx( privkey, satoshis, payment_addr ):
    """
    Make a signed transaction that will send the given number
    of satoshis to the given payment address
    """
    payment_addr = str(payment_addr)
    log.debug("Send {} to {}".format(satoshis, payment_addr))

    bitcoind = connect_bitcoind()

    try:
        bitcoind.importaddress(payment_addr, "", True)
    except virtualchain.JSONRPCException, je:
        if je.code == -4:
            # key already loaded
            pass
        else:
            raise

    send_addr = virtualchain.get_privkey_address(privkey)
    
    inputs = get_utxos(send_addr)
    outputs = [
        {"script": virtualchain.make_payment_script(payment_addr),
         "value": satoshis},
        
        {"script": virtualchain.make_payment_script(send_addr),
         "value": virtualchain.calculate_change_amount(inputs, satoshis, 5500)},
    ]
    prev_outputs = [{'out_script': inp['out_script'], 'value': inp['value']} for inp in inputs]

    serialized_tx = serialize_tx(inputs, outputs)
    signed_tx = virtualchain.tx_sign_all_unsigned_inputs(privkey, prev_outputs, serialized_tx)
    return signed_tx


def send_funds( privkey, satoshis, payment_addr ):
    """
    Send funds from a private key (in satoshis) to an address
    """
    signed_tx = send_funds_tx(privkey, satoshis, payment_addr)
    txid = sendrawtransaction(signed_tx)
    return {'txid': txid}


def broadcast_transaction(txhex):
    return sendrawtransaction(txhex)


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


def check_account_debits(state_engine, api_call_history):
    """
    Verify that each account has been debited the appropriate amount.
    """
    # don't do this if we're running in interactive mode, and the test is over
    if not is_test_running():
        return True
    
    addrs = list(set([api_call.token_record.account_addr for api_call in filter(lambda ac: ac.token_record is not None, api_call_history)]))
    token_types = filter(lambda tt: tt != 'BTC',
                         list(set([api_call.token_record.token_type for api_call in filter(lambda ac: ac.token_record is not None, api_call_history)])))

    expected_expenditures = dict([
        (addr, dict([
            (token_type, sum([api_call.token_record.token_cost for api_call in
                filter(lambda ac: ac.token_record is not None and ac.success and ac.token_record.account_addr == addr and ac.token_record.token_type == token_type, api_call_history)]))
            for token_type in token_types]))
        for addr in addrs])

    accounts = dict([
        (addr, dict([
            (token_type, 0 if state_engine.get_account(addr, token_type) is None else state_engine.get_account(addr, token_type)['debit_value'])
            for token_type in token_types]))
        for addr in addrs])

    log.debug("account debits = \n{}".format(json.dumps(accounts, indent=4, sort_keys=True)))
    log.debug("expected expenditures =\n{}".format(json.dumps(expected_expenditures, indent=4, sort_keys=True)))

    for addr in addrs:
        for token_type in token_types:
            if accounts[addr][token_type] != expected_expenditures[addr][token_type]:
                log.error("mismatch: {}'s {}: {} != {}".format(addr, token_type, accounts[addr][token_type], expected_expenditures[addr][token_type]))
                return False

    return True


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

    # flush all transactions, and re-set state engine
    kw['next_block_upcall']()
    kw['sync_virtualchain_upcall']()
    
    # snapshot the database
    blockstack_export_db( snapshots_dir, get_current_block(**kw), **kw )
    log_consensus( **kw )

    # check all account balances against the database
    assert check_account_debits(state_engine, api_call_history), "Account debit mismatch"

   
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

    for block_id in block_ids:
    
        state_engine.lastblock = block_ids[0]
        expected_consensus_hash = all_consensus_hashes[ block_id ]
       
        # this is the directory that contains the snapshot state
        untrusted_working_db_dir = os.path.join(snapshots_dir, 'snapshot.{}'.format(block_id))

        # copy over atlasdb
        atlasdb_path = os.path.join(untrusted_working_db_dir, 'atlas.db')

        # set up state to verify
        working_db_dir = os.path.join(snapshots_dir, "work.%s" % block_id)
        working_atlasdb_path = os.path.join(working_db_dir, "atlas.db")

        os.makedirs(working_db_dir)
        shutil.copy(atlasdb_path, working_atlasdb_path)

        print "\n\nverify %s - %s (%s), expect %s\n\n" % (block_ids[0], block_id+1, untrusted_working_db_dir, expected_consensus_hash)

        valid = blockstack_verify_database(expected_consensus_hash, block_id, untrusted_working_db_dir, working_db_dir, start_block=block_ids[0], genesis_block=state_engine.genesis_block)
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

        elif api_call.method == 'namespace_preorder':
            name = api_call.name
            opcode = "NAMESPACE_PREORDER"

        elif api_call.method == 'namespace_reveal':
            name = api_call.name
            opcode = 'NAMESPACE_REVEAL'

        elif api_call.method == 'namespace_ready':
            name = api_call.name
            opcode = 'NAMESPACE_READY'

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
            
            print ''
            print "SNV verify %s (from %s)" % (name, block_id)
            print "opcodes: %s" % opcode_sequence
            print "txids: %s" % txid_sequence
            print "errors: %s" % error_sequence
            print ""

            for j in xrange(0, len(txid_sequence)):
                
                opcode = opcode_sequence[j]
                txid = txid_sequence[j]
                err = error_sequence[j]

                if err is not None and txid is not None:
                    raise Exception("Test misconfigured: error '%s' at block %s" % (err, block_id))

                log.debug("Verify %s %s" % (opcode, txid))
                for i in xrange( block_id + 1, max(all_consensus_hashes.keys()) + 1 ):

                    trusted_block_id = i

                    try:
                        trusted_consensus_hash = all_consensus_hashes[i]
                    except KeyError:
                        print json.dumps(all_consensus_hashes, indent=4, sort_keys=True)
                        os.abort()

                    snv_recs = snv_client.snv_lookup( name, block_id, trusted_consensus_hash, trusted_txid=txid )
                    if 'error' in snv_recs:
                        if name in snv_fail:
                            log.debug("SNV lookup %s failed as expected" % name)
                            continue 

                        if name in snv_fail_at.get(block_id, []):
                            log.debug("SNV lookup %s failed at %s as expected" % (name, block_id))
                            continue 

                        print 'SNV lookup on {} at {} with {} failed'.format(name, block_id, trusted_consensus_hash)
                        print 'Expected SNV failures at {}: {}'.format(block_id, snv_fail_at.get(block_id, []))
                        print 'All SNV failures expected:\n{}'.format(json.dumps(snv_fail_at, indent=4, sort_keys=True))
                        print 'SNV lookup return value:'
                        print json.dumps(snv_recs, indent=4, sort_keys=True )
                        return False 

                    if len(snv_recs) > 1:
                        print "snv_lookup(%s, %s, %s, %s)" % (name, block_id, trusted_consensus_hash, txid)
                        print json.dumps(snv_recs, indent=4, sort_keys=True)
                        return False

                    assert len(snv_recs) <= 1, "Multiple SNV records returned"
                    snv_rec = snv_recs[0]

                    if snv_rec.has_key('name') and snv_rec['name'] != name:
                        print "mismatch name: expected {}, got {}".format(name, snv_rec['name'])
                        print json.dumps(snv_rec, indent=4, sort_keys=True )
                        return False 

                    # namespace operation?
                    elif not snv_rec.has_key('name') and snv_rec.has_key('namespace_id') and snv_rec['namespace_id'] != name:
                        print "mismatch namespace: expected {}, got {}".format(name, snv_rec['name'])
                        print json.dumps(snv_rec, indent=4, sort_keys=True)
                        return False
                    
                    if snv_rec['txid'] != txid:
                        if name in snv_fail_at.get(block_id, []):
                            log.debug("SNV lookup {} failed as expected".format(name))
                            continue

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
 
                    # only NAMESPACE_REVEAL doesn't have an 'op_fee' member.  It must be an int or long.
                    elif snv_rec['opcode'] != 'NAMESPACE_REVEAL' and 'op_fee' not in snv_rec:
                        print "QUIRK: %s: fee is missing".format(snv_rec['opcode'])
                        return False
                    '''
                    elif snv_rec['opcode'] != 'NAMESPACE_REVEAL' and type(snv_rec['op_fee']) not in [int,long]:
                        print "QUIRK: %s: fee isn't an int (but a %s: %s)" % (snv_rec['opcode'], type(snv_rec['op_fee']), snv_rec['op_fee'])
                    '''
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

        if name in snv_fail:
            continue

        if name in snv_fail_at.get(block_id, []):
            continue

        if "value_hash" not in api_call.result:
            log.warn("Api call {} on name {} in block {} has no value_hash, skipping atlas check.".format(api_call.method, name, block_id))
            continue

        value_hash = api_call.result['value_hash']

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
    

def check_historic_names_by_address( state_engine ):
    """
    Verify that we can look up all names owned by a given address.
    Do so by creating DIDs for all of the names we've registered or imported,
    and verifying that we can resolve them to the names' current form
    """

    global api_call_history
    global snv_fail_at
    global snv_fail

    ret = True

    addrs_checked = []  # for logging
    addr_names = {}     # map address to list of names
    revoked_names = {}  # map name to block height
    final_name_states = {}

    for api_call in api_call_history:
        if api_call.method not in ['register', 'name_import', 'revoke']:
            continue

        name = api_call.name
        address = api_call.address
        block_id = api_call.block_id

        if name in snv_fail_at.get(block_id, []):
            continue

        if name in snv_fail:
            continue

        if api_call.method in ['register', 'name_import']:
            assert address is not None
            
            add = True
            if api_call.method == 'name_import':
                # don't allow dups of names added via name_import; the db won't allow it anyway
                for addr in addr_names.keys():
                    for (n, _, calltype) in addr_names[addr]:
                        if n == name and calltype == 'name_import':
                            # another import on this name
                            add = False

            if add:
                if not address in addr_names:
                    addr_names[address] = []
            
                addr_names[address].append((name, block_id, api_call.method))

                # no longer revoked if we reregistered
                if name in revoked_names:
                    del revoked_names[name]

        if api_call.method == 'revoke':
            revoked_names[name] = block_id

        if name not in final_name_states:
            final_name_states[name] = state_engine.get_name(name, include_expired=True)

            # coerse string values
            final_name_states[name] = dict(map(lambda (k, v): (k, str(v)) if isinstance(v, unicode) else (k, v), final_name_states[name].items()))

    log.debug('addr names: {}'.format(addr_names))
    log.debug('revoked names: {}'.format(revoked_names))
    
    for address in addr_names.keys():
        for i, (name, block_id, _) in enumerate(addr_names[address]):
            # make sure this DID corresponds to this name
            did = blockstack.lib.client.get_name_DID(name, hostport='http://localhost:{}'.format(blockstack.lib.config.RPC_SERVER_PORT))
            expected_did = 'did:stack:v0:{}-{}'.format(address, i)
            if did != expected_did:
                # this would happen if the expected DID pointed to an old version of the name, or if a set of names were registered in the same block
                # but in a different order than we recorded.
                # DID must still resolve, unless the name was revoked
                old_name_rec = blockstack.lib.client.get_DID_record(expected_did, hostport='http://localhost:{}'.format(blockstack.lib.config.RPC_SERVER_PORT))
                if 'error' in old_name_rec and 'revoked' not in old_name_rec['error']:
                    log.error("Failed to resolve {}".format(expected_did))
                    print old_name_rec
                    return False

                if 'error' not in old_name_rec:
                    try:
                        if old_name_rec['name'] == name:
                            # make sure this is strictly an older DID, if it's for the same name
                            name_with_history = blockstack.lib.client.get_name_record(name, include_history=True, include_expired=True, include_grace=True, hostport='http://localhost:{}'.format(blockstack.lib.config.RPC_SERVER_PORT))
                            assert 'error' not in name_with_history, 'error looking up name {}: '.format(name,name_with_history['error'])

                            found = False
                            found_height = None
                            found_vtxindex = None
                            found_preorder = False
                            for height in sorted(name_with_history['history'].keys()):
                                if found:
                                    break

                                for state in name_with_history['history'][height]:
                                    if reduce(lambda present_1, present_2: present_1 and present_2, \
                                              map(lambda key: state.has_key(key) and old_name_rec[key] == state[key], old_name_rec.keys()), \
                                              True):

                                        # found out where this DID pointed
                                        found_height = height
                                        found_vtxindex = state['vtxindex']
                                        found = True
                                        break

                            assert found, 'Name state {} is not in history\n{}'.format(old_name_rec,name_with_history)
                            
                            # this name must have been preordered at a later point in time 
                            for height in sorted(name_with_history['history'].keys()):
                                if height < found_height:
                                    continue

                                if found_preorder:
                                    break

                                for state in name_with_history['history'][height]:
                                    if height == found_height and state['vtxindex'] < found_vtxindex:
                                        continue

                                    if state['op'] == blockstack.NAME_PREORDER:
                                        found_preorder = True
                                        break

                            assert found_preorder, 'historic DID {} points to {}-{}-{}, which is not the last DID for this name'.format(expected_did, name, found_height, found_vtxindex)

                        else:
                            # DID we expected refers to a different name.  It had better be in the same block
                            assert old_name_rec['last_renewed'] == block_id, 'Name record for {} (DID {}) comes from a different block than {}:\n{}'.format(old_name_rec['name'], expected_did, block_id, old_name_rec)

                    except Exception as e:
                        traceback.print_exc()
                        return False

            name_rec = blockstack.lib.client.get_DID_record(did, hostport='http://localhost:{}'.format(blockstack.lib.config.RPC_SERVER_PORT))

            if name in revoked_names.keys() and revoked_names[name] >= block_id:
                # name was revoked. expect failure
                if 'error' not in name_rec:
                    log.error("Accidentally resolved {} on revoked name {}".format(did,name))
                    print name_rec
                    return False 

            else:
                if name_rec is None:
                    log.error("No such name {} at {}".format(name, did))
                    return False

                elif 'error' in name_rec:
                    log.error("Failed to resolve {}: {}".format(did, name_rec['error']))
                    return False

                else:
                    # coerse string values
                    name_rec = dict(map(lambda (k,v): (k, str(v)) if isinstance(v, unicode) else (k,v), name_rec.items()))
                    for k in name_rec.keys():
                        if final_name_states[name] is not None and k in final_name_states:
                            if name_rec[k] != final_name_states[name].get(k, None) or type(name_rec[k]) != type(final_name_states[name].get(k, None)):
                                log.error("Name rec for {} does not equal final name state from db on '{}'".format(name, k))
                                log.error("Expected:\n{}".format(final_name_states[name].get(k, None)))
                                log.error("Got:\n{}".format(name_rec[k]))
                                log.error('final_name_states["{}"]:\n{}'.format(name, json.dumps(final_name_states[name], sort_keys=True, indent=4)))
                                log.error('name_rec at {}:\n{}'.format(did, json.dumps(name_rec, sort_keys=True, indent=4)))
                                return False

    return ret
 

def check_subdomain_db(firstblock=None, **kw):
    """
    Do sanity checks on the subdomain database.
    * verify that we can replay the zone files in order and arrive at the same subdomain database
    * verify that we can resolve each subdomain to its DID
    * verify that we can resolve each DID to its subdomain
    """
    # reindex
    blockstack_opts = blockstack.lib.config.get_blockstack_opts()
    new_opts = {}
    new_opts.update(blockstack_opts)

    new_opts['subdomaindb_path'] = blockstack_opts['subdomaindb_path'] + '.reindex'
    if os.path.exists(new_opts['subdomaindb_path']):
        os.unlink(new_opts['subdomaindb_path'])

    blockstack.lib.subdomains.SubdomainIndex.reindex(get_current_block(**kw), firstblock=firstblock, opts=new_opts)

    # compare both databases
    cmd = 'sqlite3 "{}" "select * from subdomain_records order by parent_zonefile_index" > "/tmp/first.dump"; '.format(blockstack_opts['subdomaindb_path']) + \
          'sqlite3 "{}" "select * from subdomain_records order by parent_zonefile_index" > "/tmp/second.dump"; '.format(new_opts['subdomaindb_path']) + \
          'cmp "/tmp/first.dump" "/tmp/second.dump"'

    print cmd
    rc = os.system(cmd)
    if rc != 0:
        print '{} disagress with {}'.format(blockstack_opts['subdomaindb_path'], new_opts['subdomaindb_path'])
        return False

    # get all subdomain records and their initial addresses
    p = subprocess.Popen('sqlite3 "{}" "select fully_qualified_subdomain from subdomain_records where sequence = 0 and accepted = 1 order by parent_zonefile_index;"'.format(blockstack_opts['subdomaindb_path']), shell=True, stdout=subprocess.PIPE)
    all_subdomains, _ = p.communicate()

    all_subdomains = all_subdomains.strip().split('\n')

    p = subprocess.Popen('sqlite3 "{}" "select owner from subdomain_records where sequence = 0 and accepted = 1 order by parent_zonefile_index;"'.format(blockstack_opts['subdomaindb_path']), shell=True, stdout=subprocess.PIPE)
    all_creator_addresses, _ = p.communicate()
    
    all_creator_addresses = all_creator_addresses.strip().split('\n')

    subrec_dids = {}
    subrecs = {}

    for (subd, addr) in zip(all_subdomains, all_creator_addresses):
        subrec = blockstack.lib.client.get_name_record(subd, hostport='localhost:{}'.format(blockstack.lib.config.RPC_SERVER_PORT))
        assert subrec
        assert 'error' not in subrec, subrec

        subd_did = blockstack.lib.client.get_name_DID(subd, hostport='localhost:{}'.format(blockstack.lib.config.RPC_SERVER_PORT))

        subrecs[subd] = subrec
        subrec_dids[subd] = subd_did

        did_info = blockstack.lib.util.parse_DID(subd_did)
        assert did_info['name_type'] == 'subdomain'
        assert virtualchain.address_reencode(did_info['address']) == virtualchain.address_reencode(addr), 'address mismatch on {}: {} (expected {})\nsubrec: {}'.format(subd, did_info['address'], addr, subrec)

    for subd in subrec_dids:
        did = subrec_dids[subd]
        subrec = blockstack.lib.client.get_DID_record(did, hostport='localhost:{}'.format(blockstack.lib.config.RPC_SERVER_PORT))
        assert subrec
        assert 'error' not in subrec, subrec

        assert subrec == subrecs[subd], 'Did not resolve {} to {}, but instead to {}'.format(did, subrecs[subd], subrec)

    return True


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

def set_server_state( state ):
    global server_state
    server_state = state

def set_default_payment_wallet( w ):
    global default_payment_wallet
    default_payment_wallet = w

def set_test_running(r):
    global test_running
    test_running = r

def get_bitcoind():
    global bitcoind
    return bitcoind

def connect_bitcoind():
    url = 'http://blockstack:blockstacksystem@localhost:18332'
    return virtualchain.AuthServiceProxy(url)


def get_state_engine():
    global state_engine
    return state_engine

def get_server_state():
    global server_state
    return server_state

def is_test_running():
    global test_running
    return test_running

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


def peer_make_config( working_dir, peer_port, dirp, seed_relations={}, blacklist_relations={}, extra_fields={} ):
    """
    Make a config directory for a peer blockstack server
    """
    hostport = "localhost:%s" % peer_port

    # generate server config
    blockstack_conf = blockstack.default_blockstack_opts(working_dir)
    virtualchain_bitcoin_conf = virtualchain.get_bitcoind_config()

    virtualchain_bitcoin_conf['bitcoind_port'] = 18332
    virtualchain_bitcoin_conf['bitcoind_p2p_port'] = 18444 
    virtualchain_bitcoin_conf['bitcoind_server'] = 'localhost'
    virtualchain_bitcoin_conf['bitcoind_regtest'] = True
    virtualchain_bitcoin_conf['bitcoind_spv_path'] = os.path.join( dirp, "spv_headers.dat" )

    blockstack_conf['rpc_port'] = peer_port
    blockstack_conf['server_version'] = '0.17.0'
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

    blockstack.lib.config.write_config_file( conf, conf_path )

    '''
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
    blockstack.lib.config.write_config_file( new_conf, os.path.join(dirp, "client.ini") )
    '''
    return True


def peer_start( global_working_dir, working_dir, port=None, command='start', args=['--foreground']):
    """
    Start up a peer blockstack subprocess
    to communicate on the given network server.
    Return a dict with the peer information.
    """
    args = ['blockstack-core', command] + args
    if port:
        args += ['--port', str(port)]
    
    args += ['--working_dir', working_dir]
    output = os.path.join(working_dir, "blockstack-server.out")
    
    args += ['--expected-snapshots', os.path.join(global_working_dir, 'blockstack-server.snapshots')]
    env = {}

    # preserve test environment variables
    for envar in os.environ.keys():
        if envar.startswith("BLOCKSTACK_") and envar not in ['BLOCKSTACK_CLIENT_CONFIG', 'BLOCKSTACK_SERVER_CONFIG']:
            log.debug("Env: '%s' = '%s'" % (envar, os.environ[envar]))
            env[envar] = os.environ[envar]

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
    rpc = blockstack.lib.client.BlockstackRPCClient( 'localhost', peer_info['port'], timeout=5 )
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

    if 'error' in info:
        log.error("Failed to query localhost:{}: {}".format(peer_info['port'], info['error']))
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


def peer_working_dir( base_working_dir, index ):
    """
    Get the working dir for a peer
    """
    peer_wd = os.path.join(base_working_dir, 'peer-{}'.format(index))
    return peer_wd


def peer_setup( base_working_dir, index ):
    """
    Set up the ith peer
    Return {'working_dir': ..., 'device_id': ..., 'config_path': ...} on success
    Return {'error': ...} on error 
    """
    # set up a new peer
    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    assert config_path

    config_dir = os.path.dirname(config_path)

    peer_wd = peer_working_dir(base_working_dir, index)
    peer_config_dir = os.path.join(peer_wd, 'client')

    os.makedirs(peer_wd)
    os.makedirs(peer_config_dir)

    config_path_2 = os.path.join(peer_config_dir, 'client.ini')
    if os.path.exists(config_path_2):
        raise Exception("Config already exists for client {}".format(index))

    res = peer_make_config(peer_working_dir, 16300 + index, peer_wd)
    if 'error' in res:
        print "failed to set up {}".format(peer_wd)
        return {'error': 'failed to set up config dir'}

    return {'working_dir': peer_wd, 'device_id': res['device_id'], 'config_path': config_path_2}


def list_working_dirs(base_working_dir):
    """
    Find all working directories
    """
    ret = [working_dir]

    # account for all peers too 
    for name in os.listdir(working_dir):
        if name.startswith("peer-"):
            ret.append(os.path.join(working_dir, name))

    return ret


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
   
    cwd = os.getcwd()

    try:
        os.chdir(tmpdir)
        p = subprocess.Popen(["/usr/bin/npm", "install", "babel-cli", "babel-preset-es2015"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, close_fds=True)
        out, err = p.communicate()
        retval = p.returncode
        os.chdir(cwd)
    except:
        os.chdir(cwd)
        raise

    if retval != 0:
        print >> sys.stderr, err
        raise Exception("Failed to set up npm: exit code {}".format(retval))

    print "Node install at {}".format(tmpdir)
    return tmpdir


def nodejs_copy_package( testdir, package_name ):
    """
    Copy the contents of a package into the test directory
    """
    prefixes = filter(lambda x: len(x) > 0, os.environ.get("NODE_PATH", "/usr/lib/node_modules:/usr/local/lib/node_modules").split(":"))
    node_package_path = None
    for prefix in prefixes:
        node_package_path = '{}/{}'.format(prefix, package_name)
        if os.path.exists(node_package_path):
            break
        else:
            node_package_path = None

    if node_package_path is None:
        raise Exception("Missing node package {}: no directories in NODE_PATH {}".format(package_name, ':'.join(prefixes)))
    
    for name in os.listdir(node_package_path):
        src_path = os.path.join(node_package_path, name)
        dest_path = os.path.join(testdir, name)

        if os.path.isdir(src_path):
            shutil.copytree(src_path, dest_path, symlinks=True)
        else:
            shutil.copy(src_path, dest_path)

    return True


def nodejs_link_package( testdir, package_name ):
    """
    Link a dependency to a package
    """

    cwd = os.getcwd()

    try:
        os.chdir(testdir)
        p = subprocess.Popen(["/usr/bin/npm", "link", package_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, close_fds=True)
        out, err = p.communicate()
        retval = p.returncode
        os.chdir(cwd)
    except:
        os.chdir(cwd)
        raise

    if retval != 0:
        print >> sys.stderr, err
        raise Exception("Failed to npm link: exit code {}".format(retval))

    return True


def nodejs_run_test( testdir, test_name="core-test" ):
    """
    Run a nodejs test
    """
    cwd = os.getcwd()

    try:
        os.chdir(testdir)
        p = subprocess.Popen(["/usr/bin/npm", "install"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, close_fds=True)
        out, err = p.communicate()
        retval = p.returncode
    except:
        os.chdir(cwd)
        raise

    if retval != 0:
        print >> sys.stderr, err
        raise Exception("Failed to npm link: exit code {}".format(retval))

    try:
        p = subprocess.Popen(["/usr/bin/npm", "run", test_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, close_fds=True)
        out, err = p.communicate()
        retval = p.returncode
        os.chdir(cwd)
    except:
        os.chdir(cwd)
        raise
    
    print ''
    print 'output'
    print out
    print ''

    print 'stderr'
    print err
    print ''

    lines = out.split('\n') + err.split('\n')
    for line in lines:
        if line.startswith('npm ERR'):
            raise Exception("Test {} failed".format(test_name))

    return True


