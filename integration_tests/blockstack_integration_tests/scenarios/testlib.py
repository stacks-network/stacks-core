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
import threading
import signal
import atexit
import re
import socket
import requests
from decimal import Decimal
import blockstack.blockstackd as blockstackd
import blockstack.lib.client as blockstackd_client
import blockstack.lib.snv as snv_client
from blockstack.lib.nameset.namedb import BlockstackDB
import traceback
import blockstack
import keylib

import virtualchain

log = virtualchain.get_logger("testlib")

SATOSHIS_PER_COIN = 10**8
TOKEN_TYPE_STACKS = 'STACKS'

TX_MIN_CONFIRMATIONS = 6
if os.environ.get("BLOCKSTACK_TEST", None) is not None:
    # test environment
    TX_MIN_CONFIRMATIONS = 0
    print 'TEST ACTIVE: TX_MIN_CONFIRMATIONS = {}'.format(TX_MIN_CONFIRMATIONS)

if os.environ.get("BLOCKSTACK_MIN_CONFIRMATIONS", None) is not None:
    TX_MIN_CONFIRMATIONS = int(os.environ['BLOCKSTACK_MIN_CONFIRMATIONS'])
    print >> sys.stderr, "Set TX_MIN_CONFIRMATIONS to {}".format(TX_MIN_CONFIRMATIONS)


class Wallet(object):
    def __init__(self, pk_wif, tokens_granted, vesting={} ):

        pk = virtualchain.BitcoinPrivateKey( pk_wif )

        self._pk = pk
        self._token_grant = tokens_granted
        self._vesting_schedule = vesting

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
        self._vesting_schedule = kwargs.get('vesting', {})

        self.addr = self.privkey['address']

        if os.environ.get('BLOCKSTACK_TEST_FORCE_SEGWIT') == '1':
            self.segwit = True
            self.privkey = virtualchain.make_multisig_segwit_info( m, pks )
            log.debug("Multisig P2SH-P2WSH wallet %s" % (self.addr))

        else:
            log.debug("Multisig wallet %s" % (self.addr))


class SegwitWallet(object):
    def __init__(self, pk_wif, tokens_granted=0, vesting={}, native=False ):

        self.privkey = virtualchain.make_segwit_info( pk_wif )
        pk = virtualchain.BitcoinPrivateKey( pk_wif )

        self._pk = pk
        self.segwit = True
        self._token_grant = tokens_granted
        self._vesting_schedule = vesting
        self.segwit_native = native
        if self.segwit_native:
            self.privkey['segwit_native'] = True

        self.pubkey_hex = pk.public_key().to_hex()
        self.addr = self.privkey['address']
        
        log.debug("P2SH-P2WPKH Wallet %s (%s)" % (self.privkey, self.addr))


class MultisigSegwitWallet(object):
    def __init__(self, m, *pks, **kwargs ):

        self.privkey = virtualchain.make_multisig_segwit_info( m, pks )
        self.m = m
        self.n = len(pks)
        self.pks = pks
        self.segwit = True
        self.segwit_native = kwargs.get('native', False)
        if self.segwit_native:
            self.privkey['segwit_native'] = True

        self._token_grant = kwargs.get('tokens_granted', 0)
        self._vesting_schedule = kwargs.get('vesting', {})

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
    def __init__(self, namespace_id, payment_addr, price=None):
        blockstackd_url = 'http://localhost:16264'
        
        namespace_cost_info = price
        if not namespace_cost_info:
            namespace_cost_info = blockstackd_client.get_namespace_cost(namespace_id, hostport=blockstackd_url)

        super(TokenNamespacePreorder, self).__init__("NAMESPACE_PREORDER", namespace_cost_info['units'], namespace_cost_info['amount'], payment_addr)


class TokenNamePreorder(TokenOperation):
    def __init__(self, name, preorder_addr, price=None):
        blockstackd_url = 'http://localhost:16264'

        name_cost_info = price
        if not name_cost_info:
            name_cost_info = blockstackd_client.get_name_cost(name, hostport=blockstackd_url)

        super(TokenNamePreorder, self).__init__('NAME_PREORDER', name_cost_info['units'], name_cost_info['amount'], preorder_addr)


class TokenNameRenewal(TokenOperation):
    def __init__(self, name, owner_addr, price=None):
        blockstackd_url = 'http://localhost:16264'

        name_cost_info = price
        if not name_cost_info:
            name_cost_info = blockstackd_client.get_name_cost(name, hostport=blockstackd_url)

        super(TokenNameRenewal, self).__init__('NAME_RENEWAL', name_cost_info['units'], name_cost_info['amount'], owner_addr)


class TokenTransfer(TokenOperation):
    def __init__(self, recipient_addr, token_type, token_amount, privatekey):
        sender_addr = virtualchain.address_reencode(virtualchain.get_privkey_address(privatekey))
        self.recipient_addr = recipient_addr
        super(TokenTransfer, self).__init__('TOKEN_TRANSFER', token_type, token_amount, sender_addr)


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

# list of cleanup methods to be called
CLEANUP_METHODS = []

AUDIT_ACCOUNTS = True

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


def blockstack_get_name_cost(name, config_path=None):
    """
    Legacy compat for bitcoin
    """
    blockstackd_url = 'http://localhost:16264'
    name_cost_info = blockstackd_client.get_name_cost(name, hostport=blockstackd_url)
    return int(name_cost_info['amount'])


def blockstack_get_name_token_cost(name):
    """
    Get the token price of a name.  Use the CLI.
    """
    assert has_nodejs_cli()
    info = nodejs_cli('price', name)
    info = json.loads(info)
    info['amount'] = int(info['amount'])
    return info


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
    Returns the last line of output, unless otherwise specified
    """
    safety_checks = kw.get('safety_checks', True)
    consensus_hash = kw.get('consensus_hash', None)
    tx_fee = kw.get('tx_fee', None)
    tx_only = kw.get('tx_only', False)
    burn_address = kw.get('burn_addr', None)
    pattern = kw.get('pattern', None)
    full_output = kw.get('full_output', False)
    price = kw.get('price', None)
    expect_fail = kw.get('expect_fail', False)

    if NODEJS_CLI_PATH is None:
        if not has_nodejs_cli():
            raise Exception("No node.js CLI found")

    base_cmd = [NODEJS_CLI_PATH, '-i']
    if not safety_checks:
        base_cmd += ['-U']

    if consensus_hash:
        base_cmd += ['-C', str(consensus_hash)]

    if burn_address:
        base_cmd += ['-B', str(burn_address)]

    if tx_only:
        pattern = '^[0-9a-f]+$'
        base_cmd += ['-x']

    if price:
        base_cmd += ['-P', '{}'.format(price['amount']), '-D', '{}'.format(price['units'])]

    grace_period = blockstack.lib.config.get_epoch_namespace_lifetime_grace_period(state_engine.get_current_block(), '*')
    fees_period = blockstack.lib.config.get_epoch_namespace_receive_fees_period(state_engine.get_current_block(), '*')

    base_cmd += ['-N', '{}'.format(fees_period), '-G', '{}'.format(grace_period)]

    base_cmd_save = base_cmd[:]

    if tx_fee:
        base_cmd += ['-x']      # don't send just yet; get the size and then update the fee rate
    
    saved_out = [None]
    saved_err = [None]

    def run(cmd_opts, cmd_args):
        cmd = cmd_opts + ['{}'.format(ca) for ca in cmd_args]
        log.debug('\n$ {}\n'.format(' '.join(cmd)))

        p = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        res = p.returncode
        if res != 0 and not expect_fail:
            print err

            if os.environ.get('BLOCKSTACK_TEST_CLI_SLEEP_ON_FAILURE'):
                print 'Sleeping so you can experiment with what went wrong'
                while True:
                    time.sleep(1)

            raise Exception("Exit code {}: {}".format(res, cmd))

        elif res != 0 and expect_fail:
            print err
            return {'error': 'CLI exited {} (but this is expected)'.format(res)}

        ret = None
        if full_output:
            ret = out
        else:
            ret = out.strip().split('\n')[-1]

        saved_out[0] = out
        saved_err[0] = err
        return ret

    ret = run(base_cmd, list(args))
    if not tx_fee or tx_only:
        try:
            json_out = saved_out[0].strip().split('\n')[-1]
            resp = json.loads(json_out)
            if 'error' in resp:
                return json_out
        except:
            pass

        if pattern and not expect_fail:
            assert re.match(pattern, ret), 'Output does not match {}: {}\nfull output:\n{}\nerror:\n{}'.format(pattern, ret, saved_out[0], saved_err[0])

        return ret

    # ret will be a transaction in full
    txlen = len(ret)/2
    tx_fee_rate = int(round(float(tx_fee)/txlen))
    
    # do it again with this fee
    base_cmd = base_cmd_save + ['-F', '{}'.format(tx_fee_rate)]
    ret = run(base_cmd, list(args))

    try:
        json_out = saved_out[0].strip().split('\n')[-1]
        resp = json.loads(json_out)
        if 'error' in resp:
            return json_out
    except:
        pass

    if pattern and not expect_fail:
        assert re.match(pattern, ret), 'Output does not match {}: {}\nfull output:\n{}\nerror:\n{}'.format(pattern, ret, saved_out[0], saved_err[0])

    return ret


def blockstack_name_preorder( name, privatekey, register_addr, wallet=None, burn_addr=None, consensus_hash=None, tx_fee=None, tx_only=False, safety_checks=True, price=None, expect_fail=False, expect_success=False, config_path=None ):

    global api_call_history 

    payment_addr = virtualchain.address_reencode(virtualchain.get_privkey_address(privatekey))
    register_addr = virtualchain.address_reencode(register_addr)
     
    resp = None
    if has_nodejs_cli():
        print privatekey
        txid = nodejs_cli('tx_preorder', name, 'ID-' + register_addr, serialize_privkey_info(privatekey), burn_addr=burn_addr, consensus_hash=consensus_hash,
                          tx_fee=tx_fee, tx_only=tx_only, price=price, safety_checks=safety_checks, expect_fail=expect_fail, pattern='^[0-9a-f]{64}$')

        if 'error' in txid:
            return txid

        if tx_only:
            resp = {
                'status': True,
                'transaction': txid
            }
        else:
            resp = {
                'status': True,
                'transaction_hash': txid
            }

    else:
        raise Exception("No Node.js CLI found")

    if not tx_only or expect_success:
        token_record = None
        if not expect_fail and (price is None or price['units'] != 'BTC'):
            token_record = TokenNamePreorder(name, payment_addr, price=price)

        if tx_only:
            transaction_hash = virtualchain.btc_tx_get_hash(resp['transaction'])
            resp['transaction_hash'] = transaction_hash

        api_call_history.append( APICallRecord( "preorder", name, payment_addr, resp, token_record=token_record ) )

    return resp


def blockstack_name_register( name, privatekey, register_addr, zonefile_hash=None, wallet=None, safety_checks=True, tx_only=False, config_path=None, tx_fee=None, expect_fail=False ):
    
    global api_call_history
    resp = None
    register_addr = virtualchain.address_reencode(register_addr)

    if has_nodejs_cli():
        txid = None
        if zonefile_hash is not None:
            txid = nodejs_cli('tx_register', name, 'ID-' + register_addr, serialize_privkey_info(privatekey), 'ignored', zonefile_hash, safety_checks=safety_checks, tx_fee=tx_fee, tx_only=tx_only, pattern='^[0-9a-f]{64}$', expect_fail=expect_fail)
        else:
            txid = nodejs_cli('tx_register', name, 'ID-' + register_addr, serialize_privkey_info(privatekey), safety_checks=safety_checks, tx_fee=tx_fee, pattern='^[0-9a-f]{64}$', expect_fail=expect_fail)

        if 'error' in txid:
            return txid

        if tx_only:
            resp = {
                'status': True,
                'transaction': txid
            }
        else:
            resp = {
                'status': True,
                'transaction_hash': txid
            }

    else:
        raise Exception("No Node.js CLI found")

    if not tx_only:
        api_call_history.append( APICallRecord( "register", name, register_addr, resp ) )

    return resp


def blockstack_name_update( name, data_hash, privatekey, consensus_hash=None, safety_checks=True, tx_only=False, config_path=None, tx_fee=None, expect_fail=False ):
    
    global api_call_history
    
    payment_key = get_default_payment_wallet().privkey
    resp = None

    if has_nodejs_cli():
        txid = nodejs_cli('update', name, 'ignored', serialize_privkey_info(privatekey), serialize_privkey_info(payment_key), data_hash, 
                safety_checks=safety_checks, consensus_hash=consensus_hash, tx_only=tx_only, tx_fee=tx_fee, pattern='^[0-9a-f]{64}$', expect_fail=expect_fail)

        if 'error' in txid:
            return txid

        if tx_only:
            resp = {
                'status': True,
                'transaction': txid
            }
        else:
            resp = {
                'status': True,
                'transaction_hash': txid
            }

    else:
        raise Exception("No Node.js CLI found")

    if not tx_only:
        api_call_history.append( APICallRecord( "update", name, None, resp ) )

    return resp


def blockstack_name_transfer( name, address, keepdata, privatekey, consensus_hash=None, safety_checks=True, tx_only=False, config_path=None, tx_fee=None, expect_fail=False ):
     
    global api_call_history

    payment_key = get_default_payment_wallet().privkey
    resp = None

    if has_nodejs_cli():
        txid = nodejs_cli('transfer', name, 'ID-' + address, '{}'.format(keepdata).lower(), serialize_privkey_info(privatekey), serialize_privkey_info(payment_key),
                safety_checks=safety_checks, consensus_hash=consensus_hash, tx_only=tx_only, tx_fee=tx_fee, pattern='^[0-9a-f]{64}$', expect_fail=expect_fail)

        if 'error' in txid:
            return txid

        if tx_only:
            resp = {
                'status': True,
                'transaction': txid
            }
        else:
            resp = {
                'status': True,
                'transaction_hash': txid
            }

    else:
        raise Exception("No Node.js CLI found")

    if not tx_only:
        api_call_history.append( APICallRecord( "transfer", name, address, resp ) )

    return resp


def blockstack_name_renew( name, privatekey, recipient_addr=None, burn_addr=None, safety_checks=True, config_path=None, zonefile_hash=None, tx_fee=None, tx_only=False, price=None, expect_fail=False, expect_success=False, tx_fee_per_byte=None, use_cli=True):
    
    global api_call_history
    
    owner_addr = virtualchain.address_reencode(virtualchain.get_privkey_address(privatekey))
    payment_key = get_default_payment_wallet().privkey
    resp = None

    if has_nodejs_cli():
        txid = None
        if recipient_addr is not None:
            if zonefile_hash is not None:
                txid = nodejs_cli('renew', name, serialize_privkey_info(privatekey), serialize_privkey_info(payment_key), 'ID-' + recipient_addr, 'ignored', zonefile_hash, 
                        safety_checks=safety_checks, tx_only=tx_only, price=price, burn_addr=burn_addr, tx_fee=tx_fee, pattern='^[0-9a-f]{64}$', expect_fail=expect_fail)
            else:
                txid = nodejs_cli('renew', name, serialize_privkey_info(privatekey), serialize_privkey_info(payment_key), 'ID-' + recipient_addr, 
                        safety_checks=safety_checks, burn_addr=burn_addr, tx_only=tx_only, tx_fee=tx_fee, price=price, pattern='^[0-9a-f]{64}$', expect_fail=expect_fail)
        else:
            if zonefile_hash is not None:
                # txid = nodejs_cli('renew', name, privatekey, payment_key, owner_addr, safety_checks=safety_checks, burn_addr=burn_addr, tx_fee=tx_fee, price=price, pattern='^[0-9a-f]{64}$')
                raise Exception("Cannot set a zone file hash without a destination address")
            else:
                txid = nodejs_cli('renew', name, serialize_privkey_info(privatekey), serialize_privkey_info(payment_key), 
                        safety_checks=safety_checks, burn_addr=burn_addr, tx_only=tx_only, price=price, tx_fee=tx_fee, expect_fail=expect_fail)

        if 'error' in txid:
            return txid

        if tx_only:
            resp = {
                'status': True,
                'transaction': txid,
            }
        else:
            resp = {
                'status': True,
                'transaction_hash': txid,
            }

    else:
        raise Exception("No Node.js CLI found")

    if not tx_only or expect_success:
        token_record = None
        if not expect_fail and (price is None or price['units'] != 'BTC'):
            token_record = TokenNameRenewal(name, owner_addr, price=price)

        if tx_only:
            transaction_hash = virtualchain.btc_tx_get_hash(resp['transaction'])
            resp['transaction_hash'] = transaction_hash

        api_call_history.append( APICallRecord( "renew", name, virtualchain.address_reencode(recipient_addr) if recipient_addr is not None else None, resp, token_record=token_record) )

    return resp


def blockstack_name_revoke( name, privatekey, safety_checks=True, config_path=None, tx_fee=None, tx_only=False, expect_fail=False ):
    
    global api_call_history

    payment_key = get_default_payment_wallet().privkey
    resp = None

    if has_nodejs_cli():
        txid = nodejs_cli('revoke', name, serialize_privkey_info(privatekey), serialize_privkey_info(payment_key), safety_checks=safety_checks, tx_fee=tx_fee, tx_only=tx_only, pattern='^[0-9a-f]{64}$', expect_fail=expect_fail)

        if 'error' in txid:
            return txid

        if tx_only:
            resp = {
                'status': True,
                'transaction': txid
            }
        else:
            resp = {
                'status': True,
                'transaction_hash': txid
            }

    else:
        raise Exception("No Node.js CLI found")

    if not tx_only:
        api_call_history.append( APICallRecord( "revoke", name, None, resp ) )

    return resp


def blockstack_name_import( name, recipient_address, update_hash, privatekey, safety_checks=True, tx_only=False, config_path=None, expect_fail=False):
    
    global api_call_history
    
    resp = None
    if has_nodejs_cli():
        txid = nodejs_cli('name_import', name, 'ID-' + recipient_address, "ignored_gaia_hub", serialize_privkey_info(privatekey), "ignored_zonefile_path", update_hash, tx_only=tx_only, safety_checks=safety_checks, expect_fail=expect_fail)

        if 'error' in txid:
            return txid

        if tx_only:
            resp = {
                'status': True,
                'transaction': txid
            }
        else:
            resp = {
                'status': True,
                'transaction_hash': txid
            }

    else:
        raise Exception("No Node.js CLI found")

    if not tx_only:
        api_call_history.append( APICallRecord( "name_import", name, virtualchain.address_reencode(recipient_address), resp ) )

    return resp


def blockstack_namespace_preorder( namespace_id, register_addr, privatekey, burn_addr=None, consensus_hash=None, safety_checks=True, config_path=None, tx_only=False, tx_fee=None, price=None, expect_fail=False, expect_reject=False, use_cli=True):
    
    global api_call_history
    resp = None
    payment_addr = virtualchain.address_reencode(virtualchain.get_privkey_address(privatekey))

    if has_nodejs_cli():
        txid = nodejs_cli('namespace_preorder', namespace_id, register_addr, serialize_privkey_info(privatekey), 
                consensus_hash=consensus_hash, burn_addr=burn_addr, safety_checks=safety_checks, price=price, tx_fee=tx_fee, tx_only=tx_only, pattern='^[0-9a-f]{64}$', expect_fail=expect_fail)

        if 'error' in txid:
            return txid

        if tx_only:
            resp = {
                'status': True,
                'transaction': txid
            }
        else:
            resp = {
                'status': True,
                'transaction_hash': txid
            }
        
    else:
        raise Exception("No Node.js CLI found")

    if not tx_only:
        token_record = None
        if not expect_fail and not expect_reject and (price is None or price['units'] != 'BTC'):
            token_record = TokenNamespacePreorder(namespace_id, payment_addr, price=price)

        api_call_history.append( APICallRecord( "namespace_preorder", namespace_id, virtualchain.address_reencode(virtualchain.get_privkey_address(privatekey)), resp, token_record=token_record) )

    return resp


def blockstack_namespace_reveal( namespace_id, register_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, privatekey, version_bits=1, safety_checks=True, tx_only=False, tx_fee=None, config_path=None, use_cli=True, expect_fail=False):
    
    global api_call_history
    resp = None
    register_addr = virtualchain.address_reencode(register_addr)

    if has_nodejs_cli():
        txid = {}
        try:
            txid = nodejs_cli('namespace_reveal', namespace_id, register_addr, '{}'.format(version_bits), '{}'.format(lifetime), '{}'.format(coeff), '{}'.format(base), 
                    ','.join(['{}'.format(bucket) for bucket in bucket_exponents]), '{}'.format(nonalpha_discount), '{}'.format(no_vowel_discount), 
                    serialize_privkey_info(privatekey), safety_checks=safety_checks, pattern='^[0-9a-f]{64}$', tx_only=tx_only, tx_fee=tx_fee, expect_fail=expect_fail)
        
        except:
            if expect_fail:
                txid = {'error': 'command failed'}
            else:
                raise

        if 'error' in txid:
            return txid

        if tx_only:
            resp = {
                'status': True,
                'transaction': txid
            }
        else:
            resp = {
                'status': True,
                'transaction_hash': txid
            }

    else:
        raise Exception("No Node.js CLI found")

    if not tx_only:
        api_call_history.append( APICallRecord( "namespace_reveal", namespace_id, virtualchain.address_reencode(register_addr), resp ) )

    return resp


def blockstack_namespace_ready( namespace_id, privatekey, safety_checks=True, tx_only=False, config_path=None, use_cli=True, expect_fail=False):
    
    global api_call_history
    resp = None

    if has_nodejs_cli():
        txid = nodejs_cli('namespace_ready', namespace_id, serialize_privkey_info(privatekey), safety_checks=safety_checks, tx_only=tx_only, pattern='^[0-9a-f]{64}$', expect_fail=expect_fail)

        if 'error' in txid:
            return txid

        resp = {
            'status': True,
            'transaction_hash': txid
        }

    else:
        raise Exception("No Node.js CLI found")

    if not tx_only:
        api_call_history.append( APICallRecord( "namespace_ready", namespace_id, virtualchain.address_reencode(virtualchain.get_privkey_address(privatekey)), resp ) )

    return resp


def blockstack_announce( message, privatekey, safety_checks=True, tx_only=False, config_path=None, expect_fail=False ):
    
    global api_call_history

    resp = None

    if has_nodejs_cli():
        message_hash = blockstack.lib.storage.get_zonefile_data_hash(message)
        txid = nodejs_cli('announce',  message_hash, serialize_privkey_info(privatekey), safety_checks=safety_checks, tx_only=tx_only, expect_fail=expect_fail)

        if 'error' in txid:
            return txid

        if tx_only:
            resp = {
                'status': True,
                'transaction': txid
            }
        else:
            resp = {
                'status': True,
                'transaction_hash': txid
            }

    else:
        raise Exception("No Node.js CLI found")

    if not tx_only:
        api_call_history.append( APICallRecord( "announce", message, None, resp ) )

    return resp


def blockstack_send_tokens(recipient_address, token_type, token_amount, privkey, consensus_hash=None, safety_checks=True, tx_only=False, expect_fail=False):
    global api_call_history

    assert has_nodejs_cli()

    # re-encode the address to stacks format
    res = nodejs_cli('convert_address', recipient_address)
    res = json.loads(res)
    if 'error' in res:
        return res

    stacks_recipient_address = res['testnet']['STACKS']

    txid = nodejs_cli('send_tokens', stacks_recipient_address, token_type, token_amount, serialize_privkey_info(privkey), safety_checks=safety_checks, tx_only=tx_only, consensus_hash=consensus_hash, expect_fail=expect_fail)
    if 'error' in txid:
        return txid

    if tx_only:
        resp = {
            'status': True,
            'transaction': txid
        }
    else:
        resp = {
            'status': True,
            'transaction_hash': txid
        }

    token_record = None
    if not expect_fail:
        token_record = TokenTransfer(recipient_address, token_type, token_amount, privkey)

    # TODO: expand SNV to cover token records
    api_call_history.append( APICallRecord( "token_transfer", recipient_address, virtualchain.address_reencode(virtualchain.get_privkey_address(privkey)), resp, token_record=token_record) )
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

            payment_privkey_str = 'segwit:p2sh:{},{}'.format(m, ','.join(payment_privkey['private_keys']))
        else:
            m, pubks = virtualchain.parse_multisig_redeemscript(payment_privkey['redeem_script'])
            n = len(payment_privkey['private_keys'])
            payment_privkey_str = '{},{}'.format(m, ','.join(payment_privkey['private_keys']))

    return payment_privkey_str


def blockstack_cli_namespace_preorder( namespace_id, payment_privkey, reveal_privkey, config_path=None ):
    """
    Preorder a namespace
    """
    use_cli = True
    if not virtualchain.is_singlesig(payment_privkey) or not virtualchain.is_singlesig(reveal_privkey):
        use_cli = False

    return blockstack_namespace_preorder(namespace_id, virtualchain.get_privkey_address(reveal_privkey), payment_privkey, use_cli=use_cli)


def blockstack_cli_namespace_reveal( namespace_id, payment_privkey, reveal_privkey, lifetime, coeff, base, buckets, nonalpha_disc, no_vowel_disc, preorder_txid=None, config_path=None, version_bits=1, expect_fail=False):
    """
    reveal a namespace
    """
    try:
        use_cli = True
        if not virtualchain.is_singlesig(payment_privkey) or not virtualchain.is_singlesig(reveal_privkey):
            use_cli = False

        buckets = [int(x) for x in buckets.split(',')]
        return blockstack_namespace_reveal(namespace_id, virtualchain.address_reencode(virtualchain.get_privkey_address(reveal_privkey)),
                lifetime, coeff, base, buckets, nonalpha_disc, no_vowel_disc, payment_privkey, version_bits=version_bits, use_cli=use_cli, expect_fail=expect_fail)
    except:
        if expect_fail:
            return {'error': 'failed to call into CLI to reveal namespace'}
        else:
            raise


def blockstack_cli_namespace_ready( namespace_id, reveal_privkey, config_path=None ):
    """
    launch a namespace
    """
    use_cli = True
    if not virtualchain.is_singlesig(payment_privkey) or not virtualchain.is_singlesig(reveal_privkey):
        use_cli = False

    return blockstack_namespace_ready(namespace_id, reveal_privkey, use_cli=use_cli)
  

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

    try:
        virtualchain.address_reencode(pubkey_or_addr)
        pubkey_or_addr = 'ID-' + pubkey_or_addr
    except:
        pass

    resp = nodejs_cli('profile_verify', path, pubkey_or_addr)
    return json.loads(resp)


def blockstack_cli_get_name_blockchain_record( name, config_path=None):
    """
    get name blockchain record
    """
    if not has_nodejs_cli():
        raise Exception("Missing blockstack-cli")

    resp = nodejs_cli('get_blockchain_record', name)
    print 'blockchain record for {} is {}'.format(name, resp)
    return json.loads(resp)


# legacy
def get_name_blockchain_record(name):
    return blockstack_cli_get_name_blockchain_record(name)


def blockstack_cli_get_name_blockchain_history( name, page, config_path=None):
    """
    get name blockchain history
    """
    if not has_nodejs_cli():
        raise Exception("Missing blockstack-cli")

    resp = nodejs_cli('get_blockchain_history', name, page)
    return json.loads(resp)


def blockstack_cli_get_namespace_blockchain_record( namespace_id, config_path=None):
    """
    get namespace blockchain record
    """
    if not has_nodejs_cli():
        raise Exception("Missing blockstack-cli")

    resp = nodejs_cli('get_namespace_blockchain_record', namespace_id)
    return json.loads(resp)



def blockstack_cli_get_name_zonefile( name ):
    """
    get name zonefile
    """
    if not has_nodejs_cli():
        raise Exception("Missing blockstack-cli")

    resp = nodejs_cli('whois', name)
    resp = json.loads(resp)
    return resp['zonefile']


def blockstack_cli_get_names_owned_by_address( address, config_path=None):
    """
    get names owned by address
    """
    if not has_nodejs_cli():
        raise Exception("Missing blockstack-cli")

    resp = nodejs_cli('names', 'ID-' + address)
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
        urls = ['http://localhost:4000/hub/{}/profile.json'.format(virtualchain.address_reencode(address, network='mainnet'))]

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


def blockstack_register_user(name, privkey, owner_privkey, **kw):
    """
    Register a user in the test framework
    Give the user an empty profile and zone file.

    Generates 2 blocks
    """
    gaia_host = kw.get('gaia_host', 'localhost:4001')
    profile_name = kw.get('profile_name', 'profile.json')

    DEFAULT_PROFILE = {'type': '@Person', 'account': []}

    profile = kw.get('profile', DEFAULT_PROFILE)
    
    addr = virtualchain.BitcoinPrivateKey(owner_privkey).public_key().address()   # make it match the wallet
    owner_privkey = virtualchain.BitcoinPrivateKey(owner_privkey).to_hex()

    blockstack_name_preorder(name, privkey, addr)
    next_block(**kw)

    hub_config = requests.get('http://{}/hub_info'.format(gaia_host)).json()
    gaia_read_prefix = hub_config['read_url_prefix']

    if gaia_read_prefix[-1] != '/':
        gaia_read_prefix += '/'

    urls = ['{}{}/{}'.format(gaia_read_prefix, virtualchain.address_reencode(addr, network='mainnet'), profile_name)]
    zonefile_txt = make_empty_zonefile(name, addr, urls=urls)
    zonefile_hash = blockstack.lib.storage.get_zonefile_data_hash(zonefile_txt)

    blockstack_name_register(name, privkey, addr, zonefile_hash=zonefile_hash)
    next_block(**kw)

    blockstack_put_zonefile(zonefile_txt)
    profile_data = blockstack_make_profile(profile, owner_privkey)
    blockstack_put_profile(name, profile_data, owner_privkey, 'http://' + gaia_host)
    return True


def blockstack_import_user(name, privkey, owner_privkey, **kw):
    """
    Import a user in the test framework
    Give the user an empty profile and zone file.

    Generates 1 block
    """
    gaia_host = kw.get('gaia_host', 'localhost:4001')
    DEFAULT_PROFILE = {'type': '@Person', 'account': []}
    
    addr = virtualchain.BitcoinPrivateKey(owner_privkey).public_key().address()   # make it match the wallet
    owner_privkey = virtualchain.BitcoinPrivateKey(owner_privkey).to_hex()

    hub_config = requests.get('http://{}/hub_info'.format(gaia_host)).json()
    gaia_read_prefix = hub_config['read_url_prefix']

    if gaia_read_prefix[-1] != '/':
        gaia_read_prefix += '/'

    profile = kw.get('profile', DEFAULT_PROFILE)

    urls = ['{}{}/profile.json'.format(gaia_read_prefix, virtualchain.address_reencode(addr, network='mainnet'))]
    zonefile_txt = make_empty_zonefile(name, addr, urls=urls)
    zonefile_hash = blockstack.lib.storage.get_zonefile_data_hash(zonefile_txt)

    blockstack_name_import(name, addr, zonefile_hash, privkey)
    next_block(**kw)

    blockstack_put_zonefile(zonefile_txt)
    profile_data = blockstack_make_profile(profile, owner_privkey)
    blockstack_put_profile(name, profile_data, owner_privkey, 'http://' + gaia_host)
    return True


def blockstack_renew_user(name, privkey, owner_privkey, **kw):
    """
    Renew a user in the test framework
    Give the user an empty profile and zone file.

    Generates 1 block
    """
    gaia_host = kw.get('gaia_host', 'localhost:4001')
    DEFAULT_PROFILE = {'type': '@Person', 'account': []}
    
    addr = virtualchain.BitcoinPrivateKey(owner_privkey).public_key().address()   # make it match the wallet
    owner_privkey = virtualchain.BitcoinPrivateKey(owner_privkey).to_hex()

    hub_config = requests.get('http://{}/hub_info'.format(gaia_host)).json()
    gaia_read_prefix = hub_config['read_url_prefix']

    if gaia_read_prefix[-1] != '/':
        gaia_read_prefix += '/'

    profile = kw.get('profile', DEFAULT_PROFILE)

    urls = ['{}{}/profile.json'.format(gaia_read_prefix, virtualchain.address_reencode(addr, network='mainnet'))]
    zonefile_txt = make_empty_zonefile(name, addr, urls=urls)
    zonefile_hash = blockstack.lib.storage.get_zonefile_data_hash(zonefile_txt)

    blockstack_name_renew(name, privkey, recipient_addr=addr, zonefile_hash=zonefile_hash)
    next_block(**kw)

    blockstack_put_zonefile(zonefile_txt)
    profile_data = blockstack_make_profile({'type': '@Person', 'account': []}, owner_privkey)
    blockstack_put_profile(name, profile_data, owner_privkey, 'http://' + gaia_host)
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

    zonefile_txt = zonefile_result['zonefiles'][zonefile_hash]

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
        fd, path = tempfile.mkstemp('-blockstack-zonefile')
        os.write(fd, zonefile_txt)
        os.close(fd)

        res = nodejs_cli('zonefile_push', path)
        os.unlink(path)

        print res
        return True

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


def blockstack_put_profile(name, profile_token, privkey, gaia_hub, safety_checks=True):
    """
    Store a signed profile token
    """
    if has_nodejs_cli():
        if name is None:
            name = virtualchain.get_privkey_address(privkey)

        fd, path = tempfile.mkstemp('-blockstack-profile-store')
        os.write(fd, profile_token)
        os.close(fd)

        try:
            virtualchain.address_reencode(name)
            name = 'ID-' + name
        except:
            pass

        res = nodejs_cli('profile_store', name, path, privkey, gaia_hub, safety_checks=safety_checks)
        os.unlink(path)

        res = json.loads(res)
        if 'error' in res:
            return res
        
        if 'zonefile' in res and 'error' in res['zonefile']:
            return res['zonefile']

        return res['profileUrls']
    
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


def blockstack_gaia_getfile(username, origin, gaia_path, privkey=None, decrypt=False, verify=False):
    """
    Get a file from Gaia
    """
    assert has_nodejs_cli()
    res = None
    if privkey:
        res = nodejs_cli('gaia_getfile', username, origin, gaia_path, privkey, '1' if decrypt else '0', '1' if verify else '0', full_output=True)
    else:
        res = nodejs_cli('gaia_getfile', username, origin, gaia_path, full_output=True)

    return res


def blockstack_gaia_putfile(privkey, data_path, gaia_path, gaia_hub, encrypt=False, sign=False):
    """
    Store a file to Gaia
    """
    assert has_nodejs_cli()
    res = nodejs_cli('gaia_putfile', gaia_hub, privkey, data_path, gaia_path, '1' if encrypt else '0', '1' if sign else '0')
    try:
        return json.loads(res)
    except:
        print res
        return {'error': 'failed to store {} to {}'.format(data_path, gaia_path)}


def blockstack_gaia_listfiles(privkey, gaia_hub):
    """
    List gaia hub files
    Returns an array of file names
    """
    assert has_nodejs_cli()
    res = nodejs_cli('gaia_listfiles', gaia_hub, privkey, full_output=True)

    # listfiles output is a newline-separated list of names, plus the number of files at the end 
    filenames = filter(lambda s: len(s) > 0, res.split('\n'))
    return filenames[:-1]


def blockstack_gaia_dump_bucket(name_or_idaddr, app_origin, gaia_hub, mnemonic, dumpdir):
    """
    Dump a gaia hub bucket
    """
    assert has_nodejs_cli()
    res = nodejs_cli('gaia_dump_bucket', name_or_idaddr, app_origin, gaia_hub, mnemonic, dumpdir, full_output=True)
    print res

    try:
        res_json = json.loads(res.strip())
        if 'error' in res_json:
            return res_json
    except:
        pass

    return {'status': True}


def blockstack_gaia_restore_bucket(name_or_idaddr, app_origin, gaia_hub, mnemonic, dumpdir):
    """
    Restore a gaia dump
    """
    assert has_nodejs_cli()
    res = nodejs_cli('gaia_restore_bucket', name_or_idaddr, app_origin, gaia_hub, mnemonic, dumpdir)
    print res

    if 'error' in res:
        return res

    return {'status': True}


def blockstack_REST_call( method, route, api_pass=None, data=None, raw_data=None, config_path=None, allow_redirects=True, **query_fields ):
    """
    Low-level call to an API route
    Returns {'http_status': http status, 'response': json}
    """
    api_port = blockstack.lib.config.DEFAULT_API_PORT

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

    resp = requests.request( method, url, headers=headers, data=data, allow_redirects=allow_redirects )

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


def blockstack_verify_database( consensus_hash, consensus_block_id, untrusted_db_dir, new_db_dir, working_db_path=None, start_block=None):
    return blockstackd.verify_database( consensus_hash, consensus_block_id, untrusted_db_dir, new_db_dir, start_block=start_block)


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


def get_unspents(address):
    """
    Get the spendable transaction outputs, also known as UTXOs or
    unspent transaction outputs.

    NOTE: this will only return unspents if the address provided is present
    in the bitcoind server.
    """
    addresses = [address]
    
    bitcoind = connect_bitcoind()
    min_confirmations = 0
    max_confirmation = 99999  # just a very large number for max
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
    return get_unspents(addr)


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


def send_funds_tx( privkey, satoshis, payment_addr, change=True ):
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
    outputs = None

    if change:
        outputs = [
            {"script": virtualchain.make_payment_script(payment_addr),
             "value": satoshis},
            {"script": virtualchain.make_payment_script(send_addr),
             "value": virtualchain.calculate_change_amount(inputs, satoshis, 5500)},
        ]
    else:
        outputs = [
            {"script": virtualchain.make_payment_script(payment_addr),
             "value": satoshis}
        ]
        # everything else is a tx fee

    prev_outputs = [{'out_script': inp['out_script'], 'value': inp['value']} for inp in inputs]

    serialized_tx = serialize_tx(inputs, outputs)
    signed_tx = virtualchain.tx_sign_all_unsigned_inputs(privkey, prev_outputs, serialized_tx)
    return signed_tx


def send_funds( privkey, satoshis, payment_addr, change=True ):
    """
    Send funds from a private key (in satoshis) to an address
    """
    signed_tx = send_funds_tx(privkey, satoshis, payment_addr, change=change)
    txid = sendrawtransaction(signed_tx)
    return {'txid': txid}


def broadcast_transaction(txhex):
    txid = sendrawtransaction(txhex)
    return {'tx_hash': txid}


def sendrawtransaction( tx_hex, **kw ):
    """
    Send a raw transaction to the regtest bitcoind
    """
    bitcoind = connect_bitcoind()
    return bitcoind.sendrawtransaction( tx_hex )


def getrawtransaction( txid, verbose, **kw ):
    """
    Get a raw transaction from the regtest bitcoind
    """
    bitcoind = connect_bitcoind()
    return bitcoind.getrawtransaction( txid, verbose )


def getbalance( addr, **kw ):
    """
    Get the balance of an address
    """
    bitcoind = connect_bitcoind()
    return bitcoind.getbalance( addr )


def check_account_debits(state_engine, api_call_history):
    """
    Verify that each account has been debited the appropriate amount.
    """
    # don't do this if we're running in interactive mode, and the test is over
    if not is_test_running():
        return True
    
    addrs = state_engine.get_all_account_addresses()
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


def check_account_credits(state_engine, api_call_history):
    """
    Verify that each account has been credited the appropriate amount.
    """
    # don't do this if we're running in interactive mode, and the test is over
    if not is_test_running():
        return True
    
    addrs = state_engine.get_all_account_addresses()
    token_types = filter(lambda tt: tt != 'BTC',
                         list(set([api_call.token_record.token_type for api_call in filter(lambda ac: ac.token_record is not None, api_call_history)])))

    # tokens received from all prior blocks from TokenTransfer
    block_credits = dict([
        (addr, dict([
            (token_type, sum([api_call.token_record.token_cost for api_call in
                filter(lambda ac: ac.success and isinstance(ac.token_record, TokenTransfer) and ac.token_record.recipient_addr == addr and ac.token_record.token_type == token_type, api_call_history)]))
            for token_type in token_types]))
        for addr in addrs])

    # tokens given at genesis
    genesis_tokens = dict([
        (addr, dict([
            (token_type, sum([blk['value'] for blk in filter(lambda g: g['address'] == addr and g['type'] == token_type, state_engine.genesis_block['rows'])]))
            for token_type in token_types]))
        for addr in addrs])

    # tokens received through vesting
    vesting_schedules = dict([
        (addr, dict([
            (token_type, [blk['vesting'] for blk in filter(lambda g: g['address'] == addr and g['type'] == token_type, state_engine.genesis_block['rows'])])
            for token_type in token_types]))
        for addr in addrs])

    log.debug("Vesting schedule = \n{}".format(vesting_schedules))

    vested_tokens = {}
    for addr in addrs:
        vested_tokens[addr] = {}
        for token_type in token_types:
            vested_tokens[addr][token_type] = 0
            vested_token_sum = 0

            assert len(vesting_schedules[addr][token_type]) <= 1, vesting_schedules[addr]
            if len(vesting_schedules[addr][token_type]) == 0:
                continue

            vest_token_blocks = vesting_schedules[addr][token_type][0]

            for block_height_key in vest_token_blocks:
                block_height = int(block_height_key)
                amount = vest_token_blocks[block_height_key]
                
                if block_height > state_engine.lastblock+1:
                    continue
                
                print >> sys.stderr, '{} receives {} {} at {}'.format(addr, amount, token_type, block_height)
                vested_token_sum += amount

            vested_tokens[addr][token_type] = vested_token_sum

    # total expected tokens
    expected_credits = dict([
        (addr, dict([
            (token_type, genesis_tokens[addr][token_type] + vested_tokens[addr][token_type] + block_credits[addr][token_type])
            for token_type in token_types]))
        for addr in addrs])

    # accounts from the db
    accounts = dict([
        (addr, dict([
            (token_type, 0 if state_engine.get_account(addr, token_type) is None else state_engine.get_account(addr, token_type)['credit_value'])
            for token_type in token_types]))
        for addr in addrs])

    log.debug("account credits = \n{}".format(json.dumps(accounts, indent=4, sort_keys=True)))
    log.debug("vested credits = \n{}".format(json.dumps(vested_tokens, indent=4, sort_keys=True)))
    log.debug("expected credits =\n{}".format(json.dumps(expected_credits, indent=4, sort_keys=True)))

    for addr in addrs:
        for token_type in token_types:
            if accounts[addr][token_type] != expected_credits[addr][token_type]:
                log.error("mismatch: {}'s {}: {} != {}".format(addr, token_type, accounts[addr][token_type], expected_credits[addr][token_type]))
                return False

    return True


def check_account_vesting(state_engine):
    """
    Verify that each account has been credited the appropriate amount
    according to its vesting schedule
    """
    global wallets

    # don't do this if we're running in interactive mode, and the test is over
    if not is_test_running():
        return True
     
    vesting_schedules = dict([(wallet.addr, wallet._vesting_schedule) for wallet in wallets])
    account_states = dict([(wallet.addr, state_engine.get_account_at(wallet.addr, state_engine.lastblock+1)) for wallet in wallets])
    account_states_prior = dict([(wallet.addr, state_engine.get_account_at(wallet.addr, state_engine.lastblock)) for wallet in wallets])
    
    for addr in account_states:
        account_states[addr].sort(cmp=lambda a1, a2: -1 if a1['vtxindex'] < a2['vtxindex'] else 0 if a1['vtxindex'] == a2['vtxindex'] else 1)

    for addr in account_states_prior:
        account_states_prior[addr].sort(cmp=lambda a1, a2: -1 if a1['vtxindex'] < a2['vtxindex'] else 0 if a1['vtxindex'] == a2['vtxindex'] else 1)

    all_vestings = []
    for addr in [wallet.addr for wallet in wallets]:
        present = {}
        for token_type in vesting_schedules[addr]:
            if state_engine.lastblock+1 not in vesting_schedules[addr][token_type]:
                continue

            present[addr] = {token_type: vesting_schedules[addr][token_type]}

        if len(present) > 0:
            all_vestings.append(present)

    if len(all_vestings) > 0:
        log.debug("Expected vestings at {}:\n{}".format(state_engine.lastblock+1, json.dumps(all_vestings, indent=4, sort_keys=True)))

    for addr in [wallet.addr for wallet in wallets]:
        for token_type in vesting_schedules[addr]:
            if state_engine.lastblock+1 not in vesting_schedules[addr][token_type]:
                continue

            expected_vesting = vesting_schedules[addr][token_type][state_engine.lastblock+1]
           
            # select account states by token type
            account_token_states = filter(lambda a: a['type'] == token_type, account_states[addr])
            account_token_states_prior = filter(lambda a: a['type'] == token_type, account_states_prior[addr])

            # the state-transition at vtxindex == 0 on the account should have bumped the 'credit_value' by the vesting amount 
            if len(account_token_states) == 0:
                log.error("No account states for {} on token type {} at {}".format(addr, token_type, state_engine.lastblock+1))
                return False

            if len(account_token_states_prior) == 0:
                raise Exception("BUG: could not query account state of {}".format(addr))

            if account_token_states[0]['vtxindex'] != 0:
                raise Exception("BUG: first account state of {} at {} is not at vtxindex 0".format(addr, state_engine.lastblock+1))

            if account_token_states_prior[-1]['credit_value'] + expected_vesting != account_token_states[0]['credit_value']:
                log.error("Account {} changed from {} to {} at {}: expected {}".format(addr, account_token_states_prior[-1]['credit_value'], account_token_states[0]['credit_value'], state_engine.lastblock+1, expected_vesting))
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
    if AUDIT_ACCOUNTS:
        assert check_account_debits(state_engine, api_call_history), "Account debit mismatch"
        assert check_account_credits(state_engine, api_call_history), "Account credit mismatch"
        assert check_account_vesting(state_engine), 'Account vesting error'


def set_account_audits(value):
    global AUDIT_ACCOUNTS
    AUDIT_ACCOUNTS = value

   
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

        valid = blockstack_verify_database(expected_consensus_hash, block_id, untrusted_working_db_dir, working_db_dir, start_block=block_ids[0])
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
            if final_name_states[name] is None:
                log.error("No final name states for {}".format(name))
                return False

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
                            log.warning('{} != {}, so {} must be in the same block'.format(old_name_rec['name'], name, block_id))
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
    print '\nbegin auditing the subdomain db\n'

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

        did_info = blockstack.lib.util.parse_DID(subd_did)
        assert did_info['name_type'] == 'subdomain'
        assert virtualchain.address_reencode(did_info['address']) == virtualchain.address_reencode(addr), 'address mismatch on {}: {} (expected {})\nsubrec: {}'.format(subd, did_info['address'], addr, subrec)

        subrec_did = blockstack.lib.client.get_DID_record(subd_did, hostport='localhost:{}'.format(blockstack.lib.config.RPC_SERVER_PORT))
        assert subrec_did
        assert 'error' not in subrec_did, subrec_did

        for rec_name in subrec_did:
            assert rec_name in subrec and subrec[rec_name] == subrec_did[rec_name], 'At ({}, {}): Did not resolve to {}, but instead to {}'.format(subd, addr, subrec, subrec_did)

    # make sure we can get all historic states of each subdomain 
    for subd in all_subdomains:
        p = subprocess.Popen('sqlite3 "{}" \'select txid,accepted from subdomain_records where fully_qualified_subdomain = "{}" order by parent_zonefile_index, zonefile_offset\''
                .format(blockstack_opts['subdomaindb_path'], subd), shell=True, stdout=subprocess.PIPE)

        all_txids_and_accepted, _ = p.communicate()

        all_txids_and_accepted = all_txids_and_accepted.strip().split('\n')
        all_txids_and_accepted = [tuple(ataa.strip().split('|')) for ataa in all_txids_and_accepted]

        assert len(all_txids_and_accepted) > 0, 'no subdomain rows for {}'.format(subd)

        for txid_and_accepted in all_txids_and_accepted:
            txid = txid_and_accepted[0]
            accepted = txid_and_accepted[1]

            res = requests.get('http://localhost:16268/v1/subdomains/{}'.format(txid))
            items = res.json()
            zfh = None
            
            for (i, subdomain_op) in enumerate(items):
                assert subdomain_op['txid'] == txid, subdomain_op
                assert subdomain_op['zonefile_offset'] >= i, subdomain_op
                assert subdomain_op['accepted'] == int(accepted), subdomain_op

                if zfh is None:
                    zfh = subdomain_op['parent_zonefile_hash']

                assert zfh == subdomain_op['parent_zonefile_hash'], subdomain_op

        
    print '\nend auditing the subdomain db\n'

    return True


def decoderawtransaction( tx_hex ):
    """
    Decode a raw transaction 
    """
    bitcoind = connect_bitcoind()
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
    blockstack_conf['server_version'] = '0.19.0'
    blockstack_conf['zonefiles'] = os.path.join( dirp, 'zonefiles' )
    blockstack_conf['atlas_seeds'] = ",".join( ["localhost:%s" % p for p in seed_relations.get(peer_port, []) ] )
    blockstack_conf['atlas_blacklist'] = ",".join( ["localhost:%s" % p for p in blacklist_relations.get(peer_port, [])] )
    blockstack_conf['atlasdb_path'] = os.path.join( dirp, 'atlas.db' )
    blockstack_conf['atlas_hostname'] = 'localhost'
    blockstack_conf['atlas_port'] = peer_port
    blockstack_conf['enabled'] = True

    bitcoin_conf = {}
    for key in virtualchain_bitcoin_conf.keys():
        if key.startswith("bitcoind_"):
            newkey = key[len('bitcoind_'):]
            bitcoin_conf[newkey] = virtualchain_bitcoin_conf[key]

    conf = {
        'bitcoind': bitcoin_conf,
        'blockstack': blockstack_conf,
        'blockstack-api': {'enabled': False},
    }

    conf_path = os.path.join( dirp, 'blockstack-server.ini' )
    log.debug("Save server config for localhost:%s to %s" % (peer_port, conf_path))

    if not os.path.exists(dirp):
        os.makedirs(dirp)

    blockstack.lib.config.write_config_file( conf, conf_path )

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

    BlockstackDB.get_readwrite_instance(working_dir).close()

    # preserve test environment variables
    for envar in os.environ.keys():
        if envar.startswith("BLOCKSTACK_") and envar not in ['BLOCKSTACK_SERVER_CONFIG']:
            log.debug("Env: '%s' = '%s'" % (envar, os.environ[envar]))
            env[envar] = os.environ[envar]

    env['BLOCKSTACK_ATLAS_NETWORK_SIMULATION'] = "1"
    env['BLOCKSTACK_ATLAS_NETWORK_SIMULATION_PEER'] = "1"
    env['BLOCKSTACK_SERVER_CONFIG'] = os.path.join(working_dir, 'blockstack-server.ini')

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
        peer_inv = blockstack.lib.util.atlas_inventory_to_string( base64.b64decode(peer_inv_info['inv']) )
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
    Return {'working_dir': ...} on success
    Return {'error': ...} on error 
    """
    # set up a new peer
    peer_wd = peer_working_dir(base_working_dir, index)
    peer_config_dir = os.path.join(peer_wd, 'client')

    os.makedirs(peer_wd)
    os.makedirs(peer_config_dir)

    res = peer_make_config(peer_working_dir, 16300 + index, peer_wd)
    if 'error' in res:
        print "failed to set up {}".format(peer_wd)
        return {'error': 'failed to set up config dir'}

    return {'working_dir': peer_wd}


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


def get_wallet_balances(wallets):
    """
    Get the balances of all tokens for a list of walelts
    """
    if not isinstance(wallets, list):
        wallets = [wallets]

    balances = {}
    for w in wallets:
       balance_info = json.loads(nodejs_cli('balance', w.addr))
       for token_type in balance_info:
           balance_info[token_type] = int(balance_info[token_type])

       balances[w.addr] = balance_info

    return balances


def get_addr_balances(addrs):
    """
    Get the balances of all tokens for a list of walelts
    """
    if not isinstance(addrs, list):
        addrs = [addrs]

    balances = {}
    for addr in addrs:
       balance_info = json.loads(nodejs_cli('balance', addr))
       for token_type in balance_info:
           balance_info[token_type] = int(balance_info[token_type])

       balances[addr] = balance_info

    return balances


def add_cleanup(m):
    """
    A poor man's atexit.register
    """
    global CLEANUP_METHODS
    CLEANUP_METHODS.append(m)

def cleanup():
    global CLEANUP_METHODS

    print 'testlib cleanup'
    for cleanup_method in CLEANUP_METHODS:
        cleanup_method()

