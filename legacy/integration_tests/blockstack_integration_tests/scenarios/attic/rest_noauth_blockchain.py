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
import os
import testlib
import virtualchain
import urllib2
import json
import blockstack_client
import blockstack_profiles
import sys
import keylib
import time
from keylib import ECPrivateKey, ECPublicKey

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet( "5K5hDuynZ6EQrZ4efrchCwy6DLhdsEzuJtTDAf3hqdsCKbxfoeD", 100000000000 ),
    testlib.Wallet( "5J39aXEeHh9LwfQ4Gy5Vieo7sbqiUMBXkPH7SaMHixJhSSBpAqz", 100000000000 ),
    testlib.Wallet( "5K9LmMQskQ9jP1p7dyieLDAeB6vsAj4GK8dmGNJAXS1qHDqnWhP", 100000000000 ),
    testlib.Wallet( "5KcNen67ERBuvz2f649t9F2o1ddTjC5pVUEqcMtbxNgHqgxG2gZ", 100000000000 ),
    testlib.Wallet( "5KMbNjgZt29V6VNbcAmebaUT2CZMxqSridtM46jv4NkKTP8DHdV", 100000000000 ),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
wallet_keys = None
wallet_keys_2 = None
error = False

index_file_data = "<html><head></head><body>foo.test hello world</body></html>"
resource_data = "hello world"
wallet_balance = None

def scenario( wallets, **kw ):

    global wallet_keys, wallet_keys_2, error, index_file_data, resource_data, wallet_balance

    wallet_keys = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[5].privkey, wallets[3].privkey, wallets[4].privkey )
    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_name_preorder( "foo.test", wallets[3].privkey, wallets[5].addr )
    testlib.next_block( **kw )
    
    register_resp = testlib.blockstack_name_register( "foo.test", wallets[3].privkey, wallets[5].addr )
    testlib.next_block( **kw )
    
    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    config_dir = os.path.dirname(config_path)
 
    conf = blockstack_client.get_config(config_path)
    assert conf

    api_pass = conf['api_password']

    # get utxos for the payer
    payer_utxos = testlib.blockstack_REST_call('GET', '/v1/blockchains/bitcoin/{}/unspent?min_confirmations=1'.format(wallets[3].addr), None, api_pass=api_pass)
    if 'error' in payer_utxos:
        payer_utxos['test'] = 'failed to get utxos'
        print json.dumps(payer_utxos)
        return False

    # have both the test wallet output and the one the NAME_REGISTRATION sent
    if len(payer_utxos['response']) != 1:
        payer_utxos['test'] = 'wrong utxos'
        print json.dumps(payer_utxos)
        return False

    # last transaction should be the register, and it should have been paid with the owner address (since that's how we sent it above)
    if payer_utxos['response'][0]['transaction_hash'] != register_resp['transaction_hash'] or payer_utxos['response'][0]['confirmations'] != 1:
        payer_utxos['test'] = 'invalid utxos (tx_hash, confirmations)'
        print json.dumps(payer_utxos)
        return False

    # get utxos for the owner wallet
    owner_utxos = testlib.blockstack_REST_call('GET', '/v1/blockchains/bitcoin/{}/unspent?min_confirmations=1'.format(wallets[5].addr), None, api_pass=api_pass)
    if 'error' in owner_utxos:
        owner_utxos['test'] = 'failed to get utxos'
        print json.dumps(owner_utxos)
        return False

    # two utxos: one for the initial wallet fill-up from the test framework, and one from the registration 
    if len(owner_utxos['response']) != 2:
        owner_utxos['test'] = 'wrong utxos'
        print json.dumps(owner_utxos)
        return False

    # last transaction should be the register
    found = False
    for utxo in owner_utxos['response']:
        if utxo['transaction_hash'] == register_resp['transaction_hash'] and utxo['confirmations'] == 1:
            found = True

    if not found:
        owner_utxos['test'] = 'invalid utxos (tx_hash, confirmations)'
        print json.dumps(owner_utxos)
        return False

    # verify that min_confirmations=2 hides these transactions
    res = testlib.blockstack_REST_call('GET', '/v1/blockchains/bitcoin/{}/unspent?min_confirmations=2'.format(wallets[5].addr), None, api_pass=api_pass)
    if 'error' in res:
        res['test'] = 'failed to get utxos'
        print json.dumps(res)
        return False

    if len(res['response']) > 1:
        res['test'] = 'got more UTXOs than we expected'
        print json.dumps(res)
        return False

    # count UTXOs in wallets[1]
    res = testlib.blockstack_REST_call('GET', '/v1/blockchains/bitcoin/{}/unspent?min_confirmations=0'.format(wallets[1].addr), None, api_pass=api_pass)
    if 'error' in res:
        res['test'] = 'failed to get utxos'
        print json.dumps(res)
        return False

    initial_utxos = res['response']
    if len(initial_utxos) == 0:
        res['test'] = 'test bug: no UTXOs for wallet'
        print json.dumps(res)
        return False

    # send money from one wallet to another
    fund_tx = testlib.send_funds_tx(wallets[0].privkey, 10**8, wallets[1].addr)
    res = testlib.blockstack_REST_call('POST', '/v1/blockchains/bitcoin/txs', None, data={'tx': fund_tx}, api_pass=api_pass)
    if 'error' in res:
        res['test'] = 'failed to send {}'.format(fund_tx)
        print json.dumps(res)
        return False

    if not res['response'].has_key('transaction_hash'):
        res['test'] = 'response is missing transaction hash'
        print json.dumps(res)
        return False

    # verify that it's in the UTXO set with min_confirmations=0
    res = testlib.blockstack_REST_call('GET', '/v1/blockchains/bitcoin/{}/unspent?min_confirmations=0'.format(wallets[1].addr), None, api_pass=api_pass)
    if 'error' in res:
        res['test'] = 'failed to get utxos'
        print json.dumps(res)
        return False

    if len(res['response']) != len(initial_utxos) + 1:
        res['test'] = 'missing UTXO'
        print json.dumps(res)
        return False

    current_utxos = res['response']

    # verify that with min_confirmations=1, we have what we started with
    res = testlib.blockstack_REST_call('GET', '/v1/blockchains/bitcoin/{}/unspent?min_confirmations=1'.format(wallets[1].addr), None, api_pass=api_pass)
    if 'error' in res:
        res['test'] = 'failed to get utxos'
        print json.dumps(res)
        return False

    if res['response'] != initial_utxos:
        res['test'] = 'initial utxos do not match current utxos'
        print json.dumps(res)
        print json.dumps(initial_utxos)
        return False

    # confirm everything
    for i in xrange(0, 10):
        testlib.next_block(**kw)
      
    # verify that we have what we started with
    res = testlib.blockstack_REST_call('GET', '/v1/blockchains/bitcoin/{}/unspent'.format(wallets[1].addr), None, api_pass=api_pass)
    if 'error' in res:
        res['test'] = 'failed to get utxos'
        print json.dumps(res)
        return False

    current_utxos_no_confirmation = [dict([(k, v) for (k, v) in filter(lambda (x, y): x != 'confirmations', utxo.items())]) for utxo in current_utxos]
    response_utxos_no_confirmation = [dict([(k, v) for (k, v) in filter(lambda (x, y): x != 'confirmations', utxo.items())]) for utxo in res['response']]

    current_utxos_no_confirmation.sort(lambda u1, u2: -1 if u1['transaction_hash'] < u2['transaction_hash'] else 0 if u1['transaction_hash'] == u2['transaction_hash'] else 1)
    response_utxos_no_confirmation.sort(lambda u1, u2: -1 if u1['transaction_hash'] < u2['transaction_hash'] else 0 if u1['transaction_hash'] == u2['transaction_hash'] else 1)

    if current_utxos_no_confirmation != response_utxos_no_confirmation:
        res['test'] = 'current utxos not confirmed'
        print json.dumps(res)
        print json.dumps(current_utxos)
        return False


def check( state_engine ):

    global wallet_keys, error, index_file_data, resource_data
    
    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG")
    assert config_path

    if error:
        print "Key operation failed."
        return False

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is not None:
        print "namespace not ready"
        return False 

    ns = state_engine.get_namespace( "test" )
    if ns is None:
        print "no namespace"
        return False 

    if ns['namespace_id'] != 'test':
        print "wrong namespace"
        return False 

    names = ['foo.test']
    wallet_keys_list = [wallet_keys]
    test_proxy = testlib.TestAPIProxy()

    for i in xrange(0, len(names)):
        name = names[i]
        wallet_payer = 3
        wallet_owner = 5
        wallet_data_pubkey = 4

        # not preordered
        preorder = state_engine.get_name_preorder( name, virtualchain.make_payment_script(wallets[wallet_payer].addr), wallets[wallet_owner].addr )
        if preorder is not None:
            print "still have preorder"
            return False
    
        # registered 
        name_rec = state_engine.get_name( name )
        if name_rec is None:
            print "name does not exist"
            return False 

        # owned 
        if name_rec['address'] != wallets[wallet_owner].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[wallet_owner].addr):
            print "name {} has wrong owner".format(name)
            return False 
    
    return True
