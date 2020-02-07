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

import testlib
import virtualchain
import json
import simplejson
import blockstack_client

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

debug = False
consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
small_unspents = []

def check_utxo_consumption( name_or_ns, payment_wallet, owner_wallet, data_wallet, operations, recipient_address, **kw):

    global small_unspents

    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", payment_wallet.privkey, owner_wallet.privkey, data_wallet.privkey )
    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )
    
    # estimate the fee for the operation sequence
    fees = testlib.blockstack_cli_price(name_or_ns, "0123456789abcdef", recipient_address=recipient_address, operations=operations)
    if 'error' in fees:
        return fees

    print "without UTXOs:"
    print simplejson.dumps(fees, indent=4, sort_keys=True)

    # make a few small UTXOs for the payment address 
    # count up the number of UTXOs that exist for this payment address
    payment_utxos = testlib.get_utxos(payment_wallet.addr)
    expected_utxo_count = len(payment_utxos)
    for i in xrange(0, 1):
        senders = wallets
        for sender in senders:
            if sender.privkey == payment_wallet.privkey:
                continue

            res = testlib.send_funds( sender.privkey, 10000, payment_wallet.addr )
            if 'error' in res:
                print simplejson.dumps(res, indent=4, sort_keys=True)
                return res

            expected_utxo_count += 1
            small_unspents.append(res['transaction_hash'])

        testlib.next_block(**kw)

    # estimate the fee with all the UTXOs
    fees_utxos = testlib.blockstack_cli_price(name_or_ns, "0123456789abcdef", recipient_address=recipient_address, operations=operations)
    if 'error' in fees_utxos:
        return fees_utxos

    print "with UTXOs:"
    print simplejson.dumps(fees_utxos, indent=4, sort_keys=True)
   
    # all our operations should have similar fees, regardless of the UTXO set
    for tx_fee_key in ['{}_tx_fee'.format(op) for op in operations]:
        fee_diff = abs(fees[tx_fee_key]['satoshis'] - fees_utxos[tx_fee_key]['satoshis'])
        if fee_diff > 9000:
            print 'tx fees for {} disagree by {}'.format(tx_fee_key, fee_diff)
            return {'error': 'No appreciable fee change'}

    return {'status': True, 'expected_utxo_count': expected_utxo_count}


def spent_small_transaction(txhash):
    """
    Did we spend a "small" tx by mistake?
    """

    # verify that all the small UTXOs are NOT consumed
    bitcoind = testlib.connect_bitcoind()
    bitcoind.ping()

    txdata = bitcoind.getrawtransaction(txhash, 1)
    for vin in txdata['vin']:
        input_tx = bitcoind.getrawtransaction(vin['txid'], 1)
        consumed_out = input_tx['vout'][vin['vout']]
        if consumed_out['value'] <= 0.00010001 and consumed_out['value'] >= 0.00009999:
            print '\n{} spent small UTXO {}\n{}'.format(txhash, vin['txid'], simplejson.dumps(bitcoind.getrawtransaction(vin['txid'], 1), indent=4, sort_keys=True))
            return True

    return False


def scenario( wallets, **kw ):

    global debug, consensus, small_unspents
    
    res = check_utxo_consumption("test", wallets[0], wallets[1], wallets[2], ['namespace_preorder', 'namespace_reveal', 'namespace_ready'], wallets[1].addr, **kw)
    if 'error' in res:
        return False

    expected_utxo_count = res['expected_utxo_count']

    # do the preorder
    resp = testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    if debug or 'error' in resp:
        print simplejson.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # verify that all the small UTXOs are NOT consumed
    bitcoind = testlib.connect_bitcoind()
    bitcoind.ping()

    txdata = bitcoind.getrawtransaction(resp['transaction_hash'], 1)
    if len(txdata['vin']) != 1:
        print simplejson.dumps(txdata, indent=4)
        print "wrong number of inputs: {} != 1".format(len(txdata['vin']))
        return False

    if spent_small_transaction(resp['transaction_hash']):
        return False

    # finish ordering the namespace
    resp = testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    if debug or 'error' in resp:
        print simplejson.dumps( resp, indent=4 )

    if spent_small_transaction(resp['transaction_hash']):
        return False

    testlib.next_block( **kw )

    resp = testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    if debug or 'error' in resp:
        print simplejson.dumps( resp, indent=4 )

    if spent_small_transaction(resp['transaction_hash']):
        return False

    testlib.next_block( **kw )
 
    res = check_utxo_consumption("foo.test", wallets[2], wallets[3], wallets[4], ['preorder', 'register', 'update', 'transfer'], wallets[4].addr, **kw)
    if 'error' in res:
        return False

    expected_utxo_count = res['expected_utxo_count']

    resp = testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    if debug or 'error' in resp:
        print simplejson.dumps( resp, indent=4 )

    if spent_small_transaction(resp['transaction_hash']):
        return False

    testlib.next_block( **kw )

    # verify that all the small UTXOs are NOT consumed
    bitcoind = testlib.connect_bitcoind()
    bitcoind.ping()

    txdata = bitcoind.getrawtransaction(resp['transaction_hash'], 1)
    if len(txdata['vin']) != 1:
        print simplejson.dumps(txdata, indent=4)
        print "wrong number of inputs: {} != {}".format(len(txdata['vin']), expected_utxo_count)
        return False

    # proceed to register
    resp = testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    if debug or 'error' in resp:
        print simplejson.dumps( resp, indent=4 )

    if spent_small_transaction(resp['transaction_hash']):
        return False

    testlib.next_block( **kw )

    # verify that all the UTXOs are consumed
    bitcoind = testlib.connect_bitcoind()
    bitcoind.ping()

    txdata = bitcoind.getrawtransaction(resp['transaction_hash'], 1)
    if len(txdata['vin']) != 1:
        print simplejson.dumps(txdata, indent=4)
        print "wrong number of inputs: {} != {}".format(len(txdata['vin']), expected_utxo_count)
        return False

    # make a few small UTXOs for the preorder payment addr
    for i in xrange(0, 3):
        res = testlib.send_funds( wallets[1].privkey, 10000, testlib.get_default_payment_wallet().addr)
        if 'error' in res:
            print simplejson.dumps(res, indent=4, sort_keys=True)
            return False

        testlib.next_block(**kw)
        small_unspents.append(res['transaction_hash'])

    utxos = testlib.get_utxos(testlib.get_default_payment_wallet().addr)
    assert len(utxos) > 3

    resp = testlib.blockstack_name_update( "foo.test", "11" * 20, wallets[3].privkey )
    if debug or 'error' in resp:
        print simplejson.dumps( resp, indent=4 )

    if spent_small_transaction(resp['transaction_hash']):
        return False

    consensus = testlib.get_consensus_at( testlib.get_current_block(**kw), **kw)
    testlib.next_block( **kw )

    # inspect the transaction: only 3 UTXOs should have been consumed (2 owner UTXOs and 1 payment UTXO)
    txdata = testlib.connect_bitcoind().getrawtransaction(resp['transaction_hash'], 1)
    if len(txdata['vin']) != 3:
        print simplejson.dumps(txdata, indent=4)
        print "too many inputs"
        return False

    # make a few more small UTXOs for the preorder payment addr
    for i in xrange(0, 3):
        res = testlib.send_funds( wallets[1].privkey, 10000, testlib.get_default_payment_wallet().addr )
        if 'error' in res:
            print simplejson.dumps(res, indent=4, sort_keys=True)
            return False

        testlib.next_block(**kw)
        small_unspents.append(res['transaction_hash'])

    utxos = testlib.get_utxos(testlib.get_default_payment_wallet().addr)
    assert len(utxos) > 3

    resp = testlib.blockstack_name_transfer( "foo.test", wallets[4].addr, True, wallets[3].privkey ) 
    if debug or 'error' in resp:
        print simplejson.dumps( resp, indent=4 )

    # inspect the transaction: only 2 UTXOs should have been consumed (1 owner UTXO and 1 payment UTXO)
    txdata = testlib.connect_bitcoind().getrawtransaction(resp['transaction_hash'], 1)
    if len(txdata['vin']) != 2:
        print simplejson.dumps(txdata, indent=4)
        print "too many inputs"
        return False

    if spent_small_transaction(resp['transaction_hash']):
        return False

    testlib.next_block( **kw )
   
    # make a few more small UTXOs for the preorder payment addr
    for i in xrange(0, 3):
        res = testlib.send_funds( wallets[1].privkey, 10000, testlib.get_default_payment_wallet().addr )
        if 'error' in res:
            print simplejson.dumps(res, indent=4, sort_keys=True)
            return False

        testlib.next_block(**kw)
        small_unspents.append(res['transaction_hash'])

    utxos = testlib.get_utxos(testlib.get_default_payment_wallet().addr)
    assert len(utxos) > 3

    resp = testlib.blockstack_name_renew( "foo.test", wallets[4].privkey )
    if debug or 'error' in resp:
        print simplejson.dumps( resp, indent=4 )

    # inspect the transaction: only 3 UTXOs should have been consumed (2 owner UTXO and 1 payment UTXO)
    # NOTE: produces two UTXOs: an "owner" utxo and the change for the owner address
    txdata = testlib.connect_bitcoind().getrawtransaction(resp['transaction_hash'], 1)
    if len(txdata['vin']) != 3:
        print simplejson.dumps(txdata, indent=4)
        print "too many inputs"
        return False

    if spent_small_transaction(resp['transaction_hash']):
        return False

    testlib.next_block( **kw )

    # make a few more small UTXOs for the preorder payment addr
    for i in xrange(0, 3):
        res = testlib.send_funds( wallets[1].privkey, 10000, testlib.get_default_payment_wallet().addr )
        if 'error' in res:
            print simplejson.dumps(res, indent=4, sort_keys=True)
            return False

        testlib.next_block(**kw)
        small_unspents.append(res['transaction_hash'])

    utxos = testlib.get_utxos(testlib.get_default_payment_wallet().addr)
    assert len(utxos) > 3

    resp = testlib.blockstack_name_revoke( "foo.test", wallets[4].privkey )
    if debug or 'error' in resp:
        print simplejson.dumps( resp, indent=4 )

    # inspect the transaction: only 3 UTXOs should have been consumed (2 owner UTXO and 1 payment UTXO)
    txdata = testlib.connect_bitcoind().getrawtransaction(resp['transaction_hash'], 1)
    if len(txdata['vin']) != 3:
        print simplejson.dumps(txdata, indent=4)
        print "too many inputs"
        return False

    if spent_small_transaction(resp['transaction_hash']):
        return False

    testlib.next_block( **kw )
    '''
    # all unspents should be unspent 
    all_unspents = testlib.connect_bitcoind().listunspent()
    all_unspent_txids = [u['txid'] for u in all_unspents]
    valid = True
    for i in xrange(0, len(small_unspents)):
        unspent_txid = small_unspents[i]
        if unspent_txid not in all_unspent_txids:
            print "Spent small transaction {}: {}".format(i, unspent_txid)
            valid = False
    '''
    

def check( state_engine ):

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is not None:
        print "'test' not revealed"
        return False 

    ns = state_engine.get_namespace( "test" )
    if ns is None:
        print "'test' not found"
        return False 

    if ns['namespace_id'] != 'test':
        print "'test' not returned"
        return False 

    # not preordered
    preorder = state_engine.get_name_preorder( "foo.test", virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr )
    if preorder is not None:
        print "'foo.test' still preordered"
        return False
    
    # registered 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        print "'foo.test' not registered"
        return False 

    # updated, but revoked
    if name_rec['value_hash'] is not None:
        print "'foo.test' invalid value hash"
        return False 

    # transferred 
    if name_rec['address'] != wallets[4].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[4].addr):
        print "'foo.test' invalid owner"
        return False 

    # QUIRK: consensus is from NAME_UPDATE 
    if name_rec['consensus_hash'] != consensus:
        print "quirk not preserved: current consensus %s != %s" % (name_rec['consensus_hash'], consensus)
        return False

    # revoked 
    if not name_rec['revoked']:
        print 'Name is not revoked'
        return False

    return True
