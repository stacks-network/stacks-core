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
import blockstack
import json

# activate tokens
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 682
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 683
TEST ENV BLOCKSTACK_EPOCH_3_END_BLOCK 684
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 1
"""

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet("9864768ccf5137392de5b5d6551a0f9f17279df2f82b4de7b905290f95fde66201", 0),
    testlib.Wallet("2e55007fec0f1d9a81700e56aa8ce24d7e6e245ede48c00663f930f99fae133601", 0),
    testlib.Wallet("9d6836cdaf81245d646988effe398338073892143b1185f4553e6118f231d1bf01", 0),
    testlib.Wallet("f9c9371b7a8cc6b5ef544457cdd565e5791d743f5d60c924265732147429414801", 0),
    testlib.Wallet("cd8d6bdf3dfd7b3d498539bb42cf218b77b0fda4f3bc119c7226d803e8425da901", 0), 
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
pk = wallets[-1].privkey

def scenario( wallets, **kw ):
    global pk

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,6,6,6,6,6,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    # pay for a name in a v1 namespace with Stacks
    addr = virtualchain.address_reencode(virtualchain.get_privkey_address(pk))

    # calculate the cost of doing so
    namespace = testlib.get_state_engine().get_namespace('test')
    stacks_price = blockstack.lib.scripts.price_name_stacks('foo', namespace, testlib.get_current_block(**kw))
    btc_price = blockstack.lib.scripts.price_name('foo', namespace, testlib.get_current_block(**kw))

    print ''
    print 'price of {} in Stacks is {}'.format('foo.test', stacks_price)
    print ''

    testlib.blockstack_send_tokens(addr, "STACKS", stacks_price * 4, wallets[0].privkey)
    testlib.send_funds(wallets[0].privkey, btc_price * 10, addr)    # fund with enough bitcoin
    testlib.next_block(**kw)

    # preorder/register using Stacks---Stacks should still be used since that's what the transaction indicates
    testlib.blockstack_name_preorder( "foo.test", pk, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price})
    testlib.next_block( **kw )

    testlib.send_funds(wallets[0].privkey, btc_price * 10, addr)
    testlib.blockstack_name_register( "foo.test", pk, wallets[3].addr )
    testlib.next_block( **kw )

    # preorder/register using Bitcoin--Stacks should NOT be used since that's what the transaction indicates
    testlib.blockstack_name_preorder("bar.test", pk, wallets[3].addr, price={'units': 'BTC', 'amount': btc_price})
    testlib.next_block(**kw)

    testlib.blockstack_name_register('bar.test', pk, wallets[3].addr)
    testlib.next_block(**kw)

    balance_before = testlib.get_addr_balances(addr)[addr]['STACKS']

    # pay with Stacks and Bitcoin.  Preorder should succeed, and register should also succeed since we're paying enough stacks.  Underpay bitcoin
    res = testlib.blockstack_name_preorder('baz.test', pk, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price}, tx_only=True, expect_success=True)
    txhex = res['transaction']
    tx = virtualchain.btc_tx_deserialize(txhex)

    # up the burn amount 
    btc_price = blockstack.lib.scripts.price_name('baz', namespace, testlib.get_current_block(**kw))
    tx['outs'][2]['script'] = virtualchain.btc_make_payment_script(blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS)
    tx['outs'][2]['value'] = btc_price - 1

    tx['outs'][1]['value'] -= btc_price - 1

    # re-sign 
    for i in tx['ins']:
        i['script'] = ''

    txhex = virtualchain.btc_tx_serialize(tx)
    txhex_signed = virtualchain.tx_sign_all_unsigned_inputs(pk, testlib.get_utxos(addr), txhex)
    
    print txhex_signed

    res = testlib.broadcast_transaction(txhex_signed)
    if 'error' in res:
        print res
        return False

    testlib.next_block(**kw)

    # should have paid in Stacks
    balance_after = testlib.get_addr_balances(addr)[addr]['STACKS']
    if balance_after != balance_before - stacks_price:
        print 'baz.test cost {}'.format(balance_before - balance_after)
        return False

    # should succeed, since we paid enough stacks (Bitcoin is not considered)
    testlib.blockstack_name_register('baz.test', pk, wallets[3].addr)
    testlib.next_block(**kw)

    balance_before = testlib.get_addr_balances(addr)[addr]['STACKS']

    # register a name where we pay not enough stacks, but enough bitcoin.  preorder should succeed, but register should fail since we tried to use stacks
    res = testlib.blockstack_name_preorder('goo.test', pk, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price-1}, tx_only=True, expect_success=True)
    txhex = res['transaction']
    tx = virtualchain.btc_tx_deserialize(txhex)

    # up the burn amount to the name price
    btc_price = blockstack.lib.scripts.price_name('goo', namespace, testlib.get_current_block(**kw))
    tx['outs'][2]['script'] = virtualchain.btc_make_payment_script(blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS)
    tx['outs'][2]['value'] = btc_price

    tx['outs'][1]['value'] -= btc_price

    # re-sign 
    for i in tx['ins']:
        i['script'] = ''

    txhex = virtualchain.btc_tx_serialize(tx)
    txhex_signed = virtualchain.tx_sign_all_unsigned_inputs(pk, testlib.get_utxos(addr), txhex)
    
    print txhex_signed

    res = testlib.broadcast_transaction(txhex_signed)
    if 'error' in res:
        print res
        return False

    testlib.next_block(**kw)

    # should have paid in Stacks
    balance_after = testlib.get_addr_balances(addr)[addr]['STACKS']
    if balance_after != balance_before - stacks_price + 1:
        print 'goo.test paid {}'.format(balance_before - balance_after)
        return False

    # should fail, since we tried to pay in stacks and didn't pay enough
    testlib.blockstack_name_register('goo.test', pk, wallets[3].addr)
    testlib.next_block(**kw)
    testlib.expect_snv_fail_at('goo.test', testlib.get_current_block(**kw))

    if testlib.get_state_engine().get_name('goo.test') is not None:
        print 'registered goo.test'
        return False

    balance_before = testlib.get_addr_balances(addr)[addr]['STACKS']

    # underpay in both Stacks and Bitcoin.
    # both stacks and bitcoin will be burned.
    # preorder should succeed, but register should fail.
    res = testlib.blockstack_name_preorder('nop.test', pk, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price-1}, safety_checks=False, tx_only=True, expect_success=True)
    txhex = res['transaction']
    tx = virtualchain.btc_tx_deserialize(txhex)

    # up the burn amount to the name price, but just under
    btc_price = blockstack.lib.scripts.price_name('nop', namespace, testlib.get_current_block(**kw))
    tx['outs'][2]['script'] = virtualchain.btc_make_payment_script(blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS)
    tx['outs'][2]['value'] = btc_price - 1

    tx['outs'][1]['value'] -= btc_price - 1

    # re-sign 
    for i in tx['ins']:
        i['script'] = ''

    txhex = virtualchain.btc_tx_serialize(tx)
    txhex_signed = virtualchain.tx_sign_all_unsigned_inputs(pk, testlib.get_utxos(addr), txhex)
    
    print txhex_signed

    res = testlib.broadcast_transaction(txhex_signed)
    if 'error' in res:
        print res
        return False

    testlib.next_block(**kw)

    # should fail, since we didn't pay enough stacks and tried to pay in stacks 
    res = testlib.blockstack_name_register('nop.test', pk, wallets[3].addr)
    testlib.next_block(**kw)
    testlib.expect_snv_fail_at('nop.test', testlib.get_current_block(**kw))

    # preorder should still have debited
    balance_after = testlib.get_addr_balances(addr)[addr]['STACKS']
    if balance_after != balance_before - stacks_price + 1:
        print 'paid {} for nop.test'.format(balance_before - balance_after)
        return False


def check( state_engine ):

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is not None:
        print "namespace reveal exists"
        return False 

    ns = state_engine.get_namespace( "test" )
    if ns is None:
        print "no namespace"
        return False 

    if ns['namespace_id'] != 'test':
        print "wrong namespace"
        return False

    # should not exist
    name_rec = state_engine.get_name('nop.test')
    if name_rec is not None:
        print 'registered nop.test'
        return False

    # preorder should exist
    addr = virtualchain.address_reencode(virtualchain.get_privkey_address(pk))
    preorder_rec = state_engine.get_name_preorder('nop.test', virtualchain.make_payment_script(addr), wallets[3].addr)
    if preorder_rec is None:
        print 'preorder does not exist for nop.test'
        return False

    if preorder_rec['op_fee'] != blockstack.lib.scripts.price_name('nop', ns, state_engine.lastblock) - 1:
        print 'wrong BTC paid for {}'.format('nop.test')
        print 'expected {}, got {}'.format(blockstack.lib.scripts.price_name('nop', ns, state_engine.lastblock) - 1, preorder_rec['op_fee'])
        return False

    if preorder_rec['token_fee'] != blockstack.lib.scripts.price_name_stacks('nop', ns, state_engine.lastblock) - 1:
        print 'wrong Stacks paid for {}'.format('nop.test')
        return False

    for name in ['foo.test', 'bar.test', 'baz.test']:
        # not preordered
        preorder = state_engine.get_name_preorder( name, virtualchain.make_payment_script(addr), wallets[3].addr )
        if preorder is not None:
            print "preorder exists"
            return False
        
        # registered 
        name_rec = state_engine.get_name( name )
        if name_rec is None:
            print "name does not exist"
            return False 

        # owned by
        if name_rec['address'] != wallets[3].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[3].addr):
            print "sender is wrong"
            return False 

        stacks_price = blockstack.lib.scripts.price_name_stacks(name.split('.')[0], ns, state_engine.lastblock)
        btc_price = blockstack.lib.scripts.price_name(name.split('.')[0], ns, state_engine.lastblock)

        if name == 'foo.test':
            # should have paid all in Stacks
            if name_rec['op_fee'] > 5500:
                print 'paid for foo.test in BTC'
                return False

            if name_rec['token_fee'] != stacks_price:
                print 'did not pay token fee for foo.test'
                return False

        if name == 'bar.test':
            # should have paid all in BTC
            if name_rec['op_fee'] != btc_price:
                print 'paid for bar.test in wrong BTC amount'
                return False

            if name_rec['token_fee'] != 0:
                print 'paid for bar.test in tokens'
                return False


        if name == 'baz.test':
            # should have paid all in Stacks, and also burned bitcoin
            if name_rec['op_fee'] != btc_price - 1:
                print 'paid for baz.test in wrong BTC amount'
                return False

            if name_rec['token_fee'] != stacks_price:
                print 'paid for baz.test in wrong Token amount'
                return False


    for name in ['goo.test']:
        # preordered still 
        preorder = state_engine.get_name_preorder(name, virtualchain.make_payment_script(addr), wallets[3].addr)
        if preorder is None:
            print 'not preordered: {}'.format(name)
            return False

        # not registered 
        name_rec = state_engine.get_name(name)
        if name_rec is not None:
            print 'name exists: {}'.format(name)
            return False

        stacks_price = blockstack.lib.scripts.price_name_stacks(name.split('.')[0], ns, state_engine.lastblock)
        btc_price = blockstack.lib.scripts.price_name(name.split('.')[0], ns, state_engine.lastblock)

        # preorder paid the right amount of Stacks and BTC
        if name == 'baz.test':
            if preorder['op_fee'] != btc_price - 1:
                print 'did not pay bitcoin for goo.test'
                return False

            if preorder['token_fee'] != stacks_price - 1:
                print 'did not pay stacks for goo.test'
                return False

    return True
