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
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_RECEIVE_FEES_PERIOD 5
TEST ENV BLOCKSTACK_EPOCH_4_NAMESPACE_RECEIVE_FEES_PERIOD 5
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
pk2 = wallets[-2].privkey

def scenario( wallets, **kw ):
    global pk, pk2

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,6,6,6,6,6,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=blockstack.lib.config.NAMESPACE_VERSION_PAY_TO_CREATOR)
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    # pay for a name in a v1 namespace with Stacks
    addr = virtualchain.address_reencode(virtualchain.get_privkey_address(pk))
    addr2 = virtualchain.address_reencode(virtualchain.get_privkey_address(pk2))

    # calculate the cost of doing so
    namespace = testlib.get_state_engine().get_namespace('test')
    stacks_price = blockstack.lib.scripts.price_name_stacks('foo', namespace, testlib.get_current_block(**kw))
    btc_price = blockstack.lib.scripts.price_name('foo', namespace, testlib.get_current_block(**kw))

    print ''
    print 'price of {} in Stacks is {}'.format('foo.test', stacks_price)
    print ''

    testlib.blockstack_send_tokens(addr, "STACKS", stacks_price * 8, wallets[0].privkey)
    testlib.blockstack_send_tokens(addr2, "STACKS", stacks_price * 8, wallets[0].privkey)
    testlib.send_funds(wallets[0].privkey, btc_price * 10, addr)    # fund with enough bitcoin
    testlib.send_funds(wallets[0].privkey, btc_price * 10, addr2)    # fund with enough bitcoin
    testlib.next_block(**kw)

    def _tx_pay_btc(txhex, privk, btc_paid, burn_addr):
        tx = virtualchain.btc_tx_deserialize(txhex)

        # up the burn amount 
        btc_price = blockstack.lib.scripts.price_name('baz', namespace, testlib.get_current_block(**kw))
        tx['outs'][2]['script'] = virtualchain.btc_make_payment_script(burn_addr)
        tx['outs'][2]['value'] = btc_paid

        tx['outs'][1]['value'] -= btc_paid

        # re-sign 
        for i in tx['ins']:
            i['script'] = ''

        txhex = virtualchain.btc_tx_serialize(tx)
        _addr = virtualchain.address_reencode(virtualchain.get_privkey_address(privk))
        txhex_signed = virtualchain.tx_sign_all_unsigned_inputs(privk, testlib.get_utxos(_addr), txhex)
        
        print txhex_signed
        res = testlib.broadcast_transaction(txhex_signed)
        assert 'error' not in res, res['error']
        return res

    balance_before = testlib.get_addr_balances(addr)[addr]['STACKS']

    # pay with Stacks and Bitcoin.  Preorder should succeed only when we use the Blockstack burn address, but register should fail since we're paying Stacks.  Pay enough bitcoin as well.
    res_fooa = testlib.blockstack_name_preorder('fooa.test', pk, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price}, burn_addr=blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS, tx_only=True, expect_success=True, safety_checks=False)
    res_fooa = _tx_pay_btc(res_fooa['transaction'], pk, btc_price, blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS)

    res_bara = testlib.blockstack_name_preorder('bara.test', pk, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price}, burn_addr=wallets[0].addr, tx_only=True, safety_checks=False)
    res_bara = _tx_pay_btc(res_bara['transaction'], pk, btc_price, wallets[0].addr)

    res_baza = testlib.blockstack_name_preorder('baza.test', pk, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price - 1}, burn_addr=blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS, tx_only=True, expect_success=True, safety_checks=False)
    res_baza = _tx_pay_btc(res_baza['transaction'], pk, btc_price, blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS)

    res_gooa = testlib.blockstack_name_preorder('gooa.test', pk, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price - 1}, burn_addr=wallets[0].addr, tx_only=True, safety_checks=False)
    res_gooa = _tx_pay_btc(res_gooa['transaction'], pk, btc_price, wallets[0].addr)

    res_foob = testlib.blockstack_name_preorder('foob.test', pk, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price}, burn_addr=blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS, tx_only=True, expect_success=True, safety_checks=False)
    res_foob = _tx_pay_btc(res_foob['transaction'], pk, btc_price - 1, blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS)
    
    res_barb = testlib.blockstack_name_preorder('barb.test', pk, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price}, burn_addr=wallets[0].addr, tx_only=True, safety_checks=False)
    res_barb = _tx_pay_btc(res_barb['transaction'], pk, btc_price - 1, wallets[0].addr)
    
    res_bazb = testlib.blockstack_name_preorder('bazb.test', pk, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price - 1}, burn_addr=blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS, tx_only=True, expect_success=True, safety_checks=False)
    res_bazb = _tx_pay_btc(res_bazb['transaction'], pk, btc_price - 1, blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS)
    
    res_goob = testlib.blockstack_name_preorder('goob.test', pk, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price - 1}, burn_addr=wallets[0].addr, tx_only=True, safety_checks=False)
    res_goob = _tx_pay_btc(res_goob['transaction'], pk, btc_price - 1, wallets[0].addr)

    testlib.next_block(**kw)

    # should have paid in Stacks for each preorder
    balance_after = testlib.get_addr_balances(addr)[addr]['STACKS']
    if balance_after != balance_before - (2 * stacks_price + 2 * stacks_price - 2):
        print 'names cost {}'.format(balance_before - balance_after)
        return False

    # should all fail since we tried to pay in stacks at this time
    testlib.blockstack_name_register('fooa.test', pk, wallets[3].addr)
    testlib.blockstack_name_register('bara.test', pk, wallets[3].addr)
    testlib.blockstack_name_register('baza.test', pk, wallets[3].addr)
    testlib.blockstack_name_register('gooa.test', pk, wallets[3].addr)

    testlib.blockstack_name_register('foob.test', pk, wallets[3].addr)
    testlib.blockstack_name_register('barb.test', pk, wallets[3].addr)
    testlib.blockstack_name_register('bazb.test', pk, wallets[3].addr)
    testlib.blockstack_name_register('goob.test', pk, wallets[3].addr)

    testlib.next_block(**kw)    # pay-to-creator ends
    testlib.expect_snv_fail_at('fooa.test', testlib.get_current_block(**kw))
    testlib.expect_snv_fail_at('bara.test', testlib.get_current_block(**kw))
    testlib.expect_snv_fail_at('baza.test', testlib.get_current_block(**kw))
    testlib.expect_snv_fail_at('gooa.test', testlib.get_current_block(**kw))

    testlib.expect_snv_fail_at('foob.test', testlib.get_current_block(**kw))
    testlib.expect_snv_fail_at('barb.test', testlib.get_current_block(**kw))
    testlib.expect_snv_fail_at('bazb.test', testlib.get_current_block(**kw))
    testlib.expect_snv_fail_at('goob.test', testlib.get_current_block(**kw))

    balance_before = testlib.get_addr_balances(addr2)[addr2]['STACKS']

    # pay with Stacks and Bitcoin, now that pay-to-creator has passed.  Preorder should succeed when we pay to blockstack burn address, and register should succeed (when we fund enough), all because we paid in stacks.
    res_fooa = testlib.blockstack_name_preorder('fooa.test', pk2, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price}, burn_addr=blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS, tx_only=True, expect_success=True, safety_checks=False)
    res_fooa = _tx_pay_btc(res_fooa['transaction'], pk2, btc_price, blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS)

    res_bara = testlib.blockstack_name_preorder('bara.test', pk2, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price}, burn_addr=wallets[0].addr, tx_only=True, safety_checks=False)
    res_bara = _tx_pay_btc(res_bara['transaction'], pk2, btc_price, wallets[0].addr)

    res_baza = testlib.blockstack_name_preorder('baza.test', pk2, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price - 1}, burn_addr=blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS, tx_only=True, expect_success=True, safety_checks=False)
    res_baza = _tx_pay_btc(res_baza['transaction'], pk2, btc_price, blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS)

    res_gooa = testlib.blockstack_name_preorder('gooa.test', pk2, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price - 1}, burn_addr=wallets[0].addr, tx_only=True, safety_checks=False)
    res_gooa = _tx_pay_btc(res_gooa['transaction'], pk2, btc_price, wallets[0].addr)

    res_foob = testlib.blockstack_name_preorder('foob.test', pk2, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price}, burn_addr=blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS, tx_only=True, expect_success=True, safety_checks=False)
    res_foob = _tx_pay_btc(res_foob['transaction'], pk2, btc_price - 1, blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS)

    res_barb = testlib.blockstack_name_preorder('barb.test', pk2, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price}, burn_addr=wallets[0].addr, tx_only=True, safety_checks=False)
    res_barb = _tx_pay_btc(res_barb['transaction'], pk2, btc_price - 1, wallets[0].addr)

    res_bazb = testlib.blockstack_name_preorder('bazb.test', pk2, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price - 1}, burn_addr=blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS, tx_only=True, expect_success=True, safety_checks=False)
    res_bazb = _tx_pay_btc(res_bazb['transaction'], pk2, btc_price - 1, blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS)

    res_goob = testlib.blockstack_name_preorder('goob.test', pk2, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price - 1}, burn_addr=wallets[0].addr, tx_only=True, safety_checks=False)
    res_goob = _tx_pay_btc(res_goob['transaction'], pk2, btc_price - 1, wallets[0].addr)

    testlib.next_block(**kw)

    # should have paid in Stacks for each preorder
    balance_after = testlib.get_addr_balances(addr2)[addr2]['STACKS']
    if balance_after != balance_before - (2 * stacks_price + 2 * stacks_price - 2):
        print 'baz.test cost {}'.format(balance_before - balance_after)
        return False

    # only foo*.test should succeed, since we both paid enough stacks and paid to the burn address
    testlib.blockstack_name_register('fooa.test', pk2, wallets[3].addr)
    testlib.blockstack_name_register('bara.test', pk2, wallets[3].addr)
    testlib.blockstack_name_register('baza.test', pk2, wallets[3].addr)
    testlib.blockstack_name_register('gooa.test', pk2, wallets[3].addr)

    testlib.blockstack_name_register('foob.test', pk2, wallets[3].addr)
    testlib.blockstack_name_register('barb.test', pk2, wallets[3].addr)
    testlib.blockstack_name_register('bazb.test', pk2, wallets[3].addr)
    testlib.blockstack_name_register('goob.test', pk2, wallets[3].addr)

    testlib.next_block(**kw)
    testlib.expect_snv_fail_at('bara.test', testlib.get_current_block(**kw))
    testlib.expect_snv_fail_at('baza.test', testlib.get_current_block(**kw))
    testlib.expect_snv_fail_at('gooa.test', testlib.get_current_block(**kw))

    testlib.expect_snv_fail_at('barb.test', testlib.get_current_block(**kw))
    testlib.expect_snv_fail_at('bazb.test', testlib.get_current_block(**kw))
    testlib.expect_snv_fail_at('goob.test', testlib.get_current_block(**kw))


def check( state_engine ):

    addr = virtualchain.address_reencode(virtualchain.get_privkey_address(pk))
    addr2 = virtualchain.address_reencode(virtualchain.get_privkey_address(pk2))

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

    # verify accepted preorders exist (except for the latter ones for foo*.test), and that they paid both btc and stacks
    print 'addr = {}'.format(addr)
    print 'addr2 = {}'.format(addr2)

    for name in ['fooa.test', 'foob.test', 'baza.test', 'bazb.test']:
        for a in [addr, addr2]:
            print '{} + {} + {} == {}'.format(name, virtualchain.make_payment_script(a), wallets[3].addr, blockstack.lib.hashing.hash_name(name, virtualchain.make_payment_script(a), wallets[3].addr))
            preorder = state_engine.get_name_preorder(name, virtualchain.make_payment_script(a), wallets[3].addr, include_failed=True)
            if a == addr2 and name.startswith('foo'):
                if preorder is not None:
                    print 'still have preorder for {}, {}'.format(name, a)
                    return False

                continue
    
            stacks_price = blockstack.lib.scripts.price_name_stacks(name.split('.')[0], ns, state_engine.lastblock)
            btc_price = blockstack.lib.scripts.price_name(name.split('.')[0], ns, state_engine.lastblock)

            if preorder is None:
                print 'missing preorder for {} from {}'.format(name, a)
                return False

            if name.split('.')[0].endswith('b') and preorder['op_fee'] != btc_price - 1:
                print 'wrong insufficient btc fee for {} ({})'.format(name, preorder['op_fee'])
                return False
        
            elif name.split('.')[0].endswith('a') and preorder['op_fee'] != btc_price:
                print 'wrong btc fee for {} ({})'.format(name, preorder['op_fee'])
                return False

            if name.split('.')[0][:3] in ['foo', 'bar'] and preorder['token_fee'] != stacks_price:
                print 'wrong stacks fee for {} ({})'.format(name, preorder['token_fee'])
                return False

            if name.split('.')[0][:3] in ['baz', 'goo'] and preorder['token_fee'] != stacks_price - 1:
                print 'wrong insufficient stacks fee for {} ({})'.format(name, preorder['token_fee'])
                return False

    # for the names that do exist, make sure we paid enough 
    for name in ['fooa.test', 'foob.test']:
        name_rec = state_engine.get_name(name)
        if name_rec is None:
            print 'no name rec for {}'.format(name)
            return False

        if name_rec['address'] != wallets[3].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[3].addr):
            print 'wrong owner for {}'.format(name)
            return False

        stacks_price = blockstack.lib.scripts.price_name_stacks(name.split('.')[0], ns, state_engine.lastblock)
        btc_price = blockstack.lib.scripts.price_name(name.split('.')[0], ns, state_engine.lastblock)
        if name_rec['token_fee'] != stacks_price:
            print 'wrong token fee for {}'.format(name)
            return False

        if name_rec['op_fee'] != btc_price and name == 'fooa.test':
            print 'wrong op_fee for {}'.format(name)
            return False

        if name_rec['op_fee'] != btc_price - 1 and name == 'foob.test':
            print 'wrong op_fee for {}'.format(name)
            return False

    return True
