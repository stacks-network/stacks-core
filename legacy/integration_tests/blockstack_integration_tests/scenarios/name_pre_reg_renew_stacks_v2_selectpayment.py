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

# activate tokens
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 682
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 683
TEST ENV BLOCKSTACK_EPOCH_3_END_BLOCK 684
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_RECEIVE_FEES_PERIOD 6
TEST ENV BLOCKSTACK_EPOCH_4_NAMESPACE_RECEIVE_FEES_PERIOD 6
"""

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet("e802e6b061d7d9594afef1d82037d6a3901c60f567b26c7ad8be9cfb3fd8320d01", 0),
    testlib.Wallet("f3723d91bf90657746f01fc1d85ba4db6d7d1e4f4ca2174445235efd1350f87101", 0),
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
    print 'price of {} in BTC is {}'.format('foo.test', btc_price)
    print ''

    testlib.blockstack_send_tokens(addr, "STACKS", 8*stacks_price, wallets[0].privkey)
    testlib.blockstack_send_tokens(addr2, "STACKS", 8*stacks_price, wallets[0].privkey)
    testlib.send_funds(wallets[0].privkey, 8*btc_price, addr)
    testlib.send_funds(wallets[0].privkey, 8*btc_price, addr2)
    testlib.next_block(**kw)

    def _tx_pay_btc(txhex, privk, burn_price, burn_addr=blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS):
        tx = virtualchain.btc_tx_deserialize(txhex)

        # up the burn amount 
        tx['outs'][3]['script'] = virtualchain.btc_make_payment_script(burn_addr)
        tx['outs'][3]['value'] = burn_price

        tx['outs'][4]['value'] -= burn_price

        # re-sign 
        for i in tx['ins']:
            i['script'] = ''

        txhex = virtualchain.btc_tx_serialize(tx)
        _addr = virtualchain.address_reencode(virtualchain.get_privkey_address(privk))
        txhex_signed = virtualchain.tx_sign_all_unsigned_inputs(privk, testlib.get_utxos(_addr), txhex)

        # re-sign the last output with the payment key
        tx_signed = virtualchain.btc_tx_deserialize(txhex_signed)
        tx_signed['ins'][-1]['script'] = ''
        txhex_signed = virtualchain.tx_sign_all_unsigned_inputs(testlib.get_default_payment_wallet().privkey, testlib.get_utxos(testlib.get_default_payment_wallet().addr), virtualchain.btc_tx_serialize(tx_signed))
        
        print txhex_signed

        res = testlib.broadcast_transaction(txhex_signed)
        assert 'error' not in res
        return res

    # preorder/register using BTC
    testlib.blockstack_name_preorder( "foo.test", pk, addr2 )
    testlib.blockstack_name_preorder( "bar.test", pk, addr2 )
    testlib.blockstack_name_preorder( "baz.test", pk, addr2 )
    testlib.blockstack_name_preorder( "goo.test", pk, addr2 )
    testlib.next_block( **kw )

    testlib.blockstack_name_register( "foo.test", pk, addr2 )
    testlib.blockstack_name_register( "bar.test", pk, addr2 )
    testlib.blockstack_name_register( "baz.test", pk, addr2 )
    testlib.blockstack_name_register( "goo.test", pk, addr2 )
    testlib.next_block( **kw )

    # try to renew using Stacks (won't work, since we used the wrong burn address while pay-to-creator was active)
    res = testlib.blockstack_name_renew('foo.test', pk2, price={'units': 'STACKS', 'amount': stacks_price}, burn_addr=blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS, safety_checks=False, expect_fail=True, tx_only=True)
    res = _tx_pay_btc(res['transaction'], pk2, btc_price)

    # try to renew using Stacks (won't work, since we send tokens to the wrong burn address for tokens)
    res = testlib.blockstack_name_renew('bar.test', pk2, price={'units': 'STACKS', 'amount': stacks_price}, burn_addr=wallets[0].addr, safety_checks=False, expect_fail=True, tx_only=True)
    res = _tx_pay_btc(res['transaction'], pk2, btc_price, wallets[0].addr)

    # try to renew using Stacks (won't work, since we used the wrong burn address while pay-to-creator was active).  Also underpay BTC
    res = testlib.blockstack_name_renew('baz.test', pk2, price={'units': 'STACKS', 'amount': stacks_price}, burn_addr=blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS, safety_checks=False, expect_fail=True, tx_only=True)
    res = _tx_pay_btc(res['transaction'], pk2, btc_price - 1)

    # try to renew using Stacks (won't work, since we send tokens to the wrong burn address for tokens).  Also underpay BTC
    res = testlib.blockstack_name_renew('goo.test', pk2, price={'units': 'STACKS', 'amount': stacks_price}, burn_addr=wallets[0].addr, safety_checks=False, expect_fail=True, tx_only=True)
    res = _tx_pay_btc(res['transaction'], pk2, btc_price - 1, wallets[0].addr)
    testlib.next_block(**kw)

    # all should have failed
    assert virtualchain.lib.indexer.StateEngine.get_block_statistics(testlib.get_current_block(**kw))['num_processed_ops'] == 0

    # try to renew using Stacks (won't work, since we're still collecting fees in BTC and need to send to the namespace creator's address)
    res = testlib.blockstack_name_renew('foo.test', pk2, price={'units': 'STACKS', 'amount': stacks_price-1}, burn_addr=blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS, safety_checks=False, expect_fail=True, tx_only=True)
    res = _tx_pay_btc(res['transaction'], pk2, btc_price)
    
    res = testlib.blockstack_name_renew('bar.test', pk2, price={'units': 'STACKS', 'amount': stacks_price-1}, burn_addr=wallets[0].addr, safety_checks=False, expect_fail=True, tx_only=True)
    res = _tx_pay_btc(res['transaction'], pk2, btc_price, wallets[0].addr)

    # try to renew using Stacks (won't work, since we used the wrong burn address while pay-to-creator was active).  Also underpay BTC
    res = testlib.blockstack_name_renew('baz.test', pk2, price={'units': 'STACKS', 'amount': stacks_price-1}, burn_addr=blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS, safety_checks=False, expect_fail=True, tx_only=True)
    res = _tx_pay_btc(res['transaction'], pk2, btc_price - 1)

    # try to renew using Stacks (won't work, since we send tokens to the wrong burn address for tokens).  Also underpay BTC
    res = testlib.blockstack_name_renew('goo.test', pk2, price={'units': 'STACKS', 'amount': stacks_price-1}, burn_addr=wallets[0].addr, safety_checks=False, expect_fail=True, tx_only=True)
    res = _tx_pay_btc(res['transaction'], pk2, btc_price - 1, wallets[0].addr)
    testlib.next_block(**kw)

    # all should have failed
    assert virtualchain.lib.indexer.StateEngine.get_block_statistics(testlib.get_current_block(**kw))['num_processed_ops'] == 0

    # try to renew using Stacks, now that pay-to-creator has expired
    res = testlib.blockstack_name_renew('foo.test', pk2, price={'units': 'STACKS', 'amount': stacks_price}, expect_success=True, tx_only=True)
    res = _tx_pay_btc(res['transaction'], pk2, btc_price)

    # should fail--can't mix stacks and btc
    res = testlib.blockstack_name_renew('bar.test', pk2, price={'units': 'STACKS', 'amount': stacks_price-1}, expect_fail=True, tx_only=True)
    res = _tx_pay_btc(res['transaction'], pk2, btc_price)

    # should succeed--paid in stacks
    res = testlib.blockstack_name_renew('baz.test', pk2, price={'units': 'STACKS', 'amount': stacks_price}, expect_success=True, tx_only=True)
    res = _tx_pay_btc(res['transaction'], pk2, btc_price - 1)

    # should fail--wrong burn address
    res = testlib.blockstack_name_renew('goo.test', pk2, price={'units': 'STACKS', 'amount': stacks_price}, burn_addr=wallets[0].addr, safety_checks=False, expect_fail=True, tx_only=True)
    res = _tx_pay_btc(res['transaction'], pk2, btc_price, wallets[0].addr)
    testlib.next_block(**kw)

    # only two should have succeeded
    assert virtualchain.lib.indexer.StateEngine.get_block_statistics(testlib.get_current_block(**kw))['num_processed_ops'] == 2


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

    # not preordered
    addr = virtualchain.address_reencode(virtualchain.get_privkey_address(pk))
    addr2 = virtualchain.address_reencode(virtualchain.get_privkey_address(pk2))

    for name in ['foo.test', 'bar.test', 'baz.test', 'goo.test']:
        preorder = state_engine.get_name_preorder( name, virtualchain.make_payment_script(addr), addr2 )
        if preorder is not None:
            print "preorder exists"
            return False
        
        # registered 
        name_rec = state_engine.get_name( name )
        if name_rec is None:
            print "name does not exist"
            return False 

        # owned by
        if name_rec['address'] != addr2 or name_rec['sender'] != virtualchain.make_payment_script(addr2):
            print "sender is wrong"
            return False 

        # paid with Stacks
        stacks_price = blockstack.lib.scripts.price_name_stacks(name.split('.')[0], ns, state_engine.lastblock)
        btc_price = blockstack.lib.scripts.price_name(name.split('.')[0], ns, state_engine.lastblock)

        if name in ['foo.test']:
            # renewed on third attempt
            if name_rec['first_registered'] + 3 != name_rec['last_renewed']:
                print 'renewed at the wrong time: {} + 3 != {}'.format(name_rec['first_registered'], name_rec['last_renewed'])
                return False

            if name_rec['op_fee'] != btc_price: 
                print 'paid wrong {} in BTC ({})'.format(name, name_rec['op_fee'])
                return False

        if name in ['baz.test']:
            # renewed on third attempt
            if name_rec['first_registered'] + 3 != name_rec['last_renewed']:
                print 'renewed at the wrong time: {} + 3 != {}'.format(name_rec['first_registered'], name_rec['last_renewed'])
                return False

            if name_rec['op_fee'] != btc_price - 1:
                print 'paid wrong {} in BTC ({})'.format(name, name_rec['op_fee'])
                return False

        if name in ['bar.test', 'goo.test']:
            # did not renew
            if name_rec['first_registered'] != name_rec['last_renewed']:
                print 'renewed {}'.format(name)
                return False

    return True
