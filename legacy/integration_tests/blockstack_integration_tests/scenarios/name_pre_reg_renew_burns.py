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
"""

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet("e802e6b061d7d9594afef1d82037d6a3901c60f567b26c7ad8be9cfb3fd8320d01", 0),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
pk = wallets[-1].privkey

def scenario( wallets, **kw ):
    global pk

    testlib.blockstack_namespace_preorder( "test1", wallets[1].addr, wallets[0].privkey)
    testlib.blockstack_namespace_preorder( "test2", wallets[1].addr, wallets[0].privkey)
    testlib.blockstack_namespace_preorder( "test3", wallets[1].addr, wallets[0].privkey)
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test1", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=1 )
    testlib.blockstack_namespace_reveal( "test2", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=2 )
    testlib.blockstack_namespace_reveal( "test3", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=3 )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test1", wallets[1].privkey )
    testlib.blockstack_namespace_ready( "test2", wallets[1].privkey )
    testlib.blockstack_namespace_ready( "test3", wallets[1].privkey )
    testlib.next_block( **kw )

    # pay for a name in a v1 namespace with Stacks
    addr = virtualchain.address_reencode(virtualchain.get_privkey_address(pk))

    # calculate the cost of doing so
    namespace = testlib.get_state_engine().get_namespace('test1')
    stacks_price = blockstack.lib.scripts.price_name_stacks('foo', namespace, testlib.get_current_block(**kw))
    btc_price = blockstack.lib.scripts.price_name('foo', namespace, testlib.get_current_block(**kw))

    print ''
    print 'price of {} in Stacks is {}'.format('foo.test', stacks_price)
    print ''

    testlib.blockstack_send_tokens(addr, "STACKS", 3 * stacks_price, wallets[0].privkey)
    testlib.send_funds(wallets[0].privkey, btc_price - 5500 - 1, addr)  # deliberately insufficient funds for ordering the name in BTC
    testlib.next_block(**kw)

    wallet_before_burn = testlib.get_balance(wallets[0].addr)

    # preorder/register in all three namespaces
    testlib.blockstack_name_preorder( "foo.test1", pk, wallets[3].addr, price={'units': 'STACKS', 'amount': stacks_price})
    testlib.blockstack_name_preorder( "bar.test1", wallets[1].privkey, wallets[3].addr)
    testlib.blockstack_name_preorder( "foo.test2", wallets[1].privkey, wallets[3].addr)
    testlib.blockstack_name_preorder( "foo.test3", wallets[1].privkey, wallets[3].addr)
    testlib.next_block( **kw )
    
    wallet_after_burn = testlib.get_balance(wallets[0].addr)
    if wallet_after_burn - wallet_before_burn != btc_price:
        print 'foo.test2 did not pay {} to {} (but paid {})'.format(btc_price, wallets[0].addr, wallet_after_burn - wallet_before_burn)
        return False

    testlib.send_funds(wallets[0].privkey, btc_price - 5500 - 1, addr)  # deliberately insufficient funds for ordering the name in BTC
    testlib.blockstack_name_register( "foo.test1", pk, wallets[3].addr ) # paid in Stacks
    testlib.blockstack_name_register( "bar.test1", wallets[1].privkey, wallets[3].addr ) # paid in BTC
    testlib.blockstack_name_register( "foo.test2", wallets[1].privkey, wallets[3].addr ) # paid in BTC to wallets[0]
    testlib.blockstack_name_register( "foo.test3", wallets[1].privkey, wallets[3].addr ) # paid in Stacks
    testlib.next_block( **kw )

    testlib.send_funds(wallets[0].privkey, btc_price - 5500 - 1, addr)  # deliberately insufficient funds for ordering the name in BTC
    
    wallet_before_burn = testlib.get_balance(wallets[0].addr)
    testlib.blockstack_name_renew( "foo.test1", wallets[3].privkey, price={'units': 'STACKS', 'amount': stacks_price}) # paid in Stacks
    testlib.blockstack_name_renew( "bar.test1", wallets[3].privkey ) # paid in BTC
    testlib.blockstack_name_renew( "foo.test2", wallets[3].privkey ) # paid in BTC to wallets[0]
    testlib.blockstack_name_renew( "foo.test3", wallets[3].privkey ) # paid in Stacks
    testlib.next_block( **kw )

    wallet_after_burn = testlib.get_balance(wallets[0].addr)
    if wallet_after_burn - wallet_before_burn != btc_price:
        print 'foo.test2 did not pay {} to {} (but paid {})'.format(btc_price, wallets[0].addr, wallet_after_burn - wallet_before_burn)
        return False

    # should all fail--wrong burn addresses
    testlib.blockstack_name_renew( "foo.test1", pk, price={'units': 'STACKS', 'amount': stacks_price}, burn_addr=wallets[0].addr, safety_checks=False, expect_fail=True )
    testlib.blockstack_name_renew( "bar.test1", wallets[3].privkey, burn_addr=wallets[0].addr, safety_checks=False, expect_fail=True )
    testlib.blockstack_name_renew( "foo.test2", wallets[3].privkey, burn_addr=wallets[1].addr, safety_checks=False, expect_fail=True )
    testlib.blockstack_name_renew( "foo.test3", wallets[3].privkey, burn_addr=wallets[0].addr, safety_checks=False, expect_fail=True )
    testlib.next_block( **kw )
    testlib.expect_snv_fail_at('foo.test1', testlib.get_current_block(**kw))
    testlib.expect_snv_fail_at('bar.test1', testlib.get_current_block(**kw))
    testlib.expect_snv_fail_at('foo.test2', testlib.get_current_block(**kw))
    testlib.expect_snv_fail_at('foo.test3', testlib.get_current_block(**kw))


def check( state_engine ):

    # not revealed, but ready 
    for namespace_id in ['test1', 'test2', 'test3']:
        ns = state_engine.get_namespace_reveal(namespace_id)
        if ns is not None:
            print "namespace reveal exists"
            return False 

        ns = state_engine.get_namespace(namespace_id)
        if ns is None:
            print "no namespace"
            return False 

        if ns['namespace_id'] != namespace_id:
            print "wrong namespace"
            return False 

    # not preordered
    addr = virtualchain.address_reencode(virtualchain.get_privkey_address(pk))
    preorder = state_engine.get_name_preorder( "foo.test", virtualchain.make_payment_script(addr), wallets[3].addr )
    if preorder is not None:
        print "preorder exists"
        return False
    
    for name in ['bar.test1', 'foo.test2', 'foo.test3']:
        # registered 
        name_rec = state_engine.get_name( name )
        if name_rec is None:
            print "name does not exist"
            return False 

        # owned by
        if name_rec['address'] != wallets[3].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[3].addr):
            print "sender is wrong"
            return False

        # renewed once
        if name_rec['first_registered'] + 1 != name_rec['last_renewed']:
            print 'renewal is wrong'
            return False

    for name in ['foo.test1', 'foo.test3']:
        # paid with Stacks
        namespace_id = name.split('.')[1]
        ns = state_engine.get_namespace(namespace_id)

        name_rec = state_engine.get_name( name )
        stacks_price = blockstack.lib.scripts.price_name_stacks(name.split('.')[0], ns, state_engine.lastblock)
        if name_rec['token_fee'] != stacks_price:
            print 'paid wrong token fee'
            print 'expected {} ({}), got {} ({})'.format(stacks_price, type(stacks_price), name_rec['token_fee'], type(name_rec['token_fee']))
            return False

        if name_rec['op_fee'] > 5500:  # dust minimum
            print 'paid in BTC ({})'.format(name_rec['op_fee'])
            return False

    for name in ['bar.test1', 'foo.test2']:
        # paid in Bitcoin
        namespace_id = name.split('.')[1]
        ns = state_engine.get_namespace(namespace_id)

        name_rec = state_engine.get_name( name )
        btc_price = blockstack.lib.scripts.price_name(name.split('.')[0], ns, state_engine.lastblock)
        if name_rec['token_fee'] != 0:
            print 'name was paid for in tokens'
            return False

        if name_rec['op_fee'] <= 5500:
            print 'not paid in BTC'
            return False

    # no failed names
    for name in ['foo_fail.test1', 'bar_fail.test1', 'foo_fail.test2', 'foo_fail.test3']:
        name_rec = state_engine.get_name(name)
        if name_rec is not None:
            print 'registered {}'.format(name)
            return False

    return True
