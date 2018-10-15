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
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", int(1e6 * 1733 * 255 * 32**10) ),    # cost of foo.test
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 0 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 0 ),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    coeff = 255
    base = 32
    bucket_exponents = [10,10,10,9,9,9,8,8,8,0,0,0,0,0,0,0]
    nonalpha_discount = 10
    novowel_discount = 10
    cost_unit = blockstack.config.NAME_COST_UNIT_STACKS

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, coeff, base, bucket_exponents, nonalpha_discount, novowel_discount, wallets[0].privkey, version_bits=blockstack.NAMESPACE_VERSION_PAY_WITH_STACKS )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    # query a large amount of Stacks (exceeds 2**64)
    name_cost = testlib.blockstack_get_name_token_cost('foo.test')
    print name_cost

    assert name_cost['units'] == 'STACKS'
    assert name_cost['amount'] > 2**64

    # send a large amount of Stacks (exceeds 2**64) -- should fail, since our transactions only allow 8 bytes to encode the STACKs count
    try:
        res = testlib.blockstack_send_tokens(wallets[2].addr, "STACKS", name_cost['amount'], wallets[0].privkey, expect_fail=True)
        assert 'error' not in res
        print res
        print 'Accidentally succeeded to send {} STACKS'.format(name_cost['amount'])
        return False
    except:
        pass

    # should fail, since we can't encode the price as a 64-bit number
    try:
        res = testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr, expect_fail=True)
        assert 'error' not in res
        print res
        print 'Accidentally succeeded to preorder foo.test for {} STACKs'.format(name_cost['amount'])
        return False
    except:
        pass

    ns = testlib.get_state_engine().get_namespace('test')

    # old price function should be wonky since it's a big float
    discount = 10.0     # for foo2.id, the non-alpha discount applies
    old_price_multiplier = 0.1
    old_price_float = (float(coeff * (base ** bucket_exponents[len('foo2')-1])) / float(discount)) * cost_unit * old_price_multiplier

    new_price_int = blockstack.scripts.price_name('foo2', ns, testlib.get_current_block(**kw))

    print 'old price: {}'.format(old_price_float)
    print 'new price: {}'.format(new_price_int)
    print 'diff: {}'.format(abs(int(old_price_float) - new_price_int))

    # diff should be 1024, since we're dealing with floats bigger than 2**53
    assert abs(int(old_price_float) - new_price_int) > 100, 'old price: {}, new price: {}'.format(old_price_float, new_price_int)

    testlib.blockstack_name_preorder( "foo2.test", wallets[2].privkey, wallets[3].addr)
    testlib.next_block( **kw )

    testlib.blockstack_name_register( "foo2.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )


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
    preorder = state_engine.get_name_preorder( "foo2.test", virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr )
    if preorder is not None:
        print "preorder exists"
        return False
    
    # registered 
    name_rec = state_engine.get_name( "foo2.test" )
    if name_rec is None:
        print "name does not exist"
        return False 

    # owned by
    if name_rec['address'] != wallets[3].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[3].addr):
        print "sender is wrong"
        return False 

    return True
