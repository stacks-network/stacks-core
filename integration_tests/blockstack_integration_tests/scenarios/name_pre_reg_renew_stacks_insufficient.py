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
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 6399999999 ),    # actual cost of .test, minus 1
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 2 * 110912000 - 1 ),     # enough to register 'foo.test', but not enough to renew it
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 6400000000 + 110912000 - 1 ),    # enough to buy .test, but not renew foo.test
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 2 * 110912000 - 1 )      # enough to register 'bar.test', but not enough to register 'baz.test'
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    # should succeed
    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey, safety_checks=False, price={'units': 'STACKS', 'amount': 6399999999})
    testlib.next_block( **kw )

    # should fail---not enough STACKs
    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=blockstack.NAMESPACE_VERSION_PAY_WITH_STACKS )
    testlib.next_block( **kw )
    testlib.expect_snv_fail_at('test', testlib.get_current_block(**kw))

    # should succeed
    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[3].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[3].privkey, version_bits=blockstack.NAMESPACE_VERSION_PAY_WITH_STACKS )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )
    
    # should succeed
    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    # should fail--not enough funds
    testlib.blockstack_name_renew( "foo.test", wallets[3].privkey, expect_fail=True )
    testlib.next_block( **kw )
    testlib.expect_snv_fail_at('foo.test', testlib.get_current_block(**kw))

    # should succeed
    testlib.blockstack_name_preorder( "bar.test", wallets[4].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    testlib.blockstack_name_register( "bar.test", wallets[4].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    # should fail--not enough funds
    testlib.blockstack_name_preorder( "baz.test", wallets[4].privkey, wallets[3].addr, expect_fail=True, safety_checks=False )
    testlib.next_block( **kw )
    testlib.expect_snv_fail_at('baz.test', testlib.get_current_block(**kw))

    testlib.blockstack_name_register( "baz.test", wallets[4].privkey, wallets[3].addr )
    testlib.next_block( **kw )
    testlib.expect_snv_fail_at('baz.test', testlib.get_current_block(**kw))


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
    preorder = state_engine.get_name_preorder( "foo.test", virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr )
    if preorder is not None:
        print "preorder exists"
        return False
    
    preorder = state_engine.get_name_preorder( "bar.test", virtualchain.make_payment_script(wallets[4].addr), wallets[3].addr )
    if preorder is not None:
        print "preorder exists"
        return False

    preorder = state_engine.get_name_preorder( "baz.test", virtualchain.make_payment_script(wallets[4].addr), wallets[3].addr )
    if preorder is not None:
        print "preorder exists"
        return False

    # registered 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        print "name does not exist"
        return False 

    # owned by
    if name_rec['address'] != wallets[3].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[3].addr):
        print "sender is wrong"
        return False

    # not renewed
    if name_rec['first_registered'] != name_rec['last_renewed']:
        print 'renewed foo.test'
        return False 

    name_rec = state_engine.get_name( "bar.test" )
    if name_rec is None:
        print "name does not exist"
        return False 

    # owned by
    if name_rec['address'] != wallets[3].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[3].addr):
        print "sender is wrong"
        return False

    name_rec = state_engine.get_name( "baz.test" )
    if name_rec is not None:
        print "name accidentally exists"
        return False 

    return True
