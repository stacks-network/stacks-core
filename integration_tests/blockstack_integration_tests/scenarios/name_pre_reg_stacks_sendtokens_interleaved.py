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

STACKS = testlib.TOKEN_TYPE_STACKS

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
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 0 ),     # no tokens yet
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 0 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 0 ),
    testlib.Wallet("9864768ccf5137392de5b5d6551a0f9f17279df2f82b4de7b905290f95fde66201", 0),
    testlib.Wallet("2e55007fec0f1d9a81700e56aa8ce24d7e6e245ede48c00663f930f99fae133601", 0),
    testlib.Wallet("9d6836cdaf81245d646988effe398338073892143b1185f4553e6118f231d1bf01", 0),
    testlib.Wallet("f9c9371b7a8cc6b5ef544457cdd565e5791d743f5d60c924265732147429414801", 0),
    testlib.Wallet("cd8d6bdf3dfd7b3d498539bb42cf218b77b0fda4f3bc119c7226d803e8425da901", 0), 
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=blockstack.NAMESPACE_VERSION_PAY_WITH_STACKS )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    balances = testlib.get_wallet_balances(wallets[2])
    assert balances[wallets[2].addr][STACKS] == 0

    # should fail--not enough stacks
    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr, safety_checks=False, expect_fail=True )
    testlib.next_block( **kw )

    name_cost = testlib.blockstack_get_name_token_cost('foo.test')
    assert name_cost['units'] == STACKS
    assert name_cost['amount'] > 0

    # send tokens and preorder multiple times in the block
    # should all succeed, BUT: force them to go in order through UTXO chaining
    for i in range(0, 5):
        name_recipient_privkey = wallets[-(i+1)].privkey
        name_recipient_addr = virtualchain.address_reencode(virtualchain.get_privkey_address(name_recipient_privkey))

        testlib.blockstack_send_tokens(name_recipient_addr, "STACKS", name_cost['amount'], wallets[0].privkey)
        testlib.send_funds(wallets[0].privkey, 1000000, name_recipient_addr)
        testlib.blockstack_name_preorder( "foo_{}.test".format(i), name_recipient_privkey, wallets[3].addr, safety_checks=False )
        testlib.blockstack_name_register( "foo_{}.test".format(i), name_recipient_privkey, wallets[3].addr, safety_checks=False )

    testlib.next_block(**kw)
   

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
    for i in range(0, 5):
        name = 'foo_{}.test'.format(i)
        preorder = state_engine.get_name_preorder( name, virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr )
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

    return True
