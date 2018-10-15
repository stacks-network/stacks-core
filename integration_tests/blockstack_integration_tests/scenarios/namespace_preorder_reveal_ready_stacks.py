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

# activate tokens
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 682
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 683
TEST ENV BLOCKSTACK_EPOCH_3_END_BLOCK 690
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 1
"""

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    res = testlib.blockstack_namespace_preorder( "teststacks", wallets[1].addr, wallets[3].privkey, safety_checks=False, price={'units': 'STACKS', 'amount': 64000000}, tx_only=True)
    ns_preorder_tx_stacks = res['transaction']

    res = testlib.blockstack_namespace_preorder('test2', wallets[1].addr, wallets[2].privkey, tx_only=True)
    ns_preorder_tx = res['transaction']

    testlib.broadcast_transaction(ns_preorder_tx_stacks)

    testlib.next_block( **kw )  # end of 689

    # should have only accepted one operation 
    block_stats = virtualchain.lib.indexer.StateEngine.get_block_statistics(testlib.get_current_block(**kw))
    if block_stats['num_parsed_ops'] != 1:
        print 'invalid number of parsed ops: {}'.format(block_stats['num_parsed_ops'])
        return False

    # try to register a Stacks transaction (should fail)
    testlib.blockstack_namespace_reveal( "teststacks", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[3].privkey)

    testlib.next_block( **kw )  # end of 690, begin Stacks
    testlib.expect_snv_fail_at('teststacks', testlib.get_current_block(**kw))

    # should not be accepted, since no stacks are paid
    testlib.broadcast_transaction(ns_preorder_tx)
    
    # should succeed, even though preordered after the Stacks token activation
    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )  # end of 690

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    # should fail
    testlib.blockstack_namespace_reveal( "test2", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[2].privkey )
    testlib.next_block(**kw)


def check( state_engine ):

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is not None:
        return False 

    ns = state_engine.get_namespace( "test" )
    if ns is None:
        return False 

    if ns['namespace_id'] != 'test':
        return False 

    # not revealed at all
    ns = state_engine.get_namespace_reveal( "test2" )
    if ns is not None:
        print 'invalid reveal'
        return False 

    ns = state_engine.get_namespace_reveal("teststacks")
    if ns is not None:
        print 'invalid reveal teststacks'
        return False

    return True
