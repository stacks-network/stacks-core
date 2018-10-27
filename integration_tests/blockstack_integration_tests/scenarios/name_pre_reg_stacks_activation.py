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
TEST ENV BLOCKSTACK_EPOCH_3_END_BLOCK 693
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

    namespace_price_old_btc_2 = {'units': 'BTC', 'amount': blockstack.lib.scripts.price_namespace('old_btc_2', 694, 'BTC')}
    namespace_price_stacks_too_early_1_btc = {'units': 'BTC', 'amount': blockstack.lib.scripts.price_namespace('stacks_too_early_1', 690, 'BTC')}
    namespace_price_stacks_too_early_2_stacks = {'units': 'STACKS', 'amount': blockstack.lib.scripts.price_namespace('stacks_too_early_1', 694, 'STACKS')}

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.blockstack_namespace_preorder( "stacks_too_early_1", wallets[1].addr, wallets[0].privkey, safety_checks=False, price=namespace_price_stacks_too_early_1_btc, tx_fee=50000)
    testlib.blockstack_namespace_preorder( "old_btc_1", wallets[1].addr, wallets[0].privkey )
    btc_too_late_tx = testlib.blockstack_namespace_preorder( 'btc_too_late', wallets[1].addr, wallets[2].privkey, tx_only=True )

    print ''
    print btc_too_late_tx
    print ''
    
    testlib.next_block( **kw ) # end of 689

    # should be accepted
    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )

    # the stacks_too_early namespace cannot be revealed (i.e. its preorder got rejected)
    testlib.blockstack_namespace_reveal( "stacks_too_early_1", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=blockstack.NAMESPACE_VERSION_PAY_WITH_STACKS, safety_checks=False, tx_fee=50000)
    testlib.next_block( **kw ) # end of 690
    testlib.expect_snv_fail_at('stacks_too_early_1', testlib.get_current_block(**kw))

    res = testlib.blockstack_cli_get_namespace_blockchain_record('test')
    if 'error' in res:
        print 'test was not revealed'
        print res
        return False

    res = testlib.blockstack_cli_get_namespace_blockchain_record('stacks_too_early_1')
    if 'error' not in res:
        print 'stacks too early 1 was revealed'
        print res
        return False

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw ) # end of 691
    testlib.next_block( **kw ) # end of 692

    # should succeed---last block we can pay in BTC
    testlib.blockstack_namespace_preorder( "old_btc_2", wallets[1].addr, wallets[0].privkey, price=namespace_price_old_btc_2)

    # should be rejected---this is one block early
    testlib.blockstack_namespace_preorder( "stacks_too_early_2", wallets[1].addr, wallets[0].privkey, safety_checks=False, price=namespace_price_stacks_too_early_2_stacks, tx_fee=50000, expect_reject=True)
    testlib.next_block( **kw ) # end of 693
    testlib.expect_snv_fail_at('stacks_too_early_2', testlib.get_current_block(**kw))

    # should succeed even though preordered with BTC
    testlib.blockstack_namespace_reveal( "old_btc_1", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=blockstack.NAMESPACE_VERSION_PAY_WITH_STACKS )
   
    # should fail -- no preorder
    testlib.blockstack_namespace_reveal( "stacks_too_early_2", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=blockstack.NAMESPACE_VERSION_PAY_WITH_STACKS, safety_checks=False, tx_fee=50000)

    # should be rejected---it's a block too late 
    testlib.broadcast_transaction(btc_too_late_tx['transaction'])

    testlib.next_block(**kw) # end of 694
    testlib.expect_snv_fail_at('stacks_too_early_2', testlib.get_current_block(**kw))
    
    res = testlib.blockstack_cli_get_namespace_blockchain_record('stacks_too_early_2')
    if 'error' not in res:
        print 'stacks too early 2 was revealed'
        print res
        return False

    res = testlib.blockstack_cli_get_namespace_blockchain_record('old_btc_1')
    if 'error' in res:
        print 'old_btc_1 not revealed'
        print res
        return False

    # should succeed, even though we're in the STACKS epoch
    testlib.blockstack_namespace_reveal( "old_btc_2", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=blockstack.NAMESPACE_VERSION_PAY_WITH_STACKS )
    
    # should fail, since the preorer for btc_too_late was sent too late
    testlib.blockstack_namespace_reveal( "btc_too_late", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[2].privkey, version_bits=blockstack.NAMESPACE_VERSION_PAY_WITH_STACKS )
    testlib.next_block( **kw ) # end of 695
    testlib.expect_snv_fail_at('btc_too_late', testlib.get_current_block(**kw))

    res = testlib.blockstack_cli_get_namespace_blockchain_record('old_btc_2')
    if 'error' in res:
        print 'failed to reveal btc 2'
        print res
        return False

    res = testlib.blockstack_cli_get_namespace_blockchain_record('btc_too_late')
    if 'error' not in res:
        print 'revealed btc_too_late'
        print res
        return False


def check( state_engine ):
    return True
