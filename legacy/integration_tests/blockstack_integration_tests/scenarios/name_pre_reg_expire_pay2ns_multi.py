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

# activate F-day 2017
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 682
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 683
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_GRACE_PERIOD 0
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_RECEIVE_FEES_PERIOD 17
"""


import testlib
import virtualchain
import blockstack

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
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 3, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=2)
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    namespace_rec = testlib.blockstack_cli_get_namespace_blockchain_record("test")
    if 'error' in namespace_rec:
        print namespace_rec
        return False

    namespace_balance = testlib.get_balance(namespace_rec['address'])
    burn_balance = testlib.get_balance(blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS)

    res = testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr ) # +name_cost
    if 'error' in res:
        print res
        return False

    testlib.next_block( **kw )

    res = testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    if 'error' in res:
        print res
        return False

    testlib.next_block( **kw )
    testlib.next_block( **kw )
    testlib.next_block( **kw )
    testlib.next_block( **kw )
    testlib.next_block( **kw ) # expired
    
    res = testlib.blockstack_name_preorder( "foo.test", wallets[3].privkey, wallets[4].addr )  # +name_cost
    if 'error' in res:
        print res
        return False

    testlib.next_block( **kw )

    res = testlib.blockstack_name_register( "foo.test", wallets[3].privkey, wallets[4].addr )
    if 'error' in res:
        print res
        return False

    testlib.next_block( **kw )
    testlib.next_block( **kw )

    res = testlib.blockstack_name_renew("foo.test", wallets[4].privkey)     # +name_cost
    if 'error' in res:
        print res
        return False

    testlib.next_block( **kw )
    testlib.next_block( **kw )
    testlib.next_block( **kw )
    testlib.next_block( **kw )
    testlib.next_block( **kw ) # expired

    res = testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )       # +name_cost
    if 'error' in res:
        print res
        return False

    testlib.next_block( **kw )

    res = testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    if 'error' in res:
        print res
        return False

    testlib.next_block( **kw )

    new_namespace_balance = testlib.get_balance(namespace_rec['address'])
    name_rec = testlib.get_name_blockchain_record('foo.test')
    name_cost = name_rec['op_fee']

    testlib.next_block( **kw )
    testlib.next_block( **kw )
    testlib.next_block( **kw )
    testlib.next_block( **kw ) # expired

    if new_namespace_balance - namespace_balance != 4*name_cost:
        print 'address {} did not get credited'.format(namespace_rec['address'])
        print '{} != {} + 4*{}'.format(new_namespace_balance, namespace_balance, name_cost)
        return False

    # preorder should send to the null burn address now.
    res = testlib.blockstack_name_preorder( "foo2.test", wallets[4].privkey, wallets[0].addr )  # does not pay to namespace
    if 'error' in res:
        print res
        return False

    # try forcing it to the namespace burn address, to verify that it fails
    res = testlib.blockstack_name_preorder( "foo_fail.test", wallets[4].privkey, wallets[0].addr, burn_addr=namespace_rec['address'], expect_fail=True)
    if 'error' not in res:
        print res
        return False

    res = testlib.blockstack_name_preorder( "foo_fail.test", wallets[4].privkey, wallets[0].addr, burn_addr=namespace_rec['address'], price={'units': 'BTC', 'amount': name_cost}, safety_checks=False, tx_fee=10000*5 ) # +name_cost
    if 'error' in res:
        print res
        return False

    testlib.next_block( **kw )

    # should be accepted
    res = testlib.blockstack_name_register( "foo2.test", wallets[4].privkey, wallets[0].addr )
    if 'error' in res:
        print res
        return False

    # should be rejected
    res = testlib.blockstack_name_register( "foo_fail.test", wallets[4].privkey, wallets[0].addr, safety_checks=False )
    if 'error' in res:
        print res
        return False

    testlib.next_block( **kw )
    testlib.expect_snv_fail_at('foo_fail.test', testlib.get_current_block(**kw))

    # should have been rejected due to wrong burn address
    whois = testlib.blockstack_cli_whois('foo_fail.test')
    if 'error' not in whois:
        print whois
        return False

    new_burn_balance = testlib.get_balance(blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS)
    new_namespace_balance = testlib.get_balance(namespace_rec['address'])
    name_rec_2 = testlib.get_name_blockchain_record('foo2.test')
    name_cost_2 = name_rec_2['op_fee']

    # namespace should NOT have gotten the fee for foo_fail.  It should only have gotten it for foo.test
    if new_namespace_balance - namespace_balance < 5*name_cost or new_namespace_balance - namespace_balance > 6*name_cost:
        print 'address {} got credited after fee capture period'.format(namespace_rec['address'])
        print '{} != {} + 5*{}'.format(new_namespace_balance, namespace_balance, name_cost)
        return False

    # burn address should have received the fee for the second name
    if new_burn_balance - name_cost_2 != burn_balance:
        print 'null burn address did not get credited'
        print '{} != {} + {}'.format(new_burn_balance, burn_balance, name_cost_2)
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

    for name in ['foo2.test']:
        # not preordered
        preorder = state_engine.get_name_preorder( name, virtualchain.make_payment_script(wallets[4].addr), wallets[0].addr )
        if preorder is not None:
            print "preorder exists"
            return False
        
        # registered 
        name_rec = state_engine.get_name( name )
        if name_rec is None:
            print "name does not exist"
            return False 

        # owned by
        if name_rec['address'] != wallets[0].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[0].addr):
            print "sender is wrong"
            return False 

    return True
