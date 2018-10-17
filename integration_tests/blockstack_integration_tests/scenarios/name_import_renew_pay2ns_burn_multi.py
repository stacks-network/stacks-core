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
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_RECEIVE_FEES_PERIOD 4
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

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=2)
    testlib.next_block( **kw )

    resp = testlib.blockstack_name_import( "foo.test", wallets[3].addr, "11" * 20, wallets[1].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    namespace_rec = testlib.blockstack_cli_get_namespace_blockchain_record("test")
    if 'error' in namespace_rec:
        print namespace_rec
        return False

    namespace_balance = testlib.get_balance(namespace_rec['address'])
    burn_balance = testlib.get_balance(blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS)

    # should send to namespace burn address
    res = testlib.blockstack_name_renew('foo.test', wallets[3].privkey)
    if 'error' in res:
        print res
        return False

    testlib.next_block(**kw)

    # should send to namespace burn address
    res = testlib.blockstack_name_renew('foo.test', wallets[3].privkey)
    if 'error' in res:
        print res
        return False

    testlib.next_block(**kw)

    new_namespace_balance = testlib.get_balance(namespace_rec['address'])
    name_rec = testlib.get_name_blockchain_record('foo.test')
    name_cost = name_rec['op_fee']

    if new_namespace_balance - namespace_balance != 2*name_cost:
        print 'address {} did not get credited'.format(namespace_rec['address'])
        print '{} != {} + {}'.format(new_namespace_balance, namespace_balance, name_cost)
        return False

    # should be rejected if not burned
    res = testlib.blockstack_name_renew('foo.test', wallets[3].privkey, burn_addr=namespace_rec['address'], expect_fail=True)
    if 'error' not in res:
        print res
        return False

    res = testlib.blockstack_name_renew('foo.test', wallets[3].privkey, burn_addr=namespace_rec['address'], safety_checks=False, tx_fee=10000*5)
    if 'error' in res:
        print res
        return False

    testlib.next_block(**kw)

    # should have been rejected
    name_rec_2 = testlib.get_name_blockchain_record('foo.test')
    if name_rec_2['last_renewed'] != name_rec['last_renewed']:
        print 'accidentally renewed'
        return False

    # renew, but correctly (with proper burn address)
    res = testlib.blockstack_name_renew('foo.test', wallets[3].privkey)
    if 'error' in res:
        print res
        return False

    testlib.next_block(**kw)

    name_rec_2 = testlib.get_name_blockchain_record('foo.test')
    if name_rec_2['last_renewed'] <= name_rec['last_renewed']:
        print 'did not renew'
        return False

    # must have burned
    new_burn_balance = testlib.get_balance(blockstack.lib.config.BLOCKSTACK_BURN_ADDRESS)
    if new_burn_balance - name_cost != burn_balance:
        print 'did not burn fee'
        print '{} != {} + {}'.format(new_burn_balance, burn_balance, name_cost)
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

    for name in ['foo.test']:
        # not preordered
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
