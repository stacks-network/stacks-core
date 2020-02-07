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
import json
import blockstack as blockstack_server
import blockstack

# in epoch 2 immediately, but with the old price (in order to test compatibility with 0.13)
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 682
TEST ENV BLOCKSTACK_EPOCH_2_PRICE_MULTIPLIER 1.0
"""

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
NAMESPACE_LIFETIME_MULTIPLIER = blockstack_server.get_epoch_namespace_lifetime_multiplier( blockstack_server.EPOCH_1_END_BLOCK + 1, "test" )


def test_name_count(expected_num, expected_cum_num):
    num_names = blockstack.lib.client.get_num_names(hostport='http://localhost:16264')
    num_names_cum = blockstack.lib.client.get_num_names(include_expired=True, hostport='http://localhost:16264')
    if num_names != expected_num:
        print 'wrong number of names: {}'.format(num_names)
        return False

    if num_names_cum != expected_cum_num:
        print 'wrong number of cumulative names: {}'.format(num_names_cum)
        return False

    num_names_res = testlib.blockstack_REST_call('GET', '/v1/blockchains/bitcoin/name_count', )
    if 'error' in num_names_res or num_names_res['http_status'] != 200:
        print num_names_res
        return False

    num_names = num_names_res['response']['names_count']

    num_names_cum_res = testlib.blockstack_REST_call('GET', '/v1/blockchains/bitcoin/name_count', all='True')
    if 'error' in num_names_cum_res or num_names_cum_res['http_status'] != 200:
        print num_names_cum_res
        return False

    num_names_cum = num_names_cum_res['response']['names_count']

    if num_names != expected_num:
        print 'wrong number of names from REST API: {} (expected {})'.format(num_names, expected_num)
        return False

    if num_names_cum != expected_cum_num:
        print 'wrong number of cumulative names from REST API: {} (expected {})'.format(num_names_cum, expected_cum_num)
        return False

    return True


def scenario( wallets, **kw ):

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    # NOTE: names expire in 5 * NAMESPACE_LIFETIME_MULTIPLER blocks
    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 5, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    # should be zero names, zero cumulative names 
    num_names = blockstack.lib.client.get_num_names(hostport='http://localhost:16264')
    num_names_cum = blockstack.lib.client.get_num_names(include_expired=True, hostport='http://localhost:16264')
    if num_names != 0:
        print 'wrong number of names: {}'.format(num_names)
        return False

    if num_names_cum != 0:
        print 'wrong number of cumulative names: {}'.format(num_names_cum)
        return False

    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    # should be 1 name, 1 cumulative name
    res = test_name_count(1, 1)
    if not res:
        return res

    # expire
    for i in xrange(0, 5 * NAMESPACE_LIFETIME_MULTIPLIER):
        testlib.next_block( **kw )

    testlib.next_block( **kw )

    # should be 1 name, 1 cumulative name
    res = test_name_count(0, 1)
    if not res:
        return res

    testlib.blockstack_name_preorder( "foo2.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    testlib.blockstack_name_register( "foo2.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    # should be 1 name, 2 cumulative names
    res = test_name_count(1, 2)
    if not res:
        return res

    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    # should be 2 names, 2 cumulative names
    res = test_name_count(2, 2)
    if not res:
        return res


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

    # not preordered
    preorder = state_engine.get_name_preorder( "foo.test", virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr )
    if preorder is not None:
        return False
    
    # registered
    for name in ['foo.test', 'foo2.test']:
        name_rec = state_engine.get_name(name)
        if name_rec is None:
            print 'no name: {}'.format(name)
            return False

        if name_rec['address'] != wallets[3].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[3].addr):
            print 'wrong owner'
            return False

    return True
