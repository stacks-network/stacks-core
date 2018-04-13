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

VESTING_AMOUNT = 10000000000

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000, vesting={STACKS: {694: VESTING_AMOUNT}}),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def get_wallet_balances(wallets):
    balances = {}
    for w in wallets:
       balance_info = json.loads(testlib.nodejs_cli('balance', w.addr))
       for token_type in balance_info:
           balance_info[token_type] = int(balance_info[token_type])

       balances[w.addr] = balance_info

    return balances

def scenario( wallets, **kw ):

    # check initial balances 
    initial_balances = get_wallet_balances(wallets) 

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )  # end 689 

    # balance should have decreased by namespace cost.  No other wallets should be affected
    # TODO check all other balances
    namespace_price_info = json.loads(testlib.nodejs_cli('price_namespace', 'test'))
    assert namespace_price_info['units'] == STACKS
    namespace_cost = int(namespace_price_info['amount'])

    balances = get_wallet_balances(wallets)
    assert initial_balances[wallets[0].addr][STACKS] - namespace_cost == balances[wallets[0].addr][STACKS], \
            'Balance mismatch: Expected {}, got {} for {}'.format(initial_balances[wallets[0].addr][STACKS] - namespace_cost, balances[wallets[0].addr][STACKS], wallets[0].addr)

    for i in range(1, len(wallets)):
        assert initial_balances[wallets[i].addr][STACKS] == balances[wallets[i].addr][STACKS], \
            'Balance of {} changed!'.format(wallets[i].addr)

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=blockstack.NAMESPACE_VERSION_PAY_WITH_STACKS )
    testlib.next_block( **kw )  # end 690

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )  # end 691

    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )  # end 692

    # balance should have decreased by stacks token amount
    name_price_info = json.loads(testlib.nodejs_cli('price', 'foo.test'))
    assert namespace_price_info['units'] == STACKS
    name_cost = int(name_price_info['amount'])

    balances = get_wallet_balances(wallets)
    assert initial_balances[wallets[2].addr][STACKS] - name_cost == balances[wallets[2].addr][STACKS], \
            'Balance mismatch: Expected {}, got {} for {}'.format(initial_balances[wallets[2].addr][STACKS] - name_cost, balances[wallets[2].addr][STACKS], wallets[2].addr)

    for i in [1] + range(3, len(wallets)):
        assert initial_balances[wallets[i].addr][STACKS] == balances[wallets[i].addr][STACKS], \
            'Balance of {} changed!'.format(wallets[i].addr)

    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )

    assert initial_balances[wallets[1].addr][STACKS] == balances[wallets[1].addr][STACKS], \
            'Balance mismatch: Expected {} NOT to vest to {} (got {})'.format(wallets[1].addr, initial_balances[wallets[1].addr][STACKS], balances[wallets[1].addr][STACKS])
    
    # vesting should happen
    testlib.next_block( **kw )  # end 693

    balances = get_wallet_balances([wallets[1]])
    assert initial_balances[wallets[1].addr][STACKS] + VESTING_AMOUNT == balances[wallets[1].addr][STACKS], \
            'Balance mismatch: Expected {} to vest to {} (got {})'.format(wallets[1].addr, initial_balances[wallets[1].addr][STACKS] + VESTING_AMOUNT, balances[wallets[1].addr][STACKS])




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
    
    # registered 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        print "name does not exist"
        return False 

    # owned by
    if name_rec['address'] != wallets[3].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[3].addr):
        print "sender is wrong"
        return False 

    return True
