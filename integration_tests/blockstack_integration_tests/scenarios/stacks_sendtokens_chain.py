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
import requests

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
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 1000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 0 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 0 ),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    # pass 100 stacks around in a circle.
    new_keys = [wallets[0].privkey] + [virtualchain.lib.ecdsalib.ecdsa_private_key().to_hex() for i in range(0, 3)]
    for i in range(0, 3 * len(new_keys)):

        new_addr = virtualchain.get_privkey_address(new_keys[(i+1) % len(new_keys)])
        cur_addr = virtualchain.get_privkey_address(new_keys[i % len(new_keys)])

        initial_new_balance_info = json.loads(testlib.nodejs_cli('balance', new_addr))
        initial_cur_balance_info = json.loads(testlib.nodejs_cli('balance', cur_addr))

        print '\n initial new balance info: {} \n'.format(initial_new_balance_info)

        if 'STACKS' not in initial_new_balance_info:
            initial_new_balance_info['STACKS'] = 0

        if i > 0:
            testlib.send_funds(wallets[0].privkey, 800000, cur_addr)

        testlib.send_funds(wallets[0].privkey, 800000, new_addr)

        testlib.blockstack_send_tokens(new_addr, 'STACKS', 100, new_keys[i % len(new_keys)])
        testlib.next_block(**kw)

        balance_info = json.loads(testlib.nodejs_cli('balance', new_addr))
        assert int(balance_info['STACKS']) == 100 + int(initial_new_balance_info['STACKS'])
        
        if (i + 1) % len(new_keys) != 0:
            assert int(balance_info['STACKS']) == 100

        balance_info = json.loads(testlib.nodejs_cli('balance', cur_addr))
        assert int(balance_info['STACKS']) == int(initial_cur_balance_info['STACKS']) - 100

        if i % len(new_keys) != 0:
            assert int(balance_info['STACKS']) == 0

    # each *new* address has 6 history items -- three spends, three receives
    for new_key in new_keys[1:]:
        new_addr = virtualchain.get_privkey_address(new_key)
        history = requests.get('http://localhost:16268/v1/accounts/{}/history?page=0'.format(new_addr)).json()

        # should have gotten 3 debits for 100, and 3 credits for 100
        assert int(history[0]['credit_value']) == 300, history
        assert int(history[0]['debit_value']) == 300, history

        assert len(history) == 6, history

def check( state_engine ):
    return True
