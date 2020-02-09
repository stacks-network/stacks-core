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
    new_keys = [wallets[0].privkey] + [virtualchain.lib.ecdsalib.ecdsa_private_key().to_hex() for i in range(0, 4)]
    for k in range(0, 4):
        for j in range(0, len(new_keys)):
            i = j

            new_addr = virtualchain.get_privkey_address(new_keys[(i+1) % len(new_keys)])
            cur_addr = virtualchain.get_privkey_address(new_keys[i % len(new_keys)])

            initial_new_balance_info = json.loads(testlib.nodejs_cli('balance', new_addr))
            initial_cur_balance_info = json.loads(testlib.nodejs_cli('balance', cur_addr))

            print '\n initial new balance info: {} \n'.format(initial_new_balance_info)

            if 'STACKS' not in initial_new_balance_info:
                initial_new_balance_info['STACKS'] = 0

            if i > 0:
                testlib.send_funds(wallets[0].privkey, 500000, cur_addr)

            testlib.send_funds(wallets[0].privkey, 500000, new_addr)

            testlib.blockstack_send_tokens(new_addr, 'STACKS', 100, new_keys[i % len(new_keys)], safety_checks=False)

            # consolidate
            utxos = testlib.get_utxos(wallets[0].addr)
            if len(utxos) > 1:
                balance = testlib.get_balance(wallets[0].addr)
                testlib.send_funds(wallets[0].privkey, balance - 5500, wallets[0].addr, change=False)
            
            utxos = testlib.get_utxos(new_addr)
            if len(utxos) > 1:
                balance = testlib.get_balance(new_addr)
                testlib.send_funds(new_keys[(i+1) % len(new_keys)], balance - 5500, new_addr, change=False)

        testlib.next_block(**kw)

        for j in range(0, len(new_keys)):
            i = j
       
            new_addr = virtualchain.get_privkey_address(new_keys[(i+1) % len(new_keys)])
            cur_addr = virtualchain.get_privkey_address(new_keys[i % len(new_keys)])

            if j == len(new_keys) - 1:
                if (i + 1) % len(new_keys) != 0:
                    # last address should have 100 stacks, unless new_addr is wallets[0]
                    balance_info = json.loads(testlib.nodejs_cli('balance', new_addr))
                    assert int(balance_info['STACKS']) == 100

            else:
                if i % len(new_keys) != 0:
                    # every other address, except wallets[0], should have 0 balance
                    balance_info = json.loads(testlib.nodejs_cli('balance', cur_addr))
                    assert int(balance_info['STACKS']) == 0

        # consolidate
        for j in range(0, len(new_keys)):
            cur_addr = virtualchain.get_privkey_address(new_keys[i % len(new_keys)])
            utxos = testlib.get_utxos(cur_addr)
            if len(utxos) > 1:
                balance = testlib.get_balance(cur_addr)
                testlib.send_funds(new_keys[i % len(new_keys)], balance - 5500, cur_addr, change=False)

        testlib.next_block(**kw)

    # each *new* address has 4 history items -- four spends, four receives
    for new_key in new_keys[1:]:
        new_addr = virtualchain.get_privkey_address(new_key)
        history = requests.get('http://localhost:16268/v1/accounts/{}/history?page=0'.format(new_addr)).json()

        # should have gotten 4 debits for 100, and 4 credits for 100
        assert int(history[0]['credit_value']) == 400, history
        assert int(history[0]['debit_value']) == 400, history

        assert len(history) == 8, history

def check( state_engine ):
    return True
