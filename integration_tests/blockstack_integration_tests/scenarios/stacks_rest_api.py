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
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 0, vesting={STACKS: {689: 600000, 'lock_send': 690, 'receive_whitelisted': False}}),   # not allowed to receive
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 0, vesting={STACKS: {689: 0, 'lock_send': 692, 'receive_whitelisted': True}}),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 0, vesting={STACKS: {689: 0, 'lock_send': 695, 'receive_whitelisted': True}}),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    # vest tokens 
    testlib.next_block(**kw) # end of 689

    # make sure we can query everything 
    expected_balances = [wallet._vesting_schedule[STACKS][689] for wallet in wallets] + [110000000000000, 2222222222222222, 2084166667*2]
    always_vesting = ['not_distributed_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']
    addrs_special = ['treasury', 'unallocated', 'not_distributed_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']

    addrs = [wallet.addr for wallet in wallets] + addrs_special

    for (addr, expected_balance) in zip(addrs, expected_balances):
        balance = requests.get('http://localhost:16268/v1/accounts/{}/{}/balance'.format(addr, STACKS)).json()['balance']
        assert int(balance) == expected_balance, 'balance of {} is {} but should be {}'.format(wallet.addr, balance, expected_balance)

        tokens = requests.get('http://localhost:16268/v1/accounts/{}/tokens'.format(addr)).json()['tokens']
        assert len(tokens) == 1
        assert tokens[0] == STACKS, 'invalid tokens {} for {}'.format(STACKS, addr)

        status = requests.get('http://localhost:16268/v1/accounts/{}/{}/status'.format(addr, STACKS)).json()
        assert status['address'] == addr, 'address should be {} but got {}'.format(addr, status['addr'])
        assert int(status['debit_value']) == 0, 'invalid debit value {} for {}'.format(status['debit_value'], addr)
        assert int(status['credit_value']) == expected_balance, 'invalid credit value {} (!= {}) for {}'.format(status['credit_value'], expected_balance, addr)
        assert status['type'] == STACKS, 'invalid type {} on {}\n{}'.format(status['type'], addr, status)
        assert status['vtxindex'] == 0, 'invalid vtxindex for {}\n{}'.format(addr, status)

        if addr in always_vesting:
            assert status['block_id'] == 690, 'invalid block id for {}\n{}'.format(addr, status)
        elif addr not in addrs_special:
            assert status['block_id'] == 689, 'invalid block id for {}\n{}'.format(addr, status)
        else:
            assert status['block_id'] == 688, 'invalid block id for {}\n{}'.format(addr, status)

        history = requests.get('http://localhost:16268/v1/accounts/{}/history?page=0'.format(addr)).json()
       
        if addr in always_vesting:
            assert len(history) == 3, 'should only be two history items for {}\n{}'.format(addr, history)
        elif addr not in addrs_special:
            assert len(history) == 2, 'should only be two history items for {}\n{}'.format(addr, history)
        else:
            assert len(history) == 1, 'should only be one history item for {}\n{}'.format(addr, history)
            
        assert history[0] == status, 'history[0] should match status:\n{}\n{}'.format(history[0], status)
        
        at = requests.get('http://localhost:16268/v1/accounts/{}/history/690'.format(addr)).json()
        assert len(at) == 1, 'should only have one update at 690 for {}\n{}'.format(addr, at)
        for k in ['debit_value', 'block_id', 'vtxindex', 'lock_transfer_block_id', 'address', 'type']:
            assert at[0][k] == status[k], 'account at should match status:\n{}\n{}'.format(at[0], status)

        assert int(at[0]['credit_value']) == expected_balance, 'at[0] credit value mismatch (!= {})\n{}'.format(expected_balance, at[0])


def check( state_engine ):
    return True
