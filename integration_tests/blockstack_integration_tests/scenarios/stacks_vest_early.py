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
import time
import sys
import requests
import time

STACKS = testlib.TOKEN_TYPE_STACKS

# activate tokens
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 682
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 683
TEST ENV BLOCKSTACK_EPOCH_3_END_BLOCK 700
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 1
"""

wallets = [
   testlib.Wallet(virtualchain.lib.ecdsalib.ecdsa_private_key().to_hex() + '01', 0, 
       vesting={
           STACKS: {
                690: 100000, 
                691: 100000,
                692: 100000,
                693: 100000,
                694: 100000,
                695: 100000,
                696: 100000,
                697: 100000,
                698: 100000,
                699: 100000,
                700: 100000, 
                701: 100000,
                702: 100000,
                703: 100000,
                704: 100000,
                705: 100000,
                706: 100000,
                707: 100000,
                708: 100000,
                709: 100000,
                710: 100000,
                711: 100000,
                712: 100000,
                713: 100000,
                714: 100000,
                715: 100000,
                716: 100000,
                717: 100000,
                718: 100000,
                719: 100000,
                720: 100000,
                721: 100000,
                722: 100000,
                723: 100000,
                724: 100000,
                725: 100000,
                "lock_send": 0}})
   for _ in range(0, 6)
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    for iters in range(0, 10):  # blocks 689-699

        # vest accounts
        testlib.next_block(**kw)

        # check balances
        balances = {}
        for wallet in wallets:
            info = requests.get('http://localhost:16268/v1/accounts/{}/STACKS/balance'.format(wallet.addr)).json()
            balances[wallet.addr] = {STACKS: int(info['balance'])}

        for i in range(0, len(wallets)):
            print 'wallet {} has {}'.format(wallets[i].addr, balances[wallets[i].addr][STACKS])
            assert balances[wallets[i].addr][STACKS] == (iters + 1) * 100000

        # check history and block heights
        for wallet in wallets:
            # note that this is the last block
            info = requests.get('http://localhost:16268/v1/accounts/{}/history/{}'.format(wallet.addr, testlib.get_current_block(**kw))).json()
            print 'wallet {} at {} has operations {} (iters {})'.format(wallet.addr, testlib.get_current_block(**kw), info, iters)
            assert len(info) == 1
            assert int(info[0]['credit_value']) == (iters) * 100000

        # check history at height
        for wallet in wallets:
            hist = requests.get('http://localhost:16268/v1/accounts/{}/history?page=0'.format(wallet.addr, testlib.get_current_block(**kw))).json()
            print 'wallet {} has {} history items'.format(wallet.addr, len(hist))
            print 'first: {}'.format(hist[0])
            print 'last: {}'.format(hist[-1])
            assert len(hist) == iters + 2       # includes initial history item
            assert int(hist[-1]['credit_value']) == (iters + 1) * 100000

        # can't transfer -- even though we're unlocked, the epoch isn't active yet

def check( state_engine ):
    return True
