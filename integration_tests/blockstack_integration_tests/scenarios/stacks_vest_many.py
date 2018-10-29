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
TEST ENV BLOCKSTACK_EPOCH_3_END_BLOCK 684
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_TEST_AMOUNT_PER_WALLET 0
"""

print >> sys.stderr, 'Instantiating 6000 wallets...'
sys.stderr.flush()

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
                726: 100000,
                "lock_send": 694}})
   for _ in range(0, 2000)
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    testlib.set_account_audits(False)
    
    times = []

    for i in range(690, 726):
        t1 = time.time()

        # vest accounts
        testlib.next_block(**kw)

        t2 = time.time()
        times.append(t2 - t1)

    balances = {}
    for wallet in wallets:
        info = requests.get('http://localhost:16268/v1/accounts/{}/STACKS/balance'.format(wallet.addr)).json()
        balances[wallet.addr] = {STACKS: int(info['balance'])}

    for i in range(0, len(wallets)):
        assert balances[wallets[i].addr][STACKS] == 3600000

    avg = sum(times) / len(times)
    times.sort()
    med = times[len(times)/2]
    _90th = times[(len(times) * 9) / 10]
    _95th = times[(len(times) * 95) / 100]
    _99th = times[(len(times) * 99) / 100]

    print ''
    print 'avg time to vest: {}'.format(avg)
    print 'med time to vest: {}'.format(med)
    print '90% time to vest: {}'.format(_90th)
    print '95% time to vest: {}'.format(_95th)
    print '99% time to vest: {}'.format(_99th)
    print ''

    sys.stdout.flush()

    time.sleep(60)

def check( state_engine ):
    return True
