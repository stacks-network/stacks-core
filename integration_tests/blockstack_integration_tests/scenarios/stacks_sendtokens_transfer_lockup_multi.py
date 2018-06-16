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

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 0, vesting={STACKS: {689: 600000, 'lock_send': 694}}),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 0 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 0, vesting={STACKS: {689: 800000, 'lock_send': 694}}),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 0, vesting={STACKS: {689: 900000, 'lock_send': 694}}),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 0, vesting={STACKS: {689: 1000000, 'lock_send': 694}}),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    # will be rejected, since locked
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 100000, wallets[0].privkey, safety_checks=False, expect_fail=True)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 100000, wallets[2].privkey, safety_checks=False, expect_fail=True)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 100000, wallets[3].privkey, safety_checks=False, expect_fail=True)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 100000, wallets[4].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw) # end of 689
    
    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 600000
    assert balances[wallets[2].addr][STACKS] == 800000
    assert balances[wallets[3].addr][STACKS] == 900000
    assert balances[wallets[4].addr][STACKS] == 1000000
    assert balances[wallets[1].addr][STACKS] == 0

    # will be rejected, since locked
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 200000, wallets[0].privkey, safety_checks=False, expect_fail=True)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 200000, wallets[2].privkey, safety_checks=False, expect_fail=True)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 200000, wallets[3].privkey, safety_checks=False, expect_fail=True)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 200000, wallets[4].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw) # end of 690

    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 600000
    assert balances[wallets[2].addr][STACKS] == 800000
    assert balances[wallets[3].addr][STACKS] == 900000
    assert balances[wallets[4].addr][STACKS] == 1000000
    assert balances[wallets[1].addr][STACKS] == 0

    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 300000, wallets[0].privkey, safety_checks=False, expect_fail=True)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 300000, wallets[2].privkey, safety_checks=False, expect_fail=True)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 300000, wallets[3].privkey, safety_checks=False, expect_fail=True)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 300000, wallets[4].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw) # end of 691

    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 600000
    assert balances[wallets[2].addr][STACKS] == 800000
    assert balances[wallets[3].addr][STACKS] == 900000
    assert balances[wallets[4].addr][STACKS] == 1000000
    assert balances[wallets[1].addr][STACKS] == 0

    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 400000, wallets[0].privkey, safety_checks=False, expect_fail=True)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 400000, wallets[2].privkey, safety_checks=False, expect_fail=True)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 400000, wallets[3].privkey, safety_checks=False, expect_fail=True)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 400000, wallets[4].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw) # end of 692

    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 600000
    assert balances[wallets[2].addr][STACKS] == 800000
    assert balances[wallets[3].addr][STACKS] == 900000
    assert balances[wallets[4].addr][STACKS] == 1000000
    assert balances[wallets[1].addr][STACKS] == 0

    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 500000, wallets[0].privkey, safety_checks=False, expect_fail=True)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 500000, wallets[2].privkey, safety_checks=False, expect_fail=True)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 500000, wallets[3].privkey, safety_checks=False, expect_fail=True)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 500000, wallets[4].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw) # end of 693

    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 600000
    assert balances[wallets[2].addr][STACKS] == 800000
    assert balances[wallets[3].addr][STACKS] == 900000
    assert balances[wallets[4].addr][STACKS] == 1000000

    # will succeed
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 600000, wallets[0].privkey, safety_checks=False)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 800000, wallets[2].privkey, safety_checks=False)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 900000, wallets[3].privkey, safety_checks=False)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 1000000, wallets[4].privkey, safety_checks=False)
    testlib.next_block(**kw) # end of 694

    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 0
    assert balances[wallets[1].addr][STACKS] == 600000 + 800000 + 900000 + 1000000
    assert balances[wallets[2].addr][STACKS] == 0
    assert balances[wallets[3].addr][STACKS] == 0
    assert balances[wallets[4].addr][STACKS] == 0



def check( state_engine ):
    return True
