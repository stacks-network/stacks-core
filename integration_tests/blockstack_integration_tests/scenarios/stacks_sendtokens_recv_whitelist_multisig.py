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
    testlib.MultisigWallet(2, "5JfHdMq9XnZ9mwW5H6LsfVCn9u6iGAj2FCVYtfhcHn72Tphvm5P", "5JaqLZaKD7cgkfsxSZBNiu6gaFxo1XAiTXw1mhtatipNNCtZBZG", "5KNsAkiHRDZb5Yyedxov2Fncr6CcNPV52yqJbzQ8M2W6dkg2qJp",
        tokens_granted=0, vesting={STACKS: {689: 600000, 'lock_send': 690, 'receive_whitelisted': False}}),   # not allowed to receive

    testlib.MultisigWallet(2, "5JPrkpfLT3rDf1Lgm1DpA2Cfepwf9wCtEbDx1HSEdd4J2R5YMxZ", "5JiALcfvzFsKcvLnHf7ECgLdp6FxbcAXB1GPvEYP7HeigbDCQ9E", "5KScD5XL5Hj83Yjvm3u4HD78vSYwFRyq9StTLPnrWrCTGiqTvVP",
        tokens_granted=0, vesting={STACKS: {689: 0, 'lock_send': 692, 'receive_whitelisted': True}}),

    testlib.MultisigWallet(2, '5JPR5iVN8KGMdU9JfzoTCsipXazUcZPRY8zp7f3g8FRff2HBaAV', '5KTTwEyATY8v12MjNdoeA1u2ZGqgjnBNcyZjk3YSkiVJWYxqBSm', '5KQ1s8UEYz3oyFRUejBvb1imMdtpoP98w6NQYGxQsSo3u6DmztZ',
        tokens_granted=0, vesting={STACKS: {689: 0, 'lock_send': 695, 'receive_whitelisted': True}}),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    # will be rejected, since locked
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 100000, wallets[0].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw) # end of 689
    
    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 600000
    assert balances[wallets[1].addr][STACKS] == 0
    assert balances[wallets[2].addr][STACKS] == 0

    # will succeed, since whitelisted
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 100000, wallets[0].privkey, safety_checks=False)  # need to disable safety checks since it's "currently" block 690
    testlib.next_block(**kw) # end of 690

    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 500000
    assert balances[wallets[1].addr][STACKS] == 100000
    assert balances[wallets[2].addr][STACKS] == 0

    # try to send back (will fail since its locked)
    testlib.blockstack_send_tokens(wallets[0].addr, "STACKS", 100000, wallets[1].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw) # end of 691

    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 500000
    assert balances[wallets[1].addr][STACKS] == 100000
    assert balances[wallets[2].addr][STACKS] == 0

    # try to send back (will fail since the address is not whitelisted)
    testlib.blockstack_send_tokens(wallets[0].addr, "STACKS", 100000, wallets[1].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw) # end of 692

    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 500000
    assert balances[wallets[1].addr][STACKS] == 100000
    assert balances[wallets[2].addr][STACKS] == 0

    # send to wallets[2] (should succeed)
    testlib.blockstack_send_tokens(wallets[2].addr, "STACKS", 50000, wallets[1].privkey, safety_checks=False)   # need to disable safety checks since it's "currently" block 692
    testlib.next_block(**kw) # end of 693

    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 500000
    assert balances[wallets[1].addr][STACKS] == 50000
    assert balances[wallets[2].addr][STACKS] == 50000

    # send to wallets[1] (should fail since locked)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 50000, wallets[2].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw) # end of 694

    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 500000
    assert balances[wallets[1].addr][STACKS] == 50000
    assert balances[wallets[2].addr][STACKS] == 50000

    # send to wallets[1] (should succeed now)
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 50000, wallets[2].privkey, safety_checks=False)
    testlib.next_block(**kw) # end of 695

    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 500000
    assert balances[wallets[1].addr][STACKS] == 100000
    assert balances[wallets[2].addr][STACKS] == 0


def check( state_engine ):
    return True
