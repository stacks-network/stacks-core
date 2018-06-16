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
        tokens_granted=0, vesting={STACKS: {689: 600000, 'lock_send': 694}}),
    testlib.MultisigWallet(2, "5JPrkpfLT3rDf1Lgm1DpA2Cfepwf9wCtEbDx1HSEdd4J2R5YMxZ", "5JiALcfvzFsKcvLnHf7ECgLdp6FxbcAXB1GPvEYP7HeigbDCQ9E", "5KScD5XL5Hj83Yjvm3u4HD78vSYwFRyq9StTLPnrWrCTGiqTvVP", tokens_granted=0),
    testlib.MultisigWallet(2, '5JPR5iVN8KGMdU9JfzoTCsipXazUcZPRY8zp7f3g8FRff2HBaAV', '5KTTwEyATY8v12MjNdoeA1u2ZGqgjnBNcyZjk3YSkiVJWYxqBSm', '5KQ1s8UEYz3oyFRUejBvb1imMdtpoP98w6NQYGxQsSo3u6DmztZ', tokens_granted=0),
    testlib.MultisigWallet(2, '5JpAkdEJuzF8E74UptksRLiB6Bf9QnwxGQutJTRWo5EAGVZfXmY', '5Hyc4wreVpZyzcfb56Zt1ymovda2xGucGZsAwoQz34iYK6aEKhR', '5JypKiQGiaD8AN6X86xtnuQYj7nnpLvp4VfcTVdDh4yFkLewAGx', tokens_granted=0),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    # will be rejected, since locked
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 100000, wallets[0].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw) # end of 689
    
    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 600000
    assert balances[wallets[1].addr][STACKS] == 0

    # will be rejected, since locked
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 200000, wallets[0].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw) # end of 690

    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 600000
    assert balances[wallets[1].addr][STACKS] == 0

    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 300000, wallets[0].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw) # end of 691

    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 600000
    assert balances[wallets[1].addr][STACKS] == 0

    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 400000, wallets[0].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw) # end of 692

    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 600000
    assert balances[wallets[1].addr][STACKS] == 0

    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 500000, wallets[0].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw) # end of 693

    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 600000
    assert balances[wallets[1].addr][STACKS] == 0

    # will succeed
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 600000, wallets[0].privkey, safety_checks=False)
    testlib.next_block(**kw) # end of 694

    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 0
    assert balances[wallets[1].addr][STACKS] == 600000


def check( state_engine ):
    return True
