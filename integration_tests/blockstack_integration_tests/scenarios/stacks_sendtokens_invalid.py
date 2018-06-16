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
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 0, vesting={STACKS: {689: 600000, 'lock_send': 690, 'receive_whitelisted': False}}),   # not allowed to receive
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 0, vesting={STACKS: {689: 0, 'lock_send': 692, 'receive_whitelisted': True}}),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 0, vesting={STACKS: {689: 0, 'lock_send': 695, 'receive_whitelisted': True}}),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    # try to spend tokens to ourselves
    testlib.blockstack_send_tokens(wallets[0].addr, "STACKS", 100000, wallets[0].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw) # end of 689

    assert virtualchain.lib.indexer.StateEngine.get_block_statistics(testlib.get_current_block(**kw))['num_processed_ops'] == 0

    # try to spend more tokens than we have 
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 600001, wallets[0].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw)

    assert virtualchain.lib.indexer.StateEngine.get_block_statistics(testlib.get_current_block(**kw))['num_processed_ops'] == 0

    # try to spend tokens that don't exist
    testlib.blockstack_send_tokens(wallets[1].addr, "noop", 600000, wallets[0].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw)

    assert virtualchain.lib.indexer.StateEngine.get_block_statistics(testlib.get_current_block(**kw))['num_processed_ops'] == 0
   
    # try to spend tokens with an invalid consensus hash
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 600000, wallets[0].privkey, consensus_hash='00' * 16, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw)
    
    assert virtualchain.lib.indexer.StateEngine.get_block_statistics(testlib.get_current_block(**kw))['num_processed_ops'] == 0

    # try to spend tokens from an account that doesn't exist
    pk = virtualchain.lib.ecdsalib.ecdsa_private_key().to_hex()
    addr = virtualchain.address_reencode(virtualchain.get_privkey_address(pk))
    testlib.send_funds(wallets[0].privkey, 10240000, addr)

    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 100000, pk, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw)

    assert virtualchain.lib.indexer.StateEngine.get_block_statistics(testlib.get_current_block(**kw))['num_processed_ops'] == 0

    # try to send 0 tokens
    testlib.blockstack_send_tokens(wallets[1].addr, "STACKS", 0, wallets[0].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw)

    assert virtualchain.lib.indexer.StateEngine.get_block_statistics(testlib.get_current_block(**kw))['num_processed_ops'] == 0


def check( state_engine ):
    return True
