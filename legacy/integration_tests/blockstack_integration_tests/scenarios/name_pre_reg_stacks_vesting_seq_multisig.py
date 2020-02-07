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

VESTING_AMOUNT = 2**63 - 1

wallets = [
    testlib.MultisigWallet(2, "5JfHdMq9XnZ9mwW5H6LsfVCn9u6iGAj2FCVYtfhcHn72Tphvm5P", "5JaqLZaKD7cgkfsxSZBNiu6gaFxo1XAiTXw1mhtatipNNCtZBZG", "5KNsAkiHRDZb5Yyedxov2Fncr6CcNPV52yqJbzQ8M2W6dkg2qJp", tokens_granted=100000000000, vesting={
        STACKS: {
            690: VESTING_AMOUNT + 1,
            692: VESTING_AMOUNT + 1,
            694: VESTING_AMOUNT + 1,
            696: VESTING_AMOUNT + 1,
            698: VESTING_AMOUNT + 1}}),
    testlib.MultisigWallet(2, "5JPrkpfLT3rDf1Lgm1DpA2Cfepwf9wCtEbDx1HSEdd4J2R5YMxZ", "5JiALcfvzFsKcvLnHf7ECgLdp6FxbcAXB1GPvEYP7HeigbDCQ9E", "5KScD5XL5Hj83Yjvm3u4HD78vSYwFRyq9StTLPnrWrCTGiqTvVP", tokens_granted=100000000000, vesting={
        STACKS: {
            690: VESTING_AMOUNT * 2,
            692: VESTING_AMOUNT * 2,
            694: VESTING_AMOUNT * 2,
            696: VESTING_AMOUNT * 2,
            698: VESTING_AMOUNT * 2}}),
    testlib.MultisigWallet(2, '5JPR5iVN8KGMdU9JfzoTCsipXazUcZPRY8zp7f3g8FRff2HBaAV', '5KTTwEyATY8v12MjNdoeA1u2ZGqgjnBNcyZjk3YSkiVJWYxqBSm', '5KQ1s8UEYz3oyFRUejBvb1imMdtpoP98w6NQYGxQsSo3u6DmztZ', tokens_granted=100000000000, vesting={
        STACKS: {
            690: VESTING_AMOUNT * 3,
            692: VESTING_AMOUNT * 3,
            694: VESTING_AMOUNT * 3,
            696: VESTING_AMOUNT * 3,
            698: VESTING_AMOUNT * 3}}),
    testlib.MultisigWallet(2, '5JpAkdEJuzF8E74UptksRLiB6Bf9QnwxGQutJTRWo5EAGVZfXmY', '5Hyc4wreVpZyzcfb56Zt1ymovda2xGucGZsAwoQz34iYK6aEKhR', '5JypKiQGiaD8AN6X86xtnuQYj7nnpLvp4VfcTVdDh4yFkLewAGx', tokens_granted=100000000000, vesting={
        STACKS: {
            690: VESTING_AMOUNT * 4,
            692: VESTING_AMOUNT * 4,
            694: VESTING_AMOUNT * 4,
            696: VESTING_AMOUNT * 4,
            698: VESTING_AMOUNT * 4}}),
    testlib.MultisigWallet(2, '5KXzk8m7sfVEciwwtb5DTBNMrHFBgn8wEWtfyi3KPNjQazWyF3e', '5JDy1qYj2no1SSXMsn8suPP6gMVofLjCR5Qfz44KB2VM6Kd2EKq', '5KBpBME2Rk7gjxoYxaB1JBrumS9zk5U6GYNRyG6BX4KzP8aovwP', tokens_granted=100000000000, vesting={
        STACKS: {
            690: VESTING_AMOUNT * 5,
            692: VESTING_AMOUNT * 5,
            694: VESTING_AMOUNT * 5,
            696: VESTING_AMOUNT * 5,
            698: VESTING_AMOUNT * 5}}),
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
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

    testlib.blockstack_namespace_preorder( "test", wallets[5].addr, wallets[0].privkey )
    testlib.next_block( **kw )  # end 689 

    # balance should have decreased by namespace cost.  No other wallets should be affected
    namespace_price_info = json.loads(testlib.nodejs_cli('price_namespace', 'test'))
    assert namespace_price_info['units'] == STACKS
    namespace_cost = int(namespace_price_info['amount'])

    testlib.blockstack_namespace_reveal( "test", wallets[5].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=blockstack.NAMESPACE_VERSION_PAY_WITH_STACKS )
    testlib.next_block( **kw )  # end 690 (vested!)

    testlib.blockstack_namespace_ready( "test", wallets[5].privkey )
    testlib.next_block( **kw )  # end 691

    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )  # end 692 (vested!)

    # balance should have decreased by stacks token amount
    name_price_info = json.loads(testlib.nodejs_cli('price', 'foo.test'))
    assert namespace_price_info['units'] == STACKS
    name_cost = int(name_price_info['amount'])

    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )

    # vesting should happen
    testlib.next_block( **kw )  # end 693
    testlib.next_block( **kw )  # end 694 (vested!)

    for i in range(0,2):
        balances = get_wallet_balances(wallets)
        expected_balances = {
            wallets[0].addr: {STACKS: initial_balances[wallets[0].addr][STACKS] - namespace_cost + (VESTING_AMOUNT + 1) * (3 + i)},
            wallets[1].addr: {STACKS: initial_balances[wallets[1].addr][STACKS] + (VESTING_AMOUNT  * 2) * (3 + i)},
            wallets[2].addr: {STACKS: initial_balances[wallets[2].addr][STACKS] - name_cost + (VESTING_AMOUNT * 3) * (3 + i)},
            wallets[3].addr: {STACKS: initial_balances[wallets[3].addr][STACKS] + (VESTING_AMOUNT  * 4) * (3 + i)},
            wallets[4].addr: {STACKS: initial_balances[wallets[4].addr][STACKS] + (VESTING_AMOUNT  * 5) * (3 + i)},
            wallets[5].addr: {STACKS: initial_balances[wallets[5].addr][STACKS]},
        }

        for j in range(0, len(wallets)):
            w = wallets[j]
            assert expected_balances[w.addr][STACKS] == balances[w.addr][STACKS], 'Balance mismatch on wallet {} {}\'s {}: expected:\n{}, got:\n{}'.format(
                    j, w.addr, STACKS,
                    json.dumps(expected_balances[w.addr][STACKS], indent=4, sort_keys=True),
                    json.dumps(balances[w.addr][STACKS], indent=4, sort_keys=True))

        testlib.next_block(**kw)
        testlib.next_block(**kw) #vested!
    

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
