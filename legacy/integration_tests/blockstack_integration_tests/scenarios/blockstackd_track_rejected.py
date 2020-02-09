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
import requests
import json

# activate tokens and stuff
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 682
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 683
TEST ENV BLOCKSTACK_EPOCH_3_END_BLOCK 684
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_DB_SAVE_REJECTED 1
"""

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def test_failed_tx(txid, op):
    resp = requests.get('http://localhost:16268/v1/blockchains/bitcoin/transactions/{}'.format(txid)).json()
    assert resp['tx']['status'] == 'rejected', json.dumps(resp)
    assert resp['tx']['op'] == op, json.dumps(resp)
    
def scenario( wallets, **kw ):
   
    testlib.disable_snv_checks()
    testlib.disable_did_checks()

    # make failed transactions
    resp = testlib.blockstack_namespace_preorder("test2", wallets[1].addr, wallets[0].privkey, consensus_hash='00000000000000000000000000000000', safety_checks=False, expect_fail=True)
    testlib.next_block( **kw )

    test_failed_tx(resp['transaction_hash'], 'NAMESPACE_PREORDER')

    resp = testlib.blockstack_namespace_reveal( "test2", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=blockstack.NAMESPACE_VERSION_PAY_WITH_STACKS, safety_checks=False, expect_fail=True)
    testlib.next_block( **kw )
    
    test_failed_tx(resp['transaction_hash'], 'NAMESPACE_REVEAL')

    resp = testlib.blockstack_namespace_ready( "test2", wallets[1].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block( **kw )
    
    test_failed_tx(resp['transaction_hash'], 'NAMESPACE_READY')
   
    # okay, go and actually create this namespace so we can preorder names 
    testlib.blockstack_namespace_preorder("test", wallets[1].addr, wallets[0].privkey)
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=blockstack.NAMESPACE_VERSION_PAY_WITH_STACKS)
    testlib.next_block( **kw )
    
    testlib.blockstack_namespace_ready( "test", wallets[1].privkey)
    testlib.next_block( **kw )

    # start failing again
    resp = testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr, consensus_hash='00000000000000000000000000000000', safety_checks=False, expect_fail=True)
    testlib.next_block( **kw )
    
    test_failed_tx(resp['transaction_hash'], 'NAME_PREORDER')

    resp = testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr, safety_checks=False, expect_fail=True)
    testlib.next_block( **kw )
    
    test_failed_tx(resp['transaction_hash'], 'NAME_REGISTRATION')

    resp = testlib.blockstack_name_update( "foo.test", "11" * 20, wallets[3].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block( **kw )
    
    test_failed_tx(resp['transaction_hash'], 'NAME_UPDATE')
    
    resp = testlib.blockstack_name_transfer("foo.test", wallets[0].addr, True, wallets[3].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw)
    
    test_failed_tx(resp['transaction_hash'], 'NAME_TRANSFER')

    resp = testlib.blockstack_name_renew("foo.test", wallets[3].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw)
    
    test_failed_tx(resp['transaction_hash'], 'NAME_REGISTRATION')

    resp = testlib.blockstack_name_revoke("foo.test", wallets[3].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw)
    
    test_failed_tx(resp['transaction_hash'], 'NAME_REVOKE')

    resp = testlib.blockstack_send_tokens(wallets[0].addr, 'STACKS', 123, wallets[3].privkey, consensus_hash='11111111111111111111111111111111', safety_checks=False, expect_fail=True)
    testlib.next_block(**kw)

    test_failed_tx(resp['transaction_hash'], 'TOKEN_TRANSFER')

    resp = testlib.blockstack_announce("hello world", wallets[0].privkey, safety_checks=False, expect_fail=True)
    testlib.next_block(**kw)

    test_failed_tx(resp['transaction_hash'], 'ANNOUNCE')

def check( state_engine ):
    return True
