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
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 680
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 681
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 2
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 2
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_GRACE_PERIOD 5
"""

import testlib
import virtualchain
import time
import json
import sys
import os
import blockstack_client

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 5500 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 5500 ),
    testlib.MultisigSegwitWallet(2, "5JfHdMq9XnZ9mwW5H6LsfVCn9u6iGAj2FCVYtfhcHn72Tphvm5P", "5JaqLZaKD7cgkfsxSZBNiu6gaFxo1XAiTXw1mhtatipNNCtZBZG", "5KNsAkiHRDZb5Yyedxov2Fncr6CcNPV52yqJbzQ8M2W6dkg2qJp"),
    testlib.MultisigSegwitWallet(2, "5JPrkpfLT3rDf1Lgm1DpA2Cfepwf9wCtEbDx1HSEdd4J2R5YMxZ", "5JiALcfvzFsKcvLnHf7ECgLdp6FxbcAXB1GPvEYP7HeigbDCQ9E", "5KScD5XL5Hj83Yjvm3u4HD78vSYwFRyq9StTLPnrWrCTGiqTvVP"),
    testlib.MultisigSegwitWallet(2, 'Ky1SXQ71uvWWbKDPGP7ZEzbY6nexcmTV8NjL3tLGm2JxXvkVsvpd', 'KzMF3Hssn6GeM4s3hWDxKXQzGjmFN42E1dBdvHc6P4AdSopE51Ki', 'L2c82atnjfYdtLSap43jMzTYSXiS2f5wrkVBwRJwRBJddaMNBUfg'),
    testlib.MultisigSegwitWallet(2, 'KwgKTD84drKBowAd3sXWeBMSixgGqGyRq3ZWikQkGWuY3j2iCbjJ', 'L47CUjK9ELreBrvmRcR6dxNQ1isCNkW8EroFTLed74qYHXHd4rRq', 'KwsxLrkNQ6o18EvThw8o8B5ihK6fLNrQbo71VxhPRg8yoeUtp5cu'),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
preorder_block = None
reveal_block = None

def scenario( wallets, **kw ):
    virtualchain.set_features('segwit', True)

    global preorder_block, reveal_block

    resp = testlib.blockstack_cli_namespace_preorder("test", wallets[5].privkey, wallets[1].privkey)
    if 'error' in resp:
        print json.dumps(resp, indent=4, sort_keys=True)
        return False

    preorder_block = testlib.get_current_block( **kw ) + 1
    testlib.next_block(**kw)

    resp = testlib.blockstack_cli_namespace_reveal('test', wallets[5].privkey, wallets[1].privkey, 52595, 250, 4, '6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0', 10, 10, version_bits=2)
    if 'error' in resp:
        print json.dumps(resp, indent=4, sort_keys=True)
        return False

    reveal_block = testlib.get_current_block( **kw ) + 1
    testlib.next_block(**kw)


def check( state_engine ):

    global reveal_block, preorder_block

    # the namespace has to have been revealed 
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is None:
        return False 

    if ns["namespace_id"] != "test":
        print "wrong namespace ID"
        return False 

    if ns["lifetime"] != 52595:
        print "wrong lifetime"
        return False 

    if ns["coeff"] != 250:
        print "wrong coeff"
        return False 

    if ns["base"] != 4:
        print "wrong base"
        return False 

    if ns["buckets"] != [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0]:
        print "wrong buckets"
        return False 

    if ns["no_vowel_discount"] != 10:
        print "wrong no-vowel discount"
        return False

    if ns["nonalpha_discount"] != 10:
        print "wrong nonalpha discount"
        return False

    if ns["reveal_block"] != reveal_block:
        print "wrong reveal block (%s)" % reveal_block
        return False 

    if ns["block_number"] != preorder_block:
        print "wrong block number"
        return False 

    return True

