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
import time
import json
import sys
import os
import blockstack_client
import virtualchain

# activate multisig
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 692
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
"""

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.MultisigWallet(2, "5JfHdMq9XnZ9mwW5H6LsfVCn9u6iGAj2FCVYtfhcHn72Tphvm5P", "5JaqLZaKD7cgkfsxSZBNiu6gaFxo1XAiTXw1mhtatipNNCtZBZG", "5KNsAkiHRDZb5Yyedxov2Fncr6CcNPV52yqJbzQ8M2W6dkg2qJp"),
    testlib.MultisigWallet(2, "5JPrkpfLT3rDf1Lgm1DpA2Cfepwf9wCtEbDx1HSEdd4J2R5YMxZ", "5JiALcfvzFsKcvLnHf7ECgLdp6FxbcAXB1GPvEYP7HeigbDCQ9E", "5KScD5XL5Hj83Yjvm3u4HD78vSYwFRyq9StTLPnrWrCTGiqTvVP"),
    testlib.MultisigWallet(2, '5JPR5iVN8KGMdU9JfzoTCsipXazUcZPRY8zp7f3g8FRff2HBaAV', '5KTTwEyATY8v12MjNdoeA1u2ZGqgjnBNcyZjk3YSkiVJWYxqBSm', '5KQ1s8UEYz3oyFRUejBvb1imMdtpoP98w6NQYGxQsSo3u6DmztZ'),
    testlib.MultisigWallet(2, '5JpAkdEJuzF8E74UptksRLiB6Bf9QnwxGQutJTRWo5EAGVZfXmY', '5Hyc4wreVpZyzcfb56Zt1ymovda2xGucGZsAwoQz34iYK6aEKhR', '5JypKiQGiaD8AN6X86xtnuQYj7nnpLvp4VfcTVdDh4yFkLewAGx')
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )
    
    # should fail if either are multisig
    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[3].privkey, wallets[0].privkey, wallets[1].privkey, exception=False )
    if 'error' not in wallet:
        print "wallet initialized\n%s" % json.dumps(wallet, indent=4, sort_keys=True)
        return False

    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[0].privkey, wallets[4].privkey, wallets[1].privkey, exception=False )
    if 'error' not in wallet:
        print "wallet initialized\n%s" % json.dumps(wallet, indent=4, sort_keys=True)
        return False

    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[3].privkey, wallets[4].privkey, wallets[1].privkey, exception=False )
    if 'error' not in wallet:
        print "wallet initialized\n%s" % json.dumps(wallet, indent=4, sort_keys=True)
        return False

    # should fail if data key is multisig
    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[0].privkey, wallets[1].privkey, wallets[3].privkey, exception=False )
    if 'error' not in wallet:
        print "wallet initialized\n%s" % json.dumps(wallet, indent=4, sort_keys=True)
        return False

    # should succeed 
    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[0].privkey, wallets[1].privkey, wallets[1].privkey, exception=False )
    if 'error' in wallet:
        print "wallet failure: %s" % wallet['error']
        return False

    # next epoch
    testlib.next_block(**kw)
    testlib.next_block(**kw)

    # multisig should now be supported
    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[3].privkey, wallets[0].privkey, wallets[1].privkey, exception=False )
    if 'error' in wallet:
        print "wallet failure: %s" % wallet['error']
        return False

    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[0].privkey, wallets[4].privkey, wallets[1].privkey, exception=False )
    if 'error' in wallet:
        print "wallet failure: %s" % wallet['error']
        return False

    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[3].privkey, wallets[4].privkey, wallets[1].privkey, exception=False )
    if 'error' in wallet:
        print "wallet failure: %s" % wallet['error']
        return False

    # should fail if data key is multisig
    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[0].privkey, wallets[1].privkey, wallets[3].privkey, exception=False )
    if 'error' not in wallet:
        print "wallet initialized\n%s" % json.dumps(wallet, indent=4, sort_keys=True)
        return False

    # should succeed 
    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[0].privkey, wallets[1].privkey, wallets[1].privkey, exception=False )
    if 'error' in wallet:
        print "wallet failure: %s" % wallet['error']
        return False



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
    
    return True
