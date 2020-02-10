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
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 694
"""

import testlib
import virtualchain
import blockstack as blockstack_server
import virtualchain 

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.MultisigWallet( 2, "5JfHdMq9XnZ9mwW5H6LsfVCn9u6iGAj2FCVYtfhcHn72Tphvm5P", "5JaqLZaKD7cgkfsxSZBNiu6gaFxo1XAiTXw1mhtatipNNCtZBZG", "5KNsAkiHRDZb5Yyedxov2Fncr6CcNPV52yqJbzQ8M2W6dkg2qJp" ),
    testlib.MultisigWallet( 2, "5JPrkpfLT3rDf1Lgm1DpA2Cfepwf9wCtEbDx1HSEdd4J2R5YMxZ", "5JiALcfvzFsKcvLnHf7ECgLdp6FxbcAXB1GPvEYP7HeigbDCQ9E", "5KScD5XL5Hj83Yjvm3u4HD78vSYwFRyq9StTLPnrWrCTGiqTvVP" ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr, wallet=wallets[3] )
    testlib.next_block( **kw )

    # should fail, since multisig isn't enabled yet
    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr, wallet=wallets[3] )
    testlib.next_block( **kw )
    
    testlib.expect_snv_fail_at( "foo.test", testlib.get_current_block(**kw))

    # foo.test should be preordered (in both 0.13 and 0.14)
    state_engine = testlib.get_state_engine()
    preorder = state_engine.get_name_preorder("foo.test", virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr)
    if preorder is None:
        print "foo.test not preordered"
        return False

    # epoch changes here

    testlib.blockstack_name_preorder( "bar.test", wallets[3].privkey, wallets[4].addr )
    testlib.next_block( **kw )

    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr, wallet=wallets[3] )
    testlib.next_block( **kw )

    testlib.blockstack_name_register( "bar.test", wallets[3].privkey, wallets[4].addr )
    testlib.next_block( **kw )


def check( state_engine ):

    original_price = 6400000
    curr_price = original_price * blockstack_server.lib.config.get_epoch_price_multiplier( 262, "test", 'BTC')

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
    preorder = state_engine.get_name_preorder( "foo.test", virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr, include_failed=True )
    if preorder is not None:
        print "preorder exists"
        return False
    
    # not preordered
    preorder = state_engine.get_name_preorder( "foo.test", virtualchain.make_payment_script(wallets[3].addr), wallets[4].addr, include_failed=True )
    if preorder is not None:
        print "preorder exists"
        return False

    # registered 
    name_rec_foo = state_engine.get_name( "foo.test" )
    if name_rec_foo is None:
        print "name does not exist"
        return False 

    # registered 
    name_rec_bar = state_engine.get_name( "bar.test" )
    if name_rec_bar is None:
        print "name does not exist"
        return False 

    # owned by
    if name_rec_foo['address'] != wallets[3].addr or name_rec_foo['sender'] != virtualchain.make_payment_script(wallets[3].addr):
        print "sender is wrong"
        return False 

    # owned by
    if name_rec_bar['address'] != wallets[4].addr or name_rec_bar['sender'] != virtualchain.make_payment_script(wallets[4].addr):
        print "sender is wrong"
        return False 

    # paid epoch 1 fee
    if abs(name_rec_foo['op_fee'] - original_price) >= 10e-8:
        print "foo paid %s, expected %s" % (name_rec_foo['op_fee'], original_price)
        return False

    # paid epoch 2 fee
    if abs(name_rec_bar['op_fee'] - curr_price) >= 10e-8:
        print "bar paid %s, expected %s" % (name_rec_bar['op_fee'], curr_price)
        return False

    return True
