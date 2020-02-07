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
import json
import blockstack as blockstack_server

"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 698
"""

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

last_first_block = None
first_preorder = None
failed_register_block = None

def scenario( wallets, **kw ):

    global last_first_block, first_preorder

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    # NOTE: names expire in 5 * NAMESPACE_LIFETIME_MULTIPLER blocks
    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 5, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    first_preorder = testlib.get_current_block( **kw )
    
    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    for i in xrange(0, 5):
        testlib.next_block( **kw )

    # epoch shifts here
    # 698

    testlib.next_block( **kw )

    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr, safety_checks=False )
    testlib.next_block( **kw )

    # should fail
    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr, safety_checks=False )
    testlib.next_block( **kw )

    failed_first_block = testlib.get_current_block( **kw )
    testlib.expect_snv_fail_at( "foo.test", failed_first_block )

    # verify it failed
    rec = testlib.blockstack_cli_get_name_blockchain_record("foo.test")
    if 'error' in rec:
        print json.dumps(rec, indent=4, sort_keys=True)
        return False

    if rec['first_registered'] != 693:
        print "invalid first registered"
        print json.dumps(rec, indent=4, sort_keys=True)
        return False

    # actually expire
    for i in xrange(0, 5 * blockstack_server.config.get_epoch_namespace_lifetime_multiplier( testlib.get_current_block(**kw), "test") - 5 - 3):
        testlib.next_block( **kw )

    # should work
    testlib.blockstack_name_preorder( "foo.test", wallets[3].privkey, wallets[4].addr, safety_checks=False )
    testlib.next_block( **kw )

    testlib.blockstack_name_register( "foo.test", wallets[3].privkey, wallets[4].addr )
    testlib.next_block( **kw )

    last_first_block = testlib.get_current_block( **kw )



def check( state_engine ):

    global last_first_block, first_preorder

    original_price = 6400000
    curr_price = original_price * blockstack_server.config.get_epoch_price_multiplier( last_first_block, "test", "BTC" )

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is not None:
        return False 

    ns = state_engine.get_namespace( "test" )
    if ns is None:
        return False 

    if ns['namespace_id'] != 'test':
        return False 

    # not preordered
    preorder = state_engine.get_name_preorder( "foo.test", virtualchain.make_payment_script(wallets[3].addr), wallets[4].addr, include_failed=True )
    if preorder is not None:
        return False
     
    # failed preorder is still there
    preorder = state_engine.get_name_preorder( "foo.test", virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr, include_failed=True )
    if preorder is None:
        print "missing preorder (%s, %s)" % (virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr)
        return False

    # failed preorder paid epoch 2 fee
    if abs(preorder['op_fee'] - curr_price) >= 10e-8:
        print "wrong preorder fee: %s != %s" % (preorder['op_fee'], curr_price)
        return False

    # registered 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        print "still expired"
        return False 

    # blocks updated
    if name_rec['address'] != wallets[4].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[4].addr):
        print json.dumps(name_rec, indent=4, sort_keys=True )
        return False

    # check blocks 
    if name_rec['first_registered'] != last_first_block:
        print "wrong first_registered; expected %s" % last_first_block
        print json.dumps(name_rec, indent=4, sort_keys=True )
        return False 

    if name_rec['block_number'] != first_preorder:
        print "wrong block_number; expected %s" % last_first_preorder
        print json.dumps(name_rec, indent=4, sort_keys=True)
        return False

    # epoch 2 fee paid on second preorder 
    if abs(name_rec['op_fee'] - curr_price) >= 10e-8:
        print "wrong fee: %s != %s" % (name_rec['op_fee'], curr_price)
        return False

    historic_name_rec = state_engine.get_name_at( "foo.test", first_preorder+1, include_expired=True )
    if historic_name_rec is None or len(historic_name_rec) == 0:
        print "no name at %s" % import_block_1
        return False
    
    # epoch 1 fee paid on first preorder
    historic_name_rec = historic_name_rec[0]
    if historic_name_rec['address'] != wallets[3].addr or historic_name_rec['sender'] != virtualchain.make_payment_script(wallets[3].addr):
        print "historic sender is wrong"
        return False

    if abs(historic_name_rec['op_fee'] - original_price) >= 10e-8:
        print "wrong historic fee at epoch 1: %s != %s" % (historic_name_rec['op_fee'], original_price)
        return False

    # epoch 2 fee paid on second preorder
    historic_name_rec = state_engine.get_name_at( "foo.test", last_first_block, include_expired=True )
    if historic_name_rec is None or len(historic_name_rec) == 0:
        print "no name at %s" % import_block_1
        return False

    historic_name_rec = historic_name_rec[0]
    if abs(historic_name_rec['op_fee'] - curr_price) >= 10e-8:
        print "wrong historic fee at epoch 1: %s != %s" % (historic_name_rec['op_fee'], original_price)
        return False

    return True
