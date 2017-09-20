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
import sys

# in epoch 2 immediately, but with the old price (in order to test compatibility with 0.13)
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 682
TEST ENV BLOCKSTACK_EPOCH_2_PRICE_MULTIPLIER 1.0
"""
wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
fail_blocks = []
NAMESPACE_LIFETIME_MULTIPLIER = blockstack_server.get_epoch_namespace_lifetime_multiplier( blockstack_server.EPOCH_1_END_BLOCK + 1, "test" )

# TODO: SNV expect failure
def scenario( wallets, **kw ):

    global fail_blocks

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 10, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )
    
    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )
    
    testlib.blockstack_name_revoke( "foo.test", wallets[3].privkey )
    testlib.next_block( **kw )

    # can't do anything with the name for another 10 blocks
    resp = testlib.blockstack_name_update( "foo.test", "11" * 20, wallets[3].privkey, safety_checks=False )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )
    testlib.expect_snv_fail_at( "foo.test", testlib.get_current_block(**kw))

    # should fail
    resp = testlib.blockstack_name_transfer( "foo.test", wallets[4].addr, True, wallets[3].privkey, safety_checks=False )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )
    testlib.expect_snv_fail_at( "foo.test", testlib.get_current_block(**kw))

    # should fail
    resp = testlib.blockstack_name_renew( "foo.test", wallets[3].privkey, safety_checks=False )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )
    testlib.expect_snv_fail_at( "foo.test", testlib.get_current_block(**kw))

    # wait for it to expire...
    for i in xrange(0, 8 * NAMESPACE_LIFETIME_MULTIPLIER):
        testlib.next_block( **kw )

    # verify that operations continue to fail (BUG in 0.13: THIS SUCCEEDS WHEN IT SHOULD FAIL)
    resp = testlib.blockstack_name_update( "foo.test", "11" * 20, wallets[3].privkey, safety_checks=False )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )
    fail_blocks.append( testlib.get_current_block( **kw ) )
    testlib.expect_snv_fail_at( "foo.test", testlib.get_current_block(**kw))

    # should fail
    resp = testlib.blockstack_name_transfer( "foo.test", wallets[4].addr, True, wallets[3].privkey, safety_checks=False )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )
    fail_blocks.append( testlib.get_current_block( **kw ) )
    testlib.expect_snv_fail_at( "foo.test", testlib.get_current_block(**kw))

    # should fail
    resp = testlib.blockstack_name_renew( "foo.test", wallets[3].privkey, safety_checks=False )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )
    fail_blocks.append( testlib.get_current_block( **kw ) )
    testlib.expect_snv_fail_at( "foo.test", testlib.get_current_block(**kw))

    # re-preorder...
    resp = testlib.blockstack_name_preorder( "foo.test", wallets[3].privkey, wallets[4].addr )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # re-register (different user) 
    resp = testlib.blockstack_name_register( "foo.test", wallets[3].privkey, wallets[4].addr )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )
    
    # warn the serialization checker that this changes behavior from 0.13
    print "BLOCKSTACK_SERIALIZATION_CHANGE_BEHAVIOR"
    sys.stdout.flush()


def check( state_engine ):

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
    preorder = state_engine.get_name_preorder( "foo.test", virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr )
    if preorder is not None:
        return False
    
    # registered 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        return False 

    # owned 
    if name_rec['address'] != wallets[4].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[4].addr):
        return False 

    # not updated
    if name_rec['value_hash'] is not None:
        print "value hash is %s" % name_rec['value_hash']
        return False 

    # not transferred 
    if name_rec['address'] != wallets[4].addr:
        print "address is %s" % name_rec['address']
        return False 

    # TODO: check renewal block
    # no longer revoked 
    if name_rec['revoked']:
        return False 

    # at each of the fail blocks, confirm that the name has not changed from the initial revocation
    for fb in fail_blocks:
        historic_name_rec = state_engine.get_name_at( "foo.test", fb, include_expired=True )
        if historic_name_rec is None or len(historic_name_rec) == 0:
            print "no name at %s" % fb
            return False

        historic_name_rec = historic_name_rec[0]
        if historic_name_rec['opcode'] != 'NAME_REVOKE':
            print "accepted opcode %s at %s" % (historic_name_rec['opcode'], fb)
            return False

    return True
