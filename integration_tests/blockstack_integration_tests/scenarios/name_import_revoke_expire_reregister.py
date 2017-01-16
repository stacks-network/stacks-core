#!/usr/bin/env python
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
import pybitcoin
import json
import shutil
import tempfile
import os
import sys
import blockstack as blockstack_server

# in epoch 2 immediately, but with the old price (in order to test compatibility with 0.13)
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 250
TEST ENV BLOCKSTACK_EPOCH_2_PRICE_MULTIPLIER 1.0
"""

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet( "5K5hDuynZ6EQrZ4efrchCwy6DLhdsEzuJtTDAf3hqdsCKbxfoeD", 100000000000 ),
    testlib.Wallet( "5J39aXEeHh9LwfQ4Gy5Vieo7sbqiUMBXkPH7SaMHixJhSSBpAqz", 100000000000 ),
    testlib.Wallet( "5K9LmMQskQ9jP1p7dyieLDAeB6vsAj4GK8dmGNJAXS1qHDqnWhP", 100000000000 ),
    testlib.Wallet( "5KcNen67ERBuvz2f649t9F2o1ddTjC5pVUEqcMtbxNgHqgxG2gZ", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

debug = True
register_block = None
revoke_blocok = None

NAMESPACE_LIFETIME_MULTIPLIER = blockstack_server.get_epoch_namespace_lifetime_multiplier( blockstack_server.EPOCH_1_END_BLOCK + 1, "test" )

def scenario( wallets, **kw ):

    global register_block, revoke_block

    # make a test namespace
    resp = testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 6, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstack_name_import( "foo.test", wallets[3].addr, "11" * 20, wallets[1].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # wait for a bit...
    for i in xrange(0, 6):
        testlib.next_block( **kw )

    resp = testlib.blockstack_name_renew( "foo.test", wallets[3].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # revoke it
    resp = testlib.blockstack_name_revoke( "foo.test", wallets[3].privkey )
    if 'error' in resp:
        print json.dumps(resp, indent=4 )

    testlib.next_block( **kw )

    revoke_block = testlib.get_current_block( **kw )

    # wait for it to expire
    for i in xrange(0, 6 * NAMESPACE_LIFETIME_MULTIPLIER):
        testlib.next_block( **kw )

    # re-register
    testlib.blockstack_name_preorder( "foo.test", wallets[7].privkey, wallets[8].addr )
    testlib.next_block( **kw )

    testlib.blockstack_name_register( "foo.test", wallets[7].privkey, wallets[8].addr )
    testlib.next_block( **kw )

    register_block = testlib.get_current_block( **kw )



def check( state_engine ):

    global register_block, revoke_block

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
    for i in xrange(0, len(wallets)):
        preorder = state_engine.get_name_preorder( "foo.test", pybitcoin.make_pay_to_address_script(wallets[i].addr), wallets[(i+1)%5].addr )
        if preorder is not None:
            print "preordered"
            return False

    # registered, but revoked 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        print "no name"
        return False 

    if name_rec['value_hash'] is not None:
        print "still have value hash"
        return False

    # renewal count reset
    if name_rec['last_renewed'] != name_rec['first_registered'] or name_rec['first_registered'] != register_block:
        print "name counts not reset"
        return False

    # correct pubkey 
    if name_rec['sender_pubkey'] != wallets[7].pubkey_hex:
        print "wrong sender pubkey: %s != %s" % (name_rec['sender_pubkey'], wallet_keys[7].pubkey_hex)
        return False

    # was revoked at one point
    historic_name_rec = state_engine.get_name_at( "foo.test", revoke_block, include_expired=True )
    if historic_name_rec is None or len(historic_name_rec) == 0:
        print "name doesn't exist at %s" % revoke_block
        return False

    historic_name_rec = historic_name_rec[0]
    
    # was actually revoked
    if historic_name_rec['opcode'] != 'NAME_REVOKE':
        print "name not revoked at %s" % revoke_block
        return False

    return True
