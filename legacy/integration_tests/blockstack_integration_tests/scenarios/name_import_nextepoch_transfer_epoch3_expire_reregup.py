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

# change epochs
import os

"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 693
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 695
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 2
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 2
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_GRACE_PERIOD 5
"""

import testlib
import virtualchain
import json
import shutil
import tempfile

import blockstack

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
first_name_block = None

def scenario( wallets, **kw ):

    global first_name_block

    # make a test namespace
    resp = testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )
        return False

    testlib.next_block( **kw ) # end of 689

    resp = testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 2, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )
        return False

    testlib.next_block( **kw ) # 690

    resp = testlib.blockstack_name_import( "foo.test", wallets[2].addr, "11" * 20, wallets[1].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )
        return False

    testlib.next_block( **kw ) # 691
    first_name_block = testlib.get_current_block( **kw )

    resp = testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )
        return False

    testlib.next_block( **kw ) # end of 692

    whois = testlib.blockstack_cli_whois('foo.test')
    if 'error' in whois:
        print 'failed to whois foo.test'
        print json.dumps(whois, indent=4)
        return False

    # this should be the second-to-last block 
    if whois['expire_block'] != testlib.get_current_block(**kw) + 2:
        print 'wrong expire block (expect 2 more)'
        print whois
        return False

    testlib.next_block(**kw) # end of 693; begin epoch 2
    # begin epoch 2
    testlib.next_block(**kw) # 694
 
    whois = testlib.blockstack_cli_whois('foo.test')
    if 'error' in whois:
        print 'failed to whois foo.test'
        print json.dumps(whois, indent=4)
        return False
   
    # this should be the last block 
    if whois['expire_block'] != testlib.get_current_block(**kw) + 2:
        print 'wrong expire block (expect 2 more)'
        print whois
        return False

    if whois['renewal_deadline'] != testlib.get_current_block(**kw) + 2:
        print 'wrong renewal block (expect 2 more)'
        print whois
        return False

    print whois

    resp = testlib.blockstack_name_transfer( 'foo.test', wallets[0].addr, True, wallets[2].privkey)
    if 'error' in resp:
        print resp
        return False

    testlib.next_block(**kw) # 695 (epoch 3 begins)
    testlib.next_block(**kw) # end of 696

    whois = testlib.blockstack_cli_whois('foo.test')
    if 'error' in whois:
        print whois
        return False

    # this should be the expire block 
    if whois['expire_block'] != testlib.get_current_block(**kw):
        print 'wrong expire block (now at {})'.format(testlib.get_current_block(**kw))
        print whois
        return False
 
    # should now be a grace period 
    if whois['renewal_deadline'] != testlib.get_current_block(**kw) + 5:
        print 'wrong renewal block (now at {})'.format(testlib.get_current_block(**kw))
        print whois
        return False

    # safety checks should NOT allow the preorder to go through
    resp = testlib.blockstack_name_preorder('foo.test', wallets[3].privkey, wallets[4].addr, expect_fail=True)
    if 'error' not in resp:
        print resp
        return False

    # begin epoch 3 (grace period)
    testlib.next_block(**kw) # end of 697

    # safety checks should NOT allow the preorder to go through
    resp = testlib.blockstack_name_preorder('foo.test', wallets[3].privkey, wallets[4].addr, expect_fail=True)
    if 'error' not in resp:
        print resp
        return False

    testlib.next_block(**kw) # 698

    # safety checks should NOT allow the preorder to go through
    resp = testlib.blockstack_name_preorder('foo.test', wallets[3].privkey, wallets[4].addr, expect_fail=True)
    if 'error' not in resp:
        print resp
        return False

    testlib.next_block(**kw) # 699

    # safety checks should NOT allow the preorder to go through
    resp = testlib.blockstack_name_preorder('foo.test', wallets[3].privkey, wallets[4].addr, expect_fail=True)
    if 'error' not in resp:
        print resp
        return False

    testlib.next_block(**kw) # 700

    # safety checks should NOT allow the preorder to go through
    resp = testlib.blockstack_name_preorder('foo.test', wallets[3].privkey, wallets[4].addr, expect_fail=True)
    if 'error' not in resp:
        print resp
        return False

    testlib.next_block(**kw) # end of 701

    # safety checks SHOULD allow the preorder to go through (will be incorporated into block 702)
    resp = testlib.blockstack_name_preorder('foo.test', wallets[3].privkey, wallets[4].addr)
    if 'error' in resp:
        print resp
        return False

    testlib.next_block(**kw) # 702

    resp = testlib.blockstack_name_register("foo.test", wallets[3].privkey, wallets[4].addr, zonefile_hash='33' * 20)
    if 'error' in resp:
        print resp
        return False

    testlib.next_block(**kw) # 703


def check( state_engine ):

    global first_name_block 

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
        preorder = state_engine.get_name_preorder( "foo.test", virtualchain.make_payment_script(wallets[i].addr), wallets[(i+1)%5].addr )
        if preorder is not None:
            print "preordered"
            return False

    # registered 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        print "no name"
        return False 

    # owned by new owner
    if name_rec['address'] != wallets[4].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[4].addr):
        print 'wrong owner'
        print name_rec['address']
        print name_rec['sender']
        return False

    namespace_rec = state_engine.get_namespace("test")
    if namespace_rec is None:
        print "missing namespace"
        return False

    return True
