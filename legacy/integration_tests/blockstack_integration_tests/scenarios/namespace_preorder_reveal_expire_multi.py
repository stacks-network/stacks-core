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

# test framework pragmas
"""
TEST ENV BLOCKSTACK_NAMESPACE_REVEAL_EXPIRE 2
"""

import os
import testlib 
import json
import virtualchain

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet( "5K5hDuynZ6EQrZ4efrchCwy6DLhdsEzuJtTDAf3hqdsCKbxfoeD", 100000000000 ),
    testlib.Wallet( "5J39aXEeHh9LwfQ4Gy5Vieo7sbqiUMBXkPH7SaMHixJhSSBpAqz", 100000000000 ),
    testlib.Wallet( "5K9LmMQskQ9jP1p7dyieLDAeB6vsAj4GK8dmGNJAXS1qHDqnWhP", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

reveal_blocks = []
reveal_block = None

def scenario( wallets, **kw ): 

    global reveal_blocks, reveal_block

    for count in xrange(0, 3):
        resp = testlib.blockstack_namespace_preorder( "test", wallets[count+1].addr, wallets[count].privkey )
        if 'error' in resp:
            print json.dumps(resp, indent=4)
            return False

        testlib.next_block( **kw )

        # reveal it  
        buckets = [count] * 16
        resp = testlib.blockstack_namespace_reveal( "test", wallets[count+1].addr, count + 1, count + 1, count + 1, buckets, count + 1, count + 1, wallets[count].privkey )
        if 'error' in resp:
            print resp
            return False

        testlib.next_block( **kw )

        reveal_blocks.append( testlib.get_current_block(**kw) )

        # expire it (2 blocks later)
        for i in xrange(0, 3): 
            testlib.next_block( **kw )

        # try to ready it (should fail)
        resp = testlib.blockstack_namespace_ready( "test", wallets[count+1].privkey, expect_fail=True)
        if 'error' in resp:
            print json.dumps(resp, indent=4)

        testlib.next_block( **kw )
        testlib.expect_snv_fail_at('test', testlib.get_current_block(**kw))



def check( state_engine ):

    global reveal_blocks

    # the namespace should not exist
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is not None:
        print "still revealed"
        return False 
    
    # should not be preordered
    namespace_preorder_hashes = state_engine.get_all_preordered_namespace_hashes()
    if len(namespace_preorder_hashes) != 0:
        print "preorder hashes: %s" % namespace_preorder_hashes
        return False 

    # examine historical form 
    for count in xrange(0, 3):
        ns = state_engine.get_namespace_at( "test", reveal_blocks[count] )
        if ns is None or len(ns) != 1:
            print "no namespace state or too much namespace state at %s" % (reveal_blocks[count])
            return False

        ns = ns[0]

        print ''
        print 'count={}, namespace at {}'.format(count, reveal_blocks[count])
        print ns
        print ''

        # fields should match 
        for f in ['lifetime', 'coeff', 'base', 'nonalpha_discount', 'no_vowel_discount']:
            if ns[f] != count + 1:
                print "%s: expected %s, got %s" % (f, count+1, ns[f])
                return False

        buckets = [count] * 16
        if ns['buckets'] != str(buckets):
            print "buckets: expected %s, got %s" % ([count]*16, ns['buckets'])
            return False
        
        # reveal block should match 
        if ns['reveal_block'] != reveal_blocks[count]:
            print "reveal block: expected %s, got %s" % (reveal_blocks[count], ns['reveal_block'])
            return False

        # sender should match
        if ns['address'] != wallets[count].addr or ns['sender'] != virtualchain.make_payment_script(wallets[count].addr):
            print "sender: expected %s, got %s" % (ns['address'], wallets[count].addr)
            return False

        # recipient should match 
        if ns['recipient_address'] != wallets[count+1].addr or ns['recipient'] != virtualchain.make_payment_script(wallets[count+1].addr):
            print "recipient: expected %s, got %s" % (ns['recipient_address'], wallets[count+1].addr)
            return False


    return True

