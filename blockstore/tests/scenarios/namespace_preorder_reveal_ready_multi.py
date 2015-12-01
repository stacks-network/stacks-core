#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstore

    Blockstore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore. If not, see <http://www.gnu.org/licenses/>.
""" 

import testlib

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet( "5K5hDuynZ6EQrZ4efrchCwy6DLhdsEzuJtTDAf3hqdsCKbxfoeD", 100000000000 ),
    testlib.Wallet( "5J39aXEeHh9LwfQ4Gy5Vieo7sbqiUMBXkPH7SaMHixJhSSBpAqz", 100000000000 ),
    testlib.Wallet( "5K9LmMQskQ9jP1p7dyieLDAeB6vsAj4GK8dmGNJAXS1qHDqnWhP", 100000000000 ),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    # order 3 namespaces
    testlib.blockstore_namespace_preorder( "test1", wallets[1].addr, wallets[0].privkey )
    testlib.blockstore_namespace_preorder( "test2", wallets[3].addr, wallets[2].privkey )
    testlib.blockstore_namespace_preorder( "test3", wallets[5].addr, wallets[4].privkey )
    testlib.next_block( **kw )

    # reveal them all
    testlib.blockstore_namespace_reveal( "test1", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 11, wallets[0].privkey )
    testlib.blockstore_namespace_reveal( "test2", wallets[3].addr, 52596, 251, 5, [7,6,5,4,3,2,1,1,1,1,1,1,1,1,1,1], 11, 12, wallets[2].privkey )
    testlib.blockstore_namespace_reveal( "test3", wallets[5].addr, 52597, 252, 6, [8,7,6,5,4,3,2,2,2,2,2,2,2,2,2,2], 12, 13, wallets[4].privkey )
    testlib.next_block( **kw )

    # ready them all
    testlib.blockstore_namespace_ready( "test1", wallets[1].privkey )
    testlib.blockstore_namespace_ready( "test2", wallets[3].privkey )
    testlib.blockstore_namespace_ready( "test3", wallets[5].privkey )
    testlib.next_block( **kw )

def check( state_engine ):

    # the namespace has to have been revealed, and must be ready 
    for i in xrange(1, 4):

        ns = state_engine.get_namespace_reveal( "test%s" % i)
        if ns is not None:
            return False 

        ns = state_engine.get_namespace( "test%s" % i )
        if ns is None:
            return False 

        if ns["namespace_id"] != ("test%s" % i):
            return False 

        if ns["lifetime"] != 52595 + (i - 1):
            return False 

        if ns["coeff"] != 250 + (i - 1):
            return False 

        if ns["base"] != 4 + (i - 1):
            return False 

        if ns["buckets"] != [x + i - 1 for x in [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0]]:
            return False 

        if ns["no_vowel_discount"] != 10 + (i):
            return False

        if ns["nonalpha_discount"] != 10 + (i - 1):
            return False

    return True
