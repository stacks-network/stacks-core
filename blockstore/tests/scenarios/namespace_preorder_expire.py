#!/usr/bin/env python 

import testlib 
import json

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

def scenario( wallets, **kw ): 
    resp = testlib.blockstore_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    if 'error' in resp:
        print json.dumps(resp, indent=4)

    testlib.next_block( **kw )

    # expire it (1 day later)
    for i in xrange(0, 145): 
        testlib.next_block( **kw )

    # try to re-preorder it 
    resp = testlib.blockstore_namespace_preorder( "test", wallets[3].addr, wallets[2].privkey )
    if 'error' in resp:
        print json.dumps(resp, indent=4)

    testlib.next_block( **kw )

def check( state_engine ):
    
    # this namespace needs to be preordered, but by wallets[2]
    namespace_preorder_hashes = state_engine.get_all_preordered_namespace_hashes()
    if len(namespace_preorder_hashes) != 1:
        print "preorder hashes: %s" % namespace_preorder_hashes
        return False 

    namespace_preorder = state_engine.get_namespace_preorder( namespace_preorder_hashes[0] )

    if namespace_preorder['address'] != wallets[2].addr:
        print "expected address %s, got %s" % (namespace_preorder['address'], wallets[2].addr)
        return False 

    return True

