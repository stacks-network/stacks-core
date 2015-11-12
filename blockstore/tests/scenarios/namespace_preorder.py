#!/usr/bin/env python 

import testlib 
import json

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ): 
    resp = testlib.blockstore_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    if 'error' in resp:
        print json.dumps(resp, indent=4)

def check( state_engine ):
    
    # this namespace needs to be preordered 
    namespace_preorder_hashes = state_engine.get_all_preordered_namespace_hashes()
    if len(namespace_preorder_hashes) != 1:
        return False 

    return True

