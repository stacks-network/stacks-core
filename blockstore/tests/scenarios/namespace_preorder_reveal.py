#!/usr/bin/env python 

import testlib

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    testlib.blockstore_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )
    
    testlib.blockstore_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

def check( state_engine ):

    # the namespace has to have been revealed 
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is None:
        return False 

    if ns["namespace_id"] != "test":
        return False 

    if ns["lifetime"] != 52595:
        return False 

    if ns["coeff"] != 250:
        return False 

    if ns["base"] != 4:
        return False 

    if ns["buckets"] != [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0]:
        return False 

    if ns["no_vowel_discount"] != 10:
        return False

    if ns["nonalpha_discount"] != 10:
        return False

    return True
