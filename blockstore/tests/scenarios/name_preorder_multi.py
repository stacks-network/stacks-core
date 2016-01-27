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
import pybitcoin
import json
import blockstore.blockstored as blockstored
import sys

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet( "5K6Nou64uUXg8YzuiVuRQswuGRfH1tdb9GUC9NBEV1xmKxWMJ54", 100000000000 ),
    testlib.Wallet( "5KcNen67ERBuvz2f649t9F2o1ddTjC5pVUEqcMtbxNgHqgxG2gZ", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    testlib.blockstore_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstore_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstore_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    resp = testlib.blockstore_name_preorder_multi( ["foo2.test", "bar2.test"], wallets[2].privkey, [wallets[3].addr, wallets[4].addr])
    if 'error' in resp:
        print json.dumps( resp, indent=4 )
        sys.exit(1)

    testlib.next_block( **kw )

    print "\n%s %s %s" % (["foo4.test", "bar4.test", "baz4.test", "goo4.test"], pybitcoin.make_pay_to_address_script(wallets[2].addr), \
                        [wallets[3].addr, wallets[4].addr, wallets[5].addr, wallets[6].addr])
    import blockstore.lib.operations as ops
    h = ops.preorder_multi_hash_names( ["foo4.test", "bar4.test", "baz4.test", "goo4.test"], pybitcoin.make_pay_to_address_script(wallets[2].addr), \
                        [wallets[3].addr, wallets[4].addr, wallets[5].addr, wallets[6].addr])

    print "hash: %s\n" % h

    resp = testlib.blockstore_name_preorder_multi( ["foo4.test", "bar4.test", "baz4.test", "goo4.test"], wallets[2].privkey, [wallets[3].addr, wallets[4].addr, wallets[5].addr, wallets[6].addr] )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )
        sys.exit(1)
        
    testlib.next_block( **kw )

    resp = testlib.blockstore_name_preorder_multi( ["foo6.test", "bar6.test", "baz6.test", "goo6.test", "quux6.test", "norf6.test"], wallets[2].privkey, \
                                                   [wallets[0].addr, wallets[1].addr, wallets[2].addr, wallets[3].addr, wallets[4].addr, wallets[5].addr] )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )
        sys.exit(1)

    testlib.next_block( **kw )

    # should fail 
    resp = testlib.blockstore_name_preorder_multi( ["foo1.test"], wallets[2].privkey, [wallets[3].addr] )
    if 'error' not in resp:
        print json.dumps( resp, indent=4 )
        sys.exit(1)

    testlib.next_block( **kw )

    # should fail 
    resp = testlib.blockstore_name_preorder_multi( ["foo3.test", "bar3.test", "baz3.test"], wallets[2].privkey, [wallets[3].addr, wallets[4].addr, wallets[5].addr])
    if 'error' not in resp:
        print json.dumps( resp, indent=4 )
        sys.exit(1)

    testlib.next_block( **kw )

    # should fail
    resp = testlib.blockstore_name_preorder_multi( ["foo5.test", "bar5.test", "baz5.test", "goo5.test", "quux5.test"], wallets[2].privkey, \
                                                   [wallets[0].addr, wallets[1].addr, wallets[2].addr, wallets[3].addr, wallets[4].addr] )

    if 'error' not in resp:
        print json.dumps( resp, indent=4 )
        sys.exit(1)
    
    testlib.next_block( **kw )

    # should fail 
    resp = testlib.blockstore_name_preorder_multi( ["foo7.test", "bar7.test", "baz7.test", "goo7.test", "quux7.test", "norf7.test", "xyzzy7.test"], wallets[2].privkey, \
                                                   [wallets[0].addr, wallets[1].addr, wallets[2].addr, wallets[3].addr, wallets[4].addr, wallets[5].addr, wallets[6].addr] )

    if 'error' not in resp:
        print json.dumps( resp, indent=4 )
        sys.exit(1)

    testlib.next_block( **kw )


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

    # preorders for an even number of names all work 
    preorder = state_engine.get_name_preorder_multi( ['foo2.test', 'bar2.test'], \
                                                     pybitcoin.make_pay_to_address_script(wallets[2].addr), \
                                                     [wallets[3].addr, wallets[4].addr])

    if preorder is None:
        print "no preorder found for 2-name preorder"
        return False

    if preorder['op_fee'] < blockstored.get_name_cost( 'foo2.test' ) + blockstored.get_name_cost( 'bar2.test' ):

        print "Insufficient fee"
        return False 

    # preorders for an even number of names all work 
    preorder = state_engine.get_name_preorder_multi( ['foo4.test', 'bar4.test', 'baz4.test', 'goo4.test'], \
                                                     pybitcoin.make_pay_to_address_script(wallets[2].addr), \
                                                     [wallets[3].addr, wallets[4].addr, wallets[5].addr, wallets[6].addr])

    if preorder is None:
        print "no preorder found for 4-name preorder"
        return False 

    if preorder['op_fee'] < blockstored.get_name_cost( 'foo4.test' ) + blockstored.get_name_cost( 'bar4.test' ) + \
                            blockstored.get_name_cost( 'baz4.test' ) + blockstored.get_name_cost( 'goo4.test' ):

        print "Insufficient fee"
        return False 

    # preorders for an even number of names all work 
    preorder = state_engine.get_name_preorder_multi( ['foo6.test', 'bar6.test', 'baz6.test', 'goo6.test', 'quux6.test', 'norf6.test'], \
                                                     pybitcoin.make_pay_to_address_script(wallets[2].addr), \
                                                     [wallets[0].addr, wallets[1].addr, wallets[2].addr, wallets[3].addr, wallets[4].addr, wallets[5].addr])

    if preorder is None:
        print "no preorder found for 6-name preorder"
        return False

    # order of addresses to names must match 
    preorder = state_engine.get_name_preorder_multi( ['foo2.test', 'bar2.test'], \
                                                     pybitcoin.make_pay_to_address_script(wallets[2].addr), \
                                                     [wallets[4].addr, wallets[3].addr])

    if preorder is not None:
        print "stealing is possible in 2-name preorder"
        return False 

    if preorder['op_fee'] < blockstored.get_name_cost( 'foo6.test' ) + blockstored.get_name_cost( 'bar6.test' ) + \
                            blockstored.get_name_cost( 'baz6.test' ) + blockstored.get_name_cost( 'goo6.test' ) + \
                            blockstored.get_name_cost( 'quux6.test') + blockstored.get_name_cost( 'norf6.test' ):

        print "Insufficient fee"
        return False 


    # preorders for an even number of names all work 
    preorder = state_engine.get_name_preorder_multi( ['foo6.test', 'bar6.test', 'baz6.test', 'goo6.test', 'quux6.test', 'norf6.test'], \
                                                     pybitcoin.make_pay_to_address_script(wallets[2].addr), \
                                                     [wallets[1].addr, wallets[0].addr, wallets[2].addr, wallets[3].addr, wallets[4].addr, wallets[5].addr])

    if preorder is not None:
        print "stealing is possible in 4-name preorder"
        return False 

    # preorders for an even number of names all work 
    preorder = state_engine.get_name_preorder_multi( ['foo6.test', 'bar6.test', 'baz6.test', 'goo6.test', 'quux6.test', 'norf6.test'], \
                                                     pybitcoin.make_pay_to_address_script(wallets[2].addr), \
                                                     [wallets[0].addr, wallets[1].addr, wallets[3].addr, wallets[2].addr, wallets[4].addr, wallets[5].addr])


    if preorder is not None:
        print "stealing is possible in 4-name preorder"
        return False 


    # preorders for an even number of names all work 
    preorder = state_engine.get_name_preorder_multi( ['foo6.test', 'bar6.test', 'baz6.test', 'goo6.test', 'quux6.test', 'norf6.test'], \
                                                     pybitcoin.make_pay_to_address_script(wallets[2].addr), \
                                                     [wallets[0].addr, wallets[1].addr, wallets[2].addr, wallets[4].addr, wallets[3].addr, wallets[5].addr])


    if preorder is not None:
        print "stealing is possible in 6-name preorder"
        return False 

    return True
