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
import sys
import blockstore.blockstored as blockstored

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet( "5K6Nou64uUXg8YzuiVuRQswuGRfH1tdb9GUC9NBEV1xmKxWMJ54", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    global final_consensus

    testlib.blockstore_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstore_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstore_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    resp = testlib.blockstore_name_preorder_multi( ["foo.test", "bar.test", "baz.test"], wallets[2].privkey, [wallets[3].addr, wallets[4].addr, wallets[5].addr] )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )
        sys.exit(1)
       
    testlib.next_block( **kw )

    resp = testlib.blockstore_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )
        sys.exit(1)
       
    testlib.next_block( **kw )

    resp = testlib.blockstore_name_preorder( "goo.test", wallets[2].privkey, wallets[3].addr )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )
        sys.exit(1)

    testlib.next_block( **kw )

    resp = testlib.blockstore_name_register( "bar.test", wallets[2].privkey, wallets[4].addr )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )
        sys.exit(1)

    resp = testlib.blockstore_name_register( "goo.test", wallets[2].privkey, wallets[3].addr )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )
        sys.exit(1)

    resp = testlib.blockstore_name_register( "baz.test", wallets[2].privkey, wallets[5].addr )
    if 'error' in resp:
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

    # there won't be a preorder for an individual name...
    preorder = state_engine.get_name_preorder( "foo.test", pybitcoin.make_pay_to_address_script(wallets[2].addr), wallets[3].addr )
    if preorder is not None:
        print "found name preorder for 'foo.test'"
        return False
   
    # there will be a preorder for all names
    preorder = state_engine.get_name_preorder_multi( ['foo.test', 'bar.test', 'baz.test'], \
                                                     pybitcoin.make_pay_to_address_script(wallets[2].addr), \
                                                     [wallets[3].addr, wallets[4].addr, wallets[5].addr])

    if preorder is None:
        print "Preorder not found for foo.test, bar.test, baz.test"
        return False

    prev_name_rec = None

    # none of the multi-preordered names will be registered 
    for name, wallet in [('foo.test', wallets[3]), ('bar.test', wallets[4]), ('baz.test', wallets[5])]:

        name_rec = state_engine.get_name( name )
        if name_rec is not None:
            print "Registered name record for %s" % name
            return False 

    # the single preordered name will be registered 
    name_rec = state_engine.get_name( 'goo.test' )
    if name_rec is None:
        print "No name record for %s" % name 
        return False 

    if name_rec['address'] != wallet[3].addr:
        print "'%s' not owned by '%s'" % (name, wallet.addr)
        return False 

    if name_rec['sender'] != pybitcoin.make_pay_to_address_script(wallet[3].addr):
        print "'%s' not controlled by '%s'" % (name, pybitcoin.make_pay_to_address_script(wallet[3].addr))
        return False

    return True

    
