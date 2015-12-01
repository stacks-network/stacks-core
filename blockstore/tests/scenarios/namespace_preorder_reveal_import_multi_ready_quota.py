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
import json

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    testlib.blockstore_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstore_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    resp = testlib.blockstore_name_import( "foo.test", wallets[2].addr, "11" * 20, wallets[1].privkey )
    if 'error' in resp:
        print json.dumps(resp, indent=4 )

    testlib.next_block( **kw )

    # try to exceed quota (currently 25): order 25, and try to register a 26th
    for i in xrange(0, 25):
        resp = testlib.blockstore_name_import( "foo%s.test" % i, wallets[3].addr, "22" * 20, wallets[1].privkey )
        if 'error' in resp:
            print json.dumps(resp, indent=4 )

    testlib.next_block( **kw )

    # try to exceed quota (currently 25): order 26, and try to update one of them (and try to transfer one too).
    for i in xrange(0, 27):
        resp = testlib.blockstore_name_import( "bar%s.test" % i, wallets[4].addr, "33" * 20, wallets[1].privkey )
        if 'error' in resp:
            print json.dumps(resp, indent=4 )

    testlib.next_block( **kw )
    
    testlib.blockstore_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    print wallets[3].privkey
    resp = testlib.blockstore_name_preorder( "foofail.test", wallets[3].privkey, wallets[1].addr )
    if 'error' in resp:
       print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # should fail 
    resp = testlib.blockstore_name_register( "foofail.test",wallets[3].privkey,  wallets[1].addr )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # should succeed
    resp = testlib.blockstore_name_update( "foo0.test", '55' * 20, wallets[3].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstore_name_preorder( "barfail.test", wallets[4].privkey, wallets[2].addr )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # should fail (exceeded quota)
    resp = testlib.blockstore_name_register( "barfail.test", wallets[4].privkey, wallets[2].addr )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # should fail (exceeded quota--have to revoke or give names away)
    resp = testlib.blockstore_name_update( "bar0.test", '44' * 20, wallets[4].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # should succeed (give a name away)
    resp = testlib.blockstore_name_transfer( "bar0.test", wallets[1].addr, True, wallets[4].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # should fail (exceeded quota--have to revoke or give names away)
    resp = testlib.blockstore_name_update( "bar0.test", '44' * 20, wallets[4].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # should succeed (revoke a name)
    resp = testlib.blockstore_name_revoke( "bar2.test", wallets[4].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # should succeed (now under quota)
    resp = testlib.blockstore_name_update( "bar1.test", '66' * 20, wallets[4].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

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

   
    # all names must exist 
    for i in xrange(0, 25):
        namerec = state_engine.get_name( "foo%s.test" % i )
        if namerec is None:
            print "foo%s.test does not exist" % i
            return False

    for i in xrange(0, 26):
        namerec = state_engine.get_name( "bar%s.test" % i)
        if namerec is None:
            print "bar%s.test does not exist" % i
            return False 

    # foofail.test and barfail.test should not exist 
    for n in ["foofail.test", "barfail.test"]:
        namerec = state_engine.get_name( n )
        if namerec is not None:
            print "%s exists" % n
            return False 

    # updating foo0.test should succeed
    namerec = state_engine.get_name("foo0.test")
    if namerec['value_hash'] != '55' * 20:
        print "foo0.test value hash %s" % namerec['value_hash']
        return False 

    # updating bar0.test should fail 
    namerec = state_engine.get_name("bar0.test")
    if namerec['value_hash'] != '33' * 20:
        print "bar0.test value hash %s" % namerec['value_hash']
        return False

    # transferring bar0.test should have worked
    if namerec['address'] != wallets[1].addr:
        print "bar0.test owned by %s" % namerec['address']
        return False 

    # revoking bar2.test should have worked 
    namerec = state_engine.get_name('bar2.test')
    if not namerec['revoked']:
        print "bar2.test not revoked"
        return False 

    # updating bar1.test should succeed
    namerec = state_engine.get_name('bar1.test')
    if namerec['value_hash'] != '66' * 20:
        print "bar1.test value hash %s" % namerec['value_hash']
        return False

    return True
