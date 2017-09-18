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

import testlib
import virtualchain
import json
import shutil
import tempfile
import os
import keychain
import virtualchain

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

def scenario( wallets, **kw ):

    # make a test namespace
    resp = testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # derive importer keys and do imports
    # NOTE: breaks consensus trace from 0.14.0
    private_keychain = keychain.PrivateKeychain.from_private_key( wallets[1].privkey )
    private_keys = [wallets[1].privkey]     # NOTE: always start with the reveal key, then use children
    for i in xrange(0, 3):
        import_key = private_keychain.child(i).private_key()

        print "fund {} (child {})".format(import_key, i)
        res = testlib.send_funds( wallets[1].privkey, 100000000, virtualchain.BitcoinPrivateKey(import_key).public_key().address() )
        if 'error' in res:
            print json.dumps(res, indent=4, sort_keys=True)
            return False

        testlib.next_block(**kw)
        private_keys.append(import_key)

    resp = testlib.blockstack_name_import( "foo.test", wallets[3].addr, "11" * 20, private_keys[0] )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # import twice
    resp = testlib.blockstack_name_import( "bar.test", wallets[4].addr, "22" * 20, private_keys[0] )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstack_name_import( "bar.test", wallets[4].addr, "33" * 20, private_keys[1] )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )
 
    testlib.next_block( **kw )

    # import thrice in the same block 
    resp = testlib.blockstack_name_import( "baz.test", wallets[5].addr, "44" * 20, private_keys[0] )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_import( "baz.test", wallets[5].addr, "55" * 20, private_keys[1] )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_import( "baz.test", wallets[5].addr, "66" * 20, private_keys[2] )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )
    
    testlib.next_block( **kw )

    # import all three in the same block 
    resp = testlib.blockstack_name_import( "foo.test", wallets[5].addr, "66" * 20, private_keys[0] )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_import( "bar.test", wallets[3].addr, "77" * 20, private_keys[1] )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_import( "baz.test", wallets[4].addr, "88" * 20, private_keys[2] )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )
    
    # import thrice in the same block, again
    resp = testlib.blockstack_name_import( "baz.test", wallets[5].addr, "44" * 20, private_keys[0] )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_import( "baz.test", wallets[5].addr, "55" * 20, private_keys[1] )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_import( "baz.test", wallets[5].addr, "66" * 20, private_keys[2] )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )
    
    testlib.next_block( **kw )
    
    # import all three in the same block, again 
    resp = testlib.blockstack_name_import( "foo.test", wallets[5].addr, "66" * 20, private_keys[0] )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_import( "bar.test", wallets[3].addr, "77" * 20, private_keys[1] )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_import( "baz.test", wallets[4].addr, "88" * 20, private_keys[2] )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )



def check( state_engine ):

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is None:
        print "not revealed"
        return False 

    if ns['namespace_id'] != 'test':
        print "wrong namespace"
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

    # updated, and data preserved
    if name_rec['value_hash'] != "66" * 20:
        print "wrong value hash"
        return False 

    # transferred 
    if name_rec['address'] != wallets[5].addr or name_rec['sender'] != virtualchain.make_payment_script( wallets[5].addr ):
        print "wrong owner"
        return False

    # not preordered 
    for i in xrange(0, len(wallets)):
        preorder = state_engine.get_name_preorder( "bar.test", virtualchain.make_payment_script(wallets[i].addr), wallets[(i+1)%5].addr )
        if preorder is not None:
            print "preordered"
            return False

    # registered 
    name_rec = state_engine.get_name( "bar.test" )
    if name_rec is None:
        print "no name"
        return False 

    # updated, and data preserved
    if name_rec['value_hash'] != "77" * 20:
        print "wrong value hash"
        return False 

    # transferred 
    if name_rec['address'] != wallets[3].addr or name_rec['sender'] != virtualchain.make_payment_script( wallets[3].addr ):
        print "wrong owner"
        return False

    # not preordered 
    for i in xrange(0, len(wallets)):
        preorder = state_engine.get_name_preorder( "baz.test", virtualchain.make_payment_script(wallets[i].addr), wallets[(i+1)%5].addr )
        if preorder is not None:
            print "preordered"
            return False

    # registered 
    name_rec = state_engine.get_name( "baz.test" )
    if name_rec is None:
        print "no name"
        return False 

    # updated, and data preserved
    if name_rec['value_hash'] != "88" * 20:
        print "wrong value hash"
        return False 

    # transferred 
    if name_rec['address'] != wallets[4].addr or name_rec['sender'] != virtualchain.make_payment_script( wallets[4].addr ):
        print "wrong owner"
        return False

    return True
