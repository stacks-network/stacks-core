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
import blockstack
import time
import sys
import binascii

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet( "5K5hDuynZ6EQrZ4efrchCwy6DLhdsEzuJtTDAf3hqdsCKbxfoeD", 100000000000 ),
    testlib.Wallet( "5J39aXEeHh9LwfQ4Gy5Vieo7sbqiUMBXkPH7SaMHixJhSSBpAqz", 100000000000 ),
    testlib.Wallet( "5K9LmMQskQ9jP1p7dyieLDAeB6vsAj4GK8dmGNJAXS1qHDqnWhP", 100000000000 ),
    testlib.Wallet( "5KcNen67ERBuvz2f649t9F2o1ddTjC5pVUEqcMtbxNgHqgxG2gZ", 100000000000 ),
    testlib.Wallet( "5J5uAKL8s62hddganFJaCkWi3Me7PFoc7fks9hAzjtWG1NDjmUK", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
wallet_keys = None
wallet_keys_2 = None

legacy_profile = {
  "bitcoin": {
    "address": "17zf596xPvV8Z8ThbWHZHYQZEURSwebsKE"
  }, 
  "github": {
    "username": "jcnelson", 
    "proof": {
      "url": "https://gist.github.com/jcnelson/70c02f80f8d4b0b8fc15"
    }
  }, 
  "website": "http://www.cs.princeton.edu/~jcnelson", 
  "v": "0.2", 
  "name": {
    "formatted": "Jude Nelson"
  }, 
  "twitter": {
    "username": "judecnelson", 
    "proof": {
      "url": "https://twitter.com/judecnelson/status/507374756291555328"
    }
  }, 
  "avatar": {
    "url": "https://s3.amazonaws.com/kd4/judecn"
  }, 
  "cover": {
    "url": "https://s3.amazonaws.com/97p/gQZ.jpg"
  }, 
  "bio": "PhD student", 
  "location": {
    "formatted": "Princeton University"
  }, 
  "facebook": {
    "username": "sunspider", 
    "proof": {
      "url": "https://facebook.com/sunspider/posts/674912239245011"
    }
  }
}

dataset_change = "This is the mutated dataset"

zonefile_hash = None
error = False

def scenario( wallets, **kw ):

    global put_result, legacy_profile, zonefile_hash, zonefile_hash_2, error

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )
    
    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    # give foo.test a nonstandard zonefile (as something that serializes to JSON)
    nonstandard_zonefile_json = {'nonstandard': 'true', 'error': 'nonstandard'}
    nonstandard_zonefile_txt = json.dumps(nonstandard_zonefile_json, sort_keys=True)
    nonstandard_zonefile_raw = binascii.unhexlify( "".join(["%02x" % i for i in xrange(0, 256)]))

    zf_data = [nonstandard_zonefile_txt, nonstandard_zonefile_raw]
    for zi in xrange(0, len(zf_data)):
        nonstandard_zonefile = zf_data[zi]
        nonstandard_hash = blockstack.lib.storage.get_zonefile_data_hash(zf_data[i])
        resp = testlib.blockstack_name_update("foo.test", nonstandard_hash, wallets[3].privkey)
        if 'error' in resp:
            print "failed to put nonstandard zonefile '%s'" % nonstandard_zonefile
            print json.dumps(resp, indent=4, sort_keys=True)
            return False

        testlib.next_block(**kw)
        testlib.blockstack_put_zonefile(nonstandard_zonefile)

        # getting zonefile should still work...
        resp = testlib.blockstack_cli_get_name_zonefile( "foo.test")
        if 'error' in resp:
            print "failed to get zonefile %s" % zi
            print json.dumps(resp, indent=4, sort_keys=True)
            return False 

        if resp != nonstandard_zonefile:
            print "failed to load nonstandard zonefile json"
            print "expected:\n%s\n\ngot:\n%s" % (nonstandard_zonefile.encode('hex'), resp.encode('hex'))
            return False
     

def check( state_engine ):

    global datasets, zonefile_hash

    if error:
        return False

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is not None:
        print "namespace not ready"
        return False 

    ns = state_engine.get_namespace( "test" )
    if ns is None:
        print "no namespace"
        return False 

    if ns['namespace_id'] != 'test':
        print "wrong namespace"
        return False 

    name = "foo.test"
    wallet_payer = 2
    wallet_owner = 3
    wallet_data_pubkey = 4

    # not preordered
    preorder = state_engine.get_name_preorder( name, virtualchain.make_payment_script(wallets[wallet_payer].addr), wallets[wallet_owner].addr )
    if preorder is not None:
        print "still have preorder"
        return False

    # registered 
    name_rec = state_engine.get_name( name )
    if name_rec is None:
        print "name does not exist"
        return False 

    # owned 
    if name_rec['address'] != wallets[wallet_owner].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[wallet_owner].addr):
        print "name has wrong owner"
        return False

    return True
