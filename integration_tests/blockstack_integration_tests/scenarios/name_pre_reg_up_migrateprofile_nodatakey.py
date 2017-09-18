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
import blockstack_client
import blockstack_profiles
import time
import sys

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
zonefile_hash_2 = None

def scenario( wallets, **kw ):

    global put_result, wallet_keys, legacy_profile, zonefile_hash, zonefile_hash_2

    wallet_keys = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[8].privkey, wallets[3].privkey, None )
    wallet_keys_2 = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[9].privkey, wallets[6].privkey, None )

    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )
    
    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.blockstack_name_preorder( "bar.test", wallets[5].privkey, wallets[6].addr )
    testlib.next_block( **kw )
    
    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.blockstack_name_register( "bar.test", wallets[5].privkey, wallets[6].addr )
    testlib.next_block( **kw )

    # set up legacy profile hash
    legacy_txt = json.dumps(legacy_profile,sort_keys=True)
    legacy_hash = virtualchain.lib.hashing.hex_hash160( legacy_txt )

    result_1 = testlib.blockstack_name_update( "foo.test", legacy_hash, wallets[3].privkey )
    result_2 = testlib.blockstack_name_update( "bar.test", legacy_hash, wallets[6].privkey )
    testlib.next_block( **kw )

    rc = blockstack_client.storage.put_immutable_data( legacy_txt, result_1['transaction_hash'], data_hash=legacy_hash )
    assert rc is not None

    rc = blockstack_client.storage.put_immutable_data( legacy_txt, result_2['transaction_hash'], data_hash=legacy_hash )
    assert rc is not None

    testlib.next_block( **kw )

    # migrate profiles 
    res = testlib.migrate_profile( "foo.test", proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in res:
        res['test'] = 'Failed to initialize foo.test profile'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 

    zonefile_hash = res['zonefile_hash']

    res = testlib.migrate_profile( "bar.test", proxy=test_proxy, wallet_keys=wallet_keys_2 )
    if 'error' in res:
        res['test'] = 'Failed to initialize bar.test profile'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    zonefile_hash_2 = res['zonefile_hash']

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    testlib.next_block( **kw )

    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] )
 
    res = testlib.start_api("0123456789abcdef")
    if 'error' in res:
        print 'failed to start API: {}'.format(res)
        return False

    # see that put_immutable works
    put_result = testlib.blockstack_cli_put_immutable( 'foo.test', 'hello_world_immutable', json.dumps({'hello': 'world_immutable'}, sort_keys=True), password='0123456789abcdef')
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True )

    testlib.expect_atlas_zonefile(put_result['zonefile_hash'])
    
    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    # wait for confirmation
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "waiting for confirmation"
    time.sleep(10)

    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys_2['payment_privkey'], wallet_keys_2['owner_privkey'], wallet_keys_2['data_privkey'] )
 
    res = testlib.start_api("0123456789abcdef")
    if 'error' in res:
        print 'failed to start API: {}'.format(res)
        return False

    # see that put_mutable works
    put_result = testlib.blockstack_cli_put_mutable( "bar.test", "hello_world_mutable", json.dumps({'hello': 'world'}, sort_keys=True), password='0123456789abcdef')
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True )
    
    testlib.next_block( **kw )
     

def check( state_engine ):

    global wallet_keys, wallet_keys_2, datasets, zonefile_hash, zonefile_hash_2


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

    # not preordered
    names = ['foo.test', 'bar.test']
    wallet_keys_list = [wallet_keys, wallet_keys_2]
    zonefile_hashes = [zonefile_hash[:], zonefile_hash_2[:]]

    for i in xrange(0, len(names)):
        name = names[i]
        wallet_payer = 3 * (i+1) - 1
        wallet_owner = 3 * (i+1)
        wallet_data_pubkey = 3 * (i+1)  # same as owner key
        wallet_keys = wallet_keys_list[i]
        zonefile_hash = zonefile_hashes[i]

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

        # zonefile is NOT legacy 
        user_zonefile = blockstack_client.zonefile.load_name_zonefile( name, zonefile_hash )
        if 'error' in user_zonefile:
            print json.dumps(user_zonefile, indent=4, sort_keys=True)
            return False 

        if blockstack_profiles.is_profile_in_legacy_format( user_zonefile ):
            print "legacy still"
            print json.dumps(user_zonefile, indent=4, sort_keys=True)
            return False

        # still have all the right info 
        user_profile = blockstack_client.profile.get_profile( name, user_zonefile=user_zonefile )
        if user_profile is None or 'error' in user_profile:
            if user_profile is not None:
                print json.dumps(user_profile, indent=4, sort_keys=True)
            else:
                print "\n\nprofile is None\n\n"

            return False

    # can get mutable data 
    res = testlib.blockstack_cli_get_mutable( "bar.test", "hello_world_mutable" )
    print 'mutable: {}'.format(res)

    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        return False
    
    if json.loads(res['data']) != {'hello': 'world'}:
        print 'invalid data: {}'.format(res['data'])
        return False

    # can get immutable data by name
    res = testlib.blockstack_cli_get_immutable( 'foo.test', 'hello_world_immutable' )
    print 'immutable by name: {}'.format(res)

    if 'error' in res:
        return res

    if json.loads(res['data']) != {'hello': 'world_immutable'}:
        print 'invalid immutable data: {}'.format(res['data'])
        return False

    # can get immutable data by hash
    hsh = res['hash']
    res = testlib.blockstack_cli_get_immutable( 'foo.test', hsh )
    print 'immutable: {}'.format(res)

    if 'error' in res:
        return res

    if json.loads(res['data']) != {'hello': 'world_immutable'}:
        print 'invalid immutable data by hash: {}'.format(res['data'])
        return False

    return True
