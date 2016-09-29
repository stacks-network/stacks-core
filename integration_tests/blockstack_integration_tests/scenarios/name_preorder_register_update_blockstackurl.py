#!/usr/bin/env python
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
import pybitcoin
import urllib2
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
    testlib.Wallet( "5KaSTdRgMfHLxSKsiWhF83tdhEj2hqugxdBNPUAw5NU8DMyBJji", 100000000000 )
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
immutable_hash = None

def scenario( wallets, **kw ):

    global put_result, wallet_keys, legacy_profile, zonefile_hash, zonefile_hash_2, immutable_hash


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

    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )
    wallet_keys = blockstack_client.make_wallet_keys( owner_privkey=wallets[3].privkey, data_privkey=wallets[4].privkey, payment_privkey=wallets[8].privkey )
    wallet_keys_2 = blockstack_client.make_wallet_keys( owner_privkey=wallets[6].privkey, data_privkey=wallets[7].privkey, payment_privkey=wallets[9].privkey )

    # set up legacy profile hash
    legacy_txt = json.dumps(legacy_profile,sort_keys=True)
    legacy_hash = pybitcoin.hex_hash160( legacy_txt )

    result_1 = testlib.blockstack_name_update( "foo.test", legacy_hash, wallets[3].privkey )
    result_2 = testlib.blockstack_name_update( "bar.test", legacy_hash, wallets[6].privkey )
    testlib.next_block( **kw )

    rc = blockstack_client.storage.put_immutable_data( None, result_1['transaction_hash'], data_hash=legacy_hash, data_text=legacy_txt )
    assert rc is not None

    rc = blockstack_client.storage.put_immutable_data( None, result_2['transaction_hash'], data_hash=legacy_hash, data_text=legacy_txt )
    assert rc is not None

    testlib.next_block( **kw )

    # migrate 
    res = testlib.migrate_profile( "foo.test", proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in res:
        res['test'] = 'Failed to initialize foo.test profile'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 
    else:
        zonefile_hash = res['zonefile_hash']

    # migrate 
    res = testlib.migrate_profile( "bar.test", proxy=test_proxy, wallet_keys=wallet_keys_2 )
    if 'error' in res:
        res['test'] = 'Failed to initialize foo.test profile'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 
    else:
        zonefile_hash_2 = res['zonefile_hash']

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    testlib.next_block( **kw )

    # start up RPC for 'foo.test'
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] ) 

    # put immutable
    put_result = blockstack_client.put_immutable( "foo.test", "hello_world_immutable", {"hello": "world"}, proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True )
        error = True
        return

    immutable_hash = put_result['immutable_data_hash']
    testlib.expect_atlas_zonefile(put_result['zonefile_hash'])

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    # wait for confirmation
    for i in xrange(0, 12):
        testlib.next_block( **kw )

    print "waiting for confirmation"
    time.sleep(10)

    # start up RPC for 'bar.test'
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys_2['payment_privkey'], wallet_keys_2['owner_privkey'], wallet_keys_2['data_privkey'] ) 
    put_result = blockstack_client.put_mutable( "bar.test", "hello_world_mutable", {"hello": "world"}, proxy=test_proxy, wallet_keys=wallet_keys_2 )
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True )
        error = True
        return
    
    testlib.next_block( **kw )

    # put mutable data with the URL 
    res = blockstack_client.data_put( "blockstack://foo.test/foo_data2", {"hello2": "world2"}, proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    # put immutable data with the URL
    # start up RPC for 'foo.test'
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] ) 
    res = blockstack_client.data_put( "blockstack://foo_immutable.foo.test", {'hello3': 'world3'}, proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return
    
    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    testlib.next_block( **kw )

    # app data
    data_pk = wallets[-1].privkey
    data_pub = wallets[-1].pubkey_hex

    res = blockstack_client.create_app_account("foo.test", "serviceFoo", "serviceFooID", "foo://foo.com", ["disk"], data_pub, proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in res:
        res['test'] = 'Failed to create foo.test account'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    # put some data into the account
    res = blockstack_client.put_app_data( "foo.test", "serviceFoo", "serviceFooID", "foo_app_data", "foo_app_payload", data_pk, proxy=test_proxy )
    if 'error' in res:
        res['test'] = 'Failed to put app data'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    # put some app data, using the blockstack URL
    res = blockstack_client.data_put( "blockstack://serviceFooID.serviceFoo@foo.test/foo_app_data2#3", "foo_app_payload2", data_privkey=data_pk, proxy=test_proxy )
    if 'error' in res:
        res['test'] = 'Failed to put app data'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    testlib.next_block( **kw )
     

def get_data( url ):
    """
    Test urllib2 opener
    """
    handler = blockstack_client.BlockstackHandler(full_response=True)
    opener = urllib2.build_opener( handler )
    dat = opener.open( url )
    return json.loads( dat.read() )


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
        wallet_data_pubkey = 3 * (i+1) + 1
        wallet_keys = wallet_keys_list[i]
        zonefile_hash = zonefile_hashes[i]

        preorder = state_engine.get_name_preorder( name, pybitcoin.make_pay_to_address_script(wallets[wallet_payer].addr), wallets[wallet_owner].addr )
        if preorder is not None:
            print "still have preorder"
            return False
    
        # registered 
        name_rec = state_engine.get_name( name )
        if name_rec is None:
            print "name does not exist"
            return False 

        # owned 
        if name_rec['address'] != wallets[wallet_owner].addr or name_rec['sender'] != pybitcoin.make_pay_to_address_script(wallets[wallet_owner].addr):
            print "name has wrong owner"
            return False 

        # zonefile is NOT legacy 
        user_zonefile = blockstack_client.profile.load_name_zonefile( name, zonefile_hash )
        if 'error' in user_zonefile:
            print json.dumps(user_zonefile, indent=4, sort_keys=True)
            return False 

        if blockstack_profiles.is_profile_in_legacy_format( user_zonefile ):
            print "legacy still"
            print json.dumps(user_zonefile, indent=4, sort_keys=True)
            return False

        # still have all the right info 
        user_profile = blockstack_client.profile.load_name_profile( name, user_zonefile, wallets[wallet_data_pubkey].addr, wallets[wallet_owner].addr )
        if user_profile is None:
            print "Unable to load user profile for %s (%s)" % (name, wallets[wallet_data_pubkey].pubkey_hex)
            return False

        if 'error' in user_profile:
            print json.dumps(user_profile, indent=4, sort_keys=True)
            return False


    # can fetch latest by name 
    immutable_data = get_data( "blockstack://hello_world_immutable.foo.test/" )
    if 'error' in immutable_data:
        print json.dumps(immutable_data, indent=4, sort_keys=True)
        return False 

    if immutable_data['data'] != {'hello': 'world'}:
        print "immutable fetch-latest mismatch:\n%s (%s)\n%s" % (immutable_data['data'], type(immutable_data['data']), {'hello': 'world'})
        return False 

    if immutable_data['hash'] != immutable_hash:
        print "immutable fetch-latest hash mismatch: %s != %s" % (immutable_data['hash'], immutable_hash)
        return False 

    # can fetch by name and hash
    immutable_data = get_data( "blockstack://hello_world_immutable.foo.test/#%s" % immutable_hash )
    if 'error' in immutable_data:
        print json.dumps(immutable_data, indent=4, sort_keys=True)
        return False 

    if immutable_data['data'] != {'hello': 'world'}:
        print "immutable fetch-by-hash mismatch:\n%s (%s)\n%s" % (immutable_data['data'], type(immutable_data['data']), {'hello': 'world'})
        return False 

    if immutable_data['hash'] != immutable_hash:
        print "immutable fetch-by-hash mismatch: %s != %s" % (immutable_data['hash'], immutable_hash)
        return False 

    # hash must match (if we put the wrong hash, it must fail)
    try:
        immutable_data = get_data( "blockstack://hello_world_immutable.foo.test/#%s" % ("0" * len(immutable_hash)))
        print "no error"
        print json.dumps(immutable_data, indent=4, sort_keys=True)
        return False
    except urllib2.URLError:
        pass

    # can list names and hashes
    immutable_data_list = get_data( "blockstack://foo.test/#immutable" )
    if 'error' in immutable_data_list:
        print json.dumps(immutable_data, indent=4, sort_keys=True )
        return False 

    if len(immutable_data_list['data']) != 2:
        print "multiple immutable data"
        print json.dumps(immutable_data_list, indent=4, sort_keys=True )
        return False 

    # order preserved
    if immutable_data_list['data'][0]['data_id'] != 'hello_world_immutable' or immutable_data_list['data'][0]['hash'] != immutable_hash:
        print "wrong data ID and/or hash"
        print json.dumps(immutable_data_list, indent=4, sort_keys=True )
        return False 

    # can fetch latest mutable by name
    mutable_data = get_data( "blockstack://bar.test/hello_world_mutable")
    if 'error' in mutable_data:
        print json.dumps(mutable_data, indent=4, sort_keys=True)
        return False 

    if mutable_data['data'] != {'hello': 'world'}:
        print json.dumps(mutable_data, indent=4, sort_keys=True)
        return False

    if mutable_data['version'] != 1:
        print "wrong version: %s" % mutable_data['data']['version']
        return False 

    # can fetch by version
    mutable_data = get_data( "blockstack://bar.test/hello_world_mutable#1")
    if 'error' in mutable_data:
        print json.dumps(mutable_data, indent=4, sort_keys=True)
        return False 

    if mutable_data['data'] != {'hello': 'world'}:
        print json.dumps(mutable_data, indent=4, sort_keys=True)
        return False 

    # will fail to fetch if we give the wrong version 
    try:
        mutable_data = get_data("blockstack://bar.test/hello_world_mutable#2")
        print "mutable fetch by wrong version worked"
        print json.dumps(mutable_data, indent=4, sort_keys=True)
        return False
    except urllib2.URLError:
        pass

    # can list mutable data
    mutable_data_list = get_data( "blockstack://bar.test/#mutable" )
    if 'error' in mutable_data_list:
        print json.dumps(mutable_data_list, indent=4, sort_keys=True )
        return False 

    if len(mutable_data_list) != 1:
        print "multiple mutable data"
        print json.dumps(mutable_data_list, indent=4, sort_keys=True )
        return False 

    if mutable_data_list['data'][0]['data_id'] != 'hello_world_mutable' or mutable_data_list['data'][0]['version'] != 1:
        print "wrong data id and/or version"
        print json.dumps(mutable_data_list, indent=4, sort_keys=True)
        return False

    # can fetch mutable data put by URL
    mutable_data = get_data( "blockstack://foo.test/foo_data2" )
    if 'error' in mutable_data or 'data' not in mutable_data or 'version' not in mutable_data:
        print json.dumps(mutable_data, indent=4, sort_keys=True)
        return False
    
    if mutable_data['data'] != {'hello2': 'world2'}:
        print "Invalid mutable data fetched from blockstack://foo.test/foo_data2"
        print json.dumps(mutable_data, indent=4, sort_keys=True)
        return False

    # can fetch immutable data put by URL 
    immutable_data = get_data( "blockstack://foo_immutable.foo.test" )
    if 'error' in immutable_data or 'hash' not in immutable_data:
        print json.dumps(immutable_data, indent=4, sort_keys=True)
        return False

    if immutable_data['data'] != {'hello3': 'world3'}:
        print "Invalid immutable data fetched from blockstack://foo_immutable.foo.test" 
        print json.dumps(immutable_data, indent=4, sort_keys=True)
        return False

    # can fetch app data put by URL 
    mutable_data = get_data( "blockstack://serviceFooID.serviceFoo@foo.test/foo_app_data" )
    if 'error' in mutable_data or 'data' not in mutable_data or 'version' not in mutable_data:
        print "Failed to get blockstack://serviceFooID.serviceFoo@foo.test/foo_app_data"
        print json.dumps(mutable_data, indent=4, sort_keys=True)
        return False

    if mutable_data['data'] != "foo_app_payload":
        print "Invalid data for blockstack://serviceFooID.serviceFoo@foo.test/foo_app_data"
        print json.dumps(mutable_data, indent=4, sort_keys=True)
        return False

    mutable_data = get_data( "blockstack://serviceFooID.serviceFoo@foo.test/foo_app_data2#3" )
    if 'error' in mutable_data or 'data' not in mutable_data or 'version' not in mutable_data:
        print "Failed to get blockstack://serviceFooID.serviceFoo@foo.test/foo_app_data2#3"
        print json.dumps(mutable_data, indent=4, sort_keys=True)
        return False

    if mutable_data['data'] != "foo_app_payload2":
        print "Failed to get blockstack://serviceFooID.serviceFoo@foo.test/foo_app_data2#3"
        print json.dumps(mutable_data, indent=4, sort_keys=True)
        return False

    # fetch by wrong version will fail
    try:
        mutable_data = get_data( "blockstack://serviceFooID.serviceFoo@foo.test/foo_app_data2#4" )
        print "got stale data with no error"
        print json.dumps(mutable_data, indent=4, sort_keys=True)
        return False
    except urllib2.URLError:
        pass

    return True
