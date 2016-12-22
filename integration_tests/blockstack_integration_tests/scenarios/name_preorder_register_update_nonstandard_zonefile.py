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
import json
import blockstack_client
import blockstack_profiles
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

    global put_result, wallet_keys, legacy_profile, zonefile_hash, zonefile_hash_2, error


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

    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )
    wallet_keys = blockstack_client.make_wallet_keys( owner_privkey=wallets[3].privkey, data_privkey=wallets[4].privkey, payment_privkey=wallets[8].privkey )

    # set up legacy profile hash
    legacy_txt = json.dumps(legacy_profile,sort_keys=True)
    legacy_hash = pybitcoin.hex_hash160( legacy_txt )

    result_1 = testlib.blockstack_name_update( "foo.test", legacy_hash, wallets[3].privkey )
    testlib.next_block( **kw )

    rc = blockstack_client.storage.put_immutable_data( None, result_1['transaction_hash'], data_hash=legacy_hash, data_text=legacy_txt )
    assert rc is not None

    testlib.next_block( **kw )

    # migrate profiles to standard zonefiles
    res = testlib.migrate_profile( "foo.test", proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in res:
        res['test'] = 'Failed to initialize foo.test profile'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 

    testlib.next_block( **kw )

    # give foo.test a nonstandard zonefile (as something that serializes to JSON)
    nonstandard_zonefile_json = {'nonstandard': 'true', 'error': 'nonstandard'}
    nonstandard_zonefile_txt = json.dumps(nonstandard_zonefile_json, sort_keys=True)
    nonstandard_zonefile_raw = binascii.unhexlify( "".join(["%02x" % i for i in xrange(0, 256)]))

    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] )

    zf_data = [nonstandard_zonefile_txt, nonstandard_zonefile_raw]
    for zi in xrange(0, len(zf_data)):
        nonstandard_zonefile = zf_data[zi]

        resp = testlib.blockstack_cli_update( "foo.test", nonstandard_zonefile, "0123456789abcdef", nonstandard=True )
        if 'error' in resp:
            print "failed to put nonstandard zonefile '%s'" % nonstandard_zonefile
            print json.dumps(resp, indent=4, sort_keys=True)
            error = True
            return

        testlib.expect_atlas_zonefile(resp['value_hash'])

        # wait for it to take effect
        for i in xrange(0, 12):
            testlib.next_block( **kw )

        time.sleep(3)

        # getting zonefile should still work...
        resp = testlib.blockstack_cli_get_name_zonefile( "foo.test", json=True )
        if 'error' in resp:
            print "failed to get zonefile %s" % zi
            print json.dumps(resp, indent=4, sort_keys=True)
            error = True
            return 

        if 'warning' not in resp:
            print "no non-standard warning:\n%s" % json.dumps(resp, indent=4, sort_keys=True)
            error = True
            return

        if resp['zonefile'] != nonstandard_zonefile:
            print "failed to load nonstandard zonefile json"
            print "expected:\n%s\n\ngot:\n%s" % (nonstandard_zonefile, resp['zonefile'])
            error = True
            return 

        # the following should all fail
        dataplane_funcs = [
            ("lookup",        lambda: testlib.blockstack_cli_lookup( "foo.test" )),
            ("put_immutable", lambda: testlib.blockstack_cli_put_immutable( "foo.test", "fail", '{"Fail": "Yes"}' )),
            ("get_immutable", lambda: testlib.blockstack_cli_get_immutable( "foo.test", "fail" )),
            ("put_mutable",   lambda: testlib.blockstack_cli_put_mutable( "foo.test", "fail", '{"fail": "yes"}' )),
            ("get_mutable",   lambda: testlib.blockstack_cli_get_mutable( "foo.test", "fail" )),
            ("delete_immutable", lambda: testlib.blockstack_cli_delete_immutable( "foo.test", "00" * 32 )),
            ("delete_mutable", lambda: testlib.blockstack_cli_delete_mutable( "foo.test", "fail" ))
        ]

        for data_func_name, data_func in dataplane_funcs:
            resp = data_func()
            if 'error' not in resp:
                print "%s succeeded when it should not have:\n%s" % (data_func_name, json.dumps(resp, indent=4, sort_keys=True))
                error = True
                return
      
        # this should succeed
        zf_hist = testlib.blockstack_cli_list_zonefile_history( "foo.test" )
        if len(zf_hist) != 2*(zi+1)+1:
            print "missing zonefile history: %s (expected %s items, got %s)" % (zf_hist, zi+3, len(zf_hist))
            error = True
            return

        if zf_hist[-1] != nonstandard_zonefile:
            print "invalid zonefile: expected\n%s\ngot\n%s\n" % (nonstandard_zonefile, zf_hist[-1])
            error = True
            return

        # this should work, but with "non-standard zonefiles"
        hist = testlib.blockstack_cli_list_immutable_data_history("foo.test", "fail")
        if len(hist) != 2*(zi+1)+1:
            print "missing immutable data history: %s (expected %s items, got %s)" % (hist, zi+3, len(hist))
            error = True
            return 

        if hist[-1] != 'non-standard zonefile':
            print "not a non-standard zonefile: %s" % hist[-1]
            error = True
            return 

        # verify that we can migrate it back
        resp = testlib.blockstack_cli_migrate( "foo.test", "0123456789abcdef", force=True )
        if 'error' in resp:
            print "failed to migrate"
            print json.dumps(resp, indent=4, sort_keys=True)
            error = True
            return 

        zonefile_hash = resp['zonefile_hash']

        # wait for it to take effect
        for i in xrange(0, 12):
            testlib.next_block( **kw )

        time.sleep(3)

    # see that put_immutable works
    put_result = blockstack_client.put_immutable( "foo.test", "hello_world_immutable", {"hello": "world"}, proxy=test_proxy, wallet_keys=wallet_keys )
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
    time.sleep(3)

    # see that put_mutable works
    put_result = blockstack_client.put_mutable( "foo.test", "hello_world_mutable", {"hello": "world"}, proxy=test_proxy, wallet_keys=wallet_keys_2 )
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True )
    
    testlib.next_block( **kw )
     

def check( state_engine ):

    global wallet_keys, datasets, zonefile_hash

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

    # still have a profile with data
    user_profile = blockstack_client.profile.load_name_profile( name, user_zonefile, wallets[wallet_data_pubkey].addr, wallets[wallet_owner].addr )
    if user_profile is None or 'error' in user_profile:
        if user_profile is not None:
            print json.dumps(user_profile, indent=4, sort_keys=True)
        else:
            print "\n\nprofile is None\n\n"
                    
        return False

    # still have immutable data
    immutable_data_by_name = blockstack_client.get_immutable_by_name( "foo.test", "hello_world_immutable" )
    if immutable_data_by_name is None:
        print "No data received by name for dataset %s" % i
        return False 

    if 'error' in immutable_data_by_name:
        print "No data received for dataset hello_world_immutable"
        return False 

    if not immutable_data_by_name.has_key('data'):
        print "Misisng data\n%s" % json.dumps(immutable_data_by_name, indent=4, sort_keys=True)
        return False 

    data_json = immutable_data_by_name['data']
    if data_json != {'hello': 'world'}:
        print "did not get dataset hello_world_immutable\ngot %s\nexpected %s" % (data_json, {'hello': 'world'})
        return False 

    # still have mutable data
    dat = blockstack_client.get_mutable( "foo.test", "hello_world_mutable" )
    if dat is None:
        print "No hello_world_mutable"
        return False 

    if 'error' in dat:
        print json.dumps(dat, indent=4, sort_keys=True)
        return False 

    if dat['data'] != {'hello': 'world'}:
        print "did not get mutable dataset"
        return False

    return True
