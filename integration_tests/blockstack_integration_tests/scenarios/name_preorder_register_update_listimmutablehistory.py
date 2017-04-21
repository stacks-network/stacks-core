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
import time
import sys

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet( "5J5uAKL8s62hddganFJaCkWi3Me7PFoc7fks9hAzjtWG1NDjmUK", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
wallet_keys = None

datasets = [
    {"dataset_1": "My first dataset!"},
    {"dataset_2": {"id": "abcdef", "desc": "My second dataset!", "data": [1, 2, 3, 4]}},
    {"dataset_3": "My third datset!"}
]

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

put_result = None
data_history_1 = []
data_history_2 = []
data_history_3 = []

def scenario( wallets, **kw ):

    global datasets, put_result, legacy_profile, data_history_1, data_history_2, data_history_3

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

    # empty data 
    testlib.blockstack_name_update( "foo.test", "00" * 20, wallets[3].privkey )
    data_history_1.append("missing zonefile")
    data_history_2.append("missing zonefile")
    data_history_3.append("missing zonefile")

    testlib.next_block( **kw )
    
    # set up legacy profile hash
    legacy_txt = json.dumps(legacy_profile,sort_keys=True)
    legacy_hash = pybitcoin.hex_hash160( legacy_txt )

    result = testlib.blockstack_name_update( "foo.test", legacy_hash, wallets[3].privkey )
    data_history_1.append("non-standard zonefile")
    data_history_2.append("non-standard zonefile")
    data_history_3.append("non-standard zonefile")
    testlib.next_block( **kw )

    rc = blockstack_client.storage.put_immutable_data( None, result['transaction_hash'], data_hash=legacy_hash, data_text=legacy_txt )
    assert rc is not None

    # put immutable data
    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )
    wallet_keys = blockstack_client.make_wallet_keys( owner_privkey=wallets[3].privkey, data_privkey=wallets[4].privkey, payment_privkey=wallets[5].privkey )
    
    # migrate profile
    res = testlib.migrate_profile( "foo.test", proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in res:
        res['test'] = 'Failed to initialize foo.test profile'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    testlib.next_block( **kw )
    data_history_1.append("data not defined")
    data_history_2.append("data not defined")
    data_history_3.append("data not defined")

    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] ) 
 
    res = testlib.start_api("0123456789abcdef")
    if 'error' in res:
        print 'failed to start API: {}'.format(res)
        return False

    put_result = blockstack_client.put_immutable( "foo.test", "hello_world_1", datasets[0], proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)

    testlib.expect_atlas_zonefile(put_result['zonefile_hash'])

    data_history_1.append(put_result['immutable_data_hash'])
    data_history_2.append("data not defined")
    data_history_3.append("data not defined")

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    # wait for confirmation
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "waiting for confirmation"
    time.sleep(10)

    put_result = blockstack_client.put_immutable( "foo.test", "hello_world_2", datasets[1], proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)

    testlib.expect_atlas_zonefile(put_result['zonefile_hash'])

    data_history_1.append(data_history_1[-1])
    data_history_2.append(put_result['immutable_data_hash'])
    data_history_3.append("data not defined")

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    # wait for confirmation
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "waiting for confirmation"
    time.sleep(10)

    put_result = blockstack_client.put_immutable( "foo.test", "hello_world_3", datasets[2], proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)

    testlib.expect_atlas_zonefile(put_result['zonefile_hash'])

    data_history_1.append(data_history_1[-1])
    data_history_2.append(data_history_2[-1])
    data_history_3.append(put_result['immutable_data_hash'])

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    testlib.next_block( **kw )

    # wait for confirmation
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "waiting for confirmation"
    time.sleep(10)

    # overwrite
    datasets[0]['newdata'] = "asdf"
    put_result = blockstack_client.put_immutable( "foo.test", "hello_world_3", datasets[0], proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True )

    testlib.expect_atlas_zonefile(put_result['zonefile_hash'])

    data_history_1.append(data_history_1[-1])
    data_history_2.append(data_history_2[-1])
    data_history_3.append( put_result['immutable_data_hash'] )

    del datasets[0]['newdata']

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    # wait for confirmation
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "waiting for confirmation"
    time.sleep(10)


def check( state_engine ):

    global wallet_keys, data_history_1, data_history_2, data_history_3

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
    preorder = state_engine.get_name_preorder( "foo.test", pybitcoin.make_pay_to_address_script(wallets[2].addr), wallets[3].addr )
    if preorder is not None:
        print "still have preorder"
        return False
    
    # registered 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        print "name does not exist"
        return False 

    # owned 
    if name_rec['address'] != wallets[3].addr or name_rec['sender'] != pybitcoin.make_pay_to_address_script(wallets[3].addr):
        print "name has wrong owner"
        return False 

    # have right data history
    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )

    hist = [data_history_1, data_history_2, data_history_3]
    for i in xrange(0, len(hist)):
        test_hist = blockstack_client.list_immutable_data_history( "foo.test", "hello_world_%s" % (i+1))
        if test_hist != hist[i]:
            print "hello_world_%s expected: %s" % (i+1, ",".join(hist[i]))
            print "hello_world_%s got:      %s" % (i+1, ",".join(test_hist))
            return False

    return True
