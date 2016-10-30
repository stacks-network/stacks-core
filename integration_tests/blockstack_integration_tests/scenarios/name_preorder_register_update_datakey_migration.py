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

log = blockstack_client.get_logger("blockstack-integration-tests")

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet( "5KaSTdRgMfHLxSKsiWhF83tdhEj2hqugxdBNPUAw5NU8DMyBJji", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
wallet_keys = None

datasets = [
    {u"dataset_1": u"My first dataset!"},
    {u"dataset_2": {u"id": u"abcdef", u"desc": u"My second dataset!", u"data": [1, 2, 3, 4]}},
    {u"dataset_3": u"My third datset!"}
]

def scenario( wallets, **kw ):

    global datasets

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
    wallet_keys = blockstack_client.make_wallet_keys( owner_privkey=wallets[3].privkey, payment_privkey=wallets[5].privkey )
    
    # migrate profile (but no data key)
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

    # put immutable (with owner key)
    log.debug("put immutable 1 with owner key")
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] ) 
    put_result = blockstack_client.put_immutable( "foo.test", "hello_world_1_immutable", datasets[0], data_url="http://www.example.unroutable", proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)
        error = True
        return

    testlib.expect_atlas_zonefile(put_result['zonefile_hash'])

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    # wait for confirmation
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "waiting for confirmation"
    time.sleep(10)
    
    # put immutable (with owner key)
    log.debug("put immutable 2 with owner key")
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] ) 
    put_result = blockstack_client.put_immutable( "foo.test", "hello_world_2_immutable", datasets[1], data_url="http://www.example.unroutable", proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)
        error = True
        return

    testlib.expect_atlas_zonefile(put_result['zonefile_hash'])

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    # wait for confirmation
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "waiting for confirmation"
    time.sleep(10)

    # put mutable (with owner key)
    log.debug("put mutable 1 with owner key")
    put_result = blockstack_client.put_mutable( "foo.test", "hello_world_1_mutable", datasets[0], proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)
        error = True
        return

    # put mutable (with owner key)
    log.debug("put mutable 2 with owner key")
    put_result = blockstack_client.put_mutable( "foo.test", "hello_world_2_mutable", datasets[1], proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)
        error = True 
        return

    testlib.next_block( **kw )

    # add data signing key 
    res = blockstack_client.set_data_pubkey("foo.test", wallets[4].pubkey_hex, wallet_keys=wallet_keys, proxy=test_proxy )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 

    testlib.expect_atlas_zonefile(res['zonefile_hash'])

    wallet_keys['data_privkey'] = wallets[4].privkey
    wallet_keys['data_pubkey'] = wallets[4].pubkey_hex

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    # wait for confirmation
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "waiting for confirmation"
    time.sleep(10)

    # put immutable (with new key)
    log.debug("put immutable with new key")

    # restart daemon
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] ) 

    # put immutable
    put_result = blockstack_client.put_immutable( "foo.test", "hello_world_3_immutable", datasets[2], data_url="http://www.example.unroutable", proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)
        error = True
        return

    testlib.expect_atlas_zonefile(put_result['zonefile_hash'])

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    # wait for confirmation
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "waiting for confirmation"
    time.sleep(10)

    # put mutable (with new key)
    log.debug("put mutable with new key")
    put_result = blockstack_client.put_mutable( "foo.test", "hello_world_3_mutable", datasets[2], proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)
        error = True 
        return

    testlib.next_block( **kw )

    # delete immutable (new key)
    log.debug("delete immutable with new key")
    result = blockstack_client.delete_immutable( "foo.test", None, data_id="hello_world_1_immutable", proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in result:
        print json.dumps(result, indent=4, sort_keys=True)
        error = True
        return 

    testlib.expect_atlas_zonefile(result['zonefile_hash'])

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    # wait for confirmation
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "waiting for confirmation"
    time.sleep(10)

    # delete mutable (new key)
    log.debug("delete mutable with new key")
    result = blockstack_client.delete_mutable( "foo.test", "hello_world_1_mutable", proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in result:
        print json.dumps(result, indent=4, sort_keys=True)
        error = True
        return

    testlib.next_block( **kw )



def check( state_engine ):

    global error

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

    # have right data 
    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )

    # should always work
    for i in xrange(1, len(datasets)):
        immutable_data = blockstack_client.get_immutable_by_name( "foo.test", "hello_world_%s_immutable" % (i+1), proxy=test_proxy )
        if immutable_data is None:
            print "No data received for immutable dataset %s" % i
            return False 

        if 'error' in immutable_data:
            print "No data received for immutable dataset %s: %s" % (i, immutable_data['error'])
            return False

        if not immutable_data.has_key('data'):
            print "Missing data\n%s" % json.dumps(immutable_data, indent=4, sort_keys=True)
            return False 

        data_json = immutable_data['data']
        if data_json != datasets[i]:
            print "did not get dataset %s\ngot %s\nexpected %s" % (i, data_json, datasets[i])
            return False 

        mutable_data = blockstack_client.get_mutable( "foo.test", "hello_world_%s_mutable" % (i+1), proxy=test_proxy )
        if mutable_data is None:
            print "No data received for mutable dataset %s" % (i+1)
            return False

        if 'error' in mutable_data:
            print "No data received for mutable dataset %s: %s" % (i+1, mutable_data['error'])
            return False

        data_json = mutable_data['data']
        if data_json != datasets[i]:
            print "did not get dataset %s\ngot %s\nexpected %s" % (i+1, data_json, datasets[i])
            return False

    # should fail 
    immutable_data = blockstack_client.get_immutable_by_name( "foo.test", "hello_world_1_immutable", proxy=test_proxy)
    if immutable_data is not None and 'error' not in immutable_data:
        print "Got deleted immutable dataset"
        return False

    mutable_data = blockstack_client.get_mutable( "foo.tesT", "hello_world_1_mutable", proxy=test_proxy )
    if mutable_data is not None and 'error' not in mutable_data:
        print "Got deleted mutable dataset"
        return False

    return True
