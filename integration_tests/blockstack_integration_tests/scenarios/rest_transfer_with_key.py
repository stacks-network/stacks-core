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
import os
import testlib
import virtualchain
import urllib2
import json
import blockstack_client
import blockstack_profiles
import blockstack_zones
import sys
import keylib
import time

from keylib import ECPrivateKey, ECPublicKey

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
    testlib.Wallet( "5KMbNjgZt29V6VNbcAmebaUT2CZMxqSridtM46jv4NkKTP8DHdV", 100000000000 ),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
wallet_keys = None
wallet_keys_2 = None
error = False

index_file_data = "<html><head></head><body>foo.test hello world</body></html>"
resource_data = "hello world"

new_key = "cPo24qGYz76xSbUCug6e8LzmzLGJPZoowQC7fCVPLN2tzCUJgfcW"
new_addr = virtualchain.get_privkey_address(new_key) # "mqnupoveYRrSHmrxFT9nQQEZt3RLsetbBQ"

insanity_key = "cSCyE5Q1AFVyDAL8LkHo1sFMVqmwdvFcCbGJ71xEvto2Nrtzjm67"

destination_owner = "17EXa2337HctK27B7TR1HFek1wE6V3krdU"

def scenario( wallets, **kw ):

    global wallet_keys, wallet_keys_2, error, index_file_data, resource_data

    wallet_keys = testlib.blockstack_client_initialize_wallet(
        "0123456789abcdef", wallets[5].privkey, wallets[3].privkey, wallets[4].privkey )
    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()

    testlib.next_block( **kw )

    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)

    # let's set the key to skip the transfer.
    config_dir = os.path.dirname(config_path)
    conf = blockstack_client.get_config(config_path)
    assert conf

    api_pass = conf['api_password']

    res = testlib.blockstack_REST_call('PUT', '/v1/wallet/keys/owner', None, api_pass=api_pass,
                                       data=new_key)
    if res['http_status'] != 200 or 'error' in res:
        print 'failed to set owner key'
        print res
        return False

    # make zonefile for recipient
    driver_urls = blockstack_client.storage.make_mutable_data_urls('bar.test', use_only=['dht', 'disk'])
    zonefile = blockstack_client.zonefile.make_empty_zonefile('bar.test', wallets[4].pubkey_hex, urls=driver_urls)
    zonefile_txt = blockstack_zones.make_zone_file( zonefile, origin='bar.test', ttl=3600 )

    # leaving the call format of this one the same to make sure that our registrar correctly
    #   detects that the requested TRANSFER is superfluous
    # register the name bar.test
    res = testlib.blockstack_REST_call(
        'POST', '/v1/names', None, api_pass=api_pass, data={
            'name': 'bar.test', 'zonefile': zonefile_txt, 'owner_address': new_addr
        })
    if 'error' in res:
        res['test'] = 'Failed to register user'
        print json.dumps(res)
        error = True
        return False

    print res
    tx_hash = res['response']['transaction_hash']

    # wait for preorder to get confirmed...
    for i in xrange(0, 6):
        testlib.next_block( **kw )

    res = testlib.verify_in_queue(None, 'bar.test', 'preorder', tx_hash, api_pass = api_pass )
    if not res:
        return False

    # wait for the preorder to get confirmed
    for i in xrange(0, 4):
        testlib.next_block( **kw )

    # wait for register to go through
    print 'Wait for register to be submitted'
    time.sleep(10)

    # wait for the register to get confirmed
    for i in xrange(0, 6):
        testlib.next_block( **kw )

    res = testlib.verify_in_queue(None, 'bar.test', 'register', None, api_pass = api_pass )
    if not res:
        return False

    for i in xrange(0, 4):
        testlib.next_block( **kw )

    print 'Wait for update to be submitted'
    time.sleep(10)

    # wait for update to get confirmed
    for i in xrange(0, 6):
        testlib.next_block( **kw )

    res = testlib.verify_in_queue(None, 'bar.test', 'update', None, api_pass = api_pass )
    if not res:
        print res
        print "update error in first update"
        return False

    for i in xrange(0, 4):
        testlib.next_block( **kw )

    print 'Wait for transfer to be submitted'
    time.sleep(10)

    # wait for transfer to get confirmed
    for i in xrange(0, 6):
        testlib.next_block( **kw )

    res = testlib.verify_in_queue(None, 'bar.test', 'transfer', None, api_pass = api_pass )
    if res:
        print "Wrongly issued a TRANSFER"
        return False

    res = testlib.blockstack_REST_call("GET", "/v1/names/bar.test",
                                       None, api_pass=api_pass)
    if 'error' in res or res['http_status'] != 200:
        res['test'] = 'Failed to get name bar.test'
        print json.dumps(res)
        return False

    zonefile_hash = res['response']['zonefile_hash']

    # should still be registered
    if res['response']['status'] != 'registered':
        print "register not complete"
        print json.dumps(res)
        return False

    # do we have the history for the name?
    res = testlib.blockstack_REST_call("GET", "/v1/names/bar.test/history",
                                       None, api_pass=api_pass )
    if 'error' in res or res['http_status'] != 200:
        res['test'] = "Failed to get name history for foo.test"
        print json.dumps(res)
        return False

    # valid history?
    hist = res['response']
    if len(hist.keys()) != 3:
        res['test'] = 'Failed to get update history'
        res['history'] = hist
        print json.dumps(res, indent=4, sort_keys=True)
        return False

    # get the zonefile
    res = testlib.blockstack_REST_call("GET", "/v1/names/bar.test/zonefile/{}".format(zonefile_hash),
                                       None, api_pass=api_pass )
    if 'error' in res or res['http_status'] != 200:
        res['test'] = 'Failed to get name zonefile'
        print json.dumps(res)
        return False

    # same zonefile we put?
    if res['response']['zonefile'] != zonefile_txt:
        res['test'] = 'mismatched zonefile, expected\n{}\n'.format(zonefile_txt)
        print json.dumps(res)
        return False

    # okay, now let's try to do a transfer.
    # FIRST, I want to change the key to a key that
    #  doesn't own the name and a payment key that has no money
    res = testlib.blockstack_REST_call('PUT', '/v1/wallet/keys/owner', None, api_pass=api_pass,
                                       data=insanity_key)
    if res['http_status'] != 200 or 'error' in res:
        print 'failed to set owner key'
        print res
        return False

    res = testlib.blockstack_REST_call('PUT', '/v1/wallet/keys/payment', None, api_pass=api_pass,
                                       data=insanity_key)
    if res['http_status'] != 200 or 'error' in res:
        print 'failed to set owner key'
        print res
        return False

    payment_key = wallets[1].privkey

    # let's do this with the bad key
    res = testlib.blockstack_REST_call(
        'PUT', '/v1/names/bar.test/owner', None, api_pass=api_pass, data={
            'owner': destination_owner, 'payment_key' : payment_key
        })
    if 'error' in res or res['http_status'] != 202:
        res['test'] = '(Correctly) failed to transfer user'
        print json.dumps(res)


    # let's do this with the good one!
    res = testlib.blockstack_REST_call(
        'PUT', '/v1/names/bar.test/owner', None, api_pass=api_pass, data={
            'owner': destination_owner, 'owner_key' : new_key,
            'payment_key' : payment_key
        })
    if 'error' in res or res['http_status'] != 202:
        res['test'] = '(Wrongly) failed to transfer user'
        print json.dumps(res)
        error = True
        return False
    else:
        print "Submitted transfer!"
        print res

    print 'Wait for transfer to be submitted'
    time.sleep(10)

    # wait to get confirmed
    for i in xrange(0, 6):
        testlib.next_block( **kw )

    res = testlib.verify_in_queue(None, 'bar.test', 'transfer', None, api_pass = api_pass )
    if not res:
        print "transfer error"
        print res
        return False

    for i in xrange(0, 4):
        testlib.next_block( **kw )

    # wait for zonefile to propagate
    time.sleep(10)

    res = testlib.blockstack_REST_call("GET", "/v1/names/bar.test",
                                       None, api_pass=api_pass)
    if 'error' in res or res['http_status'] != 200:
        res['test'] = 'Failed to get name bar.test'
        print json.dumps(res)
        return False

    cur_owner_address = res['response']['address']
    if cur_owner_address != destination_owner:
        print "After transfer, unexpected owner. Expected {}, Actual {}".format(
            destination_owner, cur_owner_address)
        return False

def check( state_engine ):

    global wallet_keys, error, index_file_data, resource_data

    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG")
    assert config_path

    if error:
        print "Key operation failed."
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

    return True
