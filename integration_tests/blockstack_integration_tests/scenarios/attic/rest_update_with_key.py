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
import time
import virtualchain

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

def scenario( wallets, **kw ):

    global wallet_keys, wallet_keys_2, error, index_file_data, resource_data

    empty_key = ECPrivateKey().to_hex()

    wallet_keys = testlib.blockstack_client_initialize_wallet(
        "0123456789abcdef", empty_key, empty_key, empty_key)
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

    config_dir = os.path.dirname(config_path)
    conf = blockstack_client.get_config(config_path)
    assert conf

    api_pass = conf['api_password']

    payment_key = wallets[1].privkey

    # make zonefile for recipient
    driver_urls = blockstack_client.storage.make_mutable_data_urls('bar.test', use_only=['dht', 'disk'])
    zonefile = blockstack_client.zonefile.make_empty_zonefile('bar.test', wallets[4].pubkey_hex, urls=driver_urls)
    zonefile_txt = blockstack_zones.make_zone_file( zonefile, origin='bar.test', ttl=3600 )

    no_key_postage = {'name': 'bar.test', 'zonefile': zonefile_txt}
    key_postage = dict(no_key_postage)
    key_postage['payment_key'] = payment_key
    key_postage['owner_key'] = new_key

    res = testlib.blockstack_REST_call('POST', '/v1/names', None, api_pass=api_pass, data=no_key_postage)
    if 'error' not in res['response']:
        print "Successfully registered user with should-have-been-bad keys"
        print res
        return False

    # let's do a small withdraw
    res = testlib.blockstack_REST_call('POST', '/v1/wallet/balance', None, api_pass=api_pass, data= {
        'address' : virtualchain.get_privkey_address(empty_key),
        'amount' : int(1e4),
        'payment_key' : payment_key
        })
    if 'error' in res['response']:
        res['test'] = 'Failed to perform withdraw'
        print json.dumps(res)
        error = True
        return False
    for i in xrange (0, 1):
        testlib.next_block( **kw )
    print 'Waiting for the withdraw to go through'
    res = testlib.blockstack_REST_call('GET', '/v1/wallet/balance/0', None, api_pass=api_pass)
    if 'error' in res['response']:
        res['test'] = 'Failed to get wallet balance'
        print json.dumps(res)
        error = True
        return False

    if int(res['response']['balance']['satoshis']) <= 0:
        res['test'] = 'Wallet balance did not increment!'
        print json.dumps(res)
        error = True
        return False

    res = testlib.blockstack_REST_call('POST', '/v1/names', None, api_pass=api_pass, data=key_postage)
    if 'error' in res['response']:
        res['test'] = 'Failed to register user'
        print json.dumps(res)
        error = True
        return False

    print "Registering bar.test"
    for i in xrange(0, 6):
        testlib.next_block( **kw )
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

    print 'Wait for zonefile to be sent'
    time.sleep(10)

    res = testlib.blockstack_REST_call("GET", "/v1/names/bar.test",
                                       None, api_pass=api_pass)
    if 'error' in res or res['http_status'] != 200:
        res['test'] = 'Failed to get name bar.test'
        print json.dumps(res)
        return False

    print res['response']

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

    # okay, now let's try to do an update.
    # make zonefile for recipient
    driver_urls = blockstack_client.storage.make_mutable_data_urls('bar.test', use_only=['http', 'disk'])
    zonefile = blockstack_client.zonefile.make_empty_zonefile('bar.test', wallets[3].pubkey_hex, urls=driver_urls)
    zonefile_txt = blockstack_zones.make_zone_file( zonefile, origin='bar.test', ttl=3600 )

    # let's do this update.
    res = testlib.blockstack_REST_call(
        'PUT', '/v1/names/bar.test/zonefile', None, api_pass=api_pass, data={
            'zonefile': zonefile_txt, 'owner_key' : new_key, 'payment_key' : payment_key
        })
    if 'error' in res or res['http_status'] != 202:
        res['test'] = 'Failed to register user'
        print json.dumps(res)
        error = True
        return False
    else:
        print "Submitted update!"
        print res

    print 'Wait for update to be submitted'
    time.sleep(10)

    # wait for update to get confirmed
    for i in xrange(0, 6):
        testlib.next_block( **kw )

    res = testlib.verify_in_queue(None, 'bar.test', 'update', None, api_pass = api_pass )
    if not res:
        print "update error in second update"
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

    zonefile_hash = res['response']['zonefile_hash']
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

    names = ['bar.test']
    owners = [ new_addr ]
    test_proxy = testlib.TestAPIProxy()

    for i in xrange(0, len(names)):
        name = names[i]

        # registered
        name_rec = state_engine.get_name( name )
        if name_rec is None:
            print "name does not exist"
            return False

        # owned
        if name_rec['address'] != owners[i]:
            print "name {} has wrong owner".format(name)
            return False

    return True
