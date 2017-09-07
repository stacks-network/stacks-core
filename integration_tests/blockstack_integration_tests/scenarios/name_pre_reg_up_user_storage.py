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
import sys
os.environ["CLIENT_STORAGE_DRIVERS"] = "blockstack_server,disk"
os.environ["CLIENT_STORAGE_DRIVERS_REQUIRED_WRITE"] = "blockstack_server"

import testlib
import pybitcoin
import json
import time
import blockstack_client
import xmlrpclib
import blockstack
import traceback
import blockstack_zones 
import base64

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
wallet_keys = None

datasets = [
    {"dataset_1": "My first dataset!"},
    {"dataset_2": {"id": "abcdef", "desc": "My second dataset!", "data": [1, 2, 3, 4]}},
    {"dataset_3": "My third datset!"}
]

dataset_change = "This is the mutated dataset"

def scenario( wallets, **kw ):

    global put_result, wallet_keys, datasets, zonefile_hash, dataset_change

    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[2].privkey, wallets[3].privkey, wallets[4].privkey )
    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )
    wallet_keys = blockstack_client.make_wallet_keys( owner_privkey=wallets[3].privkey, data_privkey=wallets[4].privkey )

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    resp = testlib.blockstack_cli_register( "foo.test", "0123456789abcdef" )
    if 'error' in resp:
        print >> sys.stderr, json.dumps(resp, indent=4, sort_keys=True)
        return False
   
    # wait for the preorder to get confirmed
    for i in xrange(0, 12):
        testlib.next_block( **kw )

    # wait for the poller to pick it up
    print >> sys.stderr, "Waiting for the backend to submit the register"
    time.sleep(10)

    # wait for the register to get confirmed 
    for i in xrange(0, 12):
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting for the backend to acknowledge registration"
    time.sleep(10)

    # wait for initial update to get confirmed 
    for i in xrange(0, 12):
        # tell serialization-checker that value_hash can be ignored here
        print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
        sys.stdout.flush()
    
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting for the backend to acknowledge update"
    time.sleep(10)

    # wait for zonefile/profile replication
    for i in xrange(0, 12):
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting for the backend to replicate zonefile and profile"
    time.sleep(10)


    # make a few accounts
    res = testlib.blockstack_cli_put_account("foo.test", "serviceFoo", "serviceFooID", "foo://bar.com", "0123456789abcdef", extra_data='foofield=foo!', wallet_keys=wallet_keys)
    if 'error' in res:
        res['test'] = 'Failed to create foo.test serviceFoo account'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 

    time.sleep(2)

    res = testlib.blockstack_cli_put_account("foo.test", "serviceBar", "serviceBarID", "bar://baz.com", "0123456789abcdef", extra_data='barfield=bar!', wallet_keys=wallet_keys)
    if 'error' in res:
        res['test'] = 'Failed to create foo.test serviceBar account'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 

    time.sleep(2)

    # put some data
    put_result = testlib.blockstack_cli_put_mutable( "foo.test", "hello_world_1", json.dumps(datasets[0]), password="0123456789abcdef")
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)
        return False

    testlib.next_block( **kw )

    time.sleep(2)

    put_result = testlib.blockstack_cli_put_mutable( "foo.test", "hello_world_2", json.dumps(datasets[1]), password="0123456789abcdef", \
                                                     storage_drivers=['blockstack_server'], storage_drivers_exclusive=True)
    
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)
        return False

    time.sleep(2)

    put_result = testlib.blockstack_cli_put_mutable( "foo.test", "hello_world_3", json.dumps(datasets[2]), password="0123456789abcdef", \
                                                     storage_drivers=['blockstack_server'], storage_drivers_exclusive=True)

    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)
        return False

    time.sleep(2)

    # increment data version too
    datasets[0]['buf'] = []
    for i in xrange(0, 5):
        datasets[0]["dataset_change"] = dataset_change
        datasets[0]['buf'].append(i)

        put_result = testlib.blockstack_cli_put_mutable( "foo.test", "hello_world_1", json.dumps(datasets[0]), password="0123456789abcdef", \
                                                         storage_drivers=['blockstack_server'], storage_drivers_exclusive=True)

        if 'error' in put_result:
            print json.dumps(put_result, indent=4, sort_keys=True )
            return False

        time.sleep(2)

    testlib.next_block( **kw )


def check( state_engine ):

    global wallet_keys, datasets, zonefile_hash

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

    srv = xmlrpclib.ServerProxy("http://localhost:%s" % blockstack.RPC_SERVER_PORT)

    # zonefile and profile replicated to blockstack server 
    try:
        zonefile_by_name_str = srv.get_zonefiles_by_names(['foo.test'])
        zonefile_by_hash_str = srv.get_zonefiles([name_rec['value_hash']])
       
        zonefile_by_name = json.loads(zonefile_by_name_str)
        zonefile_by_hash = json.loads(zonefile_by_hash_str)

        assert 'error' not in zonefile_by_name, json.dumps(zonefile_by_name, indent=4, sort_keys=True)
        assert 'error' not in zonefile_by_hash, json.dumps(zonefile_by_hash, indent=4, sort_keys=True)

        zf1 = None
        zf2 = None
        try:
            zf1 = base64.b64decode( zonefile_by_name['zonefiles']['foo.test'] )
        except:
            print zonefile_by_name
            raise

        try:
            zf2 = base64.b64decode( zonefile_by_hash['zonefiles'][name_rec['value_hash']] )
        except:
            print zonefile_by_hash
            raise
        
        assert zf1 == zf2
        zonefile = blockstack_zones.parse_zone_file( zf1 )

        user_pubkey = blockstack_client.user.user_zonefile_data_pubkey( zonefile )
        assert user_pubkey is not None, "no zonefile public key"

        profile_resp_txt = srv.get_profile("foo.test")
        profile_resp = json.loads(profile_resp_txt)
        assert 'error' not in profile_resp, "error:\n%s" % json.dumps(profile_resp, indent=4, sort_keys=True)
        assert 'profile' in profile_resp, "missing profile:\n%s" % json.dumps(profile_resp, indent=4, sort_keys=True)

        # profile will be in 'raw' form
        raw_profile = profile_resp['profile']
        profile = blockstack_client.storage.parse_mutable_data( raw_profile, user_pubkey )

    except Exception, e:
        traceback.print_exc()
        print "Invalid profile"
        return False

    # have right data 
    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )

    for i in xrange(0, len(datasets)):
        print "get hello_world_%s" % (i+1)
        dat = testlib.blockstack_cli_get_mutable( 'foo.test', "hello_world_%s" % (i+1), public_key=wallets[4].pubkey_hex )
        if dat is None:
            print "No data '%s'" % ("hello_world_%s" % (i+1))
            return False

        if 'error' in dat:
            print json.dumps(dat, indent=4, sort_keys=True)
            return False

        if json.loads(dat['data']) != datasets[i]:
            print "Mismatch %s: %s %s != %s %s" % (i, dat['data'], type(dat['data']), datasets[i], type(datasets[i]))
            return False
    
    res = blockstack_client.get_profile('foo.test')
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        return False

    profile = res['profile']
    zonefile = res['zonefile']

    # accounts should all be there 
    if not profile.has_key('account'):
        print 'profile:\n{}'.format(json.dumps(profile, indent=4, sort_keys=True))
        return False

    expected_account_info = [
        {
            "contentUrl": "foo://bar.com", 
            "foofield": "foo!", 
            "identifier": "serviceFooID", 
            "service": "serviceFoo"
        }, 
        {
            "barfield": "bar!", 
            "contentUrl": "bar://baz.com", 
            "identifier": "serviceBarID", 
            "service": "serviceBar"
        }
    ]

    for account_info in expected_account_info:
        found = False
        for profile_account_info in profile['account']:
            if profile_account_info == account_info:
                found = True
                break

        if not found:
            print "missing\n{}\nin\n{}".format(json.dumps(account_info, indent=4, sort_keys=True), json.dumps(profile, indent=4, sort_keys=True))
            return False

    # there should be no failures in the API log
    api_log_path = os.path.join(os.path.dirname(test_proxy.conf['path']), "api_endpoint.log")
    with open(api_log_path, "r") as f:
        api_log = f.read()

    if "Traceback (most recent call last)" in api_log:
        print "exception thrown by client"
        return False

    if "Server did not save" in api_log:
        print 'server did not save'
        return False

    return True
