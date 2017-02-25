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
    {u"dataset_1": u"My first dataset!"},
    {u"dataset_2": {u"id": u"abcdef", u"desc": u"My second dataset!", u"data": [1, 2, 3, 4]}},
    {u"dataset_3": u"My third datset!"}
]

put_result = None
last_hash = None
immutable_data_hashes = []

def scenario( wallets, **kw ):

    global datasets, immutable_data_hashes, put_result, last_hash

    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[5].privkey, wallets[3].privkey, None )
    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )
    wallet_keys = wallet

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
    
    put_result = testlib.blockstack_cli_put_immutable("foo.test", "hello_world_1", json.dumps(datasets[0], sort_keys=True), password='0123456789abcdef')
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)

    testlib.expect_atlas_zonefile(put_result['zonefile_hash'])
    immutable_data_hashes.append( put_result['immutable_data_hash'] )

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    # wait for confirmation 
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "waiting for confirmation"
    time.sleep(10)

    put_result = testlib.blockstack_cli_put_immutable("foo.test", "hello_world_2", json.dumps(datasets[1], sort_keys=True), password='0123456789abcdef')
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)

    testlib.expect_atlas_zonefile(put_result['zonefile_hash'])
    immutable_data_hashes.append( put_result['immutable_data_hash'] )

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "waiting for confirmation"
    time.sleep(10)

    put_result = testlib.blockstack_cli_put_immutable("foo.test", "hello_world_3", json.dumps(datasets[2], sort_keys=True), password='0123456789abcdef')
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)

    testlib.expect_atlas_zonefile(put_result['zonefile_hash'])
    immutable_data_hashes.append( put_result['immutable_data_hash'] )
    last_hash = put_result['zonefile_hash']

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "waiting for confirmation"
    time.sleep(10)

    # should succeed (name collision)
    datasets[0][u'newdata'] = u"asdf"
    put_result = testlib.blockstack_cli_put_immutable("foo.test", "hello_world_1", json.dumps(datasets[0], sort_keys=True), password='0123456789abcdef')
    if 'error' not in put_result:
        immutable_data_hashes[0] = put_result['immutable_data_hash']
    else:
        print json.dumps(put_result, indent=4, sort_keys=True )

    testlib.expect_atlas_zonefile(put_result['zonefile_hash'])
    last_hash = put_result['zonefile_hash']

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "waiting for confirmation"
    time.sleep(10)


def check( state_engine ):

    global wallet_keys, dataset_1, data_hash_1, dataset_2, data_hash_2

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

    # have right hash 
    if name_rec['value_hash'] != last_hash:
        print "Invalid zonefile hash (%s != %s)" % (name_rec['value_hash'], last_hash)
        return False 

    # have right data 
    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )

    for i in xrange(0, len(datasets)):
        immutable_data = testlib.blockstack_cli_get_immutable("foo.test", immutable_data_hashes[i] )
        if immutable_data is None:
            print "No data received for dataset %s" % i
            return False 

        if 'error' in immutable_data:
            print "No data received for dataset %s" % i
            return False

        if not immutable_data.has_key('data'):
            print "Missing data\n%s" % json.dumps(immutable_data, indent=4, sort_keys=True)
            return False 

        data_json = json.loads(immutable_data['data'])
        if data_json != datasets[i]:
            print "did not get dataset %s\ngot %s\nexpected %s" % (i, data_json, datasets[i])
            return False 

        immutable_data_by_name = testlib.blockstack_cli_get_immutable( "foo.test", "hello_world_%s" % (i+1) )
        if immutable_data_by_name is None:
            print "No data received by name for dataset %s" % i
            return False 

        if 'error' in immutable_data_by_name:
            print "No data received for dataset hello_world_%s" % (i+1)
            return False 

        if not immutable_data_by_name.has_key('data'):
            print "Misisng data\n%s" % json.dumps(immutable_data_by_name, indent=4, sort_keys=True)
            return False 

        data_json = json.loads(immutable_data_by_name['data'])
        if data_json != datasets[i]:
            print "did not get dataset hello_world_%s\ngot %s\nexpected %s" % (i+1, data_json, datasets[i])
            return False 

    return True
