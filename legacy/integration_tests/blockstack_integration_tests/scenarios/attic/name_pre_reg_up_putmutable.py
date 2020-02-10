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
import time
import blockstack_client
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

dataset_change = "This is the mutated dataset"

zonefile_hash = None

def scenario( wallets, **kw ):

    global put_result, wallet_keys, datasets, zonefile_hash, dataset_change

    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[5].privkey, wallets[3].privkey, wallets[4].privkey )
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
    else:
        zonefile_hash = res['zonefile_hash']

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    testlib.next_block( **kw )

    put_result = testlib.blockstack_cli_put_mutable( "foo.test", "hello_world_1", json.dumps(datasets[0]), password='0123456789abcdef' )
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)

    testlib.next_block( **kw )

    put_result = testlib.blockstack_cli_put_mutable( "foo.test", "hello_world_2", json.dumps(datasets[1]), password='0123456789abcdef' )
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)

    put_result = testlib.blockstack_cli_put_mutable( "foo.test", "hello_world_3", json.dumps(datasets[2]), password='0123456789abcdef' )
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)

    # increment version too
    datasets[0]['buf'] = []
    for i in xrange(0, 5):
        datasets[0]["dataset_change"] = dataset_change
        datasets[0]['buf'].append(i)

        put_result = testlib.blockstack_cli_put_mutable( "foo.test", "hello_world_1", json.dumps(datasets[0]), password='0123456789abcdef' )
        if 'error' in put_result:
            print json.dumps(put_result, indent=4, sort_keys=True )

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
    preorder = state_engine.get_name_preorder( "foo.test", virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr )
    if preorder is not None:
        print "still have preorder"
        return False
    
    # registered 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        print "name does not exist"
        return False 

    # owned 
    if name_rec['address'] != wallets[3].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[3].addr):
        print "name has wrong owner"
        return False 

    # have right hash 
    if name_rec['value_hash'] != zonefile_hash:
        print "Invalid zonefile hash"
        return False 

    # have right data 
    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )

    for i in xrange(0, len(datasets)):
        print "get hello_world_%s" % (i+1)
        dat = testlib.blockstack_cli_get_mutable( "foo.test", "hello_world_{}".format(i+1), public_key=wallets[4].pubkey_hex )
        if dat is None:
            print "No data '%s'" % ("hello_world_%s" % (i+1))
            return False

        if 'error' in dat:
            print json.dumps(dat, indent=4, sort_keys=True)
            return False

        if json.loads(dat['data']) != datasets[i]:
            print "Mismatch %s: %s != %s" % (i, dat, datasets[i])
            return False

    res = testlib.blockstack_cli_lookup("foo.test")
    if 'error' in res:
        print 'error looking up profile: {}'.format(res)
        return False

    assert 'profile' in res
    assert 'zonefile' in res

    return True
