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

from blockstack_integration_tests.scenarios import testlib
import pybitcoin
import time
import json
import sys
import os
import blockstack_client
import blockstack_zones
import base64
import keylib
from blockstack_client import subdomains

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 5500 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 5500 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
zonefile_hash = None

def scenario( wallets, **kw ):

    global zonefile_hash

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[2].privkey, wallets[3].privkey, wallets[4].privkey )
    resp = testlib.blockstack_cli_register( "foo.test", "0123456789abcdef" )
    if 'error' in resp:
        print >> sys.stderr, json.dumps(resp, indent=4, sort_keys=True)
        return False
    # wait for the preorder to get confirmed
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    # wait for the poller to pick it up
    print >> sys.stderr, "Waiting 10 seconds for the backend to submit the register"
    time.sleep(10)
    # wait for the register to get confirmed 
    for i in xrange(0, 12):
        # warn the serialization checker that this changes behavior from 0.13
        print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
        sys.stdout.flush()
        
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting 10 seconds for the backend to acknowledge registration"
    time.sleep(10)
    # wait for initial update to get confirmed 
    for i in xrange(0, 12):
        # warn the serialization checker that this changes behavior from 0.13
        print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
        sys.stdout.flush()
        
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting 10 seconds for the backend to acknowledge update"
    time.sleep(10)

    # wait for initial update to get confirmed
    for i in xrange(0, 12):
        # warn the serialization checker that this changes behavior from 0.13
        print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
        sys.stdout.flush()
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting 10 seconds for the backend to acknowledge update"
    time.sleep(10)
    
    # store a new zonefile

    # foo's zonefile
    user_zf = {
        '$origin': 'foo',
        '$ttl': 3600,
        'txt' : [], 'uri' : []
    }
    user_zf['uri'].append(blockstack_client.zonefile.url_to_uri_record("file:///tmp/foo.profile.json"))


    foo_sk = keylib.ECPrivateKey()
    print "Resolving key {}".format(foo_sk.to_hex())

    subdomain = subdomains.Subdomain("foo", subdomains.encode_pubkey_entry(foo_sk), 0,
                                     blockstack_zones.make_zone_file(user_zf))


    subdomains.add_subdomains([subdomain], "foo.test")

    # wait for new update to get confirmed 
    time.sleep(10)
    for i in xrange(0, 12):
        sys.stdout.flush()
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting 10 seconds for the backend to acknowledge update"
    time.sleep(10)

    # let's write a profile for the resolver.
    profile_raw = {"foo" : {
        "@type" : "Person",
        "description" : "Lorem Ipsum Dolorem"
        }}
    # as of now, can't use storage's put_mutable_data, because it tries to figure out
    #  where to write things based on a user's zonefile and subdomains don't have
    #  zonefiles :\

    serialized_data = blockstack_client.storage.serialize_mutable_data(
        profile_raw, data_privkey= foo_sk.to_hex(), data_pubkey=None, 
        data_signature=None, profile=True)

    with open("/tmp/foo.profile.json", 'w') as f_out:
        f_out.write(serialized_data)

def check( state_engine ):

    data = subdomains.resolve_subdomain("foo", "foo.test")

    user_profile = data['profile']

    # let's resolve!
    print "Resolved profile : {}".format(user_profile)

    assert 'foo' in user_profile

    data2 = testlib.blockstack_cli_lookup("foo.foo.test")

    print "Looked up profile : {}".format(data2)

    return True
