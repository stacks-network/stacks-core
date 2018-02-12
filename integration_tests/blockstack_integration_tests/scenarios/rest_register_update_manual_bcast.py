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
# activate F-day 2017 at the right time
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 682
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 683
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 1
"""

import testlib
import virtualchain
import time
import json
import sys
import os
import blockstack_client

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 5500 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 5500 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    testlib.blockstack_namespace_preorder( "id", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "id", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "id", wallets[1].privkey )
    testlib.next_block( **kw )

    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    config_dir = os.path.dirname(config_path)
    conf = blockstack_client.get_config(config_path)
    assert conf
    api_pass = conf['api_password']


    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[2].privkey, wallets[3].privkey, wallets[4].privkey )
    resp = testlib.blockstack_cli_register( "foo.id", "0123456789abcdef" )
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
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting 10 seconds for the backend to acknowledge registration"
    time.sleep(10)

    # wait for update to get confirmed
    for i in xrange(0, 12):
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting 10 seconds for the backend to acknowledge update"
    time.sleep(10)


    test_data = [
        { 'hash': '34fdcde8b75440c5cb82480a14b4f3d731a67dc4',
          'string': '$ORIGIN aaron.id\n$TTL 3600\n_http._tcp URI 10 1 "https://gaia.blockstack.org/hub/34bNQUVgyhSrA8XpM4HkerHUUdNmLpiyj7/0/profile.json"',
          'decoded': None,
          'b64': False },
        { 'hash': 'd4fbae5d1f66f1ae0431e35bcd5a98782adc29ba',
          'decoded': '$ORIGIN baron.id\n$TTL 3600\n_http._tcp URI 10 1 "https://gaia.blockstack.org/hub/34bNQUVgyhSrA8XpM4HkerHUUdNmLpiyj7/0/profile.json"',
          'string': 'JE9SSUdJTiBiYXJvbi5pZAokVFRMIDM2MDAKX2h0dHAuX3RjcCBVUkkgMTAgMSAiaHR0cHM6Ly9nYWlhLmJsb2Nrc3RhY2sub3JnL2h1Yi8zNGJOUVVWZ3loU3JBOFhwTTRIa2VySFVVZE5tTHBpeWo3LzAvcHJvZmlsZS5qc29uIg==',
          'b64': True }]

    for datum in test_data:
        post_data = {}
        if datum['b64']:
            key = 'zonefile_b64'
        else:
            key = 'zonefile'
        post_data[key] = datum['string']

        zfhash = datum['hash']

        res = testlib.blockstack_REST_call("PUT", "/v1/names/foo.id/zonefile", None, api_pass=api_pass,
                                           data={'zonefile_hash': zfhash} )

        if 'error' in res or res['http_status'] != 202:
            res['test'] = 'failed to update zonefile hash'
            print json.dumps(res)
            return False

        print >> sys.stderr, "Waiting 10 seconds for the backend to submit the register"
        time.sleep(10)

        # wait for update to get confirmed
        for i in xrange(0, 10):
            testlib.next_block( **kw )

        print 'Wait for second update to be confirmed'
        time.sleep(10)

        res = testlib.blockstack_REST_call("GET", "/v1/names/foo.id", None, api_pass=api_pass)
        if 'error' in res or res['http_status'] != 200:
            res['test'] = 'Failed to get name foo.id'
            print json.dumps(res)
            return False

        # update set?
        if res['response']['zonefile_hash'] != zfhash:
            res['test'] = 'failed to set zonefile hash'
            print json.dumps(res)
            return False

        res = testlib.blockstack_REST_call("POST", "/v1/zonefile/", None, api_pass=api_pass,
                                           data=post_data)
        if 'error' in res or res['http_status'] != 200:
            res['test'] = 'failed to announce zonefile'
            print json.dumps(res)
            return False

        print 'Broadcasted zonefile'
        time.sleep(10)

        res = testlib.blockstack_REST_call("GET", "/v1/names/foo.id", None, api_pass=api_pass)
        if 'error' in res or res['http_status'] != 200:
            res['test'] = 'Failed to get name foo.id'
            print json.dumps(res)
            return False

        if res['response']['zonefile'] != datum['string'] and \
           res['response']['zonefile'] != datum['decoded']:
            res['test'] = 'failed to set zonefile string'
            print json.dumps(res)
            return False


def check( state_engine ):

    # not revealed, but ready
    ns = state_engine.get_namespace_reveal( "id" )
    if ns is not None:
        print "namespace reveal exists"
        return False

    ns = state_engine.get_namespace( "id" )
    if ns is None:
        print "no namespace"
        return False

    if ns['namespace_id'] != 'id':
        print "wrong namespace"
        return False

    # registered
    name_rec = state_engine.get_name( "foo.id" )
    if name_rec is None:
        print "name does not exist"
        return False

    return True

