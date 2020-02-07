#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2017 by Blockstack.org

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

import virtualchain
import time
import json
import sys
import os, subprocess
import blockstack_client
import blockstack_zones
import keylib
import requests
from blockstack_integration_tests.scenarios import testlib
import atexit
import blockstack

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 5500 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 5500 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
SLEEP_TIME = 25

def killer(subproc):
    print "Killing subdomain registrar"
    subproc.kill()

def scenario( wallets, **kw ):
    # write our subdomain_registrar config
    client_dir = os.path.normpath(os.path.dirname(os.environ["BLOCKSTACK_CLIENT_CONFIG"]) + "/../subdomain_registrar")
    if not os.path.exists(client_dir):
        os.makedirs(client_dir)
    os.environ["BLOCKSTACK_SUBDOMAIN_CONFIG"] = client_dir + "/config.ini"
    with open(client_dir + "/config.ini", "w") as out_f:
        file_out = """[registrar-config]
maximum_entries_per_zonefile = 100
bind_port = 7103
transaction_frequency = 15
bind_address = {}
core_endpoint = http://localhost:{}
core_auth_token = False
""".format(os.getenv('BSK_SUBDOMAIN_REGTEST_BIND', 'localhost'), blockstack_client.config.read_config_file()['blockstack-client']['api_endpoint_port'])
        out_f.write(file_out)

    # spawn the registrar
    SUBPROC = subprocess.Popen(["blockstack-subdomain-registrar", "start", "foo.id"])

    testlib.blockstack_namespace_preorder( "id", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "id", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "id", wallets[1].privkey )
    testlib.next_block( **kw )
    
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
    time.sleep(SLEEP_TIME)

    # wait for the register to get confirmed 
    for i in xrange(0, 12):
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting 10 seconds for the backend to acknowledge registration"
    time.sleep(SLEEP_TIME)

    # wait for update to get confirmed 
    for i in xrange(0, 12):
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting 10 seconds for the backend to acknowledge update"
    time.sleep(SLEEP_TIME)


    print >> sys.stderr, "Waiting for subdomain to start up"
    time.sleep(SLEEP_TIME)

    baz_sk = keylib.ECPrivateKey()
    uri_rec = blockstack_client.zonefile.url_to_uri_record("file:///tmp/baz.profile.json")

    owner_address = baz_sk.public_key().address()

    zonefile_obj = { 
        '$origin' : "bar",
        '$ttl' : 3600,
        'uri' : [uri_rec]
    }
    zonefile_str = blockstack_zones.make_zone_file(zonefile_obj)

    requests.post("http://localhost:7103/register",
                  data = json.dumps({"name": "bar",
                                     "min_confs" : 0,
                                     "owner_address" : owner_address,
                                     "zonefile" : zonefile_str}))

    profile_raw = {"bar" : {
        "@type" : "Person",
        "description" : "Lorem Ipsum Bazorem"
        }}
    # as of now, can't use storage's put_mutable_data, because it tries to figure out
    #  where to write things based on a user's zonefile and subdomains don't have
    #  zonefiles :\

    serialized_data = blockstack_client.storage.serialize_mutable_data(
        profile_raw, data_privkey= baz_sk.to_hex(), data_pubkey=None, 
        data_signature=None, profile=True)
    with open("/tmp/baz.profile.json", 'w') as f_out:
        f_out.write(serialized_data)

    print >> sys.stderr, "Waiting for the registrar to propagate the name"
    time.sleep(30)
    for i in xrange(0, 12):
        sys.stdout.flush()
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting for the update to be acknowledged"
    time.sleep(SLEEP_TIME)

    atexit.register(killer, SUBPROC)

def check( state_engine ):
    subdomain = "bar"
    domain = "foo.id"
    # user_profile = blockstack_client.subdomains.resolve_subdomain(subdomain, domain)['profile']
    user_profile = blockstack.lib.client.resolve_profile('bar.foo.id', hostport='http://localhost:{}'.format(blockstack.lib.client.RPC_SERVER_PORT))['profile']
    assert subdomain in user_profile
    print "Resolved profile : {}".format(user_profile)

    return True
