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
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 680
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 681
"""

import testlib
import virtualchain
import time
import json
import sys
import os
import blockstack_client
import virtualchain
import keychain
import time

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet( "5KMbNjgZt29V6VNbcAmebaUT2CZMxqSridtM46jv4NkKTP8DHdV", 100000000000 ),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    # has the side-effect of starting the API server
    resp = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[2].privkey, wallets[3].privkey, wallets[4].privkey )
    if 'error' in resp:
        print json.dumps(resp, indent=4, sort_keys=True)
        return False

    resp = testlib.blockstack_cli_namespace_preorder("test", wallets[0].privkey, wallets[1].privkey)
    if 'error' in resp:
        print json.dumps(resp, indent=4, sort_keys=True)
        return False

    testlib.next_block(**kw)

    resp = testlib.blockstack_cli_namespace_reveal('test', wallets[0].privkey, wallets[1].privkey, 52560, 4, 4, '6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0', 10, 10)
    if 'error' in resp:
        print json.dumps(resp, indent=4, sort_keys=True)
        return False

    testlib.next_block(**kw)

    private_keychain = keychain.PrivateKeychain.from_private_key( wallets[1].privkey )
    private_keys = [wallets[1].privkey]     # NOTE: always start with the reveal key, then use children
    for i in xrange(0, 4):
        import_key = private_keychain.child(i).private_key()

        print "fund {} (child {})".format(import_key, i)
        res = testlib.send_funds( wallets[1].privkey, 100000000, virtualchain.BitcoinPrivateKey(import_key).public_key().address() )
        if 'error' in res:
            print json.dumps(res, indent=4, sort_keys=True)
            return False

        testlib.next_block(**kw)
        private_keys.append(import_key)

    # should fail (first key must be revealer)
    resp = testlib.blockstack_cli_name_import("fail.test", wallets[2].addr, "Hello fail.test!", private_keys[1])
    if 'error' not in resp:
        print json.dumps(resp, indent=4, sort_keys=True)
        return False

    # should succeed
    resp = testlib.blockstack_cli_name_import("foo.test", wallets[2].addr, "Hello foo.test!", private_keys[0])
    if 'error' in resp:
        print json.dumps(resp, indent=4, sort_keys=True)
        return False

    testlib.next_block(**kw)
    testlib.expect_snv_fail_at("fail.test", testlib.get_current_block(**kw))
   
    # 3 in one block (zero-conf)
    resp = testlib.blockstack_cli_name_import("bar.test", wallets[3].addr, "Hello bar.test!", private_keys[1])
    if 'error' in resp:
        print json.dumps(resp, indent=4, sort_keys=True)
        return False

    resp = testlib.blockstack_cli_name_import("baz.test", wallets[4].addr, "Hello baz.test!", private_keys[2])
    if 'error' in resp:
        print json.dumps(resp, indent=4, sort_keys=True)
        return False

    resp = testlib.blockstack_cli_name_import("goo.test", wallets[5].addr, "Hello goo.test!", private_keys[3])
    if 'error' in resp:
        print json.dumps(resp, indent=4, sort_keys=True)
        return False

    testlib.next_block(**kw)

    # should fail (wrong key)
    resp = testlib.blockstack_cli_name_import("fail.test", wallets[5].addr, "Hello fail.test!", wallets[2].privkey)
    if 'error' not in resp:
        print json.dumps(resp, indent=4, sort_keys=True)
        return False

    resp = testlib.blockstack_cli_namespace_ready('test', wallets[1].privkey)
    if 'error' in resp:
        print json.dumps(resp, indent=4, sort_keys=True)
        return False

    testlib.next_block(**kw)
    testlib.expect_snv_fail_at("fail.test", testlib.get_current_block(**kw))

    for i in xrange(0, 12):
        testlib.next_block(**kw)

    print "Waiting 10 seconds for registrar to replicate zone files"
    time.sleep(10)


def check( state_engine ):

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is not None:
        print "namespace reveal exists"
        return False 

    ns = state_engine.get_namespace( "test" )
    if ns is None:
        print "no namespace"
        return False 

    if ns['namespace_id'] != 'test':
        print "wrong namespace"
        return False 
   
    names = ['foo.test', 'bar.test', 'baz.test', 'goo.test']
    addresses = [wallets[2].addr, wallets[3].addr, wallets[4].addr, wallets[5].addr]
    zonefiles = ["Hello foo.test!", "Hello bar.test!", "Hello baz.test!", "Hello goo.test!"]

    for i in xrange(0, len(names)):
        name = names[i]
        owner_address = addresses[i]
        zonefile = zonefiles[i]

        # registered 
        name_rec = state_engine.get_name( name )
        if name_rec is None:
            print "name {} does not exist".format(name)
            return False 

        # owned by the right address 
        if name_rec['address'] != owner_address or name_rec['sender'] != virtualchain.make_payment_script(owner_address):
            print "sender is wrong for {}".format(name)
            return False 

        # has the right zone file
        zf = testlib.blockstack_get_zonefile(name_rec['value_hash'], parse=False)
        if zf is None:
            print "no zonefile for {}".format(name)
            return False

        if zf != zonefile:
            print "zonefile mismatch: expected {}, got {}".format(zonefile, zf)
            return False

    # all queues are drained 
    queue_info = testlib.blockstack_client_queue_state()
    if len(queue_info) > 0:
        print "Still in queue:\n%s" % json.dumps(queue_info, indent=4, sort_keys=True)
        return False

    return True
