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
import time
import json
import sys
import os
import blockstack_client
import blockstack_zones
import keylib

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 5500 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 5500 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )
   
    driver_urls = blockstack_client.storage.make_mutable_data_urls('foo.test', use_only=['dht', 'disk'])
    zonefile = blockstack_client.zonefile.make_empty_zonefile('foo.test', wallets[4].pubkey_hex, urls=driver_urls)
    zonefile_txt = blockstack_zones.make_zone_file( zonefile, origin='foo.test', ttl=3600 )

    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[2].privkey, wallets[3].privkey, wallets[4].privkey )
    resp = testlib.blockstack_cli_register( "foo.test", "0123456789abcdef", zonefile=zonefile_txt, recipient_address=wallets[4].addr )
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

    # wait for transfer to get confirmed 
    for i in xrange(0, 12):
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting 10 seconds for the backend to acknowledge transfer"
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
    
    # registered 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        print "name does not exist"
        return False 

    # owned by the right address 
    owner_address = wallets[4].addr
    if name_rec['address'] != owner_address or name_rec['sender'] != virtualchain.make_payment_script(owner_address):
        print "sender is wrong"
        return False 

    # all queues are drained 
    queue_info = testlib.blockstack_client_queue_state()
    if len(queue_info) > 0:
        print "Still in queue:\n%s" % json.dumps(queue_info, indent=4, sort_keys=True)
        return False

    # have an update hash 
    if 'value_hash' not in name_rec or name_rec.get('value_hash', None) is None:
        print "No value hash"
        return False 

    # have a zonefile 
    zonefile = testlib.blockstack_get_zonefile( name_rec['value_hash'] )
    if zonefile is None or 'error' in zonefile:
        if zonefile is not None:
            print "zonefile lookup error: %s" % zonefile['error']
        else:
            print "no zonefile returned"
        return False

    # hashes to this zonefile 
    if blockstack_client.hash_zonefile( zonefile ) != name_rec['value_hash']:
        print "wrong zonefile: %s != %s" % (blockstack_client.hash_zonefile(zonefile), name_rec['value_hash'])
        return False

    # zonefile has the right data public key 
    zonefile_pubk = blockstack_client.user.user_zonefile_data_pubkey( zonefile )
    if keylib.key_formatting.compress(zonefile_pubk) != keylib.key_formatting.compress(wallets[4].pubkey_hex) or zonefile_pubk is None:
        print 'pubkey mismatch: {} != {}'.format(zonefile_pubk, wallets[4].pubkey_hex)
        return False

    # zonefile has the right drivers
    zonefile_urls = blockstack_client.user.user_zonefile_urls( zonefile )
    driver_urls = blockstack_client.storage.make_mutable_data_urls( 'foo.test', use_only=['dht', 'disk'] )
    if driver_urls != zonefile_urls:
        print 'url mismatch: {} != {}'.format(driver_urls, zonefile_urls)
        return False

    # verify that the profile is NOT there 
    profile = testlib.blockstack_get_profile( "foo.test" )
    if profile is not None and 'error' not in profile:
        print 'make a profile by mistake: {}'.format(profile)
        return False

    return True
