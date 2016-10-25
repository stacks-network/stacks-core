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
import time
import blockstack_client
import virtualchain
import os

"""
TEST ENV BLOCKSTACK_ATLAS_NUM_NEIGHBORS 10
"""

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet( "5KaSTdRgMfHLxSKsiWhF83tdhEj2hqugxdBNPUAw5NU8DMyBJji", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
synchronized = False
value_hash = None

def scenario( wallets, **kw ):

    global synchronized, value_hash

    import blockstack_integration_tests.atlas_network as atlas_network

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

    # set up RPC daemon
    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )
    wallet_keys = blockstack_client.make_wallet_keys( owner_privkey=wallets[3].privkey, data_privkey=wallets[4].privkey, payment_privkey=wallets[5].privkey )
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] )

    # start up an atlas network with 16 peers, 8 of which will be active at once.
    # every second, have one peer come online, and one peer go offline.
    # have them all start out knowing about the same seed node.
    atlas_nodes = [17000, 17001, 17002, 17003, 17004, 17005, 17006, 17007, 17008, 17009, 17010, 17011, 17012, 17013, 17014, 17015, 17016]
    atlas_topology = {}
    for i in xrange(0, 9):
        atlas_topology[atlas_nodes[i]] = [16264]

    for i in xrange(9, len(atlas_nodes)):
        atlas_topology[atlas_nodes[i]] = [17008]

    atlas_topology[atlas_nodes[-1]].append( 16264 )

    time_start = int(time.time())
    
    # put the seed after the first four
    all_peers = atlas_nodes[:4] + [16264] + atlas_nodes[4:]

    def churn_drop(src_hostport, dest_hostport):
        if src_hostport is None:
            return 0.0

        src_host, src_port = blockstack_client.config.url_to_host_port( src_hostport )
        dest_host, dest_port = blockstack_client.config.url_to_host_port( dest_hostport )

        now = int(time.time())
        offset = (now - time_start) % len(all_peers)
        sample = all_peers + all_peers
        active_range = sample[offset: offset + 8]

        print "Active range: %s, request (%s --> %s)" % (active_range, src_port, dest_port)

        if src_port not in active_range:
            # dead 
            return 1.0

        if dest_port not in active_range:
            # dead
            return 1.0

        return 0.0

    network_des = atlas_network.atlas_network_build( atlas_nodes, atlas_topology, {}, os.path.join( testlib.working_dir(**kw), "atlas_network" ) )
    atlas_network.atlas_network_start( network_des, drop_probability=churn_drop )

    print "Waiting 25 seconds for the altas peers to catch up"
    time.sleep(25.0)

    # make an empty zonefile
    data_pubkey = virtualchain.BitcoinPrivateKey(wallet_keys['data_privkey']).public_key().to_hex()
    empty_zonefile = blockstack_client.user.make_empty_user_zonefile( "foo.test", data_pubkey, urls=["file:///tmp/foo.test"] )
    empty_zonefile_str = json.dumps(empty_zonefile) 
    value_hash = blockstack_client.hash_zonefile( empty_zonefile )

    # propagate the zonefile
    res = testlib.blockstack_cli_update( "foo.test", empty_zonefile_str, "0123456789abcdef" )

    for i in xrange(0, 12):
        testlib.next_block( **kw )
        
    print "Waiting for zonefile propagation"
    time.sleep(10.0)

    # wait at most 30 seconds for atlas network to converge
    synchronized = False
    for i in xrange(0, 30):
        atlas_network.atlas_print_network_state( network_des )
        if atlas_network.atlas_network_is_synchronized( network_des, testlib.last_block( **kw ) - 1, 1 ):
            print "Synchronized!"
            synchronized = True
            break

        else:
            time.sleep(1.0)
    
    # shut down 
    atlas_network.atlas_network_stop( network_des )
    return synchronized


def check( state_engine ):

    global synchronized
    if not synchronized:
        print "not synchronized"
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

    # updated 
    if name_rec['value_hash'] != value_hash:
        print "wrong value hash: %s" % name_rec['value_hash']
        return False 

    return True
