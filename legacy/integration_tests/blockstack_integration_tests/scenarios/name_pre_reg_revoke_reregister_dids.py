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
import blockstack
import sys

# in epoch 3 immediately
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 680
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 681
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 1
"""
wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

fail_blocks = []

NAMESPACE_LIFETIME_MULTIPLIER = blockstack.get_epoch_namespace_lifetime_multiplier( blockstack.EPOCH_1_END_BLOCK + 1, "test" )

def scenario( wallets, **kw ):

    global fail_blocks 

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 3, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.blockstack_name_preorder( "bar.test", wallets[2].privkey, wallets[3].addr )
    testlib.blockstack_name_preorder( "baz.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )
    
    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.blockstack_name_register( "bar.test", wallets[2].privkey, wallets[3].addr )
    testlib.blockstack_name_register( "baz.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )
    
    # dids for each of these names 
    foo_did = 'did:stack:v0:{}-0'.format(wallets[3].addr)
    bar_did = 'did:stack:v0:{}-1'.format(wallets[3].addr)
    baz_did = 'did:stack:v0:{}-2'.format(wallets[3].addr)

    for did in [foo_did, bar_did, baz_did]:
        res = blockstack.lib.client.get_DID_record(did, hostport='http://localhost:{}'.format(blockstack.lib.client.RPC_SERVER_PORT))
        if 'error' in res:
            print res
            return False

        if res['address'] != wallets[3].addr:
            print 'wrong address; expected {}'.format(wallets[3].addr)
            print json.dumps(res, indent=4, sort_keys=True)
            return False

    # revoke foo.test
    testlib.blockstack_name_revoke( "foo.test", wallets[3].privkey )
    testlib.next_block( **kw )

    # wait for them all to expire...
    for i in xrange(0, 3):
        testlib.next_block( **kw )

    # re-preorder/reregister to different addresses
    testlib.blockstack_name_preorder( "foo.test", wallets[4].privkey, wallets[0].addr )
    testlib.blockstack_name_preorder( "bar.test", wallets[4].privkey, wallets[1].addr )
    testlib.blockstack_name_preorder( "baz.test", wallets[4].privkey, wallets[2].addr )
    testlib.next_block( **kw )

    # re-register 
    testlib.blockstack_name_register( "foo.test", wallets[4].privkey, wallets[0].addr )
    testlib.blockstack_name_register( "bar.test", wallets[4].privkey, wallets[1].addr )
    testlib.blockstack_name_register( "baz.test", wallets[4].privkey, wallets[2].addr )
    testlib.next_block( **kw )

    # foo's DID should no longer resolve, since foo was revoked
    res = blockstack.lib.client.get_DID_record(foo_did, hostport='http://localhost:{}'.format(blockstack.lib.client.RPC_SERVER_PORT))
    if 'error' not in res:
        print 'accidentally resolved {}'.format(foo_did)
        print res
        return False

    # non-revoked DIDs should resolve to the old addresses, just before the reregister
    for did, addr in zip([bar_did, baz_did], [wallets[3].addr, wallets[3].addr]):
        res = blockstack.lib.client.get_DID_record(did, hostport='http://localhost:{}'.format(blockstack.lib.client.RPC_SERVER_PORT))
        if 'error' in res:
            print res
            return False

        if res['address'] != addr:
            print 'wrong address post-reregister; expected {}'.format(addr)
            print json.dumps(res, indent=4, sort_keys=True)
            return False

    # dids for the new names 
    foo2_did = 'did:stack:v0:{}-0'.format(wallets[0].addr)
    bar2_did = 'did:stack:v0:{}-0'.format(wallets[1].addr)
    baz2_did = 'did:stack:v0:{}-0'.format(wallets[2].addr)

    # new DIDs should all resolve to new addresses
    for did, addr in zip([foo2_did, bar2_did, baz2_did], [wallets[0].addr, wallets[1].addr, wallets[2].addr]):
        res = blockstack.lib.client.get_DID_record(did, hostport='http://localhost:{}'.format(blockstack.lib.client.RPC_SERVER_PORT))
        if 'error' in res:
            print res
            return False

        if res['address'] != addr:
            print 'wrong address post-reregister: expected {}'.format(addr)
            print json.dumps(res, indent=4, sort_keys=True)
            return False

    # transfer all names back to wallets[3]
    testlib.blockstack_name_transfer( "foo.test", wallets[3].addr, True, wallets[0].privkey )
    testlib.blockstack_name_transfer( "bar.test", wallets[3].addr, True, wallets[1].privkey )
    testlib.blockstack_name_transfer( "baz.test", wallets[3].addr, True, wallets[2].privkey )
    testlib.next_block( **kw )

    # all DIDs except for the original DID for foo.test should now resolve to wallets[3].addr
    for did in [bar_did, baz_did, foo2_did, bar2_did, baz2_did]:
        res = blockstack.lib.client.get_DID_record(did, hostport='http://localhost:{}'.format(blockstack.lib.client.RPC_SERVER_PORT))
        if 'error' in res:
            print res
            return False

        if res['address'] != wallets[3].addr:
            print 'wrong address post-transfer: expected {}'.format(wallets[3].addr)
            print json.dumps(res, indent=4, sort_keys=True)
            return False

    # foo's original DID should not resolve
    res = blockstack.lib.client.get_DID_record(foo_did, hostport='http://localhost:{}'.format(blockstack.lib.client.RPC_SERVER_PORT))
    if 'error' not in res:
        print 'accidentally resolved {}'.format(foo_did)
        print res
        return False


def check( state_engine ):

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is not None:
        return False 

    ns = state_engine.get_namespace( "test" )
    if ns is None:
        return False 

    if ns['namespace_id'] != 'test':
        return False 

    # all names exist and are owned by wallets[3]
    for name in ['foo.test', 'bar.test', 'baz.test']:
        res = state_engine.get_name(name)
        if res is None or 'error' in res:
            print '{} does not exist'.format(name)
            print res
            return False

        if res['address'] != wallets[3].addr or res['sender'] != virtualchain.make_payment_script(wallets[3].addr):
            print '{} not owned by {}'.format(name, wallets[3].addr)
            return False

    return True
