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

# activate F-day 2017
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 682
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 683
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_GRACE_PERIOD 0
"""

import testlib
import virtualchain
import json
import blockstack

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 2, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_name_preorder( "foo1.test", wallets[2].privkey, wallets[3].addr )
    testlib.blockstack_name_preorder( "foo2.test", wallets[2].privkey, wallets[3].addr )
    testlib.blockstack_name_preorder( "foo3.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    testlib.blockstack_name_register( "foo1.test", wallets[2].privkey, wallets[3].addr, zonefile_hash='11' * 20 )
    testlib.blockstack_name_register( "foo2.test", wallets[2].privkey, wallets[3].addr, zonefile_hash='22' * 20 )
    testlib.blockstack_name_register( "foo3.test", wallets[2].privkey, wallets[3].addr, zonefile_hash='33' * 20 )
    testlib.next_block( **kw )

    def name_rec_equal(r1, r2):
        keys = set(r1.keys() + r2.keys())
        for k in keys:
            if k in r1 and k in r2:
                if r1[k] != r2[k]:
                    return False
        return True

    # dids for each of these names 
    dids = [
        'did:stack:v0:{}-0'.format(wallets[3].addr),
        'did:stack:v0:{}-1'.format(wallets[3].addr),
        'did:stack:v0:{}-2'.format(wallets[3].addr)
    ]
    
    # whois
    for i in xrange(1, 4):
        name = 'foo{}.test'.format(i)

        res = testlib.blockstack_cli_whois(name)
        if 'error' in res:
            print res
            return False

        if not res.has_key('zonefile_hash') or res['zonefile_hash'] != '{}{}'.format(i,i) * 20:
            print res
            return False

        if res['owner_address'] != wallets[3].addr:
            print res
            return False

    # DIDs
    for i in xrange(0, 3):
        name = 'foo{}.test'.format(i+1)
        res = blockstack.lib.client.get_name_DID(name, hostport='http://localhost:{}'.format(blockstack.lib.config.RPC_SERVER_PORT))
        if 'error' in res:
            print res
            return False

        if res != dids[i]:
            print 'DID mismatch: expected {}, got {}'.format(dids[i], res)
            return False

        res = blockstack.lib.client.get_name_record(name, hostport='http://localhost:{}'.format(blockstack.lib.client.RPC_SERVER_PORT))
        if 'error' in res:
            print res
            return False

        name_rec = res

        res = blockstack.lib.client.get_DID_record(dids[i], hostport='http://localhost:{}'.format(blockstack.lib.client.RPC_SERVER_PORT))
        if 'error' in res:
            print res
            return False

        did_rec = res

        if not name_rec_equal(name_rec, did_rec):
            print 'record mismatch'
            print json.dumps(name_rec, sort_keys=True)
            print json.dumps(did_rec, sort_keys=True)
            return False
        
    
    # do stuff with these names
    testlib.blockstack_name_update("foo1.test", "1b" * 20, wallets[3].privkey)
    testlib.blockstack_name_update("foo2.test", "2b" * 20, wallets[3].privkey)
    testlib.blockstack_name_update("foo3.test", "3b" * 20, wallets[3].privkey)

    testlib.blockstack_name_revoke("foo1.test", wallets[3].privkey)
    testlib.blockstack_name_transfer("foo2.test", wallets[4].addr, True, wallets[3].privkey)
    testlib.blockstack_name_transfer("foo3.test", wallets[4].addr, True, wallets[3].privkey)
    testlib.next_block( **kw )

    name_recs = {
        'foo1.test': blockstack.lib.client.get_name_record('foo1.test', hostport='http://localhost:{}'.format(blockstack.lib.client.RPC_SERVER_PORT)),
        'foo2.test': blockstack.lib.client.get_name_record('foo2.test', hostport='http://localhost:{}'.format(blockstack.lib.client.RPC_SERVER_PORT)),
        'foo3.test': blockstack.lib.client.get_name_record('foo3.test', hostport='http://localhost:{}'.format(blockstack.lib.client.RPC_SERVER_PORT)),
    }
    
    assert name_recs['foo1.test']['revoked']
    assert virtualchain.address_reencode(str(name_recs['foo2.test']['address'])) == virtualchain.address_reencode(str(wallets[4].addr))
    assert virtualchain.address_reencode(str(name_recs['foo3.test']['address'])) == virtualchain.address_reencode(str(wallets[4].addr))

    # expire.  Reregister under the same owner
    testlib.next_block( **kw )
    testlib.next_block( **kw )
    testlib.next_block( **kw )
    testlib.next_block( **kw )
    testlib.next_block( **kw )


    testlib.blockstack_name_preorder( "foo1.test", wallets[2].privkey, wallets[3].addr )
    testlib.blockstack_name_preorder( "foo2.test", wallets[2].privkey, wallets[3].addr )
    testlib.blockstack_name_preorder( "foo3.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    testlib.blockstack_name_register( "foo1.test", wallets[2].privkey, wallets[3].addr, zonefile_hash='1a' * 20 )
    testlib.blockstack_name_register( "foo2.test", wallets[2].privkey, wallets[3].addr, zonefile_hash='2a' * 20 )
    testlib.blockstack_name_register( "foo3.test", wallets[2].privkey, wallets[3].addr, zonefile_hash='3a' * 20 )
    testlib.next_block( **kw )

    # whois
    for i in xrange(1, 4):
        name = 'foo{}.test'.format(i)

        res = testlib.blockstack_cli_whois(name)
        if 'error' in res:
            print res
            return False

        if not res.has_key('zonefile_hash') or res['zonefile_hash'] != '{}a'.format(i) * 20:
            print res
            return False

        if res['owner_address'] != wallets[3].addr:
            print res
            return False

    # dids for each of these names 
    new_dids = [
        'did:stack:v0:{}-3'.format(wallets[3].addr),
        'did:stack:v0:{}-4'.format(wallets[3].addr),
        'did:stack:v0:{}-5'.format(wallets[3].addr)
    ]

    # new DIDs
    for i in xrange(0, 3):
        name = 'foo{}.test'.format(i+1)
        res = blockstack.lib.client.get_name_DID(name, hostport='http://localhost:{}'.format(blockstack.lib.config.RPC_SERVER_PORT))
        if 'error' in res:
            print res
            return False

        if res != new_dids[i]:
            print 'DID mismatch: expected {}, got {}'.format(new_dids[i], res)
            return False

        res = blockstack.lib.client.get_name_record(name, hostport='http://localhost:{}'.format(blockstack.lib.client.RPC_SERVER_PORT))
        if 'error' in res:
            print res
            return False

        name_rec = res

        res = blockstack.lib.client.get_DID_record(new_dids[i], hostport='http://localhost:{}'.format(blockstack.lib.client.RPC_SERVER_PORT))
        if 'error' in res:
            print res
            return False

        did_rec = res

        if not name_rec_equal(name_rec, did_rec):
            print 'record mismatch'
            print json.dumps(name_rec, sort_keys=True)
            print json.dumps(did_rec, sort_keys=True)
            return False

    # old DIDs
    for i in xrange(0, 3):
        name = 'foo{}.test'.format(i+1)
        res = blockstack.lib.client.get_DID_record(dids[i], hostport='http://localhost:{}'.format(blockstack.lib.client.RPC_SERVER_PORT))

        did_rec = res
        old_rec = name_recs[name]
        if old_rec.get('revoked') and 'error' not in did_rec:
            print 'revoked did is sitll valid: {}'.format(dids[i])
            print did_rec
            return False

        elif not name_rec_equal(did_rec, old_rec):
            print 'old record mismatch'
            print json.dumps(did_rec, sort_keys=True)
            print json.dumps(old_rec, sort_keys=True)
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

    '''
    for i in xrange(1, 4):
        name = 'foo{}.test'.format(i)

        # not preordered
        preorder = state_engine.get_name_preorder( name, virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr )
        if preorder is not None:
            print 'still have preorder: {}'.format(preorder)
            return False
 
        # registered 
        name_rec = state_engine.get_name(name)
        if name_rec is None:
            print 'did not get name {}'.format(name)
            return False

        # owned by
        if name_rec['address'] != wallets[3].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[3].addr):
            print 'wrong address for {}: {}'.format(name, name_rec)
            return False
    '''
    return True
