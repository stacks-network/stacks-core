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
"""

import testlib
import virtualchain
import json
import base64
import blockstack
import blockstack
import blockstack_zones
import os
import time

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

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_name_preorder( "foo1.test", wallets[2].privkey, wallets[3].addr )
    testlib.blockstack_name_preorder( "foo2.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )
    
    # make zonefiles:
    # one normal one
    # one with a nonstandard zonefile
    zf1_txt = testlib.make_empty_zonefile('foo1.test', wallets[3].addr)
    zf2_txt = '\x00\x01\x02\x03\x04\x05'

    testlib.blockstack_name_register( "foo1.test", wallets[2].privkey, wallets[3].addr, zonefile_hash=blockstack.lib.storage.get_zonefile_data_hash(zf1_txt))
    testlib.blockstack_name_register( "foo2.test", wallets[2].privkey, wallets[3].addr, zonefile_hash=blockstack.lib.storage.get_zonefile_data_hash(zf2_txt))
    testlib.next_block( **kw )

    # replicate zonefiles 
    for zf in [zf1_txt, zf2_txt]:
        res = testlib.blockstack_put_zonefile(zf)
        assert res
    
    print 'waiting for zonefiles to be saved...'
    time.sleep(5)

    # store signed profile for each
    working_dir = kw['working_dir']

    for name in ['foo1.test', 'foo2.test']:
        profile = {'name': name, 'type': '@Person', 'account': []}
        print 'sign profile for {}'.format(name)

        profile_path = os.path.join(working_dir, '{}.profile'.format(name))
        with open(profile_path, 'w') as f:
            f.write(json.dumps(profile))

        jwt = testlib.blockstack_cli_sign_profile(profile_path, wallets[3].privkey)
        if 'error' in jwt:
            print jwt
            return False

        jwt_path = os.path.join(working_dir, '{}.profile.jwt'.format(name))
        with open(jwt_path, 'w') as f:
            f.write(json.dumps(jwt))

        print 'verify profile for {}'.format(name)

        res = testlib.blockstack_cli_verify_profile(jwt_path, wallets[3].addr)
        if 'error' in res:
            print res
            return False

        print 'store profile for {}'.format(name)

        # store the jwt to the right place
        res = testlib.blockstack_put_profile(name, json.dumps(jwt), wallets[3].privkey, 'http://localhost:4000')
        assert res

        print 'lookup profile for {}'.format(name)

        # lookup 
        res = testlib.blockstack_cli_lookup(name)
        if name != 'foo2.test':
            if 'error' in res:
                print res
                return False

            if res['profile'] != profile:
                print 'profile mismatch:'
                print res['profile']
                print profile
                return False

        else:
            if 'zonefile' not in res:
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

    for i in xrange(1, 2):
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

    return True
