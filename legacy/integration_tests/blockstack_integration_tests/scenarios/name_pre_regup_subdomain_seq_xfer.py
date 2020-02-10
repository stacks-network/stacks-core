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
import blockstack
import blockstack.lib.subdomains as subdomains
import blockstack.lib.storage as storage
import blockstack.lib.client as client
import blockstack_zones
import base64

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
    testlib.blockstack_name_preorder( "foo3.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    zf_template = "$ORIGIN {}\n$TTL 3600\n{}"
    zf_default_url = '_https._tcp URI 10 1 "https://raw.githubusercontent.com/nobody/content/profile.md"'

    zonefiles = {
        'foo1.test': zf_template.format('foo1.test', subdomains.make_subdomain_txt('bar.foo1.test', 'foo1.test', wallets[4].addr, 0, zf_template.format('bar.foo1.test', zf_default_url), wallets[4].privkey)),
        'foo2.test': zf_template.format('foo2.test', subdomains.make_subdomain_txt('bar.foo2.test', 'foo2.test', wallets[4].addr, 0, zf_template.format('bar.foo2.test', zf_default_url), wallets[4].privkey)),
        'foo3.test': zf_template.format('foo3.test', subdomains.make_subdomain_txt('bar.foo3.test', 'foo3.test', wallets[4].addr, 0, zf_template.format('bar.foo3.test', zf_default_url), wallets[4].privkey)),
    }

    testlib.blockstack_name_register( "foo1.test", wallets[2].privkey, wallets[3].addr, zonefile_hash=storage.get_zonefile_data_hash(zonefiles['foo1.test']))
    testlib.blockstack_name_register( "foo2.test", wallets[2].privkey, wallets[3].addr, zonefile_hash=storage.get_zonefile_data_hash(zonefiles['foo2.test']))
    testlib.blockstack_name_register( "foo3.test", wallets[2].privkey, wallets[3].addr, zonefile_hash=storage.get_zonefile_data_hash(zonefiles['foo3.test']))
    testlib.next_block( **kw )
    
    def _query_subdomains(subdomain_names, expected_sequence, expected_owner):
        # query each subdomain.  Should get the latest
        for fqn in subdomain_names:
            res = client.get_name_record(fqn, hostport='http://localhost:16264')
            if 'error' in res:
                print res
                print 'failed to query {}'.format(fqn)
                return False
            
            # should have right sequence
            if res['sequence'] != expected_sequence:
                print 'wrong sequence; expected {}'.format(expected_sequence)
                print res
                return False
           
            # should have right owner
            if res['address'] != expected_owner:
                print 'wrong owner'
                print 'expected {}'.format(res['address'])
                print res
                return False

        return True


    assert testlib.blockstack_put_zonefile(zonefiles['foo1.test'])
    assert testlib.blockstack_put_zonefile(zonefiles['foo2.test'])
    assert testlib.blockstack_put_zonefile(zonefiles['foo3.test'])
    
    # kick off indexing and check 
    testlib.next_block(**kw)
    assert _query_subdomains(['bar.foo1.test', 'bar.foo2.test', 'bar.foo3.test'], 0, wallets[4].addr)
    
    expected_owners = [wallets[4].addr]

    # send updates too, and transfer subdomains
    for i in range(0, 6):
        zf_template = "$ORIGIN {}\n$TTL 3600\n{}"
        zf_default_url = '_https._tcp URI 10 1 "https://test.com/?index={}"'.format(i+1)
        
        j = (4 + i) % 5
        k = (4 + i + 1) % 5
        expected_owners.append(wallets[k].addr)

        zonefiles = {
            'foo1.test': zf_template.format('foo1.test', subdomains.make_subdomain_txt('bar.foo1.test', 'foo1.test', wallets[k].addr, i+1, zf_template.format('bar.foo1.test', zf_default_url), wallets[j].privkey)),
            'foo2.test': zf_template.format('foo2.test', subdomains.make_subdomain_txt('bar.foo2.test', 'foo2.test', wallets[k].addr, i+1, zf_template.format('bar.foo2.test', zf_default_url), wallets[j].privkey)),
            'foo3.test': zf_template.format('foo3.test', subdomains.make_subdomain_txt('bar.foo3.test', 'foo3.test', wallets[k].addr, i+1, zf_template.format('bar.foo3.test', zf_default_url), wallets[j].privkey)),
        }

        testlib.blockstack_name_update('foo1.test', storage.get_zonefile_data_hash(zonefiles['foo1.test']), wallets[3].privkey)
        testlib.blockstack_name_update('foo2.test', storage.get_zonefile_data_hash(zonefiles['foo2.test']), wallets[3].privkey)
        testlib.blockstack_name_update('foo3.test', storage.get_zonefile_data_hash(zonefiles['foo3.test']), wallets[3].privkey)
        testlib.next_block(**kw)

        assert testlib.blockstack_put_zonefile(zonefiles['foo1.test'])
        assert testlib.blockstack_put_zonefile(zonefiles['foo2.test'])
        assert testlib.blockstack_put_zonefile(zonefiles['foo3.test'])
    
        # kick off subdomain indexing
        testlib.next_block(**kw)

        # verify history
        assert _query_subdomains(['bar.foo1.test', 'bar.foo2.test', 'bar.foo3.test'], i+1, wallets[k].addr)
        
    
    # query subdomain history
    for subd in ['bar.foo1.test', 'bar.foo2.test', 'bar.foo3.test']:
        res = client.get_name_record(subd, include_history=True, hostport='http://localhost:16264')
        if 'error' in res:
            print res
            return False

        for i, block_height in enumerate(sorted(res['history'])):
            if res['history'][block_height][0]['address'] != expected_owners[i]:
                print 'wrong owner at {}: expected {}'.format(block_height, expected_owners[i])
                print json.dumps(res, indent=4, sort_keys=True)
                return False

            if res['history'][block_height][0]['sequence'] != i:
                print 'wrong sequence at {}: expected {}'.format(block_height, i)
                print json.dumps(res, indent=4, sort_keys=True)
                return False

    # reindex
    assert testlib.check_subdomain_db(**kw)


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

    return True
