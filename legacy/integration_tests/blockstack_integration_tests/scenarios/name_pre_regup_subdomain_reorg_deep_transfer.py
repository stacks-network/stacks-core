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
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet( "5JaJ7qkW8ih1Po21Pg6EqbSBmDGm11gXrqwgyJEY4L1P5k9jyMP", 100000000000 ),
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
    
    # send initial zone files
    zonefiles = {
        'foo1.test': zf_template.format('foo1.test', subdomains.make_subdomain_txt('bar.foo1.test', 'foo1.test', wallets[4].addr, 0, zf_template.format('bar.foo1.test', zf_default_url), wallets[4].privkey)),
        'foo2.test': zf_template.format('foo2.test', subdomains.make_subdomain_txt('bar.foo2.test', 'foo2.test', wallets[4].addr, 0, zf_template.format('bar.foo2.test', zf_default_url), wallets[4].privkey)),
        'foo3.test': zf_template.format('foo3.test', subdomains.make_subdomain_txt('bar.foo3.test', 'foo3.test', wallets[4].addr, 0, zf_template.format('bar.foo3.test', zf_default_url), wallets[4].privkey)),
    }

    testlib.blockstack_name_register( "foo1.test", wallets[2].privkey, wallets[3].addr, zonefile_hash=storage.get_zonefile_data_hash(zonefiles['foo1.test']))
    testlib.blockstack_name_register( "foo2.test", wallets[2].privkey, wallets[3].addr, zonefile_hash=storage.get_zonefile_data_hash(zonefiles['foo2.test']))
    testlib.blockstack_name_register( "foo3.test", wallets[2].privkey, wallets[3].addr, zonefile_hash=storage.get_zonefile_data_hash(zonefiles['foo3.test']))
    testlib.next_block( **kw )
    
    assert testlib.blockstack_put_zonefile(zonefiles['foo1.test'])
    assert testlib.blockstack_put_zonefile(zonefiles['foo2.test'])
    assert testlib.blockstack_put_zonefile(zonefiles['foo3.test'])

    # subdomain history diagram
    # bar.foo1.test ++ #sequence ++ @zonefile_index
    #
    #
    #                                  bar.foo1.test#2@3   (1)
    #                                 /
    #                 bar.foo1.test#1@1
    #                /                \
    #               /                  bar.foo1.test#2@4   (2)
    # bar.foo1.test#0
    #               \                  bar.foo1.test#2@5   (3)
    #                \                /
    #                 bar.foo1.test#1@2
    #                                 \
    #                                  bar.foo1.test#2@6   (4)
    #
    #
    # Send branches (1), (2), (3), and (4)
    # Reveal branches (4), then (3), then (2), then (1).  Verify that the subdomain record matches the leaf node's state in order of revealing.

    def _send_batch(zf_default_url, seq, new_addr, cur_privkey):
        zf_template = "$ORIGIN {}\n$TTL 3600\n{}"

        zonefiles = {
            'foo1.test': zf_template.format('foo1.test', subdomains.make_subdomain_txt('bar.foo1.test', 'foo1.test', new_addr, seq, zf_template.format('bar.foo1.test', zf_default_url), cur_privkey)),
            'foo2.test': zf_template.format('foo2.test', subdomains.make_subdomain_txt('bar.foo2.test', 'foo2.test', new_addr, seq, zf_template.format('bar.foo2.test', zf_default_url), cur_privkey)),
            'foo3.test': zf_template.format('foo3.test', subdomains.make_subdomain_txt('bar.foo3.test', 'foo3.test', new_addr, seq, zf_template.format('bar.foo3.test', zf_default_url), cur_privkey)),
        }

        testlib.blockstack_name_update('foo1.test', storage.get_zonefile_data_hash(zonefiles['foo1.test']), wallets[3].privkey)
        testlib.blockstack_name_update('foo2.test', storage.get_zonefile_data_hash(zonefiles['foo2.test']), wallets[3].privkey)
        testlib.blockstack_name_update('foo3.test', storage.get_zonefile_data_hash(zonefiles['foo3.test']), wallets[3].privkey)
        testlib.next_block(**kw)

        return zonefiles
 
    def _query_subdomains(subdomain_names, expected_zonefiles, expected_sequence, owner_addr):
        # query each subdomain.  Should get the latest
        for (fqn, expected_zonefile) in zip(subdomain_names, expected_zonefiles):
            res = client.get_name_record(fqn, hostport='http://localhost:16264')
            if 'error' in res:
                print res
                print 'failed to query {}'.format(fqn)
                return False

            if res['sequence'] != expected_sequence:
                print 'wrong sequence; expected {}'.format(expected_sequence)
                print res
                return False

            if res['address'] != owner_addr:
                print 'wrong owner addr: {}'.format(owner_addr)
                print res
                return False
            
            if base64.b64decode(res['zonefile']) != expected_zonefile:
                print 'zonefile mismatch'
                print 'expected\n{}'.format(expected_zonefile)
                print 'got\n{}'.format(base64.b64decode(res['zonefile']))
                return False

            # should be in atlas as well
            zf = testlib.blockstack_get_zonefile(res['value_hash'], parse=False)
            if not zf:
                print 'no zone file {} in atlas'.format(res['value_hash'])
                return False

            if zf != expected_zonefile:
                print 'zonefile mismatch in atlas'
                print 'expected\n{}'.format(expected_zonefile)
                print 'got\n{}'.format(base64.b64decode(res['zonefile']))
                return False

        return True

    branch_1 = []
    branch_2 = []
    branch_3 = []
    branch_4 = []
    
    # final branch URLs, since we're reorging by both sequence number and key
    branch_urls = [
        '_https._tcp URI 10 1 "https://branch3-and-4.com"',
        '_https._tcp URI 10 1 "https://branch4.com"',
        '_https._tcp URI 10 1 "https://branch3.com"',
        '_https._tcp URI 10 1 "https://branch1-and-2.com"',
        '_https._tcp URI 10 1 "https://branch2.com"',
        '_https._tcp URI 10 1 "https://branch1.com"',
    ]

    # final sequence numbers, since we're reorging only on sequence number
    branch_sequences = [
        1,
        2,
        2,
        1,
        2,
        2,
    ]

    # expected subdomain owners at each node
    branch_owners = [
        wallets[3].addr,
        wallets[5].addr,
        wallets[4].addr,
        wallets[0].addr,
        wallets[2].addr,
        wallets[1].addr
    ]

    # send branch 1
    branch1_zfs = _send_batch('_https._tcp URI 10 1 "https://branch1-and-2.com"', 1, wallets[0].addr, wallets[4].privkey)
    # branch_1.append(zfs)

    zfs = _send_batch('_https._tcp URI 10 1 "https://branch1.com"', 2, wallets[1].addr, wallets[0].privkey)
    branch_1.append(zfs)

    # send branch 2
    branch_2.append(branch1_zfs)
    
    zfs = _send_batch('_https._tcp URI 10 1 "https://branch2.com"', 2, wallets[2].addr, wallets[0].privkey)
    branch_2.append(zfs)

    # send branch 3
    branch3_zfs = _send_batch('_https._tcp URI 10 1 "https://branch3-and-4.com"', 1, wallets[3].addr, wallets[4].privkey)
    # branch_3.append(zfs)

    zfs = _send_batch('_https._tcp URI 10 1 "https://branch3.com"', 2, wallets[4].addr, wallets[3].privkey)
    branch_3.append(zfs)

    # send branch 4
    branch_4.append(branch3_zfs)

    zfs = _send_batch('_https._tcp URI 10 1 "https://branch4.com"', 2, wallets[5].addr, wallets[3].privkey)
    branch_4.append(zfs)
    
    # reveal in reverse.
    # branch_1 should be the final result
    b = 0
    for j, branch in enumerate([branch_4, branch_3, branch_2, branch_1]):
        # reveal this branch, piecemeal 
        for i, zf_batch in enumerate(branch):
            for name in zf_batch:
                print ''
                print 'reveal branch {}, node {}:\n{}'.format(4 - j, i+1, zf_batch[name])
                print ''
                assert testlib.blockstack_put_zonefile(zf_batch[name])

            testlib.next_block(**kw)

            # make sure all subdomains are consistent with this branch 
            seq = branch_sequences[b]
            subdomain_names = ['bar.foo1.test', 'bar.foo2.test', 'bar.foo3.test']
            
            zf_template = "$ORIGIN {}\n$TTL 3600\n{}"
            zf_default_url = branch_urls[b]
            owner_addr = branch_owners[b]

            zonefiles = [
                zf_template.format('bar.foo1.test', zf_default_url),
                zf_template.format('bar.foo2.test', zf_default_url),
                zf_template.format('bar.foo3.test', zf_default_url),
            ]
            
            print ''
            print 'check {} at sequence={} at branch {} node {}'.format(','.join(subdomain_names), seq, 4 - j, i+1)
            print ''

            rc = _query_subdomains(subdomain_names, zonefiles, seq, owner_addr)
            if not rc:
                print 'failed to query subdomains'
                return False
            
            b += 1
           
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
