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

    subd_zf_template = "$ORIGIN {}\n$TTL 3600\n{}"
    zf_template = "$ORIGIN {}\n$TTL 3600\n{}"
    zf_default_url = '_https._tcp URI 10 1 "https://raw.githubusercontent.com/nobody/content/profile.md"'
    zf_default_url_original = zf_default_url

    zonefiles = {
        'foo1.test': zf_template.format('foo1.test', subdomains.make_subdomain_txt('bar.foo1.test', 'foo1.test', wallets[4].addr, 0, subd_zf_template.format('bar.foo1.test', zf_default_url), wallets[4].privkey)),
        'foo2.test': zf_template.format('foo2.test', subdomains.make_subdomain_txt('bar.foo2.test', 'foo2.test', wallets[4].addr, 0, subd_zf_template.format('bar.foo2.test', zf_default_url), wallets[4].privkey)),
        'foo3.test': zf_template.format('foo3.test', subdomains.make_subdomain_txt('bar.foo3.test', 'foo3.test', wallets[4].addr, 0, subd_zf_template.format('bar.foo3.test', zf_default_url), wallets[4].privkey)),
    }

    testlib.blockstack_name_register( "foo1.test", wallets[2].privkey, wallets[3].addr, zonefile_hash=storage.get_zonefile_data_hash(zonefiles['foo1.test']))
    testlib.blockstack_name_register( "foo2.test", wallets[2].privkey, wallets[3].addr, zonefile_hash=storage.get_zonefile_data_hash(zonefiles['foo2.test']))
    testlib.blockstack_name_register( "foo3.test", wallets[2].privkey, wallets[3].addr, zonefile_hash=storage.get_zonefile_data_hash(zonefiles['foo3.test']))
    testlib.next_block( **kw )
    
    # send these initial ones out
    assert testlib.blockstack_put_zonefile(zonefiles['foo1.test'])
    assert testlib.blockstack_put_zonefile(zonefiles['foo2.test'])
    assert testlib.blockstack_put_zonefile(zonefiles['foo3.test'])

    missing_zonefiles = []

    # send updates too
    for i in range(0, 3):
        subd_zf_template = "$ORIGIN {}\n$TTL 3600\n{}"
        zf_template = subd_zf_template
        if i % 2 == 0:
            if i == 0:
                zf_template = "$ORIGIN {}\n$TTL 3600\n{}\n_resolver URI 10 1 \"http://localhost:16269\""
            else:
                zf_template = "$ORIGIN {}\n$TTL 3600\n{}\n_resolver URI 10 1 \"http://testnet.blockstack.org:16269\""

        zf_default_url = '_https._tcp URI 10 1 "https://test.com/?index={}"'.format(i+1)

        zonefiles = {
            'foo1.test': zf_template.format('foo1.test', subdomains.make_subdomain_txt('bar.foo1.test', 'foo1.test', wallets[4].addr, i+1, subd_zf_template.format('bar.foo1.test', zf_default_url), wallets[4].privkey)),
            'foo2.test': zf_template.format('foo2.test', subdomains.make_subdomain_txt('bar.foo2.test', 'foo2.test', wallets[4].addr, i+1, subd_zf_template.format('bar.foo2.test', zf_default_url), wallets[4].privkey)),
            'foo3.test': zf_template.format('foo3.test', subdomains.make_subdomain_txt('bar.foo3.test', 'foo3.test', wallets[4].addr, i+1, subd_zf_template.format('bar.foo3.test', zf_default_url), wallets[4].privkey)),
        }

        testlib.blockstack_name_update('foo1.test', storage.get_zonefile_data_hash(zonefiles['foo1.test']), wallets[3].privkey)
        testlib.blockstack_name_update('foo2.test', storage.get_zonefile_data_hash(zonefiles['foo2.test']), wallets[3].privkey)
        testlib.blockstack_name_update('foo3.test', storage.get_zonefile_data_hash(zonefiles['foo3.test']), wallets[3].privkey)
        testlib.next_block(**kw)

        if i % 2 == 0:
            # withhold for now
            missing_zonefiles.append(zonefiles)
        else:
            # send these out
            assert testlib.blockstack_put_zonefile(zonefiles['foo1.test'])
            assert testlib.blockstack_put_zonefile(zonefiles['foo2.test'])
            assert testlib.blockstack_put_zonefile(zonefiles['foo3.test'])
    
    assert len(missing_zonefiles) == 2
    
    # verify that initial subdomains are present 
    for i in xrange(1, 4):
        fqn = 'bar.foo{}.test'.format(i)
        res = client.get_name_record(fqn, hostport='http://localhost:16264')
        if 'error' in res:
            print res
            return False
        
        if res['sequence'] != 0:
            print 'wrong sequence: expected 0'
            print res
            return False

        expected_zonefile = subd_zf_template.format(fqn, zf_default_url_original)
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

        # get domain
        res = client.get_name_record('foo{}.test'.format(i), hostport='http://localhost:16264')
        if 'error' in res:
            print res
            return False

        # no resolver entry yet
        if 'resolver' in res and res['resolver']:
            print 'got a resolver'
            print json.dumps(res, indent=4, sort_keys=True)
            return False

    # send first batch of withheld zonefiles 
    assert testlib.blockstack_put_zonefile(missing_zonefiles[0]['foo1.test'])
    assert testlib.blockstack_put_zonefile(missing_zonefiles[0]['foo2.test'])
    assert testlib.blockstack_put_zonefile(missing_zonefiles[0]['foo3.test'])
    
    # kick off subdomain indexing
    testlib.next_block(**kw)
 
    # verify that we're now up to sequence=2
    for i in xrange(1, 4):
        fqn = 'bar.foo{}.test'.format(i)
        res = client.get_name_record(fqn, hostport='http://localhost:16264')
        if 'error' in res:
            print res
            return False
        
        if res['sequence'] != 2:
            print 'wrong sequence: expected 2'
            print res
            return False

        # should have a resolver entry

        zf_default_url = '_https._tcp URI 10 1 "https://test.com/?index=2"'
        expected_zonefile = subd_zf_template.format(fqn, zf_default_url)
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

        # get domain
        res = client.get_name_record('foo{}.test'.format(i), hostport='http://localhost:16264')
        if 'error' in res:
            print res
            return False

        # should now have the (old) resolver
        if 'resolver' not in res or not res['resolver']:
            print 'no resolver; expected http://localhost:16269'
            print json.dumps(res, indent=4, sort_keys=True)
            return False

        if res['resolver'] != 'http://localhost:16269':
            print 'wrong resolver: {}'.format(res['resolver'])
            print json.dumps(res, indent=4, sort_keys=True)
            return False

    # send second batch of withheld zonefiles 
    assert testlib.blockstack_put_zonefile(missing_zonefiles[1]['foo1.test'])
    assert testlib.blockstack_put_zonefile(missing_zonefiles[1]['foo2.test'])
    assert testlib.blockstack_put_zonefile(missing_zonefiles[1]['foo3.test'])
    
    # kick off subdomain indexing
    testlib.next_block(**kw)

    # query each subdomain (should all be at sequence 3)
    for i in xrange(1, 4):
        fqn = 'bar.foo{}.test'.format(i)
        res = client.get_name_record(fqn, hostport='http://localhost:16264')
        if 'error' in res:
            print res
            return False
        
        if res['sequence'] != 3:
            print 'wrong sequence: expected 3'
            print res
            return False

        zf_default_url = '_https._tcp URI 10 1 "https://test.com/?index=3"'
        expected_zonefile = subd_zf_template.format(fqn, zf_default_url)
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

        # should now have the (new) resolver
        if 'resolver' not in res or not res['resolver']:
            print 'no resolver; expected http://testnet.blockstack.org:16269'
            print json.dumps(res, indent=4, sort_keys=True)
            return False

        if res['resolver'] != 'http://testnet.blockstack.org:16269':
            print 'wrong resolver: {}'.format(res['resolver'])
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
