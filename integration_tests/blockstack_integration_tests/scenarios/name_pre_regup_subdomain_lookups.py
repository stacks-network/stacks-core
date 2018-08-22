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
import os
import keylib

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

    working_dir = testlib.get_working_dir(**kw)

    sub_zf_template = '$ORIGIN {}\n$TTL 3600\n{}'
    zf_template = '$ORIGIN {}\n$TTL 3600\n_http._tcp URI 10 1 "http://www.foo.com"\n_resolver URI 10 1 "http://resolver.foo"\n{}'
    zf_default_url = '_file URI 10 1 "http://localhost:4000/hub/{}/profile.json'
    zf_default_url_2 = '_file URI 20 1 "http://localhost:4000/hub/{}/profile.json'

    subdomain_zonefiles = {
        'bar.foo1.test': sub_zf_template.format('bar.foo1.test', zf_default_url.format(virtualchain.address_reencode(wallets[0].addr, network='mainnet'))),
        'bar.foo2.test': sub_zf_template.format('bar.foo2.test', zf_default_url.format(virtualchain.address_reencode(wallets[1].addr, network='mainnet'))),
        'bar.foo3.test': sub_zf_template.format('bar.foo3.test', zf_default_url.format(virtualchain.address_reencode(wallets[2].addr, network='mainnet'))),
    }

    zonefiles = {
        'foo1.test': zf_template.format('foo1.test', subdomains.make_subdomain_txt('bar.foo1.test', 'foo1.test', wallets[0].addr, 0, subdomain_zonefiles['bar.foo1.test'], wallets[0].privkey)),
        'foo2.test': zf_template.format('foo2.test', subdomains.make_subdomain_txt('bar.foo2.test', 'foo2.test', wallets[1].addr, 0, subdomain_zonefiles['bar.foo2.test'], wallets[1].privkey)),
        'foo3.test': zf_template.format('foo3.test', subdomains.make_subdomain_txt('bar.foo3.test', 'foo3.test', wallets[2].addr, 0, subdomain_zonefiles['bar.foo3.test'], wallets[2].privkey)),
    }

    testlib.blockstack_name_register( "foo1.test", wallets[2].privkey, wallets[3].addr, zonefile_hash=storage.get_zonefile_data_hash(zonefiles['foo1.test']))
    testlib.blockstack_name_register( "foo2.test", wallets[2].privkey, wallets[3].addr, zonefile_hash=storage.get_zonefile_data_hash(zonefiles['foo2.test']))
    testlib.blockstack_name_register( "foo3.test", wallets[2].privkey, wallets[3].addr, zonefile_hash=storage.get_zonefile_data_hash(zonefiles['foo3.test']))
    testlib.next_block( **kw )

    # sign and put profiles
    for i, subd in enumerate(['bar.foo1.test', 'bar.foo2.test', 'bar.foo3.test']):
        profile_data = {
            'type': 'Person',
            'name': subd,
        }
        profile_jwt = testlib.blockstack_make_profile(profile_data, wallets[i].privkey)
        testlib.blockstack_put_profile(None, profile_jwt, wallets[i].privkey, 'http://localhost:4000')

    # whois
    for i in xrange(1, 4):
        name = 'foo{}.test'.format(i)

        res = testlib.blockstack_cli_whois(name)
        if 'error' in res:
            print res
            return False

        if not res.has_key('zonefile_hash') or res['zonefile_hash'] != storage.get_zonefile_data_hash(zonefiles[name]):
            print res
            return False

        if res['owner_address'] != wallets[3].addr:
            print res
            return False

        # upload zonefile
        assert testlib.blockstack_put_zonefile(zonefiles[name])
    
    subdomain_zonefiles_2 = {
        'bar.foo1.test': sub_zf_template.format('bar.foo1.test', zf_default_url_2.format(virtualchain.address_reencode(wallets[0].addr, network='mainnet'))),
        'bar.foo2.test': sub_zf_template.format('bar.foo2.test', zf_default_url_2.format(virtualchain.address_reencode(wallets[1].addr, network='mainnet'))),
        'bar.foo3.test': sub_zf_template.format('bar.foo3.test', zf_default_url_2.format(virtualchain.address_reencode(wallets[2].addr, network='mainnet'))),
    }

    zonefiles = {
        'foo1.test': zf_template.format('foo1.test', subdomains.make_subdomain_txt('bar.foo1.test', 'foo1.test', wallets[0].addr, 1, subdomain_zonefiles['bar.foo1.test'], wallets[0].privkey)),
        'foo2.test': zf_template.format('foo2.test', subdomains.make_subdomain_txt('bar.foo2.test', 'foo2.test', wallets[1].addr, 1, subdomain_zonefiles['bar.foo2.test'], wallets[1].privkey)),
        'foo3.test': zf_template.format('foo3.test', subdomains.make_subdomain_txt('bar.foo3.test', 'foo3.test', wallets[2].addr, 1, subdomain_zonefiles['bar.foo3.test'], wallets[2].privkey)),
    }

    # update zone files
    testlib.blockstack_name_update('foo1.test', storage.get_zonefile_data_hash(zonefiles['foo1.test']), wallets[3].privkey)
    testlib.blockstack_name_update('foo2.test', storage.get_zonefile_data_hash(zonefiles['foo2.test']), wallets[3].privkey)
    testlib.blockstack_name_update('foo3.test', storage.get_zonefile_data_hash(zonefiles['foo3.test']), wallets[3].privkey)
    testlib.next_block(**kw)

    assert testlib.blockstack_put_zonefile(zonefiles['foo1.test'])
    assert testlib.blockstack_put_zonefile(zonefiles['foo2.test'])
    assert testlib.blockstack_put_zonefile(zonefiles['foo3.test'])

    # kick off subdomain indexing
    testlib.next_block(**kw)
   
    # query each subdomain
    # test 301 redirects.
    res = testlib.blockstack_REST_call('GET', '/v1/names/baz.foo1.test', allow_redirects = False)
    if 'error' in res:
        res['test'] = 'Failed to query non-registered name.'
        print json.dumps(res)
        return False

    if res['http_status'] != 301:
        res['test'] = 'Failed to get a redirect.'
        print json.dumps(res)
        return False

    for i in xrange(1, 4):
        fqn = 'bar.foo{}.test'.format(i)

        # test REST whois
        res = testlib.blockstack_REST_call('GET', '/v1/names/{}'.format(fqn))
        if 'error' in res:
            res['test'] = 'Failed to query name'
            print json.dumps(res)
            return False

        if res['http_status'] != 200 and res['http_status'] != 404:
            res['test'] = 'HTTP status {}, response = {} on name lookup'.format(res['http_status'], res['response'])
            print json.dumps(res)
            return False

        if res['response']['zonefile'] != subdomain_zonefiles[fqn]:
            print 'wrong zone file'
            print res
            print 'expected'
            print zonefiles['foo{}.test'.format(i)]
            return False

        if res['response']['status'] != 'registered_subdomain':
            print 'wrong status'
            print res
            return False
        
        # test CLI lookup
        res = testlib.blockstack_cli_lookup(fqn)
        if 'error' in res:
            print res 
            return False

        print res
        if res['profile'] != {'type': 'Person', 'name': fqn}:
            print 'wrong profile'
            print res['profile']
            return False

        # test REST lookup
        res = testlib.blockstack_REST_call("GET", "/v1/users/{}".format(fqn))
        if 'error' in res:
            res['test'] = 'Failed to query name profile'
            print json.dumps(res)
            return False

        if res['http_status'] != 200 and res['http_status'] != 404:
            res['test'] = 'HTTP status {}, response = {} on name profile lookup'.format(res['http_status'], res['response'])
            print json.dumps(res)
            return False

        print res
        if res['response'] != {'type': 'Person', 'name': fqn}:
            print 'wrong profile on REST call'
            print res
            return False

        # test CLI lookup by address
        res = testlib.blockstack_cli_get_names_owned_by_address(wallets[i-1].addr)
        if 'error' in res:
            print 'failed to get subdomains owned by {}'.format(wallets[i-1].addr)
            print res
            return False

        if fqn not in res:
            print '{} not in list'.format(fqn)
            print res
            return False

        # test REST lookup by address
        res = testlib.blockstack_REST_call('GET', '/v1/addresses/bitcoin/{}'.format(wallets[i-1].addr))
        if 'error' in res:
            res['test'] = 'Failed to query names owned by address'
            print json.dumps(res)
            return False

        if res['http_status'] != 200 and res['http_status'] != 404:
            res['test'] = 'HTTP status {}, response = {} on address lookup'.format(res['http_status'], res['response'])
            print json.dumps(res)
            return False

        if fqn not in res['response']['names']:
            print '{} not in REST list'.format(fqn)
            print res
            return False
     
        # test REST get name history
        res = testlib.blockstack_REST_call('GET', '/v1/names/{}/history'.format(fqn))
        if 'error' in res:
            res['test'] = 'Failed to query subdomain history'
            print json.dumps(res)
            return False

        if res['http_status'] != 200 and res['http_status'] != 404:
            res['test'] = 'HTTP status {}, response = {} on subdomain history lookup'.format(res['http_status'], res['response'])
            print json.dumps(res)
            return False

        blocks = res['response']
        if len(blocks.keys()) != 2:
            print 'expected two updates'
            print blocks
            return False

        # get each historic zone file
        for block_height in blocks:
            for prev_state in blocks[block_height]:
                value_hash = prev_state['value_hash']
                res = testlib.blockstack_REST_call('GET', '/v1/names/{}/zonefile/{}'.format(fqn, value_hash))
                if 'error' in res:
                    print 'failed to query zone file {} for {}'.format(value_hash, fqn)
                    print json.dumps(res)
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
