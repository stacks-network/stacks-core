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
import requests
import sys

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

FOO_ZONEFILE_HASH = ''
HELLO_FOO_ZONEFILE_HASH = ''
CONSENSUS_HASH = ''

def get_fixtures():
    fixtures = [
        {
            'route': '/v1/names',
            'status': 400,
        },
        {
            'route': '/v1/names?page=0',
            'status': 200,
            'body': ['foo.test'],
        },
        {
            'route': '/v1/names?page=1',
            'status': 200,
            'body': [],
        },
        {
            'route': '/v1/subdomains',
            'status': 400,
        },
        {
            'route': '/v1/subdomains?page=0',
            'status': 200,
            'body': ['hello.foo.test'],
        },
        {
            'route': '/v1/subdomains?page=1',
            'status': 200,
            'body': [],
        },
        {
            'route': '/v1/names/foo.test',
            'status': 200,
        },
        {
            'route': '/v1/names/hello.foo.test',
            'status': 200,
        },
        {
            'route': '/v1/names/invalid',
            'status': 400,
        },
        {
            'route': '/v1/names/not.found',
            'status': 404,
        },
        {
            'route': '/v1/names/foo.test/history',
            'status': 200,
        },
        {
            'route': '/v1/names/foo.test/history?page=0',
            'status': 200,
        },
        {
            'route': '/v1/names/foo.test/history?page=1',
            'status': 404,
        },
        {
            'route': '/v1/names/hello.foo.test/history',
            'status': 200,
        },
        {
            'route': '/v1/names/hello.foo.test/history?page=0',
            'status': 200,
        },
        {
            'route': '/v1/names/hello.foo.test/history?page=1',
            'status': 404,
        },
        {
            'route': '/v1/names/not.found/history?page=0',
            'status': 404,
        },
        {
            'route': '/v1/names/notfound.foo.test/history?page=0',
            'status': 404,
        },
        {
            'route': '/v1/names/foo.test/zonefile',
            'status': 200,
        },
        {
            'route': '/v1/names/hello.foo.test/zonefile',
            'status': 200,
        },
        {
            'route': '/v1/names/not.found/zonefile',
            'status': 404,
        },
        {
            'route': '/v1/names/notfound.foo.test/zonefile',
            'status': 404,
        },
        {
            'route': '/v1/names/foo.test/zonefile/{}'.format(FOO_ZONEFILE_HASH),
            'status': 200,
        },
        {
            'route': '/v1/names/foo.test/zonefile/0000000000000000000000000000000000000000',
            'status': 404,
        },
        {
            'route': '/v1/names/foo.test/zonefile/{}'.format(HELLO_FOO_ZONEFILE_HASH),
            'status': 404,
        },
        {
            'route': '/v1/names/hello.foo.test/zonefile/{}'.format(HELLO_FOO_ZONEFILE_HASH),
            'status': 200,
        },
        {
            'route': '/v1/names/hello.foo.test/zonefile/{}'.format(FOO_ZONEFILE_HASH),
            'status': 404,
        },
        {
            'route': '/v1/names/not.found/zonefile/{}'.format(FOO_ZONEFILE_HASH),
            'status': 404,
        },
        {
            'route': '/v1/names/notfound.foo.test/zonefile/{}'.format(HELLO_FOO_ZONEFILE_HASH),
            'status': 404,
        },
        {
            'route': '/v1/addresses/bitcoin/{}'.format(wallets[3].addr),
            'status': 200,
            'body': {'names': ['foo.test', 'hello.foo.test']},
        },
        {
            'route': '/v1/addresses/bitcoin/{}'.format(wallets[0].addr),
            'status': 200,
            'body': {'names': []},
        },
        {
            'route': '/v1/prices/namespaces/id',
            'status': 200,
            'body': {"satoshis": 400000000, "units": "BTC", "amount": "400000000"},
        },
        {
            'route': '/v1/prices/namespaces/ID',
            'status': 400,
        },
        {
            'route': '/v1/prices/namespaces/asdfasdfasdfasdfasdf',
            'status': 400,
        },
        {
            'route': '/v1/prices/names/foo.test',
            'status': 200,
            'body': {"name_price": {"satoshis": 640000, "units": "BTC", "amount": "640000"}},
        },
        {
            'route': '/v1/prices/names/hello.foo.test',
            'status': 400
        },
        {
            'route': '/v1/prices/names/asdfasdfasdfasdfasdfasdfasdfasdfa.test',
            'status': 400
        },
        {
            'route': '/v1/blockchains/bitcoin/consensus',
            'status': 200,
            'body': {'consensus_hash': CONSENSUS_HASH}
        },
        {
            'route': '/v1/blockchains/bitcoin/name_count',
            'status': 200,
            'body': {'names_count': 1}
        },
        {
            'route': '/v1/blockchains/bitcoin/name_count?all=1',
            'status': 200,
            'body': {'names_count': 1}
        },
        {
            'route': '/v1/blockchains/bitcoin/subdomains_count',
            'status': 200,
            'body': {'names_count': 1}
        },
        {
            'route': '/v1/namespaces',
            'status': 200,
            'body': ['test']
        },
        {
            'route': '/v1/namespaces/test/names?page=0',
            'status': 200,
            'body': ['foo.test']
        },
        {
            'route': '/v1/namespaces/test/names?page=1',
            'status': 200,
            'body': [],
        },
        {
            'route': '/v1/namespaces/test/names',
            'status': 400,
        }
    ]
    
    return fixtures


def scenario( wallets, **kw ):
    
    global FOO_ZONEFILE_HASH, HELLO_FOO_ZONEFILE_HASH, CONSENSUS_HASH

    zf_template = "$ORIGIN {}\n$TTL 3600\n{}"
    zf_default_url = '_https._tcp URI 10 1 "https://raw.githubusercontent.com/nobody/content/profile.md"'

    hello_foo_zonefile = zf_template.format('bar.foo.test', zf_default_url)
    foo_zonefile = zf_template.format('foo.test', subdomains.make_subdomain_txt('hello.foo.test', 'foo.test', wallets[3].addr, 0, hello_foo_zonefile, wallets[3].privkey))

    HELLO_FOO_ZONEFILE_HASH = blockstack.lib.storage.get_zonefile_data_hash(hello_foo_zonefile)
    FOO_ZONEFILE_HASH = blockstack.lib.storage.get_zonefile_data_hash(foo_zonefile)

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr, zonefile_hash=FOO_ZONEFILE_HASH)
    testlib.next_block( **kw )

    testlib.blockstack_put_zonefile(foo_zonefile)
    testlib.next_block( **kw )

    CONSENSUS_HASH = testlib.get_consensus_at(testlib.get_current_block(**kw))

    errors = []
    fixtures = get_fixtures()
    for entry in fixtures:
        url = 'http://localhost:16268' + entry['route']
        res = requests.get(url, allow_redirects=False)

        res_status = res.status_code
        res_txt = res.text
        res_json = None
        try:
            res_json = res.json()
        except:
            pass

        if 'status' in entry and entry['status'] != res_status:
            err = '{}: status {} (expected {})\nbody: {}'.format(url, res_status, entry['status'], res_txt)
            print >> sys.stderr, err
            errors.append(err)

        if 'body' in entry and ((res_json is not None and entry['body'] != res_json) or (res_json is None and res_txt != entry['body'])):
            err = '{}: wrong body {} (expected {})'.format(url, res_txt, entry['body'])
            print >> sys.stderr, err
            errors.append(err)

    if len(errors) > 0:
        print >> sys.stderr, json.dumps(errors, indent=4)
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

    name = 'foo.test'

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
