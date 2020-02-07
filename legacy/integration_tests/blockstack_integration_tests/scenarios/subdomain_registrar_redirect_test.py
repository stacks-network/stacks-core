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
# activate F-day 2017 at the right time
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 682
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 683
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 1
"""

import testlib
import virtualchain
import time
import json
import sys
import os
import requests
from subprocess import Popen

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 5500 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 5500 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

SUBDOMAIN_REGISTRAR_LOCATION = os.environ.get('BSK_SUBDOMAIN_REGISTRAR_LOCATION',
                                              '/usr/bin/blockstack-subdomain-registrar')

SUBDOMAIN_PROC = None

def start_subdomain_registrar():
    global SUBDOMAIN_PROC

    try:
        os.rename('/tmp/subdomain_registrar.db', '/tmp/subdomain_registrar.last')
    except OSError:
        pass
    env = {'BSK_SUBDOMAIN_REGTEST' : '1'}
    if os.environ.get('BLOCKSTACK_TEST_CLIENT_RPC_PORT', False):
        env['BLOCKSTACK_TEST_CLIENT_RPC_PORT'] = os.environ.get('BLOCKSTACK_TEST_CLIENT_RPC_PORT')

    SUBDOMAIN_PROC = Popen(['node', SUBDOMAIN_REGISTRAR_LOCATION], env = env)
    testlib.add_cleanup(lambda: SUBDOMAIN_PROC.kill())


def scenario( wallets, **kw ):
    start_subdomain_registrar()

    testlib.blockstack_namespace_preorder( "id", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "id", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "id", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_register_user("foo.id", wallets[2].privkey, wallets[3].privkey, **kw)

    # now, queue a registration.

    requests.post('http://localhost:3000/register',
                  json = { 'zonefile' : 'hello world',
                           'name' : 'bar',
                           'owner_address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa' })

    # force a batch out of the subdomain registrar

    requests.post('http://localhost:3000/issue_batch',
                  headers = {'Authorization': 'bearer tester129'})

    for i in xrange(0, 12):
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting 10 seconds for the backend to pickup first batch"
    time.sleep(10)

    # now, queue another registration

    requests.post('http://localhost:3000/register',
                  json = { 'zonefile' : 'hello world',
                           'name' : 'zap',
                           'owner_address': '1Ez69SnzzmePmZX3WpEzMKTrcBF2gpNQ55' })

    res = testlib.blockstack_REST_call('GET', '/v1/names/zap.foo.id', None)

    if 'error' in res:
        res['test'] = 'Failed to query zap.foo.id'
        print json.dumps(res)
        return False

    if res['http_status'] != 200:
        res['test'] = 'HTTP status {}, response = {} on name lookup'.format(res['http_status'], res['response'])
        print json.dumps(res)
        return False

    name_info = res['response']
    try:
        if (name_info['zonefile'] != 'hello world' or
            name_info['address'] != '1Ez69SnzzmePmZX3WpEzMKTrcBF2gpNQ55'):
            res['test'] = 'Unexpected name info lookup for zap.foo.id'
            print 'zap.foo.id JSON:'
            print json.dumps(name_info)
            return False
    except:
        res['test'] = 'Unexpected name info lookup for zap.foo.id'
        print 'zap.foo.id JSON:'
        print json.dumps(name_info)
        return False

    SUBDOMAIN_PROC.kill()

def check( state_engine ):

    # not revealed, but ready
    ns = state_engine.get_namespace_reveal( "id" )
    if ns is not None:
        print "namespace reveal exists"
        return False

    ns = state_engine.get_namespace( "id" )
    if ns is None:
        print "no namespace"
        return False

    if ns['namespace_id'] != 'id':
        print "wrong namespace"
        return False

    # registered
    name_rec = state_engine.get_name( "foo.id" )
    if name_rec is None:
        print "name does not exist"
        return False

    return True
