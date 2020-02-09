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
        os.rename('/tmp/subdomain_registrar.log', '/tmp/subdomain_registrar.log.bak')
    except OSError:
        pass
    env = {'BSK_SUBDOMAIN_REGTEST' : '1'}
    if os.environ.get('BLOCKSTACK_TEST_CLIENT_RPC_PORT', False):
        env['BLOCKSTACK_TEST_CLIENT_RPC_PORT'] = os.environ.get('BLOCKSTACK_TEST_CLIENT_RPC_PORT')

    fd = open('/tmp/subdomain_registrar.log', 'w+')
    SUBDOMAIN_PROC = Popen(['node', SUBDOMAIN_REGISTRAR_LOCATION], stdout=fd, stderr=fd, env = env)

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

    # now, queue a few registrations.
    for i in range(0, len(wallets)):
        res = requests.post('http://localhost:3000/register',
                            json = { 'zonefile': 'hello world {}'.format(i),
                                     'name': 'bar{}'.format(i),
                                     'owner_address': virtualchain.address_reencode(wallets[i].addr, network='mainnet') })

        if res.status_code != 202:
            print 'bad POST status code {}'.format(res.status_code)
            return False

        time.sleep(1)

    # force a batch out of the subdomain registrar

    requests.post('http://localhost:3000/issue_batch',
                  headers = {'Authorization': 'bearer tester129'})

    for i in xrange(0, 12):
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting 10 seconds for the backend to pickup first batch"
    time.sleep(10)

    # list all subdomains
    res = requests.get('http://localhost:3000/list/{}'.format(0))
    if res.status_code != 200:
        print 'bad status code on list: {}'.format(res.status_code)
        return False

    listing = res.json()

    # should be in order by queue_ix (iterator)
    for i in range(0, len(wallets)):
        if listing[i]['name'] != 'bar{}.foo.id'.format(i):
            print 'wrong name: {}'.format(listing[i])
            return False

        if listing[i]['address'] != virtualchain.address_reencode(wallets[i].addr, network='mainnet'):
            print 'wrong address: {}'.format(listing[i])
            return False

        if listing[i]['sequence'] != 0:
            print 'wrong sequence: {}'.format(listing[i])
            return False

        if listing[i]['zonefile'] != 'hello world {}'.format(i):
            print 'wrong zone file: {}'.format(listing[i])
            return False

        if listing[i]['iterator'] != i+1:
            print 'wrong iterator: {}'.format(listing[i])
            return False

    # list all subdomains after the last one
    res = requests.get('http://localhost:3000/list/{}'.format(len(wallets)+1))
    if res.status_code != 200:
        print 'bad status code on list: {}'.format(res.status_code)
        return False

    listing = res.json()
    if len(listing) > 0:
        print 'got back more records'
        print listing
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
