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
import blockstack_client
from subprocess import Popen

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 5500 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 5500 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

TRANSACTION_BROADCAST_LOCATION = os.environ.get('BSK_TRANSACTION_BROADCAST_LOCATION',
                                                '/src/transaction-broadcaster')

SUBDOMAIN_REGISTRAR_LOCATION = os.environ.get('BSK_SUBDOMAIN_REGISTRAR_LOCATION',
                                              '/src/subdomain-registrar')

def start_transaction_broadcaster():
    try:
        os.rename('/tmp/transaction_broadcaster.db', '/tmp/transaction_broadcaster.db.last')
    except OSError:
        pass
    env = {'BSK_TRANSACTION_BROADCAST_DEVELOP' : '1'}
    if os.environ.get('BLOCKSTACK_TEST_CLIENT_RPC_PORT', False):
        env['BLOCKSTACK_TEST_CLIENT_RPC_PORT'] = os.environ.get('BLOCKSTACK_TEST_CLIENT_RPC_PORT')
    Popen(['node', TRANSACTION_BROADCAST_LOCATION + '/lib/index.js'],
          env = env)

def start_subdomain_registrar():
    try:
        os.rename('/tmp/subdomain_registrar.db', '/tmp/subdomain_registrar.last')
    except OSError:
        pass
    env = {'BSK_SUBDOMAIN_REGTEST' : '1'}
    if os.environ.get('BLOCKSTACK_TEST_CLIENT_RPC_PORT', False):
        env['BLOCKSTACK_TEST_CLIENT_RPC_PORT'] = os.environ.get('BLOCKSTACK_TEST_CLIENT_RPC_PORT')
    Popen(['node', SUBDOMAIN_REGISTRAR_LOCATION + '/lib/index.js'], env = env)

def scenario( wallets, **kw ):

    start_transaction_broadcaster()
    start_subdomain_registrar()

    testlib.blockstack_namespace_preorder( "id", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "id", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "id", wallets[1].privkey )
    testlib.next_block( **kw )

    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[2].privkey, wallets[3].privkey, wallets[4].privkey )
    resp = testlib.blockstack_cli_register( "foo.id", "0123456789abcdef" )
    if 'error' in resp:
        print >> sys.stderr, json.dumps(resp, indent=4, sort_keys=True)
        return False

    # wait for the preorder to get confirmed
    for i in xrange(0, 12):
        testlib.next_block( **kw )

    # wait for the poller to pick it up
    print >> sys.stderr, "Waiting 10 seconds for the backend to submit the register"
    time.sleep(10)

    # wait for the register to get confirmed
    for i in xrange(0, 12):
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting 10 seconds for the backend to acknowledge registration"
    time.sleep(10)

    # wait for update to get confirmed
    for i in xrange(0, 12):
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting 10 seconds for the backend to acknowledge update"
    time.sleep(10)


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
