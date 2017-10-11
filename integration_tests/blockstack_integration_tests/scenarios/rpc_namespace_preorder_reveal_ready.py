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
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 680
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 681
"""

import testlib
import virtualchain
import time
import json
import sys
import os
import blockstack_client

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 5500 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 5500 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):
    resp = testlib.blockstack_cli_namespace_preorder("test", wallets[0].privkey, wallets[1].privkey)
    if 'error' in resp:
        print json.dumps(resp, indent=4, sort_keys=True)
        return False

    testlib.next_block(**kw)

    resp = testlib.blockstack_cli_namespace_reveal('test', wallets[0].privkey, wallets[1].privkey, 52560, 4, 4, '6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0', 10, 10)
    if 'error' in resp:
        print json.dumps(resp, indent=4, sort_keys=True)
        return False

    testlib.next_block(**kw)

    resp = testlib.blockstack_cli_namespace_ready('test', wallets[1].privkey)
    if 'error' in resp:
        print json.dumps(resp, indent=4, sort_keys=True)
        return False

    testlib.next_block(**kw)


def check( state_engine ):

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is not None:
        print "namespace reveal exists"
        return False 

    ns = state_engine.get_namespace( "test" )
    if ns is None:
        print "no namespace"
        return False 

    if ns['namespace_id'] != 'test':
        print "wrong namespace"
        return False 
   
    return True
