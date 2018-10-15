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

import testlib
import virtualchain
import blockstack
import random

# activate tokens
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 682
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 683
TEST ENV BLOCKSTACK_EPOCH_3_END_BLOCK 684
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 1
"""

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def check_inv(expected_inv):
    # lower
    inv = blockstack.lib.client.get_zonefile_inventory('http://localhost:16264', 0, 1)
    if len(inv['inv']) != 1:
        print '0-1 wrong inv length: {} (expected {})'.format(list(inv['inv']), list(expected_inv[0]))
        return False

    if inv['inv'][0] != expected_inv[0]:
        print '0-1 wrong inv: {} (expected {})'.format(list(inv['inv']), list(expected_inv[0]))
        return False

    # middle
    inv = blockstack.lib.client.get_zonefile_inventory('http://localhost:16264', 1, 1)
    if len(inv['inv']) != 1:
        print '1-2 wrong inv length: {} (expected {})'.format(list(inv['inv']), list(expected_inv[1]))
        return False

    if inv['inv'][0] != expected_inv[1]:
        print '1-2 wrong inv: {} (expected {})'.format(list(inv['inv']), list(expected_inv[1]))
        return False

    # middle
    inv = blockstack.lib.client.get_zonefile_inventory('http://localhost:16264', 2, 1)
    if len(inv['inv']) != 1:
        print '2-3 wrong inv length: {} (expected {})'.format(list(inv['inv']), list(expected_inv[2]))
        return False

    if inv['inv'][0] != expected_inv[2]:
        print '2-3 wrong inv: {} (expected {})'.format(list(inv['inv']), list(expected_inv[2]))
        return False

    # high
    inv = blockstack.lib.client.get_zonefile_inventory('http://localhost:16264', 3, 1000)
    if len(inv['inv']) != 1:
        print '3-4 wrong inv length: {} (expected {})'.format(list(inv['inv']), list(expected_inv[3]))
        return False

    if inv['inv'][0] != expected_inv[3]:
        print '3-4 wrong inv: {} (expected {})'.format(list(inv['inv']), list(expected_inv[3]))
        return False

    # 2-range
    inv = blockstack.lib.client.get_zonefile_inventory('http://localhost:16264', 0, 2)
    if len(inv['inv']) != 2:
        print '0-2 wrong inv length: {} (expected {})'.format(list(inv['inv']), list(expected_inv[0:2]))
        return False

    if inv['inv'] != expected_inv[0:2]:
        print '0-2 wrong inv: {} (expected {})'.format(list(inv['inv']), list(expected_inv[0:2]))
        return False

    # 2-range
    inv = blockstack.lib.client.get_zonefile_inventory('http://localhost:16264', 1, 2)
    if len(inv['inv']) != 2:
        print '1-3 wrong inv length: {} (expected {})'.format(list(inv['inv']), list(expected_inv[1:3]))
        return False

    if inv['inv'] != expected_inv[1:3]:
        print '1-3 wrong inv: {} (expected {})'.format(list(inv['inv']), list(expected_inv[1:3]))
        return False

    # 2-range
    inv = blockstack.lib.client.get_zonefile_inventory('http://localhost:16264', 2, 100)
    if len(inv['inv']) != 2:
        print '2-4 wrong inv length: {} (expected {})'.format(list(inv['inv']), list(expected_inv[2:4]))
        return False

    if inv['inv'] != expected_inv[2:4]:
        print '2-4 wrong inv: {} (expected {})'.format(list(inv['inv']), list(expected_inv[2:4]))
        return False

    # 3-range
    inv = blockstack.lib.client.get_zonefile_inventory('http://localhost:16264', 0, 3)
    if len(inv['inv']) != 3:
        print '0-3 wrong inv length: {} (expected {})'.format(list(inv['inv']), list(expected_inv[0:3]))
        return False

    if inv['inv'] != expected_inv[0:3]:
        print '0-3 wrong inv: {} (expected {})'.format(list(inv['inv']), list(expected_inv[0:3]))
        return False

    # 3-range
    inv = blockstack.lib.client.get_zonefile_inventory('http://localhost:16264', 1, 100)
    if len(inv['inv']) != 3:
        print '1-4 wrong inv length: {} (expected {})'.format(list(inv['inv']), list(expected_inv[1:4]))
        return False

    if inv['inv'] != expected_inv[1:4]:
        print '1-4 wrong inv: {} (expected {})'.format(list(inv['inv']), list(expected_inv[1:4]))
        return False

    # complete area
    inv = blockstack.lib.client.get_zonefile_inventory('http://localhost:16264', 0, 100)
    if len(inv['inv']) != 4:
        print '0-4 wrong inv length: {} (expected {})'.format(list(inv['inv']), list(expected_inv[0:4]))
        return False

    if inv['inv'] != expected_inv:
        print '0-4 wrong inv: {} (expected {})'.format(inv['inv'], expected_inv)
        return False

    return True


def scenario( wallets, **kw ):

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=blockstack.NAMESPACE_VERSION_PAY_WITH_STACKS )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    # generate 25 names
    
    for i in range(0, 25):
        testlib.blockstack_name_preorder( "foo_{}.test".format(i), wallets[2].privkey, wallets[3].addr )

    testlib.next_block( **kw )

    for i in range(0, 25):
        zonefile_txt = 'hello world {}'.format(i)
        zonefile_hash = blockstack.lib.storage.get_zonefile_data_hash(zonefile_txt)

        testlib.blockstack_name_register( "foo_{}.test".format(i), wallets[2].privkey, wallets[3].addr, zonefile_hash=zonefile_hash )

    testlib.next_block( **kw )

    expected_inv = '\x00\x00\x00\x00'
    assert check_inv(expected_inv)

    # release zone files according to a pattern 
    r = range(0, 25)
    random.shuffle(r)

    for i in r:
        zonefile_txt = 'hello world {}'.format(i)
        testlib.blockstack_put_zonefile(zonefile_txt)
        
        inv_list = [ord(x) for x in list(expected_inv)]
        inv_list[i / 8] |= 1 << (7 - (i % 8))
        expected_inv = ''.join([chr(x) for x in inv_list])

        assert check_inv(expected_inv)


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

    for i in range(0, 25):
        name = 'foo_{}.test'.format(i)

        # not preordered
        preorder = state_engine.get_name_preorder( name, virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr )
        if preorder is not None:
            print "preorder exists"
            return False
        
        # registered 
        name_rec = state_engine.get_name(name)
        if name_rec is None:
            print "name does not exist"
            return False 

        # owned by
        if name_rec['address'] != wallets[3].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[3].addr):
            print "sender is wrong"
            return False 

    return True
