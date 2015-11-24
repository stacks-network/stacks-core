#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstore

    Blockstore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore. If not, see <http://www.gnu.org/licenses/>.
""" 

import testlib
import pybitcoin
import json

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

# map update hash to transaction
txids = {}

# map update hash to consensus hash 
consensuses = {}

def scenario( wallets, **kw ):

    global txids
    global consensuses

    testlib.blockstore_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstore_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstore_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstore_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )
    
    testlib.blockstore_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    testlib.next_block( **kw )
    # do a sequence of updates, every other block
    for i in xrange( 0, 20 ):

        if (i % 2) != 0:
            update_hash = ("%02x" % (i)) * 20
            resp = testlib.blockstore_name_update( "foo.test", update_hash, wallets[3].privkey )

            txids[ update_hash ] = resp['transaction_hash']
            consensuses[ update_hash ] = testlib.get_consensus_at( testlib.get_current_block( **kw ), **kw )

        testlib.next_block( **kw )

    testlib.next_block( **kw )


def check( state_engine ):

    global txids 
    global consensus 
    global consensuses

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is not None:
        return False 

    ns = state_engine.get_namespace( "test" )
    if ns is None:
        return False 

    if ns['namespace_id'] != 'test':
        return False 

    # not preordered
    preorder = state_engine.get_name_preorder( "foo.test", pybitcoin.make_pay_to_address_script(wallets[2].addr), wallets[3].addr )
    if preorder is not None:
        return False
    
    # registered 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        return False 

    # updated (latest version: update hash pattern is 0x13)
    if name_rec['value_hash'] != '13' * 20:
        return False 

    # name didn't exist before its preorder
    before_registration = state_engine.get_name_at( "foo.test", name_rec['first_registered'] - 2 )
    if before_registration is not None:
        print "before registration"
        print json.dumps( before_registration, indent=4 )
        return False 

    # name was preordered just prior to its registration 
    preorder = state_engine.get_name_at( "foo.test", name_rec['block_number'] )[0]
    if preorder is None:
        print "no preorder"
        return False

    if not preorder.has_key('opcode') or preorder['opcode'] != 'NAME_PREORDER':
        print "not a preorder"
        print json.dumps( preorder, indent=4 )
        print "history"
        print json.dumps( state_engine.get_name_history( "foo.test", name_rec['block_number'], state_engine.get_current_block() ), indent=4 )
        return False

    # name existed at the first point of its registration
    at_registration = state_engine.get_name_at( "foo.test", name_rec['first_registered'] )[0]
    if at_registration is None:
        print "at_registration is None"
        return False 

    # name had null update hash then 
    if at_registration['value_hash'] is not None:
        print "at_registration"
        print json.dumps( at_registration, indent=4 )
        return False

    # get history...
    name_history = state_engine.get_name_history( "foo.test", name_rec['first_registered'], state_engine.get_current_block()+1 )

    # did 10 updates, 1 register
    if len(name_history) != 11:
        print "history (%s)" % len(name_history)
        print json.dumps(name_history, indent=4 )
        return False 

    for i in xrange(0, 10):
        snapshot = name_history[i+1]
        expected_value_hash = ("%02x" % (2*i + 1)) * 20

        if snapshot['value_hash'] != expected_value_hash:
            print "Invalid value hash '%s'" % expected_value_hash
            print json.dumps( name_history, indent=4 )
            return False 

        if snapshot['txid'] != txids[expected_value_hash]:
            print "Invalid txid '%s'" % snapshot['txid']
            print json.dumps( name_history, indent=4 )
            return False 

    return True
