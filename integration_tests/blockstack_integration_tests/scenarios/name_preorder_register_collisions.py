#!/usr/bin/env python
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
import pybitcoin
import json
import shutil
import tempfile
import os
import sys

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

debug = True

def scenario( wallets, **kw ):

    resp = testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey, safety_checks=False )
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # should get rejected
    resp = testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, safety_checks=False )
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    # should get rejected (NOTE: the underlying mock utxo provider doesn't handle double-spends!)
    resp = testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, safety_checks=False )
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # should get accepted
    resp = testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, safety_checks=False )
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    # should get rejected (but only because the namespace isn't revealed until the block goes through)
    resp = testlib.blockstack_namespace_ready( "test", wallets[1].privkey, safety_checks=False )
    if debug or  'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstack_namespace_ready( "test", wallets[1].privkey, safety_checks=False )
    if debug or  'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr, safety_checks=False )
    if debug or  'error' in resp:
        print json.dumps( resp, indent=4 )
   
    testlib.next_block( **kw )

    # should get rejected
    resp = testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr, safety_checks=False )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    # should get rejected (NOTE: the underlying mock utxo provider doesn't handle double-spends!)
    resp = testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr, safety_checks=False )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    # don't SNV-check these 
    testlib.expect_snv_fail_at( "foo.test", testlib.get_current_block( **kw )+1 )
    testlib.next_block( **kw )
    
    # should succeed
    resp = testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr, safety_checks=False )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # (this should succeed)
    resp = testlib.blockstack_name_update( "foo.test", "11" * 20, wallets[3].privkey, safety_checks=False )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    # (this should also succeed)
    resp = testlib.blockstack_name_transfer( "foo.test", wallets[4].addr, True, wallets[3].privkey, safety_checks=False )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # (this should succeed)
    resp = testlib.blockstack_name_renew( "foo.test", wallets[4].privkey, safety_checks=False )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    # (this should also succeed)
    resp = testlib.blockstack_name_update( "foo.test", "22" * 20, wallets[4].privkey, safety_checks=False )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    # (this should succeed)
    resp = testlib.blockstack_name_transfer( "foo.test", wallets[3].addr, True, wallets[4].privkey, safety_checks=False )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )
   
    # lots of updates 
    for i in xrange(0, 9):
        resp = testlib.blockstack_name_update( "foo.test", ("%s%s" % (i,i)) * 20, wallets[3].privkey, safety_checks=False )
        if 'error' in resp:
            print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # transfer loop
    for i in xrange(0, 5):

        #resp = testlib.blockstack_name_transfer( "foo.test", wallets[3].addr, True, wallets[4].privkey )
        resp = testlib.blockstack_name_transfer( "foo.test", wallets[4].addr, True, wallets[3].privkey, safety_checks=False )
        if 'error' in resp:
            print json.dumps( resp, indent=4 )

        resp = testlib.blockstack_name_transfer( "foo.test", wallets[3].addr, True, wallets[4].privkey, safety_checks=False )
        if 'error' in resp:
            print json.dumps( resp, indent=4 )

    
    testlib.next_block( **kw )

    # update/transfer/update/transfer
    for i in xrange(0, 5):

        resp = testlib.blockstack_name_transfer("foo.test", wallets[4].addr, True, wallets[3].privkey, safety_checks=False )
        if 'error' in resp:
            print json.dumps( resp, indent=4 )

        resp = testlib.blockstack_name_update("foo.test", "aa" * 20, wallets[4].privkey, safety_checks=False )
        if 'error' in resp:
            print json.dumps( resp, indent=4 )

        resp = testlib.blockstack_name_transfer("foo.test", wallets[3].addr, True, wallets[4].privkey, safety_checks=False )
        if 'error' in resp:
            print json.dumps( resp, indent=4 )

        resp = testlib.blockstack_name_update("foo.test", "bb" * 20, wallets[3].privkey, safety_checks=False )
        if 'error' in resp:
            print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # warn the serialization checker that this changes behavior from 0.13
    print "BLOCKSTACK_SERIALIZATION_CHANGE_BEHAVIOR"
    sys.stdout.flush()
    


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

    # not preordered
    preorder = state_engine.get_name_preorder( "foo.test", pybitcoin.make_pay_to_address_script(wallets[2].addr), wallets[3].addr )
    if preorder is not None:
        print "preordered: %s" % preorder
        return False
    
    # registered 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        print "name is None"
        return False 

    # updated
    if name_rec['value_hash'] != "bb" * 20:
        print "value hash is '%s'" % name_rec['value_hash']
        return False 

    # transferred 
    if name_rec['address'] != wallets[3].addr or name_rec['sender'] != pybitcoin.make_pay_to_address_script(wallets[3].addr):
        print "owned by %s; expected %s" % (name_rec['address'], wallets[3].addr)
        return False 

    return True
