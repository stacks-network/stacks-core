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
import os
import sys
import virtualchain

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
working_dir = None

def scenario( wallets, **kw ):

    global working_dir 
    testlib.blockstore_namespace_preorder( "id", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstore_namespace_reveal( "id", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstore_namespace_ready( "id", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstore_name_preorder( "judecn.id", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    testlib.blockstore_name_register( "judecn.id", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    resp = testlib.blockstore_announce( "hello world!", wallets[3].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstore_announce( "This should not appear", wallets[4].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # save...
    working_dir = testlib.get_working_dir( **kw )


def check( state_engine ):

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "id" )
    if ns is not None:
        return False 

    ns = state_engine.get_namespace( "id" )
    if ns is None:
        return False 

    if ns['namespace_id'] != 'id':
        return False 

    # not preordered
    preorder = state_engine.get_name_preorder( "judecn.id", pybitcoin.make_pay_to_address_script(wallets[2].addr), wallets[3].addr )
    if preorder is not None:
        return False
    
    # registered 
    name_rec = state_engine.get_name( "judecn.id" )
    if name_rec is None:
        return False 

    # owned by
    if name_rec['address'] != wallets[3].addr or name_rec['sender'] != pybitcoin.make_pay_to_address_script(wallets[3].addr):
        return False 

    # announcements exist...
    if not os.path.exists( working_dir ):
        print >> sys.stderr, "No such directory %s" % working_dir
        return False

    # "hello world!" exists...
    announce_path = os.path.join(working_dir, "announcements", "13a76219ed16c5e53e2c08dde8660609bb8f63da.txt") 
    hashes_path = os.path.join( working_dir, virtualchain.get_implementation().get_virtual_chain_name() + ".announce" )

    if not os.path.exists( announce_path ):
        print >> sys.stderr, "No announcement text"
        return False 

    if not os.path.exists( hashes_path ):
        print >> sys.stderr, "No announcement hash text"
        return False 

    # announcement contains "hello world!"
    txt = None 
    with open( announce_path, "r" ) as f:
        txt = f.read()

    txt = txt.strip()
    if txt != "hello world!":
        print >> sys.stderr, "Wrong announcement text"
        return False 

    # announcement list includes the hash 
    announce_hashes = None 
    with open( hashes_path, "r" ) as f:
        txt = f.read()

    txt = txt.strip()
    if txt != "13a76219ed16c5e53e2c08dde8660609bb8f63da":
        print >> sys.stderr, "Wring announcement hash text"
        return False 

    return True
