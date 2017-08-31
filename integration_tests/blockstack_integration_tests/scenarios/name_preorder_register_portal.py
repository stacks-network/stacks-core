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

# useful for simulating the blockchain for Portal
# the user "foo.id" will be registered

import testlib
import pybitcoin
import blockstack_client

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    # save the wallet 
    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )
    wallet_keys = blockstack_client.make_wallet_keys( owner_privkey=wallets[3].privkey, data_privkey=wallets[4].privkey, payment_privkey=wallets[2].privkey )
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] )

    testlib.blockstack_namespace_preorder( "id", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "id", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "id", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_name_preorder( "demo.id", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    testlib.blockstack_name_register( "demo.id", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )
 
    # migrate profiles 
    res = testlib.migrate_profile( "demo.id", proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in res:
        res['test'] = 'Failed to initialize demo.id profile'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 
    
    res = testlib.start_api("0123456789abcdef")
    if 'error' in res:
        print 'failed to start API: {}'.format(res)
        return False


    
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

    # not preordered
    preorder = state_engine.get_name_preorder( "demo.id", pybitcoin.make_pay_to_address_script(wallets[2].addr), wallets[3].addr )
    if preorder is not None:
        print "preorder exists"
        return False
    
    # registered 
    name_rec = state_engine.get_name( "demo.id" )
    if name_rec is None:
        print "name does not exist"
        return False 

    # owned by
    if name_rec['address'] != wallets[3].addr or name_rec['sender'] != pybitcoin.make_pay_to_address_script(wallets[3].addr):
        print "sender is wrong"
        return False 

    return True
