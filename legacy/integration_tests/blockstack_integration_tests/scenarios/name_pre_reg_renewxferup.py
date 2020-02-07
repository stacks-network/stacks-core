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

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    resp = testlib.blockstack_name_renew( "foo.test", wallets[3].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )
        return False

    testlib.next_block( **kw )

    # whois
    res = testlib.blockstack_cli_whois('foo.test')
    if 'error' in res:
        print res
        return False

    if res.has_key('zonefile_hash') and res['zonefile_hash']:
        print 'have a new zone file???'
        print res
        return False

    if res['owner_address'] != wallets[3].addr:
        print 'wrong owner address'
        print res
        return False
    
    ''' no longer supported in the node.js CLI 

    resp = testlib.blockstack_name_renew( "foo.test", wallets[3].privkey, zonefile_hash='11' * 20 )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )
        return False

    testlib.next_block( **kw )

    # whois
    res = testlib.blockstack_cli_whois('foo.test')
    if 'error' in res:
        print res
        return False

    if not res.has_key('zonefile_hash') or res['zonefile_hash'] != '11' * 20:
        print 'wrong zone file hash'
        print res
        return False

    if res['owner_address'] != wallets[3].addr:
        print res
        return False
    '''
    # update/transfer

    resp = testlib.blockstack_name_renew( "foo.test", wallets[3].privkey, zonefile_hash='22' * 20, recipient_addr=wallets[0].addr )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # whois
    res = testlib.blockstack_cli_whois('foo.test')
    if 'error' in res:
        print res
        return False

    if not res.has_key('zonefile_hash') or res['zonefile_hash'] != '22' * 20:
        print res
        return False

    if res['owner_address'] != wallets[0].addr:
        print res
        return False

    # transfer 
    resp = testlib.blockstack_name_renew( "foo.test", wallets[0].privkey, recipient_addr=wallets[1].addr )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # whois
    res = testlib.blockstack_cli_whois('foo.test')
    if 'error' in res:
        print res
        return False

    if not res.has_key('zonefile_hash') or res['zonefile_hash'] != '22' * 20:
        print res
        return False

    if res['owner_address'] != wallets[1].addr:
        print res
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

    # not preordered
    preorder = state_engine.get_name_preorder( "foo.test", virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr )
    if preorder is not None:
        return False
 
    # not preordered
    preorder = state_engine.get_name_preorder( "foo.test", virtualchain.make_payment_script(wallets[3].addr), wallets[0].addr )
    if preorder is not None:
        return False

    # not preordered
    preorder = state_engine.get_name_preorder( "foo.test", virtualchain.make_payment_script(wallets[0].addr), wallets[1].addr )
    if preorder is not None:
        return False
   
    # registered 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        return False

    # owned by
    if name_rec['address'] != wallets[1].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[1].addr):
        return False

    # renewed (3 blocks difference)
    if name_rec['last_renewed'] - 3 != name_rec['first_registered']:
        print name_rec['last_renewed']
        print name_rec['first_registered']
        return False

    return True
