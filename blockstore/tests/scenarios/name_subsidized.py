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
import shutil
import tempfile
import os

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet( "5KcNen67ERBuvz2f649t9F2o1ddTjC5pVUEqcMtbxNgHqgxG2gZ", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

debug = True

def send_subsidized( client_privkey, resp, **kw ):

    unsigned_tx = resp['subsidized_tx']

    if client_privkey is not None:
        # sign all unsigned inputs 
        tx = testlib.tx_sign_all_unsigned_inputs( unsigned_tx, client_privkey )
    else:
        # already subsidized
        tx = unsigned_tx

    testlib.broadcast_transaction( tx )


def scenario( wallets, **kw ):

    subsidy_wallet = wallets[5]
    
    print json.dumps( testlib.getrawtransaction( "28f78fbae22d2273341af231a2ac049d74958e1e6ce6ae622cd48d8f0fef591e", 1 ), indent=4 )

    resp = testlib.blockstore_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstore_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstore_namespace_ready( "test", wallets[1].privkey )
    if debug or  'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # subsidized transactions...
    resp = testlib.blockstore_name_preorder( "foo.test", None, wallets[3].addr, subsidy_key=subsidy_wallet.privkey )
    if debug or  'error' in resp:
        print json.dumps( resp, indent=4 )
  
    # (already subsidized...)
    send_subsidized( None, resp, **kw )
    testlib.next_block( **kw )

    resp = testlib.blockstore_name_register( "foo.test", None, wallets[3].addr, subsidy_key=subsidy_wallet.privkey )
    if debug or  'error' in resp:
        print json.dumps( resp, indent=4 )

    # (already subsidized...)
    send_subsidized( None, resp, **kw )
    testlib.next_block( **kw )

    resp = testlib.blockstore_name_update( "foo.test", "11" * 20, None, user_public_key=wallets[3].pubkey_hex, subsidy_key=subsidy_wallet.privkey )
    if debug or  'error' in resp:
        print json.dumps( resp, indent=4 )

    send_subsidized( wallets[3].privkey, resp, **kw )
    testlib.next_block( **kw )

    resp = testlib.blockstore_name_transfer( "foo.test", wallets[4].addr, True, None, user_public_key=wallets[3].pubkey_hex, subsidy_key=subsidy_wallet.privkey ) 
    if debug or  'error' in resp:
        print json.dumps( resp, indent=4 )

    send_subsidized( wallets[3].privkey, resp, **kw )
    testlib.next_block( **kw )

    resp = testlib.blockstore_name_revoke( "foo.test", None, user_public_key=wallets[4].pubkey_hex, subsidy_key=subsidy_wallet.privkey )
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    send_subsidized( wallets[4].privkey, resp, **kw )
    
    # advance a bit 
    for i in xrange(0, 5):
        testlib.next_block( **kw )


def check( state_engine ):

    global wallets

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

    # updated, but revoked, so data should be None
    if name_rec['value_hash'] is not None:
        return False 

    # transferred 
    if name_rec['address'] != wallets[4].addr or name_rec['sender'] != pybitcoin.make_pay_to_address_script(wallets[4].addr):
        return False 

    # previously owned by...
    name_rec_prev = state_engine.get_name_at( "foo.test", sorted( name_rec['history'].keys() )[-1] - 2 )[0]
    if name_rec_prev['address'] != wallets[3].addr or name_rec_prev['sender'] != pybitcoin.make_pay_to_address_script(wallets[3].addr):
        return False

    # revoked 
    if not name_rec['revoked']:
        return False 

    # verify that the user wallets (3 and 4) were *not* debited any btc
    rc = True
    for wallet in [wallets[3], wallets[4]]:
        unspents = testlib.get_unspents( wallet.addr )
        value = sum( [us['value'] for us in unspents] )
        if value < 100000000000:
            print "value of '%s' is '%s'" % (wallet.addr, value)
            rc = False

    return rc
