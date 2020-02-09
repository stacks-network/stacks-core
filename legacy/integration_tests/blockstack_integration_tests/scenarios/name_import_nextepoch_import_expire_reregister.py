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
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 701
"""

import testlib
import virtualchain
import json
import shutil
import tempfile
import os
import blockstack

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet( "5K5hDuynZ6EQrZ4efrchCwy6DLhdsEzuJtTDAf3hqdsCKbxfoeD", 100000000000 ),
    testlib.Wallet( "5J39aXEeHh9LwfQ4Gy5Vieo7sbqiUMBXkPH7SaMHixJhSSBpAqz", 100000000000 ),
    testlib.Wallet( "5K9LmMQskQ9jP1p7dyieLDAeB6vsAj4GK8dmGNJAXS1qHDqnWhP", 100000000000 ),
    testlib.Wallet( "5KcNen67ERBuvz2f649t9F2o1ddTjC5pVUEqcMtbxNgHqgxG2gZ", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

debug = True
import_block_1 = None
import_block_2 = None

def scenario( wallets, **kw ):

    global import_block_1, import_block_2

    # make a test namespace
    resp = testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 5, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstack_name_import( "foo.test", wallets[3].addr, "11" * 20, wallets[1].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    # for funsies, pass the namespace lifetime
    for i in xrange(0, 10):
        testlib.next_block( **kw )

    # 269--next epoch
    import_block_1 = testlib.get_current_block( **kw )

    testlib.next_block( **kw )

    resp = testlib.blockstack_name_import( "foo.test", wallets[4].addr, "22" * 20, wallets[1].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )
    
    import_block_2 = testlib.get_current_block( **kw )

    testlib.next_block( **kw )

    resp = testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # name should definitely not be expired 
    res = testlib.blockstack_cli_whois('foo.test')
    if 'error' in res:
        print "name is expired unexpectedly"
        print json.dumps(res, indent=4, sort_keys=True)
        return False

    # wait for expiration (with multipler)...
    for i in xrange(0, 5 * blockstack.config.get_epoch_namespace_lifetime_multiplier( testlib.get_current_block(**kw), "test" ) ):
        testlib.next_block( **kw )

    # name should definitely be expired 
    res = testlib.blockstack_cli_whois('foo.test')
    if 'error' not in res:
        print json.dumps(res, indent=4, sort_keys=True)
        return False

    # re-register (should work)
    testlib.blockstack_name_preorder( "foo.test", wallets[7].privkey, wallets[8].addr )
    testlib.next_block( **kw )

    testlib.blockstack_name_register( "foo.test", wallets[7].privkey, wallets[8].addr )
    testlib.next_block( **kw )


def check( state_engine ):

    original_price = 6400000
    curr_price = original_price * blockstack.lib.config.get_epoch_price_multiplier( 260, "test", 'BTC' )

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
    for i in xrange(0, len(wallets)):
        preorder = state_engine.get_name_preorder( "foo.test", virtualchain.make_payment_script(wallets[i].addr), wallets[(i+1)%5].addr )
        if preorder is not None:
            print "preordered"
            return False

    # registered 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        print "no name"
        return False 

    # owned by
    if name_rec['address'] != wallets[8].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[8].addr):
        print "sender is wrong"
        return False

    # has new sender pubkey (from the payment key)
    if name_rec['sender_pubkey'] != wallets[7].pubkey_hex:
        print "wrong pubkey: %s != %s" % (name_rec['sender_pubkey'], wallets[7].pubkey_hex)
        return False

    # epoch 2 fee paid 
    if abs(name_rec['op_fee'] - curr_price) >= 10e-8:
        print "wrong fee: %s != %s" % (name_rec['op_fee'], curr_price)
        return False

    # verify historic owner and value hash and fee
    historic_name_rec = state_engine.get_name_at( "foo.test", import_block_1, include_expired=True )
    if historic_name_rec is None or len(historic_name_rec) == 0:
        print "no name at %s" % import_block_1
        return False
    
    historic_name_rec = historic_name_rec[0]
    if not historic_name_rec.has_key('value_hash') or historic_name_rec['value_hash'] != '11' * 20:
        print "wrong historic name import value hash: %s" % historic_name_rec.get("value_hash", "(null)")
        return False

    if historic_name_rec['address'] != wallets[3].addr or historic_name_rec['sender'] != virtualchain.make_payment_script(wallets[3].addr):
        print "historic sender is wrong"
        return False

    # epoch 1 fee 
    if abs(historic_name_rec['op_fee'] - original_price) >= 10e-8:
        print "wrong historic fee at epoch 1: %s != %s" % (historic_name_rec['op_fee'], original_price)
        return False

    # verify historic owner and value hash at the beginning of epoch 2
    historic_name_rec = state_engine.get_name_at( "foo.test", import_block_2, include_expired=True )
    if historic_name_rec is None or len(historic_name_rec) == 0:
        print "no name at %s" % import_block_2
        return False

    historic_name_rec = historic_name_rec[0]
    if not historic_name_rec.has_key('value_hash') or historic_name_rec['value_hash'] != '22' * 20:
        print "wrong historic name import value hash: %s" % historic_name_rec.get("value_hash", "(null)")
        return False

    if historic_name_rec['address'] != wallets[4].addr or historic_name_rec['sender'] != virtualchain.make_payment_script(wallets[4].addr):
        print "historic sender is wrong"
        return False

    # epoch 2 fee
    if abs(historic_name_rec['op_fee'] - curr_price) >= 10e-8:
        print "wrong historic fee at epoch 2: %s != %s" % (historic_name_rec['op_fee'], curr_price)
        return False

    return True
