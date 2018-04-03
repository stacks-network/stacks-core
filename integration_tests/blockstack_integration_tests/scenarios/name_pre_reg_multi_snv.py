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
import json

log = virtualchain.get_logger('name_pre_reg_multi_snv')

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet( "5K5hDuynZ6EQrZ4efrchCwy6DLhdsEzuJtTDAf3hqdsCKbxfoeD", 100000000000 ),
    testlib.Wallet( "5J39aXEeHh9LwfQ4Gy5Vieo7sbqiUMBXkPH7SaMHixJhSSBpAqz", 100000000000 ),
    testlib.Wallet( "5K9LmMQskQ9jP1p7dyieLDAeB6vsAj4GK8dmGNJAXS1qHDqnWhP", 100000000000 ),
    testlib.Wallet( "5KcNen67ERBuvz2f649t9F2o1ddTjC5pVUEqcMtbxNgHqgxG2gZ", 100000000000 ),
    testlib.Wallet( "5Jyq6RH7H42aPasyrvobvLvZGPDGYrq9m2Gq5qPEkAwDD7fqNHu", 100000000000 ),
    testlib.Wallet( "5KBc5xk9Rk3qmYg1PXPzsJ1kPfJkvzShK5ZGEn3q4Gzw4JWqMuy", 100000000000 ),
    testlib.Wallet( "5K6Nou64uUXg8YzuiVuRQswuGRfH1tdb9GUC9NBEV1xmKxWMJ54", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

snv_block_id_foo = None
snv_txid_bar = None
snv_txid_baz = None
snv_serial_number_bar = None
snv_serial_number_baz = None
last_consensus = None

def scenario( wallets, **kw ):

    global snv_block_id_foo, snv_serial_number_bar, snv_serial_number_baz, last_consensus, snv_txid_bar, snv_txid_baz

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

    snv_block_id_foo = testlib.get_current_block()

    testlib.next_block( **kw )
    testlib.next_block( **kw )
    testlib.next_block( **kw )
    testlib.next_block( **kw )
    testlib.next_block( **kw )

    bar_preorder = testlib.blockstack_name_preorder( "bar.test", wallets[4].privkey, wallets[5].addr )
    testlib.next_block( **kw )
    
    snv_serial_number_bar = "%s-%s" % (testlib.get_current_block(), 1 )
    snv_txid_bar = bar_preorder['transaction_hash']

    testlib.blockstack_name_register( "bar.test", wallets[4].privkey, wallets[5].addr )
    testlib.next_block( **kw )

    testlib.next_block( **kw )
    testlib.next_block( **kw )
    testlib.next_block( **kw )
    testlib.next_block( **kw )
    testlib.next_block( **kw )

    baz_preorder = testlib.blockstack_name_preorder( "baz.test", wallets[6].privkey, wallets[7].addr )
    testlib.next_block( **kw )
    
    snv_serial_number_baz = "%s-%s" % (testlib.get_current_block(), 1 )
    snv_txid_baz = baz_preorder['transaction_hash']

    testlib.blockstack_name_register( "baz.test", wallets[6].privkey, wallets[7].addr )
    testlib.next_block( **kw )

    last_consensus = testlib.get_consensus_at( testlib.get_current_block() )
    

def check( state_engine ):

    global snv_block_id_foo
    global snv_serial_number_bar
    global snv_serial_number_baz
    global snv_txid_bar
    global snv_txid_baz
    global last_consensus

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
    
    # registered 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        return False 

    # owned by
    if name_rec['address'] != wallets[3].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[3].addr):
        return False 

    # not preordered
    preorder = state_engine.get_name_preorder( "bar.test", virtualchain.make_payment_script(wallets[4].addr), wallets[5].addr )
    if preorder is not None:
        return False
    
    # registered 
    name_rec = state_engine.get_name( "bar.test" )
    if name_rec is None:
        return False 

    # owned by
    if name_rec['address'] != wallets[5].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[5].addr):
        return False 

    # not preordered
    preorder = state_engine.get_name_preorder( "baz.test", virtualchain.make_payment_script(wallets[6].addr), wallets[7].addr )
    if preorder is not None:
        return False
    
    # registered 
    name_rec = state_engine.get_name( "baz.test" )
    if name_rec is None:
        return False 

    # owned by
    if name_rec['address'] != wallets[7].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[7].addr):
        return False 

    # snv lookup works
    log.debug("use last consensus %s to verify foo.test at %s" % (last_consensus, snv_block_id_foo))
    snv_rec = blockstack.lib.snv.snv_lookup( "foo.test", snv_block_id_foo, last_consensus) 
    if 'error' in snv_rec:
        print json.dumps(snv_rec, indent=4 )
        return False

    # can use bar.test's serial number to verify foo.test
    log.debug("use bar.test's serial number %s to verify foo.test at %s" % (snv_serial_number_bar, snv_block_id_foo))
    snv_rec_bar = blockstack.lib.snv.snv_lookup( "foo.test", snv_block_id_foo, snv_serial_number_bar)
    if 'error' in snv_rec_bar:
        print json.dumps(snv_rec_bar, indent=4 )
        return False 

    # can use baz.test's serial number to verify foo.test 
    log.debug("use baz.test's serial number %s to verify foo.test at %s" % (snv_serial_number_baz, snv_block_id_foo))
    snv_rec_baz = blockstack.lib.snv.snv_lookup( "foo.test", snv_block_id_foo, snv_serial_number_baz)
    if 'error' in snv_rec_baz:
        print json.dumps( snv_rec_baz, indent=4 )
        return False 

    # can use bar.test's preorder txid to verify foo.test
    log.debug("use bar.test's preorder txid %s to verify foo.test at %s" % (snv_txid_bar, snv_block_id_foo))
    snv_rec_bar_tx = blockstack.lib.snv.snv_lookup( "foo.test", snv_block_id_foo, snv_txid_bar)
    if 'error' in snv_rec_bar_tx:
        print json.dumps( snv_rec_bar_tx, indent=4 )
        return False 

    # can use baz.test's preorder txid to verify foo.test 
    log.debug("use baz.test's preorder txid %s to verify foo.test at %s" % (snv_txid_baz, snv_block_id_foo))
    snv_rec_baz_tx = blockstack.lib.snv.snv_lookup( "foo.test", snv_block_id_foo, snv_txid_baz)
    if 'error' in snv_rec_baz_tx:
        print json.dumps( snv_rec_baz_tx, indent=4 )
        return False 

    # we have to have gotten the same record back in all cases
    for name, s1, s2 in [("snv_rec to snv_rec_bar", snv_rec, snv_rec_bar), \
                         ("snv_rec to snv_rec_baz", snv_rec, snv_rec_baz), \
                         ("snv_rec to snv_rec_bar_tx", snv_rec, snv_rec_bar_tx), \
                         ("snv_rec to snv_rec_baz_tx", snv_rec, snv_rec_baz_tx)]:
        if s1 != s2:
            print "--------"
            print name 
            print json.dumps(s1, indent=4 )
            print ""
            print json.dumps(s2, indent=4 )
            print ""
            print "Not equal"
            return False

    print snv_rec 
    return True
