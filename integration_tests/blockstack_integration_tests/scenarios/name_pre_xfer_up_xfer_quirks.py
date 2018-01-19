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
import json

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet( "5K9LmMQskQ9jP1p7dyieLDAeB6vsAj4GK8dmGNJAXS1qHDqnWhP", 100000000000 ),
    testlib.Wallet( "5KcNen67ERBuvz2f649t9F2o1ddTjC5pVUEqcMtbxNgHqgxG2gZ", 100000000000 )
]

debug = False
consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    global debug, consensus

    resp = testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    resp = testlib.blockstack_name_preorder( "bar.test", wallets[2].privkey, wallets[3].addr )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )
    
    resp = testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )
        return False

    resp = testlib.blockstack_name_register( "bar.test", wallets[2].privkey, wallets[3].addr )
    if 'error' in resp:
        print json.dumps( resp, indent=4 )
        return False

    testlib.next_block( **kw )

    # when transferring a name, the consensus hash saved to its history should be the one from the transaction.
    # however, the one saved to the name record should be the last consensus hash stored (i.e. None in this case)
    resp = testlib.blockstack_name_transfer( "foo.test", wallets[4].addr, True, wallets[3].privkey )
    if 'error' in resp:
        print resp
        return False
    
    testlib.next_block( **kw )

    db = testlib.get_state_engine()
    name_rec = db.get_name('foo.test')
    name_history = db.get_name_at('foo.test', testlib.get_current_block(**kw))

    if name_rec['consensus_hash'] is not None:
        print 'NAME_TRANSFER added a consensus hash: {}'.format(name_rec)
        return False

    if name_history[0]['consensus_hash'] != testlib.get_consensus_at(testlib.get_current_block(**kw)-1):
        print 'NAME_TRANSFER set wrong consensus hash (expected {}): {}'.format(
                testlib.get_consensus_at(testlib.get_current_block(**kw)-1),
                name_history[0]
        )
        return False

    # when transferring a name after any operation that sets the consensus hash (i.e. update), the previous operation's
    # consensus hash must be preserved for hashing.  However, the name history should receive the transfer's consensus hash.
    resp = testlib.blockstack_name_update('bar.test', '11' * 20, wallets[3].privkey)
    if 'error' in resp:
        print resp
        return False

    testlib.next_block(**kw)

    db = testlib.get_state_engine()
    name_rec = db.get_name('bar.test')
    bar_update_ch = name_rec['consensus_hash']
    assert bar_update_ch, 'No consensus hash set on update'

    resp = testlib.blockstack_name_transfer('bar.test', wallets[4].addr, True, wallets[3].privkey)
    if 'error' in resp:
        print resp
        return False

    testlib.next_block(**kw)

    db = testlib.get_state_engine()
    name_rec = db.get_name('bar.test')
    if name_rec['consensus_hash'] != bar_update_ch:
        print 'update consensus hash not preserved (expected {}): {}'.format(bar_update_ch, name_rec)
        return False

    # only a subsequent update ought to change the consensus hash 
    resp = testlib.blockstack_name_update('foo.test', '22' * 20, wallets[4].privkey)
    if 'error' in resp:
        print resp
        return False
    
    resp = testlib.blockstack_name_update('bar.test', '33' * 20, wallets[4].privkey)
    if 'error' in resp:
        print resp
        return False

    testlib.next_block(**kw)

    db = testlib.get_state_engine()
    name_rec = db.get_name('foo.test')
    name_history = db.get_name_at('foo.test', testlib.get_current_block(**kw))
    foo_update_ch = name_rec['consensus_hash']

    # foo.test: consensus hash should match that of the previously-sent update now.
    if name_rec['consensus_hash'] != testlib.get_consensus_at(testlib.get_current_block(**kw)-1):
        print 'NAME_UPDATE did not set consensus hash (expected {}): {}'.format(
                testlib.get_consensus_at(testlib.get_current_block(**kw)-1),
                name_rec
        )
        return False

    # foo.test: name's history's consensus hash should match the update as well
    if name_history[0]['consensus_hash'] != testlib.get_consensus_at(testlib.get_current_block(**kw)-1):
        print 'NAME_UPDATE did not match consensus hash in history (expected {}): {}'.format(
                testlib.get_consensus_at(testlib.get_current_block(**kw)-1),
                name_history[0]
        )
        return False

    name_rec = db.get_name('bar.test')
    name_history = db.get_name_at('bar.test', testlib.get_current_block(**kw))
    bar_update_ch = name_rec['consensus_hash']

    # bar.test: consensus hash should match last consensus hash 
    if name_rec['consensus_hash'] != testlib.get_consensus_at(testlib.get_current_block(**kw)-1):
        print 'NAME_UPDATE did not set consensus hash (expected {}): {}'.format(
                testlib.get_consensus_at(testlib.get_current_block(**kw)-1),
                name_rec
        )
        return False

    # foo.test: name's history's consensus hash should match the update as well
    if name_history[0]['consensus_hash'] != testlib.get_consensus_at(testlib.get_current_block(**kw)-1):
        print 'NAME_UPDATE did not match consensus hash in history (expected {}): {}'.format(
                testlib.get_consensus_at(testlib.get_current_block(**kw)-1),
                name_history[0]
        )
        return False

    # transferring the name should preserve the name's consensus hash in the name record, but not the history
    resp = testlib.blockstack_name_transfer('foo.test', wallets[3].addr, True, wallets[4].privkey)
    if 'error' in resp:
        print resp
        return False

    # transferring the name should preserve the name's consensus hash in the name record, but not the history
    resp = testlib.blockstack_name_transfer('bar.test', wallets[3].addr, True, wallets[4].privkey)
    if 'error' in resp:
        print resp
        return False

    testlib.next_block(**kw)

    db = testlib.get_state_engine()
    name_rec = db.get_name('foo.test')
    name_history = db.get_name_at('foo.test', testlib.get_current_block(**kw))

    if name_rec['consensus_hash'] != foo_update_ch:
        print 'NAME_TRANSFER did not preserve previous consensus hash (expected {}): {}'.format(
                foo_update_ch,
                name_rec
        )
        return False

    if name_history[0]['consensus_hash'] != testlib.get_consensus_at(testlib.get_current_block(**kw)-1):
        print 'NAME_UPDATE did not match consensus hash in history (expected {}): {}'.format(
                testlib.get_consensus_at(testlib.get_current_block(**kw)-1),
                name_history[0]
        )
        return False

    db = testlib.get_state_engine()
    name_rec = db.get_name('bar.test')
    name_history = db.get_name_at('bar.test', testlib.get_current_block(**kw))

    if name_rec['consensus_hash'] != bar_update_ch:
        print 'NAME_TRANSFER did not preserve previous consensus hash (expected {}): {}'.format(
                bar_update_ch,
                name_rec
        )
        return False

    if name_history[0]['consensus_hash'] != testlib.get_consensus_at(testlib.get_current_block(**kw)-1):
        print 'NAME_UPDATE did not match consensus hash in history (expected {}): {}'.format(
                testlib.get_consensus_at(testlib.get_current_block(**kw)-1),
                name_history[0]
        )
        return False

    # transferring the name again should preserve the name's consensus hash in the name record, but not the history
    resp = testlib.blockstack_name_transfer('foo.test', wallets[4].addr, True, wallets[3].privkey)
    if 'error' in resp:
        print resp
        return False

    resp = testlib.blockstack_name_transfer('bar.test', wallets[4].addr, True, wallets[3].privkey)
    if 'error' in resp:
        print resp
        return False

    testlib.next_block(**kw)
    
    db = testlib.get_state_engine()
    name_rec = db.get_name('foo.test')
    name_history = db.get_name_at('foo.test', testlib.get_current_block(**kw))

    if name_rec['consensus_hash'] != foo_update_ch:
        print 'NAME_TRANSFER did not preserve previous consensus hash (expected {}): {}'.format(
                foo_update_ch,
                name_rec
        )
        return False

    if name_history[0]['consensus_hash'] != testlib.get_consensus_at(testlib.get_current_block(**kw)-1):
        print 'NAME_UPDATE did not match consensus hash in history (expected {}): {}'.format(
                testlib.get_consensus_at(testlib.get_current_block(**kw)-1),
                name_history[0]
        )
        return False

    name_rec = db.get_name('bar.test')
    name_history = db.get_name_at('bar.test', testlib.get_current_block(**kw))

    if name_rec['consensus_hash'] != bar_update_ch:
        print 'NAME_TRANSFER did not preserve previous consensus hash (expected {}): {}'.format(
                bar_update_ch,
                name_rec
        )
        return False

    if name_history[0]['consensus_hash'] != testlib.get_consensus_at(testlib.get_current_block(**kw)-1):
        print 'NAME_UPDATE did not match consensus hash in history (expected {}): {}'.format(
                testlib.get_consensus_at(testlib.get_current_block(**kw)-1),
                name_history[0]
        )
        return False


def check( state_engine ):

    global consensus

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is not None:
        print "'test' not revealed"
        return False 

    ns = state_engine.get_namespace( "test" )
    if ns is None:
        print "'test' not found"
        return False 

    if ns['namespace_id'] != 'test':
        print "'test' not returned"
        return False 

    for name in ['foo.test', 'bar.test']:
        # not preordered
        preorder = state_engine.get_name_preorder( name, virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr )
        if preorder is not None:
            print "'foo.test' still preordered"
            return False
        
        # registered 
        name_rec = state_engine.get_name( name )
        if name_rec is None:
            print "'{}' not registered".format(name)
            return False 
    
        # transferred
        if name_rec['address'] != wallets[4].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[4].addr):
            print "'{}' invalid owner".format(name)
            return False 

    return True
