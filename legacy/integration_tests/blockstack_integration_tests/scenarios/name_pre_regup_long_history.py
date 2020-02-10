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
import blockstack

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

    preorder_block = str(testlib.get_current_block(**kw))

    zfdata = 'hello world for the first time'
    zfhash = blockstack.lib.storage.get_zonefile_data_hash(zfdata)

    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr, zonefile_hash=zfhash)
    testlib.next_block( **kw )
    
    register_block = str(testlib.get_current_block(**kw))

    testlib.blockstack_put_zonefile(zfdata)

    name = 'foo.test'

    # get name and history--make sure it works 
    name_rec = blockstack.lib.client.get_name_record(name, include_history=True, hostport='http://localhost:16264')
    if 'error' in name_rec:
        print name_rec
        return False

    if len(name_rec['history']) != 2:
        print 'invalid history'
        print json.dumps(name_rec['history'], indent=4, sort_keys=True)
        return False

    if preorder_block not in name_rec['history'] or len(name_rec['history'][preorder_block]) != 1:
        print 'missing preorder block'
        print json.dumps(name_rec['history'], indent=4, sort_keys=True)
        return False

    if register_block not in name_rec['history'] or len(name_rec['history'][register_block]) != 1:
        print 'missing register block'
        print json.dumps(name_rec['history'], indent=4, sort_keys=True)
        return False

    # do a bunch of updates in this block
    for i in xrange(0, 19):
        zfdata = 'hello update {}'.format(i)
        zfhash = blockstack.lib.storage.get_zonefile_data_hash(zfdata)
        testlib.blockstack_name_update("foo.test", zfhash, wallets[3].privkey)
        
    testlib.next_block(**kw)
    update_block_1 = str(testlib.get_current_block(**kw))

    for i in xrange(0, 19):
        zfdata = 'hello update {}'.format(i)
        testlib.blockstack_put_zonefile(zfdata)

    # get name and history--make sure it works 
    name_rec = blockstack.lib.client.get_name_record(name, include_history=True, hostport='http://localhost:16264')
    if 'error' in name_rec:
        print json.dumps(name_rec, indent=4, sort_keys=True)
        return False

    if len(name_rec['history']) != 3:
        print 'invalid history'
        print json.dumps(name_rec['history'], indent=4, sort_keys=True)
        return False

    # need to be 21 entries: the preorder, register, and 19 updates
    if preorder_block not in name_rec['history'] or len(name_rec['history'][preorder_block]) != 1:
        print 'missing preorder block'
        print json.dumps(name_rec['history'], indent=4, sort_keys=True)
        return False

    if register_block not in name_rec['history'] or len(name_rec['history'][register_block]) != 1:
        print 'missing register block'
        print json.dumps(name_rec['history'], indent=4, sort_keys=True)
        return False

    if update_block_1 not in name_rec['history'] or len(name_rec['history'][update_block_1]) != 19:
        print 'missing update block'
        print json.dumps(name_rec['history'], indent=4, sort_keys=True)
        return False

    # do a bunch more updates in this block
    for i in xrange(0, 21):
        zfdata = 'hello update round 2 {}'.format(i)
        zfhash = blockstack.lib.storage.get_zonefile_data_hash(zfdata)
        testlib.blockstack_name_update("foo.test", zfhash, wallets[3].privkey)

    testlib.next_block(**kw)
    update_block_2 = str(testlib.get_current_block(**kw))

    for i in xrange(0, 21):
        zfdata = 'hello update round 2 {}'.format(i)
        testlib.blockstack_put_zonefile(zfdata)

    # get name and history--make sure it works 
    name_rec = blockstack.lib.client.get_name_record(name, include_history=True, hostport='http://localhost:16264')
    if 'error' in name_rec:
        print json.dumps(name_rec, indent=4, sort_keys=True)
        return False

    if len(name_rec['history']) != 4:
        print 'invalid history'
        print json.dumps(name_rec['history'], indent=4, sort_keys=True)
        return False

    # need to be 21 entries: the preorder, register, and 19 updates
    if preorder_block not in name_rec['history'] or len(name_rec['history'][preorder_block]) != 1:
        print 'missing preorder block'
        print json.dumps(name_rec['history'], indent=4, sort_keys=True)
        return False

    if register_block not in name_rec['history'] or len(name_rec['history'][register_block]) != 1:
        print 'missing register block'
        print json.dumps(name_rec['history'], indent=4, sort_keys=True)
        return False

    if update_block_1 not in name_rec['history'] or len(name_rec['history'][update_block_1]) != 19:
        print 'missing update block 1'
        print json.dumps(name_rec['history'], indent=4, sort_keys=True)
        return False

    if update_block_2 not in name_rec['history'] or len(name_rec['history'][update_block_2]) != 21:
        print 'missing update block 2'
        print json.dumps(name_rec['history'], indent=4, sort_keys=True)
        return False

    # last page must be just the last updates 
    hist_page = blockstack.lib.client.get_name_history_page(name, 0, hostport='http://localhost:16264')
    if 'error' in hist_page:
        print hist_page
        return False

    history = hist_page['history']
    if len(history) != 1 or update_block_2 not in history:
        print 'missing update block 2 in history page'
        print json.dumps(history, indent=4, sort_keys=True)
        return False

    for vtx in history[update_block_2]:
        # should be vtxindex 2 through 21
        if vtx['vtxindex'] < 2:
            print 'got low vtxindex'
            print json.dumps(history, indent=4, sort_keys=True)
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

    name = 'foo.test'

    # not preordered
    preorder = state_engine.get_name_preorder( name, virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr )
    if preorder is not None:
        print 'still have preorder: {}'.format(preorder)
        return False
     
    # registered 
    name_rec = state_engine.get_name(name)
    if name_rec is None:
        print 'did not get name {}'.format(name)
        return False

    # owned by
    if name_rec['address'] != wallets[3].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[3].addr):
        print 'wrong address for {}: {}'.format(name, name_rec)
        return False

    return True
