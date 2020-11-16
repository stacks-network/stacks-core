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
import time
import os

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

os.environ['V2_MIGRATION_EXPORT'] = '1'

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

# block_threshold = 500
block_threshold = 10

def scenario( wallets, **kw ):

    testlib.blockstack_namespace_preorder( "miner", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "miner", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "miner", wallets[1].privkey )
    testlib.next_block( **kw )

    for i in xrange(0, 25):
        name = "foo_{}.miner".format(i)
        testlib.blockstack_name_preorder( name, wallets[2].privkey, wallets[3].addr )

    testlib.next_block( **kw )

    for i in xrange(0, 25):
        name = "foo_{}.miner".format(i)
        testlib.blockstack_name_register( name, wallets[2].privkey, wallets[3].addr )
        
    testlib.next_block( **kw )

    threshold_start_block = testlib.get_current_block( **kw )
    os.environ['TEST_THRESHOLD_START_BLOCK'] = str(threshold_start_block)

    testlib.blockstack_name_preorder( "bar.miner", wallets[4].privkey, wallets[5].addr )
    testlib.blockstack_name_register( "bar.miner", wallets[4].privkey, wallets[5].addr )
    testlib.next_block( **kw )

    # block_threshold = 500
    block_threshold = 10
    for i in xrange(0, block_threshold + 1):
        testlib.next_block( **kw )
    
    testlib.blockstack_name_preorder( "toolate.miner", wallets[6].privkey, wallets[7].addr )
    testlib.blockstack_name_register( "toolate.miner", wallets[6].privkey, wallets[7].addr )
    testlib.next_block( **kw )
    testlib.expect_snv_fail_at("toolate.miner", testlib.get_current_block(**kw))

def check( state_engine ):
    # toolate shouldn't have even been registered
    if state_engine.get_name( "toolate.miner" ) is not None:
        print "registered late name"
        return False

    os.environ['V2_MIGRATION_EXPORT'] = '0'

    migration_data_file_path = os.path.join( state_engine.working_dir, 'v2_migration_data.tar.bz2')
    if not os.path.exists(migration_data_file_path):
        print 'v2_migration_data file not found'
        return False

    working_dir = os.environ.get("BLOCKSTACK_WORKING_DIR")
    restore_dir = os.path.join(working_dir, "snapshot_dir")
    if os.path.exists(restore_dir):
        shutil.rmtree(restore_dir)
    os.makedirs(restore_dir)

    rc = blockstack.fast_sync_import( restore_dir, "file://{}".format(migration_data_file_path), public_keys=[], num_required=0 )
    if not rc:
        print "failed to restore snapshot {}".format(snapshot_path)
        return False

    db = blockstack.lib.namedb.BlockstackDB.get_readwrite_instance(restore_dir)
    last_block = db.get_current_block()
    threshold_start_block = int(os.environ['TEST_THRESHOLD_START_BLOCK'])

    if last_block - threshold_start_block != block_threshold:
        print "export block height is not the correct threshold, {} - {} = {}".format(last_block, threshold_start_block, last_block - threshold_start_block)
        return False

    name_rec = db.get_name( "toolate.miner" )
    if name_rec is not None:
        print "toolate.miner should not be in snapshot"
        return False 

    name_rec = db.get_name( "bar.miner" )
    if name_rec is None:
        print "bar.miner should be in snapshot"
        return False

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "miner" )
    if ns is not None:
        print "namespace not ready"
        return False 

    ns = state_engine.get_namespace( "miner" )
    if ns is None:
        print "no namespace"
        return False 

    if ns['namespace_id'] != 'miner':
        print "wrong namespace"
        return False 

    # not preordered
    preorder = state_engine.get_name_preorder( "foo_1.miner", virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr )
    if preorder is not None:
        print "still have preorder"
        return False
    
    # registered 
    name_rec = state_engine.get_name( "foo_1.miner" )
    if name_rec is None:
        print "name does not exist"
        return False 

    return True
