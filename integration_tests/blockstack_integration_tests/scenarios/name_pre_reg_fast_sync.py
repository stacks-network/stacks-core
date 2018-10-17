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

import os
import shutil
import testlib
import virtualchain
import blockstack
import blockstack_zones
import virtualchain
import json
import time

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet( "5K6Nou64uUXg8YzuiVuRQswuGRfH1tdb9GUC9NBEV1xmKxWMJ54", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
value_hashes = []
namespace_ids = []

def restore( working_dir, snapshot_path, restore_dir, pubkeys, num_required ):
    
    global value_hashes

    if os.path.exists(restore_dir):
        shutil.rmtree(restore_dir)

    os.makedirs(restore_dir)

    rc = blockstack.fast_sync_import( restore_dir, "file://{}".format(snapshot_path), public_keys=pubkeys, num_required=num_required )
    if not rc:
        print "failed to restore snapshot {}".format(snapshot_path)
        return False

    # database must be identical 
    db_filenames = ['blockstack-server.db', 'blockstack-server.snapshots', 'atlas.db', 'subdomains.db']
    src_paths = [os.path.join(working_dir, fn) for fn in db_filenames]
    backup_paths = [os.path.join(restore_dir, fn) for fn in db_filenames]

    for src_path, backup_path in zip(src_paths, backup_paths):
        rc = os.system('echo ".dump" | sqlite3 "{}" > "{}/first.dump"; echo ".dump" | sqlite3 "{}" > "{}/second.dump"; cmp "{}/first.dump" "{}/second.dump"'.format(
            src_path, restore_dir, backup_path, restore_dir, restore_dir, restore_dir))

        if rc != 0:
            print '{} disagress with {}'.format(src_path, backup_path)
            return False
    
    # all zone files must be present
    for vh in value_hashes:
        zfdata = blockstack.get_atlas_zonefile_data(vh, os.path.join(restore_dir, 'zonefiles'))
        if zfdata is None:
            print 'Missing {} in {}'.format(vh, os.path.join(restore_dir, 'zonefiles'))
            return False
    
    # all import keychains must be present
    for ns in namespace_ids:
        import_keychain_path = blockstack.lib.namedb.BlockstackDB.get_import_keychain_path(restore_dir, ns)
        if not os.path.exists(import_keychain_path):
            print 'Missing import keychain {}'.format(import_keychain_path)
            return False

    return True


def scenario( wallets, **kw ):

    global value_hashes

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    # register 10 names
    for i in xrange(0, 10):
        res = testlib.blockstack_name_preorder( "foo_{}.test".format(i), wallets[2].privkey, wallets[3].addr )
        if 'error' in res:
            print json.dumps(res)
            return False

    testlib.next_block( **kw )
    
    for i in xrange(0, 10):
        res = testlib.blockstack_name_register( "foo_{}.test".format(i), wallets[2].privkey, wallets[3].addr )
        if 'error' in res:
            print json.dumps(res)
            return False

    testlib.next_block( **kw )
 
    # make 10 empty zonefiles and propagate them 
    for i in xrange(0, 10):
        empty_zonefile_str = testlib.make_empty_zonefile( "foo_{}.test".format(i), wallets[3].addr)
        value_hash = blockstack.lib.storage.get_zonefile_data_hash(empty_zonefile_str)

        res = testlib.blockstack_name_update( "foo_{}.test".format(i), value_hash, wallets[3].privkey )
        if 'error' in res:
            print json.dumps(res)
            return False

        testlib.next_block( **kw )

        res = testlib.blockstack_put_zonefile(empty_zonefile_str)
        if not res:
            return False

        value_hashes.append(value_hash)

    testlib.next_block( **kw )

    print 'waiting for all zone files to replicate'
    time.sleep(10)

    working_dir = os.environ.get("BLOCKSTACK_WORKING_DIR")
    restore_dir = os.path.join(working_dir, "snapshot_dir")

    # snapshot the latest backup
    snapshot_path = os.path.join( working_dir, "snapshot.bsk" )
    rc = blockstack.fast_sync_snapshot(kw['working_dir'], snapshot_path, wallets[3].privkey, None )
    if not rc:
        print "Failed to fast_sync_snapshot"
        return False
   
    if not os.path.exists(snapshot_path):
        print "Failed to create snapshot {}".format(snapshot_path)
        return False

    # sign with more keys 
    for i in xrange(4, 6):
        rc = blockstack.fast_sync_sign_snapshot( snapshot_path, wallets[i].privkey )
        if not rc:
            print "Failed to sign with key {}".format(i)
            return False

    # restore!
    rc = restore( kw['working_dir'], snapshot_path, restore_dir, [wallets[3].pubkey_hex, wallets[4].pubkey_hex, wallets[5].pubkey_hex], 3 )
    if not rc:
        print "failed to restore snapshot {}".format(snapshot_path)
        return False

    rc = restore( kw['working_dir'], snapshot_path, restore_dir, [wallets[5].pubkey_hex, wallets[4].pubkey_hex, wallets[3].pubkey_hex], 3 )
    if not rc:
        print "failed to restore snapshot {}".format(snapshot_path)
        return False

    rc = restore( kw['working_dir'], snapshot_path, restore_dir, [wallets[3].pubkey_hex, wallets[4].pubkey_hex], 2 )
    if not rc:
        print "failed to restore snapshot {}".format(snapshot_path)
        return False

    rc = restore( kw['working_dir'], snapshot_path, restore_dir, [wallets[3].pubkey_hex, wallets[5].pubkey_hex], 2 )
    if not rc:
        print "failed to restore snapshot {}".format(snapshot_path)
        return False

    rc = restore( kw['working_dir'], snapshot_path, restore_dir, [wallets[4].pubkey_hex, wallets[5].pubkey_hex], 2 )
    if not rc:
        print "failed to restore snapshot {}".format(snapshot_path)
        return False

    rc = restore( kw['working_dir'], snapshot_path, restore_dir, [wallets[3].pubkey_hex], 1 )
    if not rc:
        print "failed to restore snapshot {}".format(snapshot_path)
        return False

    rc = restore( kw['working_dir'], snapshot_path, restore_dir, [wallets[4].pubkey_hex, wallets[0].pubkey_hex], 1 )
    if not rc:
        print "failed to restore snapshot {}".format(snapshot_path)
        return False

    rc = restore( kw['working_dir'], snapshot_path, restore_dir, [wallets[0].pubkey_hex, wallets[1].pubkey_hex, wallets[5].pubkey_hex], 1 )
    if not rc:
        print "failed to restore snapshot {}".format(snapshot_path)
        return False

    # should fail
    rc = restore( kw['working_dir'], snapshot_path, restore_dir, [wallets[3].pubkey_hex], 2 )
    if rc:
        print "restored insufficient signatures snapshot {}".format(snapshot_path)
        return False

    shutil.rmtree(restore_dir)

    # should fail
    rc = restore( kw['working_dir'], snapshot_path, restore_dir, [wallets[3].pubkey_hex, wallets[4].pubkey_hex], 3 )
    if rc:
        print "restored insufficient signatures snapshot {}".format(snapshot_path)
        return False

    shutil.rmtree(restore_dir)

    # should fail
    rc = restore( kw['working_dir'], snapshot_path, restore_dir, [wallets[0].pubkey_hex], 1 )
    if rc:
        print "restored wrongly-signed snapshot {}".format(snapshot_path)
        return False

    shutil.rmtree(restore_dir)

    # should fail
    rc = restore( kw['working_dir'], snapshot_path, restore_dir, [wallets[0].pubkey_hex, wallets[3].pubkey_hex], 2 )
    if rc:
        print "restored wrongly-signed snapshot {}".format(snapshot_path)
        return False

    shutil.rmtree(restore_dir)

    # should fail
    rc = restore( kw['working_dir'], snapshot_path, restore_dir, [wallets[0].pubkey_hex, wallets[3].pubkey_hex, wallets[4].pubkey_hex], 3 )
    if rc:
        print "restored wrongly-signed snapshot {}".format(snapshot_path)
        return False

    shutil.rmtree(restore_dir)


def check( state_engine ):

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is not None:
        print "namespace reveal exists"
        return False 

    ns = state_engine.get_namespace( "test" )
    if ns is None:
        print "no namespace"
        return False 

    if ns['namespace_id'] != 'test':
        print "wrong namespace"
        return False 

    for i in xrange(0, 10):
        name = 'foo_{}.test'.format(i)
        # not preordered
        preorder = state_engine.get_name_preorder( name, virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr )
        if preorder is not None:
            print "still have preorder"
            return False
        
        # registered 
        name_rec = state_engine.get_name( name )
        if name_rec is None:
            print "name does not exist"
            return False 

        # owned 
        if name_rec['address'] != wallets[3].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[3].addr):
            print "name has wrong owner"
            return False 

        # updated 
        if name_rec['value_hash'] is None:
            print "wrong value hash: %s" % name_rec['value_hash']
            return False 

    return True
