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
import hashlib
import blockstack.lib.nameset.db as namedb
import os
import time
import traceback

STACKS = testlib.TOKEN_TYPE_STACKS
# activate tokens
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 682
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 683
TEST ENV BLOCKSTACK_EPOCH_3_END_BLOCK 684
TEST ENV BLOCKSTACK_EPOCH_4_END_BLOCK 689
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_4_NAMESPACE_LIFETIME_MULTIPLIER 1
"""

patch_addrs_path = "blockchain-airdrop-2020.csv"
genesis_patches_files = dict([(str(int(k) - 613250 + 691), v) for (k, v) in blockstack.lib.genesis_block.GENESIS_BLOCK_PATCHES_FILES.items()])

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

wallets = []

def scenario( wallets, **kw ):
    patch_addrs_path = blockstack.lib.config.get_genesis_bulk_address_path("blockchain-airdrop-2020.csv")
    patch_file_contents = open(patch_addrs_path).read().strip()
    patch_file_addrs = map(lambda a: str(a.strip()), filter(lambda a: len(a.strip()) > 0, patch_file_contents.split('\n')))
    assert len(patch_file_addrs) == 322146

    for a in patch_file_addrs:
        try:
            virtualchain.address_reencode(a)
        except Exception as e:
            print "not a valid address: {}".format(a)
            traceback.print_exc();
            raise e
    
    blockstack.lib.config.set_genesis_block_patches_files(genesis_patches_files)
    testlib.set_account_audits(False)

    print json.dumps(genesis_patches_files, indent=4, sort_keys=True)
    
    for i in range(0, len(patch_file_addrs)/10000):
        assert genesis_patches_files.get(str(i + 691)) is not None
        assert genesis_patches_files[str(i + 691)]['metadata'] == 'batch-{}'.format(i+1)

    testlib.next_block(**kw)

    times = []

    for i in range(0, (len(patch_file_addrs)/10000)+1):
        t1 = time.time()
        testlib.next_block(**kw)    # make the balances real (end of 691 + i, start of 692 + i)
        t2 = time.time()
       
        db_path = os.path.join(os.environ['BLOCKSTACK_WORKING_DIR'], 'blockstack-server.db')
        db = namedb.namedb_open(db_path)
        cur = db.cursor()
        cur.execute('BEGIN')
        for j in range(i*10000, min(len(patch_file_addrs), (i+1)*10000)):
            addr = virtualchain.address_reencode(patch_file_addrs[j].strip())
            acct = namedb.namedb_get_account(cur, addr, 'STACKS')
            assert acct is not None, "no account {} (the {}'th one)".format(addr, j)
            assert namedb.namedb_get_account_balance(acct) == 100 * 10**6
        cur.execute('END')
        
        print "Pocessing time: {}".format(t2 - t1)
        times.append(t2 - t1)
        db.close()

    print "Total processing times"
    for t in times:
        print "{}".format(t)
       
    db_path = os.path.join(os.environ['BLOCKSTACK_WORKING_DIR'], 'blockstack-server.db')
    db = namedb.namedb_open(db_path)
    cur = db.cursor()
    cur.execute('BEGIN')
    for i in range(0, len(patch_file_addrs)):
        if i % 1000 == 0:
            print "Tested {} addresses".format(i)

        addr = virtualchain.address_reencode(patch_file_addrs[i].strip())
        acct = namedb.namedb_get_account(cur, addr, 'STACKS')
        assert acct is not None, "no account {} (the {}'th one)".format(addr, i)
        assert namedb.namedb_get_account_balance(acct) == 100 * 10**6
    cur.execute('END')

def check( state_engine ):
    return True
