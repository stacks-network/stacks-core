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

new_wallet = '50c0724cacee81d00b3e84858c9aa30c75d2fe7a6fbdb6c8786ad3befb82659001'
new_addr = 'ST1T9RNPG57B2Y9YZDX9S7452N1VQXT5S5T8N9RDK'
new_addr_b58 = 'mr9XxwP5FhY7DMw94pwfmxU2YLgUWqVmJm'

new_unlocked_wallet = "adc8b9e7cb04d57fc38e7c1bd3cddbc684bbf676f258223c7293b823fed2c20701"
new_unlocked_addr = "ST10J3CSXT63J5WMW5BCWRQQASBT2E7R7EPGWWZ2G"
new_unlocked_addr_b58 = "mmTLb3vqzJbqYGgQz5C6KKJKuBJ4JkqaeS"

new_grant_addr = 'ST2G61YBH4GTWD6FRR5BA760J2ETS8F96182M3YT4'
new_grant_addr_b58 = 'mv8xaeNRwVGTiGY4Gyqr8VP2aWJ37KCrZT'

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100, 
        vesting={
            STACKS: {
                689: 600000,
                690: 600001,
                691: 600010,
                692: 600100,
                693: 601000,
                694: 610000,
                'lock_send': 0,
                'receive_whitelisted': True
            }
        }
    ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 123, 
        vesting={
            STACKS: {
                689: 1000,
                'lock_send': 0,
                'receive_whitelisted': True
            }
        }
    ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 0 )
]

genesis_patches = {
    "690": {
        "add": [
            {
                # completely new address, with retroactive vesting
                "address": new_grant_addr,
                "lock_send": 900,
                "metadata": "dabe55668e11dc6486c2b2a3e908b888ee84cfa6268021466ae89007a8022d7c",
                "receive_whitelisted": True,
                "type": STACKS,
                "value": 567,
                "vesting": {
                    "600": 10000000,
                    "610": 10000000,
                    "620": 10000000,
                    "630": 10000000,
                    "640": 10000000,
                    "650": 10000000,
                    "660": 10000000,
                    "670": 10000000,
                    "680": 10000000,
                    "690": 10000000,
                    "700": 10000000,
                },
                "vesting_total": 110000000
            },
            {
                # address that was sent to prior to the patch
                "address": new_addr,
                "lock_send": 901,
                "metadata": "1d405cea0c47161cc24b8dc33196a29a18e06362098c7f2a1e57e0eb9376bb09",
                "receive_whitelisted": True,
                "type": STACKS,
                "value": 222222,
                "vesting": {
                    "680": 1,
                    "681": 2,
                    "682": 3,
                    "683": 4,
                    "684": 5,
                    "685": 6,
                    "686": 7,
                    "687": 8,
                    "688": 9,
                    "689": 10,
                    "690": 11,
                },
                "vesting_total": 66,
            },
            {
                # wallets[2] -- retroactive token grant
                "address": "ST2GRD5VV0YPR6BK89F7PGG6S34NT0HMCRKPAJNX2",
                "lock_send": 0,
                "metadata": "82ada6a1b947d4e22535bc0f20e75b3d4a5b1c4d3024b4cbb20519220c262b3c",
                "receive_whitelisted": True,
                "type": STACKS,
                "value": 123456,
                "vesting": {},
                "vesting_total": 0,
            },
            {
                # wallets[1] -- retroactive vesting, non-overlapping
                "address": "ST210JEV2MDMS50PS4TC1QVBPCQM3GK5AANEPK7C0",
                "lock_send": 0,
                "metadata": "c3f2dcdbe3f49f8f5d9eb6b7844102f912e9fd331ebcada1afc9fd1159f56c2e",
                "receive_whitelisted": True,
                "type": STACKS,
                "value": 0,
                "vesting": {
                    "600": 10000000,
                    "610": 10000000,
                    "620": 10000000,
                    "630": 10000000,
                    "640": 10000000,
                    "650": 10000000,
                    "660": 10000000,
                    "670": 10000000,
                    "680": 10000000,
                    "690": 10000000,
                    "700": 10000000,
                },
                "vesting_total": 110000000
            },
            {
                # wallets[0] -- retroactive value and vesting, with overlapping vesting, with new lock height
                "address": "ST1T1F14QX4KZYFZH8A5286Z4AK9S7GY93JFKNGJS",
                "lock_send": 903,
                "metadata": "466c9400608eed41a5bb0c5cca9e3c694a530c28cc29ab96813edfc9c01e7005",
                "receive_whitelisted": True,
                "type": STACKS,
                "value": 200,
                "vesting": {
                    "685": 10000,
                    "686": 10001,
                    "687": 10002,
                    "688": 10003,
                    "689": 10004,
                    "690": 10005,
                    "691": 10006,
                    "692": 10007,
                    "693": 10008,
                    "694": 10009
                },
                "vesting_total": 100045
            },
            {
                # add unlocked allocation
                "address": new_unlocked_addr,
                "lock_send": 0,
                "metadata": "bb" * 32,
                "receive_whitelisted": False,
                "type": STACKS,
                "value": 123456,
                "vesting": {
                    "685": 22000,
                    "686": 22001,
                    "687": 22002,
                    "688": 22003,
                    "689": 22004,
                    "690": 22005,
                    "691": 22006,
                    "692": 22007,
                    "693": 22008,
                    "694": 22009
                },
                "vesting_total": 220045
            },
            {
                # add unspendable allocation
                "address": "unspendable-allocation-1",
                "lock_send": 0,
                "metadata": "a5f53f7c49840a2b1652746c3ed8a8be3517b0596336c6bc408800dcba0b9967",
                "receive_whitelisted": False,
                "type": STACKS,
                "value": 123456,
                "vesting": {
                    "685": 20000,
                    "686": 20001,
                    "687": 20002,
                    "688": 20003,
                    "689": 20004,
                    "690": 20005,
                    "691": 20006,
                    "692": 20007,
                    "693": 20008,
                    "694": 20009
                },
                "vesting_total": 200045
            },
        ],
        "del": [],
        "db_version": "22.0.0.0"
    },
}

patch_file_privkeys = [
    "ad88c4c2a24c9d8e0818e53796a7244e1d2610be8080fd11f4385c5748d1496501",
    "ddd9eb9486afc5b8b564312049894ce78aa1982483aa07aaf3d0160347f232f301",
    "c852887352c5b4e665463e099895660c668143ba736e5b1d2eb42c58c0b2cd6f01",
    "ad9dd2bc60e0016a766efcf8992edb3c6947818b06f1e999f0fb7385061ad4ad01",
    "202314651bee0677ab88fae79609febafdf0ea3e63aa6ff0d590eba3cf3feb0c01"
]

patch_addrs_path = "/tmp/addrs.txt"

genesis_patches_files = {
    "692": {
        'path': patch_addrs_path,
        'sha256': "",
        'line_start': 0,
        'line_end': 10000,
        'receive_whitelisted': True,
        'lock_send': 0,
        'metadata': 'test_692',
        'type': 'STACKS',
        'value': 100 * 10**6,
        'vesting': {},
        'vesting_total': 0
    },
    "693": {
        'path': patch_addrs_path,
        'sha256': "",
        'line_start': 10000,
        'line_end': 20000,
        'receive_whitelisted': True,
        'lock_send': 0,
        'metadata': 'test_693',
        'type': 'STACKS',
        'value': 100 * 10**6,
        'vesting': {},
        'vesting_total': 0
    },
    "694": {
        'path': patch_addrs_path,
        'sha256': "",
        'line_start': 20000,
        'line_end': 30000,
        'receive_whitelisted': True,
        'lock_send': 0,
        'metadata': 'test_694',
        'type': 'STACKS',
        'value': 100 * 10**6,
        'vesting': {},
        'vesting_total': 0
    },
    "695": {
        'path': patch_addrs_path,
        'sha256': "",
        'line_start': 30000,
        'line_end': 40000,
        'receive_whitelisted': True,
        'lock_send': 123,
        'metadata': 'test_695',
        'type': 'STACKS',
        'value': 100 * 10**6,
        'vesting': {},
        'vesting_total': 0
    },
    "696": {
        'path': patch_addrs_path,
        'sha256': "",
        'line_start': 40000,
        'line_end': 50000,
        'receive_whitelisted': True,
        'lock_send': 0,
        'metadata': 'test_696',
        'type': 'STACKS',
        'value': 100 * 10**6,
        'vesting': {},
        'vesting_total': 0
    },
    "697": {
        'path': patch_addrs_path,
        'sha256': "",
        'line_start': 50000,
        'line_end': 60000,
        'receive_whitelisted': True,
        'lock_send': 0,
        'metadata': 'test_697',
        'type': 'STACKS',
        'value': 100 * 10**6,
        'vesting': {},
        'vesting_total': 0
    },
    "698": {
        'path': patch_addrs_path,
        'sha256': "",
        'line_start': 60000,
        'line_end': 70000,
        'receive_whitelisted': True,
        'lock_send': 0,
        'metadata': 'test_698',
        'type': 'STACKS',
        'value': 100 * 10**6,
        'vesting': {},
        'vesting_total': 0
    },
    "699": {
        'path': patch_addrs_path,
        'sha256': "",
        'line_start': 70000,
        'line_end': 80000,
        'receive_whitelisted': True,
        'lock_send': 0,
        'metadata': 'test_699',
        'type': 'STACKS',
        'value': 100 * 10**6,
        'vesting': {},
        'vesting_total': 0
    },
    "700": {
        'path': patch_addrs_path,
        'sha256': "",
        'line_start': 80000,
        'line_end': 90000,
        'receive_whitelisted': True,
        'lock_send': 0,
        'metadata': 'test_700',
        'type': 'STACKS',
        'value': 100 * 10**6,
        'vesting': {},
        'vesting_total': 0
    },
    "701": {
        'path': patch_addrs_path,
        'sha256': "",
        'line_start': 90000,
        'line_end': 100000,
        'receive_whitelisted': True,
        'lock_send': 0,
        'metadata': 'test_701',
        'type': 'STACKS',
        'value': 100 * 10**6,
        'vesting': {},
        'vesting_total': 0
    }
}

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):
    patch_file_addrs = [
        blockstack.lib.c32.c32ToB58(blockstack.lib.c32.c32address(26, '{:040x}'.format(i))) for i in range(0, 100000)
    ]
    patch_file_contents = '\n'.join(patch_file_addrs)
    
    h = hashlib.new('sha256')
    h.update(patch_file_contents)
    patch_file_hash = h.hexdigest()

    with open(patch_addrs_path, 'w') as f:
        f.write(patch_file_contents)

    for k in genesis_patches_files:
        genesis_patches_files[k]['sha256'] = patch_file_hash

    blockstack.lib.config.set_genesis_block_patches(genesis_patches)
    blockstack.lib.config.set_genesis_block_patches_files(genesis_patches_files)
    testlib.set_account_audits(False)

    testlib.next_block(**kw)
    testlib.next_block(**kw)

    times = []

    db_path = os.path.join(os.environ['BLOCKSTACK_WORKING_DIR'], 'blockstack-server.db')
    db = namedb.namedb_open(db_path)
    for i in range(0, 10):
        t1 = time.time()
        testlib.next_block(**kw)    # make the balances real (end of 691 + i, start of 692 + i)
        t2 = time.time()
       
        cur = db.cursor()
        cur.execute('BEGIN')
        for j in range(i*10000, (i+1)*10000):
            acct = namedb.namedb_get_account(cur, patch_file_addrs[j], 'STACKS')
            assert namedb.namedb_get_account_balance(acct) == 100 * 10**6
        cur.execute('END')
        
        print "Pocessing time: {}".format(t2 - t1)
        times.append(t2 - t1)

    print "Total processing times"
    for t in times:
        print "{}".format(t)
        



def check( state_engine ):
    return True
