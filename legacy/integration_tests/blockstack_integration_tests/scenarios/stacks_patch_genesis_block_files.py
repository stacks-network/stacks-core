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

patch_file_addrs = [
    virtualchain.lib.ecdsalib.ecdsa_private_key(patch_file_privkeys[0]).public_key().address(),
    virtualchain.lib.ecdsalib.ecdsa_private_key(patch_file_privkeys[1]).public_key().address(),
    virtualchain.lib.ecdsalib.ecdsa_private_key(patch_file_privkeys[2]).public_key().address(),
    virtualchain.lib.ecdsalib.ecdsa_private_key(patch_file_privkeys[3]).public_key().address(),
    virtualchain.lib.ecdsalib.ecdsa_private_key(patch_file_privkeys[4]).public_key().address(),
    new_addr_b58,
    new_unlocked_addr_b58,
    new_grant_addr_b58,
]

patch_addrs_path = "/tmp/addrs.txt"

genesis_patches_files = {
    "692": {
        'path': patch_addrs_path,
        'sha256': "",
        'line_start': 0,
        'line_end': 5,
        'receive_whitelisted': True,
        'lock_send': 0,
        'metadata': 'test',
        'type': 'STACKS',
        'value': 12345,
        'vesting': {},
        'vesting_total': 0
    },
    "693": {
        'path': patch_addrs_path,
        'sha256': "",
        'line_start': 5,
        'line_end': 8,
        'receive_whitelisted': True,
        'lock_send': 123,
        'metadata': 'test2',
        'type': 'STACKS',
        'value': 23456,
        'vesting': {},
        'vesting_total': 0
    }
}

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):
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

    # in block 689, so the patch hasn't taken place yet
    balances = testlib.get_wallet_balances(wallets)
    assert balances[wallets[0].addr][STACKS] == 100 + 600000
    assert balances[wallets[1].addr][STACKS] == 123 + 1000
    assert balances[wallets[2].addr][STACKS] == 0

    # send some tokens to a brand-new address
    testlib.blockstack_send_tokens(new_addr, "STACKS", 600000, wallets[0].privkey)
    testlib.blockstack_send_tokens(new_unlocked_addr, "STACKS", 100, wallets[0].privkey)
    testlib.next_block(**kw) # end of 689, triggers vesting of block 690
    
    assert virtualchain.lib.indexer.StateEngine.get_block_statistics(testlib.get_current_block(**kw))['num_processed_ops'] == 2

    # new balances should reflect patch
    balances = testlib.get_addr_balances([w.addr for w in wallets] + [new_addr_b58, new_grant_addr_b58, new_unlocked_addr_b58])
    print balances

    assert balances[wallets[0].addr][STACKS] == 100 + 200 + 600000 + 600001 + 10000 + 10001 + 10002 + 10003 + 10004 + 10005 - 600000 - 100         # += new value + retroactive vesting
    assert balances[wallets[1].addr][STACKS] == 123 + 1000 + (10000000 * 10)
    assert balances[wallets[2].addr][STACKS] == 123456
    assert balances[new_addr_b58][STACKS] == 600000 + 222222 + 66
    assert balances[new_grant_addr_b58][STACKS] == 567 + (10000000 * 10)
    assert balances[new_unlocked_addr_b58][STACKS] == 100 + 123456 + 22000 + 22001 + 22002 + 22003 + 22004 + 22005

    # send some tokens to a brand-new address
    # should be transfer-locked
    testlib.blockstack_send_tokens(new_addr_b58, "STACKS", 600000, wallets[0].privkey, safety_checks=False, expect_fail=True)
    testlib.blockstack_send_tokens(new_grant_addr_b58, "STACKS", 1, new_wallet, safety_checks=False, expect_fail=True)
    testlib.blockstack_send_tokens(new_grant_addr_b58, "STACKS", 10000000, wallets[1].privkey, safety_checks=False)
    testlib.blockstack_send_tokens(new_addr_b58, "STACKS", 10000000, wallets[1].privkey, safety_checks=False)
    testlib.blockstack_send_tokens(new_grant_addr_b58, "STACKS", 3, new_unlocked_wallet, safety_checks=False)
    testlib.next_block(**kw)  # 690

    assert virtualchain.lib.indexer.StateEngine.get_block_statistics(testlib.get_current_block(**kw))['num_processed_ops'] == 3
    
    balances = testlib.get_addr_balances([w.addr for w in wallets] + [new_addr_b58, new_grant_addr_b58, new_unlocked_addr_b58])
    print balances

    assert balances[wallets[0].addr][STACKS] == 100 + 200 + 600000 + 600001 + 600010 + 10000 + 10001 + 10002 + 10003 + 10004 + 10005 + 10006 - 600000 - 100         # += new value + retroactive vesting
    assert balances[wallets[1].addr][STACKS] == 123 + 1000 + (10000000 * 10) - 10000000 - 10000000
    assert balances[wallets[2].addr][STACKS] == 123456
    assert balances[new_addr_b58][STACKS] == 600000 + 222222 + 66 + 10000000
    assert balances[new_grant_addr_b58][STACKS] == 567 + (10000000 * 10) + 10000000 + 3
    assert balances[new_unlocked_addr_b58][STACKS] == 100 + 123456 + 22000 + 22001 + 22002 + 22003 + 22004 + 22005 + 22006 - 3

    # apply patches from files
    balances = testlib.get_addr_balances(patch_file_addrs[0:5])
    print balances

    for addr in patch_file_addrs[0:5]:
        assert balances[addr].get(STACKS, 0) == 0

    testlib.next_block(**kw)    # make the balances real (end of 691)

    balances = testlib.get_addr_balances(patch_file_addrs[0:5])
    for addr in patch_file_addrs[0:5]:
        assert balances[addr][STACKS] == 12345
    
    # apply patches from files
    balances_before_patch = testlib.get_addr_balances(patch_file_addrs[5:8])
    print balances_before_patch

    assert balances_before_patch[new_addr_b58][STACKS] == 600000 + 222222 + 66 + 10000000
    assert balances_before_patch[new_grant_addr_b58][STACKS] == 567 + (10000000 * 10) + 10000000 + 3
    assert balances_before_patch[new_unlocked_addr_b58][STACKS] == 100 + 123456 + 22000 + 22001 + 22002 + 22003 + 22004 + 22005 + 22006 + 22007 - 3

    testlib.next_block(**kw)    # make the balances real (end of 692)

    balances_after_patch = testlib.get_addr_balances(patch_file_addrs[5:8])

    assert balances_after_patch[new_addr_b58][STACKS] == 600000 + 222222 + 66 + 10000000 + 23456
    assert balances_after_patch[new_grant_addr_b58][STACKS] == 567 + (10000000 * 10) + 10000000 + 3 + 23456
    assert balances_after_patch[new_unlocked_addr_b58][STACKS] == 100 + 123456 + 22000 + 22001 + 22002 + 22003 + 22004 + 22005 + 22006 + 22007 + 22008 - 3 + 23456

    # drain-transfer from newly-granted
    for (addr, privkey) in zip(patch_file_addrs[0:5], patch_file_privkeys):
        testlib.send_funds(wallets[0].privkey, 388500, virtualchain.address_reencode(addr))
        testlib.blockstack_send_tokens(new_addr_b58, "STACKS", 12345, privkey)

    testlib.next_block(**kw)
    
    balances_after_xfer = testlib.get_addr_balances(patch_file_addrs)
    print balances_after_xfer

    for addr in patch_file_addrs[0:5]:
        assert balances_after_xfer[addr].get(STACKS, 0) == 0

    assert balances_after_xfer[new_addr_b58][STACKS] == 600000 + 222222 + 66 + 10000000 + 23456 + 12345*5
    assert balances_after_xfer[new_grant_addr_b58][STACKS] == 567 + (10000000 * 10) + 10000000 + 3 + 23456
    assert balances_after_xfer[new_unlocked_addr_b58][STACKS] == 100 + 123456 + 22000 + 22001 + 22002 + 22003 + 22004 + 22005 + 22006 + 22007 + 22008 + 22009 - 3 + 23456


def check( state_engine ):
    return True
