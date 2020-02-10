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
import blockstack.lib.c32 as c32 
import requests
import sys

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def get_fixtures():
    fixtures = [
        {
            'route': '/v1/accounts',
            'status': 404,
        },
        {
            'route': '/v1/accounts/{}/tokens'.format(wallets[0].addr),
            'status': 200,
            'body': {'tokens': ['STACKS']}
        },
        {
            'route': '/v1/accounts/{}/tokens'.format(virtualchain.address_reencode(wallets[0].addr, network='mainnet')),
            'status': 200,
            'body': {'tokens': []}
        },
        {
            'route': '/v1/accounts/{}/tokens'.format(c32.b58ToC32(wallets[0].addr)),
            'status': 200,
            'body': {'tokens': ['STACKS']}
        },
        {
            'route': '/v1/accounts/{}/STACKS/balance'.format(wallets[0].addr),
            'status': 200,
            'body': {'balance': "100000000000"},
        },
        {
            'route': '/v1/accounts/{}/STACKS/balance'.format(c32.b58ToC32(wallets[0].addr)),
            'status': 200,
            'body': {'balance': "100000000000"},
        },
        {
            'route': '/v1/accounts/{}/STACKS/status'.format(wallets[0].addr),
            'status': 200,
            'body_json_partial': {"debit_value": "0", "block_id": 688, "lock_transfer_block_id": 0, "address": "mr6nrMvvh44sR5MiX929mMXP5hqgaTr6fx", "credit_value": "100000000000", "type": "STACKS"}
        },
        {
            'route': '/v1/accounts/{}/STACKS/status'.format(c32.b58ToC32(wallets[0].addr)),
            'status': 200,
            'body_json_partial': {"debit_value": "0", "block_id": 688, "lock_transfer_block_id": 0, "address": "mr6nrMvvh44sR5MiX929mMXP5hqgaTr6fx", "credit_value": "100000000000", "type": "STACKS"}
        },
        {
            'route': '/v1/accounts/{}/history'.format(wallets[0].addr),
            'status': 200,
            'body_json_partial': [{"debit_value": "0", "block_id": 688, "lock_transfer_block_id": 0, "address": "mr6nrMvvh44sR5MiX929mMXP5hqgaTr6fx", "credit_value": "100000000000", "type": "STACKS"}]
        },
        {
            'route': '/v1/accounts/{}/history'.format(c32.b58ToC32(wallets[0].addr)),
            'status': 200,
            'body_json_partial': [{"debit_value": "0", "block_id": 688, "lock_transfer_block_id": 0, "address": "mr6nrMvvh44sR5MiX929mMXP5hqgaTr6fx", "credit_value": "100000000000", "type": "STACKS"}]
        },
        {
            'route': '/v1/accounts/{}/history/687'.format(wallets[0].addr),
            'status': 200,
            'body': [],
        },
        {
            'route': '/v1/accounts/{}/history/687'.format(c32.b58ToC32(wallets[0].addr)),
            'status': 200,
            'body': [],
        },
        {
            'route': '/v1/accounts/{}/history/689'.format(wallets[0].addr),
            'status': 200,
            'body_json_partial': [{"debit_value": "0", "block_id": 688, "lock_transfer_block_id": 0, "address": "mr6nrMvvh44sR5MiX929mMXP5hqgaTr6fx", "credit_value": "100000000000", "type": "STACKS"}]
        },
        {
            'route': '/v1/accounts/{}/history?page=0'.format(wallets[0].addr),
            'status': 200,
            'body_json_partial': [{"debit_value": "0", "block_id": 688, "lock_transfer_block_id": 0, "address": "mr6nrMvvh44sR5MiX929mMXP5hqgaTr6fx", "credit_value": "100000000000", "type": "STACKS"}]
        },
        {
            'route': '/v1/accounts/{}/history?page=0'.format(c32.b58ToC32(wallets[0].addr)),
            'status': 200,
            'body_json_partial': [{"debit_value": "0", "block_id": 688, "lock_transfer_block_id": 0, "address": "mr6nrMvvh44sR5MiX929mMXP5hqgaTr6fx", "credit_value": "100000000000", "type": "STACKS"}]
        },
        {
            'route': '/v1/accounts/{}/history?page=1'.format(wallets[0].addr),
            'status': 200,
            'body': [],
        },
        {
            'route': '/v1/accounts/{}/history?page=1'.format(c32.b58ToC32(wallets[0].addr)),
            'status': 200,
            'body': [],
        },
        {
            'route': '/v1/accounts/ST938N61X0VR/tokens',
            'status': 200,
            'body': {'tokens': []}
        },
        {
            'route': '/v1/accounts/ST938N61X0VR/STACKS/status',
            'status': 404,
        },
        {
            'route': '/v1/accounts/ST938N61X0VR/STACKS/balance',
            'status': 200,
            'body': {'balance': '0'}
        },
        {
            'route': '/v1/accounts/ST938N61X0VR/history',
            'status': 200,
            'body': [],
        },
        {
            'route': '/v1/accounts/ST938N61X0VR/history/688',
            'status': 200,
            'body': [],
        },
        {
            'route': '/v1/accounts/ST938N61X0VR/history?page=0',
            'status': 200,
            'body': [],
        },
    ]
    
    return fixtures


def partial_compare(partial, obj):
    if isinstance(partial, dict):
        if not isinstance(obj, dict):
            return False

        for k in partial:
            if k not in obj:
                return False

            if partial[k] != obj[k]:
                return False

        return True

    elif isinstance(partial, list):
        if not isinstance(obj, list):
            return False

        for partial_item in partial:
            found = False
            for obj_item in obj:
                if partial_compare(partial_item, obj_item):
                    found = True
                    break

            if not found:
                return False

        return True

    else:
        return partial == obj


def scenario( wallets, **kw ):
    
    errors = []
    fixtures = get_fixtures()
    for entry in fixtures:
        url = 'http://localhost:16268' + entry['route']
        res = requests.get(url, allow_redirects=False)

        res_status = res.status_code
        res_txt = res.text
        res_json = None
        try:
            res_json = res.json()
        except:
            pass

        if 'status' in entry and entry['status'] != res_status:
            err = '{}: status {} (expected {})\nbody: {}'.format(url, res_status, entry['status'], res_txt)
            print >> sys.stderr, err
            errors.append(err)

        if 'body' in entry and ((res_json is not None and entry['body'] != res_json) or (res_json is None and res_txt != entry['body'])):
            err = '{}: wrong body {} (expected {})'.format(url, res_txt, entry['body'])
            print >> sys.stderr, err
            errors.append(err)

        if 'body_json_partial' in entry:
            if not res_json:
                err = '{}: no json in {}'.format(url, res_txt)
                print >> sys.stderr, err
                errors.append(err)

            if not partial_compare(entry['body_json_partial'], res_json):
                err = '{}: wrong body {} (expected {})'.format(url, res_txt, entry['body_json_partial'])
                print >> sys.stderr, err
                errors.append(err)

    if len(errors) > 0:
        print >> sys.stderr, json.dumps(errors, indent=4)
        return False


def check( state_engine ):
    return True

