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
# activate STACKS Phase 1
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 682
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 683
TEST ENV BLOCKSTACK_EPOCH_3_END_BLOCK 684
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_4_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_PUBLIC_TESTNET 1
"""

import testlib
import virtualchain
import time
import json
import sys
import os
import BaseHTTPServer
import stun
import urlparse
import atexit
import subprocess
import socket
import threading
import traceback
import virtualchain
import cgi
import blockstack
import requests

log = virtualchain.get_logger('testnet')

wallets = [
    testlib.Wallet(virtualchain.lib.ecdsalib.ecdsa_private_key().to_wif(), 100000000000 ),
    testlib.Wallet(virtualchain.lib.ecdsalib.ecdsa_private_key().to_wif(), 100000000000 ),
    testlib.Wallet(virtualchain.lib.ecdsalib.ecdsa_private_key().to_wif(), 100000000000 ),
    testlib.Wallet(virtualchain.lib.ecdsalib.ecdsa_private_key().to_wif(), 1000000000000000000 ),
    testlib.Wallet(virtualchain.lib.ecdsalib.ecdsa_private_key().to_wif(), 100000000000 ),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

GAIA_READ_URL = None
GAIA_WRITE_URL = None
GAIA_READ_PORT = None
GAIA_WRITE_PORT = None


def scenario( wallets, **kw ):
    global GAIA_READ_URL
    global GAIA_READ_PORT
    global GAIA_WRITE_PORT
    global GAIA_WRITE_URL

    # get gaia hub info 
    with open(os.path.join(os.environ['BLOCKSTACK_WORKING_DIR'], 'gaia.conf'), 'r') as f:
        GAIA_CONF = json.loads(f.read().strip())

    try:
        GAIA_READ_PORT = urlparse.urlparse(GAIA_CONF['readURL']).netloc.split(':')[-1]
        GAIA_READ_PORT = int(GAIA_READ_PORT)
    except:
        GAIA_READ_PORT = 80

    if os.environ.get('BLOCKSTACK_PUBLIC_TESTNET_GAIA_READ_PORT'):
        GAIA_READ_PORT = int(os.environ['BLOCKSTACK_PUBLIC_TESTNET_GAIA_READ_PORT'])

    read_urlinfo = urlparse.urlparse(GAIA_CONF['readURL'])

    GAIA_READ_URL = 'http://{}:{}'.format(read_urlinfo.netloc.split(':')[0], GAIA_READ_PORT)

    GAIA_WRITE_PORT = GAIA_CONF['port']
    if os.environ.get('BLOCKSTACK_PUBLIC_TESTNET_GAIA_WRITE_PORT'):
        GAIA_WRITE_PORT = int(os.environ['BLOCKSTACK_PUBLIC_TESTNET_GAIA_WRITE_PORT'])

    GAIA_WRITE_URL = 'http://{}:{}'.format(GAIA_CONF['servername'], GAIA_WRITE_PORT)

    # fill in URL 
    tb_conf_path = os.path.join(os.environ['BLOCKSTACK_WORKING_DIR'], 'transaction-broadcaster.conf')
    with open(tb_conf_path, 'r') as f:
        tb_conf = json.loads(f.read().strip())

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, -1, 250, 4, [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=3)
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_register_user('foo.test', wallets[3].privkey, wallets[2].privkey, **kw)

    # patch the profile to insert an app URL 
    res = testlib.blockstack_cli_lookup('foo.test')
    profile = res['profile']
    print profile

    assert profile

    profile['apps'] = {
        'http://www.testapp.com': '{}/hub/{}'.format(GAIA_READ_URL, virtualchain.address_reencode(wallets[4].addr, network='mainnet')),
    }

    profile_jwt = testlib.blockstack_make_profile(profile, wallets[2].privkey)
    res = testlib.blockstack_put_profile('foo.test', profile_jwt, wallets[2].privkey, GAIA_WRITE_URL)
    if 'error' in res:
        print res
        return False

    # store a bunch of data to Gaia
    tmpdir = os.path.join(os.environ['BLOCKSTACK_WORKING_DIR'], 'gaia_inputs')
    os.makedirs(tmpdir)

    count = 3
    for i in range(0, count):
        path = os.path.join(tmpdir, 'gaia-{}.txt'.format(i))
        with open(path, 'w') as f:
            f.write('gaia data {}'.format(i))

        encrypted_path = os.path.join(tmpdir, 'gaia-{}-encrypted.txt'.format(i))
        with open(encrypted_path, 'w') as f:
            f.write('gaia encrypted data {}'.format(i))

        print '\n\nputfile {}\n\n'.format(path)
        testlib.blockstack_gaia_putfile(wallets[4].privkey[:64], path, '/gaia-{}.txt'.format(i), GAIA_WRITE_URL, encrypt=False, sign=False)
        testlib.blockstack_gaia_putfile(wallets[4].privkey[:64], encrypted_path, '/gaia-{}-encrypted.txt'.format(i), GAIA_WRITE_URL, encrypt=True)
        testlib.blockstack_gaia_putfile(wallets[4].privkey[:64], path, '/gaia-{}-signed.txt'.format(i), GAIA_WRITE_URL, encrypt=False, sign=True)
        testlib.blockstack_gaia_putfile(wallets[4].privkey[:64], encrypted_path, '/gaia-{}-encrypted-signed.txt'.format(i), GAIA_WRITE_URL, encrypt=True, sign=True)

    # make sure they're all there
    res = testlib.blockstack_gaia_listfiles(wallets[4].privkey[:64], GAIA_WRITE_URL)
    if len(res) != 5 * count:
        print json.dumps(res, indent=4, sort_keys=True)
        print 'wrong number of files: {}'.format(len(res))
        return False

    for i in range(0, count):
        for filename in ['gaia-{}.txt'.format(i), 'gaia-{}-encrypted.txt'.format(i), 'gaia-{}-signed.txt'.format(i), 'gaia-{}-signed.txt.sig'.format(i), 'gaia-{}-encrypted-signed.txt'.format(i)]:
            if filename not in res:
                print json.dumps(res, indnet=4, sort_keys=True)
                print 'missing {}'.format(filename)
                return False

    # make sure we can get them all 
    for i in range(0, count):
        for filename in ['gaia-{}.txt'.format(i), 'gaia-{}-encrypted.txt'.format(i), 'gaia-{}-signed.txt'.format(i), 'gaia-{}-encrypted-signed.txt'.format(i)]:
            verify = 'signed' in filename
            decrypt = 'encrypted' in filename
            privkey = wallets[4].privkey[:64] if verify or decrypt else None
            expected_data = 'gaia encrypted data {}'.format(i) if decrypt else 'gaia data {}'.format(i)

            res = testlib.blockstack_gaia_getfile('foo.test', 'http://www.testapp.com', '/{}'.format(filename), privkey=privkey, verify=verify, decrypt=decrypt)
            if res != expected_data:
                print 'expected\n{}'.format(expected_data)
                print 'got\n{}'.format(res)

                import time
                time.sleep(1000000)
                return False


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

    for name in ['foo.test']:
        name_info = testlib.nodejs_cli('whois', name)
        name_info = json.loads(name_info)
        if 'error' in name_info:
            print name_info
            return False

        if name_info['address'] != wallets[2].addr:
            print 'wrong address; expected {}'.format(wallets[2].addr)
            print name_info
            return False

        if 'http://localhost:4000' not in name_info['zonefile']:
            print 'wrong zone file; expected http://localhost:4000'
            print name_info
            return False

        profile = testlib.nodejs_cli('lookup', name)
        profile = json.loads(profile)
        if 'error' in profile:
            print profile
            return False

        if not profile['zonefile']:
            print 'no zonefile'
            print profile
            return False

        if not profile['profile']:
            print 'no profile'
            print profile
            return False

    return True
