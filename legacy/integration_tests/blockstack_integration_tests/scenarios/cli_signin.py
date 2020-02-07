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

owner_privkey = None
owner_address = None

def scenario( wallets, **kw ):
    global GAIA_READ_URL
    global GAIA_READ_PORT
    global GAIA_WRITE_PORT
    global GAIA_WRITE_URL
    global owner_privkey
    global owner_address

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

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, -1, 250, 4, [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=1)
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    # register this user under a keychain 
    res = testlib.nodejs_cli('make_keychain')
    res = json.loads(res)
    mnemonic = res['mnemonic']
    owner_privkey = res['ownerKeyInfo']['privateKey']
    owner_address = res['ownerKeyInfo']['idAddress'][3:]

    profile = {
        'type': '@Person',
        'account': [],
        'name': 'Testy McTestface',
    }

    testlib.blockstack_register_user('foo.test', wallets[3].privkey, owner_privkey, profile=profile, **kw)

    print ""
    print "mnemnic: {}".format(mnemonic)
    print "hub url: {}".format(GAIA_WRITE_URL)
    print ""


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

    return True
