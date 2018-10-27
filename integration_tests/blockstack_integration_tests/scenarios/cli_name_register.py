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
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

SUBDOMAIN_DOMAIN = "subdomains.test"
SUBDOMAIN_OWNER_KEY = wallets[3].privkey
SUBDOMAIN_PAYMENT_KEY = wallets[2].privkey
SUBDOMAIN_ADMIN_PASSWORD = os.urandom(16).encode('hex')
SUBDOMAIN_OWNER_ADDRESS = wallets[2].addr
SUBDOMAIN_REGISTRAR_PORT = 30000
SUBDOMAIN_PROC = None

SUBDOMAIN_REGISTRAR_CONFIG = None
GAIA_READ_URL = None
GAIA_WRITE_URL = None
GAIA_READ_PORT = None
GAIA_WRITE_PORT = None

SUBDOMAIN_REGISTRAR_URL = 'http://localhost:{}'.format(SUBDOMAIN_REGISTRAR_PORT)

def start_subdomain_registrar():
    global SUBDOMAIN_PROC
    global SUBDOMAIN_REGISTRAR_CONFIG

    # send batches every 30 seconds
    # check transactions every second
    SUBDOMAIN_REGISTRAR_CONFIG = """
    {
      "winstonConsoleTransport": {
          "level": "debug",
          "handleExceptions": false,
          "timestamp": true,
          "stringify": true,
          "colorize": true,
          "json": false
      },
      "domainName": "%s",
      "ownerKey": "%s",
      "paymentKey": "%s",
      "batchDelayPeriod": 0.5,
      "checkTransactionPeriod": 0.5,
      "dbLocation": "%s/subdomain_registrar.db",
      "adminPassword": "%s",
      "domainUri": "%s/%s/profile.json",
      "zonefileSize": 40960,
      "development": false,
      "port": %s,
      "regtest": true,
      "ipLimit": 0,
      "apiKeys": [],
      "proofsRequired": 0,
      "disableRegistrationsWithoutKey": false
    }
    """ % (SUBDOMAIN_DOMAIN, SUBDOMAIN_OWNER_KEY, SUBDOMAIN_PAYMENT_KEY, os.environ['BLOCKSTACK_WORKING_DIR'], SUBDOMAIN_ADMIN_PASSWORD, GAIA_READ_URL, SUBDOMAIN_OWNER_ADDRESS, SUBDOMAIN_REGISTRAR_PORT)

    subdomain_registrar_config_path = os.path.join(os.environ['BLOCKSTACK_WORKING_DIR'], 'subdomain-registrar.conf')
    with open(subdomain_registrar_config_path, 'w') as f:
        f.write(SUBDOMAIN_REGISTRAR_CONFIG.strip())

    subdomain_log_path = os.path.join(os.environ['BLOCKSTACK_WORKING_DIR'], 'subdomain-registrar.log')
    subdomain_stdout = open(subdomain_log_path, 'w')
    subdomain_stderr = open(subdomain_log_path, 'w')

    subdomain_registrar_path_proc = subprocess.Popen('which blockstack-subdomain-registrar', shell=True, stdout=subprocess.PIPE, stderr=None)
    out, _ = subdomain_registrar_path_proc.communicate()
    if subdomain_registrar_path_proc.returncode != 0:
        print 'which blockstack-subdomain-registrar exited {}'.format(subdomain_registrar_path_proc.returncode)
        return False

    subdomain_registrar_path = out.strip()

    os.environ['BSK_SUBDOMAIN_CONFIG'] = subdomain_registrar_config_path 
    SUBDOMAIN_PROC = subprocess.Popen([subdomain_registrar_path, 'start', SUBDOMAIN_DOMAIN], shell=False, stdout=subdomain_stdout, stderr=subdomain_stderr)

    testlib.add_cleanup(stop_subdomain_registrar)
    return True


def stop_subdomain_registrar():
    global SUBDOMAIN_PROC

    try:
        if SUBDOMAIN_PROC is not None:
            SUBDOMAIN_PROC.kill()
            SUBDOMAIN_PROC = None

        print 'killed subdomain registrar'

    except:
        traceback.print_exc()
        pass


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

    # import a name with the CLI 
    res = testlib.nodejs_cli('name_import', 'hello_imports.test', 'ID-{}'.format(wallets[3].addr), 'http://localhost:4000/hub', wallets[1].privkey)
    if 'error' in res:
        print res
        return False

    # need to wait 7 blocks
    for i in range(0, 7):
        testlib.next_block(**kw)
    
    print ''
    print 'waiting 10 seconds for name_import to complete'
    print ''
    time.sleep(10)

    # sign and store a profile for hello_imports.test
    profile_data = testlib.blockstack_make_profile({'type': '@Person', 'account': []}, wallets[3].privkey)
    testlib.blockstack_put_profile('hello_imports.test', profile_data, wallets[3].privkey, 'http://localhost:4001')

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_register_user(SUBDOMAIN_DOMAIN, SUBDOMAIN_PAYMENT_KEY, SUBDOMAIN_OWNER_KEY, **kw)
    
    # TODO do not SNV-check or DID-check this name for now, since we have no way to record the API call to registering hello_imports.test
    testlib.expect_snv_fail_at(SUBDOMAIN_DOMAIN, testlib.get_current_block(**kw))
    testlib.expect_snv_fail_at(SUBDOMAIN_DOMAIN, testlib.get_current_block(**kw)-1)
    testlib.expect_snv_fail_at(SUBDOMAIN_DOMAIN, testlib.get_current_block(**kw)-2)
    
    rc = start_subdomain_registrar()
    if not rc:
        print 'failed to start subdomain registrar'
        return False

    print ''
    print 'waiting 10 seconds for subdomain registrar to start up'
    print ''
    time.sleep(10)

    # register a subdomain
    res = testlib.nodejs_cli('register_subdomain', 'hello.subdomains.test', wallets[3].privkey, 'http://localhost:4001', 'http://localhost:{}'.format(SUBDOMAIN_REGISTRAR_PORT))
    if 'error' in res:
        print res
        return False

    # should resolve instantly 
    res = requests.get('http://localhost:{}/v1/names/hello.subdomains.test'.format(SUBDOMAIN_REGISTRAR_PORT))
    if res.status_code != 200:
        print res.text
        return False

    resp = res.json()
    if 'error' in resp:
        print resp
        return False

    if virtualchain.address_reencode(str(resp['address'])) != virtualchain.address_reencode(str(wallets[3].addr)):
        print 'wrong address'
        print resp
        print virtualchain.address_reencode(str(resp['address']))
        print virtualchain.address_reencode(wallets[3].addr)
        return False

    # need to wait 12 blocks 
    for i in range(0, 12):
        testlib.next_block(**kw)

    print ''
    print 'waiting 10 seconds for register-subdomain to complete'
    print ''
    time.sleep(10)

    # register a name with the CLI 
    print ''
    print 'Registering hello.test with the CLI'
    print ''
    
    res = testlib.nodejs_cli('register', 'hello.test', wallets[3].privkey, wallets[2].privkey, 'http://localhost:4001')
    res = json.loads(res)
    if 'error' in res and res['error']:
        print res
        return False

    # can no longer accurately trace debits/credits, since we don't control when the transactions get sent
    testlib.set_account_audits(False)

    # need to wait 12 blocks 
    for i in range(0, 12):
        testlib.next_block(**kw)

    print ''
    print 'waiting 10 seconds for register to complete, and registering hello2.test'
    print ''
    time.sleep(10)

    res = testlib.nodejs_cli('register_addr', 'hello2.test', 'ID-{}'.format(wallets[3].addr), wallets[2].privkey, 'http://localhost:4000/hub')
    res = json.loads(res)
    if 'error' in res:
        print res
        return False

    # need to wait 12 blocks 
    for i in range(0, 12):
        testlib.next_block(**kw)

    print ''
    print 'waiting 10 seconds for register-addr to complete, and registering hello3.test'
    print ''
    time.sleep(10)

    # sign and store a profile for hello2.test
    profile_data = testlib.blockstack_make_profile({'type': '@Person', 'account': []}, wallets[3].privkey)
    testlib.blockstack_put_profile('hello2.test', profile_data, wallets[3].privkey, 'http://localhost:4001')
    
    stop_subdomain_registrar()

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

    for name in ['hello_imports.test', 'hello.test', 'hello2.test', 'hello.subdomains.test']:
        name_info = testlib.nodejs_cli('whois', name)
        name_info = json.loads(name_info)
        if 'error' in name_info:
            print name_info
            return False

        if name_info['address'] != wallets[3].addr:
            print 'wrong address; expected {}'.format(wallets[3].addr)
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
