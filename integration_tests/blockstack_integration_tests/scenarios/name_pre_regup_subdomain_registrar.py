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
import blockstack.lib.subdomains as subdomains
import blockstack.lib.storage as storage
import blockstack.lib.client as client
import blockstack_zones
import base64
import requests
import os
import subprocess
import time
import sys
import traceback

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

base_name = "personal.test"

registrar_port = 31111

subdomain_registrar_config = """
{
  "winstonConsoleTransport": {
      "level": "debug",
      "handleExceptions": false,
      "timestamp": true,
      "stringify": true,
      "colorize": false,
      "json": false
  },
  "domainName": "%s",
  "ownerKey": "%s",
  "paymentKey": "%s",
  "batchDelayPeriod": 1,
  "checkTransactionPeriod": 1,
  "zonefileSize": 40960,
  "dbLocation": "%s/subdomain_registrar.db",
  "adminPassword": "hello_world",
  "domainUri": "http://localhost:%s",
  "port": %s,
  "ipLimit": 1,
  "apiKeys": ['test_registrar'],
  "proofsRequired": 0,
  "disableRegistrationsWithoutKey": false
}
""" % (base_name, wallets[3].privkey, wallets[2].privkey, os.environ.get('BLOCKSTACK_WORKING_DIR'), registrar_port, registrar_port)


SUBDOMAIN_PROC = None

SUBDOMAIN_REGISTRAR_LOCATION = os.environ.get('BSK_SUBDOMAIN_REGISTRAR_LOCATION',
                                              '/usr/bin/blockstack-subdomain-registrar')

def start_subdomain_registrar():
    global SUBDOMAIN_PROC
    # needs to exist 

    # write out config file
    working_dir = os.environ.get('BLOCKSTACK_WORKING_DIR')
    assert working_dir

    config_path = os.path.join(working_dir, 'subdomain_registrar.conf')
    with open(config_path, 'w') as f:
        f.write(subdomain_registrar_config)

    os.environ['BSK_SUBDOMAIN_CONFIG'] = config_path

    try:
        os.rename('/tmp/subdomain_registrar.db', '/tmp/subdomain_registrar.last')
        os.rename('/tmp/subdomain_registrar.log', '/tmp/subdomain_registrar.log.bak')
    except OSError:
        pass

    env = {'BSK_SUBDOMAIN_REGTEST' : '1', 'BSK_SUBDOMAIN_CONFIG': config_path}
    if os.environ.get('BLOCKSTACK_TEST_CLIENT_RPC_PORT', False):
        env['BLOCKSTACK_TEST_CLIENT_RPC_PORT'] = os.environ.get('BLOCKSTACK_TEST_CLIENT_RPC_PORT')

    fd = open('/tmp/subdomain_registrar.log', 'w+')
    SUBDOMAIN_PROC = subprocess.Popen(['node', SUBDOMAIN_REGISTRAR_LOCATION], stdout=fd, stderr=fd, env = env)

    is_up = False
    for i in range(0, 3):
        time.sleep(5)
        try:
            res = requests.get("http://localhost:{}/index".format(registrar_port))
            is_up = True
            break
        except Exception as e:
            traceback.print_exc()
            print >> sys.stderr, 'Subdomain registrar is not responding on localhost:{}, trying again...'.format(registrar_port)
            continue

    if not is_up:
        raise Exception('Subdomain registrar failed to start')

    testlib.add_cleanup(lambda: SUBDOMAIN_PROC.kill())


def scenario( wallets, **kw ):

    start_subdomain_registrar()

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_name_preorder( "personal.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )

    registrar_zf = '$ORIGIN personal.test\n$TTL 3600\n_registrar URI 10 1 "http://localhost:%s"\n_resolver URI 10 1 "http://localhost:%s"\n' % (registrar_port, registrar_port)
    registrar_zf_hash = storage.get_zonefile_data_hash(registrar_zf)

    testlib.blockstack_name_register( "personal.test", wallets[2].privkey, wallets[3].addr, zonefile_hash=registrar_zf_hash)
    testlib.next_block(**kw)

    testlib.blockstack_put_zonefile(registrar_zf)

    zf_template = "$ORIGIN {}\n$TTL 3600\n{}"
    zf_default_url = '_https._tcp URI 10 1 "https://raw.githubusercontent.com/nobody/content/profile.md"'

    # request to register hello_XXX.personal.test
    for i in range(0, 3):
        sub_name = 'hello_{}.personal.test'.format(i)
        sub_zf = zf_template.format(sub_name, zf_default_url)

        req_json = {
            'name': 'hello_{}'.format(i+1),
            'owner_address': virtualchain.address_reencode(wallets[i].addr, network='mainnet'),
            'zonefile': sub_zf,
        }

        resp = requests.post('http://localhost:{}/register'.format(registrar_port), json=req_json, headers={'Authorization': 'bearer test_registrar'})
        if resp.status_code != 202:
            print 'did not accept {}'.format(sub_name)
            print resp.text
            return False

    # try to resolve each name on the subdomain registrar
    for i in range(0, 3):
        sub_name = 'hello_{}.personal.test'.format(i)
        resp = requests.get('http://localhost:{}/status/{}'.format(registrar_port, sub_name))
        status = resp.json()

        print json.dumps(status, indent=4, sort_keys=True)

        if resp.status_code != 200:
            print 'not accepted: {}'.format(sub_name)
            return False

    # test /v1/names/{} emulation on the subdomain registrar
    for i in range(0, 3):
        sub_name = 'hello_{}.personal.test'.format(i)
        resp = requests.get('http://localhost:{}/v1/names/{}'.format(registrar_port, sub_name))
        status = resp.json()

        print json.dumps(status, indent=4, sort_keys=True)

        if 'pending_subdomain' != status['status']:
            print 'not pending: {}'.format(sub_name)
            return False

        if len(status['txid']) != 0:
            print 'not pending: {}'.format(sub_name)
            return False

    # test /v1/names/{} redirect from Blockstack Core
    for i in range(0, 3):
        sub_name = 'hello_{}.personal.test'.format(i)
        resp = requests.get('http://localhost:{}/v1/names/{}'.format(16268, sub_name))
        status = resp.json()

        print json.dumps(status, indent=4, sort_keys=True)

        if 'pending_subdomain' != status['status']:
            print 'not pending: {}'.format(sub_name)
            return False

        if len(status['txid']) != 0:
            print 'not pending: {}'.format(sub_name)
            return False

    # tell the registrar to flush the queue

    # reindex
    assert testlib.check_subdomain_db(**kw)


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

    name = 'personal.test'

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
