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
"""
TEST ENV CLIENT_STORAGE_DRIVERS test
TEST ENV CLIENT_STORAGE_DRIVERS_REQUIRED_WRITE test
"""

import os
import testlib
import pybitcoin
import urllib2
import json
import blockstack_client
import blockstack_profiles
import sys
import errno
import keylib

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

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
wallet_keys = None
error = False
index_file_data = "<html><head></head><body>foo.test hello world</body></html>"

def scenario( wallets, **kw ):

    global wallet_keys, error, index_file_data, resource_data

    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )
    wallet_keys = blockstack_client.make_wallet_keys( owner_privkey=wallets[3].privkey, data_privkey=wallets[4].privkey, payment_privkey=wallets[5].privkey )
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] )
    testlib.start_api("0123456789abcdef")
    
    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )
    
    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.next_block( **kw )
    
    # migrate profiles 
    res = testlib.migrate_profile( "foo.test", proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in res:
        res['test'] = 'Failed to initialize foo.test profile'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 
    
    res = testlib.start_api("0123456789abcdef")
    if 'error' in res:
        print 'failed to start API: {}'.format(res)
        return False

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()

    testlib.next_block( **kw )

    # sign in and make a token
    datastore_pk = keylib.ECPrivateKey(wallets[-1].privkey).to_hex()
    res = testlib.blockstack_cli_app_signin("foo.test", datastore_pk, 'http://localhost.1:8888', ['store_read', 'store_write', 'store_admin'])
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 
 
    # sign in and make a token, again (confirm keyfile works)
    datastore_pk = keylib.ECPrivateKey(wallets[-1].privkey).to_hex()
    res = testlib.blockstack_cli_app_signin("foo.test", datastore_pk, 'http://localhost.1:8888', ['store_read', 'store_write', 'store_admin'])
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    # export to environment
    blockstack_client.set_secret("BLOCKSTACK_API_SESSION", res['token'])
    ses = res['token']

    # require that we only use URLs in the device root pages
    res = testlib.blockstack_test_setenv("TEST_BLOCKSTACK_TEST_URLS_ONLY", "1")
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        return False

    print 'session:'
    print ses

    app_name = 'localhost.1:8888'

    # use random data for file
    file_data = None
    with open('/dev/urandom', 'r') as f:
        file_data = f.read(16384)

    # make datastore 
    res = testlib.blockstack_cli_create_datastore( datastore_pk, ['test'], ses )
    if 'error' in res:
        print "failed to create datastore: {}".format(res['error'])
        return False
    
    # put files 
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'putfile {}'.format(dpath)
        data = '{} hello {}'.format(file_data, dpath)
        res = testlib.blockstack_cli_datastore_putfile( datastore_pk, dpath, data, ses )
        if 'error' in res:
            print 'failed to putfile {}: {}'.format(dpath, res['error'])
            return False
 
    # list files (should all be present)
    print 'listroot'
    res = testlib.blockstack_cli_datastore_listfiles('foo.test', app_name)
    if 'error' in res:
        print 'listfiles failed'
        print res
        return False

    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        if dpath not in res['root']:
            print 'missing {}'.format(dpath)
            print res
            return False

    # stat files
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'stat {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_stat( "foo.test", None, dpath, app_name=app_name )
        if 'error' in res:
            print 'failed to stat {}: {}'.format(dpath, res['error'])
            return False

    # get files
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'getfile {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_getfile( "foo.test", None, dpath, app_name=app_name )
        if 'error' in res:
            print 'failed to getfile {}: {}'.format(dpath, res['error'])
            return False

        if res != '{} hello {}'.format(file_data, dpath):
            print 'failed to read {}'.format(dpath)
            return False

    # put files again! 
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'putfile {}'.format(dpath)
        data = '{} hello 2 {}'.format(file_data, dpath)
        res = testlib.blockstack_cli_datastore_putfile( datastore_pk, dpath, data, ses )
        if 'error' in res:
            print 'failed to putfile {}: {}'.format(dpath, res['error'])
            return False

    # get files again!
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'getfile {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_getfile( "foo.test", None, dpath, app_name=app_name )
        if 'error' in res:
            print 'failed to getfile {}: {}'.format(dpath, res['error'])
            return False

        if res != '{} hello 2 {}'.format(file_data, dpath):
            print 'failed to read {}'.format(dpath)
            return False

    # remove files
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'deletefile {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_deletefile( datastore_pk, dpath, ses )
        if 'error' in res:
            print 'failed to deletefile {}: {}'.format(dpath, res['error'])
            return False

    # stat files (should all fail)
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'stat {} (expect failure)'.format(dpath)
        res = testlib.blockstack_cli_datastore_stat( "foo.test", None, dpath, app_name=app_name )
        if 'error' not in res or 'errno' not in res:
            print 'accidentally succeeded to stat {}: {}'.format(dpath, res)
            return False

        if res['errno'] != "ENOENT":
            print 'wrong errno: {}'.format(res)
            return False

    # get files (should all fail)
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'getfile {} (expect failure)'.format(dpath)
        res = testlib.blockstack_cli_datastore_getfile( "foo.test", None, dpath, app_name=app_name )
        if 'error' not in res or 'errno' not in res:
            print 'accidentally succeeded to get {}: {}'.format(dpath, res)
            return False

        if res['errno'] != "ENOENT":
            print 'wrong errno: {}'.format(res)
            return False

    # list files (should all be absent)
    print 'listroot'
    res = testlib.blockstack_cli_datastore_listfiles('foo.test', app_name)
    if 'error' in res:
        print 'listfiles failed'
        print res
        return False

    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        if dpath in res['root']:
            print 'still present: {}'.format(dpath)
            print res
            return False

    # delete datastore
    print 'delete datastore'
    res = testlib.blockstack_cli_delete_datastore( datastore_pk, ses )
    if 'error' in res:
        print 'failed to delete datastore'
        print json.dumps(res)
        return False

    # no more data in test driver
    names = os.listdir("/tmp/blockstack-integration-test-storage/mutable")
    if names != ['foo.test']:
        print 'improper cleanup'
        return False

    testlib.next_block( **kw )


def check( state_engine ):

    global wallet_keys, error

    if error:
        print "Key operation failed."
        return False

    # not revealed, but ready
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is not None:
        print "namespace not ready"
        return False

    ns = state_engine.get_namespace( "test" )
    if ns is None:
        print "no namespace"
        return False

    if ns['namespace_id'] != 'test':
        print "wrong namespace"
        return False

    names = ['foo.test']
    wallet_keys_list = [wallet_keys]
    test_proxy = testlib.TestAPIProxy()

    for i in xrange(0, len(names)):
        name = names[i]
        wallet_payer = 3 * (i+1) - 1
        wallet_owner = 3 * (i+1)
        wallet_data_pubkey = 3 * (i+1) + 1
        wallet_keys = wallet_keys_list[i]

        # not preordered
        preorder = state_engine.get_name_preorder( name, pybitcoin.make_pay_to_address_script(wallets[wallet_payer].addr), wallets[wallet_owner].addr )
        if preorder is not None:
            print "still have preorder"
            return False

        # registered
        name_rec = state_engine.get_name( name )
        if name_rec is None:
            print "name does not exist"
            return False

        # owned
        if name_rec['address'] != wallets[wallet_owner].addr or name_rec['sender'] != pybitcoin.make_pay_to_address_script(wallets[wallet_owner].addr):
            print "name has wrong owner"
            return False

        # try to authenticate

    return True
