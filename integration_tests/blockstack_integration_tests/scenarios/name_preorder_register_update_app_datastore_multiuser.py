#!/usr/bin/env python
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
os.environ["CLIENT_STORAGE_DRIVERS"] = "test"
os.environ["CLIENT_STORAGE_DRIVERS_REQUIRED_WRITE"] = "test"

"""
TEST ENV CLIENT_STORAGE_DRIVERS test
TEST ENV CLIENT_STORAGE_DRIVERS_REQUIRED_WRITE test
"""

import testlib
import pybitcoin
import urllib2
import json
import blockstack_client
import blockstack_profiles
import sys
import errno
import keylib
import base64
import shutil
import jsontokens

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
wallet_keys = None      # for foo.test
wallet_keys_2 = None    # for bar.test
wallet_keychain = {}    # map foo.test, bar.test
error = False
index_file_data = "<html><head></head><body>foo.test hello world</body></html>"
file_data = None

sessions = {}

def get_data_pubkeys(blockchain_id):
    """
    Get device IDs and public keys for a blockchain ID
    TODO: load these from the token file
    """
    ses = sessions[blockchain_id]
    session = jsontokens.decode_token(ses)['payload']

    device_ids = [dk['device_id'] for dk in session['app_public_keys']]
    device_pubkeys = [dk['public_key'] for dk in session['app_public_keys']]

    data_pubkeys = [{
        'device_id': dev_id,
        'public_key': pubkey,
    } for (dev_id, pubkey) in zip(device_ids, device_pubkeys)]

    print "\ndata public keys for {} are\n{}\n".format(blockchain_id, json.dumps(data_pubkeys, indent=4, sort_keys=True))
    return data_pubkeys


def setup_env(session, blockchain_id):
    
    # export to environment 
    blockstack_client.set_secret("BLOCKSTACK_API_SESSION", session)
    res = testlib.blockstack_test_setenv("TEST_BLOCKSTACK_TEST_INDEXED_STORAGE", "1")
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        return False

    res = testlib.blockstack_test_setenv("TEST_BLOCKSTACK_TEST_DISK_ROOT", "/tmp/blockstack-integration-test-storage-{}".format(blockchain_id))
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        return False

    return True


def activate_account(blockchain_id, datastore_pk):
    
    global sessions

    wk = wallet_keychain.get(blockchain_id)
    assert wk, 'no wallet for {}'.format(blockchain_id)
    
    testlib.stop_api()
    testlib.blockstack_client_set_wallet( '0123456789abcdef', wk['payment_privkey'], wk['owner_privkey'], wk['data_privkey'])
    res = testlib.start_api('0123456789abcdef')
    if 'error' in res:
        print 'failed to start API for foo.test: {}'.format(res)
        return False

    # sign in and make a token with the given blockchain ID (whose wallet must be currently set)
    res = testlib.blockstack_cli_app_signin(blockchain_id, datastore_pk, 'app.com', ['store_read', 'store_write', 'store_admin'])
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        return False

    sessions[blockchain_id] = res['token']

    # export to environment 
    res = setup_env(res['token'], blockchain_id)
    if not res:
        print 'failed to setup env'
        return False

    return True


def core_signin(datastore_pk, blockchain_id):
    
    global sessions

    # sign in and make a token with the given blockchain ID (whose wallet must be currently set)
    res = testlib.blockstack_cli_app_signin(blockchain_id, datastore_pk, 'app.com', ['store_read', 'store_write', 'store_admin'])
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        return False

    sessions[blockchain_id] = res['token']

    # export to environment 
    res = setup_env(res['token'], blockchain_id)
    if not res:
        print 'failed to setup env'
        return False

    datastore_id_res = testlib.blockstack_cli_datastore_get_id( datastore_pk )
    datastore_id = datastore_id_res['datastore_id']
    
    return datastore_id


def target_datastore(blockchain_id):
    # point to a particular user's datastore
    if blockchain_id is None:
        blockchain_id = ''
    else:
        blockchain_id = '-{}'.format(blockchain_id)

    res = testlib.blockstack_test_setenv("TEST_BLOCKSTACK_TEST_DISK_ROOT", "/tmp/blockstack-integration-test-storage{}".format(blockchain_id))
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        return False
    
    os.environ['TEST_BLOCKSTACK_TEST_DISK_ROOT'] = '/tmp/blockstack-integration-test-storage{}'.format(blockchain_id)


def setup_datastore(datastore_pk, blockchain_id, write_iteration):

    global sessions

    datastore_id = core_signin(datastore_pk, blockchain_id)
    if not datastore_id:
        print 'failed to sign in with {}, by {}'.format(datastore_pk, blockchain_id)
        return False
    
    ses = sessions[blockchain_id]

    # make datastore 
    res = testlib.blockstack_cli_create_datastore( blockchain_id, datastore_pk, ['test'], ses)
    if 'error' in res:
        print "failed to create datastore: {}".format(res['error'])
        return False

    # make directories
    for dpath in ['/dir1', '/dir2', '/dir1/dir3', '/dir1/dir3/dir4']:
        print 'mkdir {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_mkdir( blockchain_id, datastore_pk, dpath, ses)
        if 'error' in res:
            print 'failed to mkdir {}: {}'.format(dpath, res['error'])
            return False

    # make directories again (should fail with EEXIST)
    for dpath in ['/dir1', '/dir2', '/dir1/dir3', '/dir1/dir3/dir4']:
        print 'mkdir {} (should fail)'.format(dpath)
        res = testlib.blockstack_cli_datastore_mkdir( blockchain_id, datastore_pk, dpath, ses )
        if 'error' not in res:
            print 'accidentally succeeded to mkdir {}: {}'.format(dpath, res)
            return False

        if not res.has_key('errno'):
            print 'no errno in error {}'.format(res)
            return False

        if res['errno'] != errno.EEXIST:
            print 'wrong errno in error {}'.format(res)
            return False

    # stat directories 
    for dpath in ['/dir1', '/dir2', '/dir1/dir3', '/dir1/dir3/dir4']:
        print 'stat {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_stat( blockchain_id, datastore_id, dpath, ses)
        if 'error' in res:
            print 'failed to stat {}: {}'.format(dpath, res['error'])
            return False

        if res['type'] != blockstack_client.schemas.MUTABLE_DATUM_DIR_TYPE:
            print 'not a directory: {}, {}'.format(dpath, res)
            return False

    # list directories 
    for dpath, expected in [('/', ['dir1', 'dir2']), ('/dir1', ['dir3']), ('/dir1/dir3', ['dir4']), ('/dir1/dir3/dir4', [])]:
        print 'listdir {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_listdir( blockchain_id, datastore_id, dpath, ses)
        if 'error' in res:
            print 'failed to listdir {}: {}'.format(dpath, res['error'])
            return False

        print res
        if len(res['children'].keys()) != len(expected):
            print 'invalid directory: expected:\n{}\ngot:\n{}\n'.format(expected, res)
            return False

        for child in expected: 
            if not res['children'].has_key(child):
                print 'invalid directory: missing {} in {}'.format(child, res)
                return False

    # put files
    res = write_datastore(blockchain_id, datastore_pk, write_iteration)
    if not res:
        print 'failed to write files (iteration {}) to {}'.format(write_iteration, datastore_id)
        return False

    # read everything to be sure it's there
    res = read_datastore(datastore_id, blockchain_id, write_iteration)
    if not res:
        print 'failed to read datastore {} from {}'.format(datastore_id, blockchain_id)
        return False

    return True


def write_datastore(blockchain_id, datastore_pk, iteration):
    """
    write some files to the datastore, over existing ones
    """
    global sessions
    ses = sessions[blockchain_id]

    # put files again! 
    for dpath in ['/file1', '/file2', '/dir1/file3', '/dir1/dir3/file4', '/dir1/dir3/dir4/file5']:
        print 'putfile {}'.format(dpath)
        data = '{} hello {} {}'.format(file_data, iteration, dpath)
        res = testlib.blockstack_cli_datastore_putfile( blockchain_id, datastore_pk, dpath, data, ses)
        if 'error' in res:
            print 'failed to putfile {}: {}'.format(dpath, res['error'])
            return False

    return True


def read_datastore(datastore_id, blockchain_id, expected_iteration):
    """
    Read tests on a particular blockchain ID's datastores
    """

    data_pubkeys = get_data_pubkeys(blockchain_id)

    # stat files
    for dpath in ['/file1', '/file2', '/dir1/file3', '/dir1/dir3/file4', '/dir1/dir3/dir4/file5']:
        print 'stat {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_stat( blockchain_id, datastore_id, dpath, data_pubkeys=data_pubkeys)
        if 'error' in res:
            print 'failed to stat {}: {}'.format(dpath, res['error'])
            return False

        if res['type'] != blockstack_client.schemas.MUTABLE_DATUM_FILE_TYPE:
            print 'not a file: {}, {}'.format(dpath, res)
            return False

    # list directories again 
    for dpath, expected in [('/', ['dir1', 'dir2', 'file1', 'file2']), ('/dir1', ['dir3', 'file3']), ('/dir1/dir3', ['dir4', 'file4']), ('/dir1/dir3/dir4', ['file5'])]:
        print 'listdir {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_listdir( blockchain_id, datastore_id, dpath, data_pubkeys=data_pubkeys)
        if 'error' in res:
            print 'failed to listdir {}: {}'.format(dpath, res['error'])
            return False

        if len(res['children'].keys()) != len(expected):
            print 'invalid directory: expected:\n{}\ngot:\n{}\n'.format(expected, res)
            return False

        for child in expected: 
            if not res['children'].has_key(child):
                print 'invalid directory: missing {} in {}'.format(child, res)
                return False
     
    # get files
    for dpath in ['/file1', '/file2', '/dir1/file3', '/dir1/dir3/file4', '/dir1/dir3/dir4/file5']:
        print 'getfile {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_getfile( blockchain_id, datastore_id, dpath, data_pubkeys=data_pubkeys)
        if 'error' in res:
            print 'failed to getfile {}: {}'.format(dpath, res['error'])
            return False

        if res != '{} hello {} {}'.format(file_data, expected_iteration, dpath):
            print 'failed to read {}'.format(dpath)
            return False

    return True


def clear_datastore_files(blockchain_id, datastore_pk):
    """
    Remove all files from the datastore
    """
    global sessions
    ses = sessions[blockchain_id]

    # remove files
    for dpath in ['/file1', '/file2', '/dir1/file3', '/dir1/dir3/file4', '/dir1/dir3/dir4/file5']:
        print 'deletefile {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_deletefile( blockchain_id, datastore_pk, dpath, ses)
        if 'error' in res:
            print 'failed to deletefile {}: {}'.format(dpath, res['error'])
            return False
    
    return True


def check_datastore_files_absent(datastore_id, blockchain_id):
    """
    Verify that all files are gone
    """
    data_pubkeys = get_data_pubkeys(blockchain_id)

    # stat files (should all fail)
    for dpath in ['/file1', '/file2', '/dir1/file3', '/dir1/dir3/file4', '/dir1/dir3/dir4/file5']:
        print 'stat {} (expect failure)'.format(dpath)
        res = testlib.blockstack_cli_datastore_stat( blockchain_id, datastore_id, dpath, data_pubkeys=data_pubkeys)
        if 'error' not in res or 'errno' not in res:
            print 'accidentally succeeded to stat {}: {}'.format(dpath, res)
            return False

        if res['errno'] != errno.ENOENT:
            print 'wrong errno: {}'.format(res)
            return False
 
    # get files (should all fail)
    for dpath in ['/file1', '/file2', '/dir1/file3', '/dir1/dir3/file4', '/dir1/dir3/dir4/file5']:
        print 'getfile {} (expect failure)'.format(dpath)
        res = testlib.blockstack_cli_datastore_getfile( blockchain_id, datastore_id, dpath, data_pubkeys=data_pubkeys)
        if 'error' not in res or 'errno' not in res:
            print 'accidentally succeeded to get {}: {}'.format(dpath, res)
            return False

        if res['errno'] != errno.ENOENT:
            print 'wrong errno: {}'.format(res)
            return False

    # list directories, 3rd time 
    for dpath, expected in [('/', ['dir1', 'dir2']), ('/dir1', ['dir3']), ('/dir1/dir3', ['dir4']), ('/dir1/dir3/dir4', [])]:
        print 'listdir {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_listdir( blockchain_id, datastore_id, dpath, data_pubkeys=data_pubkeys)
        if 'error' in res:
            print 'failed to listdir {}: {}'.format(dpath, res['error'])
            return False

        if len(res['children'].keys()) != len(expected):
            print 'invalid directory: expected:\n{}\ngot:\n{}\n'.format(expected, res)
            return False

        for child in expected: 
            if not res['children'].has_key(child):
                print 'invalid directory: missing {} in {}'.format(child, res)
                return False

    return True


def clear_datastore_directories(blockchain_id, datastore_pk):
    """
    Clear out the directories of a datastore
    """
    global sessions
    ses = sessions[blockchain_id]

    # remove directories 
    for dpath in ['/dir1/dir3/dir4', '/dir1/dir3', '/dir2', '/dir1']:
        print 'rmdir {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_rmdir( blockchain_id, datastore_pk, dpath, ses)
        if 'error' in res:
            print 'failed to rmdir {}: {}'.format(dpath, res['error'])
            return False

    return True


def check_datastore_directories_absent(datastore_id, blockchain_id):
    """
    Verify that the directories are gone
    """
    
    data_pubkeys = get_data_pubkeys(blockchain_id)

    # stat directories (should all fail)
    for dpath in ['/dir1/dir3/dir4', '/dir1/dir3', '/dir2', '/dir1']:
        print 'stat {} (expect failure)'.format(dpath)
        res = testlib.blockstack_cli_datastore_stat( blockchain_id, datastore_id, dpath, data_pubkeys=data_pubkeys)
        if 'error' not in res or 'errno' not in res:
            print 'accidentally succeeded to stat {}: {}'.format(dpath, res)
            return False

        if res['errno'] != errno.ENOENT:
            print 'wrong errno: {}'.format(res)
            return False

    # list directories (should all fail) 
    for dpath, expected in [('/dir1', ['dir3']), ('/dir1/dir3', ['dir4']), ('/dir1/dir3/dir4', [])]:
        print 'listdir {} (expect failure)'.format(dpath)
        res = testlib.blockstack_cli_datastore_listdir( blockchain_id, datastore_id, dpath, data_pubkeys=data_pubkeys)
        if 'error' not in res or 'errno' not in res:
            print 'accidentally succeeded to list {}: {}'.format(dpath, res)
            return False

        if res['errno'] != errno.ENOENT:
            print 'wrong errno: {}'.format(res)
            return False

    return True


def setup_storage_dirs(blockchain_ids):
    # set up storage directories
    for blockchain_id in blockchain_ids:
        if not os.path.exists("/tmp/blockstack-integration-test-storage-{}".format(blockchain_id)):
            os.makedirs("/tmp/blockstack-integration-test-storage-{}/immutable".format(blockchain_id))
            os.makedirs("/tmp/blockstack-integration-test-storage-{}/mutable".format(blockchain_id))


def scenario( wallets, **kw ):

    global wallet_keys, wallet_keys_2, wallet_keychain, error, index_file_data, resource_data, sessions

    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )
    
    wallet_keys_2 = blockstack_client.make_wallet_keys( owner_privkey=wallets[4].privkey, data_privkey=wallets[5].privkey, payment_privkey=wallets[3].privkey )
    wallet_keys = blockstack_client.make_wallet_keys( owner_privkey=wallets[3].privkey, data_privkey=wallets[4].privkey, payment_privkey=wallets[5].privkey )

    wallet_keychain = {
        'foo.test': wallet_keys,
        'bar.test': wallet_keys_2,
    }

    # install wallet_keys
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] )

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.blockstack_name_preorder( "bar.test", wallets[3].privkey, wallets[4].addr )
    testlib.next_block( **kw )
    
    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.blockstack_name_register( "bar.test", wallets[3].privkey, wallets[4].addr )
    testlib.next_block( **kw )
   
    setup_storage_dirs(['foo.test', 'bar.test'])

    # migrate profiles 
    # BUT! make sure we store the profile for foo.test into both foo.test's and bar.test's storage directories!
    os.environ['TEST_BLOCKSTACK_TEST_DISK_ROOT'] = '/tmp/blockstack-integration-test-storage-foo.test'

    res = testlib.migrate_profile( "foo.test", proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in res:
        res['test'] = 'Failed to initialize foo.test profile'
        print json.dumps(res, indent=4, sort_keys=True)
        return False

    shutil.copy("/tmp/blockstack-integration-test-storage-foo.test/mutable/foo.test", "/tmp/blockstack-integration-test-storage-bar.test/mutable/foo.test")
    
    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    testlib.next_block(**kw)

    # store zonefile
    res = blockstack_client.proxy.put_zonefiles("localhost:16264", [base64.b64encode(res['zonefile_txt'])])
    if 'error' in res:
        print 'failed to store zonefile for foo.test: {}'.format(res)
        return False

    # BUT! make sure we store the profile for bar.test into both foo.test's and bar.test's storage directories!
    os.environ['TEST_BLOCKSTACK_TEST_DISK_ROOT'] = '/tmp/blockstack-integration-test-storage-bar.test'

    res = testlib.migrate_profile( "bar.test", proxy=test_proxy, wallet_keys=wallet_keys_2 )
    if 'error' in res:
        res['test'] = 'Failed to initialize bar.test profile'
        print json.dumps(res, indent=4, sort_keys=True)
        return False

    shutil.copy("/tmp/blockstack-integration-test-storage-bar.test/mutable/bar.test", "/tmp/blockstack-integration-test-storage-foo.test/mutable/bar.test")

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    testlib.next_block(**kw)

    # store zonefile
    res = blockstack_client.proxy.put_zonefiles("localhost:16264", [base64.b64encode(res['zonefile_txt'])])
    if 'error' in res:
        print 'failed to store zonefile for bar.test: {}'.format(res)
        return False

    res = testlib.start_api("0123456789abcdef")
    if 'error' in res:
        print 'failed to start API for foo.test: {}'.format(res)
        return False

    target_datastore('foo.test')

    # instantiate foo.test's test driver
    res = testlib.blockstack_REST_call('POST', '/v1/node/drivers/storage/test?index=1&force=1', None, api_pass='blockstack_integration_test_api_password')
    if 'error' in res or res['http_status'] != 200:
        print json.dumps(res, indent=4, sort_keys=True)
        return False

    res = testlib.blockstack_cli_put_account("foo.test", "test", 'storage', "test:///index/index.manifest?diskroot=/tmp/blockstack-integration-test-storage-foo.test",
                                             None, wallet_keys=wallet_keys )
    if 'error' in res:
        res['test'] = 'Failed to create foo.test account'
        print json.dumps(res, indent=4, sort_keys=True)
        return False

    os.makedirs('/tmp/blockstack-integration-test-storage/mutable')
    os.makedirs('/tmp/blockstack-integration-test-storage/immutable')

    shutil.copy("/tmp/blockstack-integration-test-storage-foo.test/mutable/foo.test", "/tmp/blockstack-integration-test-storage-bar.test/mutable/foo.test")
    shutil.copy("/tmp/blockstack-integration-test-storage-foo.test/mutable/foo.test", "/tmp/blockstack-integration-test-storage/mutable/foo.test")

    # link test account for bar.test
    # BUT! make sure we store the profile for bar.test into foo.test's and bar.test's storage directories!
    target_datastore('bar.test')

    # instantiate bar.test's test driver 
    res = testlib.blockstack_REST_call('POST', '/v1/node/drivers/storage/test?index=1&force=1', None, api_pass='blockstack_integration_test_api_password')
    if 'error' in res or res['http_status'] != 200:
        print json.dumps(res, indent=4, sort_keys=True)
        return False

    res = testlib.blockstack_cli_put_account("bar.test", "test", 'storage', "test:///index/index.manifest?diskroot=/tmp/blockstack-integration-test-storage-bar.test",
                                             None, wallet_keys=wallet_keys_2 )
    if 'error' in res:
        res['test'] = 'Failed to create bar.test account'
        print json.dumps(res, indent=4, sort_keys=True)
        return False

    shutil.copy("/tmp/blockstack-integration-test-storage-bar.test/mutable/bar.test", "/tmp/blockstack-integration-test-storage-foo.test/mutable/bar.test")
    shutil.copy("/tmp/blockstack-integration-test-storage-bar.test/mutable/bar.test", "/tmp/blockstack-integration-test-storage/mutable/bar.test")

    # restore...we'll set up foo.test next
    res = testlib.blockstack_test_setenv("TEST_BLOCKSTACK_TEST_DISK_ROOT", "/tmp/blockstack-integration-test-storage-foo.test")
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        return False

    # get datastore keys...
    foo_datastore_pk = keylib.ECPrivateKey(wallets[-1].privkey).to_hex()
    datastore_id_res = testlib.blockstack_cli_datastore_get_id( foo_datastore_pk )
    foo_datastore_id = datastore_id_res['datastore_id']

    bar_datastore_pk = keylib.ECPrivateKey(wallets[-2].privkey).to_hex()
    datastore_id_res = testlib.blockstack_cli_datastore_get_id( bar_datastore_pk )
    bar_datastore_id = datastore_id_res['datastore_id']

    # activate foo.test 
    res = activate_account("foo.test", foo_datastore_pk)
    if not res:
        print 'failed to start API for bar.test: {}'.format(res)
        return False

    # set up foo.test's datastore 
    res = setup_datastore(wallets[-1].privkey, "foo.test", 1)
    if not res:
        print 'failed to setup foo.test datastore'
        return False

    # activate bar.test 
    res = activate_account("bar.test", bar_datastore_pk)
    if not res:
        print 'failed to start API for bar.test: {}'.format(res)
        return False

    # make *absolutely certain* that the test driver does not load data from
    # foo.test's or bar.test's storage directories.  We want to verify that we can look up
    # the index manifest URLs from the profile
    target_datastore(None)

    print "\n\nbar.test tries to read foo.test's datastore {}\n\n".format(foo_datastore_id)
    res = read_datastore(foo_datastore_id, "foo.test", 1)
    if not res:
        print 'failed to read foo.test datastore {}'.format(foo_datastore_id)
        return False

    # set up bar.test's files 
    res = setup_datastore(wallets[-2].privkey, 'bar.test', 2)
    if not res:
        print 'failed to setup bar.test datastore'
        return False

    # activate foo.test
    res = activate_account("foo.test", foo_datastore_pk)
    if not res:
        print 'failed to start API for foo.test: {}'.format(res)
        return False

    # make *absolutely certain* that the test driver does not load data from
    # foo.test's or bar.test's storage directories.  We want to verify that we can look up
    # the index manifest URLs from the profile
    target_datastore(None)

    # try to read all of bar.test's files
    print "\n\nfoo.test tries to read bar.test's datastore {}\n\n".format(bar_datastore_id)
    res = read_datastore(bar_datastore_id, 'bar.test', 2)
    if not res:
        print 'failed to read bar.test datastore {}'.format(bar_datastore_id)
        return False

    # re-target foo.test's datastore
    target_datastore('foo.test')

    # have foo.test write new files 
    print '\n\nupdate foo.test datastore\n\n'
    res = write_datastore('foo.test', foo_datastore_pk, 3)
    if not res:
        print 'failed to update foo.test datastore {}'.format(foo_datastore_id)
        return False

    # activate bar.test
    res = activate_account("bar.test", bar_datastore_pk)
    if not res:
        print 'failed to start API for bar.test: {}'.format(res)
        return False

    # make *absolutely certain* that the test driver does not load data from
    # foo.test's or bar.test's storage directories.  We want to verify that we can look up
    # the index manifest URLs from the profile
    target_datastore(None)

    # get foo.test's new files 
    res = read_datastore(foo_datastore_id, 'foo.test', 3)
    if not res:
        print 'failed to read new files from foo.test'
        return False

    # re-target bar.test's datastore
    target_datastore('bar.test')

    # have bar write some new files 
    print '\n\nupdate bar.test datastore\n\n'
    res = write_datastore('bar.test', bar_datastore_pk, 4)
    if not res:
        print 'failed ot update bar.test datastore {}'.format(bar_datastore_id)
        return False

    # activate foo.test
    res = activate_account("foo.test", foo_datastore_pk)
    if not res:
        print 'failed to start API for foo.test: {}'.format(res)
        return False

    # delete foo's files 
    print '\n\ndelete foo.test files\n\n'
    res = clear_datastore_files('foo.test', foo_datastore_pk)
    if not res:
        print 'failed to clear datastore {} for foo.test'.format(foo_datastore_id)
        return False

    # activate bar.test
    res = activate_account("bar.test", bar_datastore_pk)
    if not res:
        print 'failed to start API for bar.test: {}'.format(res)
        return False

    # make *absolutely certain* that the test driver does not load data from
    # foo.test's or bar.test's storage directories.  We want to verify that we can look up
    # the index manifest URLs from the profile
    target_datastore(None)

    # verify that foo's files are gone 
    res = check_datastore_files_absent(foo_datastore_id, 'foo.test')
    if not res:
        print 'failed to verify that foo.test datastore {} is devoid of files'.format(foo_datastore_id)
        return False

    # re-target bar.test's datastore
    target_datastore('bar.test')

    # clear bar.test's files 
    res = clear_datastore_files('bar.test', bar_datastore_pk)
    if not res:
        print 'failed to clear datastore {} for bar.test'.format(bar_datastore_id)
        return False

    # activate foo.test
    res = activate_account("foo.test", foo_datastore_pk)
    if not res:
        print 'failed to start API for foo.test: {}'.format(res)
        return False

    # make *absolutely certain* that the test driver does not load data from
    # foo.test's or bar.test's storage directories.  We want to verify that we can look up
    # the index manifest URLs from the profile
    target_datastore(None)

    # verify that bar's files are gone 
    res = check_datastore_files_absent(bar_datastore_id, 'bar.test')
    if not res:
        print 'failed to verify that bar.test datastore {} is devoid of files'.format(bar_datastore_id)
        return False

    # re-target foo.test's datastore
    target_datastore("foo.test")

    # clear foo's directories 
    res = clear_datastore_directories('foo.test', foo_datastore_pk)
    if not res:
        print 'failed to clear foo.test datastore {} of directories'.format(foo_datastore_id)
        return False

    # activate bar.test
    res = activate_account("bar.test", bar_datastore_pk)
    if not res:
        print 'failed to start API for bar.test: {}'.format(res)
        return False

    # make *absolutely certain* that the test driver does not load data from
    # foo.test's or bar.test's storage directories.  We want to verify that we can look up
    # the index manifest URLs from the profile
    target_datastore(None)

    # verify that foo's directories are gone 
    res = check_datastore_directories_absent(foo_datastore_id, "foo.test")
    if not res:
        print 'failed to verify that foo.test datastore {} is devoid of directories'.format(foo_datastore_id)
        return False

    # re-target bar.test's datastore
    target_datastore('bar.test')

    # clear bar's directories
    res = clear_datastore_directories('bar.test', bar_datastore_pk)
    if not res:
        print 'failed to clear bar.test datastore {} of directories'.format(bar_datastore_id)
        return False

    # activate foo.test
    res = activate_account('foo.test', foo_datastore_pk)
    if not res:
        print 'failed to start API for foo.test: {}'.format(res)
        return False

    # make *absolutely certain* that the test driver does not load data from
    # foo.test's or bar.test's storage directories.  We want to verify that we can look up
    # the index manifest URLs from the profile
    target_datastore(None)

    # verify that bar's directories are gone
    res = check_datastore_directories_absent(bar_datastore_id, "bar.test")
    if not res:
        print 'failed to verify that bar.test datastore {} is devoid of directories'.format(bar_datastore_id)
        return False

    # root should be empty in both cases
    print 'listdir {} (bar.test)'.format('/')
    res = testlib.blockstack_cli_datastore_listdir( 'bar.test', bar_datastore_id, '/', data_pubkeys=get_data_pubkeys('bar.test'))
    if 'error' in res:
        print 'failed to listdir / on bar.test: {}'.format(res['error'])
        return False

    if len(res['children'].keys()) > 0:
        print 'root still has children: {}'.format(res['children'].keys())
        return False

    # activate bar.test
    res = activate_account('bar.test', bar_datastore_pk)
    if not res:
        print 'failed to start API for foo.test: {}'.format(res)
        return False

    print 'listdir {} (foo.test)'.format('/')
    res = testlib.blockstack_cli_datastore_listdir( 'foo.test', foo_datastore_id, '/', data_pubkeys=get_data_pubkeys('foo.test'))
    if 'error' in res:
        print 'failed to listdir / on foo.test: {}'.format(res['error'])
        return False

    if len(res['children'].keys()) > 0:
        print 'root still has children: {}'.format(res['children'].keys())
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
