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
import os
os.environ["CLIENT_STORAGE_DRIVERS"] = "test"
os.environ["CLIENT_STORAGE_DRIVERS_REQUIRED_WRITE"] = "test"

"""
TEST ENV CLIENT_STORAGE_DRIVERS test
TEST ENV CLIENT_STORAGE_DRIVERS_REQUIRED_WRITE test
"""

import testlib
import virtualchain
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

app_name = 'localhost.1:8888'
app_domain = 'http://localhost.1:8888'

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
    
    storage_dir = get_blockchain_id_storage(blockchain_id)
    res = testlib.blockstack_test_setenv("TEST_BLOCKSTACK_TEST_DISK_ROOT", storage_dir)
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        return False

    # require that we only use URLs in the device root pages
    res = testlib.blockstack_test_setenv("TEST_BLOCKSTACK_TEST_URLS_ONLY", "1")
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        return False

    return True


def activate_account(blockchain_id, datastore_pk, wk):
    
    global sessions
    
    # switch wallets
    testlib.blockstack_client_set_wallet( '0123456789abcdef', wk['payment_privkey'], wk['owner_privkey'], wk['data_privkey'])
    res = testlib.blockstack_REST_call('PUT', '/v1/wallet/keys', None, api_pass='blockstack_integration_test_api_password', data=wk)
    if 'error' in res or res['http_status'] != 200:
        if 'error' not in res:
            res['error'] = 'failed to put wallet keys (generic error)'

        print res
        return res
    
    # sign in and make a token with the given blockchain ID (whose wallet must be currently set)
    res = testlib.blockstack_cli_app_signin(blockchain_id, datastore_pk, app_domain, ['store_read', 'store_write', 'store_admin'])
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
    res = testlib.blockstack_cli_app_signin(blockchain_id, datastore_pk, app_domain, ['store_read', 'store_write', 'store_admin'])
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        return None

    ses = res['token']
    sessions[blockchain_id] = ses

    # export to environment 
    res = setup_env(res['token'], blockchain_id)
    if not res:
        print 'failed to setup env'
        return None

    return ses


def target_datastore(blockchain_id):
    # point to a particular user's datastore
    storage_dir = get_blockchain_id_storage(blockchain_id)
    res = testlib.blockstack_test_setenv('TEST_BLOCKSTACK_TEST_DISK_ROOT', storage_dir)
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        return False
    
    os.environ['TEST_BLOCKSTACK_TEST_DISK_ROOT'] = storage_dir


def setup_datastore(datastore_pk, blockchain_id, write_iteration):

    global sessions

    ses = core_signin(datastore_pk, blockchain_id)
    if not ses:
        print 'failed to sign in with {}, by {}'.format(datastore_pk, blockchain_id)
        return False
    
    # make datastore 
    res = testlib.blockstack_cli_create_datastore( datastore_pk, ['test'], ses)
    if 'error' in res:
        print "failed to create datastore: {}".format(res['error'])
        return False

    # put files
    res = write_datastore(blockchain_id, datastore_pk, write_iteration)
    if not res:
        print 'failed to write files (iteration {}) to {}'.format(write_iteration, blockchain_id)
        return False

    # read everything to be sure it's there
    res = read_datastore(blockchain_id, write_iteration)
    if not res:
        print 'failed to read datastore from {}'.format(blockchain_id)
        return False

    return True


def write_datastore(blockchain_id, datastore_pk, iteration):
    """
    write some files to the datastore, over existing ones
    """
    global sessions
    ses = sessions[blockchain_id]

    # put files again! 
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'putfile {}'.format(dpath)
        data = '{} hello {} {}'.format(file_data, iteration, dpath)
        res = testlib.blockstack_cli_datastore_putfile( datastore_pk, dpath, data, ses)
        if 'error' in res:
            print 'failed to putfile {}: {}'.format(dpath, res['error'])
            return False

    return True


def read_datastore(blockchain_id, expected_iteration):
    """
    Read tests on a particular blockchain ID's datastores
    """

    # stat files
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'stat {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_stat( blockchain_id, None, dpath, app_name=app_name)
        if 'error' in res:
            print 'failed to stat {}: {}'.format(dpath, res['error'])
            return False

    # get files
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'getfile {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_getfile( blockchain_id, None, dpath, app_name=app_name)
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
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'deletefile {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_deletefile( datastore_pk, dpath, ses)
        if 'error' in res:
            print 'failed to deletefile {}: {}'.format(dpath, res['error'])
            return False
    
    return True


def check_datastore_files_absent(datastore_id, blockchain_id):
    """
    Verify that all files are gone
    """
    # stat files (should all fail)
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'stat {} (expect failure)'.format(dpath)
        res = testlib.blockstack_cli_datastore_stat( blockchain_id, None, dpath, app_name=app_name)
        if 'error' not in res or 'errno' not in res:
            print 'accidentally succeeded to stat {}: {}'.format(dpath, res)
            return False

        if res['errno'] != 'ENOENT':
            print 'wrong errno: {}'.format(res)
            return False
 
    # get files (should all fail)
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'getfile {} (expect failure)'.format(dpath)
        res = testlib.blockstack_cli_datastore_getfile( blockchain_id, None, dpath, app_name=app_name)
        if 'error' not in res or 'errno' not in res:
            print 'accidentally succeeded to get {}: {}'.format(dpath, res)
            return False

        if res['errno'] != 'ENOENT':
            print 'wrong errno: {}'.format(res)
            return False

    return True


def setup_storage_dirs(blockchain_ids):
    # set up storage directories
    for blockchain_id in blockchain_ids:
        storage_dir = get_blockchain_id_storage(blockchain_id)
        if os.path.exists(storage_dir):
            shutil.rmtree(storage_dir)

        os.makedirs(os.path.join(storage_dir, 'immutable'))
        os.makedirs(os.path.join(storage_dir, 'mutable'))


def get_blockchain_id_storage(blockchain_id):
    blockchain_id_storage = None
    if blockchain_id is not None:
        blockchain_id_storage = '/tmp/blockstack-integration-test-storage-{}'.format(blockchain_id)
    else:
        blockchain_id_storage = '/tmp/blockstack-integration-test-storage'

    if not os.path.exists(blockchain_id_storage):
        os.makedirs(blockchain_id_storage)

    return blockchain_id_storage


def setup_blockchain_id(this_blockchain_id, all_blockchain_ids, wallet_keys, test_proxy, **kw):

    testlib.blockstack_client_set_wallet( '0123456789abcdef', wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'])
    res = testlib.blockstack_REST_call('PUT', '/v1/wallet/keys', None, api_pass='blockstack_integration_test_api_password', data=wallet_keys)
    if 'error' in res or res['http_status'] != 200:
        if 'error' not in res:
            res['error'] = 'failed to put wallet keys (generic error)'

        print res
        return res
   
    # migrate profiles 
    # have all operations write data to this blockchain ID's specific directory
    this_blockchain_id_storage = get_blockchain_id_storage(this_blockchain_id)
    os.environ['TEST_BLOCKSTACK_TEST_DISK_ROOT'] = this_blockchain_id_storage

    res = testlib.migrate_profile( this_blockchain_id, proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in res:
        res['test'] = 'Failed to initialize foo.test profile'
        print json.dumps(res, indent=4, sort_keys=True)
        return res
    
    zonefile_hash = res['zonefile_hash']
    
    # make sure we wrote the key file
    key_file_txt = res['key_file']
    key_file_path = os.path.join(this_blockchain_id_storage, 'mutable', this_blockchain_id)
    if not os.path.exists(key_file_path):
        return {'error': 'no such file or directory: {}'.format(key_file_path)}

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    testlib.next_block(**kw)

    # store zonefile
    res = blockstack_client.proxy.put_zonefiles("localhost:16264", [base64.b64encode(res['zonefile_txt'])])
    if 'error' in res:
        print 'failed to store zonefile for {}: {}'.format(this_blockchain_id, res)
        return res
    
    # make sure we wrote the zone file
    zonefile_path = os.path.join(this_blockchain_id_storage, 'immutable', zonefile_hash)
    if not os.path.exists(zonefile_path):
        return {'error': 'no such file or directory: {}'.format(zonefile_path)}
    
    # replicate globally-visible state to all blockchain IDs
    for blockchain_id in all_blockchain_ids:
        if blockchain_id == this_blockchain_id:
            continue

        data_dir = '/tmp/blockstack-integration-test-storage-{}'.format(blockchain_id)
        mutable_data_dir = os.path.join(data_dir, 'mutable')
        immutable_data_dir = os.path.join(data_dir, 'immutable')

        if not os.path.exists(mutable_data_dir):
            os.makedirs(mutable_data_dir)

        if not os.path.exists(immutable_data_dir):
            os.makedirs(immutable_data_dir)

        # link this blockchain ID's key file and zone file to all other blockchain IDs' storages
        os.symlink(key_file_path, os.path.join(mutable_data_dir, this_blockchain_id))
        os.symlink(zonefile_path, os.path.join(immutable_data_dir, zonefile_hash))
    
    # also link to the "main" storage
    default_storage_dir = get_blockchain_id_storage(None)
    mutable_default_storage_dir = os.path.join(default_storage_dir, 'mutable')
    immutable_default_storage_dir = os.path.join(default_storage_dir, 'immutable')

    if not os.path.exists(mutable_default_storage_dir):
        os.makedirs(mutable_default_storage_dir)

    if not os.path.exists(immutable_default_storage_dir):
        os.makedirs(immutable_default_storage_dir)
    
    if os.path.exists(os.path.join(mutable_default_storage_dir, this_blockchain_id)):
        raise Exception('exists: {}'.format(blockchain_id))

    if os.path.exists(os.path.join(immutable_default_storage_dir, zonefile_hash)):
        return Exception('exists: {}'.format(zonefile_hash))

    os.symlink(key_file_path, os.path.join(mutable_default_storage_dir, this_blockchain_id))
    os.symlink(zonefile_path, os.path.join(immutable_default_storage_dir, zonefile_hash))

    return {'status': True}


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
      
    res = testlib.start_api('0123456789abcdef')
    if 'error' in res:
        print 'failed to start API for {}: {}'.format(this_blockchain_id, res)
        return False
    
    res = setup_blockchain_id('foo.test', ['foo.test', 'bar.test'], wallet_keys, test_proxy, **kw)
    if 'error' in res:
        print res
        return False

    res = setup_blockchain_id('bar.test', ['foo.test', 'bar.test'], wallet_keys_2, test_proxy, **kw)
    if 'error' in res:
        print res
        return False

    # get datastore keys...
    foo_datastore_pk = keylib.ECPrivateKey(wallets[-1].privkey).to_hex()
    datastore_id_res = testlib.blockstack_cli_datastore_get_id( foo_datastore_pk )
    foo_datastore_id = datastore_id_res['datastore_id']

    bar_datastore_pk = keylib.ECPrivateKey(wallets[-2].privkey).to_hex()
    datastore_id_res = testlib.blockstack_cli_datastore_get_id( bar_datastore_pk )
    bar_datastore_id = datastore_id_res['datastore_id']

    # activate foo.test 
    target_datastore('foo.test')
    res = activate_account("foo.test", foo_datastore_pk, wallet_keys)
    if not res:
        print 'failed to start API for bar.test: {}'.format(res)
        return False

    # set up foo.test's datastore 
    res = setup_datastore(wallets[-1].privkey, "foo.test", 1)
    if not res:
        print 'failed to setup foo.test datastore'
        return False

    # activate bar.test 
    target_datastore('bar.test')
    res = activate_account("bar.test", bar_datastore_pk, wallet_keys_2)
    if not res:
        print 'failed to start API for bar.test: {}'.format(res)
        return False

    # make *absolutely certain* that the test driver does not load data from
    # foo.test's or bar.test's storage directories.  We want to verify that we can look up
    # the index manifest URLs from the profile
    target_datastore(None)

    print "\n\nbar.test tries to read foo.test's datastore {}\n\n".format(foo_datastore_id)
    res = read_datastore("foo.test", 1)
    if not res:
        print 'failed to read foo.test datastore {}'.format(foo_datastore_id)
        return False

    # set up bar.test's files 
    res = setup_datastore(wallets[-2].privkey, 'bar.test', 2)
    if not res:
        print 'failed to setup bar.test datastore'
        return False

    # activate foo.test
    res = activate_account("foo.test", foo_datastore_pk, wallet_keys)
    if not res:
        print 'failed to start API for foo.test: {}'.format(res)
        return False

    # make *absolutely certain* that the test driver does not load data from
    # foo.test's or bar.test's storage directories.  We want to verify that we can look up
    # the index manifest URLs from the profile
    target_datastore(None)

    # try to read all of bar.test's files
    print "\n\nfoo.test tries to read bar.test's datastore {}\n\n".format(bar_datastore_id)
    res = read_datastore('bar.test', 2)
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
    res = activate_account("bar.test", bar_datastore_pk, wallet_keys_2)
    if not res:
        print 'failed to start API for bar.test: {}'.format(res)
        return False

    # make *absolutely certain* that the test driver does not load data from
    # foo.test's or bar.test's storage directories.  We want to verify that we can look up
    # the index manifest URLs from the profile
    target_datastore(None)

    # get foo.test's new files 
    res = read_datastore('foo.test', 3)
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
    res = activate_account("foo.test", foo_datastore_pk, wallet_keys)
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
    res = activate_account("bar.test", bar_datastore_pk, wallet_keys_2)
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
    print '\n\ndelete bar.test files\n\n'
    res = clear_datastore_files('bar.test', bar_datastore_pk)
    if not res:
        print 'failed to clear datastore {} for bar.test'.format(bar_datastore_id)
        return False

    # activate foo.test
    res = activate_account("foo.test", foo_datastore_pk, wallet_keys)
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

    # root should be empty in both cases
    print 'listdir {} (bar.test)'.format('/')
    res = testlib.blockstack_cli_datastore_listfiles('bar.test', app_name)
    if 'error' in res:
        print 'failed to listdir / on bar.test: {}'.format(res['error'])
        return False

    if len(res['root'].keys()) > 0:
        print 'root still has children: {}'.format(res['root'].keys())
        return False

    # activate bar.test
    res = activate_account('bar.test', bar_datastore_pk, wallet_keys_2)
    if not res:
        print 'failed to start API for foo.test: {}'.format(res)
        return False

    print 'listdir {} (foo.test)'.format('/')
    res = testlib.blockstack_cli_datastore_listfiles('bar.test', app_name)
    if 'error' in res:
        print 'failed to listdir / on foo.test: {}'.format(res['error'])
        return False

    if len(res['root'].keys()) > 0:
        print 'root still has children: {}'.format(res['root'].keys())
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
        preorder = state_engine.get_name_preorder( name, virtualchain.make_payment_script(wallets[wallet_payer].addr), wallets[wallet_owner].addr )
        if preorder is not None:
            print "still have preorder"
            return False
    
        # registered 
        name_rec = state_engine.get_name( name )
        if name_rec is None:
            print "name does not exist"
            return False 

        # owned 
        if name_rec['address'] != wallets[wallet_owner].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[wallet_owner].addr):
            print "name has wrong owner"
            return False 

        # try to authenticate

    return True
