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

    # sign in and make a token 
    datastore_pk = keylib.ECPrivateKey(wallets[-1].privkey).to_hex()
    res = testlib.blockstack_cli_app_signin(None, datastore_pk, 'http://localhost.1:8888', ['store_read', 'store_write', 'store_admin'])
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 
    
    ses = res['token']

    # export to environment 
    blockstack_client.set_secret("BLOCKSTACK_API_SESSION", ses)

    datastore_id_res = testlib.blockstack_cli_datastore_get_id( datastore_pk )
    datastore_id = datastore_id_res['datastore_id']

    # use random data for file 
    file_data = None
    with open('/dev/urandom', 'r') as f:
        file_data = f.read(16384)

    # make datastore 
    res = testlib.blockstack_cli_create_datastore(datastore_pk, ['disk'], ses )
    if 'error' in res:
        print "failed to create datastore: {}".format(res['error'])
        return False

    # put files 
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'putfile {}'.format(dpath)
        data = '{} hello {}'.format(file_data, dpath)
        res = testlib.blockstack_cli_datastore_putfile(datastore_pk, dpath, data, ses, datastore_id=datastore_id )
        if 'error' in res:
            print 'failed to putfile {}: {}'.format(dpath, res['error'])
            return False

    # stat files
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'stat {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_stat(None, datastore_id, dpath, ses )
        if 'error' in res:
            print 'failed to stat {}: {}'.format(dpath, res['error'])
            return False

    # get files
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'getfile {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_getfile(None, datastore_id, dpath, ses )
        if 'error' in res:
            print 'failed to getfile {}: {}'.format(dpath, res['error'])
            return False

        if res != '{} hello {}'.format(file_data, dpath):
            print 'failed to read {}'.format(dpath)
            print res
            return False
    
    # list files (should all be present)
    print 'listroot'
    res = testlib.blockstack_cli_datastore_listfiles(None, None, ses=ses, datastore_id=datastore_id)
    if 'error' in res:
        print 'listfiles failed'
        print res
        return False

    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        if dpath not in res['root']:
            print 'missing {}'.format(dpath)
            print res
            return False
    
    # put files again! 
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'putfile {}'.format(dpath)
        data = '{} hello 2 {}'.format(file_data, dpath)
        res = testlib.blockstack_cli_datastore_putfile(datastore_pk, dpath, data, ses, datastore_id=datastore_id )
        if 'error' in res:
            print 'failed to putfile {}: {}'.format(dpath, res['error'])
            return False

    # get files again!
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'getfile {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_getfile(None, datastore_id, dpath, ses )
        if 'error' in res:
            print 'failed to getfile {}: {}'.format(dpath, res['error'])
            return False

        if res != '{} hello 2 {}'.format(file_data, dpath):
            print 'failed to read {}'.format(dpath)
            return False

    # remove files
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'deletefile {}'.format(dpath)
        res = testlib.blockstack_cli_datastore_deletefile(datastore_pk, dpath, ses, datastore_id=datastore_id )
        if 'error' in res:
            print 'failed to deletefile {}: {}'.format(dpath, res['error'])
            return False

    # list files (should all be absent)
    print 'listroot'
    res = testlib.blockstack_cli_datastore_listfiles(None, None, ses=ses, datastore_id=datastore_id)
    if 'error' in res:
        print 'listfiles failed'
        print res
        return False

    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        if dpath in res['root']:
            print 'still present: {}'.format(dpath)
            print res
            return False

    # stat files (should all fail)
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'stat {} (expect failure)'.format(dpath)
        res = testlib.blockstack_cli_datastore_stat( None, datastore_id, dpath, ses )
        if 'error' not in res or 'errno' not in res:
            print 'accidentally succeeded to stat {}: {}'.format(dpath, res)
            return False

        if res['errno'] != "ENOENT":
            print 'wrong errno: {}'.format(res)
            return False
 
    # get files (should all fail)
    for dpath in ['file1', 'file2', 'file3', 'file4', 'file5']:
        print 'getfile {} (expect failure)'.format(dpath)
        res = testlib.blockstack_cli_datastore_getfile( None, datastore_id, dpath, ses )
        if 'error' not in res or 'errno' not in res:
            print 'accidentally succeeded to get {}: {}'.format(dpath, res)
            return False
        
        if not isinstance(res, dict):
            print 'did not get an error'
            print res
            return False

        if res['errno'] != "ENOENT":
            print 'wrong errno: {}'.format(res)
            return False

    # delete datastore 
    print 'delete datastore'
    res = testlib.blockstack_cli_delete_datastore( datastore_pk, ses )
    if 'error' in res:
        print 'failed to delete foo-app.com datastore'
        print json.dumps(res)
        return False

    # no more data in disk driver 
    names = os.listdir("/tmp/blockstack-disk/mutable")
    if names != []:
        print 'improper cleanup'
        return False

    testlib.next_block( **kw )


def check( state_engine ):

    global wallet_keys, error

    if error:
        print "Key operation failed."
        return False

    return True
