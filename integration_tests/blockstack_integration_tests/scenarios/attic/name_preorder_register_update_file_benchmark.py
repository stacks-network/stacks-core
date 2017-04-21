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
import sys
import traceback

# AWS tokens 
try:
    aws_key = os.environ.get("BLOCKSTACK_FILE_AWS_KEY")
    aws_secret = os.environ.get("BLOCKSTACK_FILE_AWS_SECRET")
    aws_bucket = os.environ.get("BLOCKSTACK_FILE_AWS_BUCKET")
    storage_drivers = os.environ.get("BLOCKSTACK_STORAGE_DRIVERS")
    file_sizes = os.environ.get("BLOCKSTACK_FILE_SIZES")
    samples = 1
    assert aws_key
    assert aws_secret
    assert aws_bucket
    assert storage_drivers
    assert "s3" in storage_drivers
    file_sizes = [int(fs) for fs in file_sizes.split(",")]
    samples = int(samples)
except Exception, e:
    traceback.print_exc()
    print >> sys.stderr, "Need BLOCKSTACK_STORAGE_DRIVERS='s3', BLOCKSTACK_FILE_SIZE, BLOCKSTACK_FILE_AWS_KEY, BLOCKSTACK_FILE_AWS_SECRET, and BLOCKSTACK_FILE_AWS_BUCKET set!"
    sys.exit(1)

# patch config file with S3 credentials
s3_config = """

[s3]
bucket=%s
api_key_id=%s
api_key_secret=%s
""" % (aws_bucket, aws_key, aws_secret)

# turn on tests
os.environ['BLOCKSTACK_FILE_CONFIG'] = os.path.join( os.path.dirname( os.environ['BLOCKSTACK_CLIENT_CONFIG'] ), 'blockstack-file.ini' )

import pybitcoin
import urllib2
import json
import time
import os

import testlib
import blockstack_client
import blockstack_profiles
import blockstack_gpg
import blockstack_file

log = blockstack_client.get_logger()

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet( "5K5hDuynZ6EQrZ4efrchCwy6DLhdsEzuJtTDAf3hqdsCKbxfoeD", 100000000000 ),
    testlib.Wallet( "5J39aXEeHh9LwfQ4Gy5Vieo7sbqiUMBXkPH7SaMHixJhSSBpAqz", 100000000000 ),
    testlib.Wallet( "5K9LmMQskQ9jP1p7dyieLDAeB6vsAj4GK8dmGNJAXS1qHDqnWhP", 100000000000 ),
    testlib.Wallet( "5KcNen67ERBuvz2f649t9F2o1ddTjC5pVUEqcMtbxNgHqgxG2gZ", 100000000000 ),
    testlib.Wallet( "5KBf4DMDxzhhkgLzPwHwTLpB1qG7r6MYUyy8VB8wKzyQzJsnbLY", 100000000000 ),
    testlib.Wallet( "5K8SSBstH6zPzguDJoHzBQanadDTSLRAzygfNwzWkEVcUz3Dcq4", 100000000000 ),
    testlib.Wallet( "5JuUrxefza1SHG1U5oFzH6k9n4VzhNqXFS3Pdcv4NhiW9xUQKbr", 100000000000 ),
    testlib.Wallet( "5K6Sm6vSn5DPZoF39j1Xj4oHFag3nz1PYCE3NuLC92AMvyiJDgw", 100000000000 ),
    testlib.Wallet( "5KXfThph9nmFcmy14PnX5opDW6scinQQKsSUCGB2ihXU6cVzaUa", 100000000000 ),
    testlib.Wallet( "5KHuUV3UhcM4biEmiG358DW6ecomkpT4WJLzUr7Da3W3vRUg1eH", 100000000000 ),
    testlib.Wallet( "5JFUNXS1Cpy4DbToKLbMZPfHggNv41EY2xpUryFXt3eoavZcmzp", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
wallet_keys = {}
error = False
foo_output = None
bar_output = None
baz_output = None
config_paths = {}

# test config file 
TEST_CONFIG_FILE = """
[blockstack-file]
immutable_key=False
hostname=localhost
"""

TEST_OUTPUT_FILE = TEST_CONFIG_FILE

put_benchmark_data = {} # keyed by size
get_benchmark_data = {} # keyed by size

def make_upload_name( name, i, size ):
    return "upload-%s-%s-from-%s" % (i, size, name)

def make_local_upload_path( config_path, name, size ):
    config_dir = os.path.dirname(config_path) + "." + name
    upload_path = os.path.join(config_dir, "upload-%s.txt" % size )
    return upload_path

def scenario( wallets, **kw ):

    global wallet_keys, error, foo_output, bar_output, baz_output, config_paths, put_benchmark_data, get_benchmark_data, aws_key, aws_secret

    print "patch '%s'" % os.environ.get("BLOCKSTACK_CLIENT_CONFIG")
    with open( os.environ.get('BLOCKSTACK_CLIENT_CONFIG'), "a+" ) as f:
        f.write( s3_config )
        f.flush()

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.blockstack_name_preorder( "bar.test", wallets[5].privkey, wallets[6].addr )
    testlib.next_block( **kw )
    
    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.blockstack_name_register( "bar.test", wallets[5].privkey, wallets[6].addr )
    testlib.next_block( **kw )

    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )
    wallet_keys['foo.test'] = blockstack_client.make_wallet_keys( owner_privkey=wallets[3].privkey, data_privkey=wallets[4].privkey, payment_privkey=wallets[8].privkey )
    wallet_keys['bar.test'] = blockstack_client.make_wallet_keys( owner_privkey=wallets[6].privkey, data_privkey=wallets[7].privkey, payment_privkey=wallets[9].privkey )

    # migrate profiles 
    for name in ['foo.test', 'bar.test']:
        res = testlib.migrate_profile( name, proxy=test_proxy, wallet_keys=wallet_keys[name] )
        if 'error' in res:
            res['test'] = 'Failed to initialize %s profile' % name
            print json.dumps(res, indent=4, sort_keys=True)
            error = True
            return 

    testlib.next_block( **kw )

    # set up config file 
    config_path = os.environ['BLOCKSTACK_FILE_CONFIG']
    with open(config_path, "w") as f:
        f.write(TEST_CONFIG_FILE)

    config_paths = {}

    # set up config file and upload file for each principal 
    for name in ['foo.test', 'bar.test']:
        config_dir = os.path.dirname(config_path) + "." + name
        os.makedirs(config_dir)
        name_config_path = os.path.join(config_dir, os.path.basename(config_path))
        config_paths[name] = name_config_path

        # config path
        with open(config_paths[name], "w") as f:
            f.write(TEST_CONFIG_FILE)

        # upload paths 
        for sz in file_sizes:
            upload_path = make_local_upload_path( config_path, name, sz )
            with open(upload_path, "w") as f:
                with open("/dev/urandom", "r") as r:
                    # generate file
                    file_data = r.read(sz)
                    f.write(file_data)
                    f.flush()

    foo_output = os.path.join( os.path.dirname(config_path), 'foo.test-out.txt' )
    foo_fail_output = os.path.join( os.path.dirname(config_path), 'foo.test-out-fail.txt' )
    bar_output = os.path.join( os.path.dirname(config_path), 'bar.test-out.txt' )
    bar_fail_output = os.path.join( os.path.dirname(config_path), 'bar.test-out-fail.txt' )

    # initialize file app
    res = blockstack_file.file_key_regenerate( "foo.test", "localhost", config_path=config_paths['foo.test'], wallet_keys=wallet_keys['foo.test'] )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return
    
    res = blockstack_file.file_key_regenerate( "bar.test", "localhost", config_path=config_paths['bar.test'], wallet_keys=wallet_keys['bar.test'] )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    # send a file from foo.test to bar.test
    # do so many times 
    for sz in file_sizes:
        put_benchmark_data[sz] = []
        for i in xrange(0, samples):
            upload_name = make_upload_name( 'foo.test', i, sz )
            local_path = make_local_upload_path(config_path, 'foo.test', sz)
            
            begin = time.time()
            res = blockstack_file.file_put( 'foo.test', 'localhost', ['bar.test'], upload_name, local_path,
                                        config_path=config_paths['foo.test'], wallet_keys=wallet_keys['foo.test'] )

            end = time.time()

            if 'error' in res:
                print json.dumps(res, indent=4, sort_keys=True)
                error = True
                return

            put_benchmark_data[sz].append( end - begin )

    # get a file from foo.test, as bar.test
    # do so many times
    for sz in file_sizes:
        get_benchmark_data[sz] = []
        for i in xrange(0, samples):
            upload_name = make_upload_name( 'foo.test', i, sz )
            src_local_path = make_local_upload_path(config_path, 'foo.test', sz)
            local_path = make_local_upload_path( config_path, 'bar.test', sz )
            
            begin = time.time()
            res = blockstack_file.file_get( 'bar.test', 'localhost', 'foo.test', upload_name, local_path,
                                            config_path=config_paths['bar.test'], wallet_keys=wallet_keys['bar.test'] )
            end = time.time()
            if 'error' in res:
                print json.dumps(res, indent=4, sort_keys=True)
                error = True
                return 
       
            rc = os.system("cmp \"%s\" \"%s\"" % (src_local_path, local_path))
            if rc != 0:
                raise Exception("Not equal: \"%s\" and \"%s\"" % (src_local_path, local_path))
            try:
                os.unlink(output_path)
            except:
                pass


            get_benchmark_data[sz].append( end - begin )

    # delete 
    for sz in file_sizes:
        for i in xrange(0, samples):
            upload_name = make_upload_name( 'foo.test', i, sz )
            res = blockstack_file.file_delete( 'foo.test', upload_name, config_path=config_paths['foo.test'], wallet_keys=wallet_keys['foo.test'] )
            if 'error' in res:
                print json.dumps(res, indent=4, sort_keys=True)
                error = True
                return


def check( state_engine ):

    global error, wallet_keys, wallet_keys_2, foo_output, bar_output, baz_output
    config_path = os.environ['BLOCKSTACK_FILE_CONFIG']

    if error:
        print "test failed during scenario"
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

    # not preordered
    preorder = state_engine.get_name_preorder( "foo.test", pybitcoin.make_pay_to_address_script(wallets[2].addr), wallets[3].addr )
    if preorder is not None:
        print "still have preorder"
        return False
    
    # not preordered
    preorder = state_engine.get_name_preorder( "bar.test", pybitcoin.make_pay_to_address_script(wallets[5].addr), wallets[6].addr )
    if preorder is not None:
        print "still have preorder"
        return False

    # registered 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        print "name does not exist"
        return False 

    # owned 
    if name_rec['address'] != wallets[3].addr or name_rec['sender'] != pybitcoin.make_pay_to_address_script(wallets[3].addr):
        print "foo.test name has wrong owner"
        return False 

    # registered 
    name_rec = state_engine.get_name( "bar.test" )
    if name_rec is None:
        print "name does not exist"
        return False 

    # owned 
    if name_rec['address'] != wallets[6].addr or name_rec['sender'] != pybitcoin.make_pay_to_address_script(wallets[6].addr):
        print "bar.test name has wrong owner"
        return False 

    # files are no longer listed in foo.test 
    for name in ['foo.test']:
        listing = blockstack_file.file_list( 'foo.test', config_path=config_paths[name], wallet_keys=wallet_keys[name] )
        if 'error' in listing:
            print "no listing: %s" % listing['error']
            return False

        if len(listing['listing']) != 0:
            print "still listed: %s" % listing['listing']
            return False

    # print benchmark data
    for sz in file_sizes:
        print ""
        print "put %s: %s" % (sz, ",".join([str(f) for f in put_benchmark_data[sz]]))
        print "get %s: %s" % (sz, ",".join([str(f) for f in get_benchmark_data[sz]]))
        print ""

    return True
