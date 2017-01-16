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

import testlib
import pybitcoin
import urllib2
import json
import blockstack_client
import blockstack_profiles
import blockstack_gpg
import time
import os
import sys

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
    testlib.Wallet( "5JFUNXS1Cpy4DbToKLbMZPfHggNv41EY2xpUryFXt3eoavZcmzp", 100000000000 ),
    testlib.Wallet( "5Jhp8tcLRXH3AjXX2QtyqrdJYdsNAh5FEwS24AEtZXzQBPKDmEm", 100000000000 ),
    testlib.Wallet( "5K6QPEFR8ErE9JpLEgkrGnU7YvJfzkSWfd2QX6amNzbcc9MUqhK", 100000000000 ),
    testlib.Wallet( "5J5uAKL8s62hddganFJaCkWi3Me7PFoc7fks9hAzjtWG1NDjmUK", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
wallet_keys = {}
error = False
foo_output = None
bar_output = None
baz_output = None
config_paths = {}

# turn on tests
os.environ['BLOCKSTACK_FILE_CONFIG'] = os.path.join( os.path.dirname( os.environ['BLOCKSTACK_CLIENT_CONFIG'] ), 'blockstack-file.ini' )
import blockstack_file

# test config file 
TEST_CONFIG_FILE = """
[blockstack-file]
immutable_key=False
hostname=localhost
"""

TEST_OUTPUT_FILE = TEST_CONFIG_FILE

def scenario( wallets, **kw ):

    global wallet_keys, error, foo_output, bar_output, baz_output, config_paths

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_name_preorder( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.blockstack_name_preorder( "bar.test", wallets[5].privkey, wallets[6].addr )
    testlib.blockstack_name_preorder( "baz.test", wallets[8].privkey, wallets[9].addr )
    testlib.next_block( **kw )
    
    testlib.blockstack_name_register( "foo.test", wallets[2].privkey, wallets[3].addr )
    testlib.blockstack_name_register( "bar.test", wallets[5].privkey, wallets[6].addr )
    testlib.blockstack_name_register( "baz.test", wallets[8].privkey, wallets[9].addr )
    testlib.next_block( **kw )

    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )
    wallet_keys['foo.test'] = blockstack_client.make_wallet_keys( owner_privkey=wallets[3].privkey, data_privkey=wallets[4].privkey, payment_privkey=wallets[11].privkey )
    wallet_keys['bar.test'] = blockstack_client.make_wallet_keys( owner_privkey=wallets[6].privkey, data_privkey=wallets[7].privkey, payment_privkey=wallets[12].privkey )
    wallet_keys['baz.test'] = blockstack_client.make_wallet_keys( owner_privkey=wallets[9].privkey, data_privkey=wallets[10].privkey, payment_privkey=wallets[13].privkey )

    # migrate profiles 
    for name in ['foo.test', 'bar.test', 'baz.test']:
        res = testlib.migrate_profile( name, proxy=test_proxy, wallet_keys=wallet_keys[name] )
        if 'error' in res:
            res['test'] = 'Failed to initialize %s profile' % name
            print json.dumps(res, indent=4, sort_keys=True)
            error = True
            return 

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    testlib.next_block( **kw )

    # set up config file 
    config_path = os.environ['BLOCKSTACK_FILE_CONFIG']
    with open(config_path, "w") as f:
        f.write(TEST_CONFIG_FILE)

    config_paths = {}

    # set up config file and directory for each principal 
    for name in ['foo.test', 'bar.test', 'baz.test']:
        config_dir = os.path.dirname(config_path) + "." + name
        os.makedirs(config_dir)
        name_config_path = os.path.join(config_dir, os.path.basename(config_path))
        config_paths[name] = name_config_path

        with open(config_paths[name], "w") as f:
            f.write(TEST_CONFIG_FILE)

    foo_output = os.path.join( os.path.dirname(config_path), 'foo.test-out.txt' )
    foo_fail_output = os.path.join( os.path.dirname(config_path), 'foo.test-out-fail.txt' )
    bar_output = os.path.join( os.path.dirname(config_path), 'bar.test-out.txt' )
    bar_fail_output = os.path.join( os.path.dirname(config_path), 'bar.test-out-fail.txt' )
    baz_output = os.path.join( os.path.dirname(config_path), 'baz.test-out.txt' )
    baz_fail_output = os.path.join( os.path.dirname(config_path), 'baz.test-out-fail.txt' )

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

    res = blockstack_file.file_key_regenerate( "bar.test", "mobile-phone", config_path=config_paths['bar.test'], wallet_keys=wallet_keys['bar.test'])
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    res = blockstack_file.file_key_regenerate( "baz.test", "laptop", config_path=config_paths['baz.test'], wallet_keys=wallet_keys['baz.test'] )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    # send a file from foo.test to bar.test and baz.test 
    res = blockstack_file.file_put( 'foo.test', 'localhost', ['bar.test', 'baz.test'], 'config-file-from-foo.test', config_path, config_path=config_paths['foo.test'], wallet_keys=wallet_keys['foo.test'] )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    # send a file from bar.test's mobile phone to foo.test (but not baz.test)
    res = blockstack_file.file_put( 'bar.test', 'mobile-phone', ['foo.test'], 'config-file-from-bar.test', config_path, config_path=config_paths['bar.test'], wallet_keys=wallet_keys['bar.test'] )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    # send a file from baz.test's laptop to baz.test's laptop (and no one else)
    res = blockstack_file.file_put( 'baz.test', 'laptop', [], 'config-file-from-baz.test', config_path, config_path=config_paths['baz.test'], wallet_keys=wallet_keys['baz.test'] )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    # have foo.test receive bar.test's file
    log.debug("foo.test receives bar.test's file")
    res = blockstack_file.file_get( 'foo.test', 'localhost', 'bar.test', 'config-file-from-bar.test', foo_output, config_path=config_paths['foo.test'], wallet_keys=wallet_keys['foo.test'] )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    # have bar.test receive bar.test's file to localhost 
    log.debug("bar.test receives bar.tests's file")
    res = blockstack_file.file_get( 'bar.test', 'localhost', 'bar.test', 'config-file-from-bar.test', bar_output, config_path=config_paths['bar.test'], wallet_keys=wallet_keys['bar.test'] )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    # have baz.test receive foo.test's file 
    log.debug("baz.test recieves foo.test's file")
    res = blockstack_file.file_get( 'baz.test', 'laptop', 'foo.test', 'config-file-from-foo.test', baz_output, config_path=config_paths['baz.test'], wallet_keys=wallet_keys['baz.test'] )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    # have bar.test receive foo.test's file to its mobile-phone key
    log.debug("bar.test receives foo.test's file")
    res = blockstack_file.file_get( 'bar.test', 'mobile-phone', 'foo.test', 'config-file-from-foo.test', bar_output, config_path=config_paths['bar.test'], wallet_keys=wallet_keys['bar.test'] )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    # have baz.test try to receive bar.test's file (should fail)
    log.debug("baz.test receives bar.test's file (should fail)")
    res = blockstack_file.file_get( 'baz.test', 'laptop', 'bar.test', 'config-file-from-bar.test', baz_fail_output, config_path=config_paths['baz.test'], wallet_keys=wallet_keys['baz.test'] )
    print json.dumps(res, indent=4, sort_keys=True)
    if 'error' not in res or res['error'] != 'Failed to decrypt data':
        print 'baz decrypting hidden file: succeeded when we should not have, or failed incorrectly: %s' % res
        error = True
        return

    # have foo.test and bar.test try to receive baz.test's file (should fail)
    for (name, failpath) in [('foo.test', foo_fail_output), ('bar.test', bar_fail_output)]:
        log.debug("%s receives baz.test's file (should fail)" % name)
        res = blockstack_file.file_get( name, 'localhost', 'baz.test', 'config-file-from-baz.test', failpath, config_path=config_paths[name], wallet_keys=wallet_keys[name] )
        print json.dumps(res, indent=4, sort_keys=True)
        if 'error' not in res or res['error'] != 'Failed to decrypt data':
            print '%s decrypting hidden file: succeeded when we should not have, or fialed incorrectly: %s' % (name, res)
            error = True
            return

    # regenerate everyone's keys
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

    res = blockstack_file.file_key_regenerate( "bar.test", "mobile-phone", config_path=config_paths['bar.test'], wallet_keys=wallet_keys['bar.test'])
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    res = blockstack_file.file_key_regenerate( "baz.test", "laptop", config_path=config_paths['baz.test'], wallet_keys=wallet_keys['baz.test'] )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    # have foo.test receive bar.test's file, despite regeneration
    log.debug("foo.test receives bar.test's file, despite regeneration")
    res = blockstack_file.file_get( 'foo.test', 'localhost', 'bar.test', 'config-file-from-bar.test', foo_output, config_path=config_paths['foo.test'], wallet_keys=wallet_keys['foo.test'] )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    if 'warning' not in res or res['warning'] != 'Used stale key':
        print json.dumps(res, indent=4, sort_keys=True)
        print "did not use stale key"
        error = True
        return

    # have bar.test receive bar.test's file to localhost 
    log.debug("bar.test receives bar.tests's file, despite regeneration")
    res = blockstack_file.file_get( 'bar.test', 'localhost', 'bar.test', 'config-file-from-bar.test', bar_output, config_path=config_paths['bar.test'], wallet_keys=wallet_keys['bar.test'] )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    if 'warning' not in res or res['warning'] != 'Used stale key':
        print json.dumps(res, indent=4, sort_keys=True)
        print "did not use stale key"
        error = True
        return

    # have baz.test receive foo.test's file 
    log.debug("baz.test recieves foo.test's file, despite regeneration")
    res = blockstack_file.file_get( 'baz.test', 'laptop', 'foo.test', 'config-file-from-foo.test', baz_output, config_path=config_paths['baz.test'], wallet_keys=wallet_keys['baz.test'] )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    if 'warning' not in res or res['warning'] != 'Used stale key':
        print json.dumps(res, indent=4, sort_keys=True)
        print "did not use stale key"
        error = True
        return

    # have bar.test receive foo.test's file to its mobile-phone key
    log.debug("bar.test receives foo.test's file, despite regeneration")
    res = blockstack_file.file_get( 'bar.test', 'mobile-phone', 'foo.test', 'config-file-from-foo.test', bar_output, config_path=config_paths['bar.test'], wallet_keys=wallet_keys['bar.test'] )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    if 'warning' not in res or res['warning'] != 'Used stale key':
        print json.dumps(res, indent=4, sort_keys=True)
        print "did not use stale key"
        error = True
        return

    # delete the file from foo
    log.debug("delete foo.test's file")
    res = blockstack_file.file_delete( 'foo.test', 'config-file-from-foo.test', config_path=config_paths['foo.test'], wallet_keys=wallet_keys['foo.test'] )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 

    # delete the file from bar
    log.debug("delete bar.test's file")
    res = blockstack_file.file_delete( 'bar.test', 'config-file-from-bar.test', config_path=config_paths['bar.test'], wallet_keys=wallet_keys['bar.test'] )
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    # verify that no one can read foo's file 
    for (name, host, failpath) in [('foo.test', 'localhost', foo_fail_output), ('bar.test', 'mobile-phone', bar_fail_output), ('baz.test', 'laptop', baz_fail_output)]:
        log.debug("%s receives foo.test's deleted file (should fail)" % name)
        res = blockstack_file.file_get( name, host, 'foo.test', 'config-file-from-foo.test', failpath, config_path=config_paths[name], wallet_keys=wallet_keys[name])
        print json.dumps(res, indent=4, sort_keys=True)
        if 'error' not in res or res['error'] != 'Failed to get encrypted file':
            print 'reading deleted file: succeeded when we should not have, or failed incorrectly: %s' % res
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

    # files check out 
    for path in [foo_output, bar_output]:
        with open(path, "r") as f:
            dat = f.read()

        if dat != TEST_OUTPUT_FILE:
            print "wrong data: %s" % path
            return False

    # files are no longer listed in foo.test or bar.test
    for name in ['foo.test', 'bar.test']:
        listing = blockstack_file.file_list( 'foo.test', config_path=config_paths[name], wallet_keys=wallet_keys[name] )
        if 'error' in listing:
            print "no listing: %s" % listing['error']
            return False

        if len(listing['listing']) != 0:
            print "still listed: %s" % listing['listing']
            return False

    # baz still has a file 
    listing = blockstack_file.file_list( 'baz.test', config_path=config_paths[name], wallet_keys=wallet_keys[name] )
    if 'error' in listing:
        print "no listing: %s" % listing['error']
        return False

    if len(listing['listing']) != 1:
        print "invalid listing: %s" % listing['listing']
        return False

    if listing['listing'][0]['data_id'] != 'files:config-file-from-baz.test':
        print 'not present in listing: %s' % listing['listing']
        return False

    return True
