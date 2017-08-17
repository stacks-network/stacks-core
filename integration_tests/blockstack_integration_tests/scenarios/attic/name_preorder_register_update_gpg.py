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
    testlib.Wallet( "5J3aDqRwXrtSXjdzzYxdVd9zTLCP39xSy4SzFeh49JDhNQ8qAMM", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
wallet_keys = None
wallet_keys_2 = None
error = False
gpghome = None

key_names = {
    'foo.test': [], # to be filled in 
    'bar.test': []  # to be filled in 
}

def scenario( wallets, **kw ):

    global wallet_keys, wallet_keys_2, key_names, error, gpghome


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
    wallet_keys = blockstack_client.make_wallet_keys( owner_privkey=wallets[3].privkey, data_privkey=wallets[4].privkey, payment_privkey=wallets[8].privkey )
    wallet_keys_2 = blockstack_client.make_wallet_keys( owner_privkey=wallets[6].privkey, data_privkey=wallets[7].privkey, payment_privkey=wallets[9].privkey )

    # migrate profiles 
    res = testlib.migrate_profile( "foo.test", proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in res:
        res['test'] = 'Failed to initialize foo.test profile'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 

    res = testlib.migrate_profile( "bar.test", proxy=test_proxy, wallet_keys=wallet_keys_2 )
    if 'error' in res:
        res['test'] = 'Failed to initialize bar.test profile'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    testlib.next_block( **kw )

    # add account keys 
    res = blockstack_gpg.gpg_profile_create_key( "foo.test", "foo_test_account_key", immutable=False,
                                                proxy=test_proxy, wallet_keys=wallet_keys, config_dir=testlib.get_working_dir(**kw),
                                                gpghome=testlib.gpg_key_dir(**kw), use_key_server=False )

    if 'error' in res:
        res['test'] = 'Failed to create foo.test account key'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 

    else:
        key_names['foo.test'].append( res )

    res = blockstack_gpg.gpg_profile_create_key( "bar.test", "bar_test_account_key", immutable=False,
                                                proxy=test_proxy, wallet_keys=wallet_keys_2, config_dir=testlib.get_working_dir(**kw),
                                                gpghome=testlib.gpg_key_dir(**kw), use_key_server=False )

    if 'error' in res:
        res['test'] = 'Failed to create bar.test account key'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 

    else:
        key_names['bar.test'].append( res )

    testlib.next_block( **kw )

    # add immutable app keys
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] ) 
    res = blockstack_gpg.gpg_app_create_key( "foo.test", "secure_messaging", "foo_test_immutable_secmsg_key", immutable=True,
                                              proxy=test_proxy, wallet_keys=wallet_keys, config_dir=testlib.get_working_dir(**kw) )

    if 'error' in res:
        res['test'] = 'Failed to create foo.test immutable app key'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 
    else:
        key_names['foo.test'].append( res )

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    # wait for it to go through
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "wait for confirmation"
    time.sleep(10)
    
    # set new wallet keys
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys_2['payment_privkey'], wallet_keys_2['owner_privkey'], wallet_keys_2['data_privkey'] ) 
    res = blockstack_gpg.gpg_app_create_key( "bar.test", "secure_messaging", "bar_test_immutable_secmsg_key", immutable=True,
                                                proxy=test_proxy, wallet_keys=wallet_keys_2, config_dir=testlib.get_working_dir(**kw) )

    if 'error' in res:
        res['test'] = 'Failed to create bar.test immutable app key'
        print json.dumps(res, indent=4, sort_keys=True )
        error = True
        return
    else:
        key_names['bar.test'].append( res )

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    # wait for it to go through
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "wait for confirmation"
    time.sleep(10)

    # add mutable app keys 
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] ) 
    res = blockstack_gpg.gpg_app_create_key( "foo.test", "less-secure_messaging", "foo_test_mutable_secmsg_key",
                                                proxy=test_proxy, wallet_keys=wallet_keys, config_dir=testlib.get_working_dir(**kw) )

    if 'error' in res:
        res['test'] = 'Failed to create foo.test mutable app key'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return
    else:
        key_names['foo.test'].append( res )

    testlib.next_block( **kw )
    
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys_2['payment_privkey'], wallet_keys_2['owner_privkey'], wallet_keys_2['data_privkey'] ) 
    res = blockstack_gpg.gpg_app_create_key( "bar.test", "less-secure_messaging", "bar_test_mutable_secmsg_key",
                                                proxy=test_proxy, wallet_keys=wallet_keys_2, config_dir=testlib.get_working_dir(**kw) )

    if 'error' in res:
        res['test'] = 'Failed to create bar.test mutable app key'
        print json.dumps(res, indent=4, sort_keys=True )
        error = True
        return
    else:
        key_names['bar.test'].append( res )

    testlib.next_block( **kw )

    # add profile keys that we'll delete
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] ) 
    res = blockstack_gpg.gpg_profile_create_key( "foo.test", "foo_test_deleted_account_key", immutable=True,
                                                proxy=test_proxy, wallet_keys=wallet_keys, config_dir=testlib.get_working_dir(**kw),
                                                gpghome=testlib.gpg_key_dir(**kw), use_key_server=False)

    foo_profile_delete_key_id = None
    if 'error' in res:
        res['test'] = 'Failed to create deletable foo.test account key'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return
    else:
        key_names['foo.test'].append( res )
        foo_profile_delete_key_id = res['key_id']

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    # wait for it to go through
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "wait for confirmation"
    time.sleep(10)

    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys_2['payment_privkey'], wallet_keys_2['owner_privkey'], wallet_keys_2['data_privkey'] ) 
    res = blockstack_gpg.gpg_profile_create_key( "bar.test", "bar_test_deleted_account_key", immutable=True,
                                                proxy=test_proxy, wallet_keys=wallet_keys_2, config_dir=testlib.get_working_dir(**kw),
                                                gpghome=testlib.gpg_key_dir(**kw), use_key_server=False)

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    # wait for it to go through
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "wait for confirmation"
    time.sleep(10)

    bar_profile_delete_key_id = None
    if 'error' in res:
        res['test'] = 'Failed to create deletable bar.test account key'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return
    else:
        key_names['bar.test'].append( res )
        bar_profile_delete_key_id = res['key_id']

    # add immutable app keys, which we can delete
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] ) 
    res = blockstack_gpg.gpg_app_create_key( "foo.test", "immutable_delete", "foo_test_deleted_immutable_secmsg_key", immutable=True,
                                                proxy=test_proxy, wallet_keys=wallet_keys, config_dir=testlib.get_working_dir(**kw) )

    foo_immutable_delete_key_id = None
    if 'error' in res:
        res['test'] = 'Failed to create deletable foo.test immutable app key'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return
    else:
        key_names['foo.test'].append( res )
        foo_immutable_delete_key_id = res['key_id']

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    # wait for it to go through
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "wait for confirmation"
    time.sleep(10)

    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys_2['payment_privkey'], wallet_keys_2['owner_privkey'], wallet_keys_2['data_privkey'] ) 
    res = blockstack_gpg.gpg_app_create_key( "bar.test", "immutable_delete", "bar_test_deleted_immutable_secmsg_key", immutable=True,
                                                proxy=test_proxy, wallet_keys=wallet_keys_2, config_dir=testlib.get_working_dir(**kw) )
    
    bar_immutable_delete_key_id = None
    if 'error' in res:
        res['test'] = 'Failed to create deletable bar.test immutable app key'
        print json.dumps(res, indent=4, sort_keys=True )
        error = True
        return
    else:
        key_names['bar.test'].append( res )
        bar_immutable_delete_key_id = res['key_id']

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    # wait for it to go through
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "wait for confirmation"
    time.sleep(10)

    # add mutable app keys which we can delete
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] ) 
    res = blockstack_gpg.gpg_app_create_key( "foo.test", "mutable_delete", "foo_test_deleted_mutable_secmsg_key",
                                                proxy=test_proxy, wallet_keys=wallet_keys, config_dir=testlib.get_working_dir(**kw) )

    foo_mutable_delete_key_id = None
    if 'error' in res:
        res['test'] = 'Failed to create deletable mutable foo.test app key'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return
    else:
        key_names['foo.test'].append( res )
        foo_mutable_delete_key_id = res['key_id']

    testlib.next_block( **kw )
    
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys_2['payment_privkey'], wallet_keys_2['owner_privkey'], wallet_keys_2['data_privkey'] ) 
    res = blockstack_gpg.gpg_app_create_key( "bar.test", "mutable_delete", "bar_test_deleted_mutable_secmsg_key",
                                                proxy=test_proxy, wallet_keys=wallet_keys_2, config_dir=testlib.get_working_dir(**kw) )

    bar_mutable_delete_key_id = None
    if 'error' in res:
        res['test'] = 'Failed to create deletable mutable bar.test app key'
        print json.dumps(res, indent=4, sort_keys=True )
        error = True
        return
    else:
        key_names['bar.test'].append( res )
        bar_mutable_delete_key_id = res['key_id']

    testlib.next_block( **kw )

    # delete profile keys
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] ) 
    res = blockstack_gpg.gpg_profile_delete_key( "foo.test", foo_profile_delete_key_id, proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in res:
        res['test'] = 'Failed to create deletable account foo.test profile key'
        print json.dumps(res, indent=4, sort_keys=True )
        error = True
        return

    testlib.next_block( **kw )
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys_2['payment_privkey'], wallet_keys_2['owner_privkey'], wallet_keys_2['data_privkey'] ) 
    res = blockstack_gpg.gpg_profile_delete_key( "bar.test", bar_profile_delete_key_id, proxy=test_proxy, wallet_keys=wallet_keys_2 )
    if 'error' in res:
        res['test'] = 'Failed to create deletable account bar.test profile key'
        print json.dumps(res, indent=4, sort_keys=True )
        error = True
        return 

    # delete immutable app keys 
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] ) 
    res = blockstack_gpg.gpg_app_delete_key( "foo.test", "immutable_delete", "foo_test_deleted_immutable_secmsg_key", 
                                            immutable=True, proxy=test_proxy, wallet_keys=wallet_keys, config_dir=testlib.get_working_dir(**kw))

    if 'error' in res:
        res['test'] = 'Failed to create deletable foo.test immutable app key'
        print json.dumps(res, indent=4, sort_keys=True )
        error = True
        return 

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    # wait for it to go through
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "wait for confirmation"
    time.sleep(10)

    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys_2['payment_privkey'], wallet_keys_2['owner_privkey'], wallet_keys_2['data_privkey'] ) 
    res = blockstack_gpg.gpg_app_delete_key( "bar.test", "immutable_delete", "bar_test_deleted_immutable_secmsg_key",
                                            immutable=True, proxy=test_proxy, wallet_keys=wallet_keys_2, config_dir=testlib.get_working_dir(**kw))

    if 'error' in res:
        res['test'] = 'Failed to create deletable bar.test immutable app key'
        print json.dumps(res, indent=4, sort_keys=True )
        error = True
        return 

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    # wait for it to go through
    for i in xrange(0, 12):
        testlib.next_block( **kw )
    print "wait for confirmation"
    time.sleep(10)

    # delete mutable app keys
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys['payment_privkey'], wallet_keys['owner_privkey'], wallet_keys['data_privkey'] ) 
    res = blockstack_gpg.gpg_app_delete_key( "foo.test", "mutable_delete", "foo_test_deleted_mutable_secmsg_key",
                                            proxy=test_proxy, wallet_keys=wallet_keys, config_dir=testlib.get_working_dir(**kw))

    if 'error' in res:
        res['test'] = 'Failed to create deletable foo.test mutable app key'
        print json.dumps(res, indent=4, sort_keys=True )
        error = True 
        return 

    testlib.next_block( **kw )
    testlib.blockstack_client_set_wallet( "0123456789abcdef", wallet_keys_2['payment_privkey'], wallet_keys_2['owner_privkey'], wallet_keys_2['data_privkey'] ) 
    res = blockstack_gpg.gpg_app_delete_key( "bar.test", "mutable_delete", "bar_test_deleted_mutable_secmsg_key",
                                            proxy=test_proxy, wallet_keys=wallet_keys_2, config_dir=testlib.get_working_dir(**kw))

    if 'error' in res:
        res['test'] = 'Failed to create deletable bar.test mutable app key'
        print json.dumps(res, indent=4, sort_keys=True )
        error = True 
        return 

    testlib.next_block( **kw )
 
    gpghome = testlib.gpg_key_dir(**kw)


def check( state_engine ):

    global wallet_keys, wallet_keys_2, key_names, error, gpghome

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

    # not preordered
    names = ['foo.test', 'bar.test']
    wallet_keys_list = [wallet_keys, wallet_keys_2]

    for i in xrange(0, len(names)):
        name = names[i]
        wallet_payer = 3 * (i+1) - 1
        wallet_owner = 3 * (i+1)
        wallet_data_pubkey = 3 * (i+1) + 1
        wallet_keys = wallet_keys_list[i]
        key_res = key_names[name]

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

        # account listing exists, and other keys are deleted
        account_key_listing = blockstack_gpg.gpg_list_profile_keys( name )
        secure_app_listing = blockstack_gpg.gpg_list_app_keys( name, "secure_messaging" )
        less_secure_app_listing = blockstack_gpg.gpg_list_app_keys( name, "less-secure_messaging" )

        if 'error' in account_key_listing:
            print json.dumps(account_key_listing)
            return False 

        if len(account_key_listing) != 1:
            print "Invalid account keys:\n%s" % json.dumps(account_key_listing)
            return False 

        key_id, key_url = account_key_listing[0]['identifier'], account_key_listing[0]['contentUrl']
        if key_url != key_res[0]['key_url']:
            print "Key ID mismatch (account): %s != %s\nFull listing:\n%s\n\nKeys we generated:\n%s\n" % \
                    (key_url, key_res[0]['key_url'], account_key_listing[0], json.dumps(key_res, indent=4, sort_keys=True))
            return False 

        # immutable listings exist, and other keys are deleted
        if 'error' in secure_app_listing:
            print json.dumps(secure_app_listing)
            return False 

        if len(secure_app_listing) != 1:
            print "Invalid immutable keys:\n%s" % json.dumps(secure_app_listing)
            return False 

        key_id, key_url = secure_app_listing[0]['keyName'], secure_app_listing[0]['contentUrl']
        if key_url != key_res[1]['key_url']:
            print "Key ID mismatch (immutable app): %s != %s\nFull listing:\n%s\n\nKeys we generated:\n%s\n" % \
                    (key_url, key_res[1]['key_url'], secure_app_listing[0], json.dumps(key_res, indent=4, sort_keys=True))
            return False 

        # mutable listings exist, and other keys are deleted
        if 'error' in less_secure_app_listing:
            print json.dumps(less_secure_app_listing)
            return False 

        if len(less_secure_app_listing) != 1:
            print "Invalid mutable keys (mutable app):\n%s" % json.dumps(less_secure_app_listing)
            return False 

        key_id, key_url = less_secure_app_listing[0]['keyName'], less_secure_app_listing[0]['contentUrl']
        if key_url != key_res[2]['key_url']:
            print "Key ID mismatch: %s != %s\nFull listing:\n%s\n\nKeys we generated:\n%s\n" % \
                    (key_url, key_res[2]['key_url'], less_secure_app_listing[0], json.dumps(key_res, indent=4, sort_keys=True))
            return False

        profile_key = blockstack_gpg.gpg_profile_get_key( name, account_key_listing[0]['keyName'], gpghome=gpghome )
        if 'error' in profile_key:
            print "no key in account %s: %s" % (account_key_listing, profile_key['error'])
            return False

        secure_app_key = blockstack_gpg.gpg_app_get_key( name, "secure_messaging", secure_app_listing[0]['keyName'], \
                                                         immutable=True )

        if 'error' in secure_app_key:
            print "no key in secure_messaging listing %s: %s" % (secure_app_listing, secure_app_key['error'])
            return False

        less_secure_app_key = blockstack_gpg.gpg_app_get_key( name, "less-secure_messaging", less_secure_app_listing[0]['keyName'] )
        if 'error' in less_secure_app_key:
            print "no key in less-secure_messaging listing %s: %s" % (less_secure_app_listing, less_secure_app_key['error'])
            return False

    return True
