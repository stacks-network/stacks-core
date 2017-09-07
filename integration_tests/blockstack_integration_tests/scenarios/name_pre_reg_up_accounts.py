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
    testlib.Wallet( "5KcNen67ERBuvz2f649t9F2o1ddTjC5pVUEqcMtbxNgHqgxG2gZ", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
wallet_keys = None
wallet_keys_2 = None
error = False

key_names = {
    'foo.test': [], # to be filled in 
    'bar.test': []  # to be filled in 
}

def scenario( wallets, **kw ):

    global wallet_keys, wallet_keys_2, key_names, error


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

    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )
    wallet_keys = blockstack_client.make_wallet_keys( owner_privkey=wallets[3].privkey, data_privkey=wallets[4].privkey, payment_privkey=wallets[5].privkey )

    # migrate profiles 
    res = testlib.migrate_profile( "foo.test", proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in res:
        res['test'] = 'Failed to initialize foo.test profile'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 

    # tell serialization-checker that value_hash can be ignored in this block
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    testlib.next_block( **kw )

    # make an account 
    res = testlib.blockstack_cli_put_account("foo.test", "serviceFoo", "serviceFooID", "foo://bar.com", None, extra_data='foofield=foo!', wallet_keys=wallet_keys )
    if 'error' in res:
        res['test'] = 'Failed to create foo.test account'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 

    res = testlib.blockstack_cli_put_account("foo.test", "deletedService", "deletedServiceID", "foo://deleted", None, extra_data='barfield=bar!', wallet_keys=wallet_keys ) 
    if 'error' in res:
        res['test'] = 'Failed to create foo.test deletedService account'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 

    # delete an account 
    res = testlib.blockstack_cli_delete_account("foo.test", "deletedService", "deletedServiceID", None, wallet_keys=wallet_keys )
    if 'error' in res:
        res['test'] = 'Failed to delete foo.test deletedService'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return

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

    # not preordered
    names = ['foo.test']
    wallet_keys_list = [wallet_keys]
    test_proxy = testlib.TestAPIProxy()

    for i in xrange(0, len(names)):
        name = names[i]
        wallet_payer = 3 * (i+1) - 1
        wallet_owner = 3 * (i+1)
        wallet_data_pubkey = 3 * (i+1) + 1
        wallet_keys = wallet_keys_list[i]

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

        # only serviceFoo exists
        accounts = testlib.blockstack_cli_list_accounts( "foo.test" )
        if len(accounts) != 1:
            print "wrong number of accounts"
            print json.dumps(accounts, indent=4, sort_keys=True)
            return False 

        account = accounts[0]
        on_file_account = testlib.blockstack_cli_get_account( "foo.test", "serviceFoo", "serviceFooID" )
        if 'error' in on_file_account:
            print json.dumps(on_file_account, sort_keys=True, indent=4)
            return False 

        if account != on_file_account:
            print "wrong service\nexpected:\n%s\n\ngot:\n%s\n" % \
                    (json.dumps(account, indent=4, sort_keys=True),
                     json.dumps(on_file_account, indent=4, sort_keys=True))

            return False
            
        if account['identifier'] != 'serviceFooID':
            print "wrong identifier: %s" % account
            return False 

        if account['contentUrl'] != 'foo://bar.com':
            print "wrong URL: %s" % account
            return False 

        if account['service'] != 'serviceFoo':
            print "wrong service: %s" % account
            return False

    return True
