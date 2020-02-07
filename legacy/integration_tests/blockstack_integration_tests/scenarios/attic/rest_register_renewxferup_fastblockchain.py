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
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 680
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 681
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 2
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 2
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_GRACE_PERIOD 5
"""

import os
import testlib
import virtualchain
import urllib2
import json
import blockstack_client
import blockstack_profiles
import blockstack_zones
import sys
import keylib
import time

from keylib import ECPrivateKey, ECPublicKey

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
    testlib.Wallet( "5KMbNjgZt29V6VNbcAmebaUT2CZMxqSridtM46jv4NkKTP8DHdV", 100000000000 ),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
wallet_keys = None
wallet_keys_2 = None
error = False

index_file_data = "<html><head></head><body>foo.test hello world</body></html>"
resource_data = "hello world"
    

def scenario( wallets, **kw ):

    global wallet_keys, wallet_keys_2, error, index_file_data, resource_data

    wallet_keys = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[5].privkey, wallets[3].privkey, wallets[3].privkey )
    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )

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
    
    # migrate profiles, but no data key in the zone file 
    res = testlib.migrate_profile( "foo.test", zonefile_has_data_key=False, proxy=test_proxy, wallet_keys=wallet_keys )
    if 'error' in res:
        res['test'] = 'Failed to initialize foo.test profile'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()
    
    testlib.next_block( **kw )

    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)

    # make a session 
    datastore_pk = keylib.ECPrivateKey(wallets[-1].privkey).to_hex()
    res = testlib.blockstack_cli_app_signin("foo.test", datastore_pk, 'register.app', ['names', 'register', 'prices', 'zonefiles', 'blockchain', 'node_read', 'user_read'])
    if 'error' in res:
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 

    ses = res['token']

    # register the name bar.test. autogenerate the rest 
    old_user_zonefile = blockstack_client.zonefile.make_empty_zonefile('bar.test', None)
    old_user_zonefile_txt = blockstack_zones.make_zone_file(old_user_zonefile)

    res = testlib.blockstack_REST_call('POST', '/v1/names', ses, data={'name': 'bar.test', 'zonefile': old_user_zonefile_txt, 'make_profile': True} )
    if 'error' in res:
        res['test'] = 'Failed to register user'
        print json.dumps(res)
        error = True
        return False

    print res
    tx_hash = res['response']['transaction_hash']

    # wait for preorder to get confirmed...
    for i in xrange(0, 6):
        testlib.next_block( **kw )

    res = testlib.verify_in_queue(ses, 'bar.test', 'preorder', tx_hash )
    if not res:
        return False

    # wait for the preorder to get confirmed
    for i in xrange(0, 4):
        testlib.next_block( **kw )

    # wait for register to go through 
    print 'Wait for register to be submitted'
    time.sleep(10)

    # wait for the register/update to get confirmed 
    for i in xrange(0, 6):
        testlib.next_block( **kw )

    res = testlib.verify_in_queue(ses, 'bar.test', 'register', None )
    if not res:
        return False

    for i in xrange(0, 3):
        testlib.next_block( **kw )

    # should have nine confirmations now
    res = testlib.get_queue(ses, 'register')
    if 'error' in res:
        print res
        return False
    
    if len(res) != 1:
        print res
        return False

    reg = res[0]
    confs = blockstack_client.get_tx_confirmations(reg['tx_hash'])
    if confs != 9:
        print 'wrong number of confs for {} (expected 9): {}'.format(reg['tx_hash'], confs)
        return False

    # stop the API server
    testlib.stop_api()

    # advance blockchain 
    testlib.next_block(**kw)
    testlib.next_block(**kw)

    confs = blockstack_client.get_tx_confirmations(reg['tx_hash'])
    if confs != 11:
        print 'wrong number of confs for {} (expected 11): {}'.format(reg['tx_hash'], confs)
        return False

    # make sure the registrar does not process reg/up zonefile replication
    # (i.e. we want to make sure that the zonefile gets processed even if the blockchain goes too fast)
    os.environ['BLOCKSTACK_TEST_REGISTRAR_FAULT_INJECTION_SKIP_REGUP_REPLICATION'] = '1'
    testlib.start_api("0123456789abcdef")

    print 'Wait to verify that we do not remove the zone file just because the tx is confirmed'
    time.sleep(10)

    # verify that this is still in the queue
    res = testlib.get_queue(ses, 'register')
    if 'error' in res:
        print res
        return False
    
    if len(res) != 1:
        print res
        return False
    
    # clear the fault
    print 'Clearing regup replication fault'
    testlib.blockstack_test_setenv("BLOCKSTACK_TEST_REGISTRAR_FAULT_INJECTION_SKIP_REGUP_REPLICATION", "0")

    # wait for register to go through 
    print 'Wait for zonefile to replicate'
    time.sleep(10)

    res = testlib.blockstack_REST_call("GET", "/v1/names/bar.test", ses)
    if 'error' in res or res['http_status'] != 200:
        res['test'] = 'Failed to get name bar.test'
        print json.dumps(res)
        return False

    old_expire_block = res['response']['expire_block']

    # get the zonefile
    res = testlib.blockstack_REST_call("GET", "/v1/names/bar.test/zonefile", ses )
    if 'error' in res or res['http_status'] != 200:
        res['test'] = 'Failed to get name zonefile'
        print json.dumps(res)
        return False

    # zonefile must not have a public key listed
    zonefile_txt = res['response']['zonefile']
    print zonefile_txt

    parsed_zonefile = blockstack_zones.parse_zone_file(zonefile_txt)
    if parsed_zonefile.has_key('txt'):
        print 'have txt records'
        print parsed_zonefile
        return False

    # renew it, but put the *current* owner key as the zonefile's *new* public key
    new_user_zonefile = blockstack_client.zonefile.make_empty_zonefile('bar.test', wallets[3].pubkey_hex )
    new_user_zonefile_txt = blockstack_zones.make_zone_file(new_user_zonefile)

    res = testlib.blockstack_REST_call("POST", "/v1/names", ses, data={'name': 'bar.test', 'zonefile': new_user_zonefile_txt} )
    if 'error' in res or res['http_status'] != 202:
        res['test'] = 'Failed to renew name'
        print json.dumps(res)
        return False

    # verify in renew queue
    for i in xrange(0, 6):
        testlib.next_block( **kw )

    res = testlib.verify_in_queue(ses, 'bar.test', 'renew', None )
    if not res:
        return False

    for i in xrange(0, 3):
        testlib.next_block( **kw )
 
    # should have nine confirmations now
    res = testlib.get_queue(ses, 'renew')
    if 'error' in res:
        print res
        return False
    
    if len(res) != 1:
        print res
        return False

    reg = res[0]
    confs = blockstack_client.get_tx_confirmations(reg['tx_hash'])
    if confs != 9:
        print 'wrong number of confs for {} (expected 9): {}'.format(reg['tx_hash'], confs)
        return False

    # stop the API server
    testlib.stop_api()

    # advance blockchain 
    testlib.next_block(**kw)
    testlib.next_block(**kw)

    confs = blockstack_client.get_tx_confirmations(reg['tx_hash'])
    if confs != 11:
        print 'wrong number of confs for {} (expected 11): {}'.format(reg['tx_hash'], confs)
        return False

    # make the registrar skip the first few steps, so the only thing it does is clear out confirmed updates
    # (i.e. we want to make sure that the renewal's zonefile gets processed even if the blockchain goes too fast)
    os.environ['BLOCKSTACK_TEST_REGISTRAR_FAULT_INJECTION_SKIP_RENEWAL_REPLICATION'] = '1'
    testlib.start_api("0123456789abcdef")

    # wait a while
    print 'Wait to verify that clearing out confirmed transactions does NOT remove zonefiles'
    time.sleep(10)

    # verify that this is still in the queue
    res = testlib.get_queue(ses, 'renew')
    if 'error' in res:
        print res
        return False
    
    if len(res) != 1:
        print res
        return False

    # clear the fault
    print 'Clearing renewal replication fault'
    testlib.blockstack_test_setenv("BLOCKSTACK_TEST_REGISTRAR_FAULT_INJECTION_SKIP_RENEWAL_REPLICATION", "0")

    # now the renewal zonefile should replicate
    print 'Wait for renewal zonefile to replicate'
    time.sleep(10)

    # new expire block
    res = testlib.blockstack_REST_call("GET", "/v1/names/bar.test", ses)
    if 'error' in res or res['http_status'] != 200:
        res['test'] = 'Failed to get name bar.test'
        print json.dumps(res)
        return False

    new_expire_block = res['response']['expire_block']

    # do we have the history for the name?
    res = testlib.blockstack_REST_call("GET", "/v1/names/bar.test/history", ses )
    if 'error' in res or res['http_status'] != 200:
        res['test'] = "Failed to get name history for bar.test"
        print json.dumps(res)
        return False

    # valid history?
    hist = res['response']
    if len(hist.keys()) != 3:
        res['test'] = 'Failed to get update history'
        res['history'] = hist
        print json.dumps(res, indent=4, sort_keys=True)
        return False

    # get the zonefile
    res = testlib.blockstack_REST_call("GET", "/v1/names/bar.test/zonefile", ses )
    if 'error' in res or res['http_status'] != 200:
        res['test'] = 'Failed to get name zonefile'
        print json.dumps(res)
        return False

    # zonefile must have old owner key
    zonefile_txt = res['response']['zonefile']
    parsed_zonefile = blockstack_zones.parse_zone_file(zonefile_txt)
    if not parsed_zonefile.has_key('txt'):
        print 'missing txt'
        print parsed_zonefile
        return False

    found = False
    for txtrec in parsed_zonefile['txt']:
        if txtrec['name'] == 'pubkey' and txtrec['txt'] == 'pubkey:data:{}'.format(wallets[3].pubkey_hex):
            found = True

    if not found:
        print 'missing public key {}'.format(wallets[3].pubkey_hex)
        return False

    # profile lookup must work 
    res = testlib.blockstack_REST_call("GET", "/v1/users/bar.test", ses)
    if 'error' in res or res['http_status'] != 200:
        res['text'] = 'failed to get profile for bar.test'
        print json.dumps(res)
        return False

    print ''
    print json.dumps(res['response'], indent=4, sort_keys=True)
    print ''

    # verify pushed back 
    if old_expire_block + 10 > new_expire_block:
        # didn't go through
        print >> sys.stderr, "Renewal didn't work: %s --> %s" % (old_expire_block, new_expire_block)
        return False


def check( state_engine ):

    global wallet_keys, error, index_file_data, resource_data
    
    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG")
    assert config_path

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

    names = ['foo.test', 'bar.test']
    wallet_keys_list = [wallet_keys, wallet_keys]
    test_proxy = testlib.TestAPIProxy()

    for i in xrange(0, len(names)):
        name = names[i]
        wallet_payer = 5
        wallet_owner = 3
        wallet_data_pubkey = 4

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
            print "name {} has wrong owner".format(name)
            return False 

    return True
