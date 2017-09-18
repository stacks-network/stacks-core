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
import sys
os.environ["CLIENT_STORAGE_DRIVERS"] = "blockstack_server"
os.environ["CLIENT_STORAGE_DRIVERS_REQUIRED_WRITE"] = "blockstack_server"

# deactivate storage in the test runner, and point to our server instead
os.environ['DATA_SERVERS'] = 'localhost:16300'

import testlib
import virtualchain
import json
import time
import blockstack_client
import xmlrpclib
import blockstack
import traceback
import blockstack_zones 
import base64

# activate multisig
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 250
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
"""

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.Wallet( "5K9LmMQskQ9jP1p7dyieLDAeB6vsAj4GK8dmGNJAXS1qHDqnWhP", 100000000000 ),
    testlib.Wallet( "5KcNen67ERBuvz2f649t9F2o1ddTjC5pVUEqcMtbxNgHqgxG2gZ", 100000000000 ),
    testlib.Wallet( "5J5uAKL8s62hddganFJaCkWi3Me7PFoc7fks9hAzjtWG1NDjmUK", 100000000000 ),
    testlib.MultisigWallet(2, "5JfHdMq9XnZ9mwW5H6LsfVCn9u6iGAj2FCVYtfhcHn72Tphvm5P", "5JaqLZaKD7cgkfsxSZBNiu6gaFxo1XAiTXw1mhtatipNNCtZBZG", "5KNsAkiHRDZb5Yyedxov2Fncr6CcNPV52yqJbzQ8M2W6dkg2qJp"),
    testlib.MultisigWallet(2, "5JPrkpfLT3rDf1Lgm1DpA2Cfepwf9wCtEbDx1HSEdd4J2R5YMxZ", "5JiALcfvzFsKcvLnHf7ECgLdp6FxbcAXB1GPvEYP7HeigbDCQ9E", "5KScD5XL5Hj83Yjvm3u4HD78vSYwFRyq9StTLPnrWrCTGiqTvVP"),
    testlib.MultisigWallet(2, '5JPR5iVN8KGMdU9JfzoTCsipXazUcZPRY8zp7f3g8FRff2HBaAV', '5KTTwEyATY8v12MjNdoeA1u2ZGqgjnBNcyZjk3YSkiVJWYxqBSm', '5KQ1s8UEYz3oyFRUejBvb1imMdtpoP98w6NQYGxQsSo3u6DmztZ'),
    testlib.MultisigWallet(2, '5JpAkdEJuzF8E74UptksRLiB6Bf9QnwxGQutJTRWo5EAGVZfXmY', '5Hyc4wreVpZyzcfb56Zt1ymovda2xGucGZsAwoQz34iYK6aEKhR', '5JypKiQGiaD8AN6X86xtnuQYj7nnpLvp4VfcTVdDh4yFkLewAGx'),
    testlib.MultisigWallet(2, '5KXzk8m7sfVEciwwtb5DTBNMrHFBgn8wEWtfyi3KPNjQazWyF3e', '5JDy1qYj2no1SSXMsn8suPP6gMVofLjCR5Qfz44KB2VM6Kd2EKq', '5KBpBME2Rk7gjxoYxaB1JBrumS9zk5U6GYNRyG6BX4KzP8aovwP'),
    testlib.MultisigWallet(2, '5HqVVmKy1bqP8qZrTpk9akjzEyrC1N7JjcDD2nwaWdydBz7VjfJ', '5JT4QqGNqdvpxys7SbxDqeQYmfq24u4K8cMUsVMcNQLAXRwrZnR', '5KBiBDzJBM7V63UCwE5M6P4HbXFCzc6GaeYW4n7orhLmxFNmRrE'),
    testlib.MultisigWallet(2, '5KNTRpgjo81QoM7tdWZerzgiWagDoaHJiPV5vFeLuSVUAGWgHsS', '5JRwonrfqvr7Z4aBKLzUpZh1cdSk52n5WdS2G28Yr2WCEXjtrqN', '5JGoa62nDaFwEMp4tianJqLcEQ4eaHtu4UU3AoPxfgeP54SR2CA'),
    testlib.MultisigWallet(2, '5KDJe3ptRA1HP6HRwNpswSM3DMACMvCYbojrLXp4Zu7T98gs8ir', '5JE9Luhjrb9SVZk29AM4j3ns9zUeGs4Xuau9o3EB7QyKzerSnwH', '5JvC3DN6MnFJHHq5Hpisv47KSeCaFxGfBso6y8pMpvjb6AjPiL2'),
    testlib.MultisigWallet(2, '5JHD24XrcDhcKvEXiviwpVzFuCqm9WL1aRf25iXDUj3f8ecPtKr', '5Jwv4w9RykjJYGF4GRtDCM83KsWsaPbpEcS5BZEi1bjDRLCNFn2', '5JZwEEWNNGFLkGcxFf73GXMchzDKDwc696hK94BizmgVADVFkLe'),
    testlib.MultisigWallet(2, '5HqJVoH5iZN5B3RwMq2tgwqdxxAi9Do8d4Mt97EH6BENoa5FraE', '5JmYF8mhZkggDTope6DUPBMBgLqiVjGDWzYi3ZeczwgDX64XQd9', '5KcjdfeHvVg89mJWVmKwMGYzXFXC684AmR6EJmtkrk8ZPNoWLcx'),
    testlib.MultisigWallet(2, '5K525PQyBG3xr84qY1HjLw98dQ4YYGwK5BUavVwsaZqbVc39mAy', '5JF84NuqyDircZzFsNRFfGeknw9gmJJVMbKHba2PMYuyeda5A2B', '5JmNEVANrcgJAZvUjkNWVQPyULirSN8M7UJDkGKKUy2mLXvh4GK'),
    testlib.MultisigWallet(2, '5KhRKs5p1dAVF81MuEookKqNn4W1kNU5MUSuibnkZur4RMzLzo3', '5JCUwbYzcCFjHvJgQ5iiFGxxqDKSNtDBaeBjvU3s2tKFqe6cfeL', '5KdGj6PiD3yArpAytZ3szjbagh828bZ7yBpn82Gn4esZapqC2it')
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
wallet_keys = None
wallet_keys_2 = None

datasets = [
    {"dataset_1": "My first dataset!"},
    {"dataset_2": {"id": "abcdef", "desc": "My second dataset!", "data": [1, 2, 3, 4]}},
    {"dataset_3": "My third datset!"}
]

dataset_change = "This is the mutated dataset"

def scenario( wallets, **kw ):

    global put_result, wallet_keys, wallet_keys_2, datasets, zonefile_hash, dataset_change
   
    # make a storage gateway (will be port 16300)
    res = testlib.peer_setup(0)
    if 'error' in res:
        return res
    
    storage_gateway_working_dir = res['working_dir']
    storage_gateway_config_path = res['config_path']

    # make sure the storage gateway saves to disk 
    # blockstack_client.config.
    res = peer_start( storage_gateway_wd, args=['--foreground', '--no-indexer'] )
    
    # start storage gateway 
    # res = testlib.peer_start(

    # set up client    
    wallet_keys = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[2].privkey, wallets[3].privkey, wallets[4].privkey )

    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    resp = testlib.blockstack_cli_register( "foo.test", "0123456789abcdef" )
    if 'error' in resp:
        print >> sys.stderr, json.dumps(resp, indent=4, sort_keys=True)
        return False
   
    # wait for the preorder to get confirmed
    for i in xrange(0, 12):
        testlib.next_block( **kw )

    # wait for the poller to pick it up
    print >> sys.stderr, "Waiting for the backend to submit the register"
    time.sleep(10)

    # wait for the register to get confirmed 
    for i in xrange(0, 12):
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting for the backend to acknowledge registration"
    time.sleep(10)

    # wait for initial update to get confirmed 
    for i in xrange(0, 12):
        # tell serialization-checker that value_hash can be ignored here
        print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
        sys.stdout.flush()
    
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting for the backend to acknowledge update"
    time.sleep(10)

    # wait for zonefile/profile replication
    for i in xrange(0, 12):
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting for the backend to replicate zonefile and profile"
    time.sleep(10)


    # make a few accounts
    res = testlib.blockstack_cli_put_account("foo.test", "serviceFoo", "serviceFooID", "foo://bar.com", "0123456789abcdef", extra_data='foofield=foo!', wallet_keys=wallet_keys)
    if 'error' in res:
        res['test'] = 'Failed to create foo.test serviceFoo account'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 

    time.sleep(2)

    res = testlib.blockstack_cli_put_account("foo.test", "serviceBar", "serviceBarID", "bar://baz.com", "0123456789abcdef", extra_data='barfield=bar!', wallet_keys=wallet_keys)
    if 'error' in res:
        res['test'] = 'Failed to create foo.test serviceBar account'
        print json.dumps(res, indent=4, sort_keys=True)
        error = True
        return 

    time.sleep(2)

    # put some data
    put_result = testlib.blockstack_cli_put_mutable( "foo.test", "hello_world_1", json.dumps(datasets[0]), password="0123456789abcdef")
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)
        return False

    time.sleep(2)

    put_result = testlib.blockstack_cli_put_mutable( "foo.test", "hello_world_2", json.dumps(datasets[1]), password="0123456789abcdef")
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)
        return False

    time.sleep(2)

    put_result = testlib.blockstack_cli_put_mutable( "foo.test", "hello_world_3", json.dumps(datasets[2]), password="0123456789abcdef")
    if 'error' in put_result:
        print json.dumps(put_result, indent=4, sort_keys=True)
        return False

    time.sleep(2)

    # increment data version too
    datasets[0]['buf'] = []
    for i in xrange(0, 5):
        datasets[0]["dataset_change"] = dataset_change
        datasets[0]['buf'].append(i)

        put_result = testlib.blockstack_cli_put_mutable( "foo.test", "hello_world_1", json.dumps(datasets[0]), password="0123456789abcdef")
        if 'error' in put_result:
            print json.dumps(put_result, indent=4, sort_keys=True )
            return False

        time.sleep(2)

    testlib.next_block( **kw )


def check( state_engine ):

    global wallet_keys, datasets, zonefile_hash

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
    preorder = state_engine.get_name_preorder( "foo.test", virtualchain.make_payment_script(wallets[2].addr), wallets[3].addr )
    if preorder is not None:
        print "still have preorder"
        return False
    
    # registered 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        print "name does not exist"
        return False 

    # owned 
    if name_rec['address'] != wallets[3].addr or name_rec['sender'] != virtualchain.make_payment_script(wallets[3].addr):
        print "name has wrong owner"
        return False 

    srv = xmlrpclib.ServerProxy("http://localhost:%s" % blockstack.RPC_SERVER_PORT)

    # zonefile and profile replicated to blockstack server 
    try:
        zonefile_by_name_str = srv.get_zonefiles_by_names(['foo.test'])
        zonefile_by_hash_str = srv.get_zonefiles([name_rec['value_hash']])
       
        zonefile_by_name = json.loads(zonefile_by_name_str)
        zonefile_by_hash = json.loads(zonefile_by_hash_str)

        assert 'error' not in zonefile_by_name, json.dumps(zonefile_by_name, indent=4, sort_keys=True)
        assert 'error' not in zonefile_by_hash, json.dumps(zonefile_by_hash, indent=4, sort_keys=True)

        zf1 = None
        zf2 = None
        try:
            zf1 = base64.b64decode( zonefile_by_name['zonefiles']['foo.test'] )
        except:
            print zonefile_by_name
            raise

        try:
            zf2 = base64.b64decode( zonefile_by_hash['zonefiles'][name_rec['value_hash']] )
        except:
            print zonefile_by_hash
            raise
        
        assert zf1 == zf2
        zonefile = blockstack_zones.parse_zone_file( zf1 )

        user_pubkey = blockstack_client.user.user_zonefile_data_pubkey( zonefile )
        assert user_pubkey is not None, "no zonefile public key"

        profile_resp_txt = srv.get_profile("foo.test")
        profile_resp = json.loads(profile_resp_txt)
        assert 'error' not in profile_resp, "error:\n%s" % json.dumps(profile_resp, indent=4, sort_keys=True)
        assert 'profile' in profile_resp, "missing profile:\n%s" % json.dumps(profile_resp, indent=4, sort_keys=True)

        # profile will be in 'raw' form
        raw_profile = profile_resp['profile']
        profile = blockstack_client.storage.parse_mutable_data( raw_profile, user_pubkey )

    except Exception, e:
        traceback.print_exc()
        print "Invalid profile"
        return False

    # have right data 
    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )

    for i in xrange(0, len(datasets)):
        print "get hello_world_%s" % (i+1)
        dat = blockstack_client.get_mutable( "hello_world_%s" % (i+1), blockchain_id="foo.test" )
        if dat is None:
            print "No data '%s'" % ("hello_world_%s" % (i+1))
            return False

        if 'error' in dat:
            print json.dumps(dat, indent=4, sort_keys=True)
            return False

        if json.loads(dat['data']) != datasets[i]:
            print "Mismatch %s: %s %s != %s %s" % (i, dat['data'], type(dat['data']), datasets[i], type(datasets[i]))
            return False
   
    profile, zonefile = blockstack_client.get_profile('foo.test')
    if profile is None:
        print 'No profile'
        return False

    if 'error' in zonefile:
        print json.dumps(zonefile, indent=4, sort_keys=True)
        return False 

    # accounts should all be there 
    if not profile.has_key('account'):
        print 'profile:\n{}'.format(json.dumps(profile, indent=4, sort_keys=True))
        return False

    expected_account_info = [
        {
            "contentUrl": "foo://bar.com", 
            "foofield": "foo!", 
            "identifier": "serviceFooID", 
            "service": "serviceFoo"
        }, 
        {
            "barfield": "bar!", 
            "contentUrl": "bar://baz.com", 
            "identifier": "serviceBarID", 
            "service": "serviceBar"
        }
    ]

    for account_info in expected_account_info:
        found = False
        for profile_account_info in profile['account']:
            if profile_account_info == account_info:
                found = True
                break

        if not found:
            print "missing\n{}\nin\n{}".format(json.dumps(account_info, indent=4, sort_keys=True), json.dumps(profile, indent=4, sort_keys=True))
            return False

    # there should be no failures in the API log
    api_log_path = os.path.join(os.path.dirname(test_proxy.conf['path']), "api_endpoint.log")
    with open(api_log_path, "r") as f:
        api_log = f.read()

    if "Traceback (most recent call last)" in api_log:
        print "exception thrown by client"
        return False

    if "Server did not save" in api_log:
        print 'server did not save'
        return False

    return True
