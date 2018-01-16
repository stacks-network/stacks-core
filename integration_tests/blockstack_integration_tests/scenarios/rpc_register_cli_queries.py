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
import virtualchain
import time
import json
import sys
import os
import blockstack_client

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 5500 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 5500 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
preorder_info = None
register_info = None
update_info = None
balance_before = None
balance_after = None
deposit_info = None
names_owned_before = None
names_owned_after = None
whois = None
blockchain_record = None
blockchain_history = None
price_info = None
zonefile_info = None
all_names_info = None
namespace_names_info = None
wallet_info = None
lookup_info = None
update_history = None
zonefile_history = None
names_info = None

def scenario( wallets, **kw ):

    global preorder_info, register_info, update_info, balance_before, balance_after, names_owned_before, names_owned_after, whois, blockchain_record, deposit_info, price_info
    global blockchain_history, zonefile_info, all_names_info, namespace_names_info, wallet_info, lookup_info, update_history, zonefile_history, names_info

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )
    
    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[2].privkey, wallets[3].privkey, wallets[4].privkey )

    balance_before = testlib.blockstack_cli_balance()
    deposit_info = testlib.blockstack_cli_deposit()
    price_info = testlib.blockstack_cli_price( "foo.test", password="0123456789abcdef" )
    wallet_info = testlib.blockstack_cli_wallet( "0123456789abcdef" ) 

    resp = testlib.blockstack_cli_register( "foo.test", "0123456789abcdef" )
    if 'error' in resp:
        print >> sys.stderr, json.dumps(resp, indent=4, sort_keys=True)
        return False
   
    # wait for the preorder to get confirmed
    for i in xrange(0, 5):
        testlib.next_block( **kw )

    # queued?
    preorder_info = testlib.blockstack_cli_info()
    names_owned_before = testlib.blockstack_cli_get_names_owned_by_address( wallets[3].addr )

    for i in xrange(0, 7):
        testlib.next_block( **kw )

    # wait for the poller to pick it up
    print >> sys.stderr, "Waiting 10 seconds for the backend to submit the register"
    time.sleep(10)

    # wait for the register to get confirmed 
    for i in xrange(0, 5):
        testlib.next_block( **kw )

    # registered?
    register_info = testlib.blockstack_cli_info()
    names_info = testlib.blockstack_cli_names()

    for i in xrange(0, 7):
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting 10 seconds for the backend to acknowledge registration"
    time.sleep(10)

    # wait for update to get confirmed 
    for i in xrange(0, 5):
        testlib.next_block( **kw )

    update_info = testlib.blockstack_cli_info()
    names_owned_after = testlib.blockstack_cli_get_names_owned_by_address( wallets[3].addr )
    whois = testlib.blockstack_cli_whois( "foo.test" )

    for i in xrange(0, 7):
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting 10 seconds for the backend to acknowledge update"
    time.sleep(10)

    # put some immutable data 
    put_immutable_info = testlib.blockstack_cli_put_immutable( "foo.test", "hello_world", '{"hello": "world"}' )    
    if 'error' in put_immutable_info:
        print "put_immutable failed"
        print json.dumps(put_immutable_info, indent=4, sort_keys=True)
        return False

    # wait for update to be confirmed 
    for i in xrange(0, 12):
        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting 10 seconds for backend to acknowledge put-immutable update"
    time.sleep(10)

    balance_after = testlib.blockstack_cli_balance()
    blockchain_history = testlib.blockstack_cli_get_name_blockchain_history( "foo.test" )
    zonefile_info = testlib.blockstack_cli_get_name_zonefile( "foo.test", json=False )
    all_names_info = testlib.blockstack_cli_get_all_names(0)
    namespace_names_info = testlib.blockstack_cli_get_names_in_namespace("test", 0)
    lookup_info = testlib.blockstack_cli_lookup( "foo.test" )
    update_history = testlib.blockstack_cli_list_update_history( "foo.test" )
    zonefile_history = testlib.blockstack_cli_list_zonefile_history( "foo.test" )
    blockchain_record = testlib.blockstack_cli_get_name_blockchain_record( "foo.test" )


def check( state_engine ):

    global preorder_info, register_info, update_info, balance_before, balance_after, names_owned_before, names_owned_after, whois, blockchain_record, deposit_info, price_info
    global blockchain_history, zonefile_info, all_names_info, namespace_names_info, wallet_info, lookup_info, update_history, zonefile_history, names_info

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is not None:
        print "namespace reveal exists"
        return False 

    ns = state_engine.get_namespace( "test" )
    if ns is None:
        print "no namespace"
        return False 

    if ns['namespace_id'] != 'test':
        print "wrong namespace"
        return False 
    
    # registered 
    name_rec = state_engine.get_name( "foo.test" )
    if name_rec is None:
        print "name does not exist"
        return False 

    # owned by the right address 
    owner_address = wallets[3].addr
    if name_rec['address'] != owner_address or name_rec['sender'] != virtualchain.make_payment_script(owner_address):
        print "sender is wrong"
        return False 

    # all queues are drained 
    queue_info = testlib.blockstack_client_queue_state()
    if len(queue_info) > 0:
        print "Still in queue:\n%s" % json.dumps(queue_info, indent=4, sort_keys=True)
        return False

    # have an update hash 
    if 'value_hash' not in name_rec or name_rec.get('value_hash', None) is None:
        print "No value hash"
        return False 

    # have a zonefile 
    zonefile = testlib.blockstack_get_zonefile( name_rec['value_hash'] )
    if zonefile is None or 'error' in zonefile:
        if zonefile is not None:
            print "zonefile lookup error: %s" % zonefile['error']
        else:
            print "no zonefile returned"
        return False

    # hashes to this zonefile 
    if blockstack_client.hash_zonefile( zonefile ) != name_rec['value_hash']:
        print "wrong zonefile: %s != %s" % (blockstack_client.hash_zonefile(zonefile), name_rec['value_hash'])
        return False

    # verify that the profile is there 
    profile = testlib.blockstack_get_profile( "foo.test" )
    if profile is None or 'error' in profile:
        if profile is None:
            print "no profile returned"
        else:
            print "profile lookup error: %s" % profile['error']

        return False

    # check queue operations 
    for queue_type, queue_state in [("preorder", preorder_info), ("register", register_info), ("update", update_info)]:
        if not queue_state.has_key('queues'):
            print "missing queues:\n%s" % json.dumps(queue_state, indent=4, sort_keys=True)
            return False

        for k in ['name', 'confirmations', 'tx_hash']:
            for q in queue_state['queues'][queue_type]:
                if not q.has_key(k):
                    print "missing key %s\n%s" % (k, json.dumps(queue_state, indent=4, sort_keys=True))
                    return False
            
                if q['name'] != 'foo.test':
                    print "wrong name: %s" % queue_state['name']
                    return False

    # check price
    for k in ['preorder_tx_fee', 'register_tx_fee', 'total_estimated_cost', 'name_price']:
        if not price_info.has_key(k):
            print "bad price info (missing %s):\n%s" % (k, json.dumps(price_info, indent=4, sort_keys=True))
            return False

    
    # deposit info 
    if not deposit_info.has_key('address') or deposit_info['address'] != wallets[2].addr:
        print "bad deposit info:\n%s" % json.dumps(deposit_info, indent=4, sort_keys=True)
        return False

    # whois info
    for k in ['block_preordered_at', 'block_renewed_at', 'last_transaction_id', 'owner_address', 'owner_script', 'expire_block', 'has_zonefile', 'zonefile_hash']:
        if not whois.has_key(k):
            print "bad whois: missing %s\n%s" % (k, json.dumps(whois, indent=4, sort_keys=True))
            return False
    
    # balance 
    for balance_info in [balance_before, balance_after]:
        for k in ['total_balance', 'addresses']:
            if not balance_info.has_key(k):
                print "missing '%s'\n%s" % (k, json.dumps(balance_info, indent=4, sort_keys=True))
                return False

    # name listing
    if len(names_owned_before) != 0:
        print "owned before: %s" % names_owned_before
        return False

    if len(names_owned_after) != 1 or names_owned_after[0] != 'foo.test':
        print "owned after: %s" % names_owned_after
        return False

    # blockchain record 
    for k in ['name', 'op', 'op_fee', 'opcode', 'vtxindex', 'txid', 'value_hash', 'sender', 'address', 'history']:
        if not blockchain_record.has_key(k):
            print "missing %s\n%s" % (k, json.dumps(blockchain_record, indent=4, sort_keys=True))
            return False

    # blockchain history (should have a preorder, register, and 2 updates)
    if len(blockchain_history) != 4:
        print "invalid history\n%s\n" % json.dumps(blockchain_history, indent=4, sort_keys=True)
        return False

    block_heights = blockchain_history.keys()
    block_heights.sort()
    expected_opcodes = ['NAME_PREORDER', 'NAME_REGISTRATION', 'NAME_UPDATE', 'NAME_UPDATE']
    for bh, opcode in zip(block_heights, expected_opcodes):
        if len(blockchain_history[bh]) != 1:
            print "invalid history: multiple ops at %s\n%s" % (bh, json.dumps(blockchain_history, indent=4, sort_keys=True))
            return False

        if blockchain_history[bh][0]['opcode'] != opcode:
            print "invalid history: expected %s at %s\n%s" % (opcode, bh, json.dumps(blockchain_history, indent=4, sort_keys=True))
            return False

    # zonefile info
    if zonefile_info is None or type(zonefile_info) != str:
        print "invalid zonefile\n%s\n" % zonefile_info
        return False

    # name query
    if type(all_names_info) == dict and 'error' in all_names_info:
        print "error in all_names: %s" % all_names_info
        return False

    all_names = all_names_info
    if len(all_names) != 1 or all_names != ['foo.test']:
        print "all names: %s" % all_names
        return False

    # namespace query
    if type(namespace_names_info) == dict and 'error' in namespace_names_info:
        print "error in namesace_names: %s" % namespace_names_info
        return False

    namespace_names = namespace_names_info
    if len(namespace_names) != 1 or namespace_names != ['foo.test']:
        print "all namespace names: %s" % namespace_names
        return False

    # wallet info
    for k in ['payment_privkey', 'owner_privkey', 'data_privkey', 'payment_address', 'owner_address', 'data_pubkey']:
        if not wallet_info.has_key(k):
            print "missing %s\n%s" % (k, json.dumps(wallet_info, indent=4, sort_keys=True))
            return False

    # profile info
    for k in ['profile', 'zonefile']:
        if not lookup_info.has_key(k):
            print "missing '%s'\n%s" % (k, json.dumps(lookup_info, indent=4, sort_keys=True))
            return False

    if lookup_info['zonefile'] != zonefile_info:
        print "unequal zonefiles:\n%s\n%s" % (json.dumps(lookup_info['zonefile'], indent=4, sort_keys=True), json.dumps(zonefile_info, indent=4, sort_keys=True))
        return False

    # update history (2 items)
    if len(update_history) != 2 or update_history[1] != blockchain_record['value_hash']:
        print "invalid update history\n%s" % json.dumps(update_history, indent=4, sort_keys=True)
        return False

    # zonefile history (expect 2 items)
    if len(zonefile_history) != 2 or zonefile_history[1] != zonefile_info:
        print "invalid zonefile history\n%s" % json.dumps(zonefile_history, indent=4, sort_keys=True)
        print "zonefile current:\n%s" % json.dumps(zonefile_info, indent=4, sort_keys=True)
        return False

    # names info
    if type(names_info) != dict:
        print "invalid names info: %s" % names_info
        return False
        
    for k in ['names_owned', 'addresses']:
        if not names_info.has_key(k):
            print "invalid names info (missing %s): %s" % (k, names_info)
            return False

    if len(names_info['addresses']) != 1:
        print "invalid names info (addresses): %s" % names_info
        return False

    if names_info['addresses'][0]['names_owned'] != ['foo.test']:
        print "invalid names info (names_owned): %s" % names_info
        return False

    if names_info['addresses'][0]['address'] != wallets[3].addr:
        print "invalid names info (addresses.address): %s" % names_info
        return False

    # immutable data 
    immutable_data = testlib.blockstack_cli_get_immutable( "foo.test", "hello_world" )
    if 'error' in immutable_data:
        print "Failed to get immutable data 'hello_world'"
        print json.dumps(immutable_data, indent=4, sort_keys=True)
        return False

    if 'data' not in immutable_data:
        print "invalid immutable_data: %s" % immutable_data
        return False 

    if json.loads(immutable_data['data']) != {'hello': 'world'}:
        print "failed to get immutable data"
        print 'exected %s, got %s' % ({'hello': 'world'}, immutable_data['data'])
        return False

    return True
