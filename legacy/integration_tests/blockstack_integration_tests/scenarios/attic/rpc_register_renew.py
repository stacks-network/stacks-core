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
import blockstack_client
import blockstack as blockstack_server
import virtualchain
from blockstack_client.constants import DEFAULT_DUST_FEE, DEFAULT_OP_RETURN_FEE

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 5500 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 5500 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
zonefile_hash = None
final_balance = None
new_expire_block = None

def scenario( wallets, **kw ):

    global zonefile_hash, final_balance, new_expire_block

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[2].privkey, wallets[3].privkey, wallets[4].privkey )
    resp = testlib.blockstack_cli_register( "foo.test", "0123456789abcdef" )
    if 'error' in resp:
        print >> sys.stderr, json.dumps(resp, indent=4, sort_keys=True)
        return False

    # wait for the preorder to get confirmed
    for i in xrange(0, 12):
        testlib.next_block( **kw )

    # wait for the poller to pick it up
    print >> sys.stderr, "Waiting 10 seconds for the backend to submit the register"
    time.sleep(10)


    # wait for the register to get confirmed
    for i in xrange(0, 12):
        # warn the serialization checker that this changes behavior from 0.13
        print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
        sys.stdout.flush()

        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting 10 seconds for the backend to acknowledge registration"
    time.sleep(10)

    # wait for initial update to get confirmed
    for i in xrange(0, 12):
        # warn the serialization checker that this changes behavior from 0.13
        print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
        sys.stdout.flush()

        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting 10 seconds for the backend to acknowledge update"
    time.sleep(10)

    # what's the name's renewal block?
    proxy = testlib.make_proxy()
    res = blockstack_client.get_name_blockchain_record( "foo.test", proxy=proxy )
    if 'error' in res:
        print >> sys.stderr, json.dumps(res, indent=4, sort_keys=True)
        return False

    old_expire_block = res['expire_block']

    # send an update, changing the zonefile
    data_pubkey = wallet['data_pubkey']
    zonefile = blockstack_client.zonefile.make_empty_zonefile( "foo.test", data_pubkey )
    blockstack_client.user.put_immutable_data_zonefile( zonefile, "testdata", blockstack_client.get_data_hash("testdata"), data_url="file:///testdata")
    zonefile_json = json.dumps(zonefile)

    resp = testlib.blockstack_cli_update( "foo.test", zonefile_json, "0123456789abcdef" )

    if 'error' in resp:
        print >> sys.stderr, "update error: %s" % resp['error']
        return False

    zonefile_hash = resp['zonefile_hash']

    # wait for it to go through
    for i in xrange(0, 12):
        # warn the serialization checker that this changes behavior from 0.13
        print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
        sys.stdout.flush()

        testlib.next_block( **kw )

    print >> sys.stderr, "Waiting 10 seconds for the backend to acknowedge the update"
    time.sleep(10)
    # wait for it to go through
    for i in xrange(0, 12):
        # warn the serialization checker that this changes behavior from 0.13
        print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
        sys.stdout.flush()

        testlib.next_block( **kw )

    # renew it
    resp = testlib.blockstack_cli_renew( "foo.test", "0123456789abcdef" )
    if 'error' in resp:
        print >> sys.stderr, "Renewal request failed:\n%s" % json.dumps(resp, indent=4, sort_keys=True)
        return False

    print >> sys.stderr, "Waiting 10 seconds for the backend to acknowledge the renewal"
    time.sleep(10)

    # wait for it to go through
    for i in xrange(0, 6):
        # warn the serialization checker that this changes behavior from 0.13
        print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
        sys.stdout.flush()

        testlib.next_block( **kw )

    # verify that it's in the queue
    queue_state = testlib.blockstack_cli_info()
    if 'error' in queue_state:
        print json.dumps(queue_state)
        return False

    if not queue_state.has_key('queues'):
        print 'no queues'
        print json.dumps(queue_state)
        return False

    if not queue_state['queues'].has_key('renew'):
        print 'no renew queue'
        print json.dumps(queue_state)
        return False

    if len(queue_state['queues']['renew']) != 1:
        print 'wrong renew state'
        print json.dumps(queue_state)
        return False

    if queue_state['queues']['renew'][0]['name'] != 'foo.test':
        print 'wrong name'
        print json.dumps(queue_state)
        return False

    # wait for it to go through
    for i in xrange(0, 6):
        # warn the serialization checker that this changes behavior from 0.13
        print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
        sys.stdout.flush()

        testlib.next_block( **kw )


    proxy = testlib.make_proxy()
    res = blockstack_client.get_name_blockchain_record( "foo.test", proxy=proxy )
    if 'error' in res:
        print >> sys.stderr, json.dumps(res, indent=4, sort_keys=True)
        return False


    new_expire_block = res['expire_block']
    if old_expire_block >= new_expire_block + 12:
        # didn't go through
        print >> sys.stderr, "Renewal didn't go through: %s --> %s" % (old_expire_block, new_expire_block)
        return False

    if res['op'] != blockstack_client.config.NAME_REGISTRATION + ":":
        print >> sys.stderr, "Renewal didn't go through (last op is %s)" % res['op']
        error = True
        return False

    final_balance = testlib.getbalance( wallets[2].addr )


def check( state_engine ):

    global zonefile_hash, new_expire_block

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

    # owned by
    owner_address = wallets[3].addr
    if name_rec['address'] != owner_address or name_rec['sender'] != virtualchain.make_payment_script(owner_address):
        print "sender is wrong"
        return False

    # value hash
    if name_rec['value_hash'] != zonefile_hash:
        print "wrong zonefile hash: %s != %s" % (name_rec['value_hash'], zonefile_hash)
        return False

    # replicated?
    zonefile = testlib.blockstack_get_zonefile( zonefile_hash )
    if 'error' in zonefile:
        print "zonefile error: %s" % zonefile['error']
        return False

    # right hash?
    if blockstack_client.hash_zonefile( zonefile ) != zonefile_hash:
        print "wrong zonefile: %s != %s" % (blockstack_client.hash_zonefile(zonefile), zonefile_hash)
        return False

    # all queues are drained
    queue_info = testlib.blockstack_client_queue_state()
    if len(queue_info) > 0:
        print "Still in queue:\n%s" % json.dumps(queue_info, indent=4, sort_keys=True)
        return False

    # final balance is correct?
    name_fee = blockstack_server.price_name( "foo", ns, new_expire_block )
    preorder_dust_fees = 3 * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
    register_dust_fees = 4 * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
    renewal_dust_fees = 3 * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE

    total_fee = name_fee * 2 + preorder_dust_fees + register_dust_fees + renewal_dust_fees
    payment_address = wallets[2].addr

    # TODO: check
    return True
