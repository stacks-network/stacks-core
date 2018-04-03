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
import keychain
import json
import binascii

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 ),
    testlib.MultisigSegwitWallet(2, "5JfHdMq9XnZ9mwW5H6LsfVCn9u6iGAj2FCVYtfhcHn72Tphvm5P", "5JaqLZaKD7cgkfsxSZBNiu6gaFxo1XAiTXw1mhtatipNNCtZBZG", "5KNsAkiHRDZb5Yyedxov2Fncr6CcNPV52yqJbzQ8M2W6dkg2qJp"),
    testlib.MultisigSegwitWallet(2, "5JPrkpfLT3rDf1Lgm1DpA2Cfepwf9wCtEbDx1HSEdd4J2R5YMxZ", "5JiALcfvzFsKcvLnHf7ECgLdp6FxbcAXB1GPvEYP7HeigbDCQ9E", "5KScD5XL5Hj83Yjvm3u4HD78vSYwFRyq9StTLPnrWrCTGiqTvVP"),
    testlib.MultisigSegwitWallet(2, 'Ky1SXQ71uvWWbKDPGP7ZEzbY6nexcmTV8NjL3tLGm2JxXvkVsvpd', 'KzMF3Hssn6GeM4s3hWDxKXQzGjmFN42E1dBdvHc6P4AdSopE51Ki', 'L2c82atnjfYdtLSap43jMzTYSXiS2f5wrkVBwRJwRBJddaMNBUfg'),
    testlib.MultisigSegwitWallet(2, 'KwgKTD84drKBowAd3sXWeBMSixgGqGyRq3ZWikQkGWuY3j2iCbjJ', 'L47CUjK9ELreBrvmRcR6dxNQ1isCNkW8EroFTLed74qYHXHd4rRq', 'KwsxLrkNQ6o18EvThw8o8B5ihK6fLNrQbo71VxhPRg8yoeUtp5cu'),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):

    print '\nactivating segwit\n'

    virtualchain.set_features("segwit", True)

    print '\nsegwit state: {}\n'.format(virtualchain.get_features('segwit'))

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[5].privkey )
    testlib.blockstack_namespace_preorder( "mult", wallets[2].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[5].privkey )
    testlib.blockstack_namespace_reveal( "mult", wallets[2].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=2 )
    testlib.next_block( **kw )

    private_keychain = keychain.PrivateKeychain.from_private_key( wallets[2].privkey )
    private_keys = [wallets[2].privkey]     # NOTE: always start with the reveal key, then use children
    for i in xrange(0, 4):
        import_key = private_keychain.child(i).private_key()

        print "fund {} (child {})".format(import_key, i)
        res = testlib.send_funds( wallets[1].privkey, 100000000, virtualchain.BitcoinPrivateKey(import_key).public_key().address() )
        if 'error' in res:
            print json.dumps(res, indent=4, sort_keys=True)
            return False

        testlib.next_block(**kw)
        private_keys.append(import_key)

    # should succeed
    resp = testlib.blockstack_name_import("foo.mult", wallets[2].addr, '00' * 20, private_keys[0])
    if 'error' in resp:
        print json.dumps(resp, indent=4, sort_keys=True)
        return False

    testlib.next_block(**kw)

    # should succeed
    resp = testlib.blockstack_name_import("bar.mult", wallets[3].addr, "11" * 20, private_keys[1])
    if 'error' in resp:
        print json.dumps(resp, indent=4, sort_keys=True)
        return False

    # should succeed
    resp = testlib.blockstack_name_import("baz.mult", wallets[4].addr, "22" * 20, private_keys[2])
    if 'error' in resp:
        print json.dumps(resp, indent=4, sort_keys=True)
        return False

    # should succeed
    resp = testlib.blockstack_name_import("goo.mult", wallets[5].addr, "33" * 20, private_keys[3])
    if 'error' in resp:
        print json.dumps(resp, indent=4, sort_keys=True)
        return False

    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.blockstack_namespace_ready( "mult", wallets[2].privkey )
    testlib.next_block( **kw )

    namespace_balance = testlib.get_balance(wallets[0].addr)

    # get prices
    hello_cost = testlib.blockstack_get_name_cost('hello.mult')
    world_cost = testlib.blockstack_get_name_cost('world.mult')
    foo_cost = testlib.blockstack_get_name_cost('foo.mult')

    # register/renew 
    res = testlib.blockstack_name_preorder("hello.mult", wallets[1].privkey, wallets[2].addr)
    if 'error' in res:
        print res
        return False

    res = testlib.blockstack_name_preorder('world.mult', wallets[6].privkey, wallets[7].addr, wallet=wallets[7])
    if 'error' in res:
        print res
        return False

    res = testlib.blockstack_name_renew('foo.mult', wallets[2].privkey)
    if 'error' in res:
        print res
        return False

    testlib.next_block(**kw)

    new_namespace_balance = testlib.get_balance(wallets[0].addr)

    if new_namespace_balance != namespace_balance + hello_cost + world_cost + foo_cost:
        print 'wrong balance'
        print new_namespace_balance
        print namespace_balance
        print hello_cost
        print foo_cost
        return False

    res = testlib.blockstack_name_register("hello.mult", wallets[1].privkey, wallets[2].addr)
    if 'error' in res:
        print res
        return False

    res = testlib.blockstack_name_register('world.mult', wallets[6].privkey, wallets[7].addr, wallet=wallets[7], zonefile_hash='44' * 20)
    if 'error' in res:
        print res
        return False

    testlib.next_block(**kw)


def check( state_engine ):

    # not revealed, but ready
    addrs = [wallets[5].addr, wallets[0].addr]
    for i, nsid in enumerate(['test', 'mult']):
        ns = state_engine.get_namespace_reveal(nsid)
        if ns is not None:
            return False 

        ns = state_engine.get_namespace(nsid)
        if ns is None:
            return False 

        if ns['namespace_id'] != nsid:
            return False

        if ns['address'] != addrs[i]:
            print 'wrong address'
            return False

    # names all imported 
    name_info = {
        'foo.mult': {
            'address': wallets[2].addr,
            'zonefile_hash': '00' * 20,
        },
        'bar.mult': {
            'address': wallets[3].addr,
            'zonefile_hash': '11' * 20,
        },
        'baz.mult': {
            'address': wallets[4].addr,
            'zonefile_hash': '22' * 20,
        },
        'goo.mult': {
            'address': wallets[5].addr,
            'zonefile_hash': '33' * 20,
        },
        'hello.mult': {
            'address': wallets[2].addr,
            'zonefile': None,
            'zonefile_hash': None,
        },
        'world.mult': {
            'address': wallets[7].addr,
            'zonefile_hash': '44' * 20,
        }
    }

    for name in name_info.keys():
        name_rec = state_engine.get_name(name)
        if name_rec is None or 'error' in name_rec:
            print 'missing name {}'.format(name)
            return False
        
        expected_zonefile = name_info[name].get('zonefile', None)
        expected_zonefile_hash = name_info[name].get('zonefile_hash', None)

        zonefile = testlib.blockstack_cli_get_name_zonefile(name)
        if (zonefile is None or 'error' in zonefile) and expected_zonefile is not None:
            print 'missing zonefile for {}'.format(name)
            return False

        if expected_zonefile is not None and zonefile != expected_zonefile:
            print 'different zonefiles:'
            print zonefile
            print name_info[name]['zonefile']
            return False

        if name_rec['address'] != name_info[name]['address']:
            print 'wrong address for {}'.format(name)
            return False

        if expected_zonefile_hash is not None and expected_zonefile_hash != name_rec['value_hash']:
            print 'wrong value hash for {}'.format(name)
            return False

    return True
