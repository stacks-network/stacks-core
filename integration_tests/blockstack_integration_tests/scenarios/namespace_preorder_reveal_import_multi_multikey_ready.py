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
import json
import pybitcoin
import base58
import keychain
import virtualchain

def testnet_encode( pk_wif ):
    s = pybitcoin.b58check_decode(pk_wif )
    s = '\xef' + s
    ret = base58.b58encode( s + pybitcoin.bin_double_sha256(s)[0:4] )
    return ret

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def addr_reencode( addr ):
    """
    Encode addr to testnet
    """
    return pybitcoin.b58check_encode( pybitcoin.b58check_decode( addr ), version_byte=111 )


def scenario( wallets, **kw ):

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    # derive importer keys and do imports
    # NOTE: breaks consensus trace from 0.14.0
    private_keychain = keychain.PrivateKeychain.from_private_key( wallets[1].privkey )
    private_keys = [wallets[1].privkey]     # NOTE: always start with the reveal key, then use children
    for i in xrange(0, 3):
        import_key = private_keychain.child(i).private_key()

        print "fund {} (child {})".format(import_key, i)
        res = testlib.send_funds( wallets[1].privkey, 100000000, virtualchain.BitcoinPrivateKey(import_key).public_key().address() )
        if 'error' in res:
            print json.dumps(res, indent=4, sort_keys=True)
            return False

        testlib.next_block(**kw)
        private_keys.append(import_key)

    resp = testlib.blockstack_name_import( "foo.test", addr_reencode("1BKufFedDrueBBFBXtiATB2PSdsBGZxf3N"), "11" * 20, wallets[1].privkey )    # master
    if 'error' in resp:
        print json.dumps(resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstack_name_import( "foo.test", addr_reencode("1ARVjrtKnUVWt2GNrpuFLnNCL2WGUhKdkW"), "33" * 20, private_keys[2] )    # derived child 2
    if 'error' in resp:
        print json.dumps(resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstack_name_import( "foo.test", addr_reencode("1PYu4vKB3g2QLDFdurxqYSJ9aJSed7tne1"), "22" * 20, private_keys[1] )    # derived child 1
    if 'error' in resp:
        print json.dumps(resp, indent=4 )

    testlib.next_block( **kw )
    
    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )


def check( state_engine ):

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "test" )
    if ns is not None:
        return False 

    ns = state_engine.get_namespace( "test" )
    if ns is None:
        return False 

    if ns['namespace_id'] != 'test':
        return False 

    # each name must exist 
    foo = state_engine.get_name( "foo.test" )

    if foo is None:
        print "foo doesn't exist"
        return False

    if foo['value_hash'] != "22" * 20:
        print "invalid update hash"
        return False

    if foo['address'] != addr_reencode("1PYu4vKB3g2QLDFdurxqYSJ9aJSed7tne1") or \
       foo['sender'] != pybitcoin.make_pay_to_address_script(addr_reencode("1PYu4vKB3g2QLDFdurxqYSJ9aJSed7tne1")):
        return False 
    
    return True
