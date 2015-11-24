#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstore

    Blockstore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore. If not, see <http://www.gnu.org/licenses/>.
""" 

import testlib
import pybitcoin
import json
import shutil
import tempfile
import os

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
    testlib.Wallet( "5Jyq6RH7H42aPasyrvobvLvZGPDGYrq9m2Gq5qPEkAwDD7fqNHu", 100000000000 ),
    testlib.Wallet( "5KBc5xk9Rk3qmYg1PXPzsJ1kPfJkvzShK5ZGEn3q4Gzw4JWqMuy", 100000000000 ),
    testlib.Wallet( "5K6Nou64uUXg8YzuiVuRQswuGRfH1tdb9GUC9NBEV1xmKxWMJ54", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

debug = True


def do_interleaving( name, namerecs, order ):
    
    # order should be a string of "u", "t", and "r"
    order = list(order)
    
    for i in xrange(0, len(order)):
    
        op = order[i]

        if op == 'r':
            # renew
            print "\nrenew '%s' with %s\n" % (name, pybitcoin.make_pay_to_address_script( namerecs[name][0].addr ))
            resp = testlib.blockstore_name_renew( name, namerecs[name][0].privkey, register_addr=namerecs[name][0].addr )
            if 'error' in resp:
                print json.dumps( resp, indent=4 )

        elif op == 'u':
            # update
            resp = testlib.blockstore_name_update( name, ("%s%s" % (i, i)) * 20, namerecs[name][0].privkey )
            if 'error' in resp:
                print json.dumps( resp, indent=4 )

        elif op == 't':
            # transfer and exchange wallets 
            print "\ntransfer '%s' from %s to %s" % (name, pybitcoin.make_pay_to_address_script( namerecs[name][0].addr ), pybitcoin.make_pay_to_address_script( namerecs[name][1].addr ))
            resp = testlib.blockstore_name_transfer( name, namerecs[name][1].addr, True, namerecs[name][0].privkey )
            if 'error' in resp:
                print json.dumps( resp, indent=4 )

            tmp = namerecs[name][0]
            namerecs[name][0] = namerecs[name][1]
            namerecs[name][1] = tmp


def scenario( wallets, **kw ):

    # make a test namespace
    resp = testlib.blockstore_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstore_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    if debug or 'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    resp = testlib.blockstore_namespace_ready( "test", wallets[1].privkey )
    if debug or  'error' in resp:
        print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # 6 names, for all interleavings of (u)pdate, (t)ransfer, and (r)enew
    # NOTE: the name encodes the interleaving order
    names = {
        "utr.test": [wallets[0], wallets[1]],
        "urt.test": [wallets[2], wallets[3]],
        "tur.test": [wallets[4], wallets[5]],
        "tru.test": [wallets[6], wallets[7]],
        "rut.test": [wallets[8], wallets[9]],
        "rtu.test": [wallets[10], wallets[11]]
        }

    # preorder them all
    for name in names.keys():

        resp = testlib.blockstore_name_preorder( name, names[name][1].privkey, names[name][0].addr )
        if debug or  'error' in resp:
            print json.dumps( resp, indent=4 )
   
    testlib.next_block( **kw )

    # regster them all
    for name in names.keys():

        resp = testlib.blockstore_name_register( name, names[name][1].privkey, names[name][0].addr )
        if debug or  'error' in resp:
            print json.dumps( resp, indent=4 )

    testlib.next_block( **kw )

    # test intra-block interleavings:
    # update/transfer/renew
    # update/renew/transfer
    # transfer/update/renew
    # transfer/renew/update
    # renew/update/transfer
    # renew/transfer/update
    for name in names.keys():

        do_interleaving( name, names, name[:-5] )

    # iterate the blocks a few times 
    for i in xrange(0, 5):
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

    # name recs
    names = {
        "utr.test": {
            "address": wallets[1].addr,
            "value_hash": "00" * 20
        },
        "urt.test": {
            "address": wallets[3].addr,
            "value_hash": "00" * 20
        },
        "tur.test": {
            "address": wallets[5].addr,
            "value_hash": "11" * 20
        },
        "tru.test": {
            "address": wallets[7].addr,
            "value_hash": "22" * 20
        },
        "rut.test": {
            "address": wallets[9].addr,
            "value_hash": "11" * 20
        },
        "rtu.test": {
            "address": wallets[11].addr,
            "value_hash": "22" * 20
        }
    }

    for name in names.keys():
        name_rec = state_engine.get_name( name )
        if name_rec is None:
            print "missing %s" % name
            return False 

        # check update
        if name_rec['value_hash'] != names[name]['value_hash']:
            print "value hash mismatch on %s: expected %s, got %s" % (name, names[name]['value_hash'], name_rec['value_hash'])
            return False 

        # check owner 
        if name_rec['address'] != names[name]['address'] or name_rec['sender'] != pybitcoin.make_pay_to_address_script( names[name]['address'] ):
            print "owner mismatch on %s: expected %s, got %s" % (name, names[name]['address'], name_rec['address'])
            return False 

    return True
