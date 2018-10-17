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
import blockstack
import virtualchain
import binascii
import socket
import base64
import xmlrpclib
import StringIO
import gzip

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def make_big_zonefile(filler):
    return '{:02x}'.format(filler) * 20480

def scenario( wallets, **kw ):

    # make some zonefiles
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

    zfhashes = []

    for j in range(0, 5):
        for i in range(0, 20):
            big_zonefile = make_big_zonefile(i + 20*j)
            zonefile_hash = blockstack.lib.storage.get_zonefile_data_hash(big_zonefile)
            testlib.blockstack_name_update("foo.test", zonefile_hash, wallets[3].privkey)

            zfhashes.append(zonefile_hash)

        testlib.next_block(**kw)

        for i in range(0, 20):
            big_zonefile = make_big_zonefile(i + 20*j)
            res = blockstack.lib.client.put_zonefiles('http://localhost:16264', [base64.b64encode(big_zonefile)])
            assert res['saved'][0] == 1

        print '\n\ntest with {} zone files\n\n'.format(20 * j + i)
        res = blockstack.lib.client.get_zonefiles('http://localhost:16264', zfhashes)
        assert 'error' not in res, res

        for zfh in zfhashes:
            assert zfh in res['zonefiles'], 'missing {}, got {}'.format(zfh, res['zonefiles'].keys())


def check( state_engine ):
    
    return True

