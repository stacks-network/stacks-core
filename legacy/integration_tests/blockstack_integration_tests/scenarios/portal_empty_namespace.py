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

"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 689
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 690
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 2
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 2
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_GRACE_PERIOD 5
"""

import testlib
import virtualchain
import time
import json
import sys
import re
import blockstack

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 5500 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 5500 ),
    testlib.Wallet('5Kh8cUeVaUXx8PNrNg3zn88w6m5BNZUuYLDs2tJx8bYGcRkkpa6',0),
    testlib.Wallet('5Jdmz1ZaPKKfgsX8uXGD7XBH2KsWieHEpSrq5A28Wti6b2B5Vjx',0),
    testlib.Wallet('5KFGi8jzCyFANkiCE66x17eEF74uJ1VGAdAzzz2gHbhA1XC2zfu',0),
    testlib.Wallet('5JpSjFwAD9QLyQDDhrb1hrsk2zStWFFjt6kSxT5vshBvMjJzWd4',0),
    testlib.Wallet('5K8YoPZoGsyaT3SeGSr6ab9anU8o4pYe8uHn8SJFDdHy66NoBRx',0),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

ZONEFILE_FORMAT = """
$ORIGIN {fqu}
$TTL 3600
_http._tcp URI 10 1 "{url}"
""".strip()

URL = "https://gaia.blockstack.org/hub/{addr}/{index}/profile.json"

def make_zonefile(name, address, index=0):
    """
    Make the appropriate zone file hash
    """
    url = URL.format(addr = address, index = index)
    zonefile_data = ZONEFILE_FORMAT.format(fqu = name, url = url)
    return zonefile_data


def make_zonefile_hash(name, address, index=0):
    """
    Make the appropriate zone file hash
    """
    zonefile_data = make_zonefile(name, address, index=index)
    zonefile_hash = blockstack.lib.client.get_zonefile_data_hash(zonefile_data)
    return zonefile_hash

def scenario( wallets, **kw ):

    testlib.blockstack_namespace_preorder( "id", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )
    
    # names last for 10 blocks
    testlib.blockstack_namespace_reveal( "id", wallets[1].addr, 10, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "id", wallets[1].privkey )
    testlib.next_block( **kw )
     
    names_to_preorder_and_renew = '/tmp/testdata.txt'
    if os.path.exists(names_to_preorder_and_renew):
        name_infos = []
        with open(names_to_preorder_and_renew, 'r') as f:
            while True:
                name_line = f.readline()
                if len(name_line) == 0:
                    break
                
                name_line = name_line.strip()
                m = re.match('^([^ ]+)[ ]+([^ ]+)[ ]+([^ ]+)$', name_line)
                if m:
                    name, addr, pkey = m.groups()
                    name_infos.append({'name': name.strip(), 'addr': addr.strip(), 'owner_privkey': pkey.strip()})
                else:
                    name, addr = name_line.split(' ', 1)
                    name_infos.append({'name': name.strip(), 'addr': addr.strip()})

        for i, name_info in enumerate(name_infos):
            owner_addr = None
            if name_info.has_key('owner_privkey'):
                owner_addr = virtualchain.get_privkey_address(name_info['owner_privkey'])
            else:
                print name_info['addr']
                owner_addr = virtualchain.address_reencode(name_info['addr'])
            
            testlib.blockstack_name_preorder(name_info['name'], wallets[(i%8)+2].privkey, owner_addr, safety_checks=False, tx_fee=300*1000)

        testlib.next_block(**kw)

        for i, name_info in enumerate(name_infos):
            owner_addr = None
            if name_info.has_key('owner_privkey'):
                owner_addr = virtualchain.get_privkey_address(name_info['owner_privkey'])
            else:
                owner_addr = virtualchain.address_reencode(name_info['addr'])
            
            zonefile_hash = make_zonefile_hash(name_info['name'], owner_addr)
            testlib.blockstack_name_register(name_info['name'], wallets[(i%8)+2].privkey, owner_addr, zonefile_hash=zonefile_hash, safety_checks=False, tx_fee=300*1000)
            
        testlib.next_block(**kw)

    print >> sys.stderr, "We're a go!"


def check( state_engine ):

    # not revealed, but ready 
    ns = state_engine.get_namespace_reveal( "id" )
    if ns is not None:
        print "namespace reveal exists"
        return False 

    ns = state_engine.get_namespace( "id" )
    if ns is None:
        print "no namespace"
        return False 

    if ns['namespace_id'] != 'id':
        print "wrong namespace"
        return False 
    
    return True
