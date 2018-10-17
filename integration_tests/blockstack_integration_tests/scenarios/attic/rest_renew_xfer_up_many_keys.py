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
# activate F-day 2017 at the right time
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 682
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 683
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 1
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

payment_wallets = [
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

owner_wallets = [
    testlib.Wallet('KzeuhHMPgREKPXWxEPi26tmi7TceP2dfqUEhcKi6wmEnbvXLLRim', 100000000000 ),
    testlib.Wallet('L28RXVJd3EtX9ntZ7iKxKCnChqbFVyybydZWgutaViETcVjjz14G', 100000000000 ),
    testlib.Wallet('L4Am9WmwQzVdgjZuFX8ybpiMbLxetpBW4sQdAYMZp5a5PGQZSS5f', 100000000000 ),
    testlib.Wallet('L13NYqq2zgYokm2Gqv83GAoHPTTFQZBRKBHWeW8f97NBpWgFgWEw', 100000000000 ),
    testlib.Wallet('KyMefgskvxe1BuWqVLAejnXQ1NZeStbmW83tiowCLyAamFVpnn4c', 100000000000 ),
    testlib.Wallet('KxE6yXCW4FF8DYPBoUUYyswgjvSBJK8ae3HymPSe2YXA7x7mXXo4', 100000000000 ),
    testlib.Wallet('Kztcpba3cEDrjNp7p2AXQCNvUANyTLnh4btSfcHbpYANTpwnM1d9', 100000000000 ),
    testlib.Wallet('KxdL3LNFcKVsqwKXeSgL3xig3S8c8F2PG2GduSmTm5ZNhdVvnUkL', 100000000000 ),
    testlib.Wallet('KyaEanXmnKwsNTLbCM4ASmT3xMYHVDNod54NvWHvA1hmWjCxdoYY', 100000000000 ),
    testlib.Wallet('KyTb1EobQpAB2mJD5qEsyf8QzMjKDVnPyqAkfUodKVC6sseeVdsd', 100000000000 ),
    testlib.Wallet('KxYxgeJWSABmQBxcKpQfij9DUo9ebRjS3UH3aBWaAWsTzHdbvNic', 100000000000 ),
    testlib.Wallet('L5jRydyXkQ7UhHBkheADRfL3upAUcLeXKTstHU8abrBmic7is7jB', 100000000000 ),
    testlib.Wallet('KwybQ2pZ4Pxp1YXh1eEo5emtohBKDwiA3LtRESfypHoWuehpepcP', 100000000000 ),
    testlib.Wallet('L3EEiAdMbLajHjzKNHxkjZwi4ttPjLH4CepwF3BoQMNcUvmU9ASC', 100000000000 ),
    testlib.Wallet('KxDXzGD7YoHom2bj6CmRX9Lvj3dLXv5hTsbEJau9rh8idEJFqdch', 100000000000 ),
    testlib.Wallet('KyP9iu1dDcC2sBNSzDFv4bgQ3H1zEXGiaThWvQYqwXpHNNHSS5bQ', 100000000000 ),
    testlib.Wallet('L3UcdkyjmRjXyEKSPVuzQLo2RjAJMLcfA4Gzg82PSTp5nzgCz1Uy', 100000000000 ),
    testlib.Wallet('KwTKhUvVrMpvjioGoHsbsQzQSAyWuG5NAW88Kf6DJGQZxSM6cQci', 100000000000 ),
    testlib.Wallet('L5Te6oujjD1KmpVPGJf1dYfrRAwViD6KArRpSChsnKstW72Budsf', 100000000000 ),
    testlib.Wallet('L2kU9iqu3EgtTYtF6CCshFgKsNxSL81vvL3cwx2w516ZAT6VQZ2F', 100000000000 ) ]

wallets = payment_wallets + owner_wallets

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"
error = False

names = ["name_{}.test".format(i) for i in range(20)]

recipients = [ '1PMjaoWt2TGDHJUBBZohM5pxAkkPCcEGts',
               '13HKnbQv452Rtye7NnvZvCfvkRxkyAz9jR',
               '1AfxVpjeZ1cL27ydE7ULiguSxQgtJtxB4T',
               '15oY1e8wvYGZzNFuyvfMHUgsh61rUp5qre',
               '141H87PyYWXrQgRzuaDECPT1YXCrZEriMB',
               '1HaunB9929uDXcya8A68KySAk3f6UnXGid',
               '16agRU8RK87JTWdquDWUxFFxvxywNBa5Yn',
               '19xw3zR7jMFK1i924aCkm6MDCBZDjzrbQw',
               '16tuw67Gcg9RNA7GsWdMHNt64x1UWxPi1',
               '1DKNr1rHdN2UWbSJQ5YWoVDW3sjer8nwsC',
               '1JRMBpM6xKkXxUfN4EumaPYZYrw3nrRDFQ',
               '16L7x7pup4dADZ6UoJtFX5wFKEhupCq8py',
               '194JNUUeXc2U7AgZRc5HZekurfCscjkuP1',
               '1DiQamUC7mkzCf78ANnFsDT3bnrw7UVuQ8',
               '17mH2TpxqThLRRPm4fcRvDvrJ8k24rdpFc',
               '11uWBGMgZc7gFtRPQGGu2gVU2WPo1Khwv',
               '1379QJVZEPBUadgkRv7YtkNU5GD6MEmeLW',
               '15oKqojAh2WvRWJzVPLLRaaqybWL9Pghjg',
               '1Lwxy49ihc8KP3diz78E3GESkxtTm67soK',
               '1N7km8oqun9269PXCGC4WVS7eERvsAvzbZ' ]

assert len(names) == len(recipients)
assert len(names) == len(owner_wallets)

def scenario( wallets, **kw ):

    global error
    global names, owner_wallets, payment_wallets, recipients

    wallet_keys = testlib.blockstack_client_initialize_wallet(
        "0123456789abcdef", wallets[5].privkey, wallets[3].privkey, wallets[4].privkey )
    test_proxy = testlib.TestAPIProxy()
    blockstack_client.set_default_proxy( test_proxy )

    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.next_block( **kw )

    # tell serialization-checker that value_hash can be ignored here
    print "BLOCKSTACK_SERIALIZATION_CHECK_IGNORE value_hash"
    sys.stdout.flush()


    processed_preorders = 0
    while processed_preorders < len(owner_wallets):
        name, owner = names[processed_preorders], owner_wallets[processed_preorders]
        payer_ix = processed_preorders % len(payment_wallets)
        payer = payment_wallets[payer_ix]
        testlib.blockstack_name_preorder( name, payer.privkey, owner.addr )

        processed_preorders += 1
        if payer_ix == (len(payment_wallets) - 1):
            testlib.next_block(**kw)
            testlib.next_block(**kw)

    testlib.next_block(**kw)

    processed_registers = 0
    while processed_registers < len(owner_wallets):
        name, owner = names[processed_registers], owner_wallets[processed_registers]
        payer_ix = processed_registers % len(payment_wallets)
        payer = payment_wallets[payer_ix]
        testlib.blockstack_name_register( name, payer.privkey, owner.addr )
        processed_registers += 1

        if payer_ix == (len(payment_wallets) - 1):
            testlib.next_block(**kw)
            testlib.next_block(**kw)

    # now let's go crazy with transfers

    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    config_dir = os.path.dirname(config_path)
    conf = blockstack_client.get_config(config_path)
    assert conf
    api_pass = conf['api_password']

    testlib.next_block(**kw)


    processed_transfers = 0
    while processed_transfers < len(owner_wallets):
        name, owner_privkey, recipient = (names[processed_transfers],
                                          owner_wallets[processed_transfers].privkey,
                                          recipients[processed_transfers])
        payer_ix = processed_transfers % len(payment_wallets)
        payer = payment_wallets[payer_ix]

        driver_urls = blockstack_client.storage.make_mutable_data_urls(name, use_only=['dht', 'disk'])
        zonefile = blockstack_client.zonefile.make_empty_zonefile(name, None, urls=driver_urls)
        zonefile_txt = blockstack_zones.make_zone_file( zonefile, origin=name, ttl=3600 )

        res = testlib.blockstack_REST_call(
            'POST', '/v1/names/', None, api_pass=api_pass, data={
                'name' : name,
                'owner_address': recipient, 'owner_key' : owner_privkey,
                'payment_key' : payer.privkey, 'zonefile' : zonefile_txt,
        })
        if 'error' in res or res['http_status'] != 202:
            res['test'] = '(Wrongly) failed to renew/transfer/update user'
            print json.dumps(res)
            error = True
            return False
        else:
            print "Submitted transfer!"

        processed_transfers += 1
        if (payer_ix == (len(payment_wallets) - 1) or
            processed_transfers >= len(owner_wallets)):
            print 'Waiting to get more UTXOs and processing transfers'
            time.sleep(10)
            for i in range(11):
                testlib.next_block( **kw )
    return True

def check( state_engine ):

    global error
    global names, owner_wallets, payment_wallets, recipients

    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG")
    assert config_path
    config_dir = os.path.dirname(config_path)
    conf = blockstack_client.get_config(config_path)
    assert conf
    api_pass = conf['api_password']

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

    for name, recipient in zip(names, recipients):
        res = testlib.blockstack_REST_call("GET", "/v1/names/{}".format(name),
                                           None, api_pass=api_pass)
        if 'error' in res or res['http_status'] != 200:
            res['test'] = 'Failed to get name {}'.format(name)
            print json.dumps(res)
            return False
        if 'address' not in res['response']:
            print res
            return False

        cur_owner_address = res['response']['address']
        if cur_owner_address != recipient:
            print "After transfer, unexpected owner. Expected {}, Actual {}".format(
                recipient, cur_owner_address)
            return False


    return True
