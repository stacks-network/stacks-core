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
import testlib
import virtualchain
import blockstack_client

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def check_wallet(payment_privkey, owner_privkey, data_privkey):
    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    config_dir = os.path.dirname(config_path)
     
    conf = blockstack_client.get_config(config_path)
    assert conf

    api_pass = conf['api_password']

    res = testlib.blockstack_REST_call('GET', '/v1/wallet/keys', None, api_pass=api_pass)
    if 'error' in res:
        print 'failed to get wallet'
        print res
        return False

    res = res['response']
    if res['payment_privkey'] != payment_privkey:
        print 'wrong payment privkey'
        return False

    if res['owner_privkey'] != owner_privkey:
        print 'wrong owner privkey'
        return False

    if res['data_privkey'] != data_privkey:
        print 'wrong data privkey'
        return False

    return True

def scenario( wallets, **kw ):

    # save the wallet 
    wallet = testlib.blockstack_client_initialize_wallet( "0123456789abcdef", wallets[2].privkey, wallets[3].privkey, wallets[4].privkey )
    if 'error' in wallet:
        print 'failed to set wallet: {}'.format(wallet)
        return False

    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    config_dir = os.path.dirname(config_path)
     
    conf = blockstack_client.get_config(config_path)
    assert conf

    api_pass = conf['api_password']

    if not check_wallet(wallets[2].privkey, wallets[3].privkey, wallets[4].privkey):
        return False

    res = testlib.blockstack_REST_call('PUT', '/v1/wallet/keys/owner', None, api_pass=api_pass, data=wallets[0].privkey)
    if 'error' in res:
        print 'failed to set owner key'
        print res
        return False
       
    if not check_wallet(wallets[2].privkey, wallets[0].privkey, wallets[4].privkey):
        return False

    res = testlib.blockstack_REST_call('PUT', '/v1/wallet/keys/payment', None, api_pass=api_pass, data=wallets[1].privkey)
    if 'error' in res:
        print 'failed to set payment key'
        print res
        return False

    if not check_wallet(wallets[1].privkey, wallets[0].privkey, wallets[4].privkey):
        return False

    res = testlib.blockstack_REST_call('PUT', '/v1/wallet/keys/data', None, api_pass=api_pass, data=wallets[2].privkey)
    if 'error' in res:
        print 'failed to set payment key'
        print res
        return False

    if not check_wallet(wallets[1].privkey, wallets[0].privkey, wallets[2].privkey):
        return False

    
def check( state_engine ):

    return True
