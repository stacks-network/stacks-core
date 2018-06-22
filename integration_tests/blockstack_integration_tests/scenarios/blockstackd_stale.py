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
import os
import blockstack
import time

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):
    testlib.next_block(**kw)

    rpcclient = blockstack.lib.client.BlockstackRPCClient('localhost', 16264, debug_timeline=True, protocol='http')

    res = rpcclient.getinfo()
    assert 'stale' not in res and 'error' not in res

    res = rpcclient.ping()
    assert 'stale' not in res and 'error' not in res

    res = rpcclient.get_all_names(0,10)
    assert 'stale' not in res and 'error' not in res

    # force the rpc server to think we're stale
    blockstack.blockstackd.rpc_chain_sync(testlib.get_server_state(), testlib.get_current_block(**kw), time.time() - blockstack.lib.config.RPC_MAX_INDEXING_DELAY - 1)

    res = rpcclient.getinfo()
    if 'stale' not in res or not res['stale']:
        print 'no stale; {}'.format(res)
        return False

    res = rpcclient.ping()
    if res['status'] != 'stale':
        print 'no stale: {}'.format(res)
        return False

    res = rpcclient.get_all_names(0,10)
    if 'stale' not in res or not res['stale']:
        print 'no stale: {}'.format(res)
        return False
    
    # reset
    testlib.next_block(**kw)

    res = rpcclient.getinfo()
    assert 'stale' not in res and 'error' not in res

    res = rpcclient.ping()
    assert 'stale' not in res and 'error' not in res

    res = rpcclient.get_all_names(0,10)
    assert 'stale' not in res and 'error' not in res


def check( state_engine ):
    return True

