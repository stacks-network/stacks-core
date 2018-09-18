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
TEST ENV BLOCKSTACK_RPC_MAX_THREADS 20
"""

import testlib 
import json
import os
import blockstack
import time
import threading
import socket

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def slow_client(timeout):
    # NOTE: these will 400, but that's okay -- the point is to fill up the number of concurrent client slots
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(('localhost', 16264))
    s.send('Hello {}'.format(threading.current_thread().ident))
    try:
        s.recv(65536)
    except socket.timeout:
        print '{} timed out'.format(threading.current_thread().ident)


def scenario( wallets, **kw ):
    testlib.next_block(**kw)

    # fill up the thread bank 
    threads = []
    for i in range(0, 19):
        t = threading.Thread(target=slow_client, args=(30,))
        t.start()
        threads.append(t)

    time.sleep(5)

    # confirm that we can still ping the server
    rpcclient = blockstack.lib.client.BlockstackRPCClient('localhost', 16264, debug_timeline=True, protocol='http')

    res = rpcclient.getinfo()
    assert 'error' not in res

    # fill up the thread bank completely (20 threads)
    t = threading.Thread(target=slow_client, args=(10,))
    t.start()
    threads.append(t)

    time.sleep(1)

    try:
        # should fail---no threads are free
        res = rpcclient.getinfo()
        assert 'error' in res, 'Expected error, got {}'.format(res)
        assert res['error'] == 'overloaded', res
    except:
        pass

    # make that last thread timeout
    time.sleep(15)
    
    # should work again 
    res = rpcclient.getinfo()
    assert 'error' not in res

    # wait for all other threads to die
    time.sleep(30)
    for t in threads:
        print 'join {}'.format(t.ident)
        t.join()

def check( state_engine ):
    return True

