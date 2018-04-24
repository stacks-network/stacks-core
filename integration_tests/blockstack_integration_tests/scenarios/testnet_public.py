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
# activate STACKS Phase 1
"""
TEST ENV BLOCKSTACK_EPOCH_1_END_BLOCK 682
TEST ENV BLOCKSTACK_EPOCH_2_END_BLOCK 683
TEST ENV BLOCKSTACK_EPOCH_3_END_BLOCK 684
TEST ENV BLOCKSTACK_EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER 1
TEST ENV BLOCKSTACK_EPOCH_4_NAMESPACE_LIFETIME_MULTIPLIER 1
"""

import testlib
import virtualchain
import time
import json
import sys
import os
import BaseHTTPServer

wallets = [
    testlib.Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    testlib.Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    testlib.Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    testlib.Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 100000000000 ),
    testlib.Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 100000000000 )
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

class TestnetRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """
    testnet front-end server
    """
    def do_GET(self):
        # UI
        bitcoind = testlib.connect_bitcoind()
        blockheight = bitcoind.getblockcount()

        panel = '<html><head></head><body>Public Testnet<br>'
        panel += '<br>'
        panel += 'Blockchain height: {}<br>'.format(blockheight)
        panel += '<br>'
        panel += '<form action="/sendfunds" method="post">'
        panel += '    Fund address: <input type="text" name="addr"> value (satoshis): <input type="text" name="value" default="0"> <input type="submit" value="Fund address"></form><br>'
        panel += '</body></html>'

        self.send_response(200)
        self.send_header('content-type', 'text/html')
        self.send_header('content-length', len(panel))
        self.end_headers()
        self.wfile.write(panel)
        return


    def do_POST(self):
        content_type = self.headers.getheader('content-type')
        postvars = {}

        if content_type is not None:
            ctype, pdict = cgi.parse_header(content_type)
            if ctype == 'multipart/form-data':
                postvars = cgi.parse_multipart(self.rfile, pdict)
            elif ctype == 'application/x-www-form-urlencoded':
                length = int(self.headers.getheader('content-length'))
                postvars = cgi.parse_qs(self.rfile.read(length), keep_blank_values=1)

        if self.path == '/sendfunds':
            # fund an address
            addr = postvars.get('addr', [None])
            value = postvars.get('value', [None])

            if addr[0] is None or value[0] is None:
                log.error("Missing addr or value")
                self.send_response(400, "Invalid request: missing addr or value")
                self.end_headers()
                return

            try:
                value = int(value[0])
                addr = virtualchain.address_reencode(addr[0])
            except:
                log.error("Failed to read addr and/or value")
                log.error("postvars = {}".format(postvars))
                self.send_response(400, "Invalid addr or value")
                self.end_headers()
                return

            # can't take more than 0.1 BTC per address
            

            # send funds
            res = testlib.send_funds(testlib.get_default_payment_wallet().privkey, value, addr)
            if 'error' in res:
                log.error("Failed to send {} from {} to {}: {}".format(
                    value, testlib.get_default_payment_wallet().privkey, addr, res
                ))
                self.send_response(400, "Failed to send value")
                self.end_headers()
                return

            self.send_response(302)
            self.send_header('location', '/')
            self.end_headers()
            return

        else:
            log.error("Unsupported path {}".format(self.path))
            self.send_response(400, "Only support /sendfunds at this time")
            self.end_headers()
            return


class TestnetServer(BaseHTTPServer.HTTPServer):
    def __init__(self, working_dir, port, test_env):
        BaseHTTPServer.HTTPServer.__init__(self, ("0.0.0.0", port), TestnetRequestHandler)
        self.test_env = test_env
        self.done = False
        self.working_dir = working_dir
        self.funded = {}        # map address to sum(funds) in order to rate-limit


def scenario( wallets, **kw ):

    testlib.blockstack_namespace_preorder( "id", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    # same price curve as public .id namespace
    testlib.blockstack_namespace_reveal( "id", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "id", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_register_user('foo.id', wallets[2].privkey, wallets[3].privkey, **kw)

    # do 1-minute block times forever
    while True:
        time.sleep(60)
        testlib.next_block(**kw)


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

    # registered
    name_rec = state_engine.get_name( "foo.id" )
    if name_rec is None:
        print "name does not exist"
        return False

    return True
