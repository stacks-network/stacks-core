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
TEST ENV BLOCKSTACK_PUBLIC_TESTNET 1
"""

import testlib
import virtualchain
import time
import json
import sys
import os
import BaseHTTPServer
import stun
import urlparse
import atexit
import subprocess
import socket
import threading
import traceback
import virtualchain
import cgi
import blockstack
import re

log = virtualchain.get_logger('testnet')

wallets = [
    testlib.Wallet(virtualchain.lib.ecdsalib.ecdsa_private_key().to_wif(), 1000000000000000000 ),
    testlib.Wallet(virtualchain.lib.ecdsalib.ecdsa_private_key().to_wif(), 1000000000000000000 ),
    testlib.Wallet(virtualchain.lib.ecdsalib.ecdsa_private_key().to_wif(), 1000000000000000000 ),
    testlib.Wallet(virtualchain.lib.ecdsalib.ecdsa_private_key().to_wif(), 1000000000000000000 ),
]

PROTO = 'http'

TESTNET_PUBLIC_HOST = 'localhost'   # NOTE: must match gaia config
if os.environ.get('BLOCKSTACK_TESTNET_PUBLIC_HOST'):
    TESTNET_PUBLIC_HOST = os.environ['BLOCKSTACK_TESTNET_PUBLIC_HOST']

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

TRANSACTION_BROADCASTER_URL = None

BITCOIN_JSONRPC_URL = '{}://{}:18332'.format(PROTO, TESTNET_PUBLIC_HOST)
BITCOIN_P2P_URL = '{}://{}:18444'.format(PROTO, TESTNET_PUBLIC_HOST)

SERVER_THREAD = None

class TestnetRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """
    testnet front-end server
    TODO: replace with Flask app or something
    """

    def reply_json(self, ret, cache_max_age=None):
        ret = json.dumps(ret)
        self.send_response(200)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', len(ret))

        if cache_max_age:
            self.send_header('cache-control', 'max-age={}'.format(cache_max_age))

        self.end_headers()
        self.wfile.write(ret)
        return


    def do_GET(self):
        if self.path == '/blockHeight':
            ret = self.server.get_cached_chain_tip()
            return self.reply_json(ret, 30)

        if self.path == "/operations":
            ret = self.server.get_cached_last_block()
            return self.reply_json(ret, 30)

        if self.path == "/atlas-neighbors":
            ret = self.server.get_cached_atlas_neighbors()
            return self.reply_json(ret, 30)

        if self.path == '/config':
            ret = {
                'transactionBroadcasterURL': TRANSACTION_BROADCASTER_URL,
                'bitcoinJSONRPCURL': BITCOIN_JSONRPC_URL,
                'bitcoinP2PURL': BITCOIN_P2P_URL,
            }
            return self.reply_json(ret, 3600)

        # /balance/{}
        if self.path.startswith('/balance'):
            try:
                addr = self.path.strip('/').split('/')[-1]
                addr = virtualchain.address_reencode(addr, network='testnet')
            except:
                traceback.print_exc()
                return self.error_page(400, 'Invalid address or path')

            try:
                btc_balance = testlib.get_balance(addr)
                stacks_balance = blockstack.lib.client.get_account_balance(addr, 'STACKS', hostport='http://localhost:16264')
                assert isinstance(stacks_balance, (int,long))
            except:
                traceback.print_exc()
                return self.error_page(500, 'Failed to query balance')

            ret = {
                'btc': '{}'.format(btc_balance),
                'stacks': '{}'.format(stacks_balance),
            }
            return self.reply_json(ret)

        # /names/page
        if self.path.startswith('/names/'):
            try:
                page = int(self.path.strip('/').split('/')[-1])
            except:
                traceback.print_exc()
                return self.error_page(400, 'Invalid page')

            names = blockstack.lib.client.get_all_names(offset=page * 100, count=100, hostport='http://localhost:16264')
            return self.reply_json(names, 30)

        # /namespaces/page
        if self.path.startswith('/namespaces/'):
            try:
                page = int(self.path.strip('/').split('/')[-1])
            except:
                traceback.print_exc()
                return self.error_page(400, 'Invalid page')

            names = blockstack.lib.client.get_all_namespaces(offset=page * 100, count=100, hostport='http://localhost:16264')
            return self.reply_json(names, 30)

        return self.error_page(404, 'The server that serves the testnet panel must be down')

    def error_page(self, status_code, message):
        self.send_response(status_code)
        self.send_header('content-type', 'text/plain')
        self.send_header('content-length', len(message))
        self.end_headers()
        self.wfile.write(message)
        return


    def do_POST(self):
        content_type = self.headers.getheader('content-type')
        postvars = {}
        txid = None

        if content_type is not None:
            ctype, pdict = cgi.parse_header(content_type)
            if ctype == 'multipart/form-data':
                postvars = cgi.parse_multipart(self.rfile, pdict)
            elif ctype == 'application/x-www-form-urlencoded':
                length = int(self.headers.getheader('content-length'))
                postvars = cgi.parse_qs(self.rfile.read(length), keep_blank_values=1)

        if self.path == '/sendBTC':
            # fund an address with bitcoin
            addr = postvars.get('addr', [None])
            value = postvars.get('value', [None])

            if addr[0] is None or value[0] is None:
                log.error("Missing addr or value")
                self.error_page(400, "Invalid request: missing addr or value")
                return

            try:
                value = int(value[0])
                addr = virtualchain.address_reencode(addr[0])
            except:
                log.error("Failed to read addr and/or value")
                log.error("postvars = {}".format(postvars))
                self.error_page(400, "Invalid addr or value")
                return

            # don't take too much
            if value > 10000000:
                log.error('{} requested too much ({})'.format(addr, value))
                self.error_page(400, 'Requested too much BTC (at most {} is allowed)'.format(10000000))
                return 

            # send funds
            res = testlib.send_funds(testlib.get_default_payment_wallet().privkey, value, addr)
            if 'error' in res:
                log.error("Failed to send {} BTC from {} to {}: {}".format(
                    value, testlib.get_default_payment_wallet().privkey, addr, res
                ))
                self.error_page(400, "Failed to send value")
                return

            txid = res['txid']

            self.send_response(302)
            location = '/'
            if txid:
                location = '/?bitcoinTxid={}'.format(txid)

            self.send_header('location', location)
            self.end_headers()
            return

        elif self.path == '/sendStacks':
            # fund an address with bitcoin
            addr = postvars.get('addr', [None])
            value = postvars.get('value', [None])

            if addr[0] is None or value[0] is None:
                log.error("Missing addr or value")
                log.error("Got {}".format(postvars))
                self.error_page(400, "Invalid request: missing addr or value")
                self.end_headers()
                return

            # addr can be either base58check or c32check
            if re.match('^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]+$', addr[0]):
                # c32check 
                try:
                    res = testlib.nodejs_cli('convert_address', addr[0])
                    res = json.loads(res)
                    addr = [res['BTC']]
                except:
                    self.error_page(500, 'Failed to convert {} to a Stacks address'.format(addr[0]))
                    self.end_headers()
                    return

            try:
                value = int(value[0])
                addr = virtualchain.address_reencode(str(addr[0]))
            except:
                log.error("Failed to read addr and/or value")
                log.error('addr = {}, value = {}'.format(addr[0], value[0]))
                self.error_page(400, "Invalid addr or value")
                self.end_headers()
                return

            # don't take too much
            if value > 1000000000:
                log.error('{} requested too much ({})'.format(addr, value))
                self.error_page(400, 'Requested too much STACKS (at most {} is allowed)'.format(1000000000))
                self.end_headers()
                return

            # send funds
            res = None
            try:
                res = testlib.blockstack_send_tokens(addr, 'STACKS', value, wallets[3].privkey)
                txid = res['transaction_hash']
            except Exception as e:
                log.exception(e)
                self.error_page(500, 'Failed to send tokens to {}\n{}'.format(addr, ''.join(traceback.format_exc())))
                self.end_headers()
                return

            if 'error' in res:
                log.error("Failed to send {} Stacks from {} to {}: {}".format(
                    value, testlib.get_default_payment_wallet().privkey, addr, res
                ))
                self.error_page(400, "Failed to send value")
                self.end_headers()
                return

            # also send some BTC
            res = testlib.send_funds(testlib.get_default_payment_wallet().privkey, 5000000, addr)
            if 'error' in res:
                log.error("Failed to send {} BTC from {} to {}: {}".format(
                    value, testlib.get_default_payment_wallet().privkey, addr, res
                ))
                self.error_page(400, "Failed to send value")
                return

            self.send_response(302)
            location = '/'
            if txid:
                location = '/?stacksTxid={}'.format(txid)

            self.send_header('location', location)
            self.end_headers()
            return

        else:
            log.error("Unsupported path {}".format(self.path))
            self.error_page(400, "Only support /sendfunds at this time")
            self.end_headers()
            return


class TestnetServer(BaseHTTPServer.HTTPServer):
    def __init__(self, port):
        BaseHTTPServer.HTTPServer.__init__(self, ("0.0.0.0", port), TestnetRequestHandler)

        self.block_height = None
        self.consensus_hash = None
        self.last_block_operations = None

        self.last_neighbors = None

        self.last_block_height_check = -1
        self.last_neighbors_check = -1

    def refresh_chain_tip(self):
        bitcoind = testlib.connect_bitcoind()
        self.block_height = bitcoind.getblockcount()
        self.consensus_hash = testlib.get_consensus_at(self.block_height);
        self.last_block_operations = blockstack.lib.client.get_blockstack_transactions_at(self.block_height, hostport='http://localhost:16264')
        self.last_block_height_check = time.time()

    def refresh_neighbors(self):
        ret = blockstack.lib.client.get_atlas_peers('http://localhost:16264')
        if 'error' in ret:
            return

        peers = ret['peers']
        peer_hostports = [blockstack.lib.util.url_to_host_port(p) for p in peers]
        self.last_neighbors = [{'host': peer[0], 'port': peer[1]} for peer in peer_hostports]
        self.last_neighbors_check = time.time()

    def get_cached_chain_tip(self):
        if self.last_block_height_check + 30 < time.time():
            self.refresh_chain_tip()

        return {'blockHeight': self.block_height, 'consensusHash': self.consensus_hash}

    def get_cached_last_block(self):
        if self.last_block_height_check + 30 < time.time():
            self.refresh_chain_tip()

        return self.last_block_operations

    def get_cached_atlas_neighbors(self):
        if self.last_neighbors_check + 30 < time.time():
            self.refresh_neighbors()

        return self.last_neighbors



class WebServerThread(threading.Thread):
    def __init__(self, port):
        threading.Thread.__init__(self)
        self.websrv = TestnetServer(port)
        self.done = False

    def run(self):
        while not self.done:
            self.websrv.handle_request()

    def ask_join(self):
        self.done = True
        try:
            self.websrv.socket.shutdown(socket.SHUT_RDWR)
        except:
            print >> sys.stderr, 'Failed to shut down testnet server socket'


def start_test_server(port):
    global SERVER_THREAD

    t = WebServerThread(port)
    SERVER_THREAD = t

    testlib.add_cleanup(stop_test_server)
    t.start()


def stop_test_server():
    global SERVER_THREAD
    print 'kill test server'

    try:
        if SERVER_THREAD is not None:
            SERVER_THREAD.ask_join()
            SERVER_THREAD.join()
            SERVER_THREAD = None
    except:
        traceback.print_exc()
        pass


def scenario( wallets, **kw ):
    global TRANSACTION_BROADCASTER_URL


    # fill in URL
    tb_conf_path = os.path.join(os.environ['BLOCKSTACK_WORKING_DIR'], 'transaction-broadcaster.conf')
    with open(tb_conf_path, 'r') as f:
        tb_conf = json.loads(f.read().strip())

    TRANSACTION_BROADCASTER_URL = 'http://{}:{}'.format(TESTNET_PUBLIC_HOST, tb_conf['port'])

    PORTNUM = int(os.environ.get('TESTNET_PORTNUM', '30001'))
    start_test_server(PORTNUM)

    testlib.blockstack_namespace_preorder( "id2", wallets[1].addr, wallets[0].privkey )
    testlib.blockstack_namespace_preorder( "test", wallets[1].addr, wallets[0].privkey )
    testlib.blockstack_namespace_preorder( "sandbox", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    # same price curve as public .id namespace
    testlib.blockstack_namespace_reveal( "id2", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=3)
    testlib.blockstack_namespace_reveal( "test", wallets[1].addr, -1, 250, 4, [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=3)
    testlib.blockstack_namespace_reveal( "sandbox", wallets[1].addr, -1, 250, 4, [6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=3)
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "id2", wallets[1].privkey )
    testlib.blockstack_namespace_ready( "test", wallets[1].privkey )
    testlib.blockstack_namespace_ready( "sandbox", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.set_account_audits(False)

    print 'Testnet initialized'

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
