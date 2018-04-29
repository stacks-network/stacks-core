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

log = virtualchain.get_logger('testnet')

wallets = [
    testlib.Wallet(virtualchain.lib.ecdsalib.ecdsa_private_key().to_wif(), 100000000000 ),
    testlib.Wallet(virtualchain.lib.ecdsalib.ecdsa_private_key().to_wif(), 100000000000 ),
    testlib.Wallet(virtualchain.lib.ecdsalib.ecdsa_private_key().to_wif(), 100000000000 ),
    testlib.Wallet(virtualchain.lib.ecdsalib.ecdsa_private_key().to_wif(), 1000000000000000000 ),
]

consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

SUBDOMAIN_DOMAIN = "personal.id"
SUBDOMAIN_OWNER_KEY = wallets[3].privkey
SUBDOMAIN_PAYMENT_KEY = wallets[2].privkey
SUBDOMAIN_ADMIN_PASSWORD = os.urandom(16).encode('hex')
SUBDOMAIN_OWNER_ADDRESS = wallets[2].addr
SUBDOMAIN_REGISTRAR_PORT = 30000
SUBDOMAIN_PROC = None

try:
    _, IP_ADDRESS, _ = stun.get_ip_info()
except:
    IP_ADDRESS = '127.0.0.1'

SUBDOMAIN_REGISTRAR_CONFIG = None
GAIA_READ_URL = None
GAIA_WRITE_URL = None
GAIA_PORT = None

SUBDOMAIN_REGISTRAR_URL = 'http://{}:{}'.format(IP_ADDRESS, SUBDOMAIN_REGISTRAR_PORT)
TRANSACTION_BROADCASTER_URL = None

SERVER_THREAD = None

def attrs(**kw):
    for k in kw:
        assert '"' not in kw[k]

    kwstr = " ".join('{}="{}"'.format(k.strip('_'), kw[k]) for k in kw)
    return kwstr

def table(body, **kw):
    kwstr = attrs(**kw)
    return "<table {}>{}</table>".format(kwstr, body)

def tr(body, **kw):
    kwstr = attrs(**kw)
    return "<tr {}>{}</tr>".format(kwstr, body)

def td(body, **kw):
    kwstr = attrs(**kw)
    return "<td {}>{}</td>".format(kwstr, body)

def div(body, **kw):
    kwstr = attrs(**kw)
    return "<div {}>{}</div>".format(kwstr, body)

def span(body, **kw):
    kwstr = attrs(**kw)
    return "<span {}>{}</span>".format(kwstr, body)

def ol(body, **kw):
    kwstr = attrs(**kw)
    return '<ol {}>{}</ol>'.format(kwstr)

def li(body, **kw):
    kwstr = attrs(**kw)
    return '<li {}>{}</li>'.format(kwstr)

def form(action, method, body, **kw):
    kwstr = attrs(**kw)
    return '<form action="{}" method="{}" {}>{}</form>'.format(action, method, kwstr, body)

def textinput(name, default):
    return '<input type="text" name="{}" default="{}"/>'

def submit(value):
    assert '"' not in value
    return '<input type="submit", value="{}"/>'.format(value)

SCRIPTS_LIB = """
function makeHttpObject() {
  try {return new XMLHttpRequest();}
  catch (error) {}
  try {return new ActiveXObject("Msxml2.XMLHTTP");}
  catch (error) {}
  try {return new ActiveXObject("Microsoft.XMLHTTP");}
  catch (error) {}

  throw new Error("Could not create HTTP request object.");
}

function formatCode(body) {
   return "<div class=\\"code\\" align=\\"left\\">" + body + "</div>";
}

function formatNotGiven(body) {
   return "<div class=\\"not-given\\" align=\\"left\\">" + body + "</div>";
}

function makeOperationsTable(operations) {
   var tableData = "<table width=\\"100%\\">"
   for (var i = 0; i < operations.length; i++) {
      var txid = operations[i].txid;
      var opcode = operations[i].opcode;
      var address = operations[i].address;
      var name = operations[i].name;
      var op_fee = operations[i].op_fee;
      var token_fee = operations[i].token_fee;
      var namespace_id = operations[i].namespace_id;

      if (!token_fee) {
        token_fee = formatNotGiven("(no Stacks fee)");
      }
      else {
        token_fee = formatCode("uStacks: " + token_fee);
      }

      if (!op_fee) {
        op_fee = formatNotGiven("(no BTC fee)");
      }
      else {
        op_fee = formatCode("satoshis: " + op_fee);
      } 

      if (!name) {
        name = formatNotGiven("(no name)");
      }
      else {
        name = formatCode(name);
      }

      if (!namespace_id) {
        namespace_id = formatNotGiven("(no namespace)");
      }
      else {
        namespace_id = formatCode(namespace_id);
      }

      tableData += "<tr>";
      tableData += "<td>" + name + "</td>";
      tableData += "<td>" + namespace_id + "</td>";
      tableData += "<td>" + op_fee + "</td>";
      tableData += "<td>" + token_fee + "</td>";
      tableData += "</tr><tr>"
      tableData += "<td>" + formatCode(opcode) + "</td>";
      tableData += "<td>" + formatCode(address) + "</td>";
      tableData += "<td>" + formatCode(txid) + "</td>";
      tableData += "</tr>";
      tableData += "<tr><td colspan=\\"4\\"><hr/></td></tr>";
    }
    if (operations.length == 0) {
       tableData += "<tr><td colspan=\\"4\\">" + formatNotGiven("(no Blockstack transactions)") + "</tr>";
    }

    tableData += "</table>"
    return tableData;
}

function makeAtlasNeighborsTable(neighbors) {
   var tableData = "<table width=\\"100%\\">"
   for (var i = 0; i < neighbors.length; i++) {
      var atlasHost = neighbors[i].host;
      var atlasPort = neighbors[i].port;
      
      tableData += "<tr>";
      tableData += "<td>" + formatCode(atlasHost + ":" + atlasPort) + "<td>";
      tableData += "</tr>";
    }
    if (neighbors.length == 0) {
      tableData += "<tr><td colspan=\\"2\\">" + formatNotGiven("(no neighbor peers)") + "</tr>";
    }
    tableData += "</table>";
    return tableData;
}

function getBlockHeight() {
    var blockHeightRequest = makeHttpObject();
    blockHeightRequest.open("GET", "/blockHeight", true);
    blockHeightRequest.send(null);
    blockHeightRequest.onreadystatechange = function() {
        if (blockHeightRequest.readyState == 4) {
            var blockInfo = JSON.parse(blockHeightRequest.responseText);
            var blockHeight = blockInfo.blockHeight;
            var consensusHash = blockInfo.consensusHash;
            
            var blockHeightElem = document.getElementById("blockHeight");
            blockHeightElem.innerHTML = blockHeight;

            var chElem = document.getElementById("consensusHash");
            chElem.innerHTML = consensusHash;
        }
    }
}

function getBlockchainOperations() {
    var operationsRequest = makeHttpObject();
    operationsRequest.open("GET", "/operations");
    operationsRequest.send(null);
    operationsRequest.onreadystatechange = function() {
        if (operationsRequest.readyState == 4) {
            var operations = JSON.parse(operationsRequest.responseText);
            var operationsElem = document.getElementById("lastOperations");
            operationsElem.innerHTML = makeOperationsTable(operations);
        }
    }
}

function getAtlasNeighbors() {
    var atlasNeighborsRequest = makeHttpObject();
    atlasNeighborsRequest.open("GET", "/atlas-neighbors");
    atlasNeighborsRequest.send(null);
    atlasNeighborsRequest.onreadystatechange = function() {
        if (atlasNeighborsRequest.readyState == 4) {
            var neighbors = JSON.parse(atlasNeighborsRequest.responseText);
            var neighborsElem = document.getElementById("atlasNeighbors");
            neighborsElem.innerHTML = makeAtlasNeighborsTable(neighbors);
        }
    }
}

function loadStats() {
    getBlockHeight();
    getBlockchainOperations();
    getAtlasNeighbors();
}

window.setInterval(loadStats, 15000);
"""

CSS = ""
CSS += "body { text-align: center; } "
CSS += "table { border-collapse: separate; border-spacing: 6pt; border-style: hidden hidden; } "
CSS += ".code { font-family: monospace; line-height: 100%; } " 
CSS += ".leftcolumn { float: left; width: 40%; } "
CSS += ".rightcolumn { float: left; width: 60%; } "
CSS += ".row:after { content; \"\"; display: table; clear: both; } "
CSS += ".table { display: table; border-collapse: separate; border-spacing: 6pt; } "
CSS += "DIV.table { display: table; } "
CSS += "FORM.tr, DIV.tr { display: table-row; } "
CSS += "SPAN.td { display: table-cell; } "
CSS += ".not-given { font-style: italic; color: rgb(128,128,128); } "

class TestnetRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """
    testnet front-end server
    TODO: replace with Flask app or something
    """

    def do_GET(self):
        if self.path == '/blockHeight':
            ret = self.server.get_cached_chain_tip()
            ret = json.dumps(ret)
            self.send_response(200)
            self.send_header('content-type', 'application/json')
            self.send_header('content-length', len(ret))
            self.send_header('cache-control', 'max-age=30')
            self.end_headers()
            self.wfile.write(ret)
            return

        if self.path == "/operations":
            ret = self.server.get_cached_last_block()
            ret = json.dumps(ret)

            self.send_response(200)
            self.send_header('content-type', 'application/json')
            self.send_header('content-length', len(ret))
            self.send_header('cache-control', 'max-age=30')
            self.end_headers()
            self.wfile.write(ret)
            return

        if self.path == "/atlas-neighbors":
            ret = self.server.get_cached_atlas_neighbors()
            ret = json.dumps(ret)

            self.send_response(200)
            self.send_header('content-type', 'application/json')
            self.send_header('content-length', len(ret))
            self.send_header('cache-control', 'max-age=30')
            self.end_headers()
            self.wfile.write(ret)
            return

        # UI
        blockheight = testlib.get_current_block()
        consensus_hash = testlib.get_consensus_at(blockheight);

        url_set = table(
                    tr(td(div("Blockckchain Height:", align="right")) + td(div("{}".format(blockheight), align="left", _class="code", _id="blockHeight"))) +
                    tr(td(div("Consensus Hash:", align="right")) + td(div("{}".format(consensus_hash), align="left", _class="code", _id="consensusHash"))) +
                    tr(td(div("Gaia read URL:", align="right")) + td(div(GAIA_READ_URL, align="left", _class="code"))) +
                    tr(td(div("Gaia write URL:", align="right")) + td(div(GAIA_WRITE_URL, align="left", _class="code"))) + 
                    tr(td(div("Subdomain registrar:", align="right")) + td(div(SUBDOMAIN_REGISTRAR_URL, align="left", _class="code"))) +
                    tr(td(div("Transaction broadcaster:", align="right")) + td(div(TRANSACTION_BROADCASTER_URL, align="left", _class="code"))) +
                    tr(td(div("Bitcoin JSON-RPC:", align="right")) + td(div("http://{}:18332".format(IP_ADDRESS), align="left", _class="code"))) + 
                    tr(td(div("Bitcoin P2P:", align="right")) + td(div("http://{}:18444".format(IP_ADDRESS), align="left", _class="code"))),
                 width="100%")

        fund_form = div(
                        form("/sendBTC", "POST",
                            span("Address: ", align="right", _class="td") + span(textinput("addr", ""), _class="td") + span("Satoshis: ", align="right", _class="td") + span(textinput("value", "0"), _class="td") + span(submit("Fund address"), _class="td"),
                        _class="tr") +
                        "<br>" +
                        form("/sendStacks", "POST",
                            span("Address: ", align="right", _class="td") + span(textinput("addr", ""), _class="td") + span("microStacks: ", align="right", _class="td") + span(textinput("value", "0"), _class="td") + span(submit("Fund address"), _class="td"),
                        _class="tr"),
                    _class="table")

        left_column = div(
                "<h2>Services</h2>" + 
                div(url_set) + 
                "<br>" + 
                "<h2>Faucet</h2>" + 
                div(fund_form) + "<br>", _class="leftcolumn")

        blockchain_operations = div("loading...", _id="lastOperations")

        atlas_neighbors = div("loading...", _id="atlasNeighbors")

        right_column = div(
                "<h2>Last Block</h2>" +
                div(blockchain_operations) +
                "<br>" +
                "<h2>Testnet Peers</h2>" +
                div(atlas_neighbors),
                _class="rightcolumn")

        panel = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">'
        panel += '<html><head></head><title>Stacks Token Testnet</title><style>{}</style><body><h1>Stacks Token Testnet</h1><br>'.format(CSS)
        panel += '<br>'

        panel += div(left_column + right_column, _class="row")

        random_owner_key = virtualchain.lib.ecdsalib.ecdsa_private_key().to_hex()
        random_payment_key = virtualchain.lib.ecdsalib.ecdsa_private_key().to_hex()
        random_recipient_key = virtualchain.lib.ecdsalib.ecdsa_private_key().to_hex()
        random_recipient_address = virtualchain.address_reencode(virtualchain.get_privkey_address(random_recipient_key), network='testnet')

        panel += div("<hr/><h2 align='left'>Example Usage</h2>" + "<br>" +
                    div(
                        div(
                            span("Owner private key: ", _class="td", align='left') + 
                            span(div(random_owner_key + ' (address: {})'.format(virtualchain.address_reencode(virtualchain.get_privkey_address(random_owner_key), network='testnet')), _class="code", align="left"), _class="td"),
                        _class="tr") +
                        div(
                            span("Payment private key: ", _class="td", align='left') + 
                            span(div(random_payment_key + ' (address: {})'.format(virtualchain.address_reencode(virtualchain.get_privkey_address(random_payment_key), network='testnet')), _class="code", align='left'), _class="td"),
                        _class="tr") + 
                        div(
                            span("Recipient private key: ", _class="td", align='left') + 
                            span(div(random_recipient_key + ' (address: {})'.format(virtualchain.address_reencode(virtualchain.get_privkey_address(random_recipient_key), network='testnet')), _class="code", align='left'), _class="td"), 
                        _class="tr") +
                        div(
                            span("Install blockstack.js with Stacks tokens:", align="left", _class="td") +
                            span(div("$ git clone https://github.com/blockstack/blockstack.js && cd blockstack.js && git checkout feature/stacks-transactions && npm install && npm run build && sudo npm link", _class="code", align="left"), _class="td"),
                        _class="tr") +
                        div(
                            span("Install the Node.js CLI:", align="left", _class="td") + 
                            span(div("$ git clone https://github.com/jcnelson/cli-blockstack && cd cli-blockstack && npm install && npm link blockstack && npm run build && sudo npm install -g", _class="code", align='left'), _class="td"),
                         _class="tr") +
                        div(
                            span("Install Blockstack Core with Stacks tokens:", align="left", _class="td") + 
                            span(div("$ git clone https://github.com/blockstack/blockstack-core && cd cli-blockstack && git checkout feature/token-v1 && ./setup.py build && sudo ./setup.py install", _class="code", align='left'), _class="td"),
                         _class="tr") +
                        div(
                            span("Register a name:", align="left", _class="td") + 
                            span(div("$ blockstack-cli -t register hello.id {} {} \"{}\"".format(random_owner_key, random_payment_key, GAIA_READ_URL), _class="code", align='left'), _class="td"),
                        _class="tr") +
                        div(
                            span("Register a subdomain:", align="left", _class="td") + 
                            span(div("$ blockstack-cli -t register_subdomain hello.personal.id {} \"{}\" \"{}\"".format(random_owner_key, GAIA_READ_URL, SUBDOMAIN_REGISTRAR_URL), align='left', _class="code"), _class="td"),
                        _class="tr") +
                        div(
                            span("Send Stacks tokens:", align="left", _class="td") + 
                            span(div("$ blockstack-cli send_tokens {} STACKS 100000 {}".format(random_recipient_address, random_payment_key), _class="code", align='left'), _class="td"),
                        _class="tr"),
                    _class="table"),
                )

        panel += "<script>" + SCRIPTS_LIB + "</script>"

        panel += "</body></html>"

        self.send_response(200)
        self.send_header('content-type', 'text/html')
        self.send_header('content-length', len(panel))
        self.send_header('cache-control', 'max-age=30')
        self.end_headers()
        self.wfile.write(panel)
        return


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

            self.send_response(302)
            self.send_header('location', '/')
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

            try:
                value = int(value[0])
                addr = virtualchain.address_reencode(addr[0])
            except:
                log.error("Failed to read addr and/or value")
                log.error("postvars = {}".format(postvars))
                self.error_page(400, "Invalid addr or value")
                self.end_headers()
                return

            # don't take too much
            if value > 1000000000:
                log.error('{} requested too much ({})'.format(addr, value))
                self.error_page(400, 'Requested too much BTC (at most {} is allowed)'.format(1000000000))
                self.end_headers()
                return 

            # send funds
            res = None
            try:
                res = testlib.blockstack_send_tokens(addr, 'STACKS', value, wallets[3].privkey)
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
            self.send_header('location', '/')
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


def start_subdomain_registrar():
    global SUBDOMAIN_PROC
    global SUBDOMAIN_REGISTRAR_CONFIG
    global GAIA_READ_URL
    global GAIA_PORT
    global GAIA_WRITE_URL

    # get gaia hub info 
    with open(os.path.join(os.environ['BLOCKSTACK_WORKING_DIR'], 'gaia.conf'), 'r') as f:
        GAIA_CONF = json.loads(f.read().strip())

    GAIA_READ_URL = 'http://{}:{}'.format(IP_ADDRESS, urlparse.urlparse(GAIA_CONF['readURL']).netloc.split(':')[-1])
    GAIA_PORT = GAIA_CONF['port']
    GAIA_WRITE_URL = 'http://{}:{}'.format(IP_ADDRESS, GAIA_PORT)

    # send batches every 30 seconds
    # check transactions every second
    SUBDOMAIN_REGISTRAR_CONFIG = """
    {
      "winstonConsoleTransport": {
          "level": "debug",
          "handleExceptions": false,
          "timestamp": true,
          "stringify": true,
          "colorize": true,
          "json": false
      },
      "domainName": "%s",
      "ownerKey": "%s",
      "paymentKey": "%s",
      "batchDelayPeriod": 0.5,
      "checkTransactionPeriod": 0.5,
      "dbLocation": "%s/subdomain_registrar.db",
      "adminPassword": "%s",
      "domainUri": "%s/%s/profile.json",
      "zonefileSize": 40960,
      "development": false,
      "port": %s,
      "regtest": true,
      "ipLimit": 0,
      "apiKeys": [],
      "proofsRequired": 0,
      "disableRegistrationsWithoutKey": false
    }
    """ % (SUBDOMAIN_DOMAIN, SUBDOMAIN_OWNER_KEY, SUBDOMAIN_PAYMENT_KEY, os.environ['BLOCKSTACK_WORKING_DIR'], SUBDOMAIN_ADMIN_PASSWORD, GAIA_READ_URL, SUBDOMAIN_OWNER_ADDRESS, SUBDOMAIN_REGISTRAR_PORT)

    subdomain_registrar_config_path = os.path.join(os.environ['BLOCKSTACK_WORKING_DIR'], 'subdomain-registrar.conf')
    with open(subdomain_registrar_config_path, 'w') as f:
        f.write(SUBDOMAIN_REGISTRAR_CONFIG.strip())

    subdomain_log_path = os.path.join(os.environ['BLOCKSTACK_WORKING_DIR'], 'subdomain-registrar.log')
    subdomain_stdout = open(subdomain_log_path, 'w')
    subdomain_stderr = open(subdomain_log_path, 'w')

    os.environ['BSK_SUBDOMAIN_CONFIG'] = subdomain_registrar_config_path 
    SUBDOMAIN_PROC = subprocess.Popen('blockstack-subdomain-registrar start personal.id', shell=True, stdout=subdomain_stdout, stderr=subdomain_stderr)

    testlib.add_cleanup(stop_subdomain_registrar)


def stop_subdomain_registrar():
    global SUBDOMAIN_PROC
    print 'kill subdomain registrar'

    try:
        if SUBDOMAIN_PROC is not None:
            SUBDOMAIN_PROC.kill()
            SUBDOMAIN_PROC = None

    except:
        traceback.print_exc()
        pass


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

    TRANSACTION_BROADCASTER_URL = 'http://{}:{}'.format(IP_ADDRESS, tb_conf['port'])

    PORTNUM = int(os.environ.get('TESTNET_PORTNUM', '30001'))
    start_test_server(PORTNUM)

    testlib.blockstack_namespace_preorder( "id", wallets[1].addr, wallets[0].privkey )
    testlib.next_block( **kw )

    # same price curve as public .id namespace
    testlib.blockstack_namespace_reveal( "id", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey, version_bits=3)
    testlib.next_block( **kw )

    testlib.blockstack_namespace_ready( "id", wallets[1].privkey )
    testlib.next_block( **kw )

    testlib.blockstack_register_user(SUBDOMAIN_DOMAIN, SUBDOMAIN_PAYMENT_KEY, SUBDOMAIN_OWNER_KEY, **kw)

    start_subdomain_registrar()

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
