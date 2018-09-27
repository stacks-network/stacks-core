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
import sys
import signal
import json
import traceback
import time
import socket
import math
import random
import shutil
import binascii
import atexit
import threading
import errno
import blockstack_zones
import keylib
import base64
import gc
import argparse
import jsonschema
from jsonschema import ValidationError
import BaseHTTPServer

import xmlrpclib
from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
import SocketServer


import virtualchain
from virtualchain.lib.hashing import *

log = virtualchain.get_logger("blockstack-core")

from lib import get_db_state
from lib.client import BlockstackRPCClient
from lib.client import ping as blockstack_ping
from lib.client import OP_HEX_PATTERN, OP_CONSENSUS_HASH_PATTERN, OP_ADDRESS_PATTERN, OP_BASE64_EMPTY_PATTERN
from lib.config import REINDEX_FREQUENCY, BLOCKSTACK_TEST, default_bitcoind_opts, is_subdomains_enabled
from lib.util import url_to_host_port, atlas_inventory_to_string, daemonize, make_DID, parse_DID, BoundedThreadingMixIn, GCThread
from lib import *
from lib.storage import *
from lib.atlas import *
from lib.fast_sync import *
from lib.rpc import BlockstackAPIEndpoint
from lib.subdomains import (subdomains_init, SubdomainNotFound, get_subdomain_info, get_subdomain_history,
                            get_DID_subdomain, get_subdomains_owned_by_address, get_subdomain_DID_info,
                            get_all_subdomains, get_subdomains_count, get_subdomain_resolver, is_subdomain_zonefile_hash)

import lib.nameset.virtualchain_hooks as virtualchain_hooks
import lib.config as config

# stop common XML attacks
from defusedxml import xmlrpc
xmlrpc.MAX_DATA = MAX_RPC_LEN
xmlrpc.monkey_patch()

# global variables, for use with the RPC server
bitcoind = None
rpc_server = None
api_server = None
gc_thread = None


def get_bitcoind(new_bitcoind_opts=None, reset=False, new=False):
   """
   Get or instantiate our bitcoind client.
   Optionally re-set the bitcoind options.
   """
   global bitcoind

   if reset:
       bitcoind = None

   elif not new and bitcoind is not None:
      return bitcoind

   if new or bitcoind is None:
      if new_bitcoind_opts is not None:
         set_bitcoin_opts( new_bitcoind_opts )

      bitcoin_opts = get_bitcoin_opts()
      new_bitcoind = None
      try:

         try:
             new_bitcoind = virtualchain.connect_bitcoind( bitcoin_opts )
         except KeyError, ke:
             log.exception(ke)
             log.error("Invalid configuration: %s" % bitcoin_opts)
             return None

         if new:
             return new_bitcoind

         else:
             # save for subsequent reuse
             bitcoind = new_bitcoind
             return bitcoind

      except Exception, e:
         log.exception( e )
         return None


def get_pidfile_path(working_dir):
   """
   Get the PID file path.
   """
   pid_filename = virtualchain_hooks.get_virtual_chain_name() + ".pid"
   return os.path.join( working_dir, pid_filename )


def put_pidfile( pidfile_path, pid ):
    """
    Put a PID into a pidfile
    """
    with open( pidfile_path, "w" ) as f:
        f.write("%s" % pid)
        os.fsync(f.fileno())

    return


def get_logfile_path(working_dir):
   """
   Get the logfile path for our service endpoint.
   """
   logfile_filename = virtualchain_hooks.get_virtual_chain_name() + ".log"
   return os.path.join( working_dir, logfile_filename )


def get_index_range(working_dir):
    """
    Get the bitcoin block index range.
    Mask connection failures with timeouts.
    Always try to reconnect.

    The last block will be the last block to search for names.
    This will be NUM_CONFIRMATIONS behind the actual last-block the
    cryptocurrency node knows about.
    """

    bitcoind_session = get_bitcoind(new=True)
    assert bitcoind_session is not None

    first_block = None
    last_block = None
    wait = 1.0
    while last_block is None and is_running():

        first_block, last_block = virtualchain.get_index_range('bitcoin', bitcoind_session, virtualchain_hooks, working_dir)

        if first_block is None or last_block is None:

            # try to reconnnect
            log.error("Reconnect to bitcoind in {} seconds".format(wait))
            time.sleep(wait)
            wait = min(wait * 2.0 + random.random() * wait, 60)

            bitcoind_session = get_bitcoind( new=True )
            continue

        else:
            return first_block, last_block - NUM_CONFIRMATIONS

    return None, None


def rpc_traceback():
    exception_data = traceback.format_exc().splitlines()
    return {
        "error": exception_data[-1],
        "traceback": exception_data
    }


def get_name_cost( db, name ):
    """
    Get the cost of a name, given the fully-qualified name.
    Do so by finding the namespace it belongs to (even if the namespace is being imported).

    Return {'amount': ..., 'units': ...} on success
    Return None if the namespace has not been declared
    """
    lastblock = db.lastblock
    namespace_id = get_namespace_from_name( name )
    if namespace_id is None or len(namespace_id) == 0:
        log.debug("No namespace '%s'" % namespace_id)
        return None

    namespace = db.get_namespace( namespace_id )
    if namespace is None:
        # maybe importing?
        log.debug("Namespace '{}' is being revealed".format(namespace_id))
        namespace = db.get_namespace_reveal( namespace_id )

    if namespace is None:
        # no such namespace
        log.debug("No namespace '%s'" % namespace_id)
        return None

    name_fee = price_name( get_name_from_fq_name( name ), namespace, lastblock )
    name_fee_units = 'BTC'

    name_fee = int(math.ceil(name_fee))
    log.debug("Cost of '%s' at %s is %s %s" % (name, lastblock, name_fee, name_fee_units))

    return {'amount': name_fee, 'units': name_fee_units}


def get_namespace_cost( db, namespace_id ):
    """
    Get the cost of a namespace.
    Returns {'amount': ..., 'units': ..., 'namespace': ...}
    """
    lastblock = db.lastblock
    namespace_fee = price_namespace( namespace_id, lastblock )
    
    # namespace might exist
    namespace = db.get_namespace( namespace_id )
    namespace_fee = int(math.ceil(namespace_fee))

    return {'amount': namespace_fee, 'units': 'BTC', 'namespace': namespace}


class BlockstackdRPCHandler(SimpleXMLRPCRequestHandler):
    """
    Dispatcher to properly instrument calls and do
    proper deserialization and request-size limiting.
    """

    MAX_REQUEST_SIZE = 512 * 1024   # 500KB

    def do_POST(self):
        """
        Based on the original, available at https://github.com/python/cpython/blob/2.7/Lib/SimpleXMLRPCServer.py

        Only difference is that it denies requests bigger than a certain size.

        Handles the HTTP POST request.
        Attempts to interpret all HTTP POST requests as XML-RPC calls,
        which are forwarded to the server's _dispatch method for handling.
        """

        # Check that the path is legal
        if not self.is_rpc_path_valid():
            self.report_404()
            return

        # reject gzip, so size-caps will work
        encoding = self.headers.get("content-encoding", "identity").lower()
        if encoding != 'identity':
            log.error("Reject request with encoding '{}'".format(encoding))
            self.send_response(501, "encoding %r not supported" % encoding)
            return

        try:
            size_remaining = int(self.headers["content-length"])
            if size_remaining > self.MAX_REQUEST_SIZE:
                if os.environ.get("BLOCKSTACK_DEBUG") == "1":
                    log.error("Request is too big!")

                self.send_response(400)
                self.send_header('Content-length', '0')
                self.end_headers()
                return

            if os.environ.get("BLOCKSTACK_DEBUG") == "1":
                log.debug("Message is small enough to parse ({} bytes)".format(size_remaining))

            # Get arguments by reading body of request.
            # never read more than our max size
            L = []
            while size_remaining:
                chunk_size = min(size_remaining, self.MAX_REQUEST_SIZE)
                chunk = self.rfile.read(chunk_size)
                if not chunk:
                    break
                L.append(chunk)
                size_remaining -= len(L[-1])

            data = ''.join(L)

            data = self.decode_request_content(data)
            if data is None:
                return #response has been sent

            # In previous versions of SimpleXMLRPCServer, _dispatch
            # could be overridden in this class, instead of in
            # SimpleXMLRPCDispatcher. To maintain backwards compatibility,
            # check to see if a subclass implements _dispatch and dispatch
            # using that method if present.
            response = self.server._marshaled_dispatch(
                    data, getattr(self, '_dispatch', None), self.path
                )

        except Exception, e: # This should only happen if the module is buggy
            # internal error, report as HTTP server error
            self.send_response(500)
            self.send_header("Content-length", "0")
            self.end_headers()

        else:
            # got a valid XML RPC response
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            if self.encode_threshold is not None:
                if len(response) > self.encode_threshold:
                    q = self.accept_encodings().get("gzip", 0)
                    if q:
                        try:
                            response = xmlrpclib.gzip_encode(response)
                            self.send_header("Content-Encoding", "gzip")
                        except NotImplementedError:
                            pass

            self.send_header("Content-length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)


    def _dispatch(self, method, params):
        global gc_thread
        gc_thread.gc_event()

        try:
            con_info = {
                "client_host": self.client_address[0],
                "client_port": RPC_SERVER_PORT
            }

            params_fmt = ','.join(str(p) for p in params)
            if len(params_fmt) > 100:
                params_fmt = params_fmt[:100] + '...'

            # if this is running as part of the atlas network simulator,
            # then for methods whose first argument is 'atlas_network', then
            # the second argument is always the simulated client host/port
            # (for atlas-specific methods)
            if os.environ.get("BLOCKSTACK_ATLAS_NETWORK_SIMULATION", None) == "1" and len(params) > 0 and params[0] == 'atlas_network':

                client_hostport = params[1]
                params = params[3:]
                params_fmt = ','.join(str(p) for p in params)
                if len(params_fmt) > 100:
                    params_fmt = params_fmt[:100] + '...'

                log.debug("Reformatting '%s(%s)' as atlas network simulator call" % (method, params_fmt))

                con_info = {}

                if client_hostport is not None:
                    client_host, client_port = url_to_host_port( client_hostport )
                    con_info = {
                        "client_host": client_host,
                        "client_port": client_port
                    }

                else:
                    con_info = {
                        "client_host": "",
                        "client_port": 0
                    }

                log.debug("Inbound RPC begin %s(%s) (from atlas simulator)" % ("rpc_" + str(method), params))

            else:
                if os.environ.get("BLOCKSTACK_ATLAS_NETWORK_SIMULATION", None) == "1":
                    log.debug("Inbound RPC begin %s(%s) from %s" % ("rpc_" + str(method), params_fmt, self.client_address[0]))
                else:
                    log.debug("RPC %s(%s) begin from %s" % ("rpc_" + str(method), params_fmt, self.client_address[0]))

            res = None
            with self.server.rpc_guard:
                # RPC calls should be sequential to ensure database integrity 
                if BLOCKSTACK_TEST:
                    log.debug('RPC thread enter {}'.format(threading.current_thread().ident))

                res = self.server.funcs["rpc_" + str(method)](*params, **con_info)

                if BLOCKSTACK_TEST:
                    log.debug('RPC thread exit {}'.format(threading.current_thread().ident))

            if 'deprecated' in res and res['deprecated']:
                log.warn("DEPRECATED method call {} from {}".format(method, self.client_address[0]))

            # lol jsonrpc within xmlrpc
            ret = json.dumps(res)

            if os.environ.get("BLOCKSTACK_ATLAS_NETWORK_SIMULATION", None) == "1":
                log.debug("Inbound RPC end %s(%s) from %s" % ("rpc_" + str(method), params_fmt, self.client_address[0]))
            else:
                log.debug("RPC %s(%s) end from %s" % ("rpc_" + str(method), params_fmt, self.client_address[0]))

            return ret
        except Exception, e:
            print >> sys.stderr, "\n\n%s(%s)\n%s\n\n" % ("rpc_" + str(method), params_fmt, traceback.format_exc())
            return json.dumps(rpc_traceback())



class BlockstackdRPC(BoundedThreadingMixIn, SimpleXMLRPCServer):
    """
    Blockstackd RPC server, used for querying
    the name database and the blockchain peer.

    Methods that start with rpc_* will be registered
    as RPC methods.
    """

    def __init__(self, working_dir, host='0.0.0.0', port=config.RPC_SERVER_PORT, subdomain_index=None, handler=BlockstackdRPCHandler ):
        log.info("Serving database state from {}".format(working_dir))
        log.info("Listening on %s:%s" % (host, port))
        SimpleXMLRPCServer.__init__( self, (host, port), handler, allow_none=True )
        
        self.working_dir = working_dir

        # register methods
        for attr in dir(self):
            if attr.startswith("rpc_"):
                method = getattr(self, attr)
                if callable(method) or hasattr(method, '__call__'):
                    self.register_function( method )
        
        # cache bitcoind info until we reindex, or a blocktime has passed
        self.cache = {}

        # remember how long ago we reached the given block height
        self.last_indexing_time = time.time()

        # subdomain indexer handle
        self.subdomain_index = subdomain_index

        self.rpc_guard = threading.Lock()

    
    def cache_flush(self):
        """
        Clear all cached state
        """
        self.cache = {}


    def set_last_index_time(self, timestamp):
        """
        Set the time of last indexing.
        Called by the indexing thread.
        """
        self.last_indexing_time = timestamp


    def is_stale(self):
        """
        Are we behind the chain?
        """
        return self.last_indexing_time + RPC_MAX_INDEXING_DELAY < time.time()

    
    def overloaded(self, client_address):
        """
        Got too many requests.
        Send back a (precompiled) XMLRPC response saying as much
        """
        body = {
            'status': False,
            'indexing': False,
            'lastblock': -1,
            'error': 'overloaded',
            'http_status': 429
        }
        body_str = json.dumps(body)

        resp = 'HTTP/1.0 200 OK\r\nServer: BaseHTTP/0.3 Python/2.7.14+\r\nContent-type: text/xml\r\nContent-length: {}\r\n\r\n'.format(len(body_str))
        resp += '<methodResponse><params><param><value><string>{}</string></value></param></params></methodResponse>'.format(body_str)
        return resp


    def success_response(self, method_resp, **kw):
        """
        Make a standard "success" response,
        which contains some ancilliary data.

        Also, detect if this node is too far behind the Bitcoin blockchain,
        and if so, convert this into an error message.
        """
        resp = {
            'status': True,
            'indexing': config.is_indexing(self.working_dir),
            'lastblock': virtualchain_hooks.get_last_block(self.working_dir),
        }

        resp.update(kw)
        resp.update(method_resp)
        
        if self.is_stale():
            # our state is stale
            resp['stale'] = True
            resp['warning'] = 'Daemon has not reindexed since {}'.format(self.last_indexing_time)

        return resp


    def sanitize_rec(self, rec):
        """
        sanitize a name/namespace record before returning it.
        * canonicalize it
        * remove quirk fields
        """
        opcode = rec['opcode']
        canonical_op = op_canonicalize(opcode, rec)

        # don't return internally-used quirk fields
        quirk_fields = op_get_quirk_fields(opcode)
        for f in quirk_fields:
            if f in canonical_op:
                del canonical_op[f]

        canonical_op['opcode'] = opcode
        return canonical_op


    def rpc_ping(self, **con_info):
        reply = {}
        reply['status'] = "alive"
        reply['version'] = VERSION
       
        if self.is_stale():
            reply['status'] = "stale"
            
        return reply
    

    def load_name_info(self, db, name_record):
        """
        Get some extra name information, given a db-loaded name record.
        Return the updated name_record
        """
        name = str(name_record['name'])
        name_record = self.sanitize_rec(name_record)

        namespace_id = get_namespace_from_name(name)
        namespace_record = db.get_namespace(namespace_id, include_history=False)
        if namespace_record is None:
            namespace_record = db.get_namespace_reveal(namespace_id, include_history=False)

        if namespace_record is None:
            # name can't exist (this can be arrived at if we're resolving a DID)
            return None

        # when does this name expire (if it expires)?
        if namespace_record['lifetime'] != NAMESPACE_LIFE_INFINITE:
            deadlines = BlockstackDB.get_name_deadlines(name_record, namespace_record, db.lastblock)
            if deadlines is not None:
                name_record['expire_block'] = deadlines['expire_block']
                name_record['renewal_deadline'] = deadlines['renewal_deadline']
            else:
                # only possible if namespace is not yet ready
                name_record['expire_block'] = -1
                name_record['renewal_deadline'] = -1

        else:
            name_record['expire_block'] = -1
            name_record['renewal_deadline'] = -1

        if name_record['expire_block'] > 0 and name_record['expire_block'] <= db.lastblock:
            name_record['expired'] = True
        else:
            name_record['expired'] = False

        # try to get the zonefile as well 
        if 'value_hash' in name_record and name_record['value_hash'] is not None:
            conf = get_blockstack_opts()
            if is_atlas_enabled(conf):
                zfdata = self.get_zonefile_data(name_record['value_hash'], conf['zonefiles'])
                if zfdata is not None:
                    zfdata = base64.b64encode(zfdata)
                    name_record['zonefile'] = zfdata

        return name_record


    def get_name_record(self, name, include_expired=False, include_history=False):
        """
        Get the whois-related info for a name (not a subdomain).
        Optionally include the history.
        Return {'status': True, 'record': rec} on success
        Return {'error': ...} on error
        """
        if not check_name(name):
            return {'error': 'invalid name', 'http_status': 400}
        
        name = str(name)

        db = get_db_state(self.working_dir)
        name_record = db.get_name(str(name), include_expired=include_expired, include_history=include_history)

        if name_record is None:
            db.close()
            return {"error": "Not found.", 'http_status': 404}

        else:
            assert 'opcode' in name_record, 'BUG: missing opcode in {}'.format(json.dumps(name_record, sort_keys=True))
            name_record = self.load_name_info(db, name_record)
            db.close()

            # also get the subdomain resolver 
            resolver = get_subdomain_resolver(name)
            name_record['resolver'] = resolver
            return {'status': True, 'record': name_record}


    def get_subdomain_record(self, fqn, include_history=False):
        """
        Get the whois-related info for a subdomain.
        Optionally include the history for the domain.
        Return {'status': True, 'record': rec} on success
        Return {'error': ...} on error
        """
        if not check_subdomain(fqn):
            return {'error': 'invalid subdomain', 'http_status': 400}
        
        fqn = str(fqn)

        # get current record
        subdomain_rec = get_subdomain_info(fqn, check_pending=True)
        if subdomain_rec is None:
            return {'error': 'Failed to load subdomain', 'http_status': 404}
   
        ret = subdomain_rec.to_json()
        if include_history:
            subdomain_hist = get_subdomain_history(fqn, json=True)
            ret['history'] = subdomain_hist

        return {'status': True, 'record': ret}


    def rpc_get_name_record(self, name, **con_info):
        """
        Get the curernt state of a name or subdomain, excluding its history.
        Return {'status': True, 'record': rec} on success
        Return {'error': ...} on error
        """
        res = None
        if check_name(name):
            res = self.get_name_record(name, include_expired=True, include_history=False)
        elif check_subdomain(name):
            res = self.get_subdomain_record(name, include_history=False)
        else:
            return {'error': 'Invalid name or subdomain', 'http_status': 400}

        if 'error' in res:
            return {'error': res['error'], 'http_status': 404}

        return self.success_response({'record': res['record']})


    def get_name_DID_info(self, name):
        """
        Get a name's DID info
        Returns None if not found
        """
        db = get_db_state(self.working_dir)
        did_info = db.get_name_DID_info(name)
        if did_info is None:
            return {'error': 'No such name', 'http_status': 404}

        return did_info


    def get_subdomain_DID_info(self, fqn):
        """
        Get a subdomain's DID info
        Returns None if not found
        """
        did_info = get_subdomain_DID_info(fqn)
        return did_info


    def rpc_get_name_DID(self, name, **con_info):
        """
        Given a name or subdomain, return its DID.
        """
        did_info = None
        if check_name(name):
            did_info = self.get_name_DID_info(name)
        elif check_subdomain(name):
            did_info = self.get_subdomain_DID_info(name)
        else:
            return {'error': 'Invalid name or subdomain', 'http_status': 400}

        if did_info is None:
            return {'error': 'No DID for this name', 'http_status': 404}

        did = make_DID(did_info['name_type'], did_info['address'], did_info['index'])
        return self.success_response({'did': did})


    def get_name_DID_record(self, did):
        """
        Given a DID for a name, return the name record.
        Return {'record': ...} on success
        Return {'error': ...} on error
        """
        try:
            did_info = parse_DID(did)
            assert did_info['name_type'] == 'name'
        except Exception as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            return {'error': 'Invalid DID', 'http_status': 400}

        db = get_db_state(self.working_dir)
        rec = db.get_DID_name(did)
        if rec is None:
            db.close()
            return {'error': 'Failed to resolve DID to a non-revoked name', 'http_status': 404}

        name_record = self.load_name_info(db, rec)
        db.close()

        if name_record is None:
            return {'error': 'DID does not resolve to an existing name', 'http_status': 404}

        return {'record': name_record}


    def get_subdomain_DID_record(self, did):
        """
        Given a DID for subdomain, get the subdomain record
        Return {'record': ...} on success
        Return {'error': ...} on error
        """
        try:
            did_info = parse_DID(did)
            assert did_info['name_type'] == 'subdomain'
        except Exception as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            return {'error': 'Invalid DID', 'http_status': 400}

        subrec = get_DID_subdomain(did, check_pending=True)
        if subrec is None:
            return {'error': 'Failed to load subdomain from {}'.format(did), 'http_status': 404}

        return {'record': subrec.to_json()}


    def rpc_get_DID_record(self, did, **con_info):
        """
        Given a DID, return the name or subdomain it corresponds to
        """
        if not isinstance(did, (str,unicode)):
            return {'error': 'Invalid DID: not a string', 'http_status': 400}

        try:
            did_info = parse_DID(did)
        except:
            return {'error': 'Invalid DID', 'http_status': 400}

        res = None
        if did_info['name_type'] == 'name':
            res = self.get_name_DID_record(did)
        elif did_info['name_type'] == 'subdomain':
            res = self.get_subdomain_DID_record(did)
        
        if 'error' in res:
            return {'error': res['error'], 'http_status': res.get('http_status', 404)}

        return self.success_response({'record': res['record']})


    def rpc_get_name_blockchain_record(self, name, **con_info):
        """
        Lookup all blockchain state for a name or subdomain, including its history.
        Return {'status': True, 'record': rec} on success
        Return {'error': ...} on error
        """
        res = None
        if check_name(name):
            res = self.get_name_record(name, include_expired=True, include_history=True)
        elif check_subdomain(name):
            res = self.get_subdomain_record(name, include_history=True)
        else:
            return {'error': 'Invalid name or subdomain', 'http_status': 400}

        if 'error' in res:
            return {'error': res['error'], 'http_status': res.get('http_status', 404)}

        return self.success_response({'record': res['record']})


    def rpc_get_name_history_page(self, name, page, **con_info):
        """
        Get the list of history entries for a name or subdomain's history, paginated.
        Small pages correspond to later history (page = 0 is the page of last updates)
        Page size is 20 rows.
        Return {'status': True, 'history': [...]} on success
        Return {'error': ...} on error
        """
        if not check_name(name) and not check_subdomain(name):
            return {'error': 'invalid name', 'http_status': 400}

        if not check_count(page):
            return {'error': 'invalid page', 'http_status': 400}

        offset = page * 20
        count = (page + 1) * 20
        history_data = None

        if check_name(name):
            # on-chain name
            db = get_db_state(self.working_dir)
            history_data = db.get_name_history(name, offset, count, reverse=True)
            db.close()

        else:
            # off-chain name
            history_data = get_subdomain_history(name, offset=offset, count=count, json=True, reverse=True)

        if len(history_data) == 0:
            # name didn't exist 
            return {'error': 'Not found', 'http_status': 404}

        return self.success_response({'history': history_data})
      

    def rpc_is_name_zonefile_hash(self, name, zonefile_hash, **con_info):
        """
        Was a zone file hash issued by a name?  Return {'result': True/False}
        """
        if not check_name(name) and not check_subdomain(name):
            return {'error': 'invalid name', 'http_status': 400}

        if not check_string(zonefile_hash, min_length=LENGTHS['value_hash']*2, max_length=LENGTHS['value_hash']*2, pattern=OP_HEX_PATTERN):
            return {'error': 'invalid zone file hash', 'http_status': 400}
        
        was_set = None
        if check_name(name):
            # on-chain name 
            db = get_db_state(self.working_dir)
            was_set = db.is_name_zonefile_hash(name, zonefile_hash)
            db.close()
        else:
            # off-chain name 
            was_set = is_subdomain_zonefile_hash(name, zonefile_hash)

        return self.success_response({'result': was_set})


    def rpc_get_name_at( self, name, block_height, **con_info ):
        """
        Get all the states the name was in at a particular block height.
        Does NOT work on expired names.
        Return {'status': true, 'record': ...}
        """
        if not check_name(name):
            return {'error': 'invalid name', 'http_status': 400}

        if not check_block(block_height):
            return self.success_response({'record': None})

        db = get_db_state(self.working_dir)
        names_at = db.get_name_at( name, block_height, include_expired=False )
        db.close()
        
        ret = []
        for name_rec in names_at:
            if 'opcode' not in name_rec:
                name_rec['opcode'] = op_get_opcode_name(name_rec['op'])
            
            ret.append(self.sanitize_rec(name_rec))

        return self.success_response( {'records': ret} )


    def rpc_get_historic_name_at( self, name, block_height, **con_info ):
        """
        Get all the states the name was in at a particular block height.
        Works on expired and unexpired names.
        Return {'status': true, 'record': ...}
        """
        if not check_name(name):
            return {'error': 'invalid name', 'http_status': 400}

        if not check_block(block_height):
            return self.success_response({'record': None})

        db = get_db_state(self.working_dir)
        names_at = db.get_name_at( name, block_height, include_expired=True )
        db.close()

        ret = []
        for name_rec in names_at:
            if 'opcode' not in name_rec:
                name_rec['opcode'] = op_get_opcode_name(name_rec['op'])

            ret.append(self.sanitize_rec(name_rec))

        return self.success_response( {'records': ret} )

    
    def rpc_get_num_blockstack_ops_at(self, block_id, **con_info):
        """
        Get the number of Blockstack transactions that occured at the given block.
        Returns {'count': ..} on success
        Returns {'error': ...} on error
        """
        if not check_block(block_id):
            return {'error': 'Invalid block height', 'http_status': 400}

        db = get_db_state(self.working_dir)
        count = db.get_num_blockstack_ops_at( block_id )
        db.close()

        log.debug("{} name operations at {}".format(count, block_id))
        return self.success_response({'count': count})


    def rpc_get_blockstack_ops_at(self, block_id, offset, count, **con_info):
        """
        Get the name operations that occured in the given block.

        Returns {'nameops': [...]} on success.
        Returns {'error': ...} on error
        """
        if not check_block(block_id):
            return {'error': 'Invalid block height', 'http_status': 400}

        if not check_offset(offset):
            return {'error': 'Invalid offset', 'http_status': 400}

        if not check_count(count, 10):
            return {'error': 'Invalid count', 'http_status': 400}

        db = get_db_state(self.working_dir)
        nameops = db.get_all_blockstack_ops_at(block_id, offset=offset, count=count)
        db.close()

        log.debug("{} name operations at block {}, offset {}, count {}".format(len(nameops), block_id, offset, count))
        ret = []
        
        for nameop in nameops:
            assert 'opcode' in nameop, 'BUG: missing opcode in {}'.format(json.dumps(nameop, sort_keys=True))
            canonical_op = self.sanitize_rec(nameop)
            ret.append(canonical_op)
        
        return self.success_response({'nameops': ret})


    def rpc_get_blockstack_ops_hash_at( self, block_id, **con_info ):
        """
        Get the hash over the sequence of names and namespaces altered at the given block.
        Used by SNV clients.

        Returns {'status': True, 'ops_hash': ops_hash} on success
        Returns {'error': ...} on error
        """
        if not check_block(block_id):
            return {'error': 'Invalid block height', 'http_status': 400}

        db = get_db_state(self.working_dir)
        ops_hash = db.get_block_ops_hash( block_id )
        db.close()

        return self.success_response( {'ops_hash': ops_hash} )


    def get_cached_bitcoind_info(self):
        """
        Get cached bitcoind info.
        Returns {...} on success
        Return None if it is stale
        """
        cached_bitcoind_info = self.cache.get('bitcoind_info', None)
        if cached_bitcoind_info is None:
            # not cached
            return None

        now = time.time()
        if cached_bitcoind_info['time'] + AVERAGE_SECONDS_PER_BLOCK < now:
            # stale
            return None

        return cached_bitcoind_info['getinfo']


    def set_cached_bitcoind_info(self, info):
        """
        Cache bitcoind info
        """
        self.cache['bitcoind_info'] = {'time': time.time(), 'getinfo': info}


    def get_cached_consensus_info(self):
        """
        Get cached consensus info.
        Returns {...} on success
        Return None if it is stale
        """
        cached_consensus_info = self.cache.get('consensus_info', None)
        if cached_consensus_info is None:
            # not cached
            return None

        now = time.time()
        if cached_consensus_info['time'] + AVERAGE_SECONDS_PER_BLOCK < now:
            # stale
            return None

        return cached_consensus_info['info']


    def set_cached_consensus_info(self, info):
        """
        Cache bitcoind info
        """
        self.cache['consensus_info'] = {'time': time.time(), 'info': info}


    def get_bitcoind_info(self):
        """
        Get bitcoind info.  Try the cache, and on cache miss, 
        fetch from bitcoind and cache.
        """
        cached_bitcoind_info = self.get_cached_bitcoind_info()
        if cached_bitcoind_info:
            return cached_bitcoind_info

        bitcoind_opts = default_bitcoind_opts( virtualchain.get_config_filename(virtualchain_hooks, self.working_dir), prefix=True )
        bitcoind = get_bitcoind( new_bitcoind_opts=bitcoind_opts, new=True )

        if bitcoind is None:
            return {'error': 'Internal server error: failed to connect to bitcoind'}
        
        try:
            info = bitcoind.getinfo()
            assert 'error' not in info
            assert 'blocks' in info

            self.set_cached_bitcoind_info(info)
            return info

        except Exception as e:
            raise
   

    def get_consensus_info(self):
        """
        Get block height and consensus hash.  Try the cache, and
        on cache miss, fetch from the db
        """
        cached_consensus_info = self.get_cached_consensus_info()
        if cached_consensus_info:
            return cached_consensus_info

        db = get_db_state(self.working_dir)
        ch = db.get_current_consensus()
        block = db.get_current_block()
        db.close()

        cinfo = {'consensus_hash': ch, 'block_height': block}
        self.set_cached_consensus_info(cinfo)
        return cinfo


    def rpc_getinfo(self, **con_info):
        """
        Get information from the running server:
        * last_block_seen: the last block height seen
        * consensus: the consensus hash for that block
        * server_version: the server version
        * last_block_processed: the last block processed
        * server_alive: True
        * [optional] zonefile_count: the number of zonefiles known
        """
        conf = get_blockstack_opts()
        info = self.get_bitcoind_info()
        cinfo = self.get_consensus_info()
        reply = {}
        reply['last_block_seen'] = info['blocks']

        reply['consensus'] = cinfo['consensus_hash']
        reply['server_version'] = "%s" % VERSION
        reply['last_block_processed'] = cinfo['block_height']
        reply['server_alive'] = True
        reply['indexing'] = config.is_indexing(self.working_dir)
        reply['testnet'] = BLOCKSTACK_TEST or BLOCKSTACK_TESTNET

        if conf.get('atlas', False):
            # return zonefile inv length
            reply['zonefile_count'] = atlas_get_num_zonefiles()

        if self.is_stale():
            reply['stale'] = True
            reply['warning'] = 'Daemon is behind the chain tip.  Do not rely on it for fresh information.'

        return reply


    def rpc_get_subdomains_owned_by_address(self, address, **con_info):
        """
        Get the list of subdomains owned by an address.
        Return {'status': True, 'subdomains': ...} on success
        Return {'error': ...} on error
        """
        if not check_address(address):
            return {'error': 'Invalid address', 'http_status': 400}

        res = get_subdomains_owned_by_address(address)
        return self.success_response({'subdomains': res})


    def rpc_get_names_owned_by_address(self, address, **con_info):
        """
        Get the list of names owned by an address.
        Return {'status': True, 'names': ...} on success
        Return {'error': ...} on error
        """
        if not check_address(address):
            return {'error': 'Invalid address', 'http_status': 400}

        db = get_db_state(self.working_dir)
        names = db.get_names_owned_by_address( address )
        db.close()

        if names is None:
            names = []

        return self.success_response( {'names': names} )


    def rpc_get_historic_names_by_address(self, address, offset, count, **con_info):
        """
        Get the list of names owned by an address throughout history
        Return {'status': True, 'names': [{'name': ..., 'block_id': ..., 'vtxindex': ...}]} on success
        Return {'error': ...} on error
        """
        if not check_address(address):
            return {'error': 'Invalid address', 'http_status': 400}

        if not check_offset(offset):
            return {'error': 'invalid offset', 'http_status': 400}

        if not check_count(count, 10):
            return {'error': 'invalid count', 'http_status': 400}

        db = get_db_state(self.working_dir)
        names = db.get_historic_names_by_address(address, offset, count)
        db.close()

        if names is None:
            names = []

        return self.success_response( {'names': names} )

    
    def rpc_get_num_historic_names_by_address(self, address, **con_info):
        """
        Get the number of names owned by an address throughout history
        Return {'status': True, 'count': ...} on success
        Return {'error': ...} on failure
        """
        if not check_address(address):
            return {'error': 'Invalid address', 'http_status': 400}

        db = get_db_state(self.working_dir)
        ret = db.get_num_historic_names_by_address(address)
        db.close()

        if ret is None:
            ret = 0

        return self.success_response( {'count': ret} )


    def rpc_get_name_cost( self, name, **con_info ):
        """
        Return the cost of a given name.
        Returns {'amount': ..., 'units': ...}
        """
        if not check_name(name):
            return {'error': 'Invalid name or namespace', 'http_status': 400}

        db = get_db_state(self.working_dir)
        ret = get_name_cost( db, name )
        db.close()

        if ret is None:
            return {"error": "Unknown/invalid namespace", 'http_status': 404}

        return self.success_response(ret)


    def rpc_get_namespace_cost( self, namespace_id, **con_info ):
        """
        Return the cost of a given namespace, including fees.
        Returns {'amount': ..., 'units': ...}
        """
        if not check_namespace(namespace_id):
            return {'error': 'Invalid namespace', 'http_status': 400}

        db = get_db_state(self.working_dir)
        res = get_namespace_cost( db, namespace_id )
        db.close()

        units = res['units']
        amount = res['amount']
        ns = res['namespace']

        if amount is None:
            # invalid 
            return {'error': 'Invalid namespace', 'http_status': 404}

        ret = {
            'units': units,
            'amount': amount,
        }

        if ns is not None:
            ret['warning'] = 'Namespace already exists'

        return self.success_response( ret )


    def rpc_get_namespace_blockchain_record( self, namespace_id, **con_info ):
        """ 
        Return the namespace with the given namespace_id
        Return {'status': True, 'record': ...} on success
        Return {'error': ...} on error
        """
        if not check_namespace(namespace_id):
            return {'error': 'Invalid name or namespace', 'http_status': 400}

        db = get_db_state(self.working_dir)
        ns = db.get_namespace( namespace_id )
        if ns is None:
            # maybe revealed?
            ns = db.get_namespace_reveal( namespace_id )
            db.close()

            if ns is None:
                return {"error": "No such namespace", 'http_status': 404}

            assert 'opcode' in ns, 'BUG: missing opcode in {}'.format(json.dumps(ns, sort_keys=True))
            ns = self.sanitize_rec(ns)

            ns['ready'] = False
            return self.success_response( {'record': ns} )

        else:
            db.close()
            
            assert 'opcode' in ns, 'BUG: missing opcode in {}'.format(json.dumps(ns, sort_keys=True))
            ns = self.sanitize_rec(ns)

            ns['ready'] = True
            return self.success_response( {'record': ns} )


    def rpc_get_num_names( self, **con_info ):
        """
        Get the number of names that exist and are not expired
        Return {'status': True, 'count': count} on success
        Return {'error': ...} on error
        """
        db = get_db_state(self.working_dir)
        num_names = db.get_num_names()
        db.close()

        return self.success_response( {'count': num_names} )


    def rpc_get_num_subdomains( self, **con_info ):
        """
        Get the number of subdomains that exist
        Return {'status': True, 'count': count} on success
        Return {'error': ...} on error
        """
        num_names = get_subdomains_count()

        return self.success_response( {'count': num_names} )


    def rpc_get_num_names_cumulative( self, **con_info ):
        """
        Get the number of names that have ever existed
        Return {'status': True, 'count': count} on success
        Return {'error': ...} on error
        """
        db = get_db_state(self.working_dir)
        num_names = db.get_num_names(include_expired=True)
        db.close()

        return self.success_response( {'count': num_names} )


    def rpc_get_all_names( self, offset, count, **con_info ):
        """
        Get all unexpired names, paginated
        Return {'status': true, 'names': [...]} on success
        Return {'error': ...} on error
        """
        if not check_offset(offset):
            return {'error': 'invalid offset', 'http_status': 400}

        if not check_count(count, 100):
            return {'error': 'invalid count', 'http_status': 400}

        db = get_db_state(self.working_dir)
        num_domains = db.get_num_names()
        if num_domains > offset:
           all_domains = db.get_all_names( offset=offset, count=count )
        else:
           all_domains = []
        db.close()

        return self.success_response( {'names': all_domains} )


    def rpc_get_all_subdomains( self, offset, count, **conf_info):
        """
        Get all subdomains, paginated
        Return {'status': true, 'names': [...]} on success
        Return {'error': ...} on error
        """
        if not check_offset(offset):
            return {'error': 'invalid offset', 'http_status': 400}

        if not check_count(count, 100):
            return {'error': 'invalid count', 'http_status': 400}

        all_subdomains = get_all_subdomains(offset = offset,
                                            count = count)

        return self.success_response( {'names': all_subdomains} )


    def rpc_get_all_names_cumulative( self, offset, count, **con_info ):
        """
        Get all names that have ever existed, paginated
        Return {'status': true, 'names': [...]} on success
        Return {'error': ...} on error
        """
        if not check_offset(offset):
            return {'error': 'invalid offset', 'http_status': 400}

        if not check_count(count, 100):
            return {'error': 'invalid count', 'http_status': 400}

        db = get_db_state(self.working_dir)
        all_names = db.get_all_names( offset=offset, count=count, include_expired=True )
        db.close()

        return self.success_response( {'names': all_names} )


    def rpc_get_all_namespaces( self, **con_info ):
        """
        Get all namespace names
        Return {'status': true, 'namespaces': [...]} on success
        Return {'error': ...} on error
        """
        db = get_db_state(self.working_dir)
        all_namespaces = db.get_all_namespace_ids()
        db.close()

        return self.success_response( {'namespaces': all_namespaces} )


    def rpc_get_num_names_in_namespace( self, namespace_id, **con_info ):
        """
        Get the number of names in a namespace
        Return {'status': true, 'count': count} on success
        Return {'error': ...} on error
        """
        if not check_namespace(namespace_id):
            return {'error': 'Invalid name or namespace', 'http_status': 400}

        db = get_db_state(self.working_dir)
        num_names = db.get_num_names_in_namespace( namespace_id )
        db.close()

        return self.success_response( {'count': num_names} )


    def rpc_get_names_in_namespace( self, namespace_id, offset, count, **con_info ):
        """
        Return all names in a namespace, paginated
        Return {'status': true, 'names': [...]} on success
        Return {'error': ...} on error
        """
        if not check_namespace(namespace_id):
            return {'error': 'Invalid name or namespace', 'http_status': 400}

        if not check_offset(offset):
            return {'error': 'invalid offset', 'http_status': 400}

        if not check_count(count, 100):
            return {'error': 'invalid count', 'http_status': 400}

        if not is_namespace_valid( namespace_id ):
            return {'error': 'invalid namespace ID', 'http_status': 400}

        db = get_db_state(self.working_dir)
        res = db.get_names_in_namespace( namespace_id, offset=offset, count=count )
        db.close()

        return self.success_response( {'names': res} )


    def rpc_get_consensus_at( self, block_id, **con_info ):
        """
        Return the consensus hash at a block number.
        Return {'status': True, 'consensus': ...} on success
        Return {'error': ...} on error
        """
        if not check_block(block_id):
            return {'error': 'Invalid block height', 'http_status': 400}

        db = get_db_state(self.working_dir)
        consensus = db.get_consensus_at( block_id )
        db.close()
        return self.success_response( {'consensus': consensus} )


    def rpc_get_consensus_hashes( self, block_id_list, **con_info ):
        """
        Return the consensus hashes at multiple block numbers
        Return a dict mapping each block ID to its consensus hash.

        Returns {'status': True, 'consensus_hashes': dict} on success
        Returns {'error': ...} on success
        """
        if type(block_id_list) != list:
            return {'error': 'Invalid block heights', 'http_status': 400}

        if len(block_id_list) > 32:
            return {'error': 'Too many block heights', 'http_status': 400}

        for bid in block_id_list:
            if not check_block(bid):
                return {'error': 'Invalid block height', 'http_status': 400}

        db = get_db_state(self.working_dir)
        ret = {}
        for block_id in block_id_list:
            ret[block_id] = db.get_consensus_at(block_id)

        db.close()

        return self.success_response( {'consensus_hashes': ret} )


    def rpc_get_block_from_consensus( self, consensus_hash, **con_info ):
        """
        Given the consensus hash, find the block number (or None)
        """
        if not check_string(consensus_hash, min_length=LENGTHS['consensus_hash']*2, max_length=LENGTHS['consensus_hash']*2, pattern=OP_CONSENSUS_HASH_PATTERN):
            return {'error': 'Not a valid consensus hash', 'http_status': 400}

        db = get_db_state(self.working_dir)
        block_id = db.get_block_from_consensus( consensus_hash )
        db.close()
        return self.success_response( {'block_id': block_id} )


    def get_zonefile_data( self, zonefile_hash, zonefile_dir ):
        """
        Get a zonefile by hash
        Return the serialized zonefile on success
        Return None on error
        """
        # check cache
        atlas_zonefile_data = get_atlas_zonefile_data( zonefile_hash, zonefile_dir )
        if atlas_zonefile_data is not None:
            # check hash
            zfh = get_zonefile_data_hash( atlas_zonefile_data )
            if zfh != zonefile_hash:
                log.debug("Invalid local zonefile %s" % zonefile_hash )
                remove_atlas_zonefile_data( zonefile_hash, zonefile_dir )

            else:
                log.debug("Zonefile %s is local" % zonefile_hash)
                return atlas_zonefile_data

        return None


    def rpc_get_zonefiles( self, zonefile_hashes, **con_info ):
        """
        Get zonefiles from the local zonefile set.
        Only return at most 100 zonefiles.
        Return {'status': True, 'zonefiles': {zonefile_hash: zonefile}} on success
        Return {'error': ...} on error

        zonefiles will be serialized to string and base64-encoded
        """
        conf = get_blockstack_opts()
        if not is_atlas_enabled(conf):
            return {'error': 'No data', 'http_status': 400}
            
        if 'zonefiles' not in conf:
            return {'error': 'No zonefiles directory (likely a configuration bug)', 'http_status': 404}

        if type(zonefile_hashes) != list:
            log.error("Not a zonefile hash list")
            return {'error': 'Invalid zonefile hashes', 'http_status': 400}

        if len(zonefile_hashes) > 100:
            log.error("Too many requests (%s)" % len(zonefile_hashes))
            return {'error': 'Too many requests (no more than 100 allowed)', 'http_status': 400}

        for zfh in zonefile_hashes:
            if not check_string(zfh, min_length=LENGTHS['value_hash']*2, max_length=LENGTHS['value_hash']*2, pattern=OP_HEX_PATTERN):
                return {'error': 'Invalid zone file hash', 'http_status': 400}

        ret = {}
        for zonefile_hash in zonefile_hashes:
            zonefile_data = self.get_zonefile_data( zonefile_hash, conf['zonefiles'] )
            if zonefile_data is None:
                continue

            else:
                ret[zonefile_hash] = base64.b64encode( zonefile_data )

        log.debug("Serve back %s zonefiles" % len(ret.keys()))
        return self.success_response( {'zonefiles': ret} )

    
    def rpc_put_zonefiles( self, zonefile_datas, **con_info ):
        """
        Replicate one or more zonefiles, given as serialized strings.
        Only stores zone files whose zone file hashes were announced on the blockchain (i.e. not subdomain zone files)
        Returns {'status': True, 'saved': [0|1]'} on success ('saved' is a vector of success/failure)
        Returns {'error': ...} on error
        Takes at most 5 zonefiles
        """
        conf = get_blockstack_opts()
        if not is_atlas_enabled(conf):
            return {'error': 'No data', 'http_status': 400}
        
        if 'zonefiles' not in conf:
            return {'error': 'No zonefiles directory (likely a configuration error)', 'http_status': 400}

        if type(zonefile_datas) != list:
            return {'error': 'Invalid data', 'http_status': 400}

        if len(zonefile_datas) > 5:
            return {'error': 'Too many zonefiles', 'http_status': 400}

        for zfd in zonefile_datas:
            if not check_string(zfd, max_length=((4 * RPC_MAX_ZONEFILE_LEN) / 3) + 3, pattern=OP_BASE64_EMPTY_PATTERN):
                return {'error': 'Invalid zone file payload (exceeds {} bytes and/or not base64-encoded)'.format(RPC_MAX_ZONEFILE_LEN)}

        zonefile_dir = conf.get("zonefiles", None)
        saved = []

        for zonefile_data in zonefile_datas:

            # decode
            try:
                zonefile_data = base64.b64decode( zonefile_data )
            except:
                log.debug("Invalid base64 zonefile")
                saved.append(0)
                continue

            if len(zonefile_data) > RPC_MAX_ZONEFILE_LEN:
                log.debug("Zonefile too long")
                saved.append(0)
                continue
            
            # is this zone file already discovered?
            zonefile_hash = get_zonefile_data_hash(str(zonefile_data))
            zfinfos = atlasdb_get_zonefiles_by_hash(zonefile_hash, path=conf['atlasdb_path'])
            if not zfinfos:
                # nope
                log.debug("Unknown zonefile hash {}".format(zonefile_hash))
                saved.append(0)
                continue
            
            # keep this zone file
            rc = store_atlas_zonefile_data( str(zonefile_data), zonefile_dir )
            if not rc:
                log.error("Failed to store zonefile {}".format(zonefile_hash))
                saved.append(0)
                continue
             
            # mark this zone file as present, so we don't ask anyone else for it
            was_present = atlasdb_set_zonefile_present(zonefile_hash, True, path=conf['atlasdb_path'])
            if was_present:
                # we already got this zone file
                log.debug("Already have zonefile {}".format(zonefile_hash))
                saved.append(1)
                continue

            if self.subdomain_index:
                # got new zonefile
                # let the subdomain indexer know, along with giving it the minimum block height
                min_block_height = min([zfi['block_height'] for zfi in zfinfos])

                log.debug("Enqueue {} from {} for subdomain processing".format(zonefile_hash, min_block_height))
                self.subdomain_index.enqueue_zonefile(zonefile_hash, min_block_height)

            log.debug("Stored new zonefile {}".format(zonefile_hash))
            saved.append(1)

        log.debug("Saved {} zonefile(s)".format(sum(saved)))
        log.debug("Reply: {}".format({'saved': saved}))
        return self.success_response( {'saved': saved} )


    def rpc_get_zonefiles_by_block( self, from_block, to_block, offset, count, **con_info ):
        """
        Get information about zonefiles announced in blocks [@from_block, @to_block]
        @offset - offset into result set
        @count - max records to return, must be <= 100
        Returns {'status': True, 'lastblock' : blockNumber,
                 'zonefile_info' : [ { 'block_height' : 470000,
                                       'txid' : '0000000',
                                       'zonefile_hash' : '0000000' } ] }
        """
        conf = get_blockstack_opts()
        if not is_atlas_enabled(conf):
            return {'error': 'Not an atlas node', 'http_status': 400}

        if not check_block(from_block):
            return {'error': 'Invalid from_block height', 'http_status': 400}

        if not check_block(to_block):
            return {'error': 'Invalid to_block height', 'http_status': 400}

        if not check_offset(offset):
            return {'error': 'invalid offset', 'http_status': 400}

        if not check_count(count, 100):
            return {'error': 'invalid count', 'http_status': 400}

        zonefile_info = atlasdb_get_zonefiles_by_block(from_block, to_block, offset, count, path=conf['atlasdb_path'])
        if 'error' in zonefile_info:
           return zonefile_info

        return self.success_response( {'zonefile_info': zonefile_info } )


    def peer_exchange(self, peer_host, peer_port):
        """
        Exchange peers.
        Add the given peer to the list of new peers to consider.
        Return the list of healthy peers
        """
        # get peers
        peer_list = atlas_get_live_neighbors( "%s:%s" % (peer_host, peer_port) )
        if len(peer_list) > atlas_max_neighbors():
            random.shuffle(peer_list)
            peer_list = peer_list[:atlas_max_neighbors()]

        log.info("Enqueue remote peer {}:{}".format(peer_host, peer_port))
        atlas_peer_enqueue( "%s:%s" % (peer_host, peer_port))

        log.debug("Live peers reply to %s:%s: %s" % (peer_host, peer_port, peer_list))
        return peer_list


    def rpc_get_atlas_peers( self, **con_info ):
        """
        Get the list of peer atlas nodes.
        Give its own atlas peer hostport.
        Return at most atlas_max_neighbors() peers
        Return {'status': True, 'peers': ...} on success
        Return {'error': ...} on failure
        """
        conf = get_blockstack_opts()
        if not conf.get('atlas', False):
            return {'error': 'Not an atlas node', 'http_status': 404}

        # identify the client...
        client_host = con_info['client_host']
        client_port = con_info['client_port']

        peers = self.peer_exchange(client_host, client_port)
        return self.success_response( {'peers': peers} )


    def rpc_atlas_peer_exchange(self, remote_peer, **con_info):
        """
        Accept a remotely-given atlas peer, and return our list
        of healthy peers.  The remotely-given atlas peer will only
        be considered if the caller is localhost; otherwise, the caller's
        socket-given information will be used.  This is to prevent
        a malicious node from filling up this node's peer table with
        junk.

        Returns at most atlas_max_neighbors() peers
        Returns {'status': True, 'peers': ...} on success
        Returns {'error': ...} on failure
        """
        conf = get_blockstack_opts()
        if not conf.get('atlas', False):
            return {'error': 'Not an atlas node', 'http_status': 404}

        # take the socket-given information if this is not localhost
        client_host = con_info['client_host']
        client_port = con_info['client_port']

        peer_host = None
        peer_port = None
        
        LOCALHOST = ['127.0.0.1', '::1', 'localhost']
        if client_host not in LOCALHOST:
            # we don't allow a non-localhost peer to insert an arbitrary host
            peer_host = client_host
            peer_port = client_port

        else:
            try:
                peer_host, peer_port = url_to_host_port(remote_peer)
                assert peer_host
                assert peer_port
            except:
                # invalid
                return {'error': 'Invalid remote peer address', 'http_status': 400}
        
        peers = self.peer_exchange(peer_host, peer_port)
        return self.success_response({'peers': peers})


    def rpc_get_zonefile_inventory( self, offset, length, **con_info ):
        """
        Get an inventory bit vector for the zonefiles in the
        given bit range (i.e. offset and length are in bytes)
        Returns at most 64k of inventory (or 524288 bits)
        Return {'status': True, 'inv': ...} on success, where 'inv' is a b64-encoded bit vector string
        Return {'error': ...} on error.
        """
        conf = get_blockstack_opts()
        if not is_atlas_enabled(conf):
            return {'error': 'Not an atlas node', 'http_status': 400}

        if not check_offset(offset):
            return {'error': 'invalid offset', 'http_status': 400}

        if not check_count(length, 524288):
            return {'error': 'invalid length', 'http_status': 400}

        zonefile_inv = atlas_get_zonefile_inventory( offset=offset, length=length )

        if BLOCKSTACK_TEST:
            log.debug("Zonefile inventory is '%s'" % (atlas_inventory_to_string(zonefile_inv)))

        return self.success_response( {'inv': base64.b64encode(zonefile_inv) } )


    def rpc_get_all_neighbor_info( self, **con_info ):
        """
        For network simulator purposes only!
        This method returns all of our peer info.

        DISABLED BY DEFAULT
        """
        if os.environ.get("BLOCKSTACK_ATLAS_NETWORK_SIMULATION") != "1":
            return {'error': 'No such method', 'http_status': 401}

        return atlas_get_all_neighbors()


class BlockstackdRPCServer( threading.Thread, object ):
    """
    RPC server thread
    """
    def __init__(self, working_dir, port, subdomain_index=None):
        super(BlockstackdRPCServer, self).__init__()
        self.port = port
        self.working_dir = working_dir
        self.subdomain_index = subdomain_index
        self.rpc_server = BlockstackdRPC( self.working_dir, port=self.port, subdomain_index=self.subdomain_index )

    def run(self):
        """
        Serve until asked to stop
        """
        self.rpc_server.serve_forever()


    def stop_server(self):
        """
        Stop serving.  Also stops the thread.
        """
        if self.rpc_server is not None:
            try:
                self.rpc_server.socket.shutdown(socket.SHUT_RDWR)
            except:
                log.warning("Failed to shut down server socket")

            self.rpc_server.shutdown()


    def cache_flush(self):
        """
        Flush any cached state
        """
        self.rpc_server.cache_flush()


    def set_last_index_time(self, timestamp):
        """
        Set the time that we last indexed
        """
        self.rpc_server.set_last_index_time(timestamp)


class BlockstackdAPIServer( threading.Thread, object ):
    """
    API server thread
    """
    def __init__(self, working_dir, host, port):
        super(BlockstackdAPIServer, self).__init__()
        self.host = host
        self.port = port
        self.working_dir = working_dir
        self.api_server = BlockstackAPIEndpoint(host=host, port=port)

        self.api_server.bind()
        self.api_server.timeout = 0.5


    def run(self):
        """
        Serve until asked to stop
        """
        self.api_server.serve_forever()

    
    def stop_server(self):
        """
        Stop serving
        """
        if self.api_server is not None:
            try:
                self.api_server.socket.shutdown(socket.SHUT_RDWR)
            except:
                log.warning("Failed to shut down API server socket")

            self.api_server.shutdown()
            

def rpc_start( working_dir, port, subdomain_index=None, thread=True ):
    """
    Start the global RPC server thread
    Returns the RPC server thread
    """
    rpc_srv = BlockstackdRPCServer( working_dir, port, subdomain_index=subdomain_index )
    log.debug("Starting RPC on port {}".format(port))

    if thread:
        rpc_srv.start()

    return rpc_srv


def rpc_chain_sync(server_state, new_block_height, finish_time):
    """
    Flush the global RPC server cache, and tell the rpc server that we've
    reached the given block height at the given time.
    """
    rpc_srv = server_state['rpc']
    if rpc_srv is not None:
        rpc_srv.cache_flush()
        rpc_srv.set_last_index_time(finish_time)


def rpc_stop(server_state):
    """
    Stop the global RPC server thread
    """
    rpc_srv = server_state['rpc']

    if rpc_srv is not None:
        log.info("Shutting down RPC")
        rpc_srv.stop_server()
        rpc_srv.join()
        log.info("RPC joined")

    else:
        log.info("RPC already joined")

    server_state['rpc'] = None


def gc_start():
    """
    Start a thread to garbage-collect every 30 seconds.
    """
    global gc_thread

    gc_thread = GCThread()
    log.info("Optimistic GC thread start")
    gc_thread.start()


def gc_stop():
    """
    Stop a the optimistic GC thread
    """
    global gc_thread
    
    if gc_thread:
        log.info("Shutting down GC thread")
        gc_thread.signal_stop()
        gc_thread.join()
        log.info("GC thread joined")
        gc_thread = None
    else:
        log.info("GC thread already joined")


def get_gc_thread():
    """
    Get the global GC thread
    """
    global gc_thread
    return gc_thread


def api_start(working_dir, host, port, thread=True):
    """
    Start the global API server
    Returns the API server thread
    """
    api_srv = BlockstackdAPIServer( working_dir, host, port )
    log.info("Starting API server on port {}".format(port))
    if thread:
        api_srv.start()

    return api_srv


def api_stop(server_state):
    """
    Stop the global API server thread
    """
    api_srv = server_state['api']

    if api_srv is not None:
        log.info("Shutting down API")
        api_srv.stop_server()
        api_srv.join()
        log.info("API server joined")
    else:
        log.info("API already joined")

    server_state['api'] = None


def atlas_init(blockstack_opts, db, port=None):
    """
    Start up atlas functionality
    """
    if port is None:
        port = blockstack_opts['rpc_port']

    # start atlas node
    atlas_state = None
    if is_atlas_enabled(blockstack_opts):
        atlas_seed_peers = filter( lambda x: len(x) > 0, blockstack_opts['atlas_seeds'].split(","))
        atlas_blacklist = filter( lambda x: len(x) > 0, blockstack_opts['atlas_blacklist'].split(","))
        zonefile_dir = blockstack_opts['zonefiles']
        my_hostname = blockstack_opts['atlas_hostname']
        my_port = blockstack_opts['atlas_port']

        initial_peer_table = atlasdb_init(blockstack_opts['atlasdb_path'], zonefile_dir, db, atlas_seed_peers, atlas_blacklist, validate=True)
        atlas_peer_table_init(initial_peer_table)

        atlas_state = atlas_node_init(my_hostname, my_port, blockstack_opts['atlasdb_path'], zonefile_dir, db.working_dir)

    return atlas_state


def atlas_stop( atlas_state ):
    """
    Stop atlas functionality
    """
    if atlas_state is not None:
        atlas_node_stop( atlas_state )
        atlas_state = None


def read_pid_file(pidfile_path):
    """
    Read the PID from the PID file
    """

    try:
        fin = open(pidfile_path, "r")
    except Exception, e:
        return None

    else:
        pid_data = fin.read().strip()
        fin.close()

        try:
            pid = int(pid_data)
            return pid
        except:
            return None


def check_server_running(pid):
    """
    Determine if the given process is running
    """
    if pid == os.getpid():
        # special case--we're in Docker or some other kind of container
        # (or we got really unlucky and got the same PID twice).
        # this PID does not correspond to another running server, either way.
        return False

    try:
        os.kill(pid, 0)
        return True
    except OSError as oe:
        if oe.errno == errno.ESRCH:
            return False
        else:
            raise


def stop_server( working_dir, clean=False, kill=False ):
    """
    Stop the blockstackd server.
    """

    timeout = 1.0
    dead = False

    for i in xrange(0, 5):
        # try to kill the main supervisor
        pid_file = get_pidfile_path(working_dir)
        if not os.path.exists(pid_file):
            dead = True
            break

        pid = read_pid_file(pid_file)
        if pid is not None:
            try:
               os.kill(pid, signal.SIGTERM)
            except OSError, oe:
               if oe.errno == errno.ESRCH:
                  # already dead
                  log.info("Process %s is not running" % pid)
                  try:
                      os.unlink(pid_file)
                  except:
                      pass

                  return

            except Exception, e:
                log.exception(e)
                os.abort()

        else:
            log.info("Corrupt PID file.  Please make sure all instances of this program have stopped and remove {}".format(pid_file))
            os.abort()

        # is it actually dead?
        blockstack_opts = get_blockstack_opts()
        srv = BlockstackRPCClient('localhost', blockstack_opts['rpc_port'], timeout=5, protocol='http')
        try:
            res = blockstack_ping(proxy=srv)
        except socket.error as se:
            # dead?
            if se.errno == errno.ECONNREFUSED:
                # couldn't connect, so infer dead
                try:
                    os.kill(pid, 0)
                    log.info("Server %s is not dead yet..." % pid)

                except OSError, oe:
                    log.info("Server %s is dead to us" % pid)
                    dead = True
                    break
            else:
                continue

        log.info("Server %s is still running; trying again in %s seconds" % (pid, timeout))
        time.sleep(timeout)
        timeout *= 2

    if not dead and kill:
        # be sure to clean up the pidfile
        log.info("Killing server %s" % pid)
        clean = True
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception, e:
            pass

    if clean:
        # blow away the pid file
        try:
            os.unlink(pid_file)
        except:
            pass


    log.debug("Blockstack server stopped")


def blockstack_tx_filter( tx ):
    """
    Virtualchain tx filter function:
    * only take txs whose OP_RETURN payload starts with 'id'
    """
    if not 'nulldata' in tx:
        return False
    
    if tx['nulldata'] is None:
        return False

    payload = binascii.unhexlify( tx['nulldata'] )
    if payload.startswith("id"):
        return True

    else:
        return False


def index_blockchain(server_state, expected_snapshots=GENESIS_SNAPSHOT):
    """
    Index the blockchain:
    * find the range of blocks
    * synchronize our state engine up to them

    Return True if we should continue indexing
    Return False if not
    Aborts on error
    """
    working_dir = server_state['working_dir']
    log.debug("index blockchain in {}".format(working_dir))
    blockstack_opts = get_blockstack_opts()

    bt_opts = get_bitcoin_opts()
    start_block, current_block = get_index_range(working_dir)

    db = get_db_state(working_dir)
    old_lastblock = db.lastblock

    if start_block is None and current_block is None:
        log.error("Failed to find block range")
        db.close()
        return False

    # sanity check: does the subdomain db exist yet, and are we at the point where we can start indexing them?
    if is_subdomains_enabled(blockstack_opts):
        subdomain_last_block = server_state['subdomains'].get_db().get_last_block()
        if subdomain_last_block < SUBDOMAINS_FIRST_BLOCK and start_block >= SUBDOMAINS_FIRST_BLOCK and not server_state['subdomains_initialized']:
            # initialize subdomains db
            log.debug("Creating subdomain DB {}".format(blockstack_opts['subdomaindb_path']))
            server_state['subdomains'].reindex(current_block)
            server_state['subdomains_initialized'] = True

    # bring the db up to the chain tip.
    # NOTE: at each block, the atlas db will be synchronized by virtualchain_hooks
    log.debug("Begin indexing (up to %s)" % current_block)
    set_indexing( working_dir, True )
    rc = virtualchain_hooks.sync_blockchain(working_dir, bt_opts, current_block, server_state, expected_snapshots=expected_snapshots, tx_filter=blockstack_tx_filter)
    set_indexing( working_dir, False )

    db.close()

    if not rc:
        log.debug("Stopped indexing at %s" % current_block)
        return rc

    # uncache state specific to this block
    rpc_chain_sync(server_state, current_block, time.time())

    log.debug("End indexing (up to %s)" % current_block)
    return rc


def blockstack_exit(atlas_state):
    """
    Shut down the server on exit(3)
    """
    if atlas_state is not None:
        atlas_node_stop( atlas_state )


def blockstack_signal_handler( sig, frame ):
    """
    Fatal signal handler
    """
    set_running(False)


def server_setup(working_dir, port=None, api_port=None, indexer_enabled=None, indexer_url=None, api_enabled=None):
    """
    Set up the server.
    Start all subsystems, write pid file, set up signal handlers, set up DB.
    Returns a server instance.
    """
    blockstack_opts = get_blockstack_opts()
    blockstack_api_opts = get_blockstack_api_opts()
    pid_file = get_pidfile_path(working_dir)

    indexer_enabled = indexer_enabled if indexer_enabled is not None else blockstack_opts['enabled']
    api_enabled = api_enabled if api_enabled is not None else blockstack_api_opts['enabled']
    indexer_url = indexer_url if indexer_url is not None else blockstack_api_opts.get('indexer_url', None)

    # sanity check 
    if api_enabled and not indexer_url:
        print("FATAL: no 'indexer_url' in the config file, and no --indexer_url given in the arguments")
        sys.exit(1)

    if port is None:
        port = blockstack_opts['rpc_port']

    if api_port is None:
        api_port = blockstack_api_opts['api_port']

    # set up signals
    signal.signal( signal.SIGINT, blockstack_signal_handler )
    signal.signal( signal.SIGQUIT, blockstack_signal_handler )
    signal.signal( signal.SIGTERM, blockstack_signal_handler )

    # put pid file
    put_pidfile(pid_file, os.getpid())

    # clear indexing state
    set_indexing(working_dir, False)

    # process overrides
    if blockstack_opts['enabled'] != indexer_enabled:
        log.debug("Override blockstack.enabled to {}".format(indexer_enabled))
        blockstack_opts['enabled'] = indexer_enabled
        set_blockstack_opts(blockstack_opts)

    if blockstack_api_opts['enabled'] != api_enabled:
        log.debug("Override blockstack-api.enabled to {}".format(indexer_enabled))
        blockstack_api_opts['enabled'] = api_enabled
        set_blockstack_api_opts(blockstack_api_opts)

    if blockstack_api_opts['indexer_url'] != indexer_url:
        log.debug("Override blockstack-api.indexer_url to {}".format(indexer_url))
        blockstack_api_opts['indexer_url'] = indexer_url
        set_blockstack_api_opts(blockstack_api_opts)

    # start API servers
    rpc_srv = None
    api_srv = None
    atlas_state = None
    subdomain_state = None

    if blockstack_opts['enabled']:
        # get db state
        db = get_or_instantiate_db_state(working_dir)
    
        # set up atlas state, if we're an indexer
        atlas_state = atlas_init(blockstack_opts, db, port=port)
        db.close()

        # set up subdomains state
        subdomain_state = subdomains_init(blockstack_opts, working_dir, atlas_state)
    
        # start atlas node
        if atlas_state:
            atlas_node_start(atlas_state)
        
        # start back-plane API server
        rpc_srv = rpc_start(working_dir, port, subdomain_index=subdomain_state, thread=False)

    if blockstack_api_opts['enabled']:
        # start public RESTful API server
        api_srv = api_start(working_dir, blockstack_api_opts['api_host'], api_port, thread=False)

    if rpc_srv:
        rpc_srv.start()

    if api_srv:
        api_srv.start()

    # start GC
    gc_start()

    set_running(True)

    # clear any stale indexing state
    set_indexing(working_dir, False)

    log.debug("Server setup: API = {}, Indexer = {}, Indexer URL = {}".format(blockstack_api_opts['enabled'], blockstack_opts['enabled'], blockstack_api_opts['indexer_url']))

    ret = {
        'working_dir': working_dir,
        'atlas': atlas_state,
        'subdomains': subdomain_state,
        'subdomains_initialized': False,
        'rpc': rpc_srv,
        'api': api_srv,
        'pid_file': pid_file,
        'port': port,
        'api_port': api_port
    }

    return ret


def server_atlas_shutdown(server_state):
    """
    Shut down just the atlas system
    (used for testing)
    """
    # stop atlas node
    log.debug("Stopping Atlas node")
    atlas_stop(server_state['atlas'])
    server_state['atlas'] = None
    return 


def server_shutdown(server_state):
    """
    Shut down server subsystems.
    Remove PID file.
    """
    set_running( False )

    # stop API servers
    rpc_stop(server_state)
    api_stop(server_state)

    # stop atlas node
    server_atlas_shutdown(server_state)

    # stopping GC
    gc_stop()

    # clear PID file
    try:
        if os.path.exists(server_state['pid_file']):
            os.unlink(server_state['pid_file'])
    except:
        pass

    return True


def run_server(working_dir, foreground=False, expected_snapshots=GENESIS_SNAPSHOT, port=None, api_port=None, use_api=None, use_indexer=None, indexer_url=None):
    """
    Run blockstackd.  Optionally daemonize.
    Return 0 on success
    Return negative on error
    """
    global rpc_server
    global api_server

    indexer_log_path = get_logfile_path(working_dir)
    
    logfile = None
    if not foreground:
        if os.path.exists(indexer_log_path):
            logfile = open(indexer_log_path, 'a')
        else:
            logfile = open(indexer_log_path, 'a+')

        child_pid = daemonize(logfile)
        if child_pid < 0:
            log.error("Failed to daemonize: {}".format(child_pid))
            return -1

        if child_pid > 0:
            # we're the parent
            log.debug("Running in the background as PID {}".format(child_pid))
            sys.exit(0)
    
    server_state = server_setup(working_dir, port=port, api_port=api_port, indexer_enabled=use_indexer, indexer_url=indexer_url, api_enabled=use_api)
    atexit.register(server_shutdown, server_state)

    rpc_server = server_state['rpc']
    
    blockstack_opts = get_blockstack_opts()
    blockstack_api_opts = get_blockstack_api_opts()

    if blockstack_opts['enabled']:
        log.debug("Begin Indexing")
        while is_running():
            try:
               running = index_blockchain(server_state, expected_snapshots=expected_snapshots)
            except Exception, e:
               log.exception(e)
               log.error("FATAL: caught exception while indexing")
               os.abort()

            # wait for the next block
            deadline = time.time() + REINDEX_FREQUENCY
            while time.time() < deadline and is_running():
                try:
                    time.sleep(1.0)
                except:
                    # interrupt
                    break

        log.debug("End Indexing")

    elif blockstack_api_opts['enabled']:
        log.debug("Begin serving REST requests")
        while is_running():
            try:
                time.sleep(1.0)
            except:
                # interrupt
                break

        log.debug("End serving REST requests")

    server_shutdown(server_state)
    
    # close logfile
    if logfile is not None:
        logfile.flush()
        logfile.close()
    
    return 0


def setup(working_dir, interactive=False):
    """
    Do one-time initialization.
    Call this to set up global state.
    """
    # set up our implementation
    log.debug("Working dir: {}".format(working_dir))
    if not os.path.exists( working_dir ):
        os.makedirs( working_dir, 0700 )

    node_config = load_configuration(working_dir)
    if node_config is None:
        sys.exit(1)

    log.debug("config\n{}".format(json.dumps(node_config, indent=4, sort_keys=True)))
    return node_config


def reconfigure(working_dir):
    """
    Reconfigure blockstackd.
    """
    configure(working_dir, force=True, interactive=True)
    print "Blockstack successfully reconfigured."
    sys.exit(0)


def verify_database(trusted_consensus_hash, consensus_block_height, untrusted_working_dir, trusted_working_dir, start_block=None, expected_snapshots={}):
    """
    Verify that a database is consistent with a
    known-good consensus hash.
    Return True if valid.
    Return False if not
    """
    db = BlockstackDB.get_readwrite_instance(trusted_working_dir)
    consensus_impl = virtualchain_hooks
    return virtualchain.state_engine_verify(trusted_consensus_hash, consensus_block_height, consensus_impl, untrusted_working_dir, db, start_block=start_block, expected_snapshots=expected_snapshots)


def check_and_set_envars( argv ):
    """
    Go through argv and find any special command-line flags
    that set environment variables that affect multiple modules.

    If any of them are given, then set them in this process's
    environment and re-exec the process without the CLI flags.

    argv should be like sys.argv:  argv[0] is the binary

    Does not return on re-exec.
    Returns {args} on success
    Returns False on error.
    """
    special_flags = {
        '--debug': {
            'arg': False,
            'envar': 'BLOCKSTACK_DEBUG',
            'exec': True,
        },
        '--verbose': {
            'arg': False,
            'envar': 'BLOCKSTACK_DEBUG',
            'exec': True,
        },
        '--testnet': {
            'arg': False,
            'envar': 'BLOCKSTACK_TESTNET',
            'exec': True,
        },
        '--testnet3': {
            'arg': False,
            'envar': 'BLOCKSTACK_TESTNET3',
            'exec': True,
        },
        '--working_dir': {
            'arg': True,
            'argname': 'working_dir',
            'exec': False,
        },
        '--working-dir': {
            'arg': True,
            'argname': 'working_dir',
            'exec': False,
        },
    }

    cli_envs = {}
    cli_args = {}
    new_argv = []
    stripped_argv = []

    do_exec = False
    i = 0
    while i < len(argv):

        arg = argv[i]
        value = None

        for special_flag in special_flags.keys():

            if not arg.startswith(special_flag):
                continue

            if special_flags[special_flag]['arg']:
                if '=' in arg:
                    argparts = arg.split("=")
                    value_parts = argparts[1:]
                    arg = argparts[0]
                    value = '='.join(value_parts)

                elif i + 1 < len(argv):
                    value = argv[i+1]
                    i += 1

                else:
                    print >> sys.stderr, "%s requires an argument" % special_flag
                    return False

            else:
                # just set
                value = "1"

            break

        i += 1

        if value is not None:
            if 'envar' in special_flags[special_flag]:
                # recognized
                cli_envs[ special_flags[special_flag]['envar'] ] = value
            
            if 'argname' in special_flags[special_flag]:
                # recognized as special argument
                cli_args[ special_flags[special_flag]['argname'] ] = value
                new_argv.append(arg)
                new_argv.append(value)

            if special_flags[special_flag]['exec']:
                do_exec = True

        else:
            # not recognized
            new_argv.append(arg)
            stripped_argv.append(arg)

    if do_exec:
        # re-exec
        for cli_env, cli_env_value in cli_envs.items():
            os.environ[cli_env] = cli_env_value

        if os.environ.get("BLOCKSTACK_DEBUG") is not None:
            print "Re-exec as {}".format(" ".join(new_argv))

        os.execv(new_argv[0], new_argv)

    log.debug("Stripped argv: {}".format(' '.join(stripped_argv)))
    return cli_args, stripped_argv


def load_expected_snapshots( snapshots_path ):
    """
    Load expected consensus hashes from a .snapshots file.
    Return the snapshots as a dict on success
    Return None on error
    """
    # use snapshots?
    snapshots_path = os.path.expanduser(snapshots_path)
    expected_snapshots = {}

    # legacy chainstate?
    try:
        with open(snapshots_path, "r") as f:
            snapshots_json = f.read()
        
        snapshots_data = json.loads(snapshots_json)
        assert 'snapshots' in snapshots_data.keys(), "Not a valid snapshots file"

        # extract snapshots: map int to consensus hash
        for (block_id_str, consensus_hash) in snapshots_data['snapshots'].items():
            expected_snapshots[ int(block_id_str) ] = str(consensus_hash)
        
        log.debug("Loaded expected snapshots from legacy JSON {}; {} entries".format(snapshots_path, len(expected_snapshots)))
        return expected_snapshots
    
    except ValueError as ve:
        log.debug("Snapshots file {} is not JSON".format(snapshots_path))

    except Exception as e:
        if os.environ.get('BLOCKSTACK_DEBUG') == '1':
            log.exception(e)

        log.debug("Failed to read expected snapshots from '{}'".format(snapshots_path))
        return None

    try:
        # sqlite3 db?
        db_con = virtualchain.StateEngine.db_connect(snapshots_path)
        expected_snapshots = virtualchain.StateEngine.get_consensus_hashes(None, None, db_con=db_con, completeness_check=False)
        log.debug("Loaded expected snapshots from chainstate DB {}, {} entries".format(snapshots_path, len(expected_snapshots)))
        return expected_snapshots

    except:
        log.debug("{} does not appear to be a chainstate DB".format(snapshots_path))

    return None
    

def run_blockstackd():
    """
    run blockstackd
    """
    special_args, new_argv = check_and_set_envars( sys.argv )
    working_dir = special_args.get('working_dir')
    if working_dir is None:
        working_dir = os.path.expanduser('~/.{}'.format(virtualchain_hooks.get_virtual_chain_name()))
        
    setup(working_dir)

    # need sqlite3
    sqlite3_tool = virtualchain.sqlite3_find_tool()
    if sqlite3_tool is None:
        print 'Failed to find sqlite3 tool in your PATH.  Cannot continue'
        sys.exit(1)
    
    argparser = argparse.ArgumentParser()

    # get RPC server options
    subparsers = argparser.add_subparsers(
        dest='action', help='the action to be taken')
     
    # -------------------------------------
    parser = subparsers.add_parser(
        'start',
        help='start blockstackd')
    parser.add_argument(
        '--foreground', action='store_true',
        help='start blockstackd in foreground')
    parser.add_argument(
        '--expected-snapshots', action='store')
    parser.add_argument(
        '--expected_snapshots', action='store',
        help='path to a .snapshots file with the expected consensus hashes')
    parser.add_argument(
        '--port', action='store',
        help='peer network port to bind on')
    parser.add_argument(
        '--api-port', action='store')
    parser.add_argument(
        '--api_port', action='store',
        help='RESTful API port to bind on')
    parser.add_argument(
        '--working-dir', action='store',
        help='Directory with the chain state to use')
    parser.add_argument(
        '--no-indexer', action='store_true',
        help='Do not start the indexer component')
    parser.add_argument(
        '--indexer_url', action='store'),
    parser.add_argument(
        '--indexer-url', action='store',
        help='URL to the indexer-enabled blockstackd instance to use')
    parser.add_argument(
        '--no-api', action='store_true',
        help='Do not start the RESTful API component')

    # -------------------------------------
    parser = subparsers.add_parser(
        'stop',
        help='stop the blockstackd server')
    parser.add_argument(
        '--working-dir', action='store',
        help='Directory with the chain state to use')

    # -------------------------------------
    parser = subparsers.add_parser(
        'configure',
        help='reconfigure the blockstackd server')
    parser.add_argument(
        '--working-dir', action='store',
        help='Directory with the chain state to use')

    # -------------------------------------
    parser = subparsers.add_parser(
        'clean',
        help='remove all blockstack database information')
    parser.add_argument(
        '--force', action='store_true',
        help='Do not confirm the request to delete.')
    parser.add_argument(
        '--working-dir', action='store',
        help='Directory with the chain state to use')

    # -------------------------------------
    parser = subparsers.add_parser(
        'restore',
        help="Restore the database from a backup")
    parser.add_argument(
        'block_number', nargs='?',
        help="The block number to restore from (if not given, the last backup will be used)")
    parser.add_argument(
        '--working-dir', action='store',
        help='Directory with the chain state to use')

    # -------------------------------------
    parser = subparsers.add_parser(
        'verifydb',
        help='verify an untrusted database against a known-good consensus hash')
    parser.add_argument(
        'block_height',
        help='the block height of the known-good consensus hash')
    parser.add_argument(
        'consensus_hash',
        help='the known-good consensus hash')
    parser.add_argument(
        'chainstate_dir',
        help='the path to the database directory to verify')
    parser.add_argument(
        '--expected-snapshots', action='store',
        help='path to a .snapshots file with the expected consensus hashes')
    parser.add_argument(
        '--working-dir', action='store',
        help='Directory with the chain state to use')

    # -------------------------------------
    parser = subparsers.add_parser(
        'version',
        help='Print version and exit')

    # -------------------------------------
    parser = subparsers.add_parser(
        'fast_sync',
        help='fetch and verify a recent known-good name database')
    parser.add_argument(
        'url', nargs='?',
        help='the URL to the name database snapshot')
    parser.add_argument(
        'public_keys', nargs='?',
        help='a CSV of public keys to use to verify the snapshot')
    parser.add_argument(
        '--num_required', action='store',
        help='the number of required signature matches')
    parser.add_argument(
        '--working-dir', action='store',
        help='Directory with the chain state to use')

    # -------------------------------------
    parser = subparsers.add_parser(
        'fast_sync_snapshot',
        help='make a fast-sync snapshot')
    parser.add_argument(
        'private_key',
        help='a private key to use to sign the snapshot')
    parser.add_argument(
        'path',
        help='the path to the resulting snapshot')
    parser.add_argument(
        'block_height', nargs='?',
        help='the block ID of the backup to use to make a fast-sync snapshot')
    parser.add_argument(
        '--working-dir', action='store',
        help='Directory with the chain state to use')

    # -------------------------------------
    parser = subparsers.add_parser(
        'fast_sync_sign',
        help='sign an existing fast-sync snapshot')
    parser.add_argument(
        'path', action='store',
        help='the path to the snapshot')
    parser.add_argument(
        'private_key', action='store',
        help='a private key to use to sign the snapshot')
    parser.add_argument(
        '--working-dir', action='store',
        help='Directory with the chain state to use')

    args, _ = argparser.parse_known_args(new_argv[1:])

    if args.action == 'version':
        print "Blockstack version: %s" % VERSION

    elif args.action == 'start':
        expected_snapshots = {}

        pid = read_pid_file(get_pidfile_path(working_dir))
        still_running = False
       
        use_api = None
        use_indexer = None
        if args.no_api:
            use_api = False

        if args.no_indexer:
            use_indexer = False

        if pid is not None:
           try:
               still_running = check_server_running(pid)
           except:
               log.error("Could not contact process {}".format(pid))
               sys.exit(1)
       
        if still_running:
           log.error("Blockstackd appears to be running already.  If not, please run '{} stop'".format(sys.argv[0]))
           sys.exit(1)

        # unclean shutdown?
        is_indexing = BlockstackDB.db_is_indexing(virtualchain_hooks, working_dir)
        if is_indexing:
            log.warning('Unclean shutdown detected!  Will attempt to restore from backups')

        if pid is not None and use_indexer is not False or is_indexing:
           # The server didn't shut down properly.
           # restore from back-up before running
           log.warning("Server did not shut down properly (stale PID {}, or indexing lockfile detected).  Restoring state from last known-good backup.".format(pid))

           # move any existing db information out of the way so we can start fresh.
           state_paths = BlockstackDB.get_state_paths(virtualchain_hooks, working_dir)
           need_backup = reduce( lambda x, y: x or y, map(lambda sp: os.path.exists(sp), state_paths), False )
           if need_backup:

               # have old state.  keep it around for later inspection
               target_dir = os.path.join( working_dir, 'crash.{}'.format(time.time()))
               os.makedirs(target_dir)
               for sp in state_paths:
                   if os.path.exists(sp):
                      target = os.path.join( target_dir, os.path.basename(sp) )
                      shutil.move( sp, target )

               log.warning("State from crash stored to '{}'".format(target_dir))

           blockstack_backup_restore(working_dir, None)

           # make sure we "stop"
           set_indexing(working_dir, False)
           BlockstackDB.db_set_indexing(False, virtualchain_hooks, working_dir)

        # use snapshots?
        if args.expected_snapshots is not None:
           expected_snapshots = load_expected_snapshots( args.expected_snapshots )
           if expected_snapshots is None:
               sys.exit(1)
        else:
           log.debug("No expected snapshots given")

        # we're definitely not running, so make sure this path is clear
        try:
           os.unlink(get_pidfile_path(working_dir))
        except:
           pass

        if args.foreground:
           log.info('Initializing blockstackd server in foreground (working dir = \'%s\')...' % (working_dir))
        else:
           log.info('Starting blockstackd server (working_dir = \'%s\') ...' % (working_dir))

        if args.port is not None:
           log.info("Binding on port %s" % int(args.port))
           args.port = int(args.port)
        else:
           args.port = None

        if args.api_port is not None:
            log.info('Binding RESTful API on port {}'.format(int(args.api_port)))
            args.api_port = int(args.api_port)
        else:
            args.api_port = None

        exit_status = run_server(working_dir, foreground=args.foreground, expected_snapshots=expected_snapshots, port=args.port, api_port=args.api_port, use_api=use_api, use_indexer=use_indexer, indexer_url=args.indexer_url)
        if args.foreground:
           log.info("Service endpoint exited with status code %s" % exit_status )

    elif args.action == 'stop':
        stop_server(working_dir, kill=True)

    elif args.action == 'configure':
        reconfigure(working_dir)

    elif args.action == 'restore':
        block_number = args.block_number
        if block_number is not None:
          block_number = int(block_number)

        pid = read_pid_file(get_pidfile_path(working_dir))
        still_running = False
       
        if pid is not None:
           try:
               still_running = check_server_running(pid)
           except:
               log.error("Could not contact process {}".format(pid))
               sys.exit(1)
       
        if still_running:
           log.error("Blockstackd appears to be running already.  If not, please run '{} stop'".format(sys.argv[0]))
           sys.exit(1)

        blockstack_backup_restore(working_dir, args.block_number)

        # make sure we're "stopped"
        set_indexing(working_dir, False)
        if os.path.exists(get_pidfile_path(working_dir)):
           os.unlink(get_pidfile_path(working_dir))

    elif args.action == 'verifydb':
        expected_snapshots = None
        if args.expected_snapshots is not None:
           expected_snapshots = load_expected_snapshots(args.expected_snapshots)
           if expected_snapshots is None:
               sys.exit(1)
     
        tmpdir = tempfile.mkdtemp('blockstack-verify-chainstate-XXXXXX')
        rc = verify_database(args.consensus_hash, int(args.block_height), args.chainstate_dir, tmpdir, expected_snapshots=expected_snapshots)
        if rc:
           # success!
           print "Database is consistent with %s" % args.consensus_hash
           print "Verified files are in '%s'" % working_dir

        else:
           # failure!
           print "Database is NOT CONSISTENT"

    elif args.action == 'fast_sync_snapshot':
        # create a fast-sync snapshot from the last backup
        dest_path = str(args.path)
        private_key = str(args.private_key)
        try:
           keylib.ECPrivateKey(private_key)
        except:
           print "Invalid private key"
           sys.exit(1)

        block_height = None
        if args.block_height is not None:
           block_height = int(args.block_height)

        rc = fast_sync_snapshot(working_dir, dest_path, private_key, block_height)
        if not rc:
           print "Failed to create snapshot"
           sys.exit(1)

    elif args.action == 'fast_sync_sign':
        # sign an existing fast-sync snapshot with an additional key
        snapshot_path = str(args.path)
        private_key = str(args.private_key)
        try:
           keylib.ECPrivateKey(private_key)
        except:
           print "Invalid private key"
           sys.exit(1)

        rc = fast_sync_sign_snapshot( snapshot_path, private_key )
        if not rc:
           print "Failed to sign snapshot"
           sys.exit(1)

    elif args.action == 'fast_sync':
        # fetch the snapshot and verify it
        if hasattr(args, 'url') and args.url:
           url = str(args.url)
        else:
           url = str(config.FAST_SYNC_DEFAULT_URL)

        public_keys = config.FAST_SYNC_PUBLIC_KEYS

        if args.public_keys is not None:
           public_keys = args.public_keys.split(',')
           for pubk in public_keys:
               try:
                   keylib.ECPublicKey(pubk)
               except:
                   print "Invalid public key"
                   sys.exit(1)

        num_required = len(public_keys)
        if args.num_required:
           num_required = int(args.num_required)

        print "Synchronizing from snapshot from {}.  This may take up to 15 minutes.".format(url)

        rc = fast_sync_import(working_dir, url, public_keys=public_keys, num_required=num_required, verbose=True)
        if not rc:
           print 'fast_sync failed'
           sys.exit(1)

        print "Node synchronized!  Node state written to {}".format(working_dir)
        print "Start your node with `blockstack-core start`"
        print "Pass `--debug` for extra output."

