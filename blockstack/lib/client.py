#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack.

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

import sys
import os

import xmlrpclib
from xmlrpclib import ServerProxy, Transport
from defusedxml import xmlrpc
import httplib
import base64
import jsonschema
from jsonschema.exceptions import ValidationError
import random
import json
import traceback
import re
import urllib2
import socket
from .util import url_to_host_port, url_protocol, parse_DID
from .config import MAX_RPC_LEN, BLOCKSTACK_DEBUG, RPC_SERVER_PORT, RPC_SERVER_TEST_PORT, LENGTHS, RPC_DEFAULT_TIMEOUT, BLOCKSTACK_TEST, get_blockstack_api_opts
from .schemas import *
from .scripts import is_name_valid, is_subdomain, check_name, check_subdomain
from .storage import verify_zonefile

import virtualchain
import keylib
import jsontokens
import blockstack_zones
import requests

log = virtualchain.get_logger('blockstackd-client')

# prevent the usual XML attacks
xmlrpc.MAX_DATA = MAX_RPC_LEN
xmlrpc.monkey_patch()

class TimeoutHTTPConnection(httplib.HTTPConnection):
    """
    borrowed with gratitude from Justin Cappos
    https://seattle.poly.edu/browser/seattle/trunk/demokit/timeout_xmlrpclib.py?rev=692
    """
    def connect(self):
        httplib.HTTPConnection.connect(self)
        self.sock.settimeout(self.timeout)


class TimeoutHTTPSConnection(httplib.HTTPSConnection):
    def connect(self):
        httplib.HTTPSConnection.connect(self)
        self.sock.settimeout(self.timeout)


class TimeoutHTTP(httplib.HTTP):
    _connection_class = TimeoutHTTPConnection

    def set_timeout(self, timeout):
        self._conn.timeout = timeout

    def getresponse(self, **kw):
        return self._conn.getresponse(**kw)


class TimeoutHTTPS(httplib.HTTP):
    _connection_class = TimeoutHTTPSConnection

    def set_timeout(self, timeout):
        self._conn.timeout = timeout

    def getresponse(self, **kw):
        return self._conn.getresponse(**kw)


class TimeoutTransport(Transport):
    def __init__(self, protocol, *l, **kw):
        self.timeout = kw.pop('timeout', 10)
        self.protocol = protocol
        if protocol not in ['http', 'https']:
            raise Exception("Protocol {} not supported".format(protocol))
        Transport.__init__(self, *l, **kw)

    def make_connection(self, host):
        if self.protocol == 'http':
            conn = TimeoutHTTP(host)
        elif self.protocol == 'https':
            conn = TimeoutHTTPS(host)

        conn.set_timeout(self.timeout)
        return conn


class TimeoutServerProxy(ServerProxy):
    def __init__(self, uri, protocol, *l, **kw):
        timeout = kw.pop('timeout', 10)
        use_datetime = kw.get('use_datetime', 0)
        kw['transport'] = TimeoutTransport(protocol, timeout=timeout, use_datetime=use_datetime)
        ServerProxy.__init__(self, uri, *l, **kw)


class BlockstackRPCClient(object):
    """
    RPC client for the blockstackd
    """
    def __init__(self, server, port, max_rpc_len=MAX_RPC_LEN,
                 timeout=RPC_DEFAULT_TIMEOUT, debug_timeline=False, protocol=None, **kw):

        if protocol is None:
            log.warn("RPC constructor called without a protocol, defaulting " +
                     "to HTTP, this could be an issue if connection is on :6263")
            protocol = 'http'

        self.url = '{}://{}:{}'.format(protocol, server, port)
        self.srv = TimeoutServerProxy(self.url, protocol, timeout=timeout, allow_none=True)
        self.server = server
        self.port = port
        self.debug_timeline = debug_timeline


    def log_debug_timeline(self, event, key, r=-1):
        # random ID to match in logs
        r = random.randint(0, 2 ** 16) if r == -1 else r
        if self.debug_timeline:
            log.debug('RPC({}) {} {} {}'.format(r, event, self.url, key))
        return r


    def __getattr__(self, key):
        try:
            return object.__getattr__(self, key)
        except AttributeError:
            r = self.log_debug_timeline('begin', key)

            def inner(*args, **kw):
                func = getattr(self.srv, key)
                res = func(*args, **kw)
                if res is None:
                    self.log_debug_timeline('end', key, r)
                    return

                # lol jsonrpc within xmlrpc
                try:
                    res = json.loads(res)
                except (ValueError, TypeError):
                    msg = 'Server replied invalid JSON'
                    if BLOCKSTACK_TEST is not None:
                        log.debug('{}: {}'.format(msg, res))

                    log.error(msg)
                    res = {'error': msg}

                except xmlrpclib.ProtocolError as pe:
                    msg = 'Server replied ProtocolError: {} {}'.format(pe.errcode, pe.errmsg)
                    if BLOCKSTACK_TEST is not None:
                        log.debug('{}: {}'.format(msg, res))

                    log.error(msg)
                    res = {'error': msg}

                self.log_debug_timeline('end', key, r)
                return res

            return inner


def json_is_error(resp):
    """
    Is the given response object
    (be it a string, int, or dict)
    an error message?

    Return True if so
    Return False if not
    """

    if not isinstance(resp, dict):
        return False

    return 'error' in resp or 'traceback' in resp


def json_is_exception(resp):
    """
    Is the given response object
    an exception traceback?

    Return True if so
    Return False if not
    """
    if not json_is_error(resp):
        return False

    if 'traceback' not in resp.keys() or 'error' not in resp.keys():
        return False

    return True


def json_validate_error(resp):
    """
    See if this is a well-formed error
    """
    error_schema = {
        'type': 'object',
        'properties': {
            'error': {
                'type': 'string',
            },
            'http_status': {
                'type': 'integer',
            },
        },
        'required': [
            'error',
            'http_status',
        ]
    }

    jsonschema.validate(resp, error_schema)
    return True


def json_validate(schema, resp):
    """
    Validate an RPC response.
    The response must either take the
    form of the given schema, or it must
    take the form of {'error': ...}

    Returns the resp on success
    Returns {'error': ...} on validation error
    """
    # is this an error?
    try:
        json_validate_error(resp)
    except ValidationError:
        if json_is_exception(resp):
            # got a traceback 
            if BLOCKSTACK_TEST:
                log.error('\n{}'.format(resp['traceback']))

            return {'error': 'Blockstack Core encountered an exception. See `traceback` for details', 'traceback': resp['traceback'], 'http_status': 500}

        if 'error' in resp and 'http_status' not in resp:
            # invalid error message (shouldn't happen)
            raise 

        # not an error.
        jsonschema.validate(resp, schema)

    return resp


def json_traceback(error_msg=None):
    """
    Generate a stack trace as a JSON-formatted error message.
    Optionally use error_msg as the error field.
    Return {'error': ..., 'traceback'...}
    """

    exception_data = traceback.format_exc().splitlines()
    if error_msg is None:
        error_msg = '\n'.join(exception_data)
    else:
        error_msg = 'Remote RPC error: {}'.format(error_msg)

    return {
        'error': error_msg,
        'traceback': exception_data
    }


def json_response_schema( expected_object_schema ):
    """
    Make a schema for a "standard" server response.
    Standard server responses have 'status': True
    and possibly 'indexing': True set.
    """
    schema = {
        'type': 'object',
        'properties': {
            'status': {
                'type': 'boolean',
            },
            'indexing': {
                'type': 'boolean',
            },
            'lastblock': {
                'anyOf': [
                    {
                        'type': 'integer',
                        'minimum': 0,
                    },
                    {
                        'type': 'null',
                    },
                ],
            },
        },
        'required': [
            'status',
            'indexing',
            'lastblock'
        ],
    }

    # fold in the given object schema
    schema['properties'].update( expected_object_schema['properties'] )
    schema['required'] = list(set( schema['required'] + expected_object_schema['required'] ))

    return schema


def get_blockstackd_url():
    """
    Get the URL to the blockstackd RPC server instance
    """
    conf = get_blockstack_api_opts()
    if conf is None:
        return None
    
    if not conf['enabled']:
        return None

    return conf['indexer_url']


def connect_hostport(hostport, timeout=RPC_DEFAULT_TIMEOUT, my_hostport=None):
    """
    Connect to the given "host:port" string
    Returns a BlockstackRPCClient instance
    """
    host, port = url_to_host_port(hostport)

    assert host is not None and port is not None

    protocol = url_protocol(hostport)
    if protocol is None:
        log.warning("No scheme given in {}. Guessing by port number".format(hostport))
        if port == RPC_SERVER_PORT or port == RPC_SERVER_TEST_PORT:
            protocol = 'http'
        else:
            protocol = 'https'

    proxy = BlockstackRPCClient(host, port, timeout=timeout, src=my_hostport, protocol=protocol)
    return proxy


def create_bitcoind_service_proxy(rpc_username, rpc_password, server='127.0.0.1', port=8332, use_https=False):
    """
    create a bitcoind service proxy
    """
    assert BLOCKSTACK_TEST, 'create_bitcoind_service_proxy can only be used in test mode!'

    protocol = 'https' if use_https else 'http'
    uri = '%s://%s:%s@%s:%s' % (protocol, rpc_username, rpc_password, server, port)
    return virtualchain.AuthServiceProxy(uri)


def ping(proxy=None, hostport=None):
    """
    rpc_ping
    Returns {'alive': True} on succcess
    Returns {'error': ...} on error
    """
    schema = {
        'type': 'object',
        'properties': {
            'status': {
                'type': 'string'
            },
        },
        'required': [
            'status'
        ]
    }

    assert proxy or hostport, 'Need either proxy handle or hostport string'
    if proxy is None:
        proxy = connect_hostport(hostport)

    resp = {}

    try:
        resp = proxy.ping()
        resp = json_validate( schema, resp )
        if json_is_error(resp):
            return resp

        assert resp['status'] == 'alive'

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return resp


def getinfo(proxy=None, hostport=None):
    """
    getinfo
    Returns server info on success
    Returns {'error': ...} on error
    """
    schema = {
        'type': 'object',
        'properties': {
            'last_block_seen': {
                'type': 'integer',
                'minimum': 0,
            },
            'consensus': {
                'type': 'string'
            },
            'server_version': {
                'type': 'string'
            },
            'last_block_processed': {
                'type': 'integer',
                'minimum': 0,
            },
            'server_alive': {
                'type': 'boolean'
            },
            'zonefile_count': {
                'type': 'integer',
                'minimum': 0,
            },
            'indexing': {
                'type': 'boolean'
            },
            'stale': {
                'type': 'boolean',
            },
            'warning': {
                'type': 'string',
            }
        },
        'required': [
            'last_block_seen',
            'consensus',
            'server_version',
            'last_block_processed',
            'server_alive',
            'indexing'
        ]
    }

    resp = {}

    assert proxy or hostport, 'Need either proxy handle or hostport string'
    if proxy is None:
        proxy = connect_hostport(hostport)

    try:
        resp = proxy.getinfo()
        old_resp = resp
        resp = json_validate( schema, resp )
        if json_is_error(resp):
            if BLOCKSTACK_TEST:
                log.debug("invalid response: {}".format(old_resp))

            return resp

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return resp


def get_zonefile_inventory(hostport, offset, count, timeout=30, my_hostport=None, proxy=None):
    """
    Get the atlas zonefile inventory from the given peer.
    Return {'status': True, 'inv': inventory} on success.
    Return {'error': ...} on error
    """
    
    assert hostport or proxy, 'Need either hostport or proxy'

    inv_schema = {
        'type': 'object',
        'properties': {
            'inv': {
                'type': 'string',
                'pattern': OP_BASE64_EMPTY_PATTERN
            },
        },
        'required': [
            'inv'
        ]
    }

    schema = json_response_schema( inv_schema )

    if proxy is None:
        proxy = connect_hostport(hostport)

    zf_inv = None
    try:
        zf_inv = proxy.get_zonefile_inventory(offset, count)
        zf_inv = json_validate(schema, zf_inv)
        if json_is_error(zf_inv):
            return zf_inv

        # decode
        zf_inv['inv'] = base64.b64decode(str(zf_inv['inv']))

        # make sure it corresponds to this range
        assert len(zf_inv['inv']) <= count, 'Zonefile inventory in is too long (got {} bytes)'.format(len(zf_inv['inv']))

    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except AssertionError as ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        resp = {'error': 'Server replied an invalid zone file inventory vector'}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return zf_inv


def get_atlas_peers(hostport, timeout=30, my_hostport=None, proxy=None):
    """
    Get an atlas peer's neighbors. 
    Return {'status': True, 'peers': [peers]} on success.
    Return {'error': ...} on error
    """
    assert hostport or proxy, 'need either hostport or proxy'

    peers_schema = {
        'type': 'object',
        'properties': {
            'peers': {
                'type': 'array',
                'items': {
                    'type': 'string',
                    'pattern': '^([^:]+):([1-9][0-9]{1,4})$',
                },
            },
        },
        'required': [
            'peers'
        ],
    }

    schema = json_response_schema( peers_schema )

    if proxy is None:
        proxy = connect_hostport(hostport)

    peers = None
    try:
        peer_list_resp = proxy.get_atlas_peers()
        peer_list_resp = json_validate(schema, peer_list_resp)
        if json_is_error(peer_list_resp):
            return peer_list_resp

        # verify that all strings are host:ports
        for peer_hostport in peer_list_resp['peers']:
            peer_host, peer_port = url_to_host_port(peer_hostport)
            if peer_host is None or peer_port is None:
                return {'error': 'Server did not return valid Atlas peers', 'http_status': 503}

        peers = peer_list_resp

    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node {}.  Try again with `--debug`.'.format(hostport), 'http_status': 500}
        return resp

    return peers


def atlas_peer_exchange(hostport, my_hostport, timeout=30, proxy=None):
    """
    Get an atlas peer's neighbors, and list ourselves as a possible peer.
    Return {'status': True, 'peers': [peers]} on success.
    Return {'error': ...} on error
    """
    assert hostport or proxy, 'need either hostport or proxy'

    peers_schema = {
        'type': 'object',
        'properties': {
            'peers': {
                'type': 'array',
                'items': {
                    'type': 'string',
                    'pattern': '^([^:]+):([1-9][0-9]{1,4})$',
                },
            },
        },
        'required': [
            'peers'
        ],
    }

    schema = json_response_schema( peers_schema )

    if proxy is None:
        proxy = connect_hostport(hostport)

    peers = None
    try:
        peer_list_resp = proxy.atlas_peer_exchange(my_hostport)
        peer_list_resp = json_validate(schema, peer_list_resp)
        if json_is_error(peer_list_resp):
            return peer_list_resp

        # verify that all strings are host:ports
        for peer_hostport in peer_list_resp['peers']:
            peer_host, peer_port = url_to_host_port(peer_hostport)
            if peer_host is None or peer_port is None:
                return {'error': 'Server did not return valid Atlas peers', 'http_status': 503}

        peers = peer_list_resp

    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node {}.  Try again with `--debug`.'.format(hostport), 'http_status': 500}
        return resp

    return peers


def get_zonefiles(hostport, zonefile_hashes, timeout=30, my_hostport=None, proxy=None):
    """
    Get a set of zonefiles from the given server.  Used primarily by Atlas.
    Return {'status': True, 'zonefiles': {hash: data, ...}} on success
    Return {'error': ...} on error
    """

    assert hostport or proxy, 'need either hostport or proxy'

    zonefiles_schema = {
        'type': 'object',
        'properties': {
            'zonefiles': {
                'type': 'object',
                'patternProperties': {
                    OP_ZONEFILE_HASH_PATTERN: {
                        'type': 'string',
                        'pattern': OP_BASE64_EMPTY_PATTERN
                    },
                },
            },
        },
        'required': [
            'zonefiles',
        ]
    }

    schema = json_response_schema( zonefiles_schema )

    if proxy is None:
        proxy = connect_hostport(hostport)

    zonefiles = None
    try:
        zf_payload = proxy.get_zonefiles(zonefile_hashes)
        zf_payload = json_validate(schema, zf_payload)
        if json_is_error(zf_payload):
            return zf_payload

        decoded_zonefiles = {}

        for zf_hash, zf_data_b64 in zf_payload['zonefiles'].items():
            zf_data = base64.b64decode( zf_data_b64 )
            assert verify_zonefile( zf_data, zf_hash ), "Zonefile data mismatch"

            # valid
            decoded_zonefiles[ zf_hash ] = zf_data

        # return this
        zf_payload['zonefiles'] = decoded_zonefiles
        zonefiles = zf_payload

    except AssertionError as ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        zonefiles = {'error': 'Zonefile data mismatch'}
        return zonefiles

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        zonefiles = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return zonefiles

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return zonefiles


def put_zonefiles(hostport, zonefile_data_list, timeout=30, my_hostport=None, proxy=None):
    """
    Push one or more zonefiles to the given server.
    Each zone file in the list must be base64-encoded

    Return {'status': True, 'saved': [...]} on success
    Return {'error': ...} on error
    """
    assert hostport or proxy, 'need either hostport or proxy'

    saved_schema = {
        'type': 'object',
        'properties': {
            'saved': {
                'type': 'array',
                'items': {
                    'type': 'integer',
                    'minimum': 0,
                    'maximum': 1,
                },
                'minItems': len(zonefile_data_list),
                'maxItems': len(zonefile_data_list)
            },
        },
        'required': [
            'saved'
        ]
    }

    schema = json_response_schema( saved_schema )
    
    if proxy is None:
        proxy = connect_hostport(hostport)

    push_info = None
    try:
        push_info = proxy.put_zonefiles(zonefile_data_list)
        push_info = json_validate(schema, push_info)
        if json_is_error(push_info):
            return push_info

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return push_info


def get_zonefiles_by_block(from_block, to_block, hostport=None, proxy=None):
    """
    Get zonefile information for zonefiles announced in [@from_block, @to_block]
    Returns { 'last_block' : server's last seen block,
              'zonefile_info' : [ { 'zonefile_hash' : '...',
                                    'txid' : '...',
                                    'block_height' : '...' } ] }
    """
    assert hostport or proxy, 'need either hostport or proxy'
    if proxy is None:
        proxy = connect_hostport(hostport)

    zonefile_info_schema = {
        'type' : 'array',
        'items' : {
            'type' : 'object',
            'properties' : {
                'name' : {'type' : 'string'},
                'zonefile_hash' : { 'type' : 'string',
                                    'pattern' : OP_ZONEFILE_HASH_PATTERN },
                'txid' : {'type' : 'string',
                          'pattern' : OP_TXID_PATTERN},
                'block_height' : {'type' : 'integer'}
            },
            'required' : [ 'zonefile_hash', 'txid', 'block_height' ]
        }
    }
    response_schema = {
        'type' : 'object',
        'properties' : {
            'lastblock' : {'type' : 'integer'},
            'zonefile_info' : zonefile_info_schema
        },
        'required' : ['lastblock', 'zonefile_info']
    }

    offset = 0
    output_zonefiles = []
    last_server_block = 0

    resp = {'zonefile_info': []}
    while offset == 0 or len(resp['zonefile_info']) > 0:

        resp = proxy.get_zonefiles_by_block(from_block, to_block, offset, 100)
        if 'error' in resp:
            return resp

        resp = json_validate(response_schema, resp)
        if json_is_error(resp):
            return resp

        output_zonefiles += resp['zonefile_info']
        offset += 100
        last_server_block = max(resp['lastblock'], last_server_block)

    return { 'last_block' : last_server_block,
             'zonefile_info' : output_zonefiles }


def get_name_record(name, include_history=False, include_expired=False, include_grace=True, proxy=None, hostport=None,
                    history_page=None):
    """
    Get the record for a name or a subdomain.  Optionally include its history, and optionally return an expired name or a name in its grace period.
    Return the blockchain-extracted information on success.
    Return {'error': ...} on error
        In particular, return {'error': 'Not found.'} if the name isn't registered

    If include_expired is True, then a name record will be returned even if it expired
    If include_expired is False, but include_grace is True, then the name record will be returned even if it is expired and in the grace period
    """
    if isinstance(name, (str,unicode)):
        # coerce string
        name = str(name)

    assert proxy or hostport, 'Need either proxy handle or hostport string'
    if proxy is None:
        proxy = connect_hostport(hostport)
    
    # what do we expect?
    required = None
    is_blockstack_id = False
    is_blockstack_subdomain = False

    if is_name_valid(name):
        # full name
        required = NAMEOP_SCHEMA_REQUIRED[:]
        is_blockstack_id = True

    elif is_subdomain(name):
        # subdomain 
        required = SUBDOMAIN_SCHEMA_REQUIRED[:]
        is_blockstack_subdomain = True

    else:
        # invalid
        raise ValueError("Not a valid name or subdomain: {}".format(name))
        
    if include_history:
        required += ['history']

    nameop_schema = {
        'type': 'object',
        'properties': NAMEOP_SCHEMA_PROPERTIES,
        'required': required
    }

    rec_schema = {
        'type': 'object',
        'properties': {
            'record': nameop_schema,
        },
        'required': [
            'record'
        ],
    }

    resp_schema = json_response_schema(rec_schema)

    resp = {}
    lastblock = None
    try:
        if include_history:
            resp = get_name_and_history(name, proxy=proxy, history_page=history_page)
            if 'error' in resp:
                # fall back to legacy path
                log.debug(resp)
                resp = proxy.get_name_blockchain_record(name)
        else:
            resp = proxy.get_name_record(name)

        resp = json_validate(resp_schema, resp)
        if json_is_error(resp):
            if resp['error'] == 'Not found.':
                return {'error': 'Not found.', 'http_status': resp.get('http_status', 404)}

            return resp

        lastblock = resp['lastblock']

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp
    
    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    if not include_expired and is_blockstack_id:
        # check expired
        if lastblock is None:
            return {'error': 'No lastblock given from server', 'http_status': 503}

        if include_grace:
            # only care if the name is beyond the grace period
            if lastblock >= int(resp['record']['renewal_deadline']) and int(resp['record']['renewal_deadline']) > 0:
                return {'error': 'Name expired', 'http_status': 404}

            elif int(resp['record']['renewal_deadline']) > 0 and lastblock >= int(resp['record']['expire_block']) and lastblock < int(resp['record']['renewal_deadline']):
                resp['record']['grace_period'] = True

            else:
                resp['record']['grace_period'] = False

        else:
            # only care about expired, even if it's in the grace period
            if lastblock > int(resp['record']['expire_block']) and int(resp['record']['expire_block']) > 0:
                return {'error': 'Name expired', 'http_status': 404}

    return resp['record']


def get_namespace_record(namespace_id, proxy=None, hostport=None):
    """
    Get the blockchain record for a namespace.
    Returns the dict on success
    Returns {'error': ...} on failure
    """

    assert proxy or hostport, 'Need either proxy handle or hostport string'
    if proxy is None:
        proxy = connect_hostport(hostport)
    
    namespace_schema = {
        'type': 'object',
        'properties': NAMESPACE_SCHEMA_PROPERTIES,
        'required': NAMESPACE_SCHEMA_REQUIRED
    }

    rec_schema = {
        'type': 'object',
        'properties': {
            'record': namespace_schema,
        },
        'required': [
            'record',
        ],
    }

    resp_schema = json_response_schema( rec_schema )
            
    ret = {}
    try:
        ret = proxy.get_namespace_blockchain_record(namespace_id)
        ret = json_validate(resp_schema, ret)
        if json_is_error(ret):
            return ret

        ret = ret['record']

        # this isn't needed
        ret.pop('opcode', None)

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return ret


def get_name_cost(name, proxy=None, hostport=None):
    """
    name_cost
    Returns the name cost info on success
    Returns {'amount': ..., 'units': ...} on success
    Returns {'error': ...} on error
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    cost_schema_v1 = {
        'type': 'object',
        'properties': {
            'satoshis': {
                'type': 'integer',
                'minimum': 0,
            },
        },
        'required': [
            'satoshis'
        ]
    }

    cost_schema_v2 = {
        'type': 'object',
        'properties': {
            'units': {
                'type': 'string',
            },
            'amount': {
                'type': 'integer',
                'minimum': 0,
            },
        },
        'required': [
            'units',
            'amount',
        ]
    }

    resp_version = None
    resp_schema_v1 = json_response_schema(cost_schema_v1)
    resp_schema_v2 = json_response_schema(cost_schema_v2)

    resp = {}
    try:
        resp = proxy.get_name_cost(name)
        try:
            resp = json_validate(resp_schema_v2, resp)
        except:
            resp = json_validate(resp_schema_v1, resp)
            if not json_is_error(resp):
                resp = {'units': 'BTC', 'amount': resp['satoshis']}

        if json_is_error(resp):
            return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return resp


def get_namespace_cost(namespace_id, proxy=None, hostport=None):
    """
    namespace_cost
    Returns the namespace cost info on success.
    Returns {'amount': ..., 'units': ...} on success (optionally with 'satoshis': ... if the namespace is priced in BTC)
    Returns {'error': ...} on error
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    cost_schema_v1 = {
        'type': 'object',
        'properties': {
            'satoshis': {
                'type': 'integer',
                'minimum': 0,
            },
        },
        'required': [
            'satoshis'
        ],
    }

    cost_schema_v2 = {
        'type': 'object',
        'properties': {
            'units': {
                'type': 'string',
                'pattern': '^BTC$|^STACKS$'
            },
            'amount': {
                'type': 'integer',
                'minimum': 0,
            },
        },
        'required': [
            'units',
            'amount',
        ],
    }

    schema_v1 = json_response_schema(cost_schema_v1)
    schema_v2 = json_response_schema(cost_schema_v2)

    resp = {}
    try:
        resp = proxy.get_namespace_cost(namespace_id)
        try:
            resp = json_validate(cost_schema_v2, resp)
        except:
            resp = json_validate(cost_schema_v1, resp)
            if not json_is_error(resp):
                resp = {'units': 'BTC', 'amount': resp['satoshis']}

        if json_is_error(resp):
            return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return resp


def get_all_names_page(offset, count, include_expired=False, hostport=None, proxy=None):
    """
    get a page of all the names
    Returns the list of names on success
    Returns {'error': ...} on error
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    page_schema = {
        'type': 'object',
        'properties': {
            'names': {
                'type': 'array',
                'items': {
                    'type': 'string',
                    'uniqueItems': True
                },
            },
        },
        'required': [
            'names',
        ],
    }

    schema = json_response_schema(page_schema)

    try:
        assert count <= 100, 'Page too big: {}'.format(count)
    except AssertionError as ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        return {'error': 'Invalid page', 'http_status': 400}

    resp = {}
    try:
        if include_expired:
            resp = proxy.get_all_names_cumulative(offset, count)
        else:
            resp = proxy.get_all_names(offset, count)

        resp = json_validate(schema, resp)
        if json_is_error(resp):
            return resp

        # must be valid names
        valid_names = []
        for n in resp['names']:
            if not is_name_valid(str(n)):
                log.error('Invalid name "{}"'.format(str(n)))
            else:
                valid_names.append(n)

        resp['names'] = valid_names

    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)
        
        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return resp['names']


def get_num_names(include_expired=False, proxy=None, hostport=None):
    """
    Get the number of names, optionally counting the expired ones
    Return {'error': ...} on failure
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    schema = {
        'type': 'object',
        'properties': {
            'count': {
                'type': 'integer',
                'minimum': 0,
            },
        },
        'required': [
            'count',
        ],
    }

    count_schema = json_response_schema(schema)

    resp = {}
    try:
        if include_expired:
            resp = proxy.get_num_names_cumulative()
        else:
            resp = proxy.get_num_names()

        resp = json_validate(count_schema, resp)
        if json_is_error(resp):
            return resp

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return resp['count']


def get_num_subdomains(proxy=None, hostport=None):
    """
    Get the number of subdomains registered
    Return integer count on success
    Return {'error': ...} on failure
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    count_schema = {
        'type': 'object',
        'properties': {
            'count': {
                'type': 'integer',
                'minimum': 0
            },
        },
        'required': [
            'count'
        ]
    }

    schema = json_response_schema(count_schema)

    try:
        resp = proxy.get_num_subdomains()
        resp = json_validate(schema, resp)
        if json_is_error(resp):
            return resp

    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return resp['count']


def get_all_subdomains(offset=0, count=100, proxy=None, hostport=None):
    """
    Get all subdomains within the given range.
    Return the list of names on success
    Return {'error': ...} on failure
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    offset = int(offset)
    count = int(count)

    page_schema = {
        'type': 'object',
        'properties': {
            'names': {
                'type': 'array',
                'items': {
                    'type': 'string',
                    'uniqueItems': True
                },
            },
        },
        'required': [
            'names',
        ],
    }

    schema = json_response_schema(page_schema)

    try:
        resp = proxy.get_all_subdomains(offset, count)
        resp = json_validate(schema, resp)
        if json_is_error(resp):
            return resp

        for name in resp['names']:
            if not is_subdomain(str(name)):
                raise ValidationError('Invalid subdomain {}'.format(str(name)))

    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return resp['names']


def get_all_names(offset=None, count=None, include_expired=False, proxy=None, hostport=None):
    """
    Get all names within the given range.
    Return the list of names on success
    Return {'error': ...} on failure
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    offset = 0 if offset is None else offset

    if count is None:
        # get all names after this offset
        count = get_num_names(proxy=proxy, hostport=hostport)
        if json_is_error(count):
            # error
            return count

        count -= offset

    page_size = 100
    all_names = []
    while len(all_names) < count:
        request_size = page_size
        if count - len(all_names) < request_size:
            request_size = count - len(all_names)

        page = get_all_names_page(offset + len(all_names), request_size, include_expired=include_expired, proxy=proxy, hostport=hostport)
        if json_is_error(page):
            # error
            return page

        if len(page) > request_size:
            # error
            error_str = 'server replied too much data'
            return {'error': error_str, 'http_status': 503}
        elif len(page) == 0:
            # end-of-table
            break

        all_names += page

    return all_names


def get_all_namespaces(offset=None, count=None, proxy=None, hostport=None):
    """
    Get all namespaces
    Return the list of namespaces on success
    Return {'error': ...} on failure

    TODO: make this scale like get_all_names
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    offset = 0 if offset is None else offset

    schema = {
        'type': 'object',
        'properties': {
            'namespaces': {
                'type': 'array',
                'items': {
                    'type': 'string',
                    'pattern': OP_NAMESPACE_PATTERN,
                },
            },
        },
        'required': [
            'namespaces'
        ],
    }

    namespaces_schema = json_response_schema(schema)

    resp = {}
    try:
        resp = proxy.get_all_namespaces()
        resp = json_validate(namespaces_schema, resp)
        if json_is_error(resp):
            return resp

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    stride = len(resp['namespaces']) if count is None else offset + count
    return resp['namespaces'][offset:stride]


def get_names_in_namespace_page(namespace_id, offset, count, proxy=None, hostport=None):
    """
    Get a page of names in a namespace
    Returns the list of names on success
    Returns {'error': ...} on error
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    assert count <= 100, 'Page too big: {}'.format(count)

    names_schema = {
        'type': 'object',
        'properties': {
            'names': {
                'type': 'array',
                'items': {
                    'type': 'string',
                    'uniqueItems': True
                },
            },
        },
        'required': [
            'names',
        ],
    }

    schema = json_response_schema( names_schema )
    resp = {}
    try:
        resp = proxy.get_names_in_namespace(namespace_id, offset, count)
        resp = json_validate(schema, resp)
        if json_is_error(resp):
            return resp

        # must be valid names
        valid_names = []
        for n in resp['names']:
            if not is_name_valid(str(n)):
                log.error('Invalid name "{}"'.format(str(n)))
            else:
                valid_names.append(n)

        return valid_names

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp


def get_num_names_in_namespace(namespace_id, proxy=None, hostport=None):
    """
    Get the number of names in a namespace
    Returns the count on success
    Returns {'error': ...} on error
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    num_names_schema = {
        'type': 'object',
        'properties': {
            'count': {
                'type': 'integer',
                'minimum': 0,
            },
        },
        'required': [
            'count',
        ],
    }

    schema = json_response_schema( num_names_schema )
    resp = {}
    try:
        resp = proxy.get_num_names_in_namespace(namespace_id)
        resp = json_validate(schema, resp)
        if json_is_error(resp):
            return resp

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return resp['count']


def get_names_in_namespace(namespace_id, offset=None, count=None, proxy=None, hostport=None):
    """
    Get all names in a namespace
    Returns the list of names on success
    Returns {'error': ..} on error
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    offset = 0 if offset is None else offset
    if count is None:
        # get all names in this namespace after this offset
        count = get_num_names_in_namespace(namespace_id, proxy=proxy, hostport=hostport)
        if json_is_error(count):
            return count

        count -= offset

    page_size = 100
    all_names = []
    while len(all_names) < count:
        request_size = page_size
        if count - len(all_names) < request_size:
            request_size = count - len(all_names)

        page = get_names_in_namespace_page(namespace_id, offset + len(all_names), request_size, proxy=proxy, hostport=hostport)
        if json_is_error(page):
            # error
            return page

        if len(page) > request_size:
            # error
            error_str = 'server replied too much data'
            return {'error': error_str, 'http_status': 503}
        elif len(page) == 0:
            # end-of-table
            break

        all_names += page

    return all_names[:count]


def get_names_owned_by_address(address, proxy=None, hostport=None):
    """
    Get the names owned by an address.
    Returns the list of names on success
    Returns {'error': ...} on error
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    owned_schema = {
        'type': 'object',
        'properties': {
            'names': {
                'type': 'array',
                'items': {
                    'type': 'string',
                    'uniqueItems': True
                },
            },
        },
        'required': [
            'names',
        ],
    }

    schema = json_response_schema( owned_schema )

    resp = {}
    try:
        resp = proxy.get_names_owned_by_address(address)
        resp = json_validate(schema, resp)
        if json_is_error(resp):
            return resp

        # names must be valid
        for n in resp['names']:
            assert is_name_valid(str(n)), ('Invalid name "{}"'.format(str(n)))

    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except AssertionError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Got an invalid name from the server'}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return resp['names']


def get_subdomains_owned_by_address(address, proxy=None, hostport=None):
    """
    Get the list of subdomains owned by a particular address
    Returns the list of subdomains on succes
    Returns {'error': ...} on error
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    owned_schema = {
        'type': 'object',
        'properties': {
            'subdomains': {
                'type': 'array',
                'items': {
                    'type': 'string',
                    'uniqueItems': True
                },
            },
        },
        'required': [
            'subdomains',
        ],
    }

    schema = json_response_schema(owned_schema)

    resp = {}
    try:
        resp = proxy.get_subdomains_owned_by_address(address)
        resp = json_validate(schema, resp)
        if json_is_error(resp):
            return resp

        # names must be valid
        for n in resp['subdomains']:
            assert is_subdomain(str(n)), ('Invalid subdomain "{}"'.format(str(n)))

    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except AssertionError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Server response included an invalid subdomain'}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return resp['subdomains']


def get_name_DID(name, proxy=None, hostport=None):
    """
    Get the DID for a name or subdomain
    Return the DID string on success
    Return None if not found
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    did_schema = {
        'type': 'object',
        'properties': {
            'did': {
                'type': 'string'
            }
        },
        'required': [ 'did' ],
    }

    schema = json_response_schema(did_schema)
    resp = {}
    try:
        resp = proxy.get_name_DID(name)
        resp = json_validate(schema, resp)
        if json_is_error(resp):
            return resp

        # DID must be well-formed
        assert parse_DID(resp['did'])

    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp
    
    except AssertionError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Server replied an unparseable DID'}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return resp['did']


def get_DID_record(did, proxy=None, hostport=None):
    """
    Resolve a Blockstack decentralized identifier (DID) to its blockchain record.
    Works for names and subdomains.

    DID format: did:stack:v0:${address}-${name_index}, where:
    * address is the address that created the name this DID references (version byte 0 or 5)
    * name_index is the nth name ever created by this address.

    Returns the blockchain record on success
    Returns {'error': ...} on failure
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)
 
    # what do we expect?
    required = None
    is_blockstack_id = False
    is_blockstack_subdomain = False

    did_info = parse_DID(did)
    if did_info['name_type'] == 'name':
        # full name
        required = NAMEOP_SCHEMA_REQUIRED[:]
        is_blockstack_id = True
        
    elif did_info['name_type'] == 'subdomain':
        # subdomain 
        required = SUBDOMAIN_SCHEMA_REQUIRED[:]
        is_blockstack_subdomain = True

    else:
        # invalid
        raise ValueError("Not a valid name or subdomain DID: {}".format(did))
        
    nameop_schema = {
        'type': 'object',
        'properties': NAMEOP_SCHEMA_PROPERTIES,
        'required': required
    }

    rec_schema = {
        'type': 'object',
        'properties': {
            'record': nameop_schema,
        },
        'required': [
            'record'
        ],
    }

    resp_schema = json_response_schema(rec_schema)
    resp = {}

    try:
        resp = proxy.get_DID_record(did)
        resp = json_validate(resp_schema, resp)
        if json_is_error(resp):
            return resp

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    final_name_state = resp['record']

    # remove extra fields that shouldn't be present
    for extra_field in ['expired', 'expire_block', 'renewal_deadline']:
        if extra_field in final_name_state:
            del final_name_state[extra_field]

    return final_name_state
 

def get_consensus_at(block_height, proxy=None, hostport=None):
    """
    Get consensus at a block
    Returns the consensus hash on success
    Returns {'error': ...} on error
    """
    assert proxy or hostport, 'Need either proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    consensus_schema = {
        'type': 'object',
        'properties': {
            'consensus': {
                'anyOf': [
                    {
                        'type': 'string',
                        'pattern': OP_CONSENSUS_HASH_PATTERN,
                    },
                    {
                        'type': 'null'
                    },
                ],
            },
        },
        'required': [
            'consensus',
        ],
    }

    resp_schema = json_response_schema( consensus_schema )
    resp = {}
    try:
        resp = proxy.get_consensus_at(block_height)
        resp = json_validate(resp_schema, resp)
        if json_is_error(resp):
            return resp

    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    if resp['consensus'] is None:
        # node hasn't processed this block 
        return {'error': 'The node has not processed block {}'.format(block_height), 'http_status': 503}

    return resp['consensus']


def get_blockstack_transactions_at(block_id, proxy=None, hostport=None):
    """
    Get the *prior* states of the blockstack records that were
    affected at the given block height.
    Return the list of name records at the given height on success.
    Return {'error': ...} on error.
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    history_schema = {
        'type': 'array',
        'items': {
            'type': 'object',
            'properties': OP_HISTORY_SCHEMA['properties'],
            'required': [
                'op',
                'opcode',
                'txid',
                'vtxindex',
            ]
        }
    }

    nameop_history_schema = {
        'type': 'object',
        'properties': {
            'nameops': history_schema,
        },
        'required': [
            'nameops',
        ],
    }

    history_count_schema = {
        'type': 'object',
        'properties': {
            'count': {
                'type': 'integer',
                'minimum': 0,
            },
        },
        'required': [
            'count',
        ],
    }
    
    count_schema = json_response_schema( history_count_schema )
    nameop_schema = json_response_schema( nameop_history_schema )

    # how many nameops?
    num_nameops = None
    try:
        num_nameops = proxy.get_num_blockstack_ops_at(block_id)
        num_nameops = json_validate(count_schema, num_nameops)
        if json_is_error(num_nameops):
            return num_nameops

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    num_nameops = num_nameops['count']

    # grab at most 10 of these at a time
    all_nameops = []
    page_size = 10
    while len(all_nameops) < num_nameops:
        resp = {}
        try:
            resp = proxy.get_blockstack_ops_at(block_id, len(all_nameops), page_size)
            resp = json_validate(nameop_schema, resp)
            if json_is_error(resp):
                return resp

            if len(resp['nameops']) == 0:
                return {'error': 'Got zero-length nameops reply', 'http_status': 503}

            all_nameops += resp['nameops']

        except ValidationError as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
            return resp

        except socket.timeout:
            log.error("Connection timed out")
            resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
            return resp

        except socket.error as se:
            log.error("Connection error {}".format(se.errno))
            resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
            return resp

        except Exception as ee:
            if BLOCKSTACK_DEBUG:
                log.exception(ee)

            log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
            resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
            return resp

    return all_nameops


def get_consensus_hashes(block_heights, hostport=None, proxy=None):
    """
    Get consensus hashes for a list of blocks
    NOTE: returns {block_height (int): consensus_hash (str)}
    (coerces the key to an int)
    Returns {'error': ...} on error
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    consensus_hashes_schema = {
        'type': 'object',
        'properties': {
            'consensus_hashes': {
                'type': 'object',
                'patternProperties': {
                    '^([0-9]+)$': {
                        'type': 'string',
                        'pattern': OP_CONSENSUS_HASH_PATTERN,
                    },
                },
            },
        },
        'required': [
            'consensus_hashes',
        ],
    }

    resp_schema = json_response_schema( consensus_hashes_schema )
    resp = {}
    try:
        resp = proxy.get_consensus_hashes(block_heights)
        resp = json_validate(resp_schema, resp)
        if json_is_error(resp):
            log.error('Failed to get consensus hashes for {}: {}'.format(block_heights, resp['error']))
            return resp

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    consensus_hashes = resp['consensus_hashes']

    # hard to express as a JSON schema, but the format is thus:
    # { block_height (str): consensus_hash (str) }
    # need to convert all block heights to ints

    try:
        ret = {int(k): v for k, v in consensus_hashes.items()}
        log.debug('consensus hashes: {}'.format(ret))
        return ret
    except ValueError:
        return {'error': 'Server returned invalid data: expected int', 'http_status': 503}


def get_block_from_consensus(consensus_hash, hostport=None, proxy=None):
    """
    Get a block height from a consensus hash
    Returns the block height on success
    Returns {'error': ...} on failure
    """
    assert hostport or proxy, 'Need hostport or proxy'
    if proxy is None:
        proxy = connect_hostport(hostport)

    consensus_schema = {
        'type': 'object',
        'properties': {
            'block_id': {
                'anyOf': [
                    {
                        'type': 'integer',
                        'minimum': 0,
                    },
                    {
                        'type': 'null',
                    },
                ],
            },
        },
        'required': [
            'block_id'
        ],
    }

    schema = json_response_schema( consensus_schema )
    resp = {}
    try:
        resp = proxy.get_block_from_consensus(consensus_hash)
        resp = json_validate( schema, resp )
        if json_is_error(resp):
            log.error("Failed to find block ID for %s" % consensus_hash)
            return resp

    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp
    
    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return resp['block_id']


def get_name_history_page(name, page, hostport=None, proxy=None):
    """
    Get a page of the name's history
    Returns {'status': True, 'history': ..., 'indexing': ..., 'lastblock': ...} on success
    Returns {'error': ...} on error
    """
    assert hostport or proxy, 'Need hostport or proxy'
    if proxy is None:
        proxy = connect_hostport(hostport)

    name_required = ['op', 'opcode', 'txid', 'vtxindex']
    subdomain_required = ['txid']
    required = name_required if check_name(name) else subdomain_required

    hist_schema = {
        'type': 'object',
        'patternProperties': {
            '^[0-9]+$': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': OP_HISTORY_SCHEMA['properties'],
                    'required': required
                },
            },
        },
    }

    hist_resp_schema = {
        'type': 'object',
        'properties': {
            'history': hist_schema,
        },
        'required': [ 'history' ],
    }

    resp_schema = json_response_schema(hist_resp_schema)
    resp = {}
    lastblock = None
    indexin = None

    try:
        _resp = proxy.get_name_history_page(name, page)
        resp = json_validate(resp_schema, _resp)
        if json_is_error(resp):
            return resp

        lastblock = _resp['lastblock']
        indexing = _resp['indexing']

    except ValidationError as e:
        resp = json_traceback(resp.get('error'))
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
        return resp

    return {'status': True, 'history': resp['history'], 'lastblock': lastblock, 'indexing': indexing}


def name_history_merge(h1, h2):
    """
    Given two name histories (grouped by block), merge them.
    """
    ret = {}
    blocks_1 = [int(b) for b in h1.keys()]
    blocks_2 = [int(b) for b in h2.keys()]

    # find overlapping blocks
    overlap = list(set(blocks_1).intersection(set(blocks_2)))
    if len(overlap) > 0:
        for b in overlap:
            h = h1[str(b)] + h2[str(b)]
            h.sort(lambda v1, v2: -1 if v1['vtxindex'] < v2['vtxindex'] else 1)
            
            uniq = []
            last_vtxindex = None
            for i in range(0, len(h)):
                if h[i]['vtxindex'] != last_vtxindex:
                    uniq.append(h[i])
                    last_vtxindex = h[i]['vtxindex']
                
            ret[str(b)] = uniq
    
    all_blocks = list(set(blocks_1 + blocks_2))
    for b in all_blocks:
        if b in overlap:
            continue

        if b in blocks_1:
            ret[str(b)] = h1[str(b)]
        else:
            ret[str(b)] = h2[str(b)]

    return ret
    

def get_name_history(name, hostport=None, proxy=None, history_page=None):
    """
    Get the full history of a name
    Returns {'status': True, 'history': ...} on success, where history is grouped by block
    Returns {'error': ...} on error
    """
    assert hostport or proxy, 'Need hostport or proxy'
    if proxy is None:
        proxy = connect_hostport(hostport)

    hist = {}
    indexing = None
    lastblock = None

    if history_page != None:
        resp = get_name_history_page(name, history_page, proxy=proxy)
        if 'error' in resp:
            return resp

        indexing = resp['indexing']
        lastblock = resp['lastblock']

        return {'status': True, 'history': resp['history'], 'indexing': indexing, 'lastblock': lastblock}

    for i in range(0, 100000000):       # this is obviously too big
        resp = get_name_history_page(name, i, proxy=proxy)
        if 'error' in resp:
            return resp

        indexing = resp['indexing']
        lastblock = resp['lastblock']

        if len(resp['history']) == 0:
            # caught up 
            break

        hist = name_history_merge(hist, resp['history'])

    return {'status': True, 'history': hist, 'indexing': indexing, 'lastblock': lastblock}


def get_name_and_history(name, include_expired=False, include_grace=True, hostport=None, proxy=None, history_page=None):
    """
    Get the current name record and its history
    (this is a replacement for proxy.get_name_blockchain_record())
    Return {'status': True, 'record': ...} on success, where .record.history is defined as {block_height: [{history}, {history}, ...], ...}
    Return {'error': ...} on error
    """
    assert hostport or proxy, 'Need hostport or proxy'
    if proxy is None:
        proxy = connect_hostport(hostport)

    hist = get_name_history(name, proxy=proxy, history_page=history_page)
    if 'error' in hist:
        return hist

    # just the name
    rec = get_name_record(name, include_history=False, include_expired=include_expired, include_grace=include_grace, proxy=proxy)
    if 'error' in rec:
        return rec

    rec['history'] = hist['history']
    return {'status': True, 'record': rec, 'lastblock': hist['lastblock'], 'indexing': hist['indexing']}


def get_name_at(name, block_id, include_expired=False, hostport=None, proxy=None):
    """
    Get the name as it was at a particular height.
    Returns the name record states at this block height on success (an array)
    Returns {'error': ...} on error
    """
    assert hostport or proxy, 'Need hostport or proxy'
    if proxy is None:
        proxy = connect_hostport(hostport)

    namerec_schema = {
        'type': 'object',
        'properties': NAMEOP_SCHEMA_PROPERTIES,
        'required': NAMEOP_SCHEMA_REQUIRED
    }

    namerec_list_schema = {
        'type': 'object',
        'properties': {
            'records': {
                'anyOf': [
                    {
                        'type': 'array',
                        'items': namerec_schema
                    },
                    {
                        'type': 'null',
                    },
                ],
            },
        },
        'required': [
            'records'
        ],
    }

    resp_schema = json_response_schema( namerec_list_schema )
    resp = {}
    try:
        if include_expired:
            resp = proxy.get_historic_name_at(name, block_id)
        if not include_expired or 'KeyError' in resp.get('error', ''):
            resp = proxy.get_name_at(name, block_id)

        assert resp, "No such name {} at block {}".format(name, block_id)

        resp = json_validate(resp_schema, resp)
        if json_is_error(resp):
            return resp

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return resp['records']


def get_blockstack_ops_hash_at(block_id, hostport=None, proxy=None):
    """
    Get the hash of a set of records as they were at a particular block.
    Return the hash on success.
    Return {'error': ...} on error.
    """
    assert hostport or proxy, 'Need hostport or proxy'
    if proxy is None:
        proxy = connect_hostport(hostport)

    hash_schema = {
        'type': 'object',
        'properties': {
            'ops_hash': {
                'type': 'string',
                'pattern': '^([0-9a-fA-F]+)$'
            },
        },
        'required': [
            'ops_hash',
        ],
    }

    schema = json_response_schema( hash_schema )
    resp = {}
    try:
        resp = proxy.get_blockstack_ops_hash_at(block_id)
        resp = json_validate(schema, resp)
        if json_is_error(resp):
            return resp

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return resp['ops_hash']


def is_name_zonefile_hash(name, zonefile_hash, hostport=None, proxy=None):
    """
    Determine if a name set a given zone file hash.
    Return {'result': True/False} if so
    Return {'error': ...} on error
    """
    assert hostport or proxy, 'Need hostport or proxy'
    if proxy is None:
        proxy = connect_hostport(hostport)

    zonefile_check_schema = {
        'type': 'object',
        'properties': {
            'result': {
                'type': 'boolean'
            }
        },
        'required': [ 'result' ]
    }

    schema = json_response_schema(zonefile_check_schema)
    resp = {}
    try:
        resp = proxy.is_name_zonefile_hash(name, zonefile_hash)
        resp = json_validate(schema, resp)
        if json_is_error(resp):
            return resp

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = {'error': 'Server response did not match expected schema.  You are likely communicating with an out-of-date Blockstack node.', 'http_status': 502}
        return resp

    except socket.timeout:
        log.error("Connection timed out")
        resp = {'error': 'Connection to remote host timed out.', 'http_status': 503}
        return resp

    except socket.error as se:
        log.error("Connection error {}".format(se.errno))
        resp = {'error': 'Connection to remote host failed.', 'http_status': 502}
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.', 'http_status': 500}
        return resp

    return {'result': resp['result']}


def get_JWT(url, address=None):
    """
    Given a URL, fetch and decode the JWT it points to.
    If address is given, then authenticate the JWT with the address.

    Return None if we could not fetch it, or unable to authenticate it.

    NOTE: the URL must be usable by the requests library
    """
    jwt_txt = None
    jwt = None

    log.debug("Try {}".format(url))

    # special case: handle file://
    urlinfo = urllib2.urlparse.urlparse(url)
    if urlinfo.scheme == 'file':
        # points to a path on disk
        try:
            with open(urlinfo.path, 'r') as f:
                jwt_txt = f.read()

        except Exception as e:
            if BLOCKSTACK_TEST:
                log.exception(e)

            log.warning("Failed to read {}".format(url))
            return None

    else:
        # http(s) URL or similar
        try:
            resp = requests.get(url)
            assert resp.status_code == 200, 'Bad status code on {}: {}'.format(url, resp.status_code)
            jwt_txt = resp.text

        except Exception as e:
            if BLOCKSTACK_TEST:
                log.exception(e)

            log.warning("Unable to resolve {}".format(url))
            return None

    try:
        # one of two things are possible:
        # * this is a JWT string
        # * this is a serialized JSON string whose first item is a dict that has 'token' as key,
        # and that key is a JWT string.
        try:
            jwt_txt = json.loads(jwt_txt)[0]['token']
        except:
            pass

        jwt = jsontokens.decode_token(jwt_txt)
    except Exception as e:
        if BLOCKSTACK_TEST:
            log.exception(e)

        log.warning("Unable to decode token at {}".format(url))
        return None

    try:
        # must be well-formed
        assert isinstance(jwt, dict)
        assert 'payload' in jwt, jwt
        assert isinstance(jwt['payload'], dict)
        assert 'issuer' in jwt['payload'], jwt
        assert isinstance(jwt['payload']['issuer'], dict)
        assert 'publicKey' in jwt['payload']['issuer'], jwt
        assert virtualchain.ecdsalib.ecdsa_public_key(str(jwt['payload']['issuer']['publicKey']))

    except AssertionError as ae:
        if BLOCKSTACK_TEST or BLOCKSTACK_DEBUG:
            log.exception(ae)

        log.warning("JWT at {} is malformed".format(url))
        return None

    if address is not None:
        public_key = str(jwt['payload']['issuer']['publicKey'])
        addrs = [virtualchain.address_reencode(virtualchain.ecdsalib.ecdsa_public_key(keylib.key_formatting.decompress(public_key)).address()),
                 virtualchain.address_reencode(virtualchain.ecdsalib.ecdsa_public_key(keylib.key_formatting.compress(public_key)).address())]

        if virtualchain.address_reencode(address) not in addrs:
            # got a JWT, but it doesn't match the address
            log.warning("Found JWT at {}, but its public key has addresses {} and {} (expected {})".format(url, addrs[0], addrs[1], address))
            return None

        verifier = jsontokens.TokenVerifier()
        if not verifier.verify(jwt_txt, public_key):
            # got a JWT, and the address matches, but the signature does not
            log.warning("Found JWT at {}, but it was not signed by {} ({})".format(url, public_key, address))
            return None

    return jwt


def resolve_profile(name, include_expired=False, include_name_record=False, hostport=None, proxy=None):
    """
    Resolve a name to its profile.
    This is a multi-step process:
    1. get the name record
    2. get the zone file
    3. parse the zone file to get its URLs (if it's not well-formed, then abort)
    4. fetch and authenticate the JWT at each URL (abort if there are none)
    5. extract the profile JSON and return that, along with the zone file and public key

    Return {'profile': ..., 'zonefile': ..., 'public_key': ...['name_rec': ...]} on success
    Return {'error': ...} on error
    """
    assert hostport or proxy, 'Need hostport or proxy'
    
    name_rec = get_name_record(name, include_history=False, include_expired=include_expired, include_grace=False, proxy=proxy, hostport=hostport)
    if 'error' in name_rec:
        log.error("Failed to get name record for {}: {}".format(name, name_rec['error']))
        return {'error': 'Failed to get name record: {}'.format(name_rec['error']), 'http_status': name_rec.get('http_status', 500)}
   
    if 'grace_period' in name_rec and name_rec['grace_period']:
        log.error("Name {} is in the grace period".format(name))
        return {'error': 'Name {} is not yet expired, but is in the renewal grace period.'.format(name), 'http_status': name_rec.get('http_status', 404)}
        
    if 'value_hash' not in name_rec:
        log.error("Name record for {} has no zone file hash".format(name))
        return {'error': 'No zone file hash in name record for {}'.format(name), 'http_status': 404}

    zonefile_hash = name_rec['value_hash']
    zonefile_res = get_zonefiles(hostport, [zonefile_hash], proxy=proxy)
    if 'error' in zonefile_res:
        log.error("Failed to get zone file for {} for name {}: {}".format(zonefile_hash, name, zonefile_res['error']))
        return {'error': 'Failed to get zone file for {}'.format(name), 'http_status': 404}

    zonefile_txt = zonefile_res['zonefiles'][zonefile_hash]
    log.debug("Got {}-byte zone file {}".format(len(zonefile_txt), zonefile_hash))

    try:
        zonefile_data = blockstack_zones.parse_zone_file(zonefile_txt)
        zonefile_data = dict(zonefile_data)
        assert 'uri' in zonefile_data
        if len(zonefile_data['uri']) == 0:
            return {'error': 'No URI records in zone file {} for {}'.format(zonefile_hash, name), 'http_status': 404}

    except Exception as e:
        if BLOCKSTACK_TEST:
            log.exception(e)

        return {'error': 'Failed to parse zone file {} for {}'.format(zonefile_hash, name), 'http_status': 404}

    urls = [uri['target'] for uri in zonefile_data['uri']]
    for url in urls:
        jwt = get_JWT(url, address=str(name_rec['address']))
        if not jwt:
            continue

        if 'claim' not in jwt['payload']:
            # not something we produced
            log.warning("No 'claim' field in payload for {}".format(url))
            continue

        # success!
        profile_data = jwt['payload']['claim']
        public_key = str(jwt['payload']['issuer']['publicKey'])

        # return public key that matches address 
        pubkeys = [virtualchain.ecdsalib.ecdsa_public_key(keylib.key_formatting.decompress(public_key)),
                   virtualchain.ecdsalib.ecdsa_public_key(keylib.key_formatting.compress(public_key))]

        if name_rec['address'] == pubkeys[0].address():
            public_key = pubkeys[0].to_hex()
        else:
            public_key = pubkeys[1].to_hex()

        ret = {
            'profile': profile_data,
            'zonefile': zonefile_txt,
            'public_key': public_key,
        }

        if include_name_record:
            ret['name_record'] = name_rec

        return ret

    log.error("No zone file URLs resolved to a JWT with the public key whose address is {}".format(name_rec['address']))
    return {'error': 'No profile found for this name', 'http_status': 404}


def resolve_DID(did, hostport=None, proxy=None):
    """
    Resolve a DID to a public key.
    This is a multi-step process:
    1. get the name record
    2. get the zone file
    3. parse the zone file to get its URLs (if it's not well-formed, then abort)
    4. fetch and authenticate the JWT at each URL (abort if there are none)
    5. extract the public key from the JWT and return that.

    Return {'public_key': ...} on success
    Return {'error': ...} on error
    """
    assert hostport or proxy, 'Need hostport or proxy'

    did_rec = get_DID_record(did, hostport=hostport, proxy=proxy)
    if 'error' in did_rec:
        log.error("Failed to get DID record for {}: {}".format(did, did_rec['error']))
        return {'error': 'Failed to get DID record: {}'.format(did_rec['error']), 'http_status': did_rec.get('http_status', 500)}
    
    if 'value_hash' not in did_rec:
        log.error("DID record for {} has no zone file hash".format(did))
        return {'error': 'No zone file hash in name record for {}'.format(did), 'http_status': 404}

    zonefile_hash = did_rec['value_hash']
    zonefile_res = get_zonefiles(hostport, [zonefile_hash], proxy=proxy)
    if 'error' in zonefile_res:
        log.error("Failed to get zone file for {} for DID {}: {}".format(zonefile_hash, did, zonefile_res['error']))
        return {'error': 'Failed to get zone file for {}'.format(did), 'http_status': 404}

    zonefile_txt = zonefile_res['zonefiles'][zonefile_hash]
    log.debug("Got {}-byte zone file {}".format(len(zonefile_txt), zonefile_hash))

    try:
        zonefile_data = blockstack_zones.parse_zone_file(zonefile_txt)
        zonefile_data = dict(zonefile_data)
        assert 'uri' in zonefile_data
        if len(zonefile_data['uri']) == 0:
            return {'error': 'No URI records in zone file {} for {}'.format(zonefile_hash, did), 'http_status': 404}

    except Exception as e:
        if BLOCKSTACK_TEST:
            log.exception(e)

        return {'error': 'Failed to parse zone file {} for {}'.format(zonefile_hash, did), 'http_status': 404}

    urls = [uri['target'] for uri in zonefile_data['uri']]
    for url in urls:
        jwt = get_JWT(url, address=str(did_rec['address']))
        if not jwt:
            continue

        # found!
        public_key = str(jwt['payload']['issuer']['publicKey'])
        return {'public_key': public_key}

    log.error("No zone file URLs resolved to a JWT with the public key whose address is {}".format(did_rec['address']))
    return {'error': 'No public key found for the given DID', 'http_status': 404}


def decode_name_zonefile(name, zonefile_txt):
    """
    Decode a zone file for a name.
    Must be either a well-formed DNS zone file, or a legacy Onename profile.
    Return None on error
    """

    user_zonefile = None
    try:
        # by default, it's a zonefile-formatted text file
        user_zonefile_defaultdict = blockstack_zones.parse_zone_file(zonefile_txt)

        # force dict
        user_zonefile = dict(user_zonefile_defaultdict)

    except (IndexError, ValueError, blockstack_zones.InvalidLineException):
        # might be legacy profile
        log.debug('WARN: failed to parse user zonefile; trying to import as legacy')
        try:
            user_zonefile = json.loads(zonefile_txt)
            if not isinstance(user_zonefile, dict):
                log.debug('Not a legacy user zonefile')
                return None

        except Exception as e:
            log.error('Failed to parse non-standard zonefile')
            return None

    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error('Failed to parse zonefile')
        return None

    if user_zonefile is None:
        return None 

    return user_zonefile
