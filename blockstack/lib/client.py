#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack-client.

    Blockstack-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack-client. If not, see <http://www.gnu.org/licenses/>.
"""

import sys
import os

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
from .util import url_to_host_port, url_protocol
from .config import MAX_RPC_LEN, BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, RPC_SERVER_PORT, RPC_SERVER_TEST_PORT, LENGTHS, RPC_DEFAULT_TIMEOUT, NAME_REVOKE
from .schemas import *
from .scripts import is_name_valid, is_subdomain
from .storage import verify_zonefile

import virtualchain
import keylib

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

    return 'error' in resp


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


def json_validate(schema, resp):
    """
    Validate an RPC response.
    The response must either take the
    form of the given schema, or it must
    take the form of {'error': ...}

    Returns the resp on success
    Returns {'error': ...} on validation error
    """
    error_schema = {
        'type': 'object',
        'properties': {
            'error': {
                'type': 'string'
            }
        },
        'required': [
            'error'
        ]
    }

    # is this an error?
    try:
        jsonschema.validate(resp, error_schema)
    except ValidationError:
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
        error_msg = exception_data[-1]
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

        resp = json_traceback(resp.get('error'))

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
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

        resp = json_traceback(resp.get('error'))

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
        return resp

    return resp


def get_zonefile_inventory(hostport, bit_offset, bit_count, timeout=30, my_hostport=None, proxy=None):
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
        zf_inv = proxy.get_zonefile_inventory(bit_offset, bit_count)
        zf_inv = json_validate(schema, zf_inv)
        if json_is_error(zf_inv):
            return zf_inv

        # decode
        zf_inv['inv'] = base64.b64decode(str(zf_inv['inv']))

        # make sure it corresponds to this range
        assert len(zf_inv['inv']) <= (bit_count / 8) + (bit_count % 8), 'Zonefile inventory in is too long (got {} bytes)'.format(len(zf_inv['inv']))
    except (ValidationError, AssertionError) as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        zf_inv = {'error': 'Failed to fetch and parse zonefile inventory'}

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
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
                return {'error': 'Invalid peer listing'}

        peers = peer_list_resp

    except (ValidationError, AssertionError) as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        peers = json_traceback()

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node {}.  Try again with `--debug`.'.format(hostport)}
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
                return {'error': 'Invalid peer listing'}

        peers = peer_list_resp

    except (ValidationError, AssertionError) as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        peers = json_traceback()

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node {}.  Try again with `--debug`.'.format(hostport)}
        return resp

    return peers


def get_zonefiles(hostport, zonefile_hashes, timeout=30, my_hostport=None, proxy=None):
    """
    Get a set of zonefiles from the given server.
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

    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        zonefiles = json_traceback()

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
        return resp

    return zonefiles


def put_zonefiles(hostport, zonefile_data_list, timeout=30, my_hostport=None, proxy=None):
    """
    Push one or more zonefiles to the given server.
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

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        push_info = json_traceback()

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
        return resp

    return push_info


def get_name_record(name, include_history=False, include_expired=True, include_grace=True, proxy=None, hostport=None):
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
            resp = proxy.get_name_blockchain_record(name)
        else:
            resp = proxy.get_name_record(name)

        resp = json_validate(resp_schema, resp)
        if json_is_error(resp):
            if resp['error'] == 'Not found.':
                return {'error': 'Not found.'}

            return resp

        lastblock = resp['lastblock']

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = json_traceback(resp.get('error'))
        return resp
    
    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
        return resp

    if not include_expired and is_blockstack_id:
        # check expired
        if lastblock is None:
            return {'error': 'No lastblock given from server'}

        if include_grace:
            # only care if the name is beyond the grace period
            if lastblock > int(resp['record']['renewal_deadline']) and int(resp['record']['renewal_deadline']) > 0:
                return {'error': 'Name expired'}

        else:
            # only care about expired, even if it's in the grace period
            if lastblock > resp['record']['expire_block'] and int(resp['record']['expire_block']) > 0:
                return {'error': 'Name expired'}

    return resp['record']


def get_name_cost(name, proxy=None, hostport=None):
    """
    name_cost
    Returns the name cost info on success
    Returns {'error': ...} on error
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    schema = {
        'type': 'object',
        'properties': {
            'status': {
                'type': 'boolean',
            },
            'satoshis': {
                'type': 'integer',
                'minimum': 0,
            },
        },
        'required': [
            'status',
            'satoshis'
        ]
    }

    resp = {}
    try:
        resp = proxy.get_name_cost(name)
        resp = json_validate( schema, resp )
        if json_is_error(resp):
            return resp

    except ValidationError as e:
        resp = json_traceback(resp.get('error'))

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
        return resp

    return resp


def get_namespace_cost(namespace_id, proxy=None, hostport=None):
    """
    namespace_cost
    Returns the namespace cost info on success
    Returns {'error': ...} on error
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    cost_schema = {
        'type': 'object',
        'properties': {
            'satoshis': {
                'type': 'integer',
                'minimum': 0,
            }
        },
        'required': [
            'satoshis'
        ]
    }

    schema = json_response_schema(cost_schema)

    resp = {}
    try:
        resp = proxy.get_namespace_cost(namespace_id)
        resp = json_validate( cost_schema, resp )
        if json_is_error(resp):
            return resp

    except ValidationError as e:
        resp = json_traceback(resp.get('error'))

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
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

        return {'error': 'Invalid page'}

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
    except (ValidationError, AssertionError) as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        resp = json_traceback(resp.get('error'))
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
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

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = json_traceback(resp.get('error'))
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
        return resp

    return resp['count']


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
            return {'error': error_str}
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

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = json_traceback(resp.get('error'))
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
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
    except (ValidationError, AssertionError) as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = json_traceback(resp.get('error'))
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
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

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = json_traceback(resp.get('error'))
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
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
            return {'error': error_str}
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
    
    proxy = get_default_proxy() if proxy is None else proxy

    resp = {}
    try:
        resp = proxy.get_names_owned_by_address(address)
        resp = json_validate(schema, resp)
        if json_is_error(resp):
            return resp

        # names must be valid
        for n in resp['names']:
            assert is_name_valid(str(n)), ('Invalid name "{}"'.format(str(n)))
    except (ValidationError, AssertionError) as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = json_traceback(resp.get('error'))
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
        return resp

    return resp['names']


def get_num_historic_names_by_address(address, proxy=None, hostport=None):
    """
    Get the number of names historically created by an address
    Returns the number of names on success
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

    schema = json_response_schema(num_names_schema)

    if proxy is None:
        proxy = get_default_proxy()

    resp = {}
    try:
        resp = proxy.get_num_historic_names_by_address(address)
        resp = json_validate(schema, resp)
        if json_is_error(resp):
            return resp

    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = json_traceback(resp.get('error'))
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
        return resp

    return resp['count']


def get_historic_names_by_address_page(address, offset, count, proxy=None, hostport=None):
    """
    Get the list of names historically created by an address
    Returns the list of names on success
    Returns {'error': ...} on error
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    assert count <= 100, "Page too big"

    names_schema = {
        'type': 'object',
        'properties': {
            'names': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'name': {
                            'type': 'string',
                            'pattern': OP_NAME_OR_SUBDOMAIN_PATTERN,
                        },
                        'block_id': {
                            'type': 'integer',
                            'minimum': 0,
                        },
                        'vtxindex': {
                            'type': 'integer',
                            'minimum': 0,
                        },
                    },
                    'required': [
                        'name',
                        'block_id',
                        'vtxindex',
                    ],
                },
            },
        },
        'required': [
            'names'
        ],
    }

    schema = json_response_schema( names_schema )
    resp = {}
    try:
        resp = proxy.get_historic_names_by_address(address, offset, count)
        resp = json_validate(schema, resp)
        if json_is_error(resp):
            return resp

        # names must be valid
        for n in resp['names']:
            assert is_name_valid(str(n['name'])), ('Invalid name "{}"'.format(str(n['name'])))

    except (ValidationError, AssertionError) as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Caught exception while connecting to Blockstack node: {}".format(e))
        resp = json_traceback(resp.get('error'))
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
        return resp

    return resp['names']


def get_historic_names_by_address(address, offset=None, count=None, proxy=None, hostport=None):
    """
    Get the list of names created by an address throughout history
    Returns the list of names on success
    Returns {'error': ...} on failure
    """
    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    offset = 0 if offset is None else offset
    if count is None:
        # get all names owned by this address
        count = get_num_historic_names_by_address(address, proxy=proxy, hostport=hostport)
        if json_is_error(count):
            return count

        count -= offset

    page_size = 10
    all_names = []
    while len(all_names) < count:
        request_size = page_size
        if count - len(all_names) < request_size:
            request_size = count - len(all_names)

        page = get_historic_names_by_address_page(address, offset + len(all_names), request_size, proxy=proxy, hostport=hostport)
        if json_is_error(page):
            # error
            return page

        if len(page) > request_size:
            # error
            error_str = 'server replied too much data'
            return {'error': error_str}

        elif len(page) == 0:
            # end-of-table
            break

        all_names += page

    return all_names[:count]


def get_DID_name_blockchain_record(did, proxy=None, hostport=None):
    """
    Resolve a Blockstack decentralized identifier (DID) to its blockchain record.
    This is for cases where the DID corresponds to a name, not a subdomain!
    You can tell because name DID addresses start with 1 or 3 (version byte 0 or 5) on Bitcoin mainnet.

    DID format: did:stack:v0:${address}-${name_index}, where:
    * address is the address that created the name this DID references (version byte 0 or 5)
    * name_index is the nth name ever created by this address.

    Follow the sequence of NAME_TRANSFERs and NAME_RENEWALs to find the current
    address, and then look up the public key.

    Returns the blockchain record on success
    Returns {'error': ...} on failure
    """
    from .subdomains import SUBDOMAIN_ADDRESS_VERSION_BYTES

    assert proxy or hostport, 'Need proxy or hostport'
    if proxy is None:
        proxy = connect_hostport(hostport)

    did_pattern = '^did:stack:v0:({}{{25,35}})-([0-9]+)$'.format(OP_BASE58CHECK_CLASS)

    m = re.match(did_pattern, did)
    assert m, 'Invalid DID: {}'.format(did)

    address = m.groups()[0]
    name_index = int(m.groups()[1])

    address_vb = keylib.b58check.b58check_version_byte(address)
    assert address_vb not in SUBDOMAIN_ADDRESS_VERSION_BYTES, 'Address {} is a subdomain address'.format(address)

    addr_names = get_historic_names_by_address(address, proxy=proxy, hostport=hostport)
    if json_is_error(addr_names):
        log.error("get_historic_names_by_address({}): {}".format(address, addr_names['error']))
        return addr_names

    if len(addr_names) <= name_index:
        errormsg = 'Invalid DID: index {} exceeds number of names ({}: {}) created by {}'.format(name_index, len(addr_names), ", ".join([an['name'] for an in addr_names]), address)
        log.error(errormsg)
        return {'error': errormsg}
    
    # order by blockchain and tx
    addr_names.sort(lambda n1,n2: -1 if n1['block_id'] < n2['block_id'] or (n1['block_id'] == n2['block_id'] and n1['vtxindex'] < n2['vtxindex']) else 1)
    name = addr_names[name_index]['name']
    start_block = addr_names[name_index]['block_id']
    end_block = 100000000       # TODO: update if this gets too small (not likely in my lifetime)

    # verify that the name hasn't been revoked since this DID was created.
    name_blockchain_record = get_name_record(name, include_history=True, hostport=hostport, proxy=proxy)
    if json_is_error(name_blockchain_record):
        log.error("Failed to get name history for '{}'".format(name))
        return name_blockchain_record

    name_history = name_blockchain_record['history']
    final_name_state = None

    for history_block in sorted(name_history.keys()):
        for history_state in sorted(name_history[history_block], cmp=lambda n1,n2: -1 if n1['vtxindex'] < n2['vtxindex'] else 1):
            if history_state['op'] == NAME_REVOKE:
                # end of the line
                return {'error': 'The name for this DID has been deleted'}
            
            assert history_state is not None
            final_name_state = history_state

    if final_name_state is None:
        # no history to go through
        final_name_state = name_blockchain_record

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
    except (ValidationError, AssertionError) as e:
        resp = json_traceback(resp.get('error'))
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
        return resp

    if resp['consensus'] is None:
        # node hasn't processed this block 
        return {'error': 'The node has not processed block {}'.format(block_height)}

    return resp['consensus']
