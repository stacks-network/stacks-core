#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import print_function

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

import json
import traceback
import os
import random
import re
from xmlrpclib import ServerProxy, Transport
from defusedxml import xmlrpc
import httplib
import base64
import jsonschema
from jsonschema.exceptions import ValidationError
from utils import url_to_host_port

from .constants import (
    MAX_RPC_LEN, CONFIG_PATH, BLOCKSTACK_TEST, DEFAULT_TIMEOUT,
    BLOCKSTACK_DEBUG, NAME_REVOKE
)

# prevent the usual XML attacks
xmlrpc.MAX_DATA = MAX_RPC_LEN
xmlrpc.monkey_patch()

import storage
import scripts

from .logger import get_logger

from .operations import (
    nameop_history_extract, nameop_restore_from_history,
    nameop_restore_snv_consensus_fields
)

from .schemas import (
    OP_NAMESPACE_PATTERN,
    OP_BASE58CHECK_CLASS,
    OP_NAME_OR_SUBDOMAIN_PATTERN,
    OP_CONSENSUS_HASH_PATTERN,
    OP_CONSENSUS_HASH_PATTERN,
    NAMEOP_SCHEMA_PROPERTIES,
    NAMEOP_SCHEMA_REQUIRED,
    OP_TXID_PATTERN,
    OP_CODE_PATTERN,
    OP_ZONEFILE_HASH_PATTERN,
    OP_TXID_PATTERN,
    OP_HISTORY_SCHEMA,
    NAMESPACE_SCHEMA_PROPERTIES,
    NAMESPACE_SCHEMA_REQUIRED
)

log = get_logger('blockstack-client')

BLOCKSTACK_CLIENT_TEST_ALTERNATIVE_CONFIG = os.environ.get('BLOCKSTACK_CLIENT_TEST_ALTERNATIVE_CONFIG', None)

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


# default API endpoint proxy to blockstackd
default_proxy = None


class BlockstackRPCClient(object):
    """
    RPC client for the blockstack server
    """

    def __init__(self, server, port, max_rpc_len=MAX_RPC_LEN,
                 timeout=DEFAULT_TIMEOUT, debug_timeline=False, protocol=None, **kw):

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


def get_default_proxy(config_path=CONFIG_PATH):
    """
    Get the default API proxy to blockstack.
    """
    global default_proxy
    if default_proxy is not None:
        return default_proxy

    import client
    import config

    if BLOCKSTACK_CLIENT_TEST_ALTERNATIVE_CONFIG is not None:
        # feature test: make sure alternative config paths get propagated
        if config_path.startswith('/home'):
            print(config_path)
            traceback.print_stack()
            os.abort()

    # load
    conf = config.get_config(config_path)
    assert conf is not None, 'Failed to get config from "{}"'.format(config_path)

    blockstack_server, blockstack_port = conf['server'], conf['port']
    protocol = conf['protocol']

    if os.environ.get("BLOCKSTACK_TEST") == "1":
        # we'd better be using the test port
        if blockstack_port != 16264:
            log.warning("Invalid port {} loaded from {}, at\n{}".format(blockstack_port, config_path, ''.join(traceback.format_stack())))

    log.debug('Default proxy to {}://{}:{}'.format(protocol, blockstack_server, blockstack_port))

    proxy = client.session(conf=conf, server_host=blockstack_server, server_port=blockstack_port,
                           server_protocol=protocol)

    return proxy


def set_default_proxy(proxy):
    """
    Set the default API proxy
    """
    global default_proxy
    default_proxy = proxy


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

    if proxy is None:
        if hostport is None:
            proxy = get_default_proxy()
        else:
            host, port = url_to_host_port(hostport)
            assert host is not None and port is not None

            protocol = None
            if port == 6264 or port == 16264:
                protocol = 'http'
            else:
                protocol = 'https'

            proxy = BlockstackRPCClient(host, port, protocol=protocol)

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


def ping(proxy=None):
    """
    ping
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

    proxy = get_default_proxy() if proxy is None else proxy

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


def get_name_cost(name, proxy=None):
    """
    name_cost
    Returns the name cost info on success
    Returns {'error': ...} on error
    """

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

    proxy = get_default_proxy() if proxy is None else proxy

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


def get_namespace_cost(namespace_id, proxy=None):
    """
    namespace_cost
    Returns the namespace cost info on success
    Returns {'error': ...} on error
    """

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

    schema = json_response_schema( cost_schema )
    proxy = get_default_proxy() if proxy is None else proxy

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


def get_all_names_page(offset, count, include_expired=False, proxy=None):
    """
    get a page of all the names
    Returns the list of names on success
    Returns {'error': ...} on error
    """

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

    schema = json_response_schema( page_schema )

    try:
        assert count <= 100, 'Page too big: {}'.format(count)
    except AssertionError as ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        return {'error': 'Invalid page'}

    proxy = get_default_proxy() if proxy is None else proxy

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
            if not scripts.is_name_valid(str(n)):
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


def get_num_names(proxy=None, include_expired=False):
    """
    Get the number of names, optionally counting the expired ones
    Return {'error': ...} on failure
    """

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

    count_schema = json_response_schema( schema )

    proxy = get_default_proxy() if proxy is None else proxy

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


def get_all_names(offset=None, count=None, include_expired=False, proxy=None):
    """
    Get all names within the given range.
    Return the list of names on success
    Return {'error': ...} on failure
    """
    offset = 0 if offset is None else offset
    proxy = get_default_proxy() if proxy is None else proxy

    if count is None:
        # get all names after this offset
        count = get_num_names(proxy=proxy)
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

        page = get_all_names_page(offset + len(all_names), request_size, include_expired=include_expired, proxy=proxy)
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


def get_all_namespaces(offset=None, count=None, proxy=None):
    """
    Get all namespaces
    Return the list of namespaces on success
    Return {'error': ...} on failure

    TODO: make this scale like get_all_names
    """
    offset = 0 if offset is None else offset
    proxy = get_default_proxy() if proxy is None else proxy

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


def get_names_in_namespace_page(namespace_id, offset, count, proxy=None):
    """
    Get a page of names in a namespace
    Returns the list of names on success
    Returns {'error': ...} on error
    """

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

    assert count <= 100, 'Page too big: {}'.format(count)

    proxy = get_default_proxy() if proxy is None else proxy

    resp = {}
    try:
        resp = proxy.get_names_in_namespace(namespace_id, offset, count)
        resp = json_validate(schema, resp)
        if json_is_error(resp):
            return resp

        # must be valid names
        valid_names = []
        for n in resp['names']:
            if not scripts.is_name_valid(str(n)):
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


def get_num_names_in_namespace(namespace_id, proxy=None):
    """
    Get the number of names in a namespace
    Returns the count on success
    Returns {'error': ...} on error
    """

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

    if proxy is None:
        proxy = get_default_proxy()

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


def get_names_in_namespace(namespace_id, offset=None, count=None, proxy=None):
    """
    Get all names in a namespace
    Returns the list of names on success
    Returns {'error': ..} on error
    """
    offset = 0 if offset is None else offset
    if count is None:
        # get all names in this namespace after this offset
        count = get_num_names_in_namespace(namespace_id, proxy=proxy)
        if json_is_error(count):
            return count

        count -= offset

    page_size = 100
    all_names = []
    while len(all_names) < count:
        request_size = page_size
        if count - len(all_names) < request_size:
            request_size = count - len(all_names)

        page = get_names_in_namespace_page(namespace_id, offset + len(all_names), request_size, proxy=proxy)
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


def get_names_owned_by_address(address, proxy=None):
    """
    Get the names owned by an address.
    Returns the list of names on success
    Returns {'error': ...} on error
    """

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
            assert scripts.is_name_valid(str(n)), ('Invalid name "{}"'.format(str(n)))
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


def get_num_historic_names_by_address(address, proxy=None):
    """
    Get the number of names historically created by an address
    Returns the number of names on success
    Returns {'error': ...} on error
    """
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


def get_historic_names_by_address_page(address, offset, count, proxy=None):
    """
    Get the list of names historically created by an address
    Returns the list of names on success
    Returns {'error': ...} on error
    """

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
    
    proxy = get_default_proxy() if proxy is None else proxy
    
    assert count <= 100, "Page too big"

    resp = {}
    try:
        resp = proxy.get_historic_names_by_address(address, offset, count)
        resp = json_validate(schema, resp)
        if json_is_error(resp):
            return resp

        # names must be valid
        for n in resp['names']:
            assert scripts.is_name_valid(str(n['name'])), ('Invalid name "{}"'.format(str(n['name'])))

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


def get_historic_names_by_address(address, offset=None, count=None, proxy=None):
    """
    Get the list of names created by an address throughout history
    Returns the list of names on success
    Returns {'error': ...} on failure
    """
    proxy = get_default_proxy() if proxy is None else proxy

    offset = 0 if offset is None else offset
    if count is None:
        # get all names owned by this address
        count = get_num_historic_names_by_address(address, proxy=proxy)
        if json_is_error(count):
            return count

        count -= offset

    page_size = 10
    all_names = []
    while len(all_names) < count:
        request_size = page_size
        if count - len(all_names) < request_size:
            request_size = count - len(all_names)

        page = get_historic_names_by_address_page(address, offset + len(all_names), request_size, proxy=proxy)
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


def get_DID_blockchain_record(did, proxy=None):
    """
    Resolve a Blockstack decentralized identifier (DID) to its blockchain record.
    DID format: did:stack:v0:${address}-${name_index}, where:
    * address is the address that created the name this DID references
    * name_index is the nth name ever created by this address.

    Follow the sequence of NAME_TRANSFERs and NAME_RENEWALs to find the current
    address, and then look up the public key.

    Returns the blockchain record on success
    Returns {'error': ...} on failure
    """
    proxy = get_default_proxy() if proxy is None else proxy
    did_pattern = '^did:stack:v0:({}{{25,35}})-([0-9]+)$'.format(OP_BASE58CHECK_CLASS)

    m = re.match(did_pattern, did)
    assert m, 'Invalid DID: {}'.format(did)

    address = m.groups()[0]
    name_index = int(m.groups()[1])

    addr_names = get_historic_names_by_address(address, proxy=proxy)
    if json_is_error(addr_names):
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
    name_history = get_name_blockchain_history(name, start_block, end_block)
    final_name_state = None

    for history_block in sorted(name_history.keys()):
        for history_state in name_history[history_block]:
            if history_state['op'] == NAME_REVOKE:
                # end of the line
                return {'error': 'The name for this DID has been deleted'}

            final_name_state = history_state

    return final_name_state


def get_consensus_at(block_height, proxy=None, hostport=None):
    """
    Get consensus at a block
    Returns the consensus hash on success
    Returns {'error': ...} on error
    """
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

    if proxy is None:
        if hostport is None:
            proxy = get_default_proxy()
        else:
            host, port = url_to_host_port(hostport)
            assert host is not None and port is not None

            protocol = None
            if port == 6264 or port == 16264:
                protocol = 'http'
            else:
                protocol = 'https'

            proxy = BlockstackRPCClient(host, port, protocol=protocol)

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


def get_consensus_hashes(block_heights, proxy=None):
    """
    Get consensus hashes for a list of blocks
    NOTE: returns {block_height (int): consensus_hash (str)}
    (coerces the key to an int)
    Returns {'error': ...} on error
    """

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
    
    proxy = get_default_proxy() if proxy is None else proxy

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

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = json_traceback(resp.get('error'))
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
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
        return {'error': 'Invalid data: expected int'}


def get_consensus_range(block_id_start, block_id_end, proxy=None):
    """
    Get a range of consensus hashes.  The range is inclusive.
    """
    proxy = get_default_proxy() if proxy is None else proxy

    ch_range = get_consensus_hashes(range(block_id_start, block_id_end + 1), proxy=proxy)
    if 'error' in ch_range:
        return ch_range

    # verify that all blocks are included
    for i in range(block_id_start, block_id_end + 1):
        if i not in ch_range:
            return {'error': 'Missing consensus hashes'}

    return ch_range


def get_block_from_consensus(consensus_hash, proxy=None):
    """
    Get a block ID from a consensus hash
    """
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

    if proxy is None:
        proxy = get_default_proxy()

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

        resp = json_traceback(resp.get('error'))
        return resp
    
    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
        return resp

    return resp['block_id']


def get_name_history_blocks(name, proxy=None):
    """
    Get the list of blocks at which this name was affected.
    Returns the list of blocks on success
    Returns {'error': ...} on error
    """
    hist_schema = {
        'type': 'array',
        'items': {
            'type': 'integer',
            'minimum': 0,
        },
    }

    hist_list_schema = {
        'type': 'object',
        'properties': {
            'history_blocks': hist_schema
        },
        'required': [
            'history_blocks'
        ],
    }

    resp_schema = json_response_schema( hist_list_schema )

    if proxy is None:
        proxy = get_default_proxy()

    resp = {}
    try:
        resp = proxy.get_name_history_blocks(name)
        resp = json_validate(resp_schema, resp)
        if json_is_error(resp):
            return resp
    except ValidationError as e:
        resp = json_traceback(resp.get('error'))
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
        return resp

    return resp['history_blocks']


def get_name_at(name, block_id, include_expired=False, proxy=None):
    """
    Get the name as it was at a particular height.
    Returns the name record states on success (an array)
    Returns {'error': ...} on error
    """
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

    proxy = get_default_proxy() if proxy is None else proxy

    resp = {}
    try:
        if include_expired:
            resp = proxy.get_historic_name_at(name, block_id)
        else:
            resp = proxy.get_name_at(name, block_id)

        assert resp, "No such name {} at block {}".format(name, block_id)

        resp = json_validate(resp_schema, resp)
        if json_is_error(resp):
            return resp

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

    return resp['records']


def get_name_blockchain_history(name, start_block, end_block, proxy=None):
    """
    Get the name's historical blockchain records.
    Returns the list of states the name has been in on success, as a dict,
    mapping {block_id: [states]}

    Returns {'error': ...} on error
    """
    proxy = get_default_proxy() if proxy is None else proxy

    history_blocks = get_name_history_blocks(name, proxy=proxy)
    if json_is_error(history_blocks):
        # error
        return history_blocks

    query_blocks = sorted(b for b in history_blocks if b >= start_block and b <= end_block)

    ret = {}
    for qb in query_blocks:
        name_at = get_name_at(name, qb, include_expired=True)
        if json_is_error(name_at):
            # error
            return name_at

        ret[qb] = name_at

    return ret


def get_op_history_rows(name, proxy=None):
    """
    Get the history rows for a name or namespace.
    """
    history_schema = {
        'type': 'array',
        'items': {
            'type': 'object',
            'properties': {
                'txid': {
                    'type': 'string',
                    'pattern': OP_TXID_PATTERN,
                },
                'history_id': {
                    'type': 'string',
                    'pattern': '^({})$'.format(name),
                },
                'block_id': {
                    'type': 'integer',
                    'minimum': 0,
                },
                'vtxindex': {
                    'type': 'integer',
                    'minimum': 0,
                },
                'op': {
                    'type': 'string',
                    'pattern': OP_CODE_PATTERN,
                },
                'history_data': {
                    'type': 'string'
                },
            },
            'required': [
                'txid',
                'history_id',
                'block_id',
                'vtxindex',
                'op',
                'history_data',
            ],
        },
    }

    hist_count_schema = {
        'type': 'object',
        'properties': {
            'count': {
                'type': 'integer',
                'minimum': 0,
            },
        },
        'required': [
            'count'
        ],
    }

    hist_rows_schema = {
        'type': 'object',
        'properties': {
            'history_rows': history_schema
        },
        'required': [
            'history_rows'
        ]
    }

    count_schema = json_response_schema( hist_count_schema )
    resp_schema = json_response_schema( hist_rows_schema )

    proxy = get_default_proxy() if proxy is None else proxy

    # how many history rows?
    history_rows_count = None
    try:
        history_rows_count = proxy.get_num_op_history_rows(name)
        history_rows_count = json_validate(count_schema, history_rows_count)
        if json_is_error(history_rows_count):
            return history_rows_count

    except ValidationError as e:
        resp = json_traceback()
        return resp

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
        return resp

    history_rows = []
    history_rows_count = history_rows_count['count']
    page_size = 10
    while len(history_rows) < history_rows_count:
        resp = {}
        try:
            resp = proxy.get_op_history_rows(name, len(history_rows), page_size)
            resp = json_validate(resp_schema, resp)
            if json_is_error(resp):
                return resp

            history_rows += resp['history_rows']

            if BLOCKSTACK_TEST is not None:
                if len(resp['history_rows']) == page_size:
                    continue

                if len(history_rows) == history_rows_count:
                    continue

                # something's wrong--we should have them all
                msg = 'Missing history rows: expected {}, got {}'
                raise Exception(msg.format(history_rows_count, len(history_rows)))

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

    return history_rows


def get_zonefiles_by_block(from_block, to_block, proxy=None):
    """
    Get zonefile information for zonefiles announced in [@from_block, @to_block]
    Returns { 'last_block' : server's last seen block,
              'zonefile_info' : [ { 'zonefile_hash' : '...',
                                    'txid' : '...',
                                    'block_height' : '...' } ] }
    """
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

    proxy = get_default_proxy() if proxy is None else proxy

    offset = 0
    output_zonefiles = []

    last_server_block = 0
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


def get_nameops_affected_at(block_id, proxy=None):
    """
    Get the *current* states of the name records that were
    affected at the given block height.
    Return the list of name records at the given height on success.
    Return {'error': ...} on error.
    """
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

    proxy = get_default_proxy() if proxy is None else proxy

    # how many nameops?
    num_nameops = None
    try:
        num_nameops = proxy.get_num_nameops_affected_at(block_id)
        num_nameops = json_validate(count_schema, num_nameops)
        if json_is_error(num_nameops):
            return num_nameops

    except ValidationError as e:
        num_nameops = json_traceback()
        return num_nameops

    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
        return resp

    num_nameops = num_nameops['count']

    # grab at most 10 of these at a time
    all_nameops = []
    page_size = 10
    while len(all_nameops) < num_nameops:
        resp = {}
        try:
            resp = proxy.get_nameops_affected_at(block_id, len(all_nameops), page_size)
            resp = json_validate(nameop_schema, resp)
            if json_is_error(resp):
                return resp

            if len(resp['nameops']) == 0:
                return {'error': 'Got zero-length nameops reply'}

            all_nameops += resp['nameops']

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

    return all_nameops


def get_nameops_at(block_id, proxy=None):
    """
    Get all the name operation that happened at a given block,
    as they were written.
    Return the list of operations on success, ordered by transaction index.
    Return {'error': ...} on error.
    """
    
    all_nameops = get_nameops_affected_at(block_id, proxy=proxy)
    if json_is_error(all_nameops):
        log.debug('Failed to get nameops affected at {}: {}'.format(block_id, all_nameops['error']))
        return all_nameops

    log.debug('{} nameops at {}'.format(len(all_nameops), block_id))

    # get the history for each nameop
    nameops = []
    nameop_histories = {}   # cache histories
    for nameop in all_nameops:

        rec_id = None
        rec_key = None
        if 'name' in nameop:
            rec_key = 'name'
        elif 'namespace_id' in nameop:
            rec_key = 'namespace_id'
        
        if rec_key:
            rec_id = nameop[rec_key]
        else:
            rec_id = 'UNKNOWN'

        # get history (if not a preorder)
        history_rows = []
        if rec_key is not None:
            # this isn't some kind of preorder.  We have history for it.
            history_rows = nameop_histories.get(nameop[rec_key])
            if history_rows is None:
                history_rows = get_op_history_rows( nameop[rec_key], proxy=proxy )
                if json_is_error(history_rows):
                    return history_rows

                nameop_histories[nameop[rec_key]] = history_rows

        # restore history
        history = nameop_history_extract(history_rows)
        historic_nameops = nameop_restore_from_history(nameop, history, block_id)

        msg = '{} had {} operations ({} history rows, {} historic nameops, txids: {})'
        log.debug(
            msg.format(
                rec_id, len(history), len(history_rows),
                len(historic_nameops), [op['txid'] for op in historic_nameops]
            )
        )

        for historic_nameop in historic_nameops:
            # restore SNV consensus information
            historic_nameop['history'] = history
            restored_rec = nameop_restore_snv_consensus_fields(historic_nameop, block_id)
            if json_is_error(restored_rec):
                return restored_rec

            nameops.append(restored_rec)

    log.debug('restored {} nameops at height {}'.format(len(nameops), block_id))
    return sorted(nameops, key=lambda n: n['vtxindex'])


def get_nameops_hash_at(block_id, proxy=None):
    """
    Get the hash of a set of records as they were at a particular block.
    Return the hash on success.
    Return {'error': ...} on error.
    """

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
    
    proxy = get_default_proxy() if proxy is None else proxy

    resp = {}
    try:
        resp = proxy.get_nameops_hash_at(block_id)
        resp = json_validate(schema, resp)
        if json_is_error(resp):
            return resp
    except ValidationError as e:
        resp = json_traceback(resp.get('error'))
        return resp
    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
        return resp

    return resp['ops_hash']


def get_name_blockchain_record(name, include_expired=True, include_grace=True, proxy=None):
    """
    get_name_blockchain_record
    Return the blockchain-extracted information on success.
    Return {'error': ...} on error
        In particular, return {'error': 'Not found.'} if the name isn't registered

    If include_expired is True, then a name record will be returned even if it expired
    If include_expired is False, but include_grace is True, then the name record will be returned even if it is expired and in the grace period
    """

    nameop_schema = {
        'type': 'object',
        'properties': NAMEOP_SCHEMA_PROPERTIES,
        'required': NAMEOP_SCHEMA_REQUIRED + ['history']
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

    resp_schema = json_response_schema( rec_schema )

    proxy = get_default_proxy() if proxy is None else proxy

    resp = {}
    lastblock = None
    try:
        resp = proxy.get_name_blockchain_record(name)
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

    if not include_expired:
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



def get_namespace_blockchain_record(namespace_id, proxy=None):
    """
    get_namespace_blockchain_record
    """

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
            
    proxy = get_default_proxy() if proxy is None else proxy

    ret = {}
    try:
        ret = proxy.get_namespace_blockchain_record(namespace_id)
        ret = json_validate(resp_schema, ret)
        if json_is_error(ret):
            return ret

        ret = ret['record']

        # this isn't needed
        ret.pop('opcode', None)
    except ValidationError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        ret = json_traceback(ret.get('error'))
        return ret
    except Exception as ee:
        if BLOCKSTACK_DEBUG:
            log.exception(ee)

        log.error("Caught exception while connecting to Blockstack node: {}".format(ee))
        resp = {'error': 'Failed to contact Blockstack node.  Try again with `--debug`.'}
        return resp

    return ret


def is_name_registered(fqu, config_path=CONFIG_PATH, proxy=None, include_grace=True):
    """
    Return True if @fqu is a registered name on the blockchain.
    Must not be revoked, and must not be expired.
    """

    proxy = get_default_proxy(config_path) if proxy is None else proxy

    blockchain_record = get_name_blockchain_record(fqu, include_expired=False, include_grace=include_grace, proxy=proxy)
    if 'error' in blockchain_record:
        log.debug('Failed to read blockchain record for {}'.format(fqu))
        return False

    if blockchain_record.get('revoked', None):
        log.debug("{} is revoked".format(fqu))
        return False

    if not 'first_registered' in blockchain_record:
        log.debug("{} lacks 'first_registered'".format(fqu))
        # log.debug("\n{}\n".format(json.dumps(blockchain_record, indent=4, sort_keys=True))
        return False

    return 'first_registered' in blockchain_record


def is_namespace_revealed(ns, proxy=None):
    """
    Return True if @ns is a revealed namespace on the blockchain
    """

    proxy = get_default_proxy() if proxy is None else proxy
    namespace_record = get_namespace_blockchain_record(ns, proxy=proxy)
    if 'error' in namespace_record:
        log.debug("Failed to read blockchain record for namespace {}".format(ns))
        return False

    return True


def is_namespace_ready(ns, proxy=None):
    """
    Return True if @ns is a revealed, ready namespace
    """
    proxy = get_default_proxy() if proxy is None else proxy
    namespace_record = get_namespace_blockchain_record(ns, proxy=proxy)
    if 'error' in namespace_record:
        log.debug("Failed to read blockchain record for {}".format(ns))
        return False

    return namespace_record['ready']


def has_zonefile_hash(fqu, proxy=None):
    """
    Return True if @fqu has a zonefile hash on the blockchain
    """

    proxy = get_default_proxy() if proxy is None else proxy

    blockchain_record = get_name_blockchain_record(fqu, proxy=proxy)
    if 'error' in blockchain_record:
        log.debug('Failed to read blockchain record for {}'.format(fqu))
        return False

    return blockchain_record.get('value_hash', None) is not None


def is_zonefile_current(fqu, zonefile_json, proxy=None):
    """
    Return True if hash(@zonefile_json) is published on the blockchain
    """

    proxy = get_default_proxy() if proxy is None else proxy

    zonefile_hash = storage.hash_zonefile(zonefile_json)

    return is_zonefile_hash_current(fqu, zonefile_hash, proxy=proxy)


def is_zonefile_data_current(fqu, zonefile_data, proxy=None):
    """
    Return True if hash(@zonefile_data) is published on the blockchain
    """

    proxy = get_default_proxy() if proxy is None else proxy

    zonefile_hash = storage.get_zonefile_data_hash(zonefile_data)

    return is_zonefile_hash_current(fqu, zonefile_hash, proxy=proxy)


def is_zonefile_hash_current(fqu, zonefile_hash, proxy=None):
    """
    Return True if hash(@zonefile_json) published on blockchain
    """

    proxy = get_default_proxy() if proxy is None else proxy

    blockchain_record = get_name_blockchain_record(fqu, proxy=proxy)
    if 'error' in blockchain_record:
        log.debug('Failed to read blockchain record for {}'.format(fqu))
        return False

    return zonefile_hash == blockchain_record.get('value_hash', '')


def is_name_owner(fqu, address, proxy=None):
    """
    return True if @btc_address owns @fqu
    """

    proxy = get_default_proxy() if proxy is None else proxy

    blockchain_record = get_name_blockchain_record(fqu, include_expired=False, include_grace=True, proxy=proxy)
    if 'error' in blockchain_record:
        log.debug('Failed to read blockchain record for {}'.format(fqu))
        return False

    return address == blockchain_record.get('address', '')


def get_zonefile_inventory(hostport, bit_offset, bit_count, timeout=30, my_hostport=None, proxy=None):
    """
    Get the atlas zonefile inventory from the given peer.
    Return {'status': True, 'inv': inventory} on success.
    Return {'error': ...} on error
    """

    # NOTE: we want to match the empty string too
    base64_zero_pattern = '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'

    inv_schema = {
        'type': 'object',
        'properties': {
            'inv': {
                'type': 'string',
                'pattern': base64_zero_pattern,
            },
        },
        'required': [
            'inv'
        ]
    }

    schema = json_response_schema( inv_schema )

    if proxy is None:
        host, port = url_to_host_port(hostport)
        assert host is not None and port is not None
        proxy = BlockstackRPCClient(host, port, timeout=timeout, src=my_hostport, protocol = 'http')

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
        host, port = url_to_host_port(hostport)
        assert host is not None and port is not None
        proxy = BlockstackRPCClient(host, port, timeout=timeout, src=my_hostport, protocol = 'http')

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


def get_zonefiles(hostport, zonefile_hashes, timeout=30, my_hostport=None, proxy=None):
    """
    Get a set of zonefiles from the given server.
    Return {'status': True, 'zonefiles': {hash: data, ...}} on success
    Return {'error': ...} on error
    """

    # NOTE: we want to match the empty string too
    base64_pattern = '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'

    zonefiles_schema = {
        'type': 'object',
        'properties': {
            'zonefiles': {
                'type': 'object',
                'patternProperties': {
                    OP_ZONEFILE_HASH_PATTERN: {
                        'type': 'string',
                        'pattern': base64_pattern
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
        host, port = url_to_host_port(hostport)
        assert host is not None and port is not None
        proxy = BlockstackRPCClient(host, port, timeout=timeout, src=my_hostport, protocol = 'http')

    zonefiles = None
    try:
        zf_payload = proxy.get_zonefiles(zonefile_hashes)
        zf_payload = json_validate(schema, zf_payload)
        if json_is_error(zf_payload):
            return zf_payload

        decoded_zonefiles = {}

        for zf_hash, zf_data_b64 in zf_payload['zonefiles'].items():
            zf_data = base64.b64decode( zf_data_b64 )
            assert storage.verify_zonefile( zf_data, zf_hash ), "Zonefile data mismatch"

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
        host, port = url_to_host_port(hostport)
        assert host is not None and port is not None

        protocol = None
        if port == 6264 or port == 16264:
            protocol = 'http'
        else:
            protocol = 'https'

        proxy = BlockstackRPCClient(host, port, protocol=protocol)

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
