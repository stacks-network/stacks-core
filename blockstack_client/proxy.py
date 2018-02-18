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

# use this instead
import blockstack.lib.client as blockstackd_client
from blockstack.lib.client import json_is_error

from .logger import get_logger

log = get_logger('blockstack-client')

BLOCKSTACK_CLIENT_TEST_ALTERNATIVE_CONFIG = os.environ.get('BLOCKSTACK_CLIENT_TEST_ALTERNATIVE_CONFIG', None)

# default API endpoint proxy to blockstackd
default_proxy = None

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

    if proxy is None:
        if hostport is None:
            proxy = get_default_proxy()

    return blockstackd_client.getinfo(proxy=proxy, hostport=hostport)
  

def ping(proxy=None):
    """
    ping
    Returns {'alive': True} on succcess
    Returns {'error': ...} on error
    """
    proxy = get_default_proxy() if proxy is None else proxy
    return blockstackd_client.ping(proxy=proxy)


def get_name_cost(name, proxy=None):
    """
    name_cost
    Returns the name cost info on success
    Returns {'error': ...} on error
    """
    proxy = get_default_proxy() if proxy is None else proxy
    return blockstackd_client.get_name_cost(name, proxy=proxy)


def get_namespace_cost(namespace_id, proxy=None):
    """
    namespace_cost
    Returns the namespace cost info on success
    Returns {'error': ...} on error
    """
    proxy = get_default_proxy() if proxy is None else proxy
    return blockstackd_client.get_namespace_cost(namespace_id, proxy=proxy)
   

def get_num_names(proxy=None, include_expired=False):
    """
    Get the number of names, optionally counting the expired ones
    Return {'error': ...} on failure
    """
    proxy = get_default_proxy() if proxy is None else proxy
    return blockstackd_client.get_num_names(include_expired=include_expired, proxy=proxy)


def get_all_names(offset=None, count=None, include_expired=False, proxy=None):
    """
    Get all names within the given range.
    Return the list of names on success
    Return {'error': ...} on failure
    """
    offset = 0 if offset is None else offset
    proxy = get_default_proxy() if proxy is None else proxy
    return blockstackd_client.get_all_names(offset=offset, count=count, include_expired=include_expired, proxy=proxy)
   

def get_all_namespaces(offset=None, count=None, proxy=None):
    """
    Get all namespaces
    Return the list of namespaces on success
    Return {'error': ...} on failure

    TODO: make this scale like get_all_names
    """
    offset = 0 if offset is None else offset
    proxy = get_default_proxy() if proxy is None else proxy
    return blockstackd_client.get_all_namespaces(offset=offset, count=count, proxy=proxy)
   

def get_num_names_in_namespace(namespace_id, proxy=None):
    """
    Get the number of names in a namespace
    Returns the count on success
    Returns {'error': ...} on error
    """
    proxy = get_default_proxy() if proxy is None else proxy
    return blockstackd_client.get_num_names_in_namespace(namespace_id, proxy=proxy)
   

def get_names_in_namespace(namespace_id, offset=None, count=None, proxy=None):
    """
    Get all names in a namespace
    Returns the list of names on success
    Returns {'error': ..} on error
    """
    proxy = get_default_proxy() if proxy is None else proxy
    return blockstackd_client.get_names_in_namespace(namespace_id, offset=offset, count=count, proxy=proxy)


def get_names_owned_by_address(address, proxy=None):
    """
    Get the names owned by an address.
    Returns the list of names on success
    Returns {'error': ...} on error
    """
    proxy = get_default_proxy() if proxy is None else proxy
    return blockstackd_client.get_names_owned_by_address(address, proxy=proxy)


def get_consensus_at(block_height, proxy=None, hostport=None):
    """
    Get consensus at a block
    Returns the consensus hash on success
    Returns {'error': ...} on error
    """
    if proxy is None:
        if hostport is None:
            proxy = get_default_proxy()

    return blockstackd_client.get_consensus_at(block_height, proxy=proxy, hostport=hostport)


def get_consensus_hashes(block_heights, proxy=None):
    """
    Get consensus hashes for a list of blocks
    NOTE: returns {block_height (int): consensus_hash (str)}
    (coerces the key to an int)
    Returns {'error': ...} on error
    """
    proxy = get_default_proxy() if proxy is None else proxy
    return blockstackd_client.get_consensus_hashes(block_heights, proxy=proxy)


def get_consensus_range(block_id_start, block_id_end, proxy=None):
    """
    Get a range of consensus hashes.  The range is inclusive.
    """
    proxy = get_default_proxy() if proxy is None else proxy
    return blockstackd_client.get_consensus_range(block_id_start, block_id_end, proxy=proxy)


def get_block_from_consensus(consensus_hash, proxy=None):
    """
    Get a block ID from a consensus hash
    """
    proxy = get_default_proxy() if proxy is None else proxy
    return blockstackd_client.get_block_from_consensus(consensus_hash, proxy=proxy)


def get_name_history_blocks(name, proxy=None):
    """
    Get the list of blocks at which this name was affected.
    Returns the list of blocks on success
    Returns {'error': ...} on error
    """
    proxy = get_default_proxy() if proxy is None else proxy
    return blockstackd_client.get_name_history_blocks(name, proxy=proxy)


def get_name_at(name, block_id, include_expired=False, proxy=None):
    """
    Get the name as it was at a particular height.
    Returns the name record states on success (an array)
    Returns {'error': ...} on error
    """
    proxy = get_default_proxy() if proxy is None else proxy
    return blockstackd_client.get_name_at(name, block_id, include_expired=include_expired, proxy=proxy)


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
        name_at = get_name_at(name, qb, include_expired=True, proxy=proxy)
        if json_is_error(name_at):
            # error
            return name_at

        ret[qb] = name_at

    return ret


# DEPRECATED
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


def get_blockstack_transactions_at(block_id, proxy=None):
    """
    Get the *prior* states of the blockstack records that were
    affected at the given block height.
    Return the list of name records at the given height on success.
    Return {'error': ...} on error.
    """
    proxy = get_default_proxy() if proxy is None else proxy
    return blockstackd_client.get_blockstack_transactions_at(block_id, proxy=proxy)


def get_nameops_at(block_id, proxy=None):
    """
    Get all the name operation that happened at a given block,
    as they were written.
    Return the list of operations on success, ordered by transaction index.
    Return {'error': ...} on error.
    """
    proxy = get_default_proxy() if proxy is None else proxy
    return blockstackd_client.get_blockstack_transactions_at(block_id, proxy=proxy)


def get_nameops_hash_at(block_id, proxy=None):
    """
    Get the hash of a set of records as they were at a particular block.
    Return the hash on success.
    Return {'error': ...} on error.
    """
    proxy = get_default_proxy() if proxy is None else proxy
    return blockstackd_client.get_nameops_hash_at(block_id, proxy=proxy)


def get_name_record(name, include_history=False, include_expired=True, include_grace=True, proxy=None):
    """
    rpc_get_name_blockchain_record or rpc_get_name_record, depending on include_history
    Return the blockchain-extracted information on success.
    Return {'error': ...} on error
        In particular, return {'error': 'Not found.'} if the name isn't registered

    If include_expired is True, then a name record will be returned even if it expired
    If include_expired is False, but include_grace is True, then the name record will be returned even if it is expired and in the grace period
    """
    
    proxy = get_default_proxy() if proxy is None else proxy
    return blockstackd_client.get_name_record(name, include_history=include_history, include_expired=include_expired, include_grace=include_grace, proxy=proxy)


def get_name_blockchain_record(name, include_expired=True, include_grace=True, proxy=None):
    """
    Get a name and its blockchain history
    Return the record on success, as a dict
    Return {'error': ...} on failure
    """
    return get_name_record(name, include_history=True, include_expired=include_expired, include_grace=include_grace, proxy=proxy)


def get_namespace_blockchain_record(namespace_id, proxy=None):
    """
    get_namespace_blockchain_record
    """
    
    proxy = get_default_proxy() if proxy is None else proxy
    return blockstackd_client.get_namespace_record(namespace_id, proxy=proxy)

    '''
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
    '''


def is_name_registered(fqu, config_path=CONFIG_PATH, proxy=None, include_grace=True):
    """
    Return True if @fqu is a registered name on the blockchain.
    Must not be revoked, and must not be expired.
    """

    proxy = get_default_proxy(config_path) if proxy is None else proxy

    blockchain_record = get_name_record(fqu, include_expired=False, include_grace=include_grace, proxy=proxy)
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

    blockchain_record = get_name_record(fqu, proxy=proxy)
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

    blockchain_record = get_name_record(fqu, proxy=proxy)
    if 'error' in blockchain_record:
        log.debug('Failed to read blockchain record for {}'.format(fqu))
        return False

    return zonefile_hash == blockchain_record.get('value_hash', '')


def is_name_owner(fqu, address, proxy=None):
    """
    return True if @btc_address owns @fqu
    """

    proxy = get_default_proxy() if proxy is None else proxy

    blockchain_record = get_name_record(fqu, include_expired=False, include_grace=True, proxy=proxy)
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
    return blockstackd_client.get_zonefile_inventory(hostport, bit_offset, bit_count, timeout=timeout, my_hostport=my_hostport, proxy=proxy)


def get_atlas_peers(hostport, timeout=30, my_hostport=None, proxy=None):
    """
    Get an atlas peer's neighbors.
    Return {'status': True, 'peers': [peers]} on success.
    Return {'error': ...} on error
    """
    return blockstackd_client.get_atlas_peers(hostport, timeout=timeout, my_hostport=my_hostport, proxy=proxy)


def get_zonefiles(hostport, zonefile_hashes, timeout=30, my_hostport=None, proxy=None):
    """
    Get a set of zonefiles from the given server.
    Return {'status': True, 'zonefiles': {hash: data, ...}} on success
    Return {'error': ...} on error
    """
    return blockstackd_client.get_zonefiles(hostport, zonefile_hashes, timeout=timeout, my_hostport=my_hostport, proxy=proxy)


def put_zonefiles(hostport, zonefile_data_list, timeout=30, my_hostport=None, proxy=None):
    """
    Push one or more zonefiles to the given server.
    Return {'status': True, 'saved': [...]} on success
    Return {'error': ...} on error
    """
    return blockstackd_client.put_zonefiles(hostport, zonefile_data_list, timeout=timeout, my_hostport=my_hostport, proxy=proxy)
