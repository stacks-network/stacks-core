#!/usr/bin/env python
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

import os
import sys
import traceback
import errno
import time
import atexit
import socket
import inspect
import requests
import uuid
import random
import posixpath
import SocketServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
import urllib
import urllib2
import re
import base58
import base64
import jsonschema
import jsontokens
import subprocess
from jsonschema import ValidationError
from schemas import *

from types import ModuleType
import keylib
from keylib import *

import signal
import json
import config as blockstack_config
import config as blockstack_constants
import backend
import proxy
from proxy import json_is_error, json_is_exception

from .constants import BLOCKSTACK_DEBUG, RPC_MAX_ZONEFILE_LEN, CONFIG_PATH, WALLET_FILENAME, TX_MIN_CONFIRMATIONS
from .method_parser import parse_methods
import app
import assets
import data
import resolve
import zonefile
import wallet
import user as user_db
from utils import daemonize 

log = blockstack_config.get_logger()

running = False

RPC_INTERNAL_METHODS = None
RPC_CLI_METHOD_INFO = None


class RPCInternalProxy(object):
    pass


class CLIRPCArgs(object):
    """
    Argument holder for RPC arguments
    destined to a CLI method
    """
    pass


class RPCException(Exception):
    pass


# maps method name to method information
def load_api_cli_method_info(blockstack_client_mod):
    """
    Load and cache RPC method information
    Call this from __main__
    """
    global RPC_CLI_METHOD_INFO

    if RPC_CLI_METHOD_INFO is not None:
        return RPC_CLI_METHOD_INFO

    # load methods
    all_method_names = blockstack_client_mod.get_cli_methods()
    all_methods = parse_methods(all_method_names)

    # map method names to info
    RPC_CLI_METHOD_INFO = {}
    for method_info in all_methods:
        RPC_CLI_METHOD_INFO[method_info['command']] = method_info

    os.environ['BLOCKSTACK_RPC_INITIALIZED_INFO'] = '1'

    return RPC_CLI_METHOD_INFO


def load_api_internal_methods(config_path):
    """
    Load internal RPC method proxy
    (for the server to use to call its own methods safely)
    Call this from __main__
    """
    global RPC_INTERNAL_METHODS

    if RPC_INTERNAL_METHODS is not None:
        return RPC_INTERNAL_METHODS

    srv_internal = BlockstackAPIEndpoint(None, None, config_path=config_path, server=False)

    RPC_INTERNAL_METHODS = srv_internal.internal_proxy

    os.environ['BLOCKSTACK_RPC_INITIALIZED_METHODS'] = '1'

    return RPC_INTERNAL_METHODS


def get_api_internal_methods():
    """
    Get a proxy object to the set of registered
    RPC methods within the RPC server.
    This is used for when the RPC server wants to
    "make a call to itself' without deadlocking.
    """

    global RPC_INTERNAL_METHODS

    msg = 'Failed to load RPC methods (loaded = {})'
    msg = msg.format(os.environ.get('BLOCKSTACK_RPC_INITIALIZED_METHODS', None))
    assert RPC_INTERNAL_METHODS is not None, msg

    return RPC_INTERNAL_METHODS


def get_api_cli_method_info(method_name):
    global RPC_CLI_METHOD_INFO

    msg = 'RPC methods not initialized (loaded = {})'
    msg = msg.format(os.environ.get('BLOCKSTACK_RPC_INITIALIZED_INFO', None))
    assert RPC_CLI_METHOD_INFO is not None, msg

    return RPC_CLI_METHOD_INFO.get(method_name, None)


def list_api_cli_method_info():
    global RPC_CLI_METHOD_INFO

    msg = 'RPC methods not loaded (loaded = {})'
    msg = msg.format(os.environ.get('BLOCKSTACK_RPC_INITIALIZED_INFO', None))
    assert RPC_CLI_METHOD_INFO is not None, msg

    return RPC_CLI_METHOD_INFO


def run_cli_api(command_name, argv, config_path=CONFIG_PATH, check_rpc=True, **kw):
    """
    Invoke a CLI method via the RESTful API.  Note that @command_name
    is the name of the *command*, not the method.

    Return the result of the command on success (as a dict).

    side-effect: caches parsed methods
    """
    command_info = get_api_cli_method_info(command_name)

    # do sanity checks.
    if command_info is None:
        return {'error': 'No such method'}

    num_argv = len(argv)
    num_args = len(command_info['args'])
    num_opts = len(command_info['opts'])
    pragmas = command_info['pragmas']

    if num_argv > num_args + num_opts:
        msg = 'Invalid number of arguments (need at most {}, got {})'
        return {'error': msg.format(num_args + num_opts, num_argv)}

    if num_argv < num_args:
        msg = 'Invalid number of arguments (need at least {})'
        return {'error': msg.format(num_args)}

    if check_rpc and 'rpc' not in command_info['pragmas']:
        return {'error': 'This method is not available via RPC'}

    arg_infos = command_info['args'] + command_info['opts']
    args = CLIRPCArgs()

    for i, arg in enumerate(argv):
        arg_info = arg_infos[i]
        arg_name = arg_info['name']
        arg_type = arg_info['type']

        if arg is not None:
            # type-check...
            try:
                arg = arg_type(arg)
            except:
                return {'error': 'Type error: {} must be {}'.format(arg_name, arg_type)}

        setattr(args, arg_name, arg)

    if 'config_path' in kw:
        config_path = kw.pop('config_path')

    res = command_info['method'](args, config_path=config_path, **kw)

    return res


# need to wrap CLI methods to capture arguments
def api_cli_wrapper(method_info, config_path, check_rpc=True, include_kw=False):
    """
    Factory for producing methods that call the right
    version of run_cli_api.  Makes the same methods
    available via the CLI accessible to both the
    API daemon code and to external clients of the API daemon.
    """
    def argwrapper(*args, **kw):
        cf = config_path
        if kw.has_key('config_path'):
            cf = kw.pop('config_path')

        if include_kw:
            result = run_cli_api(method_info['command'], list(args), config_path=cf, check_rpc=check_rpc, **kw)
        else:
            result = run_cli_api(method_info['command'], list(args), config_path=cf, check_rpc=check_rpc)

        return result

    argwrapper.__doc__ = method_info['method'].__doc__
    argwrapper.__name__ = method_info['method'].__name__
    return argwrapper


class BlockstackAPIEndpointHandler(SimpleHTTPRequestHandler):
    '''
    Blockstack RESTful API endpoint.
    '''

    JSONRPC_MAX_SIZE = 1024 * 1024

    http_errors = {
        errno.ENOENT: 404,
        errno.EINVAL: 401,
        errno.EPERM: 400,
        errno.EACCES: 403,
        errno.EEXIST: 409,
    }

    def _send_headers(self, status_code=200, content_type='application/json'):
        """
        Generate and reply headers
        """
        self.send_response(status_code)
        self.send_header('content-type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')    # CORS
        self.end_headers()


    def _reply_json(self, json_payload, status_code=200):
        """
        Return a JSON-serializable data structure
        """
        self._send_headers(status_code=status_code)
        json_str = json.dumps(json_payload)
        self.wfile.write(json_str)


    def _read_payload(self, maxlen=None):
        """
        Read raw uploaded data.
        Return the data on success
        Return None on I/O error, or if maxlen is not None and the number of bytes read is too big
        """

        client_address_str = "{}:{}".format(self.client_address[0], self.client_address[1])

        # check length
        read_len = self.headers.get('content-length', None)
        if read_len is None:
            log.error("No content-length given from {}".format(client_address_str))
            return None

        try:
            read_len = int(read_len)
        except:
            log.error("Invalid content-length")
            return None

        if maxlen is not None and read_len >= maxlen:
            log.error("Request from {} is too long ({} >= {})".format(client_address_str, read_len, maxlen))
            return None

        # get the payload
        request_str = self.rfile.read(read_len)
        return request_str


    def _read_json(self, schema=None):
        """
        Read a JSON payload from the requester
        Return the parsed payload on success
        Return None on error
        """
        # JSON post?
        request_type = self.headers.get('content-type', None)
        client_address_str = "{}:{}".format(self.client_address[0], self.client_address[1])

        if request_type != 'application/json':
            log.error("Invalid request of type {} from {}".format(request_type, client_address_str))
            return None

        request_str = self._read_payload(maxlen=self.JSONRPC_MAX_SIZE)
        if request_str is None:
            log.error("Failed to read request")
            return None

        # parse the payload
        request = None
        try:
            request = json.loads( request_str )
            if schema is not None:
                jsonschema.validate( request, schema )

        except (TypeError, ValueError, ValidationError) as ve:
            if BLOCKSTACK_DEBUG:
                log.exception(ve)

            return None

        return request


    def parse_qs(self, qs):
        """
        Parse query string, but enforce one instance of each variable.
        Return a dict with the variables on success
        Return None on parse error
        """
        qs_state = urllib2.urlparse.parse_qs(qs)
        ret = {}
        for qs_var, qs_value_list in qs_state.items():
            if len(qs_value_list) > 1:
                return None

            ret[qs_var] = qs_value_list[0]

        return ret


    def verify_session(self, qs_values):
        """
        Verify and return the application's session.
        Return the decoded session token on success.
        Return None on error
        """
        session = None
        auth_header = self.headers.get('authorization', None)
        if auth_header is not None:
            # must be a 'bearer' type
            auth_parts = auth_header.split(" ", 1)
            if auth_parts[0].lower() == 'bearer':
                # valid JWT?
                session_token = auth_parts[1]
                session = app.app_verify_session(session_token, self.server.master_data_pubkey)

        else:
            # possibly given as a qs argument
            session_token = qs_values.get('session', None)
            if session_token is not None:
                session = app.app_verify_session(session_token, self.server.master_data_pubkey)

        return session


    def verify_password(self):
        """
        Verify that the caller submitted the right
        RPC authorization header

        Return True if we got the right header
        Return False if not
        """
        auth_header = self.headers.get('authorization', None)
        if auth_header is None:
            log.debug("No authorization header")
            return False

        auth_parts = auth_header.split(" ", 1)
        if auth_parts[0].lower() != 'basic':
            # need basic auth
            log.debug("Not 'basic' auth")
            return False

        if auth_parts[1] != self.server.api_pass:
            # wrong token
            log.debug("Wrong API password")
            return False

        return True


    def get_path_and_qs(self):
        """
        Parse and obtain the path and query values.
        We don't care about fragments.

        Return {'path': ..., 'qs_values': ...} on success
        Return {'error': ...} on error
        """
        path_parts = self.path.split("?", 1)

        if len(path_parts) > 1:
            qs = path_parts[1].split("#", 1)[0]
        else:
            qs = ""

        path = path_parts[0].split("#", 1)[0]
        path = posixpath.normpath(urllib.unquote(path))

        qs_values = self.parse_qs( qs )
        if qs_values is None:
            return {'error': 'Failed to parse query string'}

        parts = path.strip('/').split('/')

        return {'path': path, 'qs_values': qs_values, 'parts': parts}


    def _route_match( self, method_name, path_info, route_table ):
        """
        Look up the method to call
        Return the route info and its arguments on success:
        Return None on error
        """
        path = path_info['path']

        for route_path, route_info in route_table.items():
            if method_name not in route_info['routes'].keys():
                continue

            grps = re.match(route_path, path)
            if grps is None:
                continue

            groups = grps.groups()
            whitelist = route_info['whitelist']

            assert method_name in whitelist.keys()
            whitelist_info = whitelist[method_name]

            return {
                'route': route_info,
                'whitelist': whitelist_info,
                'method': route_info['routes'][method_name],
                'args': groups,
            }

        return None


    def OPTIONS_preflight( self, ses, path_info ):
        """
        Give back CORS preflight check headers
        """
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')    # CORS
        self.send_header('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE')
        self.send_header('Access-Control-Allow-Headers', 'content-type')
        self.send_header('Access-Control-Max-Age', 21600)
        self.end_headers()
        return


    def GET_auth( self, ses, path_info ):
        """
        Get a session token, given a signed request in the query string.
        Return 200 on success with {'token': token}
        Return 401 if the authRequest argument is missing
        Return 404 if we failed to sign in
        """
        
        token = path_info['qs_values'].get('authRequest')
        if token is None:
            log.debug("missing authRequest")
            return self._send_headers(status_code=401, content_type='text/plain')

        if len(token) > 4096:
            # no way no how
            log.debug("token too long")
            return self._send_headers(status_code=401, content_type='text/plain')

        decoded_token = jsontokens.decode_token(token)
        try:
            assert isinstance(decoded_token, dict)
            assert decoded_token.has_key('payload')
            jsonschema.validate(decoded_token['payload'], APP_AUTHREQUEST_SCHEMA )
        except ValidationError as ve:
            if BLOCKSTACK_TEST:
                log.exception(ve)

            log.debug("Invalid token")
            return self._send_headers(status_code=401, content_type='text/plain')

        app_domain = str(decoded_token['payload']['app_domain'])
        methods = [str(m) for m in decoded_token['payload']['methods']]
        session_lifetime = DEFAULT_SESSION_LIFETIME
        app_user_id = decoded_token['payload'].get('app_user_id', None)
        blockchain_ids = decoded_token['payload'].get('blockchain_ids', None)

        if app_user_id is not None:
            app_user_id = str(app_user_id)

        if blockchain_ids is not None:
            blockchain_ids = ",".join(blockchain_ids)

        internal = self.server.get_internal_proxy()
        res = internal.cli_app_signin( app_domain, ",".join(methods), session_lifetime, blockchain_ids, app_user_id, config_path=self.server.config_path )
        if 'error' in res:
            log.error("Failed to sign in: {}".format(res['error']))
            return self._reply_json({'error': res['error']}, status_code=404)

        return self._reply_json({'token': res['token']})


    def GET_names_owned_by_address( self, ses, path_info, address ):
        """
        Get all names owned by an address
        Returns the list on success
        Returns 500 on failure to get names
        """
        res = proxy.get_names_owned_by_address(address)
        if json_is_error(res):
            log.error("Failed to get names owned by address")
            self._reply_json({'error': 'Failed to list names by address'}, status_code=500)
            return

        self._reply_json({'names': res})
        return


    def GET_names( self, ses, path_info ):
        """
        Get all names in existence
        Returns the list on success
        Returns 401 on invalid arguments
        Returns 500 on failure to get names
        """

        # optional args: offset=..., count=...
        qs_values = path_info['qs_values']
        offset = qs_values.get('offset')
        count = qs_values.get('count')

        try:
            if offset is not None:
                offset = int(offset)

            if count is not None:
                count = int(count)

        except ValueError:
            log.error("Invalid offset and/or count")
            return self._send_headers(status_code=401, content_type='text/plain')

        res = proxy.get_all_names(offset, count)
        if json_is_error(res):
            log.error("Failed to list all names (offset={}, count={}): {}".format(offset, count, res['error']))
            self._reply_json({'error': 'Failed to list all names'}, status_code=500)
            return

        self._reply_json(res)
        return


    def POST_names( self, ses, path_info ):
        """
        Register or renew a name.
        Takes {'name': name to register}
        Reply 202 with a txid on success
        Reply 401 for invalid payload
        Reply 500 on failure to register
        """
        request_schema = {
            'type': 'object',
            'properties': {
                "name": {
                    'type': 'string',
                    'pattern': OP_NAME_PATTERN
                },
                "zonefile": {
                    'type': 'string',
                    'maxLength': RPC_MAX_ZONEFILE_LEN,
                },
                "owner_address": {
                    'type': 'string',
                    'pattern': OP_BASE58CHECK_PATTERN,
                },
                'min_confs': {
                    'type': 'integer'
                },
                'tx_fee': {
                    'type': 'integer',
                },
                'cost_satoshis': {
                    'type': 'integer',
                },
            },
            'required': [
                'name'
            ],
            'additionalProperties': False,
        }

        qs_values = path_info['qs_values']
        internal = self.server.get_internal_proxy()

        request = self._read_json(schema=request_schema)
        if request is None:
            return self._reply_json({"error": 'Invalid request'}, status_code=401)

        name = request['name']
        zonefile_txt = request.get('zonefile', None)
        recipient_address = request.get('owner_address', None)
        min_confs = request.get('min_confs', TX_MIN_CONFIRMATIONS)
        tx_fee = request.get('tx_fee', None)
        cost_satoshis = request.get('cost_satoshis', None)

        if min_confs < 0:
            min_confs = 0

        if min_confs != TX_MIN_CONFIRMATIONS:
            log.warning("Using payment UTXOs with as few as {} confirmations".format(min_confs))

        if tx_fee is not None:
            if tx_fee > (5 * 1e5):
                # this is a bug...
                log.error("Absurd tx fee {}".format(tx_fee))
                return self._reply_json({'error': 'Absurd transaction fee'}, status_code=401)
        
        # do we own this name already?
        # i.e. do we need to renew?
        res = proxy.get_names_owned_by_address( self.server.wallet_keys['owner_addresses'][0] )
        if json_is_error(res):
            log.error("Failed to get names owned by address")
            self._reply_json({'error': 'Failed to list names by address'}, status_code=500)
            return

        op = None
        if name in res:
            # renew
            for prop in request_schema['properties'].keys():
                if prop in request.keys() and prop not in ['name', 'tx_fee']:
                    log.debug("Invalid argument {}".format(prop))
                    return self._reply_json({'error': 'Name already owned by this wallet'}, status_code=401)

            op = 'renew'
            log.debug("renew {}".format(name))
            res = internal.cli_renew(name, interactive=False, cost_satoshis=cost_satoshis, tx_fee=tx_fee)

        else:
            # register
            op = 'register'
            log.debug("register {}".format(name))
            res = internal.cli_register(name, zonefile_txt, recipient_address, min_confs, interactive=False, force_data=True, cost_satoshis=cost_satoshis, tx_fee=tx_fee)

        if 'error' in res:
            log.error("Failed to {} {}".format(op, name))
            return self._reply_json({"error": "{} failed.\n{}".format(op, res['error'])}, status_code=500)

        resp = {
            'success': True,
            'transaction_hash': res['transaction_hash'],
            'message': 'Name queued for registration.  The process takes several hours.  You can check the status with `blockstack info`.',
        }

        if 'tx' in res:
            resp['tx'] = res['tx']

        return self._reply_json(resp, status_code=202)


    def GET_name_info( self, ses, path_info, name ):
        """
        Look up a name's zonefile, address, and last TXID
        Reply status, zonefile, zonefile hash, address, and last TXID.
        'status' can be 'available', 'registered', 'revoked', or 'pending'
        """
        # are there any pending operations on this name
        internal = self.server.get_internal_proxy()
        registrar_info = internal.cli_get_registrar_info()
        if 'error' in registrar_info:
            log.error("Failed to connect to backend")
            self._reply_json({'error': 'Failed to connect to backend'}, status_code=500)
            return

        # if the name has pending operations, return the pending status
        for queue_type in registrar_info.keys():
            for pending_entry in registrar_info[queue_type]:
                if pending_entry['name'] == name:
                    # pending
                    log.debug("{} is pending".format(name))
                    ret = {
                        'status': 'pending',
                        'operation': queue_type,
                        'txid': pending_entry['tx_hash'],
                        'confirmations': pending_entry['confirmations'],
                    }
                    self._reply_json(ret)
                    return

        # not pending. get name
        name_rec = proxy.get_name_blockchain_record(name)
        if json_is_error(name_rec):
            # does it exist?
            if name_rec['error'] == 'Not found.':
                ret = {
                    'status': 'available'
                }
                self._reply_json(ret, status_code=404)
                return

            else:
                # some other error
                log.error("Failed to look up {}: {}".format(name, name_rec['error']))
                self._reply_json({'error': 'Failed to lookup name'}, status_code=500)
                return

        zonefile_res = zonefile.get_name_zonefile(name, raw_zonefile=True, name_record=name_rec)
        zonefile_txt = None
        if 'error' in zonefile_res:
            error = "No zonefile for name"
            if zonefile_res is not None:
                error = zonefile_res['error']

            log.error("Failed to get name zonefile for {}: {}".format(name, error))

        else:
            zonefile_txt = zonefile_res.pop("zonefile")

        status = 'revoked' if name_rec['revoked'] else 'registered'

        log.debug("{} is {}".format(name, status))
        ret = {
            'status': status,
            'zonefile': zonefile_txt,
            'zonefile_hash': name_rec['value_hash'],
            'address': name_rec['address'],
            'last_txid': name_rec['txid'],
            'blockchain': 'bitcoin',
            'expire_block': name_rec['expire_block'],
        }

        self._reply_json(ret)
        return


    def GET_name_history(self, ses, path_info, name ):
        """
        Get the history of a name.
        Takes `start_block` and `end_block` in the query string.
        return the history on success
        return 401 on invalid start_block or end_block
        return 500 on failure to query blockstack server
        """
        qs_values = path_info['qs_values']
        start_block = qs_values.get('start_block', None)
        end_block = qs_values.get('end_block', None)

        try:
            if start_block is None:
                start_block = FIRST_BLOCK_MAINNET
            else:
                start_block = int(start_block)

            if end_block is None:
                end_block = 2**32   # hope we never get this many blocks!
            else:
                end_block = int(end_block)
        except:
            log.error("Invalid start_block or end_block")
            self._reply_json({'error': 'Invalid start_block or end_block'}, status_code=401)
            return

        res = proxy.get_name_blockchain_history(name, start_block, end_block)
        if json_is_error(res):
            self._reply_json({'error': res['error']}, status_code=500)
            return

        self._reply_json(res)
        return


    def PUT_name_transfer( self, ses, path_info, name ):
        """
        Transfer a name to a new owner
        Return 202 and a txid on success, with {'transaction_hash': txid}
        Return 401 on invalid recipient address
        Return 500 on failure to broadcast tx
        """
        request_schema = {
            'type': 'object',
            'properties': {
                "owner": {
                    'type': 'string',
                    'pattern': OP_ADDRESS_PATTERN
                },
                'tx_fee': {
                    'type': 'integer',
                },
            },
            'required': [
                'owner'
            ],
            'additionalProperties': False,
        }

        qs_values = path_info['qs_values']
        internal = self.server.get_internal_proxy()

        request = self._read_json(schema=request_schema)
        if request is None:
            self._reply_json({"error": 'Invalid request'}, status_code=401)
            return

        recipient_address = request['owner']
        try:
            base58.b58decode_check(recipient_address)
        except ValueError:
            self._reply_json({"error": 'Invalid owner address'}, status_code=401)
            return

        tx_fee = request.get('tx_fee', None)
        if tx_fee is not None:
            if tx_fee > (5 * 1e5):
                # this is a bug...
                log.error("Absurd tx fee {}".format(tx_fee))
                return self._reply_json({'error': 'Absurd transaction fee'}, status_code=401)


        res = internal.cli_transfer(name, recipient_address, interactive=False, tx_fee=tx_fee)
        if 'error' in res:
            log.error("Failed to transfer {}: {}".format(name, res['error']))
            self._reply_json({"error": 'Transfer failed.\n{}'.format(res['error'])}, status_code=500)
            return

        resp = {
            'success': True,
            'transaction_hash': res['transaction_hash'],
            'message': 'Name queued for transfer.  The process takes ~1 hour.  You can check the status with `blockstack info`.',
        }
        
        if 'tx' in res:
            resp['tx'] = res['tx']

        self._reply_json(resp, status_code=202)
        return


    def PUT_name_zonefile( self, ses, path_info, name ):
        """
        Set a new name zonefile
        Return 202 with a txid on success, with {'transaction_hash': txid}
        Return 401 on invalid zonefile payload
        Return 500 on failure to broadcast tx
        """
        request_schema = {
            'type': 'object',
            'properties': {
                "zonefile": {
                    'type': 'string',
                    'maxLength': RPC_MAX_ZONEFILE_LEN,
                },
                'zonefile_b64': {
                    'type': 'string',
                    'maxLength': (RPC_MAX_ZONEFILE_LEN * 4) / 3 + 1,
                },
                'zonefile_hash': {
                    'type': 'string',
                    'pattern': OP_ZONEFILE_HASH_PATTERN,
                },
                'tx_fee': {
                    'type': 'integer',
                },
            },
            'additionalProperties': False,
        }

        qs_values = path_info['qs_values']
        internal = self.server.get_internal_proxy()

        request = self._read_json(schema=request_schema)
        if request is None:
            self._reply_json({"error": 'Invalid request'}, status_code=401)
            return

        zonefile_hash = request.get('zonefile_hash')
        zonefile_str = request.get('zonefile')
        zonefile_str_b64 = request.get('zonefile_b64')
        tx_fee = request.get('tx_fee', None)
        
        if tx_fee is not None:
            if tx_fee > (5 * 1e5):
                # this is a bug...
                log.error("Absurd tx fee {}".format(tx_fee))
                return self._reply_json({'error': 'Absurd transaction fee'}, status_code=401)

        if zonefile_hash is None and zonefile_str is None and zonefile_str_b64 is None:
            log.error("No zonefile or zonefile hash received")
            self._reply_json({'error': 'Invalid request'}, status_code=401)
            return

        if zonefile_str is not None and zonefile_str_b64 is not None:
            log.error("Got both 'zonefile' and 'zonefile_b64'")
            self._reply_json({'error': 'Invalid request'}, status_code=401)
            return 

        if zonefile_str_b64 is not None:
            try:
                zonefile_str = base64.b64decode(zonefile_str_b64)
            except:
                self._reply_json({'error': 'Invalid base64-encoded zonefile'}, status_code=401)
                return

        if zonefile_hash is not None and zonefile_str is not None:
            log.error("Got both zonefile and zonefile hash")
            self._reply_json({'error': 'Invalid request'}, status_code=401)
            return

        res = None
        if zonefile_str is not None:
            res = internal.cli_update(name, str(zonefile_str), "false", interactive=False, nonstandard=True, force_data=True, tx_fee=tx_fee)

        else:
            res = internal.cli_set_zonefile_hash(name, str(zonefile_hash), tx_fee=tx_fee)

        if 'error' in res:
            log.error("Failed to update {}: {}".format(name, res['error']))
            self._reply_json({"error": "Update failed.\n{}".format(res['error'])}, status_code=503)
            return

        resp = {
            'success': True,
            'zonefile_hash': res['zonefile_hash'],
            'transaction_hash': res['transaction_hash'],
            'message': 'Name queued for update.  The process takes ~1 hour.  You can check the status with `blockstack info`.',
        }

        if 'tx' in res:
            resp['tx'] = res['tx']

        self._reply_json(resp, status_code=202)
        return


    def DELETE_name( self, ses, path_info, name ):
        """
        Revoke a name.
        Reply 202 on success, with {'transaction_hash': txid}
        Reply 401 on invalid payload
        Reply 500 on failure to revoke
        """
        internal = self.server.get_internal_proxy()
        res = internal.cli_revoke(name, interactive=False)
        if 'error' in res:
            log.error("Failed to revoke {}: {}".format(name, res['error']))
            self._reply_json({"error": "Revoke failed.\n{}".format(res['error'])}, status_code=500)
            return

        resp = {
            'success': True,
            'transaction_hash': res['transaction_hash'],
            'message': 'Name queued for revocation.  The process takes ~1 hour.  You can check the status with `blockstack info`.'
        }

        if 'tx' in res:
            resp['tx'] = res['tx']

        self._reply_json(resp, status_code=202)
        return


    def GET_name_zonefile( self, ses, path_info, name ):
        """
        Get the name's current zonefile data
        Reply the {'zonefile': zonefile} on success
        Reply 500 on failure to fetch data
        """
        internal = self.server.get_internal_proxy()
        resp = internal.cli_get_name_zonefile(name, "true")
        if json_is_error(resp):
            self._reply_json({"error": resp['error']}, status_code=500)
            return

        self._reply_json({'zonefile': resp['zonefile']})
        return


    def GET_name_zonefile_by_hash( self, ses, path_info, name, zonefile_hash ):
        """
        Get a historic zonefile for a name
        Reply {'zonefile': zonefile} on success
        Reply 404 on not found
        Reply 500 on failure to fetch data
        """
        conf = blockstack_config.get_config(self.server.config_path)

        blockstack_server = conf['server']
        blockstack_port = conf['port']
        blockstack_hostport = '{}:{}'.format(blockstack_server, blockstack_port)

        historic_zonefiles = data.list_update_history(name)
        if json_is_error(historic_zonefiles):
            self._reply_json({'error': historic_zonefiles['error']}, status_code=500)
            return

        if zonefile_hash not in historic_zonefiles:
            self._reply_json({'error': 'No such zonefile'}, status_code=404)
            return

        resp = proxy.get_zonefiles( blockstack_hostport, [str(zonefile_hash)] )
        if json_is_error(resp):
            self._reply_json({'error': resp['error']}, status_code=500)
            return

        self._reply_json({'zonefile': resp['zonefiles'][str(zonefile_hash)]})
        return


    def PUT_name_zonefile_hash( self, ses, path_info, name, zonefile_hash ):
        """
        Set a name's zonefile hash directly.
        Reply 202 with txid on success, as {'transaction_hash': txid}
        Reply 500 on internal failure
        """
        internal = self.server.get_internal_proxy()
        resp = internal.cli_set_zonefile_hash( name, zonefile_hash )
        if json_is_error(resp):
            self._reply_json({'error': resp['error']}, status_code=500)
            return

        ret = {
            'status': True,
            'transaction_hash': resp['transaction_hash'],
            'message': 'Name queued for update.  The process takes ~1 hour.  You can check the status with `blockstack info`.'
        }

        if 'tx' in res:
            ret['tx'] = res['tx']

        self._reply_json(ret)
        return


    def POST_users( self, ses, path_info ):
        """
        Create a profile for a user, given the blockchain ID and profile
        Return 200 on success
        Return 500 on failure to create the user account
        Return 503 on failure to replicate the profile (the caller should try POST_user_profile to re-try uploading)
        """
        upload_schema = {
            'type': 'object',
            'properties': {
                'blockchain_id': {
                    'type': 'string',
                    'pattern': OP_NAME_PATTERN,
                },
                'profile': {
                    'type': 'object'
                },
            },
            'required': [
                'name',
                'profile'
            ],
            'additionalProperties': False
        }

        user_profile_json = self._read_json(schema=upload_schema)
        if user_profile_json is None:
            self._reply_json({'error': 'Invalid user ID or profile'}, status_code=401)
            return

        name = user_profile_json['blockchain_id']
        user_profile = user_profile_json['profile']

        # store profile
        internal = self.server.get_internal_proxy()
        profile_str = json.dumps(user_profile)
        res = internal.cli_put_user_profile( name, profile_str, force_data=True )
        if json_is_error(res):
            self._reply_json({'error': 'Failed to store user profile: {}'.format(res['error'])}, status_code=503)
            return

        self._reply_json({'status': True})
        return


    def DELETE_user_profile( self, ses, path_info, user_id ):
        """
        Delete a profile.
        Return 200 on success
        Return 500 on failure to remove the local user information.
        Return 503 to delete the profile.  The caller should try this method again until it succeeds.
        """
        internal = self.server.get_internal_proxy()
        res = internal.cli_delete_profile( user_id, wallet_keys=self.server.wallet_keys )
        if json_is_error(res):
            self._reply_json({'error': 'Failed to delete user profile: {}'.format(res['error'])}, status_code=503)
            return

        self._reply_json({'status': True})
        return


    def GET_user_profile( self, ses, path_info, user_id ):
        """
        Get a user profile.
        Only works on the session user's profile
        Reply the profile on success
        Return 404 on failure to load
        """
        internal = self.server.get_internal_proxy()
        resp = internal.cli_lookup( user_id )
        if json_is_error(resp):
            self._reply_json({'error': resp['error']}, status_code=404)
            return

        self._reply_json(resp['profile'])
        return


    def PATCH_user_profile( self, ses, path_info, user_id ):
        """
        Patch a user profile.
        Reply 200 on success
        Reply 401 if the data uploaded isn't valid JSON
        Reply 403 on invalid user ID (must match session user ID)
        Reply 500 on failure to save
        """
        upload_schema = {
            'type': 'object',
            'properties': {
                'profile': {
                    'type': 'object'
                },
            },
            'required': [
                'profile'
            ],
            'additionalProperties': False
        }

        profile_json = self._read_json(schema=upload_schema)
        if profile_json is None:
            self._reply_json({'error': 'Invalid profile'}, status_code=401)
            return

        internal = self.server.get_internal_proxy()
        resp = internal.cli_put_profile( user_id, json.dumps(profile_json['profile']), wallet_keys=self.server.wallet_keys, force_data=True )
        if json_is_error(resp):
            self._reply_json({'error': resp['error']}, status_code=500)
            return

        self._reply_json(resp)
        return


    def GET_store( self, ses, path_info, app_user_id_or_app_domain ):
        """
        Get the specific data store for this app user account or app domain
        Reply 200 on success
        Reply 503 on failure to load
        
        # TODO see if we can load cached app user private key to auth request
        """
        
        internal = self.server.get_internal_proxy()

        app_user_id = None
        if app_user_id_or_app_domain == ses['app_user_id']:
            app_user_id = app_user_id_or_app_domain

        else:
            # must be the app domain 
            app_user_id_res = internal.cli_datastore_get_id( app_user_id_or_app_domain, config_path=self.server.config_path, wallet_keys=self.server.wallet_keys )
            if 'error' in app_user_id_res:
                return self._reply_json({'error': 'Unrecognized datastore identifier'}, status_code=404)

            app_user_id = app_user_id_res['datastore_id']

        if app_user_id != ses['app_user_id']:
            return self._reply_json({'error': 'Invalid datastore ID'}, status=403)

        internal = self.server.get_internal_proxy()
        res = internal.cli_get_datastore(app_user_id, config_path=self.server.config_path)
        if 'error' in res:
            if res.has_key('errno'):
                # propagate an error code, if possible
                if res['errno'] in self.http_errors:
                    return self._send_headers(status_code=self.http_errors[res['errno']], content_type='text/plain')
            
            return self._reply_json({'error': res['error']}, status_code=503)

        res['datastore_id'] = app_user_id
        return self._reply_json(res)


    def POST_store( self, ses, path_info ):
        """
        Make a data store for the application identified by the session
        Reply 200 on success
        Reply 503 on failure to replicate
        
        Takes optional "drivers={driver,driver,driver}" qs argument.

        # TODO see if we can load cached app user private key
        """
        
        qs = path_info['qs_values']
        drivers = qs.get('drivers', None)
        app_domain = ses['app_domain']
        internal = self.server.get_internal_proxy()

        # does it exist?
        res = internal.cli_create_datastore(app_domain, drivers, wallet_keys=self.server.wallet_keys, config_path=self.server.config_path)
        if json_is_error(res):
            if res.has_key('errno'):
                # propagate an error code, if possible
                if res['errno'] in self.http_errors:
                    return self._send_headers(status_code=self.http_errors[res['errno']], content_type='text/plain')
            
            return self._reply_json({'error': 'Failed to put datastore: {}'.format(res['error'])}, status_code=503)
        
        # must be the app domain 
        app_user_id_res = internal.cli_datastore_get_id( app_domain, config_path=self.server.config_path, wallet_keys=self.server.wallet_keys )
        if 'error' in app_user_id_res:
            return self._reply_json({'error': 'Unrecognized datastore identifier'}, status_code=404)

        app_user_id = app_user_id_res['datastore_id']
        return self._reply_json({'status': True, 'datastore_id': app_user_id})


    def PUT_store( self, ses, path_info, user_id ):
        """
        Update a data store for the application identified by the session.
        """
        return self._reply_json({'error': 'Not implemented'}, status_code=501) 


    def DELETE_store( self, ses, path_info ):
        """
        Delete the data store identified by the given session
        Reply 200 on success
        Reply 403 on invalid user ID
        Reply 503 on (partial) failure to delete all replicas

        # TODO see if we can load cached app user private key
        """
        internal = self.server.get_internal_proxy()
        qs = path_info['qs_values']
        force = qs.get('force', "0")
        force = (force.lower() in ['1', 'true'])

        app_domain = ses['app_domain']
       
        internal = self.server.get_internal_proxy()
        res = internal.cli_delete_datastore(app_domain, force)
        if json_is_error(res):
            if res.has_key('errno'):
                # propagate an error code, if possible
                if res['errno'] in self.http_errors:
                    return self._send_headers(status_code=self.http_errors[res['errno']], content_type='text/plain')

            self._reply_json({'error': 'Failed to delete datastore: {}'.format(res['error'])}, status_code=503)
            return

        self._reply_json({'status': True})
        return


    def GET_store_item( self, ses, path_info, app_user_id, inode_type ):
        """
        Get a store item
        Only works on the session's user ID
        Reply 200 on succes, with the raw data (as application/octet-stream for files, and as application/json for directories and inodes)
        Reply 401 if no path is given
        Reply 403 on invalid user ID
        Reply 404 if the file/directory/datastore does not exist
        Reply 500 if we fail to load the datastore record for some other reason than the above
        Reply 503 on failure to load data from storage providers
        
        # TODO see if we can load cached app user private key
        """
        if app_user_id != ses['app_user_id']:
            return self._reply_json({'error': 'Invalid user'}, status=403)

        if inode_type not in ['files', 'directories', 'inodes']:
            self._reply_json({'error': 'Invalid request'}, status_code=401)
            return

        qs = path_info['qs_values']
        internal = self.server.get_internal_proxy()
        path = qs.get('path', None)
        if path is None:
            self._reply_json({'error': 'No path given'}, status_code=401)
            return

        res = None

        if inode_type == 'files':
            res = internal.cli_datastore_getfile(app_user_id, path, config_path=self.server.config_path)
        elif inode_type == 'directories':
            res = internal.cli_datastore_listdir(app_user_id, path, config_path=self.server.config_path)
        else:
            res = internal.cli_datastore_stat(app_user_id, path, config_path=self.server.config_path)

        if json_is_error(res):
            if res.has_key('errno'):
                # propagate an error code, if possible
                if res['errno'] in self.http_errors:
                    return self._send_headers(status_code=self.http_errors[res['errno']], content_type='text/plain')
            
            err = {'error': 'Failed to read {}: {}'.format(inode_type, res['error'])}
            self._reply_json(err, status_code=500)
            return

        if inode_type == 'files':
            self._send_headers(status_code=200, content_type='application/octet-stream')
            self.wfile.write(res['file']['idata'])

        elif inode_type == 'directories':
            self._reply_json(res['dir']['idata'])

        else:
            self._reply_json(res['inode'])

        return


    def POST_store_item( self, ses, path_info, app_user_id, inode_type ):
        """
        Create a store item.
        Only works with the session's user ID.
        For directories, this is mkdir.  There is no payload.
        For files, this is putfile.  The payload is the raw data
        Reply 200 on success
        Reply 401 if no path is given, or we can't read the file
        Reply 403 on invalid userID
        Reply 503 on failure to upload data to storage providers
        """
        return self._create_or_update_store_item( ses, path_info, app_user_id, inode_type, create=True )


    def PUT_store_item(self, ses, path_info, user_id, store_id, inode_type ):
        """
        Update a store item.
        Only works with the session's user ID.
        Only works on files.
        Reply 200 on success
        Reply 401 if no path is given, ir we can't read the file
        Reply 403 on invalid userID
        Reply 503 on failre to upload data to storage providers
        """
        return self._create_or_update_store_item( ses, path_info, user_id, store_id, inode_type, create=False )


    def _create_or_update_store_item( self, ses, path_info, app_user_id, inode_type, create=False ):
        """
        Create or update a file, or create a directory.
        Implements POST_store_item and PUT_store_item
        
        # TODO see if we can load cached app user private key
        """
        
        if app_user_id != ses['app_user_id']:
            return self._reply_json({'error': 'Invalid user'}, status=403)

        if inode_type not in ['files', 'directories']:
            log.debug("Invalid request: unrecognized inode type")
            self._reply_json({'error': 'Invalid request'}, status_code=401)
            return

        qs = path_info['qs_values']
        internal = self.server.get_internal_proxy()
        path = qs.get('path', None)
        if path is None:
            log.debug("Invalid request: no path given")
            self._reply_json({'error': 'No path given'}, status_code=401)
            return

        res = None

        if inode_type == 'files':
            data = self._read_payload()
            if data is None:
                self._reply_json({'error': 'Failed to read file data'}, status_code=401)
                return

            do_create = None
            if create:
                do_create = "True"
            else:
                do_create = "False"

            res = internal.cli_datastore_putfile(ses['app_domain'], path, data, do_create, force_data=True, wallet_keys=self.server.wallet_keys)

        elif create:
            res = internal.cli_datastore_mkdir(ses['app_domain'], path, wallet_keys=self.server.wallet_keys)

        else:
            log.error("Invalid request: cannot update directory {}".format(path))
            self._reply_json({'error': 'Invalid request'}, status_code=401)
            return

        if 'error' in res:
            if res.has_key('errno'):
                # propagate an error code, if possible
                if res['errno'] in self.http_errors:
                    return self._send_headers(status_code=self.http_errors[res['errno']], content_type='text/plain')
            
            log.error("Failed to make {} {}: {}".format(inode_type, path, res['error']))
            self._reply_json({'error': 'Failed to store item'}, status_code=503)
            return

        self._reply_json({'status': True})
        return


    def DELETE_store_item( self, ses, path_info, app_user_id, inode_type ):
        """
        Delete a store item.
        Only works with the session's user ID.
        For directories, this is rmdir.
        For files, this is deletefile.
        Reply 200 on success
        Reply 401 if no path is given
        Reply 403 on invalid user ID
        Reply 404 if the file/directory does not exist
        Reply 503 on failure to contact remote storage providers
        
        # TODO see if we can load cached app user private key
        """
        if app_user_id != ses['app_user_id']:
            return self._reply_json({'error': 'Invalid user'}, status=403)

        if inode_type not in ['files', 'directories']:
            self._reply_json({'error': 'Invalid request'}, status_code=401)
            return

        qs = path_info['qs_values']
        internal = self.server.get_internal_proxy()
        path = qs.get('path', None)
        if path is None:
            self._reply_json({'error': 'No path given'}, status_code=401)
            return

        res = None

        if inode_type == 'files':
            res = internal.cli_datastore_deletefile(ses['app_domain'], path, wallet_keys=self.server.wallet_keys)

        else:
            res = internal.cli_datastore_rmdir(ses['app_domain'], path, wallet_keys=self.server.wallet_keys)

        if 'error' in res:
            log.error("Failed to remove {} {}: {}".format(inode_type, path, res['error']))
            if res.has_key('errno'):
                # propagate an error code, if possible
                if res['errno'] in self.http_errors:
                    return self._send_headers(status_code=self.http_errors[res['errno']], content_type='text/plain')

            else:
                self._reply_json({'error': 'Failed to remove item'}, status_code=503)
                return

        self._reply_json({'status': True})
        return


    def GET_app_resource( self, ses, path_info, blockchain_id, app_domain ):
        """
        Get a signed application resource
        qs includes `name=...` for the resource name
        Return 200 on success with `application/octet-stream`
        Return 401 if no path is given
        Return 403 if the session has a whitelist of blockchain IDs, and the given one is not present
        Return 404 on not found
        Return 503 on failure to load
        """

        if ses is not None:
            if ses['app_domain'] != app_domain:
                return self._reply_json({'error': 'Unauthorized app domain'}, status_code=403)

            blockchain_ids = ses.get('blockchain_ids', None)
            if blockchain_ids is not None and blockchain_id not in blockchain_ids:
                return self._reply_json({'error': 'Unauthorized blockchain ID'}, status_code=403)

        qs = path_info['qs_values']
        internal = self.server.get_internal_proxy()
        res_path = qs.get('name', None)
        if res_path is None:
            return self._reply_json({'error': 'No resource name given'}, status_code=401)
        
        res = internal.cli_app_get_resource(blockchain_id, app_domain, res_path, config_path=self.server.config_path)
        if 'error' in res:
            if res.has_key('errno') and res['errno'] in self.http_errors:
                return self._send_headers(status_code=self.http_errors[res['errno']], content_type='text/plain')

            else:
                return self._reply_json({'error': 'Failed to load resource'}, status_code=503)

        self._send_headers(status_code=200, content_type='application/octet-stream')
        self.wfile.write(res['res'])
        return


    def GET_collections( self, ses, path_info, user_id ):
        """
        Get the list of collections
        Reply the list of collections on success.
        """
        return self._reply_json({'error': 'Not implemented'}, status_code=501) 


    def POST_collections( self, ses, path_info, user_id ):
        """
        Create a new collection
        """
        return self._reply_json({'error': 'Not implemented'}, status_code=501) 


    def GET_collection_info( self, ses, path_info, user_id, collection_id ):
        """
        Get metadata on a user's collection (including the list of items)
        Reply the list of items on success
        Reply 404 on not found
        """
        return self._reply_json({'error': 'Not implemented'}, status_code=501) 


    def GET_collection_item( self, ses, path_info, user_id, collection_id, item_id ):
        """
        Get a particular item from a particular collection
        Reply the item requested
        Reply 404 if the collection doesn't exist
        Reply 404 if the item doesn't exist
        """
        return self._reply_json({'error': 'Not implemented'}, status_code=501) 


    def POST_collection_item( self, ses, path_info, user_id, collection_id ):
        """
        Add an item to a collection
        """
        return self._reply_json({'error': 'Not implemented'}, status_code=501) 


    def GET_prices_namespace( self, ses, path_info, namespace_id ):
        """
        Get the price for a namespace
        Reply the price for the namespace as {'satoshis': price in satoshis}
        Reply 500 if we can't reach the namespace for whatever reason
        """
        price_info = proxy.get_namespace_cost(namespace_id)
        if json_is_error(price_info):
            # error
            status_code = None
            if json_is_exception(price_info):
                status_code = 500
            else:
                status_code = 404

            self._reply_json({'error': price_info['error']}, status_code=status_code)
            return

        ret = {
            'satoshis': price_info['satoshis']
        }
        self._reply_json(ret)
        return


    def GET_prices_name( self, ses, path_info, name ):
        """
        Get the price for a name in a namespace
        Reply the price as {'satoshis': price in satoshis}
        Reply 404 if the namespace doesn't exist
        Reply 500 if we can't reach the server for whatever reason
        """

        internal = self.server.get_internal_proxy()
        res = internal.cli_price(name)
        if json_is_error(res):
            # error
            status_code = None
            if json_is_exception(res):
                status_code = 500
            else:
                status_code = 404

            self._reply_json({'error': res['error']}, status_code=status_code)
            return

        self._reply_json(res)
        return


    def GET_namespaces( self, ses, path_info ):
        """
        Get the list of all namespaces
        Reply all existing namespaces
        Reply 500 if we can't reach the server for whatever reason
        """

        qs_values = path_info['qs_values']
        offset = qs_values.get('offset', None)
        count = qs_values.get('count', None)

        namespaces = proxy.get_all_namespaces(offset=offset, count=count)
        if json_is_error(namespaces):
            # error
            self._reply_json({'error': namespaces['error']}, status_code=500)
            return

        self._reply_json(namespaces)
        return


    def POST_namespaces( self, ses, path_info ):
        """
        Preorder and reveal a namespace
        Currently unimpleemnted
        """
        self._reply_json({'error': 'Unimplemented'}, status_code=405)
        return


    def GET_namespace_info( self, ses, path_info, namespace_id ):
        """
        Look up a namespace's info
        Reply information about a namespace
        Reply 404 if the namespace doesn't exist
        Reply 500 for any error in talking to the blocksatck server
        """

        namespace_rec = proxy.get_namespace_blockchain_record(namespace_id)
        if json_is_error(namespace_rec):
            # error
            status_code = None
            if json_is_exception(namespace_rec):
                status_code = 500
            else:
                status_code = 404

            self._reply_json({'error': namespace_rec['error']}, status_code=status_code)
            return

        self._reply_json(namespace_rec)
        return


    def PUT_namespace_ready( self, ses, path_info, namespace_id ):
        """
        Launch a namespace; mark it as ready.
        Not implemented
        """
        return self._reply_json({'error': 'Not implemented'}, status_code=501) 


    def GET_namespace_names( self, ses, path_info, namespace_id ):
        """
        Get the list of names in a namespace
        Reply the list of names in a namespace
        Reply 404 if the namespace doesn't exist
        Reply 500 for any error in talking to the blockstack server
        """

        qs_values = path_info['qs_values']
        offset = qs_values.get('offset', None)
        count = qs_values.get('count', None)

        namespace_names = proxy.get_names_in_namespace(namespace_id, offset=offset, count=count)
        if json_is_error(namespace_names):
            # error
            status_code = None
            if json_is_exception(namespace_names):
                status_code = 500
            else:
                status_code = 404

            self._reply_json({'error': namespace_names['error']}, status_code=status_code)
            return

        self._reply_json(namespace_names)
        return


    def POST_namespace_name_import( self, ses, path_info, namespace_id ):
        """
        Import a name.
        Not implemented
        """
        return self._reply_json({'error': 'Not implemented'}, status_code=501) 


    def PUT_namespace_name_import( self, ses, path_info, namespace_id ):
        """
        Re-import a name
        Not implemented
        """
        return self._reply_json({'error': 'Not implemented'}, status_code=501) 


    def GET_wallet_payment_address( self, ses, path_info ):
        """
        Get the wallet payment address
        Return 200 with {'address': ...} on success
        Return 500 on failure to read the wallet
        """

        wallet_path = os.path.join( os.path.dirname(self.server.config_path), WALLET_FILENAME )
        if not os.path.exists(wallet_path):
            return self._reply_json({'error': 'No such wallet'}, status_code=500)

        try:
            payment_address, owner_address, data_pubkey = wallet.get_addresses_from_file(wallet_path=wallet_path)
            self._reply_json({'address': payment_address})
            return

        except Exception as e:
            self._reply_json({'error': 'Failed to read wallet file'}, status_code=500)
            return


    def GET_wallet_owner_address( self, ses, path_info ):
        """
        Get the wallet owner address
        Return 200 with {'address': ...} on success
        Return 500 on failure to read the wallet
        """

        wallet_path = os.path.join( os.path.dirname(self.server.config_path), WALLET_FILENAME )
        if not os.path.exists(wallet_path):
            return self._reply_json({'error': 'No such wallet'}, status_code=500)

        try:
            payment_address, owner_address, data_pubkey = wallet.get_addresses_from_file(wallet_path=wallet_path)
            self._reply_json({'address': owner_address})
            return

        except Exception as e:
            self._reply_json({'error': 'Failed to read wallet file'}, status_code=500)
            return

    
    def GET_wallet_data_pubkey( self, ses, path_info ):
        """
        Get the data public key
        Return 200 with {'public_key': ...} on success
        Return 500 on failure to read the wallet
        """
        wallet_path = os.path.join( os.path.dirname(self.server.config_path), WALLET_FILENAME )
        if not os.path.exists(wallet_path):
            return self._reply_json({'error': 'No such wallet'}, status_code=500)

        try:
            payment_address, owner_address, data_pubkey = wallet.get_addresses_from_file(wallet_path=wallet_path)
            return self._reply_json({'public_key': data_pubkey})

        except Exception as e:
            return self._reply_json({'error': 'Failed to read wallet file'}, status_code=500)


    def GET_wallet_keys( self, ses, path_info ):
        """
        Get the decrypted wallet keys
        Return 200 with wallet info on success
        Return 404 if the wallet is not loaded
        """
        res = backend.registrar.get_wallet(config_path=self.server.config_path)
        if 'error' in res:
            return self._reply_json({'error': res['error']}, status_code=500)

        else:
            return self._reply_json(res)


    def GET_wallet_balance( self, ses, path_info ):
        """
        Get the wallet balance
        Return 200 with the balance
        """
        internal = self.server.get_internal_proxy()
        res = internal.cli_balance(config_path=self.server.config_path)
        if 'error' in res:
            log.debug("Failed to query wallet balance: {}".format(res['error']))
            return self._reply_json({'error': 'Failed to query wallet balance'}, status_code=500)

        return self._reply_json({'balance': res['total_balance']})


    def POST_wallet_balance( self, ses, path_info ):
        """
        Transfer wallet balance.  Takes {'address': ...}
        Return 200 with the balance
        Return 500 on failure to contact the blockchain service
        """
        address_schema = {
            'type': 'object',
            'properties': {
                'address': {
                    'type': 'string',
                    'pattern': OP_BASE58CHECK_PATTERN,
                },
                'amount': {
                    'type': 'integer',
                },
                'min_confs': {
                    'type': 'integer',
                },
                'tx_only': {
                    'type': 'boolean'
                },
            },
            'required': [
                'address'
            ],
            'additionalProperties': False
        }

        request = self._read_json(schema=address_schema)
        if request is None:
            return self._reply_json({'error': 'Invalid request'}, status_code=401)

        address = str(request['address'])
        amount = request.get('amount', None)
        min_confs = request.get('min_confs', TX_MIN_CONFIRMATIONS)
        tx_only = request.get('tx_only', False)

        if tx_only:
            tx_only = 'True'
        else:
            tx_only = 'False'

        if min_confs < 0:
            min_confs = 0

        internal = self.server.get_internal_proxy()
        res = internal.cli_withdraw(address, amount, min_confs, tx_only, config_path=self.server.config_path, interactive=False, wallet_keys=self.server.wallet_keys)
        if 'error' in res:
            log.debug("Failed to transfer balance: {}".format(res['error']))
            return self._reply_json({'error': 'Failed to transfer balance: {}'.format(res['error'])}, status_code=500)

        return self._reply_json(res)


    def PUT_wallet_keys( self, ses, path_info ):
        """
        Set wallet keys
        Return 200 on success
        Return 500 on error
        """
        wallet = self._read_json(schema=WALLET_SCHEMA_CURRENT)
        if request is None:
            return self._reply_json({'error': 'Failed to validate keys'}, status_code=401)
        
        res = backend.registrar.set_wallet( (wallet['payment_addresses'][0], wallet['payment_privkey']),
                                            (wallet['owner_addresses'][0], wallet['owner_privkey']),
                                            (wallet['data_pubkeys'][0], wallet['data_privkey']), config_path=self.server.config_path )

        if 'error' in res:
            return self._reply_json({'error': 'Failed to set wallet: {}'.format(res['error'])}, status_code=500)
       
        self.server.wallet_keys = wallet
        return self._reply_json({'status': True})


    def PUT_wallet_password( self, ses, path_info ):
        """
        Change the wallet password.
        Takes {'password': password, 'new_password': new password}
        Returns 200 on success
        Returns 401 on invalid request
        Returns 500 on failure to change the password
        """
        password_schema = {
            'type': 'object',
            'properties': {
                'password': {
                    'type': 'string'
                },
                'new_password': {
                    'type': 'string',
                },
            },
            'required': [
                'password',
                'new_password'
            ],
            'additionalProperties': False
        }
        
        request = self._read_json(schema=password_schema)
        if request is None:
            return self._reply_json({'error': 'Invalid request'}, status_code=401)

        password = str(request['password'])
        new_password = str(request['password'])

        internal = self.server.get_internal_proxy()
        res = internal.cli_wallet_passwod(password, new_password, config_path=self.server.config_path, interactive=False)
        if 'error' in res:
            log.debug("Failed to change wallet password: {}".format(res['error']))
            return self._reply_json({'error': 'Failed to change password: {}'.format(res['error'])}, status_code=500)

        return self._reply_json({'status': True})


    def GET_ping( self, ses, path_info ):
        """
        Ping the node
        always succeeds
        """
        self._send_headers(status_code=200, content_type='text/plain')
        return

    
    def GET_registrar_state( self, ses, path_info ):
        """
        Handle GET /v1/node/registrar/state
        Get registrar state 
        Return 200 on success
        """
        res = backend.registrar.state()
        return self._reply_json(res)


    def POST_reboot( self, ses, path_info ):
        """
        Reboot the node.
        Requires the caller pass the RPC secret
        Does not return on success
        Return 403 on failure
        """
        return self._reply_json({'error': 'Not implemented'}, status_code=501) 


    def GET_node_config( self, ses, path_info ):
        """
        Get node configuration
        Return 200 on success
        Return 500 on failure to read
        """
        conf = None
        try:
            conf = blockstack_config.read_config_file(self.server.config_path)
            assert conf
        except Exception as e:
            log.exception(e)
            return self._reply_json({'error': 'Failed to read config'}, status_code=500)

        for unneeded_field in ['path', 'dir']:
            if conf.has_key(unneeded_field):
                del conf[unneeded_field]

        return self._reply_json(conf)


    def POST_node_config( self, ses, path_info, section ):
        """
        Set node configuration items (as {name}={value} in the query string)
        Return 200 on success
        Return 500 on failure to write
        """
        conf_items = path_info['qs_values']
        for conf_item_name, conf_item_value in conf_items.items():
            field_name = str(conf_item_name)
            field_value = str(conf_item_value)
            
            res = blockstack_config.write_config_field( self.server.config_path, section, field_name, field_value )
            if not res:
                log.debug("Failed to set {}.{} = {}".format(section, field_name, field_value))
                return self._reply_json({'error': 'Failed to write config field'}, status=500)

        return self._reply_json({'status': True})


    def DELETE_node_config_section( self, ses, path_info, section ):
        """
        Remove a config file section
        Return 200 on success
        Return 500 on failure
        """
        res = blockstack_config.delete_config_section(self.server.config_path, section)
        if not res:
            return self._reply_json({'error': 'Failed to delete section'}, status_code=500)

        else:
            return self._reply_json({'status': True})


    def DELETE_node_config_field( self, ses, path_info, section, field ):
        """
        Delete a specific config item
        Return 200 on success
        Return 500 on failure
        """
        res = blockstack_config.delete_config_field(self.server.config_path, section, field)
        if not res:
            return self._reply_json({'error': 'Failed to delete field'}, status_code=500)
        
        else:
            return self._reply_json({'status': True})


    def GET_blockchain_ops( self, ses, path_info, blockchain_name, blockheight ):
        """
        Get the name's historic name operations
        Reply the list of nameops at the given block height
        Reply 404 for blockchains other than those supported
        Reply 500 for any error we have in talking to the blockstack server
        """
        if blockchain_name != 'bitcoin':
            # not supported
            self._reply_json({'error': 'Unsupported blockchain'}, status_code=401)
            return

        nameops = proxy.get_nameops_at(blockheight)
        if json_is_error(nameops):
            # error
            status_code = None
            if json_is_exception(nameops):
                status_code = 500
            else:
                status_code = 404

            self._reply_json({'error': nameops['error']}, status_code=status_code)
            return

        self._reply_json(nameops)
        return


    def GET_blockchain_name_history( self, ses, path_info, blockchain_name, name ):
        """
        Get the name's blockchain history
        Reply the raw history record on success
        Reply 404 if the name is not found
        Reply 500 if we have an error talking to the server
        """
        if blockchain_name != 'bitcoin':
            # not supported
            self._reply_json({'error': 'Unsupported blockchain'}, status_code=401)
            return

        name_rec = proxy.get_name_blockchain_record(name)
        if json_is_error(name_rec):
            # error
            status_code = None
            if json_is_exception(name_rec):
                status_code = 500
            else:
                status_code = 404

            self._reply_json({'error': name_rec['error']}, status_code=status_code)
            return

        pass


    def GET_blockchain_consensus( self, ses, path_info, blockchain_name ):
        """
        Handle GET /blockchain/:blockchainID/consensus
        Reply the consensus hash at this blockchain's tip
        Reply 401 for unrecognized blockchain
        Reply 404 for blockchains that we don't support
        Reply 500 for any error we have in talking to the blockstack server
        """
        if blockchain_name != 'bitcoin':
            # not supported
            self._reply_json({'error': 'Unsupported blockchain'}, status_code=401)
            return

        info = proxy.getinfo()
        if json_is_error(info):
            # error
            status_code = None
            if json_is_exception(info):
                status_code = 500
            else:
                status_code = 404

            self._reply_json({'error': consensus_hash['error']}, status_code=status_code)
            return

        self._reply_json({'consensus_hash': info['consensus']})
        return


    def GET_blockchain_pending( self, ses, path_info, blockchain_name ):
        """
        Handle GET /blockchain/:blockchainID/pending
        Reply the list of pending transactions from our internal registrar queue
        Reply 401 if the blockchain is not known
        Reply 404 if the name cannot be found.
        """
        if blockchain_name != 'bitcoin':
            # not supported
            self._reply_json({'error': 'Unsupported blockchain'}, status_code=401)
            return

        internal = self.server.get_internal_proxy()
        res = internal.cli_get_registrar_info()
        if json_is_error(res):
            # error
            status_code = None
            if json_is_exception(res):
                status_code = 500
            else:
                status_code = 404

            self._reply_json({'error': res['error']}, status_code=status_code)
            return

        self._reply_json({'queues': res})
        return


    def GET_ping(self, session, path_info):
        """
        ping
        """
        self._reply_json({'status': 'alive'})
        return


    def _dispatch(self, method_name):
        """
        Top-level dispatch method
        """

        URLENCODING_CLASS = r'[a-zA-Z0-9\-_.~%]+'
        NAME_CLASS = r'[a-z0-9\-_.+]{{{},{}}}'.format(3, LENGTH_MAX_NAME)
        NAMESPACE_CLASS = r'[a-z0-9\-_+]{{{},{}}}'.format(1, LENGTH_MAX_NAMESPACE_ID)
        BASE58CHECK_CLASS = r'[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+'

        routes = {
            r'^/v1/ping$': {
                'routes': {
                    'GET': self.GET_ping,
                },
                'whitelist': {
                    'GET': {
                        'name': 'ping',
                        'desc': 'Check to see if the server is alive.',
                        'auth_session': False,
                        'auth_pass': False,
                        'need_data_key': False,
                    },
                },
                'need_data_key': False,
            },
            r'^/v1/auth$': {
                'routes': {
                    'GET': self.GET_auth,
                },
                'whitelist': {
                    'GET': {
                        'name': 'auth',
                        'desc': 'get a session token',
                        'auth_session': False,
                        'auth_pass': True,
                        'need_data_key': True,
                    },
                },
            },
            # TODO: change to /v1/addresses/{blockchain}/{address}
            r'^/v1/addresses/({})$'.format(BASE58CHECK_CLASS): {
                'routes': {
                    'GET': self.GET_names_owned_by_address,
                },
                'whitelist': {
                    'GET': {
                        'name': 'names',
                        'desc': 'get names owned by an address',
                        'auth_session': False,
                        'auth_pass': False,
                        'need_data_key': False,
                    },
                },
            },
            r'^/v1/blockchains/({})/operations/([0-9]+)$'.format(URLENCODING_CLASS): {
                'routes': {
                    'GET': self.GET_blockchain_ops
                },
                'whitelist': {
                    'GET': {
                        'name': 'blockchain',
                        'desc': 'read blockchain name blocks',
                        'auth_session': False,
                        'auth_pass': False,
                        'need_data_key': False,
                    },
                },
            },
            r'^/v1/blockchains/({})/names/({})/history$'.format(URLENCODING_CLASS, NAME_CLASS): {
                'routes': {
                    'GET': self.GET_blockchain_name_history
                },
                'whitelist': {
                    'GET': {
                        'name': 'blockchain',
                        'desc': 'read blockchain name histories',
                        'auth_session': False,
                        'auth_pass': False,
                        'need_data_key': False,
                    },
                },
            },
            r'^/v1/blockchains/({})/consensus$'.format(URLENCODING_CLASS): {
                'routes': {
                    'GET': self.GET_blockchain_consensus,
                },
                'whitelist': {
                    'GET': {
                        'name': 'blockchain',
                        'desc': 'get current consensus hash',
                        'auth_session': False,
                        'auth_pass': False,
                        'need_data_key': False,
                    },
                },
            },
            r'^/v1/blockchains/({})/pending$'.format(URLENCODING_CLASS): {
                'routes': {
                    'GET': self.GET_blockchain_pending,
                },
                'whitelist': {
                    'GET': {
                        'name': 'blockchain',
                        'desc': 'get pending transactions this node has sent',
                        'auth_session': False,
                        'auth_pass': False,
                        'need_data_key': False,
                    },
                },
            },
            r'^/v1/names$': {
                'routes': {
                    'GET': self.GET_names,
                    'POST': self.POST_names,    # accepts: name, address, zonefile.  Returns: HTTP 202 with txid
                },
                'whitelist': {
                    'GET': {
                        'name': 'names',
                        'desc': 'read all names',
                        'auth_session': False,
                        'auth_pass': False,
                        'need_data_key': False,
                    },
                    'POST': {
                        'name': 'register',
                        'desc': 'register new names',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': False,
                    },
                },
            },
            r'^/v1/names/({})$'.format(NAME_CLASS): {
                'routes': {
                    'GET': self.GET_name_info,
                    'DELETE': self.DELETE_name,     # revoke
                },
                'whitelist': {
                    'GET': {
                        'name': 'names',
                        'desc': 'read name information',
                        'auth_session': False,
                        'auth_pass': False,
                        'need_data_key': False,
                    },
                    'DELETE': {
                        'name': 'revoke',
                        'desc': 'revoke names',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': False,
                    },
                },
            },
            r'^/v1/names/({})/history$'.format(NAME_CLASS): {
                'routes': {
                    'GET': self.GET_name_history,
                },
                'whitelist': {
                    'GET': {
                        'name': 'names',
                        'desc': 'read name history',
                        'auth_session': False,
                        'auth_pass': False,
                        'need_data_key': False,
                    },
                },
            },
            r'^/v1/names/({})/owner$'.format(NAME_CLASS): {
                'routes': {
                    'PUT': self.PUT_name_transfer,     # accepts: recipient address.  Returns: HTTP 202 with txid
                },
                'whitelist': {
                    'PUT': {
                        'name': 'transfer',
                        'desc': 'transfer names to new addresses',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': False,
                    },
                },
            },
            r'^/v1/names/({})/zonefile$'.format(NAME_CLASS): {
                'routes': {
                    'GET': self.GET_name_zonefile,
                    'PUT': self.PUT_name_zonefile,
                },
                'whitelist': {
                    'GET': {
                        'name': 'zonefiles',
                        'desc': 'read name zonefiles',
                        'auth_session': False,
                        'auth_pass': False,
                        'need_data_key': False,
                    },
                    'PUT': {
                        'name': 'update',
                        'desc': 'set name zonefiles',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': False,
                    },
                },
            },
            r'^/v1/names/({})/zonefile/([0-9a-fA-F]{{40}})$'.format(NAME_CLASS): {
                'routes': {
                    'GET': self.GET_name_zonefile_by_hash,     # returns a zonefile
                },
                'whitelist': {
                    'GET': {
                        'name': 'zonefiles',
                        'desc': 'get current and historic name zonefiles',
                        'auth_session': False,
                        'auth_pass': False,
                        'need_data_key': False,
                    },
                },
            },
            r'^/v1/names/({})/zonefile/zonefileHash$'.format(NAME_CLASS): {
                'routes': {
                    'PUT': self.PUT_name_zonefile_hash,     # accepts: zonefile hash.  Returns: HTTP 202 with txid
                },
                'whitelist': {
                    'PUT': {
                        'name': 'update',
                        'desc': 'set name zonefile hashes',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': False
                    },
                },
            },
            r'^/v1/namespaces$': {
                'routes': {
                    'GET': self.GET_namespaces,
                    'POST': self.POST_namespaces,       # accepts: namespace-reveal info.  Returns: HTTP 202 with txid (NAMESPACE_PREORDER)
                },
                'whitelist': {
                    'GET': {
                        'name': 'namespaces',
                        'desc': 'read all namespace IDs',
                        'auth_session': False,
                        'auth_pass': False,
                        'need_data_key': False
                    },
                    'POST': {
                        'name': 'namespace_registration',
                        'desc': 'create new namespaces',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': False
                    },
                },
            },
            r'^/v1/namespaces/({})$'.format(NAMESPACE_CLASS): {
                'routes': {
                    'GET': self.GET_namespace_info,
                    'PUT': self.PUT_namespace_ready,     # accepts: {'launched': True}, Returns: HTTP 202 with txid (NAMESPACE_READY)
                },
                'whitelist': {
                    'GET': {
                        'name': 'namespaces',
                        'desc': 'read namespace information',
                        'auth_session': False,
                        'auth_pass': False,
                        'need_data_key': False
                    },
                    'PUT': {
                        'name': 'namespace_registration',
                        'desc': 'launch namespaces',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': False
                    },
                },
            },
            r'^/v1/namespaces/({})/names$'.format(NAMESPACE_CLASS): {
                'routes': {
                    'GET': self.GET_namespace_names,
                    'POST': self.POST_namespace_name_import,    # accepts name, owner, zonefile; returns HTTP 202 with txid (NAME_IMPORT)
                },
                'whitelist': {
                    'GET': {
                        'name': 'namespaces',
                        'desc': 'read all names in a namespace',
                        'auth_session': False,
                        'auth_pass': False,
                        'need_data_key': False
                    },
                    'POST': {
                        'name': 'namespace_registration',
                        'desc': 'import names into new namespaces',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': False
                    },
                },
            },
            r'^/v1/namespaces/({})/names/({})$'.format(NAMESPACE_CLASS, NAME_CLASS): {
                'routes': {
                    'PUT': self.PUT_namespace_name_import,       # re-imports a name
                },
                'whitelist': {
                    'PUT': {
                        'name': 'namespace_registration',
                        'desc': 're-import names into a new namespace',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': False
                    },
                },
            },
            r'^/v1/wallet/payment_address$': {
                'routes': {
                    'GET': self.GET_wallet_payment_address,
                },
                'whitelist': {
                    'GET': {
                        'name': 'wallet_read',
                        'desc': 'get the node wallet\'s payment address',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': False
                    },
                },
            },
            r'^/v1/wallet/owner_address$': {
                'routes': {
                    'GET': self.GET_wallet_owner_address,
                },
                'whitelist': {
                    'GET': {
                        'name': 'wallet_read',
                        'desc': 'get the node wallet\'s payment address',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': False
                    },
                },
            },
            r'^/v1/wallet/data_pubkey$': {
                'routes': {
                    'GET': self.GET_wallet_data_pubkey,
                },
                'whitelist': {
                    'GET': {
                        'name': 'wallet_read',
                        'desc': 'get the node wallet\'s data public key',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': True,
                    },
                },
            },
            r'^/v1/wallet/balance$': {
                'routes': {
                    'GET': self.GET_wallet_balance,
                    'POST': self.POST_wallet_balance,
                },
                'whitelist': {
                    'GET': {
                        'name': 'wallet_read',
                        'desc': 'get the node wallet\'s balance',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': False,
                    },
                    'POST': {
                        'name': 'wallet_write',
                        'desc': 'transfer the node wallet\'s funds',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': False,
                    },
                },
            },
            r'^/v1/wallet/password$': {
                'routes': {
                    'PUT': self.PUT_wallet_password,
                },
                'whitelist': {
                    'PUT': {
                        'name': 'wallet_write',
                        'desc': 'Change the wallet password',
                        'auth_session': False,
                        'auth_pass': True,
                        'need_data_key': False
                    },
                },
            },
            r'^/v1/wallet/keys$': {
                'routes': {
                    'GET': self.GET_wallet_keys,
                    'PUT': self.PUT_wallet_keys,
                },
                'whitelist': {
                    'GET': {
                        'name': 'wallet_read',
                        'desc': 'Get the wallet\'s private keys',
                        'auth_session': False,
                        'auth_pass': True,
                        'need_data_key': False,
                    },
                    'PUT': {
                        'name': 'wallet_write',
                        'desc': 'Set the wallet\'s private keys',
                        'auth_session': False,
                        'auth_pass': True,
                        'need_data_key': False
                    },
                },
            },
            r'^/v1/node/ping$': {
                'routes': {
                    'GET': self.GET_ping,
                },
                'whitelist': {
                    'GET': {
                        'name': '',
                        'desc': 'ping the node',
                        'auth_session': False,
                        'auth_pass': False,
                        'need_data_key': False
                    },
                },
            },
            r'^/v1/node/registrar/state$': {
                'routes': {
                    'GET': self.GET_registrar_state,
                },
                'whitelist': {
                    'GET': {
                        'name': '',
                        'desc': 'Get internal registrar state',
                        'auth_session': False,
                        'auth_pass': True,
                        'need_data_key': False,
                    },
                },
            },
            r'^/v1/node/reboot$': {
                'routes': {
                    'POST': self.POST_reboot,
                },
                'whitelist': {
                    'POST': {
                        'name': '',
                        'desc': 'reboot the node',
                        'auth_session': False,
                        'auth_pass': True,
                        'need_data_key': False
                    },
                },
            },
            r'^/v1/node/config$': {
                'routes': {
                    'GET': self.GET_node_config,
                },
                'whitelist': {
                    'GET': {
                        'name': '',
                        'desc': 'get the node config',
                        'auth_session': False,
                        'auth_pass': True,
                        'need_data_key': False,
                    },
                },
            },
            r'^/v1/node/config/({})$'.format(URLENCODING_CLASS): {
                'routes': {
                    'POST': self.POST_node_config,
                    'DELETE': self.DELETE_node_config_section,
                },
                'whitelist': {
                    'POST': {
                        'name': '',
                        'desc': 'set node section fields',
                        'auth_session': False,
                        'auth_pass': True,
                        'need_data_key': False,
                    },
                    'DELETE': {
                        'name': '',
                        'desc': 'delete a config section',
                        'auth_session': False,
                        'auth_pass': True,
                        'need_data_key': False,
                    },
                },
            },
            r'^/v1/node/config/({})/({})$'.format(URLENCODING_CLASS, URLENCODING_CLASS): {
                'routes': {
                    'DELETE': self.DELETE_node_config_field,
                },
                'whitelist': {
                    'DELETE': {
                        'name': '',
                        'desc': 'delete a config section field',
                        'auth_session': False,
                        'auth_pass': True,
                        'need_data_key': False,
                    },
                },
            },
            r'^/v1/prices/namespaces/({})$'.format(NAMESPACE_CLASS): {
                'routes': {
                    'GET': self.GET_prices_namespace,
                },
                'whitelist': {
                    'GET': {
                        'name': 'prices',
                        'desc': 'get the price of a namespace',
                        'auth_session': False,
                        'auth_pass': False,
                        'need_data_key': False,
                    },
                },
            },
            r'^/v1/prices/names/({})$'.format(NAME_CLASS): {
                'need_data_key': False,
                'routes': {
                    'GET': self.GET_prices_name,
                },
                'whitelist': {
                    'GET': {
                        'name': 'prices',
                        'desc': 'get the price of a name',
                        'auth_session': False,
                        'auth_pass': False,
                        'need_data_key': False,
                    },
                },
            },
            r'^/v1/users$': {
                'routes': {
                    'POST': self.POST_users,
                },
                'whitelist': {
                    'POST': {
                        'name': 'user_admin',
                        'desc': 'create new users',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': True,
                    },
                    'DELETE': {
                        'name': 'user_admin',
                        'desc': 'delete users',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': True,
                    },
                },
            },
            r'^/v1/users/({})$'.format(URLENCODING_CLASS): {
                'routes': {
                    'GET': self.GET_user_profile,
                    'PATCH': self.PATCH_user_profile,
                    'DELETE': self.DELETE_user_profile,
                },
                'whitelist': {
                    'GET': {
                        'name': 'user_read',
                        'desc': 'read user profile',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': True,
                    },
                    'PATCH': {
                        'name': 'user_write',
                        'desc': 'update user profile',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': True,
                    },
                    'DELETE': {
                        'name': 'user_admin',
                        'desc': 'delete user profile',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': True,
                    },
                },
            },
            r'^/v1/collections$': {
                'routes': {
                    'GET': self.GET_collections,
                    'POST': self.POST_collections,
                },
                'whitelist': {
                    'GET': {
                        'name': 'collections',
                        'desc': 'list a user\'s collections',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': True,
                    },
                    'POST': {
                        'name': 'collections_admin',
                        'desc': 'create new collections',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': True,
                    },
                },
            },
            r'^/v1/collections/({})$'.format(URLENCODING_CLASS): {
                'routes': {
                    'GET': self.GET_collection_info,
                    'POST': self.POST_collection_item,
                },
                'whitelist': {
                    'GET': {
                        'name': 'collections',
                        'desc': 'list items in a collection',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': True,
                    },
                    'POST': {
                        'name': 'collections_write',
                        'desc': 'add items to a collection',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': True,
                    },
                },
            },
            r'^/v1/collections/({})/({})$'.format(URLENCODING_CLASS, URLENCODING_CLASS): {
                'routes': {
                    'GET': self.GET_collection_item,
                },
                'whitelist': {
                    'GET': {
                        'name': 'collections',
                        'desc': 'read collection items',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': True,
                    },
                },
            },
            r'^/v1/stores$': {
                'routes': {
                    'POST': self.POST_store,
                    'PUT': self.PUT_store,
                    'DELETE': self.DELETE_store,
                },
                'whitelist': {
                    'POST': {
                        'name': 'store_write',
                        'desc': 'create the datastore for the app user',
                        'auth_session': True,
                        'auth_pass': False,     # need app_domain from session
                        'need_data_key': True,
                    },
                    'PUT': {
                        'name': 'store_write',
                        'desc': 'update the app user\'s datastore',
                        'auth_session': True,
                        'auth_pass': False,     # need app_domain from session
                        'need_data_key': True,
                    },
                    'DELETE': {
                        'name': 'store_write',
                        'desc': 'delete the app user\'s datastore',
                        'auth_session': True,
                        'auth_pass': False,     # need app_domain from session
                        'need_data_key': True,
                    },
                },
            },
            r'^/v1/stores/({})$'.format(URLENCODING_CLASS): {
                'routes': {
                    'GET': self.GET_store,
                },
                'whitelist': {
                    'GET': {
                        'name': 'store_admin',
                        'desc': 'Get an app user\'s datastore metadata',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': True,
                    },
                },
            },
            r'^/v1/stores/({})/(files|directories|inodes)$'.format(URLENCODING_CLASS, URLENCODING_CLASS, URLENCODING_CLASS): {
                'routes': {
                    'GET': self.GET_store_item,
                    'POST': self.POST_store_item,
                    'PUT': self.PUT_store_item,
                    'DELETE': self.DELETE_store_item,
                },
                'whitelist': {
                    'GET': {
                        'name': 'store_read',
                        'desc': 'read files and list directories in the app user\'s data store',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': True,
                    },
                    'POST': {
                        'name': 'store_write',
                        'desc': 'create files and make directories in the app user\'s data store',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': True,
                    },
                    'PUT': {
                        'name': 'store_write',
                        'desc': 'write files and directories to the app user\'s data store',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': True,
                    },
                    'DELETE': {
                        'name': 'store_write',
                        'desc': 'delete files and directories in the app user\'s data store',
                        'auth_session': True,
                        'auth_pass': True,
                        'need_data_key': True,
                    },
                },
            },
            r'^/v1/resources/({})/({})$'.format(NAME_CLASS, URLENCODING_CLASS): {
                'routes': {
                    'GET': self.GET_app_resource,
                },
                'whitelist': {
                    'GET': {
                        'name': 'app',
                        'desc': 'get an application resource',
                        'auth_session': False,
                        'auth_pass': False,
                        'need_data_key': False,
                    },
                },
            },
            r'^/v1/.*$': {
                'routes': {
                    'OPTIONS': self.OPTIONS_preflight,
                },
                'whitelist': {
                    'OPTIONS': {
                        'name': '',
                        'desc': 'preflight check',
                        'auth_session': False,
                        'auth_pass': False,
                        'need_data_key': False,
                    },
                },
            },
        }

        path_info = self.get_path_and_qs()
        if 'error' in path_info:
            self._send_headers(status_code=401, content_type='text/plain')
            return

        qs_values = path_info['qs_values']

        route_info = self._route_match( method_name, path_info, routes )
        if route_info is None:
            log.debug("Unmatched route: {} '{}'".format(method_name, path_info['path']))
            print(json.dumps( routes.keys(), sort_keys=True, indent=4 ))
            self._send_headers(status_code=404, content_type='text/plain')
            return

        route_args = route_info['args']
        route_method = route_info['method']
        route = route_info['route']
        whitelist_info = route_info['whitelist']

        need_data_key = whitelist_info['need_data_key']
        use_session = whitelist_info['auth_session']
        use_password = whitelist_info['auth_pass']

        log.debug("\nfull path: {}\nmethod: {}\npath: {}\nqs: {}\nheaders:\n {}\n".format(self.path, method_name, path_info['path'], qs_values, '\n'.join( '{}: {}'.format(k, v) for (k, v) in self.headers.items() )))

        have_password = self.verify_password()
        session = self.verify_session(qs_values)
        authorized = False

        # sanity check: this API only works if we have a data key
        if self.server.master_data_privkey is None and need_data_key:
            log.debug("No master data private key set")
            self._send_headers(status_code=503, content_type='text/plain')
            return

        if not use_session and not use_password:
            # no auth needed
            log.debug("No authentication needed")
            authorized = True

        elif have_password and use_password:
            # password allowed
            log.debug("Authenticated with password")
            authorized = True

        elif session is not None and use_session:
            # session required, but we have one
            # validate session
            allowed_methods = session['methods']

            # is this method allowed?
            if whitelist_info['name'] not in allowed_methods:
                # this method is not allowed
                log.info("Unauthorized method call to {}".format(path_info['path']))
                return self._send_headers(status_code=403, content_type='text/plain')

            authorized = True
            log.debug("Authenticated with session")

        if not authorized:
            log.info("Failed to authenticate caller")
            if BLOCKSTACK_TEST:
                log.debug("Session was: {}".format(session))

            return self._send_headers(status_code=403, content_type='text/plain')

        # good to go!
        try:
            return route_method( session, path_info, *route_args )
        except Exception as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            return self._send_headers(status_code=500, content_type='text/plain')


    def do_GET(self):
        """
        Top-level GET dispatch
        """
        return self._dispatch("GET")

    def do_POST(self):
        """
        Top-level POST dispatch
        """
        return self._dispatch("POST")

    def do_PUT(self):
        """
        Top-level PUT dispatch
        """
        return self._dispatch("PUT")

    def do_DELETE(self):
        """
        Top-level DELETE dispatch
        """
        return self._dispatch("DELETE")

    def do_HEAD(self):
        """
        Top-level HEAD dispatch
        """
        return self._dispatch("HEAD")

    def do_OPTIONS(self):
        """
        Top-level OPTIONS dispatch
        """
        return self._dispatch("OPTIONS")

    def do_PATCH(self):
        """
        TOp-level PATCH dispatch
        """
        return self._dispatch("PATCH")


class BlockstackAPIEndpoint(SocketServer.TCPServer):
    """
    Lightweight API endpoint to Blockstack server:
    exposes all of the client methods via a RESTful interface,
    so other local programs (e.g. those that can't use the library)
    can access the Blockstack client functionality.
    """

    @classmethod
    def is_method(cls, method):
        return bool(callable(method) or getattr(method, '__call__', None))


    def register_function(self, func_internal, name=None):
        """
        Register a CLI-wrapper function
        """
        name = func.__name__ if name is None else name
        assert name

        setattr(self.internal_proxy, name, func_internal)


    def get_internal_proxy(self):
        return self.internal_proxy


    def register_api_functions(self, config_path):
        """
        Register all API functions.
        Do so for both the internal API proxy (for server-callers)
        and for the exteranl API (for RPC callers).
        """

        # register the command-line methods (will all start with cli_)
        # methods will be named after their *action*
        for command_name, method_info in list_api_cli_method_info().items():
            method_name = 'cli_{}'.format(method_info['command'])
            method = method_info['method']

            msg = 'Register CLI method "{}" as "{}"'
            log.debug(msg.format(method.__name__, method_name))

            self.register_function(
                api_cli_wrapper(method_info, config_path, check_rpc=False, include_kw=True),
                name=method_name,
            )

        return True


    def cache_app_config(self, name, appname, app_config):
        """
        Cache application config for a loaded application
        """
        self.app_configs["{}:{}".format(name, appname)] = app_config


    def get_cached_app_config(self, name, appname):
        """
        Get a cached app config
        """
        return self.app_configs.get("{}:{}".format(name, appname), None)


    def __init__(self, api_pass, wallet_keys, host='localhost', port=blockstack_constants.DEFAULT_API_PORT,
                 handler=BlockstackAPIEndpointHandler, config_path=CONFIG_PATH, server=True):

        """
        wallet_keys is only needed if server=True
        """

        if server:
            assert wallet_keys is not None
            SocketServer.TCPServer.__init__(self, (host, port), handler, bind_and_activate=False)

            log.debug("Set SO_REUSADDR")
            self.socket.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )

            self.server_bind()
            self.server_activate()

        # instantiate
        self.plugin_mods = []
        self.plugin_destructors = []
        self.plugin_prefixes = []
        self.config_path = config_path
        self.internal_proxy = RPCInternalProxy()
        self.funcs = {}
        self.wallet_keys = wallet_keys
        self.master_data_privkey = None
        self.master_data_pubkey = None
        self.port = port
        self.api_pass = api_pass
        self.app_configs = {}   # cached app config state

        conf = blockstack_config.get_config(path=config_path)
        assert conf

        if wallet_keys is not None:
            assert wallet_keys.has_key('data_privkey')

            self.master_data_privkey = ECPrivateKey(wallet_keys['data_privkey']).to_hex()
            self.master_data_pubkey = ECPrivateKey(self.master_data_privkey).public_key().to_hex()

            if keylib.key_formatting.get_pubkey_format(self.master_data_pubkey) == 'hex_compressed':
                self.master_data_pubkey = keylib.key_formatting.decompress(self.master_data_pubkey)

        self.register_api_functions(config_path)


class BlockstackAPIEndpointClient(object):
    """
    Client for blockstack's local API endpoint.
    Usable both by external clients and by the API server itself.
    """
    def __init__(self, server, port, api_pass=None, session=None, config_path=CONFIG_PATH,
                 timeout=blockstack_constants.DEFAULT_TIMEOUT, debug_timeline=False, **kw):

        self.timeout = timeout
        self.server = server
        self.port = port
        self.debug_timeline = debug_timeline
        self.api_pass = api_pass
        self.session = session
        self.config_path = config_path
        self.config_dir = os.path.dirname(config_path)


    def log_debug_timeline(self, event, key, r=-1):
        # random ID to match in logs
        r = random.randint(0, 2 ** 16) if r == -1 else r
        if self.debug_timeline:
            log.debug('RPC({}) {} {} {}'.format(r, event, self.url, key))
        return r


    def make_request_headers(self):
        """
        Make HTTP request headers
        """

        headers = {
            'content-type': 'application/json'
        }

        if self.api_pass:
            headers['Authorization'] = 'basic {}'.format(self.api_pass)
        
        elif self.session:
            headers['Authorization'] = 'bearer {}'.format(self.session)

        return headers

    
    def get_response(self, req):
        """
        Get the response
        """
        try:
            resp = req.json()
        except:
            resp = {'error': 'No JSON response; HTTP status {}'.format(req.status_code)}

        return resp

    
    def ping(self):
        """
        Ping the endpoint
        """
        assert not is_api_server(self.config_dir), 'API server should not call this method'
        headers = self.make_request_headers()
        req = requests.get( 'http://localhost:{}/v1/node/ping'.format(self.port), timeout=self.timeout, headers=headers)
        return self.get_response(req)

    
    def backend_set_wallet(self, wallet_keys):
        """
        Save wallet keys to memory
        Return {'status': True} on success
        Return {'error': ...} on error
        """
        assert not is_api_server(self.config_dir), 'API server should not call this method'
        headers = self.make_request_headers()
        req = requests.put( 'http://localhost:{}/v1/wallet/keys'.format(self.port), timeout=self.timeout, data=json.dumps(wallet), headers=headers )
        return self.get_response(req)


    def backend_get_wallet(self):
        """
        Get the wallet from the API server
        Return wallet data on success
        Return {'error': ...} on error
        """
        assert not is_api_server(self.config_dir), 'API server should not call this method'
        headers = self.make_request_headers()
        req = requests.get( 'http://localhost:{}/v1/wallet/keys'.format(self.port), timeout=self.timeout, headers=headers )
        return self.get_response(req)


    def backend_state(self): 
        """
        Get the backend registrar state
        Return the state on success
        Return {'error': ...} on error
        """
        if is_api_server(self.config_dir):
            # directly invoke 
            return backend.registrar.state()

        else:
            # ask API server
            headers = self.make_request_headers()
            req = requests.get( 'http://localhost:{}/v1/node/registrar/state'.format(self.port), timeout=self.timeout, headers=headers)
            return self.get_response(req)


    def backend_preorder(self, fqu, cost_satoshis, user_zonefile, user_profile, transfer_address, min_payment_confs, tx_fee):
        """
        Queue up a name for registration.
        """

        if is_api_server(self.config_dir):
            # directly invoke the registrar
            return backend.registrar.preorder(fqu, cost_satoshis, user_zonefile, user_profile, transfer_address, min_payment_confs, tx_fee, config_path=self.config_path)

        else:
            # ask API server
            data = {
                'name': fqu,
            }

            if user_zonefile is not None:
                data['zonefile'] = user_zonefile

            if transfer_address is not None:
                data['owner_address'] = transfer_address

            if min_payment_confs is not None:
                data['min_confs'] = min_payment_confs

            if tx_fee is not None:
                data['tx_fee'] = tx_fee

            if cost_satoshis is not None:
                data['cost_satoshis'] = cost_satoshis

            headers = self.make_request_headers()
            req = requests.post( 'http://localhost:{}/v1/names'.format(self.port), data=json.dumps(data), timeout=self.timeout, headers=headers)
            return self.get_response(req)

    
    def backend_update(self, fqu, zonefile_txt, profile, zonefile_hash, tx_fee):
        """
        Queue an update
        """
        if is_api_server(self.config_dir):
            # directly invoke the registrar 
            return backend.registrar.update(fqu, zonefile_txt,  profile, zonefile_hash, None, tx_fee, config_path=self.config_path)

        else:
            # ask the API server
            headers = self.make_request_headers()
            data = {}

            if zonefile_txt is not None:
                try:
                    json.dumps(zonefile_txt)
                    data['zonefile'] = zonefile_txt
                except:
                    # non-standard
                    data['zonefile_b64'] = base64.b64encode(zonefile_txt)

            if zonefile_hash is not None:
                data['zonefile_hash'] = zonefile_hash

            if tx_fee is not None:
                data['tx_fee'] = tx_fee

            headers = self.make_request_headers()
            req = requests.put( 'http://localhost:{}/v1/names/{}/zonefile'.format(self.port, fqu), data=json.dumps(data), timeout=self.timeout, headers=headers)
            return self.get_response(req)


    def backend_transfer(self, fqu, recipient_addr, tx_fee):
        """
        Queue a transfer
        """
        if is_api_server(self.config_dir):
            # directly invoke the transfer
            return backend.registrar.transfer(fqu, recipient_addr, tx_fee, config_path=self.config_path)
        
        else:
            # ask the API server
            data = {
                'owner': recipient_addr
            }

            if tx_fee:
                data['tx_fee'] = tx_fee

            headers = self.make_request_headers()
            req = requests.put( 'http://localhost:{}/v1/names/{}/owner'.format(self.port, fqu), data=json.dumps(data), timeout=self.timeout, headers=headers)
            return self.get_response(req)


    def backend_renew(self, fqu, renewal_fee, tx_fee):
        """
        Queue a renewal
        """
        if is_api_server(self.config_dir):
            # directly invoke the renew 
            return backend.registrar.renew(fqu, renewal_fee, tx_fee, config_path=self.config_path)

        else:
            # ask the API server
            data = {
                'name': fqu,
            }

            if tx_fee:
                data['tx_fee'] = tx_fee

            headers = self.make_request_headers()
            req = requests.post( 'http://localhost:{}/v1/names'.format(self.port), data=json.dumps(data), timeout=self.timeout, headers=headers)
            return self.get_response(req)


    def backend_revoke(self, fqu, tx_fee):
        """
        Queue a revoke
        """
        if is_api_server(self.config_dir):
            # directly invoke the revoke 
            return backend.registrar.revoke(fqu, tx_fee, config_path=self.config_path)

        else:
            # ask the API server
            headers = self.make_request_headers()
            req = requests.delete( 'http://localhost:{}/v1/names/{}'.format(self.port, fqu), timeout=self.timeout, headers=headers)
            return self.get_response(req)


def make_local_api_server(api_pass, portnum, wallet_keys, config_path=blockstack_constants.CONFIG_PATH, plugins=None):
    """
    Make a local RPC server instance.
    It will be derived from BaseHTTPServer.HTTPServer.
    @plugins can be a list of modules, or a list of strings that
    identify module names to import.

    Returns the global server instance on success.
    """
    srv = BlockstackAPIEndpoint(api_pass, wallet_keys, port=portnum, config_path=config_path)
    return srv


def is_api_server(config_dir=blockstack_constants.CONFIG_DIR):
    """
    Is this process running an RPC server?
    Return True if so
    Return False if not
    """
    rpc_pidpath = local_api_pidfile_path(config_dir=config_dir)
    if not os.path.exists(rpc_pidpath):
        return False

    rpc_pid = local_api_read_pidfile(rpc_pidpath)
    if rpc_pid != os.getpid():
        return False

    return True


def local_api_server_run(srv):
    """
    Start running the RPC server, but in a separate thread.
    """
    global running

    srv.timeout = 0.5
    while running:
        srv.handle_request()


def local_api_server_stop(srv):
    """
    Stop a running RPC server
    """
    log.debug("Server shutdown")
    srv.socket.close()

    # stop the registrar too
    backend.registrar.registrar_shutdown(srv.config_path)    


def local_api_connect(api_pass=None, api_session=None, password=None, config_dir=blockstack_constants.CONFIG_DIR, api_port=None):
    """
    Connect to a locally-running API server.
    Return a server proxy object on success.
    Raise on error.

    The API server can safely connect to itself using this method,
    since instead of opening a socket and doing the conventional RPC,
    it will instead use the proxy object to call the request method
    directly.
    """

    config_path = os.path.join(config_dir, blockstack_constants.CONFIG_FILENAME)

    '''
    TODO: might not need this
    if is_api_server(config_dir=config_dir):
        # this process is an API server.
        # route the method directly.
        log.debug("Caller is the API server. Short-circuiting.")
        return get_api_internal_methods()
    '''
    conf = blockstack_config.get_config(config_path)
    if conf is None:
        raise Exception('Failed to read conf at "{}"'.format(config_path))

    api_port = conf['api_endpoint_port'] if api_port is None else api_port
    
    if api_pass is None:
        # try environment
        api_pass = os.environ.get('BLOCKSTACK_API_PASSWORD', None)

    if api_pass is None:
        # try config file
        api_pass = conf.get('api_password', None)

    connect_msg = 'Connect to API at localhost:{}'
    log.debug(connect_msg.format(api_port))
    return BlockstackAPIEndpointClient('localhost', api_port, timeout=3000, config_path=config_path, session=api_session, api_pass=api_pass)


def local_api_action(command, password=None, api_pass=None, config_dir=blockstack_constants.CONFIG_DIR):
    """
    Handle an API endpoint command:
    * start: start up an API endpoint
    * stop: stop a running API endpoint
    * status: see if there's an API endpoint running.
    * restart: stop and start the API endpoint

    Return True on success
    Return False on error
    """

    if command not in ['start', 'start-foreground', 'stop', 'status', 'restart']:
        raise ValueError('Invalid command "{}"'.format(command))

    if command in ['start', 'start-foreground', 'restart']:
        assert api_pass, "Need API password for '{}'".format(command)

    config_path = os.path.join(config_dir, blockstack_constants.CONFIG_FILENAME)

    conf = blockstack_config.get_config(config_path)
    if conf is None:
        raise Exception('Failed to read conf at "{}"'.format(config_path))

    api_port = None
    try:
        api_port = int(conf['api_endpoint_port'])
    except:
        raise Exception("Invalid port number {}".format(conf['api_endpoint_port']))

    argv = [sys.executable, '-m', 'blockstack_client.rpc_runner', str(command), str(api_port), str(config_dir)]

    env = {}
    env.update( os.environ )

    if password:
        env['BLOCKSTACK_CLIENT_WALLET_PASSWORD'] = password

    if api_pass:
        env['BLOCKSTACK_API_PASSWORD'] = api_pass

    p = subprocess.Popen(argv, cwd=config_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, env=env)
    out, err = p.communicate()
    res = p.wait()
    if res != 0:
        log.error("Failed to {} API endpoint: exit code {}".format(command, res))
        log.error("Error log:\n{}".format("\n".join(["  " + e for e in err.split('\n')])))
        return False

    return True


def local_api_pidfile_path(config_dir=blockstack_constants.CONFIG_DIR):
    """
    Where do we put the PID file?
    """
    return os.path.join(config_dir, 'api_endpoint.pid')


def local_api_logfile_path(config_dir=blockstack_constants.CONFIG_DIR):
    """
    Where do we put logs?
    """
    return os.path.join(config_dir, 'api_endpoint.log')


def local_api_read_pidfile(pidfile_path):
    """
    Read a PID file
    Return None if unable
    """
    try:
        with open(pidfile_path, 'r') as f:
            data = f.read()
            return int(data)
    except:
        return None


def local_api_write_pidfile(pidfile_path):
    """
    Write a PID file
    """
    with open(pidfile_path, 'w') as f:
        f.write(str(os.getpid()))
        f.flush()
        os.fsync(f.fileno())

    return


def local_api_unlink_pidfile(pidfile_path):
    """
    Remove a PID file
    """
    try:
        os.unlink(pidfile_path)
    except:
        pass


def local_api_atexit():
    """
    atexit: clean out PID file
    """
    log.debug("Atexit handler invoked; shutting down")

    global rpc_pidpath, rpc_srv
    local_api_unlink_pidfile(rpc_pidpath)
    if rpc_srv is not None:
        local_api_server_stop(rpc_srv)
        rpc_srv = None


def local_api_exit_handler(sig, frame):
    """
    Fatal signal handler
    """
    local_api_atexit()
    log.debug('Local API exit from signal {}'.format(sig))
    sys.exit(0)


def local_api_start_wait( config_path=CONFIG_PATH ):
    """
    Wait for the API server to come up
    Return True if we could ping it
    Return False if not.

    Used by the intermediate process when forking a daemon.
    """

    config_dir = os.path.dirname(config_path)

    # ping it
    running = False
    for i in range(1, 4):
        log.debug("Attempt {} to ping API server".format(i))
        try:
            local_proxy = local_api_connect(config_dir=config_dir)
            local_proxy.ping()
            running = True
            break
        except requests.ConnectionError as ie:
            log.debug('API server is not responding; trying again in {} seconds'.format(i))
            time.sleep(i)
            continue

        except (IOError, OSError) as ie:
            if ie.errno == errno.ECONNREFUSED:
                log.debug('API server not responding; try again in {} seconds'.format(i))
                time.sleep(i)
                continue
            else:
                log.exception(ie)
                return False
        
        except Exception as e:
            log.exception(e)
            return False

    if not running:
        log.error("API endpoint did not initialize")
    else:
        log.debug("API endpoint is running")

    return running


# used when running in a separate process
rpc_pidpath = None
rpc_srv = None


def local_api_start( port=None, config_dir=blockstack_constants.CONFIG_DIR, foreground=False, api_pass=None, password=None):
    """
    Start up an API endpoint
    Return True on success
    Return False on error
    """

    import blockstack_client
    from blockstack_client.wallet import load_wallet

    global rpc_pidpath, rpc_srv, running
    config_path = os.path.join(config_dir, blockstack_constants.CONFIG_FILENAME)
    wallet_path = os.path.join(config_dir, blockstack_constants.WALLET_FILENAME)

    if port is None:
        conf = blockstack_client.get_config(config_path)
        assert conf

        port = int(conf['api_endpoint_port'])
    
    # already running?
    rpc_pidpath = local_api_pidfile_path(config_dir=config_dir)
    if os.path.exists(rpc_pidpath):
        pid = local_api_read_pidfile(rpc_pidpath)
        print("API endpoint already running (PID {}, {})".format(pid, rpc_pidpath), file=sys.stderr)
        return False

    if not os.path.exists(wallet_path):
        print("No wallet found at {}".format(wallet_path), file=sys.stderr)
        return False

    signal.signal(signal.SIGINT, local_api_exit_handler)
    signal.signal(signal.SIGQUIT, local_api_exit_handler)
    signal.signal(signal.SIGTERM, local_api_exit_handler)

    wallet = load_wallet(
        password=password, config_path=config_path,
        include_private=True, wallet_path=wallet_path
    )

    if 'error' in wallet:
        log.error('Failed to load wallet: {}'.format(wallet['error']))
        print('Failed to load wallet: {}'.format(wallet['error']), file=sys.stderr)
        return False

    if wallet['migrated']:
        log.error("Wallet is in legacy format")
        print("Wallet is in legacy format.  Please migrate it first with the `setup_wallet` command.", file=sys.stderr)
        return False

    wallet = wallet['wallet']
    if not foreground:
        log.debug('Running in the background')

        logpath = local_api_logfile_path(config_dir=config_dir)

        res = daemonize(logpath, child_wait=lambda: local_api_start_wait(config_path=config_path))
        if res < 0:
            log.error("API server failed to start")
            return False

        if res > 0:
            # parent 
            log.debug("Parent {} forked intermediate child {}".format(os.getpid(), res))
            return True
        
    # daemon child takes this path...
    atexit.register(local_api_atexit)

    # load up internal RPC methods
    # TODO: might not need these
    log.debug('Loading RPC methods')
    load_api_cli_method_info(blockstack_client)
    load_api_internal_methods(config_path)
    log.debug('Finished loading RPC methods')

    # make server
    try:
        rpc_srv = make_local_api_server(api_pass, port, wallet, config_path=config_path)
    except socket.error as se:
        if BLOCKSTACK_DEBUG is not None:
            log.exception(se)

        if not foreground:
            msg = 'Failed to open socket (socket errno {}); aborting...'
            log.error(msg.format(se.errno))
            os.abort()
        else:
            msg = 'Failed to open socket (socket errno {})'
            log.error(msg.format(se.errno))
            return False

    log.debug("Initializing registrar...")
    state = backend.registrar.set_registrar_state(config_path=config_path)
    if state is None:
        log.error("Failed to initialize registrar: {}".format(res['error']))
        return False
    
    log.debug("Setting wallet...")

    # NOTE: test that wallets without data keys still work
    assert wallet.has_key('owner_addresses')
    assert wallet.has_key('owner_privkey')
    assert wallet.has_key('payment_addresses')
    assert wallet.has_key('payment_privkey')
    assert wallet.has_key('data_pubkeys')
    assert wallet.has_key('data_privkey')

    res = backend.registrar.set_wallet(
        (wallet['payment_addresses'][0], wallet['payment_privkey']),
        (wallet['owner_addresses'][0], wallet['owner_privkey']),
        (wallet['data_pubkeys'][0], wallet['data_privkey']),
        config_path=config_path
    )

    if 'error' in res:
        log.error("Failed to set wallet: {}".format(res['error']))
        return False

    log.debug("Setup finished")

    running = True
    local_api_write_pidfile(rpc_pidpath)
    local_api_server_run(rpc_srv)

    local_api_unlink_pidfile(rpc_pidpath)
    local_api_server_stop(rpc_srv)

    return True


def api_kill(pidpath, pid, sig, unlink_pidfile=True):
    """
    Utility function to send signals
    Return True if signal actions were successful
    Return False if signal actions were unsuccessful
    """
    try:
        os.kill(pid, sig)
        if sig == signal.SIGKILL:
            local_api_unlink_pidfile(pidpath)

        return True
    except OSError as oe:
        if oe.errno == errno.ESRCH:
            log.debug('Not running: {} ({})'.format(pid, pidpath))
            if unlink_pidfile:
                local_api_unlink_pidfile(pidpath)
            return True
        elif oe.errno == errno.EPERM:
            log.debug('Not our RPC daemon: {} ({})'.format(pid, pidpath))
            return False
        else:
            raise


def local_api_stop(config_dir=blockstack_constants.CONFIG_DIR):
    """
    Shut down an API endpoint
    Return True if we stopped it
    Return False if it wasn't running, or we couldn't stop it
    """
    # already running?
    pidpath = local_api_pidfile_path(config_dir=config_dir)
    if not os.path.exists(pidpath):
        print('Not running ({})'.format(pidpath), file=sys.stderr)
        return False

    pid = local_api_read_pidfile(pidpath)
    if pid is None:
        print('Failed to read "{}"'.format(pidpath), file=sys.stderr)
        return False

    if not api_kill(pidpath, pid, 0):
        print('API server is not running', file=sys.stderr)
        return False

    # still running. try to terminate
    print('Sending SIGTERM to {}'.format(pid), file=sys.stderr)

    if not api_kill(pidpath, pid, signal.SIGTERM):
        print("Unable to send SIGTERM to {}".format(pid), file=sys.stderr)
        return False

    time.sleep(1)

    for i in xrange(0, 2):
        # still running?
        if not api_kill(pidpath, pid, 0):
            # dead
            return False

        time.sleep(1)

    # still running
    print('Sending SIGKILL to {}'.format(pid), file=sys.stderr)

    # sigkill ensure process will die
    return api_kill(pidpath, pid, signal.SIGKILL)


def local_api_status(config_dir=blockstack_constants.CONFIG_DIR):
    """
    Print the status of an instantiated API endpoint
    Return True if the daemon is running.
    Return False if not, or if unknown.
    """
    # see if it's running
    pidpath = local_api_pidfile_path(config_dir=config_dir)
    if not os.path.exists(pidpath):
        log.debug('No PID file {}'.format(pidpath))
        return False

    pid = local_api_read_pidfile(pidpath)
    if pid is None:
        log.debug('Invalid PID file {}'.format(pidpath))
        return False

    if not api_kill(pidpath, pid, 0, unlink_pidfile=False):
        return False

    log.debug('RPC running ({})'.format(pidpath))

    return True


