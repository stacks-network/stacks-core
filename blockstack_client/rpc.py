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
import jsonschema
from jsonschema import ValidationError
from schemas import *

from types import ModuleType
import keylib
from keylib import *

import signal
import json
import config as blockstack_config
import backend
import proxy
from proxy import json_is_error, json_is_exception

from .constants import BLOCKSTACK_DEBUG, RPC_MAX_ZONEFILE_LEN, CONFIG_PATH, WALLET_FILENAME
from .client import check_storage_setup
from .method_parser import parse_methods
import app
import assets
import data
import zonefile
import wallet
import user as user_db

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
def load_rpc_cli_method_info(blockstack_client_mod):
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


def load_rpc_internal_methods(config_path):
    """
    Load internal RPC method proxy
    (for the server to use to call its own methods safely)
    Call this from __main__
    """
    global RPC_INTERNAL_METHODS

    if RPC_INTERNAL_METHODS is not None:
        return RPC_INTERNAL_METHODS

    srv_internal = BlockstackAPIEndpoint(
        None, config_path=config_path, plugins=get_default_plugins(), server=False
    )

    RPC_INTERNAL_METHODS = srv_internal.internal_proxy

    os.environ['BLOCKSTACK_RPC_INITIALIZED_METHODS'] = '1'

    return RPC_INTERNAL_METHODS


def get_rpc_internal_methods():
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


def get_rpc_cli_method_info(method_name):
    global RPC_CLI_METHOD_INFO

    msg = 'RPC methods not initialized (loaded = {})'
    msg = msg.format(os.environ.get('BLOCKSTACK_RPC_INITIALIZED_INFO', None))
    assert RPC_CLI_METHOD_INFO is not None, msg

    return RPC_CLI_METHOD_INFO.get(method_name, None)


def list_rpc_cli_method_info():
    global RPC_CLI_METHOD_INFO

    msg = 'RPC methods not loaded (loaded = {})'
    msg = msg.format(os.environ.get('BLOCKSTACK_RPC_INITIALIZED_INFO', None))
    assert RPC_CLI_METHOD_INFO is not None, msg

    return RPC_CLI_METHOD_INFO


def run_cli_rpc(command_name, argv, config_path=CONFIG_PATH, check_rpc=True, **kw):
    """
    Invoke a CLI method via RPC.  Note that @command_name
    is the name of the *command*, not the method.

    Return the result of the command on success (as a dict).

    side-effect: caches parsed methods
    """
    command_info = get_rpc_cli_method_info(command_name)

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

        # type-check...
        try:
            arg = arg_type(arg)
        except:
            return {'error': 'Type error: {} must be {}'.format(arg_name, arg_type)}

        setattr(args, arg_name, arg)

    if 'config_path' in kw:
        config_path = kw.pop('config_path')

    if 'check_storage' in pragmas:
        # need storage set up first
        res = check_storage_setup(config_path=config_path)
        if 'error' in res:
            log.error("Storage is not set up for this wallet")
            return {'error': 'Storage is not set up.  Please run `setup_storage`.'}

    res = command_info['method'](args, config_path=config_path, **kw)

    return res


# need to wrap CLI methods to capture arguments
def local_rpc_factory(method_info, config_path, check_rpc=True, include_kw=False):
    """
    Factory for producing methods that call the right
    version of run_cli_rpc.  Makes the same methods
    available via the CLI accessible to both the
    RPC daemon code and to external clients of the RPC daemon.
    """
    def argwrapper(*args, **kw):
        cf = config_path
        if kw.has_key('config_path'):
            cf = kw.pop('config_path')

        if include_kw:
            result = run_cli_rpc(method_info['command'], list(args), config_path=cf, check_rpc=check_rpc, **kw)
        else:
            result = run_cli_rpc(method_info['command'], list(args), config_path=cf, check_rpc=check_rpc)

        return result

    argwrapper.__doc__ = method_info['method'].__doc__
    argwrapper.__name__ = method_info['method'].__name__
    return argwrapper


# ping method
def ping():
    return True


class BlockstackAPIEndpointHandler(SimpleHTTPRequestHandler):
    '''
    Blockstack API endpoint.
    * handle JSONRPC requests on POST
    * handle app authentication 
    * serve app resources to authenticated applications
    '''

    JSONRPC_PARSE_ERROR = -32700
    JSONRPC_INVALID_REQUEST = -32600
    JSONRPC_METHOD_NOT_FOUND = -32601
    JSONRPC_INVALID_PARAMS = -32602
    JSONRPC_INTERNAL_ERROR = -32603

    JSONRPC_MAX_SIZE = 1024 * 1024      # 1 MB

    def _send_headers(self, status_code=200, content_type='application/json'):
        """
        Generate and reply headers
        """
        self.send_response(status_code)
        self.send_header('content-type', content_type)
        self.end_headers()


    def _send_redirect(self, redirect_url):
        """
        Generate and reply a redirect response
        """
        self.send_response(302)
        self.send_header('Location', redirect_url)
        self.end_headers()

    
    def _make_jsonrpc_response(self, m_id, have_result=False, result=None, have_error=False, error=None):
        """
        Make a base JSON-RPC response
        """
        assert have_result or have_error, "Need result or error"

        payload = {}
        if have_result:
            payload['result'] = result

        if have_error:
            payload['error'] = error
            
        res = {'jsonrpc': '2.0', 'id': m_id}
        res.update(payload)
        return res


    def _make_jsonrpc_error(self, code, message, data=None):
        """
        Make a JSON-RPC error message
        """
        error_msg = {}
        error_msg['code'] = code
        error_msg['message'] = message
        if data:
            error_msg['data'] = data

        return error_msg


    def _reply(self, resp):
        """
        Send a JSON response
        """
        jsonschema.validate(resp, JSONRPC_RESPONSE_SCHEMA)

        resp_str = json.dumps(resp)
        self.wfile.write(resp_str)
        return


    def _reply_error(self, m_id, code, message, data=None):
        """
        Generate and reply an error code
        """
        self._send_headers()

        error_msg = self._make_jsonrpc_error( code, message, data=data )
        resp = self._make_jsonrpc_response( m_id, have_error=True, error=error_msg )

        self._reply(resp)
        return


    def _reply_result(self, m_id, result_payload):
        """
        Generate and reply a result
        """
        self._send_headers()

        resp = self._make_jsonrpc_response( m_id, have_result=True, result=result_payload )

        self._reply(resp)
        return


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

    
    def JSONRPC_call(self, session, path_info ):
        """
        Handle one JSON-RPC request
        """
        
        qs_values = path_info['qs_values']
        request = self._read_json(schema=JSONRPC_REQUEST_SCHEMA)
        if request is None:
            self._reply_error( None, self.JSONRPC_PARSE_ERROR, 'Parse error' )
            return 

        # look up
        rpc_id = request['id']
        method_name = request['method']
        method_params = request.get('params', [])
        if method_name not in self.server.funcs:
            self._reply_error( rpc_id, self.JSONRPC_METHOD_NOT_FOUND, 'No such method')
            return

        # must be allowed by the session.
        # the only method allowed-by-default is 'ping'
        log.debug("Call '{}'".format(method_name))
        if method_name not in ['ping']:
            if not request.has_key('blockstack_rpc_token') or request['blockstack_rpc_token'] != self.server.rpc_token:
                # no RPC token, so need a session
                if session is None:
                        # must authenticate first
                        return self.app_auth_begin(qs_values)

                elif method_name not in session['methods']:
                    # not allowed by session
                    self._reply_error( rpc_id, self.JSONRPC_INVALID_REQUEST, "Method not allowed")
                    return 

        # validate arguments
        method = self.server.funcs[method_name]
        try:
            if isinstance(method_params, dict):
                inspect.getcallargs(method, **method_params)
            else:
                inspect.getcallargs(method, *method_params)

        except ValueError as ve:
            if BLOCKSTACK_DEBUG:
                log.exception(ve)

            self._reply_error( rpc_id, self.JSONRPC_INVALID_PARAMS, "Invalid parameters")
            return

        # call 
        resp = None
        try:
            if isinstance(method_params, dict):
                resp = method(**method_params)
            else:
                resp = method(*method_params)

        except Exception, e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            msg = "Internal error"
            
            if BLOCKSTACK_DEBUG:
                trace = traceback.format_exc()
                msg += "\nCaught exception\n{}".format(trace)

            self._reply_error( rpc_id, self.JSONRPC_INTERNAL_ERROR, msg )
            return 

        # return result
        self._reply_result( rpc_id, resp )
        return

    
    def get_app_info(self, qs_values):
        """
        Get the app blockchain ID and appname information on request
        Return {''app_fqu': ..., 'appname': ...} on success
        Return {'error': ...} on error
        """
        # NOTE: the way we get the name and appname here is a place-holder until
        # (1) we can get the appname from the Host: field reliably (i.e. need local DNS stub), and
        # (2) we have a .app namespace, where the app name and the Blockstack ID are the same thing.
        # application owner name is in the `name=` parameter, or `Host:` header
        app_fqu = qs_values.get("name", None)
        if app_fqu is None:
            app_fqu = self.headers.get('host', None)
            if app_fqu is None or app_fqu.startswith("localhost:") or app_fqu == "localhost":
                log.error("No Host: header, and no name= query arg")
                return {'error': 'Could not identify application owner'}

        # application name should be in the query string under `appname=`;
        # if not given, it falls back to the name of the app
        appname = qs_values.get('appname', None)
        if appname is None:
            appname = app_fqu

        return {'app_fqu': app_fqu, 'appname': appname}


    def app_auth_begin(self, qs_values):
        """
        Begin application authentication.
        Redirect the user with a URL to either sign in with an existing account
        or create a new account.
        """
        app_info = self.get_app_info(qs_values)
        if 'error' in app_info:
            self._send_headers(status_code=401, content_type='text/plain')
            return 

        app_fqu = app_info['app_fqu']
        appname = app_info['appname']

        name_payload = {
            'name': app_fqu,
            'appname': appname
        }

        url = app.app_auth_begin( app_fqu, appname, name_payload, self.server.master_data_privkey, config_path=self.server.config_path )
        if url is None:
            log.error("Failed to generate auth-begin URL")
            self._send_headers(status_code=500, content_type='text/plain')
            return 

        self._send_redirect( url )
        return

    
    def app_make_session(self, user_id, app_fqu, appname):
        """
        Make a session for the application
        Return the session token on success
        Return None on error
        """
        user = data.get_user( user_id, self.server.master_data_pubkey, config_path=self.server.config_path )
        if 'error' in user:
            log.error("Failed to load user {}".format(user_id))
            return None 
        
        # we have to own it locally 
        if not user['owned']:
            log.error("This wallet does not own user {}".format(user_id))
            return None 

        user_info = user['user']

        acct = app.app_load_account( user_id, app_fqu, appname, user_info['public_key'], config_path=self.server.config_path)
        if 'error' in acct:
            log.error("Failed to load user for {}/{}".format(app_fqu, appname))
            return None
       
        # extract account payload
        acct_info = acct['account']

        ses = app.app_make_session( acct_info, self.server.master_data_privkey, config_path=self.server.config_path )
        if 'error' in ses:
            log.error("Failed to make session for {}/{}".format(app_fqu, appname))
            return None

        return ses['session_token']


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

    
    def verify_url(self):
        """
        Reconstruct and authenticate the URL send to this handler.
        Return True if verified
        Return False if not
        """
        host = self.headers.get('host', None)
        if host is None:
            log.error("No Host: given")
            return False
        
        url = "http://{}{}".format(host, self.path)
        res = app.app_verify_url( url, self.server.master_data_pubkey, config_path=self.server.config_path )
        if res is None:
            log.error("Failed to verify '{}'".format(url))
            return False

        return True


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
            {'authenticate': True/False, 
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
            whitelist = route_info.get('whitelist', None)
            if whitelist is not None:
                assert method_name in whitelist.keys()
                whitelist = whitelist[method_name]

            return {
                'route': route_info,
                'whitelist': whitelist,
                'method': route_info['routes'][method_name],
                'args': groups,
                'need_data_key': route_info.get('need_data_key', True),
            }

        return None


    def GET_auth_signin(self, ses_ignored, path_info, app_fqu, appname):
        """
        Handle an application signin.  The user has the option
        of signing into the application, or going back to the identity page

        @app_fqu is the name that owns the app
        @appname is the name of the specific application.

        Serve the signin page for the user, with a URL to finish the authentication.
        """
        # must correspond to this application
        qs_values = path_info['qs_values']
        app_info = self.get_app_info(qs_values)
        if 'error' in app_info:
            self._send_headers(status_code=401, content_type='text/plain')
            return 

        if app_info['app_fqu'] != app_fqu or app_info['appname'] != appname:
            self._send_headers(status_code=403, content_type='text/plain')
            return 

        # serve back the page that lets users sign in to an application.
        auth_abort_url = app.app_url_auth_abort( config_path=self.server.config_path )
        if auth_abort_url is None:
            log.error("Failed to generate URLs for signin page")
            self._send_headers(status_code=500, content_type='text/plain')
            return 

        acct_infos = app.app_find_accounts(app_fqu=app_fqu, appname=appname, config_path=self.server.config_path)
        if len(acct_infos) == 0:
            log.error("Failed to find accounts for {}/{}".format(app_fqu, appname))
            self._send_headers(status_code=500, content_type='text/plain')
            return 

        user_ids = list(set(acct_info['user_id'] for acct_info in acct_infos))
        name_payload = {
            'name': app_fqu,
            'appname': appname
        }

        user_id_urls = [app.app_url_auth_load_account(user_id, app_fqu, appname, name_payload, self.server.master_data_privkey, config_path=self.server.config_path) for user_id in user_ids]
        page = assets.asset_make_signin_page(appname, app_fqu, user_id_urls, auth_abort_url)

        self._send_headers(content_type='text/html')
        self.wfile.write(page)
        return

    
    def GET_auth_allowdeny(self, ses_ignored, path_info, app_fqu, appname):
        """
        Handle an application account creation.  The user has the
        option of creating an account for the application.

        @app_fqu is the name that owns the app
        @appname is the name of the app itself

        Serve the allow/deny page for the user, with a URL to create the account
        """
        # must correspond to this application
        qs_values = path_info['qs_values']
        app_info = self.get_app_info(qs_values)
        if 'error' in app_info:
            self._send_headers(status_code=401, content_type='text/plain')
            return 

        if app_info['app_fqu'] != app_fqu or app_info['appname'] != appname:
            self._send_headers(status_code=403, content_type='text/plain')
            return 

        # serve back the page that lets users select whether or not
        # to create an account and begin an application session.
        log.debug("Get app config for {}:{}".format(app_fqu, appname))
        app_config = app.app_get_config( app_fqu, appname, config_path=self.server.config_path )
        if 'error' in app_config:
            log.error("Failed to load app config for {}:{}".format(app_fqu, appname))
            error_page = assets.asset_make_error_page("Failed to load application config.")
            self._send_headers(content_type='text/html')
            self.wfile.write(error_page)
            return

        app_config = app_config['config']
        self.server.cache_app_config(app_fqu, appname, app_config)

        app_methods = app_config['api_methods']

        log.debug("Get user list for {}".format(self.server.master_data_pubkey))
        users = data.get_user_list( self.server.master_data_pubkey, config_path=self.server.config_path )
        if 'error' in users:
            log.error("Failed to load users list")
            error_page = assets.asset_make_error_page("Failed to get user list.")
            self._send_headers(content_type='text/html')
            self.wfile.write(error_page)
            return

        user_ids = users['user_ids']
        name_payload = {
            'name': app_fqu,
            'appname': appname
        }
        
        create_account_urls = [app.app_url_auth_create_account(user_id, app_fqu, appname, name_payload, self.server.master_data_privkey, config_path=self.server.config_path) for user_id in user_ids]
        auth_abort_url = app.app_url_auth_abort( config_path=self.server.config_path )
        
        if None in create_account_urls or auth_abort_url is None:
            log.error("Failed to generate URLs for account-creation page")
            self._send_headers(status_code=500, content_type='text/plain')
            return 

        page = assets.asset_make_account_page(app_fqu, appname, app_methods, create_account_urls, auth_abort_url )
        
        self._send_headers(content_type='text/html')
        self.wfile.write(page)
        return


    def GET_auth_create_account_and_redirect(self, ses_ignored, path_info, user_id, app_fqu, appname ):
        """
        Create an application account and make a session, and redirect
        the user with a URL to finish authenticating the application
        """
        # must correspond to this application
        qs_values = path_info['qs_values']
        app_info = self.get_app_info(qs_values)
        if 'error' in app_info:
            self._send_headers(status_code=401, content_type='text/plain')
            return 

        if app_info['app_fqu'] != app_fqu or app_info['appname'] != appname:
            self._send_headers(status_code=403, content_type='text/plain')
            return 

        app_config = self.server.get_cached_app_config(app_fqu, appname)
        if app_config is None:
            log.error("No cached app config for {}:{}".format(app_fqu, appname))
            self._send_headers(status_code=500, content_type='text/plain')
            return 

        qs_values = path_info['qs_values']
        app_methods = app_config['api_methods']
        session_lifetime = qs_values.get("session_lifetime", 24*7*3600)

        # TODO: override session lifetime from config file, or from page
        internal = self.server.get_internal_proxy()
        res = internal.cli_app_put_account( user_id, app_fqu, appname, ",".join(app_methods) )
        if 'error' in res:
            log.error("Failed to put account for {} in {}/{}: {}".format(user_id, app_fqu, appname, res['error']))
            self._send_headers(status_code=503, content_type='text/plain')
            return

        # make a session 
        return self.GET_auth_load_account_and_redirect(ses_ignored, path_info, user_id, app_fqu, appname )


    def GET_auth_load_account_and_redirect(self, ses_ignored, path_info, user_id, app_fqu, appname ):
        """
        Load a user, generate a session, and redirect to the auth-finish endpoint
        """
        # must correspond to this application
        qs_values = path_info['qs_values']
        app_info = self.get_app_info(qs_values)
        if 'error' in app_info:
            self._send_headers(status_code=401, content_type='text/plain')
            return 

        if app_info['app_fqu'] != app_fqu or app_info['appname'] != appname:
            self._send_headers(status_code=403, content_type='text/plain')
            return 

        # make a session 
        ses_token = self.app_make_session(user_id, app_fqu, appname)
        if ses_token is None:
            log.error("Failed to make session")
            self._send_headers(status_code=403, content_type='text/plain')
            return 

        name_payload = {
            'name': app_fqu,
            'appname': appname
        }

        # redirect to finish 
        auth_finish_url = app.app_url_auth_finish( name_payload, self.server.master_data_privkey, ses_token, config_path=self.server.config_path )
        if auth_finish_url is None:
            log.error("Failed to generate auth-finish URL")
            self._send_headers(status_code=500, content_type='text/plain')
            return 

        self._send_redirect(auth_finish_url)
        return 


    def GET_index(self, ses, path_info ):
        """
        Handle GET /index.html
        Load the given application index file.
        Handled separately from resources, since
        the index file may be hosted on the legacy web.
        """
        appname = ses['appname']
        app_fqu = ses['name']
        app_config = self.server.get_cached_app_config(app_fqu, appname)
        
        res = app.app_get_index_file( app_fqu, appname, app_config=app_config, config_path=self.server.config_path )
        if 'error' in res:
            # not found 
            log.error("Failed to load index file {}:{}/index.html: {}".format(name, appname, path, res['error']))
            self._send_headers(status_code=404, content_type='text/plain')
            return 

        self._send_headers(status_code=200, content_type='application/octet-stream')
        self.wfile.write( res['index_file'] )
        return 


    def GET_app_resource(self, ses, path_info, fqu, appname, path ):
        """
        Load the given application resource
        Write it back to the client on success.
        Return 404 on not found.
        Return 403 if the FQU or app name do not match the session
        """
        if appname != ses['appname'] or fqu != ses['name']:
            # nope!
            self._send_headers(status_code=403, content_type='text/plain')
            return 

        appname = ses['appname']
        app_fqu = ses['name']
        app_config = self.server.get_cached_app_config(app_fqu, appname)

        res = app.app_get_resource( name, appname, path, app_config=app_config, config_path=self.server.config_path )
        if 'error' in res:
            # not found 
            log.error("Failed to load {}:{}/{}: {}".format(name, appname, path, res['error']))
            self._send_headers(status_code=404, content_type='text/plain')
            return

        self._send_headers(status_code=200, content_type='application/octet-stream')
        self.wfile.write( res['data'] )
        return


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
        Register a name.
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
            self._reply_json({"error": 'Invalid request'}, status_code=401)
            return 

        name = request['name']
        res = internal.cli_register(name, interactive=False)
        if 'error' in res:
            log.error("Failed to register {}".format(name))
            self._reply_json({"error": "Failed to register name: {}".format(res['error'])}, status_code=500)
            return 

        resp = {
            'transaction_hash': res['transaction_hash']
        }
        self._reply_json(resp, status_code=202)
        return

    
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
        ret = {
            'status': status,
            'zonefile': zonefile_txt,
            'zonefile_hash': name_rec['value_hash'],
            'address': name_rec['address'], 
            'last_txid': name_rec['txid'],
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

    
    def PATCH_name_transfer( self, ses, path_info, name ):
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

        res = internal.cli_transfer(name, recipient_address, interactive=False)
        if 'error' in res:
            log.error("Failed to register {}".format(name))
            self._reply_json({"error": "Failed to register name: {}".format(res['error'])}, status_code=500)
            return 

        resp = {
            'transaction_hash': res['transaction_hash']
        }
        self._reply_json(resp, status_code=202)
        return

        
    def PATCH_name_zonefile( self, ses, path_info, name ):
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
                'zonefile_hash': {
                    'type': 'string',
                    'pattern': OP_ZONEFILE_HASH_PATTERN,
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

        if zonefile_hash is None and zonefile_str is None:
            log.error("No zonefile or zonefile hash received")
            self._reply_json({'error': 'Invalid request'}, status_code=401)
            return 
    
        if zonefile_hash is not None and zonefile_str is not None:
            log.error("Got both zonefile and zonefile hash")
            self._reply_json({'error': 'Invalid request'}, status_code=401)
            return 

        res = None
        if zonefile_str is not None:
            res = internal.cli_update(name, str(zonefile_str), "false", interactive=False, nonstandard=True, force_data=True)

        else:
            res = internal.cli_set_zonefile_hash(name, str(zonefile_hash))
        
        if 'error' in res:
            log.error("Failed to update {}: {}".format(name, res['error']))
            self._reply_json({"error": "Failed to update: {}".format(res['error'])}, status_code=503)
            return 

        resp = {
            'transaction_hash': res['transaction_hash']
        }
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
            log.error("Failed to revoke {}".format(name))
            self._reply_json({"error": "Failed to revoke name: {}".format(res['error'])}, status_code=500)
            return 

        resp = {
            'transaction_hash': res['transaction_hash']
        }
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
            'transaction_hash': resp['transaction_hash']
        }

        self._reply_json(ret)
        return

    
    def GET_users( self, ses, path_info ):
        """
        Get all users
        Reply the list of users on success (see USER_SCHEMA)
        Return 500 on error
        """
        internal = self.server.get_internal_proxy()
        resp = internal.cli_list_users()
        if json_is_error(resp):
            self._reply_json({'error': resp['error']}, status_code=500)
            return 

        self._reply_json(resp)
        return 


    def POST_users( self, ses, path_info ):
        """
        Create a user, given a user ID and a profile
        Return 200 on success
        Return 500 on failure to create the user account
        Return 503 on failure to replicate the profile (the caller should try POST_user_profile to re-try uploading)
        """
        upload_schema = {
            'type': 'object',
            'properties': {
                'user_id': {
                    'type': 'string',
                    'pattern': OP_USER_ID_PATTERN,
                },
                'profile': {
                    'type': 'object'
                },
            },
            'required': [
                'profile'
            ],
            'additionalProperties': False
        }

        user_profile_json = self._read_json(schema=upload_schema)
        if user_profile_json is None:
            self._reply_json({'error': 'Invalid user ID or profile'}, status_code=401)
            return

        user_id = user_profile_json['user_id']
        user_profile = user_profile_json['profile']

        internal = self.server.get_internal_proxy()
        res = internal.cli_create_user( user_id )
        if json_is_error(res):
            self._reply_json({'error': 'Failed to create user: {}'.format(res['error'])}, status_code=500)
            return 

        # store profile 
        profile_str = json.dumps(user_profile)
        res = internal.cli_put_user_profile( user_id, profile_str )
        if json_is_error(res):
            self._reply_json({'error': 'Failed to store user profile: {}'.format(res['error'])}, status_code=503)
            return 

        self._reply_json({'status': True})
        return


    def DELETE_user( self, ses, path_info, user_id ):
        """
        Delete a user and its profile.
        Return 200 on success
        Return 403 if the user ID does not match the session user ID
        Return 500 on failure to remove the local user information.
        Return 503 to delete the profile.  The caller should try this method again until it succeeds.
        """
        if user_id != ses['user_id']:
            self._reply_json({'error': 'Invalid user ID'}, status_code=403)
            return 

        internal = self.server.get_internal_proxy()
        res = internal.cli_delete_user_profile( user_id, wallet_keys=self.server.wallet_keys )
        if json_is_error(res):
            self._reply_json({'error': 'Failed to delete user profile: {}'.format(res['error'])}, status_code=503)
            return 

        res = internal.cli_delete_user( user_id, wallet_keys=self.server.wallet_keys )
        if json_is_error(res):
            self._reply_json({'error': 'Failed to delete user: {}'.format(res['error'])}, status_code=500)
            return 

        self._reply_json({'status': True})
        return 


    def GET_user_profile( self, ses, path_info, user_id ):
        """
        Get a user profile.
        Only works on the session user's profile
        Reply the profile on success
        Return 403 on invalid user ID (must match the session user ID)
        Return 404 on failure to load
        """
        if user_id != ses['user_id']:
            self._reply_json({'error': 'Invalid user ID'}, status_code=403)
            return 

        internal = self.server.get_internal_proxy()
        resp = internal.cli_get_user_profile( user_id )
        if json_is_error(resp):
            self._reply_json({'error': resp['error']}, status_code=404)
            return
    
        self._reply_json(resp)
        return


    def PATCH_user_profile( self, ses, path_info, user_id ):
        """
        Patch a user profile.
        Only works on the session user's profile
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

        if user_id != ses['user_id']:
            self._reply_json({'error': 'Invalid user ID'}, status_code=403)
            return 

        profile_json = self._read_json(schema=upload_schema)
        if profile_json is None:
            self._reply_json({'error': 'Invalid profile'}, status_code=401)
            return

        internal = self.server.get_internal_proxy()
        resp = internal.cli_put_user_profile( user_id, json.dumps(profile_json['profile']), force_data=True )
        if json_is_error(resp):
            self._reply_json({'error': resp['error']}, status_code=500)
            return 

        self._reply_json(resp)
        return 


    def GET_user_stores( self, ses, path_info, user_id ):
        """
        Get the user's list of stores
        Only works on the session user's stores
        Reply 200 on success
        Reply 403 on invalid user ID
        Reply 500 on failure to load
        """
        if user_id != ses['user_id']:
            self._reply_json({'error': 'Invalid user ID'}, status_code=403)
            return 

        internal = self.server.get_internal_proxy()
        user_datastore_list = internal.cli_list_datastores(user_id)
        if json_is_error(user_datastore_list):
            self._reply_json({'error': 'Failed to list datastores: {}'.format(user_datastore_list['error'])}, status_code=500)
            return 

        self._reply_json(user_datastore_list)
        return

    
    def POST_user_stores( self, ses, path_info, user_id ):
        """
        Make a data store for the given user ID 
        Only works on this user's stores
        Reply 200 on success
        Reply 403 on invalid user ID
        Reply 503 on failure to replicate
        """
        upload_schema = {
            'type': 'object',
            'properties': {
                'storeID': {
                    'type': 'string',
                    'pattern': OP_URLENCODED_PATTERN
                },
            },
            'required': [
                'storeID'
            ],
            'additionalProperties': False
        }

        if user_id != ses['user_id']:
            self._reply_json({'error': 'Invalid user ID'}, status_code=403)
            return 

        datastore_info = self._read_json(schema=upload_schema)
        if datastore_info is None:
            self._reply_json({'error': 'Invalid request'}, status_code=401)
            return 
        
        datastore_id = datastore_info['storeID']
        internal = self.server.get_internal_proxy()
        res = internal.cli_create_datastore(user_id, datastore_id, wallet_keys=self.server.wallet_keys)
        if json_is_error(res):
            self.reply_json({'error': 'Failed to put datastore: {}'.format(res['error'])}, status_code=503)
            return 

        self._reply_json({'status': True})
        return 
        

    def PUT_user_stores( self, ses, path_info, user_id, store_id ):
        """
        Update a user store.
        """
        if user_id != ses['user_id']:
            self._reply_json({'error': 'Invalid user ID'}, status_code=403)
            return 

        pass

    
    def DELETE_user_stores( self, ses, path_info, user_id, store_id ):
        """
        Delete a user store
        Only works on the session's user ID
        Reply 200 on success
        Reply 403 on invalid user ID
        Reply 503 on (partial) failure to delete all replicas
        """
        if user_id != ses['user_id']:
            self._reply_json({'error': 'Invalid user ID'}, status_code=403)
            return 

        qs = path_info['qs_values']
        force = qs.get('force', "0")
        force = (force.lower() in ['1', 'true'])

        internal = self.server.get_internal_proxy()
        res = internal.cli_delete_datastore(user_id, store_id, force)
        if json_is_error(res):
            self._reply_json({'error': 'Failed to delete datastore: {}'.format(res['error'])}, status_code=503)
            return 

        self._reply_json({'status': True})
        return 


    def GET_user_store_item( self, ses, path_info, user_id, store_id, inode_type ):
        """
        Get a store item
        Only works on the session's user ID
        Reply 200 on succes, with the raw data (as application/octet-stream for files, and as application/json for directories and inodes)
        Reply 401 if no path is given
        Reply 403 on invalid user ID
        Reply 404 if the file/directory does not exist
        Reply 503 on failure to load data from storage providers
        """
        if user_id != ses['user_id']:
            self._reply_json({'error': 'Invalid user ID'}, status_code=403)
            return 

        if inode_type not in ['file', 'directory', 'inode']:
            self._reply_json({'error': 'Invalid request'}, status_code=401)
            return 

        qs = path_info['qs_values']
        internal = self.server.get_internal_proxy()
        path = qs.get('path', None)
        if path is None:
            self._reply_json({'error': 'No path given'}, status_code=401)
            return 

        res = None

        if inode_type == 'file':
            res = internal.cli_datastore_getfile(user_id, store_id, path)
        elif inode_type == 'directory':
            res = internal.cli_datastore_listdir(user_id, store_id, path)
        else:
            res = internal.cli_datastore_stat(user_id, store_id, path)
        
        if json_is_error(res):
            if res['errno'] == errno.ENOENT:
                self._send_headers(status_code=404, content_type='text/plain')
                return 

            else:
                self.reply_json({'error': 'Failed to read {}: {}'.format(inode_type, res['error'])})
                return 

        if inode_type == 'file':
            self._send_headers(status_code=200, content_type='application/octet-stream')
            self.wfile.write(res['file']['idata'])

        elif inode_type == 'directory':
            self._reply_json(res['dir']['idata'])

        else:
            self._reply_json(res['inode'])

        return

    
    def POST_user_store_item( self, ses, path_info, user_id, store_id, inode_type ):
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
        return self._create_or_update_store_item( ses, path_info, user_id, store_id, inode_type, create=True )


    def PUT_user_store_item(self, ses, path_info, user_id, store_id, inode_type ):
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


    def _create_or_update_store_item( self, ses, path_info, user_id, store_id, inode_type, create=False ):
        """
        Create or update a file, or create a directory.
        Implements POST_user_store_item and PUT_user_store_item
        """
        if user_id != ses['user_id']:
            log.debug("Invalid user ID")
            self._reply_json({'error': 'Invalid user ID'}, status_code=403)
            return

        if inode_type not in ['file', 'directory']:
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

        if inode_type == 'file':
            data = self._read_payload()
            if data is None:
                self._reply_json({'error': 'Failed to read file data'}, status_code=401)
                return 

            do_create = None
            if create:
                do_create = "True"
            else:
                do_create = "False"

            res = internal.cli_datastore_putfile(user_id, store_id, path, data, do_create, force_data=True, wallet_keys=self.server.wallet_keys)
        
        elif create:
            res = internal.cli_datastore_mkdir(user_id, store_id, path, wallet_keys=self.server.wallet_keys)

        else:
            log.error("Invalid request: cannot update directory {}".format(path))
            self._reply_json({'error': 'Invalid request'}, status_code=401)
            return

        if 'error' in res:
            log.error("Failed to make {} {}: {}".format(inode_type, path, res['error']))
            self._reply_json({'error': 'Failed to store item'}, status_code=503)
            return 

        self._reply_json({'status': True})
        return

    
    def DELETE_user_store_item( self, ses, path_info, user_id, store_id, inode_type ):
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
        """
        if user_id != ses['user_id']:
            self._reply_json({'error': 'Invalid user ID'}, status_code=403)
            return 

        if inode_type not in ['file', 'directory']:
            self._reply_json({'error': 'Invalid request'}, status_code=401)
            return 

        qs = path_info['qs_values']
        internal = self.server.get_internal_proxy()
        path = qs.get('path', None)
        if path is None:
            self._reply_json({'error': 'No path given'}, status_code=401)
            return 

        res = None 

        if inode_type == 'file':
            res = internal.cli_datastore_deletefile(user_id, store_id, path, wallet_keys=self.server.wallet_keys)

        else:
            res = internal.cli_datastore_rmdir(user_id, store_id, path, wallet_keys=self.server.wallet_keys)

        if 'error' in res:
            log.error("Failed to remove {} {}: {}".format(inode_type, path, res['error']))
            if res['errno'] == errno.ENOENT:
                self._send_headers(status_code=404, content_type='text/plain')
                return 

            else:
                self._reply_json({'error': 'Failed to remove item'}, status_code=503)
                return 

        self._reply_json({'status': True})
        return


    def GET_user_collections( self, ses, path_info, user_id ):
        """
        Get the list of collections
        Reply the list of collections on success.
        """
        if user_id != ses['user_id']:
            self._reply_json({'error': 'Invalid user ID'}, status_code=403)
            return 

        pass


    def POST_user_collections( self, ses, path_info, user_id ):
        """
        Create a new collection
        """
        if user_id != ses['user_id']:
            self._reply_json({'error': 'Invalid user ID'}, status_code=403)
            return 

        pass


    def GET_user_collection_info( self, ses, path_info, user_id, collection_id ):
        """
        Get metadata on a user's collection (including the list of items)
        Reply the list of items on success
        Reply 404 on not found
        """
        if user_id != ses['user_id']:
            self._reply_json({'error': 'Invalid user ID'}, status_code=403)
            return 

        pass


    def GET_user_collection_item( self, ses, path_info, user_id, collection_id, item_id ):
        """
        Get a particular item from a particular collection
        Reply the item requested
        Reply 404 if the collection doesn't exist
        Reply 404 if the item doesn't exist
        """
        if user_id != ses['user_id']:
            self._reply_json({'error': 'Invalid user ID'}, status_code=403)
            return 

        pass


    def POST_user_collection_item( self, ses, path_info, user_id, collection_id ):
        """
        Add an item to a collection
        """
        if user_id != ses['user_id']:
            self._reply_json({'error': 'Invalid user ID'}, status_code=403)
            return 

        pass


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
            if json_is_exception(info):
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
        self._reply_json({"error": "Unimplemented"}, status_code=405)
        return

    
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
        self._reply_json({'error': 'Unimplemented'}, status_code=405)
        return 


    def PUT_namespace_name_import( self, ses, path_info, namespace_id ):
        """
        Re-import a name
        Not implemented
        """
        self._reply_json({'error': 'Unimplemented'}, status_code=405)
        return 

    
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


    def PUT_wallet( self, ses, path_info ):
        """
        Upload a new wallet.
        Requires the caller pass the RPC secret.
        Return 200 on success
        Return 403 on wrong token
        """
        pass


    def GET_ping( self, ses, path_info ):
        """
        Ping the node
        always succeeds
        """
        self._send_headers(status_code=200, content_type='text/plain')
        return


    def POST_reboot( self, ses, path_info ):
        """
        Reboot the node.
        Requires the caller pass the RPC secret
        Does not return on success
        Return 403 on failure
        """
        pass


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
        Reply 404 
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
            if json_is_exception(info):
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
            r'^/$': {
                'routes': {
                    'GET': self.GET_index
                },
            },
            r'^/index.html$': {
                'routes': {
                    'GET': self.GET_index
                },
            },
            r'^/api/v1/ping$': {
                'routes': {
                    'GET': self.GET_ping,
                },
                'whitelist': {
                    'GET': {
                        'name': 'ping',
                        'desc': 'Check to see if the server is alive.'
                    },
                },
                'need_data_key': False,
            },
            r'^/api/v1/jsonrpc$': {
                # JSONRPC endpoint (we handle our own auth)
                'authenticate': False,
                'routes': {
                    'POST': self.JSONRPC_call
                },
                'whitelist': {
                    'POST': {
                        'name': 'JSONRPC',
                        'desc': 'full API access'
                    },
                },
                'need_data_key': False,
            },
            r'^/api/v1/auth/signin/({})/({})$'.format(NAME_CLASS, URLENCODING_CLASS): {
                'authenticate_url': True,
                'authenticate': False,
                'routes': {
                    'GET': self.GET_auth_signin,
                },
            },
            r'^/api/v1/auth/loadaccount/({})/({})/({})$'.format(URLENCODING_CLASS, NAME_CLASS, URLENCODING_CLASS): {
                'authenticate_url': True,
                'authenticate': False,
                'routes': {
                    'GET': self.GET_auth_load_account_and_redirect,
                },
            },
            r'^/api/v1/auth/allowdeny/({})/({})$'.format(NAME_CLASS, URLENCODING_CLASS): {
                'authenticate_url': True,
                'authenticate': False,
                'routes': {
                    'GET': self.GET_auth_allowdeny,
                },
            },
            r'^/api/v1/auth/newaccount/({})/({})/({})$'.format(URLENCODING_CLASS, NAME_CLASS, URLENCODING_CLASS): {
                'authenticate_url': True,
                'authenticate': False,
                'routes': {
                    'GET': self.GET_auth_create_account_and_redirect
                },
            },
            r'^/api/v1/addresses/({})/names$'.format(BASE58CHECK_CLASS): {
                'routes': {
                    'GET': self.GET_names_owned_by_address,
                },
                'whitelist': {
                    'GET': {
                        'name': 'names',
                        'desc': 'get names owned by an address',
                    },
                },
            },
            r'^/api/v1/blockchains/({})/operations/([0-9]+)$'.format(URLENCODING_CLASS): {
                'routes': {
                    'GET': self.GET_blockchain_ops
                },
                'whitelist': {
                    'GET': {
                        'name': 'blockchain',
                        'desc': 'read blockchain name blocks'
                    },
                },
            },
            r'^/api/v1/blockchains/({})/names/({})/history$'.format(URLENCODING_CLASS, NAME_CLASS): {
                'routes': {
                    'GET': self.GET_blockchain_name_history
                },
                'whitelist': {
                    'GET': {
                        'name': 'blockchain',
                        'desc': 'read blockchain name histories',
                    },
                },
            },
            r'^/api/v1/blockchains/({})/consensus$'.format(URLENCODING_CLASS): {
                'routes': {
                    'GET': self.GET_blockchain_consensus,
                },
                'whitelist': {
                    'GET': {
                        'name': 'blockchain',
                        'desc': 'get current consensus hash'
                    },
                },
            },
            r'^/api/v1/blockchains/({})/pending$'.format(URLENCODING_CLASS): {
                'routes': {
                    'GET': self.GET_blockchain_pending,
                },
                'whitelist': {
                    'GET': {
                        'name': 'blockchain',
                        'desc': 'get pending transactions this node has sent'
                    },
                },
            },
            r'^/api/v1/names$': {
                'routes': {
                    'GET': self.GET_names,
                    'POST': self.POST_names,    # accepts: name, address, zonefile.  Returns: HTTP 202 with txid
                },
                'whitelist': {
                    'GET': {
                        'name': 'names',
                        'desc': 'read all names',
                    },
                    'POST': {
                        'name': 'register',
                        'desc': 'register new names',
                    },
                },
            },
            r'^/api/v1/names/({})$'.format(NAME_CLASS): {
                'routes': {
                    'GET': self.GET_name_info,
                    'DELETE': self.DELETE_name,     # revoke
                },
                'whitelist': {
                    'GET': {
                        'name': 'names',
                        'desc': 'read name information',
                    },
                    'DELETE': {
                        'name': 'revoke',
                        'desc': 'revoke names'
                    },
                },
            },
            r'^/api/v1/names/({})/history$'.format(NAME_CLASS): {
                'routes': {
                    'GET': self.GET_name_history,
                },
                'whitelist': {
                    'GET': {
                        'name': 'names',
                        'desc': 'read name history'
                    },
                },
            },
            r'^/api/v1/names/({})/owner$'.format(NAME_CLASS): {
                'routes': {
                    'PATCH': self.PATCH_name_transfer,     # accepts: recipient address.  Returns: HTTP 202 with txid
                },
                'whitelist': {
                    'PATCH': {
                        'name': 'transfer',
                        'desc': 'transfer names to new addresses'
                    },
                },
            },
            r'^/api/v1/names/({})/zonefile$'.format(NAME_CLASS): {
                'routes': {
                    'GET': self.GET_name_zonefile,
                    'PATCH': self.PATCH_name_zonefile,
                },
                'whitelist': {
                    'GET': {
                        'name': 'zonefiles',
                        'desc': 'read name zonefiles',
                    },
                    'PATCH': {
                        'name': 'update',
                        'desc': 'set name zonefiles'
                    },
                },
            },
            r'^/api/v1/names/({})/zonefile/([0-9a-fA-F]{{40}})$'.format(NAME_CLASS): {
                'routes': {
                    'GET': self.GET_name_zonefile_by_hash,     # returns a zonefile
                },
                'whitelist': {
                    'GET': {
                        'name': 'zonefiles',
                        'desc': 'get current and historic name zonefiles'
                    },
                },
            },
            r'^/api/v1/names/({})/zonefile/zonefileHash$'.format(NAME_CLASS): {
                'routes': {
                    'PUT': self.PUT_name_zonefile_hash,     # accepts: zonefile hash.  Returns: HTTP 202 with txid
                },
                'whitelist': {
                    'PUT': {
                        'name': 'update',
                        'desc': 'set name zonefile hashes'
                    },
                },
            },
            r'^/api/v1/namespaces$': {
                'routes': {
                    'GET': self.GET_namespaces, 
                    'POST': self.POST_namespaces,       # accepts: namespace-reveal info.  Returns: HTTP 202 with txid (NAMESPACE_PREORDER)
                },
                'whitelist': {
                    'GET': {
                        'name': 'namespaces',
                        'desc': 'read all namespace IDs',
                    },
                    'POST': {
                        'name': 'namespace_registration',
                        'desc': 'create new namespaces',
                    },
                },
            },
            r'^/api/v1/namespaces/({})$'.format(NAMESPACE_CLASS): {
                'routes': {
                    'GET': self.GET_namespace_info,
                    'PUT': self.PUT_namespace_ready,     # accepts: {'launched': True}, Returns: HTTP 202 with txid (NAMESPACE_READY)
                },
                'whitelist': {
                    'GET': {
                        'name': 'namespaces',
                        'desc': 'read namespace information'
                    },
                    'PUT': {
                        'name': 'namespace_registration',
                        'desc': 'launch namespaces'
                    },
                },
            },
            r'^/api/v1/namespaces/({})/names$'.format(NAMESPACE_CLASS): {
                'routes': {
                    'GET': self.GET_namespace_names,
                    'POST': self.POST_namespace_name_import,    # accepts name, owner, zonefile; returns HTTP 202 with txid (NAME_IMPORT)
                },
                'whitelist': {
                    'GET': {
                        'name': 'namespaces',
                        'desc': 'read all names in a namespace',
                    },
                    'POST': {
                        'name': 'namespace_registration',
                        'desc': 'import names into new namespaces'
                    },
                },
            },
            r'^/api/v1/namespaces/({})/names/({})$'.format(NAMESPACE_CLASS, NAME_CLASS): {
                'routes': {
                    'PUT': self.PUT_namespace_name_import,       # re-imports a name
                },
                'whitelist': {
                    'PUT': {
                        'name': 'namespace_registration',
                        'desc': 're-import names into a new namespace'
                    },
                },
            },
            r'^/api/v1/wallet/payment_address$': {
                'routes': {
                    'GET': self.GET_wallet_payment_address,
                },
                'whitelist': {
                    'GET': {
                        'name': 'wallet_read',
                        'desc': 'get the node wallet\'s payment address',
                    },
                },
            },
            r'^/api/v1/wallet/owner_address$': {
                'routes': {
                    'GET': self.GET_wallet_owner_address,
                },
                'whitelist': {
                    'GET': {
                        'name': 'wallet_read',
                        'desc': 'get the node wallet\'s payment address',
                    },
                },
            },
            r'^/api/v1/wallet/private$': {
                'authenticate': False,
                'routes': {
                    'PUT': self.PUT_wallet,
                },
                'whitelist': {
                    'PUT': {
                        'name': 'wallet_write',
                        'desc': 'Set the wallet\'s private keys'
                    },
                },
                'need_data_key': False
            },
            r'^/api/v1/node/ping$': {
                'authenticate': False,
                'routes': {
                    'GET': self.GET_ping,
                },
                'whitelist': {
                    'GET': {
                        'name': '',
                        'desc': 'ping the node'
                    },
                },
                'need_data_key': False,
            },
            r'^/api/v1/node/reboot$': {
                'authenticate': False,
                'routes': {
                    'POST': self.POST_reboot,
                },
                'whitelist': {
                    'POST': {
                        'name': '',
                        'desc': 'reboot the node'
                    },
                },
                'need_data_key': False,
            },
            r'^/api/v1/prices/namespaces/({})$'.format(NAMESPACE_CLASS): {
                'routes': {
                    'GET': self.GET_prices_namespace,
                },
                'whitelist': {
                    'GET': {
                        'name': 'prices',
                        'desc': 'get the price of a namespace'
                    },
                },
            },
            r'^/api/v1/prices/names/({})$'.format(NAME_CLASS): {
                'routes': {
                    'GET': self.GET_prices_name,
                },
                'whitelist': {
                    'GET': {
                        'name': 'prices',
                        'desc': 'get the price of a name'
                    },
                },
            },
            r'^/api/v1/resources/({})/({})/({})$'.format(NAME_CLASS, URLENCODING_CLASS, URLENCODING_CLASS): {
                'routes': {
                    'GET': self.GET_app_resource,
                },
                'whitelist': {
                    'GET': {
                        'name': 'resources',
                        'desc': 'load resources on-the-fly'
                    },
                },
            },
            r'^/api/v1/users$': {
                'routes': {
                    'GET': self.GET_users,
                    'POST': self.POST_users,
                },
                'whitelist': {
                    'GET': {
                        'name': 'user_admin',
                        'desc': 'list all users',
                    },
                    'POST': {
                        'name': 'user_admin',
                        'desc': 'create new users',
                    },
                    'DELETE': {
                        'name': 'user_admin',
                        'desc': 'delete users',
                    },
                },
            },
            r'^/api/v1/users/({})$'.format(URLENCODING_CLASS): {
                'routes': {
                    'GET': self.GET_user_profile,
                    'PATCH': self.PATCH_user_profile,
                    'DELETE': self.DELETE_user,
                },
                'whitelist': {
                    'GET': {
                        'name': 'user_read',
                        'desc': 'read user profile',
                    },
                    'PATCH': {
                        'name': 'user_write',
                        'desc': 'update user profile'
                    },
                    'DELETE': {
                        'name': 'user_admin',
                        'desc': 'delete user profile'
                    },
                },
            },
            r'^/api/v1/users/({})/collections$'.format(URLENCODING_CLASS): {
                'routes': {
                    'GET': self.GET_user_collections,
                    'POST': self.POST_user_collections,
                },
                'whitelist': {
                    'GET': {
                        'name': 'collections',
                        'desc': 'list a user\'s collections',
                    },
                    'POST': {
                        'name': 'collections_admin',
                        'desc': 'create new collections',
                    },
                },
            },
            r'^/api/v1/users/({})/collections/({})$'.format(URLENCODING_CLASS, URLENCODING_CLASS): {
                'routes': {
                    'GET': self.GET_user_collection_info,
                    'POST': self.POST_user_collection_item,
                },
                'whitelist': {
                    'GET': {
                        'name': 'collections',
                        'desc': 'list items in a collection',
                    },
                    'POST': {
                        'name': 'collections_write',
                        'desc': 'add items to a collection',
                    },
                },
            },
            r'^/api/v1/users/({})/collections/({})/({})$'.format(URLENCODING_CLASS, URLENCODING_CLASS, URLENCODING_CLASS): {
                'routes': {
                    'GET': self.GET_user_collection_item,
                },
                'whitelist': {
                    'GET': {
                        'name': 'collections',
                        'desc': 'read collection items',
                    },
                },
            },
            r'^/api/v1/users/({})/stores$'.format(URLENCODING_CLASS): {
                'routes': {
                    'GET': self.GET_user_stores,
                    'POST': self.POST_user_stores,
                },
                'whitelist': {
                    'GET': {
                        'name': 'store_admin',
                        'desc': 'list a user\'s data stores'
                    },
                    'POST': {
                        'name': 'store_admin',
                        'desc': 'create a new data store'
                    },
                },
            },
            r'^/api/v1/users/({})/stores/({})$'.format(URLENCODING_CLASS, URLENCODING_CLASS): {
                'routes': {
                    'PUT': self.PUT_user_stores,
                    'DELETE': self.DELETE_user_stores,
                },
                'whitelist': {
                    'PUT': {
                        'name': 'store_admin',
                        'desc': 'update a user data store',
                    },
                    'DELETE': {
                        'name': 'store_admin',
                        'desc': 'delete a user data store',
                    },
                },
            },
            r'^/api/v1/users/({})/stores/({})/(file|directory|inode)$'.format(URLENCODING_CLASS, URLENCODING_CLASS, URLENCODING_CLASS): {
                'routes': {
                    'GET': self.GET_user_store_item,
                    'POST': self.POST_user_store_item,
                    'PUT': self.PUT_user_store_item,
                    'DELETE': self.DELETE_user_store_item,
                },
                'whitelist': {
                    'GET': {
                        'name': 'store_read',
                        'desc': 'read files and list directories in a data store'
                    },
                    'POST': {
                        'name': 'store_write',
                        'desc': 'create files and make directories in a data store'
                    },
                    'PUT': {
                        'name': 'store_write',
                        'desc': 'write files and directories to a data store',
                    },
                    'DELETE': {
                        'name': 'store_write',
                        'desc': 'delete files and directories in a data store',
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
        need_data_key = route_info['need_data_key']
        session = None

        # sanity check: this API only works if we have a data key 
        if self.server.master_data_privkey is None and need_data_key:
            log.debug("No master data private key set")
            self._send_headers(status_code=503, content_type='text/plain')
            return 

        log.debug("\nfull path: {}\nmethod: {}\npath: {}\nqs: {}\nheaders:\n {}\n".format(self.path, method_name, path_info['path'], qs_values, '\n'.join( '{}: {}'.format(k, v) for (k, v) in self.headers.items() )))

        if route.get('authenticate_url'):
            # authenticate URL first 
            res = self.verify_url()
            if not res:
                self._send_headers(status_code=400, content_type='text/plain')
                return 

        if not self.server.authenticate:
            # server has disabled authentication
            # make a new session.
            log.warning("Authentication disabled; making a new session automatically")

            # require appname=, name=, user_id=
            appname = qs_values.get('appname', None)
            app_fqu = qs_values.get('app_fqu', None)
            user_id = qs_values.get('user_id', None)
            
            if appname is None:
                appname = 'unknown'

            if app_fqu is None:
                app_fqu = 'unknown'

            if user_id is None:
                user_id = 'unknown'

            fake_account = app.app_make_account_info( app_fqu, appname, [], user_id, self.server.master_data_pubkey, -1, 3600*24*7 )
            session = app.app_make_session( fake_account, self.server.master_data_privkey, config_path=self.server.config_path )
            if 'error' in session:
                log.error("Failed to make session for {}/{}".format(app_fqu, appname))
                return self._send_headers(status_code=500, content_type='text/plain')

        elif not route.has_key('authenticate') or route['authenticate']:
            # session token required 
            session = self.verify_session(qs_values)
            if session is None:
                # caller is not authenticated.
                # begin authentication
                log.debug("Unauthenticated method call to {}".format(path_info['path']))
                return self.app_auth_begin(qs_values)
            
            appname = session['appname']
            app_fqu = session['name']

            # must match requested application and application name 
            app_info = self.get_app_info(qs_values)
            if 'error' in app_info:
                log.debug("Could not determine application")
                return self._send_headers(status_code=401, content_type='text/plain')

            if app_info['appname'] != appname or app_info['app_fqu'] != app_fqu:
                log.debug("Session for {}/{} does not match requested {}/{}".format(appname, app_fqu, app_info['appname'], app_info['app_fqu']))
                return self._send_headers(status_code=403, content_type='text/plain')
            
            # is this method allowed?
            if whitelist_info is not None:
                allowed_methods = session['methods']
                if whitelist_info['name'] not in allowed_methods:
                    # this method is not allowed
                    log.info("Unauthorized method call to {} from {}/{}".format(path_info['path'], app_fqu, appname))
                    return self._send_headers(status_code=403, content_type='text/plain')

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

    def do_PATCH(self):
        """
        TOp-level PATCH dispatch
        """
        return self._dispatch("PATCH")


class BlockstackAPIEndpoint(SocketServer.TCPServer):
    """
    Lightweight API endpoint to Blockstack server:
    exposes all of the client methods via an XMLRPC interface,
    so other local programs (e.g. those that can't use the library)
    can access the Blockstack client functionality.
    """

    RPC_SERVER_INST = None

    @classmethod
    def is_method(cls, method):
        return bool(callable(method) or getattr(method, '__call__', None))


    def register_function(self, func_rpc, func_internal, name=None):
        """
        Register a function with the RPC server,
        and also with the internal RPC container.
        Optionall don't register on the server.
        """
        name = func.__name__ if name is None else name
        assert name

        setattr(self.internal_proxy, name, func_internal)
        self.funcs[name] = func_rpc

    
    def get_internal_proxy(self):
        return self.internal_proxy


    def get_plugin_methods(self, plugin):
        """
        Get the set of methods in a module.
        The module must have a RPC_METHODS attribute, which in turn must be
        an array of callables to register.
        """

        methods = getattr(plugin, 'RPC_METHODS', [])

        # there is a madness to these methods!
        if methods:
            return [method for method in methods if self.is_method(method)]

        # assume all methods that don't start with '__'
        for attr in dir(plugin):
            method = getattr(plugin, attr, None)
            if self.is_method(method):
                methods.append(method)

        return methods


    def get_or_import_plugin_module(self, plugin_or_plugin_name):
        """
        Get a module.  The plugin_or_plugin_name argument can either
        be a module (in which case it is simply returned), or a string 
        that can be imported as a module.

        Returns a module on success
        Returns None on error
        """
        if isinstance(plugin_or_plugin_name, ModuleType):
            return plugin_or_plugin_name

        try:
            return __import__(plugin_or_plugin_name)
        except ImportError as e:
            msg = 'Skipping plugin "{}", since it cannot be imported'
            log.error(msg.format(plugin_or_plugin_name))

        return None


    def register_plugin_methods(self, config_path, plugins):
        """
        Given the config path and a list of either modules or module strings,
        load all of the modules' methods.

        Each module must have an RPC_METHODS member and an RPC_PREFIX member.
        The RPC_METHODS member must be an array of functions.
        The RPC_PREFIX member must be a string; it will be used to namespace the methods.

        The module may optionally have an RPC_INIT and RPC_SHUTDOWN member, which
        must be callables that instantiate the plugin or destroy it.
        """

        for plugin_or_plugin_name in plugins:
            mod_plugin = self.get_or_import_plugin_module(plugin_or_plugin_name)
            if mod_plugin is None:
                continue

            plugin_prefix = getattr(mod_plugin, 'RPC_PREFIX', mod_plugin.__name__)
            if plugin_prefix in self.plugin_prefixes:
                log.error('Skipping conflicting plugin "{}"'.format(mod_plugin))
                continue

            plugin_init = getattr(mod_plugin, 'RPC_INIT', lambda: True)
            plugin_shutdown = getattr(mod_plugin, 'RPC_SHUTDOWN', lambda: True)

            methods = self.get_plugin_methods(mod_plugin)

            for method in methods:
                msg = 'Register plugin method "{}_{}"'
                log.debug(msg.format(plugin_prefix, method.__name__))

                name = '{}_{}'.format(plugin_prefix, method.__name__)
                self.register_function(method, method, name=name)

            # keep state around
            self.plugin_prefixes.append(plugin_prefix)
            self.plugin_mods.append(mod_plugin)
            self.plugin_destructors.append(plugin_shutdown)

            # initialize plugin
            plugin_init(config_path=config_path)


    def register_api_functions(self, config_path, plugins):
        """
        Register all API functions.
        Do so for both the internal API proxy (for server-callers)
        and for the exteranl API (for RPC callers).
        """

        # pinger
        self.register_function(ping, ping, name='ping')

        # register the command-line methods (will all start with cli_)
        # methods will be named after their *action*
        for command_name, method_info in list_rpc_cli_method_info().items():
            method_name = 'cli_{}'.format(method_info['command'])
            method = method_info['method']

            msg = 'Register CLI method "{}" as "{}"'
            log.debug(msg.format(method.__name__, method_name))

            self.register_function(
                local_rpc_factory(method_info, config_path, check_rpc=True),
                local_rpc_factory(method_info, config_path, check_rpc=False, include_kw=True),
                name=method_name,
            )

        self.register_plugin_methods(config_path, plugins)

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


    def __init__(self, wallet_keys, host='localhost', rpc_token=None, port=blockstack_config.DEFAULT_API_PORT,
                 plugins=None, handler=BlockstackAPIEndpointHandler, 
                 config_path=CONFIG_PATH, server=True):

        """
        wallet_keys is only needed if server=True
        """

        plugins = [] if plugins is None else plugins

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
        self.app_configs = {}   # cached app config state
        self.rpc_token = rpc_token
        self.authenticate = True

        conf = blockstack_config.get_config(path=config_path)

        if self.rpc_token is None:
            self.rpc_token = conf.get('rpc_token', None)
            if self.rpc_token is None:
                log.warning("Failed to load RPC token from {}".format(config_path))

        if not conf.get('authenticate_api', True):
            log.warn("Will NOT authenticate API calls with session tokens")
            self.authenticate = False

        if wallet_keys is not None:
            assert wallet_keys.has_key('data_privkey')

            self.master_data_privkey = ECPrivateKey(wallet_keys['data_privkey']).to_hex()
            self.master_data_pubkey = ECPrivateKey(self.master_data_privkey).public_key().to_hex()

            if keylib.key_formatting.get_pubkey_format(self.master_data_pubkey) == 'hex_compressed':
                self.master_data_pubkey = keylib.key_formatting.decompress(self.master_data_pubkey)

        self.register_api_functions(config_path, plugins)


    def shutdown_plugins(self):
        """
        Shut down each plugin
        """
        log.debug('RPC plugin shutdown')

        for pd in self.plugin_destructors:
            pd(config_path=self.config_path)

        self.plugin_destructors = []


class BlockstackAPIEndpointClient(object):
    """
    JSONRPC client for blockstack's local RPC endpoint
    """
    def __init__(self, server, port, max_rpc_len=1024*1024, rpc_token=None,
                 timeout=blockstack_config.DEFAULT_TIMEOUT, debug_timeline=False, **kw):

        self.url = 'http://{}:{}/api/v1/jsonrpc'.format(server, port)
        self.timeout = timeout
        self.server = server
        self.port = port
        self.debug_timeline = debug_timeline
        self.max_rpc_len = max_rpc_len
        self.rpc_token = rpc_token


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
                """
                JSON-RPC call wrapper
                """
                assert len(args) == 0 or len(kw) == 0, "Cannot support both positional and keyword arguments"

                jsonrpc_request = {
                    'id': str(uuid.uuid4()),
                    'jsonrpc': '2.0',
                    'method': key
                }

                if self.rpc_token is not None:
                    jsonrpc_request['blockstack_rpc_token'] = self.rpc_token

                if len(args) > 0:
                    jsonrpc_request['params'] = args

                if len(kw) > 0:
                    jsonrpc_request['params'] = kw

                req = requests.post(self.url, timeout=self.timeout, data=json.dumps(jsonrpc_request), headers={'content-type': 'application/json'}, stream=True)
                if req.status_code != 200:
                    raise RPCException("Request '{}' status {}".format(key, req.status_code))

                raw_data = req.raw.read( self.max_rpc_len + 1, decode_content=True )
                if len(raw_data) > self.max_rpc_len:
                    # too big 
                    raise RPCException("Request '{}' replied too much data".format(key))

                resp = json.loads(raw_data)
                jsonschema.validate(resp, JSONRPC_RESPONSE_SCHEMA)
                assert 'error' in resp or 'result' in resp
            
                self.log_debug_timeline('end', key, r)

                if 'error' in resp:
                    raise RPCException(resp['error'])

                return resp['result']

            return inner
        

def get_default_plugins():
    return [backend]


def make_local_rpc_server(portnum, wallet_keys, config_path=blockstack_config.CONFIG_PATH, plugins=None):
    """
    Make a local RPC server instance.
    It will be derived from BaseHTTPServer.HTTPServer.
    @plugins can be a list of modules, or a list of strings that
    identify module names to import.

    Returns the global server instance on success.
    """
    plugins = [] if plugins is None else plugins
    plugins = get_default_plugins() + plugins
    srv = BlockstackAPIEndpoint(wallet_keys, port=portnum, config_path=config_path, plugins=plugins)

    return srv


def is_rpc_server(config_dir=blockstack_config.CONFIG_DIR):
    """
    Is this process running an RPC server?
    Return True if so
    Return False if not
    """
    rpc_pidpath = local_rpc_pidfile_path(config_dir=config_dir)
    if not os.path.exists(rpc_pidpath):
        return False

    rpc_pid = local_rpc_read_pidfile(rpc_pidpath)
    if rpc_pid != os.getpid():
        return False

    return True


def local_rpc_server_run(srv):
    """
    Start running the RPC server, but in a separate thread.
    """
    global running

    srv.timeout = 0.5
    while running:
        srv.handle_request()


def local_rpc_server_stop(srv):
    """
    Stop a running RPC server
    """
    log.debug("Server shutdown")
    srv.shutdown_plugins()
    srv.socket.close()


def local_rpc_connect(config_dir=blockstack_config.CONFIG_DIR, api_port=None):
    """
    Connect to a locally-running RPC server.
    Return a server proxy object on success.
    Raise on error.

    The RPC server can safely connect to itself using this method,
    since instead of opening a socket and doing the conventional RPC,
    it will instead use the proxy object to call the request method
    directly.
    """

    config_path = os.path.join(config_dir, blockstack_config.CONFIG_FILENAME)

    if is_rpc_server(config_dir=config_dir):
        # this process is an RPC server.
        # route the method directly.
        log.debug("Caller is the RPC server. Short-circuiting.")
        return get_rpc_internal_methods()

    conf = blockstack_config.get_config(config_path)
    if conf is None:
        raise Exception('Failed to read conf at "{}"'.format(config_path))

    api_port = conf['api_endpoint_port'] if api_port is None else api_port
    rpc_token = conf['rpc_token']

    connect_msg = 'Connect to RPC at localhost:{}'
    log.debug(connect_msg.format(api_port))
    return BlockstackAPIEndpointClient('localhost', api_port, timeout=3000, config_path=config_path, rpc_token=rpc_token)


def local_rpc_action(command, config_dir=blockstack_config.CONFIG_DIR):
    """
    Handle an API endpoint command:
    * start: start up an API endpoint
    * stop: stop a running API endpoint
    * status: see if there's an API endpoint running.
    * restart: stop and start the API endpoint

    Return the exit status
    """

    if command not in ['start', 'start-foreground', 'stop', 'status', 'restart']:
        raise ValueError('Invalid command "{}"'.format(command))

    config_path = os.path.join(config_dir, blockstack_config.CONFIG_FILENAME)

    conf = blockstack_config.get_config(config_path)
    if conf is None:
        raise Exception('Failed to read conf at "{}"'.format(config_path))

    api_port = conf['api_endpoint_port']

    cmdline_fmt = '{} -m blockstack_client.rpc_runner {} {} {}'
    cmdline = cmdline_fmt.format(sys.executable, command, api_port, config_dir)
    
    rc = os.system(cmdline)

    return 0 if rc is None else os.WEXITSTATUS(rc)


def local_rpc_dispatch(port, method_name, *args, **kw):
    """
    Connect to the running endpoint, issue the command,
    and return the result.
    """
    config_dir = kw.pop('config_dir', blockstack_config.CONFIG_DIR)

    client = local_rpc_connect(config_dir=config_dir, api_port=port)
    try:
        method = getattr(client, method_name)
        result = method(*args, **kw)
        if isinstance(result, (str, unicode)):
            result = json.loads(result)

        return result
    except:
        return {'error': traceback.format_exc()}


def local_rpc_pidfile_path(config_dir=blockstack_config.CONFIG_DIR):
    """
    Where do we put the PID file?
    """
    return os.path.join(config_dir, 'api_endpoint.pid')


def local_rpc_logfile_path(config_dir=blockstack_config.CONFIG_DIR):
    """
    Where do we put logs?
    """
    return os.path.join(config_dir, 'api_endpoint.log')


def local_rpc_read_pidfile(pidfile_path):
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


def local_rpc_write_pidfile(pidfile_path):
    """
    Write a PID file
    """
    with open(pidfile_path, 'w') as f:
        f.write(str(os.getpid()))
        f.flush()
        os.fsync(f.fileno())

    return


def local_rpc_unlink_pidfile(pidfile_path):
    """
    Remove a PID file
    """
    try:
        os.unlink(pidfile_path)
    except:
        pass


def local_rpc_atexit():
    """
    atexit: clean out PID file
    """
    global rpc_pidpath, rpc_srv
    local_rpc_unlink_pidfile(rpc_pidpath)
    if rpc_srv is not None:
        local_rpc_server_stop(rpc_srv)
        rpc_srv = None


def local_rpc_exit_handler(sig, frame):
    """
    Fatal signal handler
    """
    local_rpc_atexit()
    log.debug('Local RPC exit')
    sys.exit(0)


# used when running in a separate process
rpc_pidpath = None
rpc_srv = None


def local_rpc_start(portnum, config_dir=blockstack_config.CONFIG_DIR, foreground=False, password=None):
    """
    Start up an API endpoint
    Return True on success
    Return False on error
    """

    import blockstack_client
    from blockstack_client.wallet import load_wallet

    global rpc_pidpath, rpc_srv, running
    config_path = os.path.join(config_dir, blockstack_config.CONFIG_FILENAME)
    wallet_path = os.path.join(config_dir, blockstack_config.WALLET_FILENAME)

    # already running?
    rpc_pidpath = local_rpc_pidfile_path(config_dir=config_dir)
    if os.path.exists(rpc_pidpath):
        pid = local_rpc_read_pidfile(rpc_pidpath)
        print("API endpoint already running (PID {}, {})".format(pid, rpc_pidpath), file=sys.stderr)
        return False

    if not os.path.exists(wallet_path):
        print("No wallet found at {}".format(wallet_path), file=sys.stderr)
        return False
    
    signal.signal(signal.SIGINT, local_rpc_exit_handler)
    signal.signal(signal.SIGQUIT, local_rpc_exit_handler)
    signal.signal(signal.SIGTERM, local_rpc_exit_handler)

    atexit.register(local_rpc_atexit)
        
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

        logpath = local_rpc_logfile_path(config_dir=config_dir)
        logfile = open(logpath, 'a+')
        child_pid = os.fork()

        if child_pid == 0:
            # child!
            sys.stdin.close()
            os.dup2(logfile.fileno(), sys.stdout.fileno())
            os.dup2(logfile.fileno(), sys.stderr.fileno())
            os.setsid()

            daemon_pid = os.fork()
            if daemon_pid == 0:
                # daemon!
                os.chdir('/')

            elif daemon_pid > 0:
                # parent (intermediate child)
                sys.exit(0)

            else:
                # error
                sys.exit(1)

        elif child_pid > 0:
            # grand-parent
            # wait for intermediate child
            pid, status = os.waitpid(child_pid, 0)
            sys.exit(status)

    # load up internal RPC methods
    log.debug('Loading RPC methods')
    load_rpc_cli_method_info(blockstack_client)
    load_rpc_internal_methods(config_path)
    log.debug('Finished loading RPC methods')

    # make server
    try:
        rpc_srv = make_local_rpc_server(portnum, wallet, config_path=config_path)
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

    log.debug("Setting wallet...")

    # NOTE: test that wallets without data keys still work
    assert wallet.has_key('owner_addresses')
    assert wallet.has_key('owner_privkey')
    assert wallet.has_key('payment_addresses')
    assert wallet.has_key('payment_privkey')
    assert wallet.has_key('data_pubkeys')
    assert wallet.has_key('data_privkey')

    res = backend.set_wallet(
        (wallet['payment_addresses'][0], wallet['payment_privkey']),
        (wallet['owner_addresses'][0], wallet['owner_privkey']),
        (wallet['data_pubkeys'][0], wallet['data_privkey']),
        config_path=config_path
    )
    if 'error' in res:
        log.error("Failed to set wallet: {}".format(res['error']))
        return False

    log.debug("Set wallet")

    running = True
    local_rpc_write_pidfile(rpc_pidpath)
    local_rpc_server_run(rpc_srv)

    local_rpc_unlink_pidfile(rpc_pidpath)
    local_rpc_server_stop(rpc_srv)

    return True


def rpc_kill(pidpath, pid, sig, unlink_pidfile=True):
    """
    Utility function to send signals
    Return True if signal actions were successful
    Return False if signal actions were unsuccessful
    """
    try:
        os.kill(pid, sig)
        if sig == signal.SIGKILL:
            local_rpc_unlink_pidfile(pidpath)
        
        return True
    except OSError as oe:
        if oe.errno == errno.ESRCH:
            log.debug('Not running: {} ({})'.format(pid, pidpath))
            if unlink_pidfile:
                local_rpc_unlink_pidfile(pidpath)
            return False
        elif oe.errno == errno.EPERM:
            log.debug('Not our RPC daemon: {} ({})'.format(pid, pidpath))
            return False
        else:
            raise


def local_rpc_stop(config_dir=blockstack_config.CONFIG_DIR):
    """
    Shut down an API endpoint
    Return True if we stopped it
    Return False if it wasn't running, or we couldn't stop it
    """
    # already running?
    pidpath = local_rpc_pidfile_path(config_dir=config_dir)
    if not os.path.exists(pidpath):
        print('Not running ({})'.format(pidpath), file=sys.stderr)
        return False

    pid = local_rpc_read_pidfile(pidpath)
    if pid is None:
        print('Failed to read "{}"'.format(pidpath), file=sys.stderr)
        return False

    if not rpc_kill(pidpath, pid, 0):
        return False

    # still running. try to terminate
    print('Sending SIGTERM to {}'.format(pid), file=sys.stderr)

    if not rpc_kill(pidpath, pid, signal.SIGTERM):
        return False

    time.sleep(1)

    for i in xrange(0, 5):
        # still running?
        if not rpc_kill(pidpath, pid, 0):
            # dead
            return False

        time.sleep(1)

    # still running
    print('Sending SIGKILL to {}'.format(pid), file=sys.stderr)

    # sigkill ensure process will die
    return rpc_kill(pidpath, pid, signal.SIGKILL)


def local_rpc_status(config_dir=blockstack_config.CONFIG_DIR):
    """
    Print the status of an instantiated API endpoint
    Return True if the daemon is running.
    Return False if not, or if unknown.
    """
    # see if it's running
    pidpath = local_rpc_pidfile_path(config_dir=config_dir)
    if not os.path.exists(pidpath):
        log.debug('No PID file {}'.format(pidpath))
        return False

    pid = local_rpc_read_pidfile(pidpath)
    if pid is None:
        log.debug('Invalid PID file {}'.format(pidpath))
        return False

    if not rpc_kill(pidpath, pid, 0, unlink_pidfile=False):
        return False

    log.debug('RPC running ({})'.format(pidpath))

    return True


def local_rpc_ensure_running(config_dir=blockstack_config.CONFIG_DIR, password=None):
    """
    Ensure that the RPC daemon is running.
    Start it if it is not.
    Return True on success
    Return False on failure
    """
    # if we're the RPC server, then we're running 
    if is_rpc_server(config_dir=config_dir):
        return True

    rc = local_rpc_status(config_dir)
    if rc:
        log.debug('RPC endpoint already running ({})'.format(config_dir))
        return True

    log.debug('Starting RPC endpoint ({})'.format(config_dir))

    if password is not None and os.environ.get('BLOCKSTACK_CLIENT_WALLET_PASSWORD', None) is None:
        # pass password to local rpc daemon
        os.environ['BLOCKSTACK_CLIENT_WALLET_PASSWORD'] = password

    rc = local_rpc_action('start', config_dir=config_dir)

    # we do not need the password anymore. so remove it from the environment
    os.environ.pop('BLOCKSTACK_CLIENT_WALLET_PASSWORD', None)

    if rc != 0:
        log.error('Failed to start RPC endpoint; exit code was {}'.format(rc))
        return False

    # ping it
    running = False
    for i in range(1, 4):
        try:
            local_proxy = local_rpc_connect(config_dir=config_dir)
            local_proxy.ping()
            running = True
            break
        except requests.ConnectionError as ie:
            log.debug('API server is not responding; trying again in {} seconds'.format(i))
            time.sleep(i)
            continue

        except (IOError, OSError) as ie:
            if ie.errno == errno.ECONNREFUSED:
                msg = 'API server not responding; trying again in {} seconds'
                log.debug(msg.format(i))
                time.sleep(i)
                continue
            else:
                raise

    return running


def start_rpc_endpoint(config_dir=blockstack_config.CONFIG_DIR, password=None):
    """
    Ensure that the RPC endpoint is running.
    Used in interactive mode due to its better error messages.
    Raise on error
    """

    rc = local_rpc_ensure_running(config_dir, password=password)
    if not rc:
        msg = (
            'Failed to start RPC endpoint (in working directory {}).\n'
            'Please check your password, and verify that the working '
            'directory exists and is writeable.'
        )

        return {'error': msg.format(config_dir)}

    return {'status': True}
