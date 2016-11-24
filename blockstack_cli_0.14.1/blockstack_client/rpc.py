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
import jsonschema
from schemas import *

from types import ModuleType

import signal
import json
import config as blockstack_config
import backend
import proxy

from config import BLOCKSTACK_DEBUG
from method_parser import parse_methods

log = blockstack_config.get_logger()

running = False

RPC_INTERNAL_METHODS = os.environ.get('BLOCKSTACK_RPC_INITIALIZED_METHODS', None)
RPC_CLI_METHOD_INFO = os.environ.get('BLOCKSTACK_RPC_INITIALIZED_INFO', None)


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
    basic_methods = blockstack_client_mod.get_cli_basic_methods()
    basic_method_info = parse_methods(basic_methods)

    advanced_methods = blockstack_client_mod.get_cli_advanced_methods()
    advanced_method_info = parse_methods(advanced_methods)

    all_methods = basic_method_info + advanced_method_info

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
        config_path=config_path, plugins=get_default_plugins(), server=False
    )

    RPC_INTERNAL_METHODS = srv_internal.internal_proxy

    os.environ['BLOCKSTACK_RPC_INITIALIZED_METHODS'] = '1'

    return RPC_INTERNAL_METHODS


def get_rpc_internal_methods():
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


def run_cli_rpc(command_name, argv, config_path=blockstack_config.CONFIG_PATH):
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

    if num_argv > num_args + num_opts:
        msg = 'Invalid number of arguments (need at most {}, got {})'
        return {'error': msg.format(num_args + num_opts, num_argv)}

    if num_argv < num_args:
        msg = 'Invalid number of arguments (need at least {})'
        return {'error': msg.format(num_args)}

    if 'norpc' in command_info['pragmas']:
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

    res = command_info['method'](args, config_path=config_path)

    return res


# need to wrap CLI methods to capture arguments
def local_rpc_factory(method_info, config_path):
    """
    Factory for producing methods that call the right
    version of run_cli_rpc
    """
    def argwrapper(*args, **kw):
        result = run_cli_rpc(method_info['command'], list(args), config_path=config_path)
        return result

    argwrapper.__doc__ = method_info['method'].__doc__
    argwrapper.__name__ = method_info['method'].__name__
    return argwrapper


# ping method
def ping():
    return True


class BlockstackAPIEndpointHandler(SimpleHTTPRequestHandler):
    '''
    Handle one JSON RPC request
    '''

    JSONRPC_PARSE_ERROR = -32700
    JSONRPC_INVALID_REQUEST = -32600
    JSONRPC_METHOD_NOT_FOUND = -32601
    JSONRPC_INVALID_PARAMS = -32602
    JSONRPC_INTERNAL_ERROR = -32603

    JSONRPC_MAX_SIZE = 1024 * 1024      # 1 MB

    def _send_headers(self, status_code=200):
        """
        Generate and reply headers
        """
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
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

    
    def JSONRPC_call(self):
        """
        Handle one JSON-RPC request
        """

        # JSON post?
        request_type = self.headers.get('content-type', None)
        client_address_str = "{}:{}".format(self.client_address[0], self.client_address[1])

        if request_type != 'application/json':
            log.error("Invalid request of type {} from {}".format(request_type, client_address_str))
            self._reply_error( None, self.JSONRPC_PARSE_ERROR, "Parse error" )
            return

        # check length
        read_len = self.headers.get('content-length', None)
        if read_len is None:
            log.error("No content-length given from {}".format(client_address_str))
            self._reply_error( None, self.JSONRPC_PARSE_ERROR, "Parse error" )
            return 

        try:
            read_len = int(read_len)
        except:
            log.error("Invalid content-length")
            self._reply_error( None, self.JSONRPC_PARSE_ERROR, "Parse error" )
            return 

        if read_len >= self.JSONRPC_MAX_SIZE:
            log.error("Request from {} is too long ({} >= {})".format(client_address_str, read_len, self.JSONRPC_MAX_SIZE))
            self._reply_error( None, self.JSONRPC_PARSE_ERROR, "Parse error" )
            return 

        # get the payload
        request_str = self.rfile.read(read_len)

        # parse the payload
        request = None
        try:
            request = json.loads( request_str )
            jsonschema.validate( request, JSONRPC_REQUEST_SCHEMA )
        
        except (TypeError, ValueError, ValidationError) as ve:
            if BLOCKSTACK_DEBUG:
                log.exception(ve)
            self._reply_error( None, self.JSONRPC_PARSE_ERROR, 'Parse error')
            return

        # look up
        rpc_id = request['id']
        method_name = request['method']
        method_params = request.get('params', [])
        if method_name not in self.server.funcs:
            self._reply_error( rpc_id, self.JSONRPC_METHOD_NOT_FOUND, 'No such method')
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


    def do_POST(self):
        """
        Top-level POST dispatch
        """
        path = posixpath.normpath(urllib.unquote(self.path))
        if path == '/API':
            return self.JSONRPC_call()

        else:
            self.send_response(404)
            self.end_headers()
            return


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


    def register_function(self, func, name=None):
        """
        Register a function with the RPC server,
        and also with the internal RPC container.
        Optionall don't register on the server.
        """
        name = func.__name__ if name is None else name
        assert name

        setattr(self.internal_proxy, name, func)
        self.funcs[name] = func


    @classmethod
    def get_internal_proxy(cls):
        """
        Get the internal object that contains pointers to all our register =ed methods
        """
        return cls.RPC_SERVER_INST.internal_proxy


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
                self.register_function(method, name=name)

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
        self.register_function(ping, name='ping')

        # register the command-line methods (will all start with cli_)
        # methods will be named after their *action*
        for command_name, method_info in list_rpc_cli_method_info().items():
            method_name = 'cli_{}'.format(method_info['command'])
            method = method_info['method']

            # only include rpc-pragma'ed methods
            if 'rpc' not in method_info['pragmas']:
                msg = 'Skipping "norpc" method "{}"'
                log.debug(msg.format(method.__name__))
                continue

            msg = 'Register CLI method "{}" as "{}"'
            log.debug(msg.format(method.__name__, method_name))

            self.register_function(
                local_rpc_factory(method_info, config_path),
                name=method_name,
            )

        self.register_plugin_methods(config_path, plugins)

        return True


    def __init__(self, host='localhost', port=blockstack_config.DEFAULT_API_PORT,
                 plugins=None, handler=BlockstackAPIEndpointHandler,
                 config_path=blockstack_config.CONFIG_PATH, server=True):

        plugins = [] if plugins is None else plugins

        if server:
            SocketServer.TCPServer.__init__(self, (host, port), handler)
            self.socket.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )

        # instantiate
        self.plugin_mods = []
        self.plugin_destructors = []
        self.plugin_prefixes = []
        self.config_path = config_path
        self.internal_proxy = RPCInternalProxy()
        self.funcs = {}

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
    def __init__(self, server, port, max_rpc_len=1024*1024,
                 timeout=blockstack_config.DEFAULT_TIMEOUT, debug_timeline=False, **kw):

        self.url = 'http://{}:{}/API'.format(server, port)
        self.timeout = timeout
        self.server = server
        self.port = port
        self.debug_timeline = debug_timeline
        self.max_rpc_len = max_rpc_len


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

                if len(args) > 0:
                    jsonrpc_request['params'] = args

                if len(kw) > 0:
                    jsonrpc_request['params'] = kw

                req = requests.post(self.url, timeout=self.timeout, data=json.dumps(jsonrpc_request), headers={'content-type': 'application/json'}, stream=True)
                if req.status_code != 200:
                    raise RPCException("Request '{}' status {}".foramt(key, req.status_code))

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


def make_local_rpc_server(portnum, config_path=blockstack_config.CONFIG_PATH, plugins=None):
    """
    Make a local RPC server instance.
    It will be derived from BaseHTTPServer.HTTPServer.
    @plugins can be a list of modules, or a list of strings that
    identify module names to import.

    Returns the global server instance on success.
    """
    plugins = [] if plugins is None else plugins
    plugins = get_default_plugins() + plugins
    srv = BlockstackAPIEndpoint(port=portnum, config_path=config_path, plugins=plugins)

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
    srv.shutdown_plugins()


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
        return get_rpc_internal_methods()

    connect_msg = 'Connect to RPC at localhost:{}'
    if api_port is not None:
        log.debug(connect_msg.format(api_port))
        return BlockstackAPIEndpointClient('localhost', api_port, timeout=3000)

    conf = blockstack_config.get_config(config_path)
    if conf is None:
        raise Exception('Failed to read conf at "{}"'.format(config_path))

    api_port = conf['api_endpoint_port']

    log.debug(connect_msg.format(api_port))
    return BlockstackAPIEndpointClient('localhost', api_port, timeout=3000)


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
        msg = 'API endpoint already running (PID {}, {})'
        msg = msg.format(local_rpc_read_pidfile(rpc_pidpath), rpc_pidpath)
        print(msg, file=sys.stderr)
        return False

    signal.signal(signal.SIGINT, local_rpc_exit_handler)
    signal.signal(signal.SIGQUIT, local_rpc_exit_handler)
    signal.signal(signal.SIGTERM, local_rpc_exit_handler)

    atexit.register(local_rpc_atexit)

    wallet = load_wallet(
        password=password, config_dir=config_dir,
        include_private=True, wallet_path=wallet_path
    )

    if 'error' in wallet:
        log.error('Failed to load wallet: {}'.format(wallet['error']))
        print('Failed to load wallet: {}'.format(wallet['error']), file=sys.stderr)
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
        rpc_srv = make_local_rpc_server(portnum, config_path=config_path)
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

    backend.set_wallet(
        (wallet['payment_addresses'][0], wallet['payment_privkey']),
        (wallet['owner_addresses'][0], wallet['owner_privkey']),
        (wallet['data_pubkeys'][0], wallet['data_privkey']),
        config_path=config_path
    )

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
                print('Removing stale PID file "{}"'.format(pidpath), file=sys.stderr)
                local_rpc_unlink_pidfile(pidpath)
            return False
        elif oe.errno == errno.EPERM:
            log.debug('Not our RPC daemon: {} ({})'.format(pid, pidpath))
            return False
        else:
            raise

    return True


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

    # still running?
    if not rpc_kill(pidpath, pid, 0):
        # dead
        return False

    time.sleep(3)

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
    for i in range(1, 4):
        try:
            local_proxy = local_rpc_connect(config_dir=config_dir)
            local_proxy.ping()
            break
        except (IOError, OSError) as ie:
            if ie.errno == errno.ECONNREFUSED:
                msg = 'API server not responding; trying again in {} seconds'
                log.debug(msg.format(i))
                time.sleep(i)
                continue
            else:
                raise

    return True


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
