#!/usr/bin/env python
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

import os
import sys
import traceback
import errno
import time
import atexit

from defusedxml import xmlrpc

# prevent the usual XML attacks
xmlrpc.monkey_patch()

import signal
import json
import config as blockstack_config
import backend
import proxy

log = blockstack_config.get_logger()

from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler 

running = False

# need to wrap CLI methods to capture arguments
def local_rpc_factory( method, config_path ):
    """
    Factory for producing wrappers around CLI functions
    """
    import blockstack_client.method_parser as method_parser
    import blockstack_client.cli as cli
    method_info = method_parser.parse_methods( [method] )[0]

    def argwrapper( *args, **kw ):
        argv = ["blockstack", method_info['command']] + list(args)
        result = cli.run_cli( argv=argv, config_path=config_path )
        return result 

    argwrapper.__doc__ = method.__doc__
    argwrapper.__name__ = method.__name__
    return argwrapper


class BlockstackAPIEndpointHandler(SimpleXMLRPCRequestHandler):
    """
    Hander to capture tracebacks
    """
    def _dispatch(self, method, params):
        try: 
            res = self.server.funcs[str(method)](*params)

            # lol jsonrpc within xmlrpc
            return json.dumps(res)
        except Exception, e:
            print >> sys.stderr, "\n\n%s\n\n" % traceback.format_exc()
            return json.dumps( {'error': 'Caught exception:\n%s' % traceback.format_exc()})


class BlockstackAPIEndpoint(SimpleXMLRPCServer):
    """
    Lightweight API endpoint to Blockstack server:
    exposes all of the client methods via an XMLRPC interface,
    so other local programs (e.g. those that can't use the library)
    can access the Blockstack client functionality.
    """

    def __init__(self, host='localhost', port=blockstack_config.DEFAULT_API_PORT, plugins=[], handler=BlockstackAPIEndpointHandler, config_path=blockstack_config.CONFIG_PATH, timeout=30 ):
        self.plugin_mods = []
        self.plugin_destructors = []
        self.plugin_prefixes = []
        SimpleXMLRPCServer.__init__( self, (host,port), handler, allow_none=True )
        self.timeout = timeout
        self.config_path = config_path

        import blockstack_client 
        import blockstack_client.cli as cli

        # register methods in blockstack_client 
        for attr in dir(blockstack_client):
            if not attr.startswith("__"):
                method = getattr( blockstack_client, attr )
                if callable(method) or hasattr(method, '__call__'):
                    self.register_function( method )

        # register the command-line methods (will all start with cli_)
        for method in cli.get_cli_basic_methods() + cli.get_cli_advanced_methods():
            log.debug("Register CLI method '%s'" % method.__name__)
            self.register_function( local_rpc_factory(method, config_path), method.__name__ )
    
        # register all plugin methods 
        for plugin_or_plugin_name in plugins:

            if type(plugin_or_plugin_name) in [str, unicode]:
                # name of a module to load
                try:
                    mod_plugin = __import__(plugin_name)
                except ImportError, e:
                    log.error("Skipping plugin '%s', since it cannot be imported" % plugin_name)
                    continue
            else:
                mod_plugin = plugin_or_plugin_name

            plugin_prefix = getattr(mod_plugin, "RPC_PREFIX", mod_plugin.__name__)
            if plugin_prefix in self.plugin_prefixes:
                log.error("Skipping conflicting plugin '%s'" % mod_plugin)
                continue

            plugin_init = getattr(mod_plugin, "RPC_INIT", None)
            if plugin_init is None:
                plugin_init = lambda: True

            plugin_shutdown = getattr(mod_plugin, "RPC_SHUTDOWN", None)
            if plugin_shutdown is None:
                plugin_shutdown = lambda: True

            method_list = getattr(mod_plugin, "RPC_METHODS", None)
            if method_list is None:
                # assume all methods that don't start with '__'
                method_list = []
                for attr in dir(mod_plugin):
                    method = getattr(mod_plugin, attr, None)
                    if callable(method) or hasattr(method, '__call__'):
                        method_list.append(method)


            for method in method_list:
                if callable(method) or hasattr(method, '__call__'):
                    log.debug("Register plugin method '%s_%s'" % (plugin_prefix, method.__name__))
                    self.register_function( method, plugin_prefix + "_" + method.__name__ )

                else:
                    log.error("Skipping non-method '%s'" % method)
                    continue

            # keep state around
            self.plugin_prefixes.append(plugin_prefix)
            self.plugin_mods.append( mod_plugin )
            self.plugin_destructors.append( plugin_shutdown )

            # initialize plugin 
            plugin_init(config_path=config_path)

        self.register_introspection_functions()
        self.register_multicall_functions()


    def shutdown_plugins(self):
        """
        Shut down each plugin
        """
        log.debug("RPC plugin shutdown")

        for pd in self.plugin_destructors:
            pd(config_path=self.config_path)

        self.plugin_destructors = []
       

class BlockstackAPIEndpointClient(proxy.BlockstackRPCClient):
    pass


def make_local_rpc_server( portnum, config_path=blockstack_config.CONFIG_PATH, plugins=[] ):
    """
    Make a local RPC server instance.
    It will be derived from BaseHTTPServer.HTTPServer.
    @plugins can be a list of modules, or a list of strings that
    identify module names to import.

    Returns a new server instance on success.
    """
    plugins = [backend] + plugins 
    srv = BlockstackAPIEndpoint( port=portnum, config_path=config_path, plugins=plugins )
    return srv


def local_rpc_server_run( srv ):
    """
    Start running the RPC server, but in a separate thread.
    """
    global running

    srv.timeout = 0.5
    while running:
        srv.handle_request()


def local_rpc_server_stop( srv ):
    """
    Stop a running RPC server
    """
    srv.shutdown_plugins()


def local_rpc_connect( config_dir=blockstack_config.CONFIG_DIR, api_port=None ):
    """
    Connect to a locally-running RPC server
    Return a server proxy object on success.
    Raise on error.
    """
    if api_port is None:
        config_path = os.path.join( config_dir, blockstack_config.CONFIG_FILENAME )
        conf = blockstack_config.get_config( config_path )
        if conf is None:
            raise Exception("Failed to read config at '%s'" % config_path )

        api_port = conf['api_endpoint_port']

    log.debug("Connect to RPC at localhost:%s" % api_port)
    return BlockstackAPIEndpointClient( "localhost", api_port )


def local_rpc_action( command, config_dir=blockstack_config.CONFIG_DIR ):
    """
    Handle an API endpoint command:
    * start: start up an API endpoint
    * stop: stop a running API endpoint
    * status: see if there's an API endpoint running.
    * restart: stop and start the API endpoint

    Return the exit status
    """

    if command not in ['start', 'start-foreground', 'stop', 'status', 'restart']:
        raise ValueError("Invalid command '%s'" % command)

    config_path = os.path.join(config_dir, blockstack_config.CONFIG_FILENAME) 
    config = blockstack_config.get_config( config_path )
    if config is None:
        raise Exception("Failed to read config at '%s'" % config_path)

    api_port = config['api_endpoint_port']
    rc = os.system( "%s -m blockstack_client.rpc %s %s %s" % (sys.executable, command, api_port, config_dir) )
    if rc is None:
        rc = 0

    return os.WEXITSTATUS(rc)


def local_rpc_dispatch( port, method_name, *args, **kw ):
    """
    Connect to the running endpoint, issue the command,
    and return the result.
    """
    client = BlockstackAPIEndpointClient( "localhost", port )
    try:
        method = getattr(client, method_name)
        result = method( *args, **kw )
        if type(result) in [str, unicode]:
            result = json.loads(result)

        return result
    except:
        return {'error': traceback.format_exc()}
    

def local_rpc_pidfile_path(config_dir=blockstack_config.CONFIG_DIR):
    """
    Where do we put the PID file?
    """
    return os.path.join( config_dir, "api_endpoint.pid" )


def local_rpc_logfile_path(config_dir=blockstack_config.CONFIG_DIR):
    """
    Where do we put logs?
    """
    return os.path.join( config_dir, "api_endpoint.log" )


def local_rpc_read_pidfile( pidfile_path ):
    """
    Read a PID file
    Return None if unable
    """
    try:
        with open(pidfile_path, "r") as f:
            data = f.read()
    except:
        return None

    try:
        data = int(data)
        return data
    except:
        return None


def local_rpc_write_pidfile( pidfile_path ):
    """
    Write a PID file
    """
    with open(pidfile_path, "w") as f:
        f.write( str(os.getpid()) )
        f.flush()
        os.fsync( f.fileno() )

    return 


def local_rpc_unlink_pidfile( pidfile_path ):
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
        local_rpc_server_stop( rpc_srv )
        rpc_srv = None


def local_rpc_exit_handler( sig, frame ):
    """
    Fatal signal handler
    """
    local_rpc_atexit()
    log.debug("Local RPC exit")
    sys.exit(0)


# used when running in a separate process
rpc_pidpath = None
rpc_srv = None


def local_rpc_start( portnum, config_dir=blockstack_config.CONFIG_DIR, foreground=False, password=None ):
    """
    Start up an API endpoint
    Return True on success
    Return False on error
    """
    from blockstack_client.wallet import load_wallet, initialize_wallet

    global rpc_pidpath, rpc_srv, running
    config_path = os.path.join(config_dir, blockstack_config.CONFIG_FILENAME)
    wallet_path = os.path.join(config_dir, blockstack_config.WALLET_FILENAME)

    # already running?
    rpc_pidpath = local_rpc_pidfile_path( config_dir=config_dir )
    if os.path.exists( rpc_pidpath ):
        print >> sys.stderr, "API endpoint already running (PID %s, %s)" % (local_rpc_read_pidfile(rpc_pidpath), rpc_pidpath)
        return False

    signal.signal( signal.SIGINT, local_rpc_exit_handler )
    signal.signal( signal.SIGQUIT, local_rpc_exit_handler )
    signal.signal( signal.SIGTERM, local_rpc_exit_handler )

    atexit.register( local_rpc_atexit )

    wallet = load_wallet( password=password, config_dir=config_dir, include_private=True, wallet_path=wallet_path )
    if 'error' in wallet:
        log.error("Failed to load wallet: %s" % wallet['error'])
        return False

    wallet = wallet['wallet']
    
    if not foreground:
        log.debug("Running in the background")

        logpath = local_rpc_logfile_path( config_dir=config_dir )
        logfile = open(logpath, "a+")
        child_pid = os.fork()
        if child_pid == 0:

            # child!
            sys.stdin.close()
            os.dup2( logfile.fileno(), sys.stdout.fileno() )
            os.dup2( logfile.fileno(), sys.stderr.fileno() )
            os.setsid()

            daemon_pid = os.fork()
            if daemon_pid == 0:

                # daemon!
                os.chdir("/")

            elif daemon_pid > 0:

                # parent (intermediate child)
                sys.exit(0)

            else:

                # error
                sys.exit(1)

        elif child_pid > 0:

            # grand-parent
            # wait for intermediate child
            pid, status = os.waitpid( child_pid, 0 )
            sys.exit(status)


    rpc_srv = make_local_rpc_server( portnum, config_path=config_path ) 
    backend.set_wallet( [wallet['payment_addresses'][0], wallet['payment_privkey']],
                        [wallet['owner_addresses'][0], wallet['owner_privkey']],
                        [wallet['data_pubkeys'][0], wallet['data_privkey']],
                        config_path=config_path )

    running = True
    local_rpc_write_pidfile( rpc_pidpath )
    local_rpc_server_run( rpc_srv )
    local_rpc_unlink_pidfile( rpc_pidpath )
    local_rpc_server_stop( rpc_srv )
     
    return True


def local_rpc_stop( config_dir=blockstack_config.CONFIG_DIR ):
    """
    Shut down an API endpoint
    Return True if we stopped it
    Return False if it wasn't running, or we couldn't stop it
    """
    # already running?
    pidpath = local_rpc_pidfile_path( config_dir=config_dir )
    if not os.path.exists( pidpath ):
        print >> sys.stderr, "Not running (%s)" % pidpath
        return False

    pid = local_rpc_read_pidfile( pidpath )
    if pid is None:
        print >> sys.stderr, "Failed to read '%s'" % pidpath
        return False

    try:
        os.kill( pid, 0 )
    except OSError, oe:
        if oe.errno == errno.ESRCH:
            print >> sys.stderr, "Removing stale PID file '%s'" % pidpath
            local_rpc_unlink_pidfile( pidpath )
            return False
        else:
            raise

    # still running
    # try to terminate
    try:
        print >> sys.stderr, "Sending SIGTERM to %s" % pid
        os.kill( pid, signal.SIGTERM )
    except OSError, oe:
        if oe.errno == errno.ESRCH:
            print >> sys.stderr, "Removing stale PID file '%s'" % pidpath
            local_rpc_unlink_pidfile( pidpath )
            return False
        else:
            raise

    # still running?
    time.sleep(1)
    try:
        os.kill(pid, 0)
    except OSError, oe:
        if oe.errno == errno.ESRCH:
            # dead 
            local_rpc_unlink_pidfile( pidpath )
            return False
        else:
            raise 

    # still running
    time.sleep(3)
    try:
        print >> sys.stderr, "Sending SIGKILL to %s" % pid
        os.kill(pid, signal.SIGKILL)
        local_rpc_unlink_pidfile( pidpath )
        return True
    except OSError, oe:
        if oe.errno == errno.ESRCH:
            # dead
            local_rpc_unlink_pidfile( pidpath )
            return False
        else:
            raise

    # definitely dead now
    return True


def local_rpc_status( config_dir=blockstack_config.CONFIG_DIR ):
    """
    Print the status of an instantiated API endpoint
    Return True if the daemon is running.
    Return False if not, or if unknown.
    """
    # see if it's running 
    pidpath = local_rpc_pidfile_path( config_dir=config_dir )
    if not os.path.exists(pidpath):
        return False

    pid = local_rpc_read_pidfile( pidpath )
    if pid is None:
        return False

    try:
        os.kill( pid, 0 )
    except OSError, oe:
        if oe.errno == errno.ESRCH:
            return False

        elif oe.errno == errno.EPERM:
            return False

        else:
            raise
    
    return True


def local_rpc_ensure_running( config_dir=blockstack_config.CONFIG_DIR, password=None ):
    """
    Ensure that the RPC daemon is running.
    Start it if it is not.
    Return True on success
    Return False on failure
    """
    rc = local_rpc_status( config_dir )
    if not rc:
        log.debug("Starting RPC endpoint (%s)" % config_dir)

        pass_password = False
        if password is not None and os.environ.get('BLOCKSTACK_CLIENT_WALLET_PASSWORD', None) is None:
            # pass password to local rpc daemon
            os.environ['BLOCKSTACK_CLIENT_WALLET_PASSWORD'] = password
            pass_password = True

        rc = local_rpc_action( "start", config_dir=config_dir )

        if pass_password:
            del os.environ['BLOCKSTACK_CLIENT_WALLET_PASSWORD']

        if rc != 0:
            log.error("Failed to start RPC endpoint; exit code was %s" % rc)
            return False

        else:
            return True

    else:
        log.debug("RPC endpoint already running (%s)" % config_dir)
        return True



if __name__ == "__main__":
    # running as a local API endpoint 
    usage = "%s COMMAND PORT [config_path]" % sys.argv[0] 
    try:
        command = sys.argv[1]
        portnum = int(sys.argv[2])
        config_dir = blockstack_config.CONFIG_DIR

        if len(sys.argv) > 3:
            config_dir = sys.argv[3]

    except Exception, e:
        traceback.print_exc()
        print >> sys.stderr, usage
        sys.exit(1)
    
    if command == 'start':
        # maybe inherited password through the environment?
        passwd = os.environ.get("BLOCKSTACK_CLIENT_WALLET_PASSWORD", None)
        rc = local_rpc_start( portnum, config_dir=config_dir, password=passwd )
        if rc:
            sys.exit(0)
        else:
            sys.exit(1)
       
    elif command == 'start-foreground':
        passwd = os.environ.get("BLOCKSTACK_CLIENT_WALLET_PASSWORD", None)
        rc = local_rpc_start( portnum, config_dir=config_dir, foreground=True, password=passwd )
        if rc:
            sys.exit(0)
        else:
            sys.exit(1)

    elif command == 'status':
        rc = local_rpc_status( config_dir=config_dir )
        if rc:
            print >> sys.stderr, "Alive"
            sys.exit(0)
        else:
            print >> sys.stderr, "Dead"
            sys.exit(1)

    elif command == 'stop':
        rc = local_rpc_stop( config_dir=config_dir )
        if rc:
            sys.exit(0)
        else:
            sys.exit(1)

    elif command == 'restart':
        rc = local_rpc_stop( config_dir=config_dir )
        if not rc:
            sys.exit(1)
        else:
            rc = local_rpc_start( portnum, config_dir=config_dir )
            if rc:
                sys.exit(0)
            else:
                sys.exit(1)


