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
import xmlrpclib
import signal
import json
from blockstack_client import config

from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler 

# need to wrap CLI methods to capture arguments
def local_rpc_factory( method, config_path ):
    """
    Factory for producing wrappers around CLI functions
    """
    import blockstack_client.parser as parser
    import blockstack_client.cli as cli
    method_info = parser.parse_methods( [method] )[0]

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
            return json.dumps( {'error': 'Caught exception', 'trace': traceback.format_exc()})


class BlockstackAPIEndpoint(SimpleXMLRPCServer):
    """
    Lightweight API endpoint to Blockstack server:
    exposes all of the client methods via an XMLRPC interface,
    so other local programs (e.g. those that can't use the library)
    can access the Blockstack client functionality.
    """

    def __init__(self, host='localhost', port=config.DEFAULT_API_PORT, plugins=[], handler=BlockstackAPIEndpointHandler, config_path=config.CONFIG_PATH ):
        SimpleXMLRPCServer.__init__( self, (host, port), handler, allow_none=True )

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
            self.register_function( local_rpc_factory(method, config_path), method.__name__ )
    
        # register all plugin methods 
        for plugin_name in plugins:
            try:
                mod_plugin = __import__(plugin_name)
            except ImportError, e:
                log.error("Skipping plugin '%s', since it cannot be imported" % plugin_name)
                continue

            for attr in dir(mod_plugin):
                if not attr.startswith("__"):
                    method = getattr(mod_plugin, attr)
                    if callable(method) or hasattr(method, '__call__'):
                        self.register_function( method, plugin_name + method.__name__ )

        self.register_introspection_functions()
        self.register_multicall_functions()
        

def make_local_rpc_server( portnum, plugins=[] ):
    """
    Make a local RPC server instance.
    It will be derived from BaseHTTPServer.HTTPServer.

    Returns a new server instance on success.
    """
    srv = BlockstackAPIEndpoint( port=portnum, plugins=plugins )
    return srv


def local_rpc_server_run( srv ):
    """
    Start running the RPC server, but in a separate thread.
    """
    srv.serve_forever()


def local_rpc_server_stop( srv ):
    """
    Stop a running RPC server
    """
    srv.shutdown()


def local_rpc_action( command, config_dir=config.CONFIG_DIR ):
    """
    Handle an API endpoint command:
    * start: start up an API endpoint
    * stop: stop a running API endpoint
    * status: see if there's an API endpoint running.
    * restart: stop and start the API endpoint

    Return the exit status
    """

    from blockstack_client import config 

    if command not in ['start', 'stop', 'status', 'restart']:
        raise ValueError("Invalid command '%s'" % command)

    config_path = os.path.join(config_dir, config.CONFIG_FILENAME) 
    config = config.get_config( config_path )
    if config is None:
        raise Exception("Failed to read config at '%s'" % config_path)

    api_port = config['api_endpoint_port']
    rc = os.system( "%s -m blockstack_client.rpc %s %s %s" % (sys.executable, command, api_port, config_dir) )
    if rc is None:
        rc = 0

    return rc


def local_rpc_dispatch( port, method_name, *args, **kw ):
    """
    Connect to the running endpoint, issue the command,
    and return the result.
    """
    client = xmlrpclib.ServerProxy('http://localhost:%s' % port)
    try:
        method = getattr(client, method)
        result = method( *args, **kw )
        return result
    except:
        return {'error': traceback.format_exc()}
    

def local_rpc_pidfile_path(config_dir=config.CONFIG_DIR):
    """
    Where do we put the PID file?
    """
    return os.path.join( config_dir, "api_endpoint.pid" )


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
    global rpc_pidpath
    if rpc_pidpath is not None and os.path.exists( rpc_pidpath ):
        try:
            os.unlink(rpc_pidpath)
        except:
            pass

        rpc_pidpath = None


def local_rpc_exit_handler( sig, frame ):
    """
    Fatal signal handler
    """
    local_rpc_atexit()
    sys.exit(0)


# used when running in a separate process
rpc_pidpath = None
rpc_srv = None


def local_rpc_start( config_dir, portnum ):
    """
    Start up an API endpoint 
    Return False on error
    """
    # already running?
    pidpath = local_rpc_pidfile_path( config_dir=config_dir )
    if os.path.exists( pidpath ):
        print >> sys.stderr, "API endpoint already running (PID %s, %s)" % (local_rpc_read_pidfile(pidpath), pidpath)
        return False

    signal.signal( signal.SIGINT, local_rpc_exit_handler )
    signal.signal( signal.SIGQUIT, local_rpc_exit_handler )
    signal.signal( signal.SIGTERM, local_rpc_exit_handler )

    atexit.register( local_rpc_atexit )

    # start up!
    local_rpc_write_pidfile( pidpath )

    rpc_srv = make_local_rpc_server( portnum )
    local_rpc_server_run( rpc_srv )
    return True


def local_rpc_stop( config_dir ):
    """
    Shut down an API endpoint
    Return True if we stopped it
    Return False if it wasn't running, or we couldn't stop it
    """
    # already running?
    pidpath = local_rpc_pidfile_path( config_dir=config_dir )
    if not os.path.exists( pidpath ):
        print >> sys.stderr, "Not running"
        return False

    pid = local_rpc_read_pidfile( pidpath )
    if pid is None:
        print >> sys.stderr, "Failed to read '%s'" % pidpath
        return False

    try:
        os.kill( pid, 0 )
    except OSError, oe:
        if oe.errno == errno.ESRCH:
            print >> sys.stderr, "Removing stale PID file"
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
            print >> sys.stderr, "Removing stale PID file"
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
    time.sleep(5)
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


def local_rpc_status( config_dir ):
    """
    Print the status of an instantiated API endpoint
    Return True if we determined the status
    Return False if not
    """
    # see if it's running 
    pidpath = local_rpc_pidfile_path( config_dir=config_dir )
    if not os.path.exists(pidpath):
        print >> sys.stderr, "Dead"
        return True

    pid = local_rpc_read_pidfile( pidpath )
    if pid is None:
        print >> sys.stderr, "Dead"
        return True

    try:
        os.kill( pid, 0 )
        print >> sys.stderr, "Alive"
    except OSError, oe:
        if oe.errno == errno.ESRCH:
            print >> sys.stderr, "Dead"
            return True

        elif oe.errno == errno.EPERM:
            print >> sys.stderr, "Unknown"
            return False

        else:
            raise
    
    return True



if __name__ == "__main__":
    # running as a local API endpoint 
    usage = "%s COMMAND PORT [config_path]" % sys.argv[0] 
    try:
        command = sys.argv[1]
        portnum = int(sys.argv[2])
        config_dir = config.CONFIG_DIR

        if len(sys.argv) > 3:
            config_dir = sys.argv[3]

    except Exception, e:
        traceback.print_exc()
        print >> sys.stderr, usage
        sys.exit(1)
    
    if command == 'start':
        rc = local_rpc_start( config_dir, portnum )
        if rc:
            sys.exit(0)
        else:
            sys.exit(1)
        
    elif command == 'status':
        rc = local_rpc_status( config_dir )
        if rc:
            sys.exit(0)
        else:
            sys.exit(1)

    elif command == 'stop':
        rc = local_rpc_stop( config_dir )
        if rc:
            sys.exit(0)
        else:
            sys.exit(1)

    elif command == 'restart':
        rc = local_rpc_stop( config_dir )
        if not rc:
            sys.exit(1)
        else:
            rc = local_rpc_start( config_dir, portnum )
            if rc:
                sys.exit(0)
            else:
                sys.exit(1)


