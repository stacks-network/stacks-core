#!/usr/bin/env python
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
import socket
import base64
import blockstack_zones
import json
import shutil
import atexit
import errno
import subprocess
import signal
import SocketServer
import threading
import time
import traceback
import random

import blockstack
import blockstack_client
import virtualchain

from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler

from blockstack_client.config import FIRST_BLOCK_MAINNET, get_logger, url_to_host_port, atlas_inventory_to_string
from blockstack_client import BlockstackRPCClient

from blockstack import RPC_SERVER_PORT
# from blockstack.atlas import *

log = get_logger( "atlas-network-simulator" )

ATLAS_TESTNET_PORT = 16265

# current simulator time
TIME = 0

# TODO: set these back to None if we want to fetch them from a simulator server
PEER_LIFETIME_INTERVAL = 10
PEER_MAX_NEIGHBORS = 10
PEER_PING_INTERVAL = 3
PEER_MAX_AGE = 10
PEER_CLEAN_INTERVAL = 3
PEER_PING_TIMEOUT = 2
PEER_INV_TIMEOUT = 2
PEER_NEIGHBORS_TIMEOUT = 2
PEER_ZONEFILES_TIMEOUT = 2
PEER_PUSH_ZONEFILES_TIMEOUT = 2


def time_now():
    """
    Get the current time
    """
    return time.time()


def time_sleep(hostport, procname, value):
    """
    Have this host sleep for a bit
    """
    time.sleep(value)


def atlas_max_neighbors():
    """
    How many neighbors can a peer have?
    """
    global PEER_MAX_NEIGHBORS
    if os.environ.get("BLOCKSTACK_ATLAS_NUM_NEIGHBORS", None) is not None:
        PEER_MAX_NEIGHBORS = int(os.environ['BLOCKSTACK_ATLAS_NUM_NEIGHBORS'])
        return PEER_MAX_NEIGHBORS

    if PEER_MAX_NEIGHBORS is not None:
        return PEER_MAX_NEIGHBORS

    rpc = AtlasRPCTestClient( "none", 0 )
    PEER_MAX_NEIGHBORS = rpc.max_neighbors()
    return PEER_MAX_NEIGHBORS


def atlas_peer_lifetime_interval():
    """
    How long is a peer's request history viable?
    """
    global PEER_LIFETIME_INTERVAL
    if PEER_LIFETIME_INTERVAL is not None:
        return PEER_LIFETIME_INTERVAL

    rpc = AtlasRPCTestClient( "none", 0 )
    PEER_LIFETIME_INTERVAL = rpc.peer_lifetime_interval()
    return PEER_LIFETIME_INTERVAL


def atlas_peer_ping_interval():
    """
    How long is a peer's last-contact information fresh?
    """
    global PEER_PING_INTERVAL
    if PEER_PING_INTERVAL is not None:
        return PEER_PING_INTERVAL

    rpc = AtlasRPCTestClient( "none", 0 )
    PEER_PING_INTERVAL = rpc.peer_ping_interval()
    return PEER_PING_INTERVAL


def atlas_peer_max_age():
    """
    What's the maximum allowed peer age in the peer db?
    """
    global PEER_MAX_AGE
    if PEER_MAX_AGE is not None:
        return PEER_MAX_AGE

    rpc = AtlasRPCTestClient( "none", 0 )
    PEER_MAX_AGE = rpc.peer_max_age()
    return PEER_MAX_AGE


def atlas_peer_clean_interval():
    """
    What's the interval between peer cleanups?
    """
    global PEER_CLEAN_INTERVAL
    if PEER_CLEAN_INTERVAL is not None:
        return PEER_CLEAN_INTERVAL

    rpc = AtlasRPCTestClient( "none", 0 )
    PEER_CLEAN_INTERVAL = rpc.peer_clean_interval()
    return PEER_CLEAN_INTERVAL


def atlas_ping_timeout():
    """
    What's the ping timeout?
    """
    global PEER_PING_TIMEOUT
    if PEER_PING_TIMEOUT is not None:
        return PEER_PING_TIMEOUT

    rpc = AtlasRPCTestClient( "none", 0 )
    PEER_PING_TIMEOUT = rpc.ping_timeout()
    return PEER_PING_TIMEOUT


def atlas_inv_timeout():
    """
    What's the inv timeout?
    """
    global PEER_INV_TIMEOUT
    if PEER_INV_TIMEOUT is not None:
        return PEER_INV_TIMEOUT

    rpc = AtlasRPCTestClient( "none", 0 )
    PEER_INV_TIMEOUT = rpc.inv_timeout()
    return PEER_INV_TIMEOUT


def atlas_neighbors_timeout():
    """
    what's the neighbors timeout?
    """
    global PEER_NEIGHBORS_TIMEOUT
    if PEER_NEIGHBORS_TIMEOUT is not None:
        return PEER_NEIGHBORS_TIMEOUT

    rpc = AtlasRPCTestClient( "none", 0 ) 
    PEER_NEIGHBORS_TIMEOUT = rpc.neighbors_timeout()
    return PEER_NEIGHBORS_TIMEOUT


def atlas_zonefiles_timeout():
    """
    what's the zonefiles timeout?
    """
    global PEER_ZONEFILES_TIMEOUT 
    if PEER_ZONEFILES_TIMEOUT is not None:
        return PEER_ZONEFILES_TIMEOUT

    rpc = AtlasRPCTestClient( "none", 0 ) 
    PEER_ZONEFILES_TIMEOUT = rpc.zonefiles_timeout()
    return PEER_ZONEFILES_TIMEOUT


def atlas_push_zonefiles_timeout():
    """
    what's the push-zonefile timeout?
    """
    global PEER_PUSH_ZONEFILES_TIMEOUT
    if PEER_PUSH_ZONEFILES_TIMEOUT is not None:
        return PEER_PUSH_ZONEFILES_TIMEOUT

    rpc = AtlasRPCTestClient( "none", 0 ) 
    PEER_PUSH_ZONEFILES_TIMEOUT = rpc.push_zonefiles_timeout()
    return PEER_PUSH_ZONEFILES_TIMEOUT


class AtlasRPCTestClient(object):
    def __init__(self, host, port, timeout=60, src=None):
        self.rpc = BlockstackRPCClient( "127.0.0.1", ATLAS_TESTNET_PORT, timeout=timeout )
        self.src_hostport = src
        self.dest_hostport = "%s:%s" % (host, port)
        self.timeout = timeout


    def get_atlas_peers( self ):
        """
        Get atlas peers from the destination
        """
        return self.rpc.get_atlas_peers( 'atlas_network', self.src_hostport, self.dest_hostport )


    def get_zonefile_inventory( self, bit_offset, bit_len ):
        """
        Get zonefile inventory from the given dest hostport, with simulated loss
        """
        return self.rpc.get_zonefile_inventory( 'atlas_network', self.src_hostport, self.dest_hostport, bit_offset, bit_len )


    def get_zonefiles( self, zonefile_hashes ):
        """
        Get the list of zonefiles, given the zonefile hashes (with simulated loss)
        Returns [{'zonefile hash': zonefile data}]
        """
        return self.rpc.get_zonefiles( 'atlas_network', self.src_hostport, self.dest_hostport, zonefile_hashes )

    
    def put_zonefiles( self, zonefile_info ):
        """
        Upload a list of zonefiles, and enqueue them in the pusher
        """
        return self.rpc.put_zonefiles( 'atlas_network', self.src_hostport, self.dest_hostport, zonefile_info )


    def ping( self ):
        """
        Ping!
        """
        return self.rpc.ping( 'atlas_network', self.src_hostport, self.dest_hostport )


    def getinfo( self ):
        """
        get server info
        """
        return self.rpc.getinfo( 'atlas_network', self.src_hostport, self.dest_hostport )


    def add_sleep_deadline( self, hostport, procname, value ):
        """
        make the node sleep
        """
        return self.rpc.add_sleep_deadline( hostport, procname, value )


    def max_neighbors( self ):
        """
        get max neighbors
        """
        return self.rpc.max_neighbors()


    def peer_lifetime_interval( self ):
        """
        peer lifetime interval
        """
        return self.rpc.peer_lifetime_interval()


    def peer_ping_interval( self ):
        """
        peer ping interval
        """
        return self.rpc.peer_ping_interval()


    def peer_max_age( self ):
        """
        peer max age
        """
        return self.rpc.peer_max_age()


    def peer_clean_interval( self ):
        """
        peer clean interval
        """
        return self.rpc.peer_clean_interval()


    def ping_timeout( self ):
        """
        ping timeout
        """
        return self.rpc.ping_timeout()

    
    def inv_timeout( self ):
        """
        inv timeout
        """
        return self.rpc.inv_timeout()


    def neighbors_timeout( self ):
        """
        getneighbors timeout
        """
        return self.rpc.neighbors_timeout()


    def zonefiles_timeout( self ):
        """
        zonefiles timeout
        """
        return self.rpc.zonefiles_timeout()


    def push_zonefiles_timeout( self ):
        """
        push zonefiles timeout
        """
        return self.rpc.push_zonefiles_timeout()


    def time_now( self ):
        """
        time now
        """
        return self.rpc.time_now()


def rpc_traceback():
    exception_data = traceback.format_exc().splitlines()
    return {
        "error": exception_data[-1],
        "traceback": exception_data
    }


class AtlasNetworkRPCHandler(SimpleXMLRPCRequestHandler):
    """
    Hander to capture tracebacks
    """
    def _dispatch(self, method, params):
        try:
            
            if len(params) > 0 and params[0] == 'atlas_network':
                # trim
                params = params[1:]

            log.debug("Atlas Network RPC begin %s(%s)" % (method, params))

            res = self.server.funcs["rpc_" + str(method)](*params)

            # lol jsonrpc within xmlrpc
            ret = json.dumps(res)

            log.debug("Atlas Network RPC end %s(%s)" % (method, params))
            return ret
        except Exception, e:
            print >> sys.stderr, "\n%s(%s)\n%s\n" % (method, params, traceback.format_exc())
            return json.dumps(rpc_traceback())


class AtlasNetwork( SocketServer.ThreadingMixIn, SimpleXMLRPCServer ):

    """
    Dynamic network test: simulate
    an inter-Atlas network, with certain
    reliability characteristics.

    Other Atlas nodes will connect to it
    and it will forward their messages to
    each other.
    """

    def __init__(self, port, **network_params):
        """
         @network_params includes:
        * drop_probability (callable(hostport, hostport)): probability that a message gets dropped en route to the given peer
        * peer_delay (callable(hostport)): function that returns the amount of iterations to sleep on getting a peer's neighbors
        * inv_delay (callable(hostport)): function that returns the amount of iterations to sleep on getting a peer's inventory
        * zonefile_delay (callable(hostport, num_zfs)): function that returns the amount of iterations to sleep on getting a peer's zonefiles (given the number of zonefiles)
        * max_neighbors (int): maximum number of node neighbors (defaults to 80)
        * peer_ping_interval (int): maximum ttl of a peer's state before we ask again (default is 60)
        * peer_lifetime_interval (int): maximum ttl of a peer's liveness data
        """
        SimpleXMLRPCServer.__init__(self, ('localhost', port), AtlasNetworkRPCHandler, allow_none=True )
        self.port = port

        self.drop_probability = network_params.get( "drop_probability", lambda hostport_src, hostport_dst: 0 )
        self.peer_delay = network_params.get( "peer_delay", lambda hostport: 0 )
        self.inv_delay = network_params.get( "inv_delay", lambda hostport: 0 )
        self.zonefile_delay = network_params.get("zonefile_delay", lambda hostport, num_zfs: 0 )
        self.max_neighbors = network_params.get("max_neighbors", 3)
        self.peer_ping_interval = network_params.get("peer_ping_interval", 3)
        self.peer_lifetime_interval = network_params.get("peer_lifetime_interval", 10)
        self.peer_max_age = network_params.get("peer_max_age", 10)
        self.peer_clean_interval = network_params.get("peer_clean_interval", 3)
        self.ping_timeout = network_params.get("ping_timeout", 1)
        self.inv_timeout = network_params.get("inv_timeout", 1 )
        self.neighbors_timeout = network_params.get("neighbors_timeout", 1 )
        self.zonefiles_timeout = network_params.get('zonefiles_timeout', 1 )
        self.push_zonefiles_timeout = network_params.get("push_zonefiles_timeout", 1 )

        # register methods 
        for attr in dir(self):
            if attr.startswith("rpc_"):
                method = getattr(self, attr)
                if callable(method) or hasattr(method, '__call__'):
                    self.register_function( method )

 
    def possibly_drop(self, src_hostport, dest_hostport):
        """
        Possibly drop the connection
        """
        if src_hostport is None:
            # test control-plane
            return 0.0

        prob = self.drop_probability( src_hostport, dest_hostport )
        if random.random() <= prob:
            log.debug("Drop connection (%s-%s)" % (src_hostport, dest_hostport))
            se = socket.error("Connection Refused")
            se.errno = errno.ECONNREFUSED
            raise se


    def rpc_get_zonefile_inventory( self, src_hostport, dest_hostport, bit_offset, bit_len, **con_info ):
        """
        Get zonefile inventory from the given dest hostport, with simulated loss
        """
        log.debug("atlas network: get_zonefile_inventory(%s,%s)" % (src_hostport, dest_hostport))
        self.possibly_drop( src_hostport, dest_hostport )
        time.sleep( self.inv_delay( dest_hostport ) )
        
        dest_host, dest_port = url_to_host_port( dest_hostport )
        rpc = BlockstackRPCClient( dest_host, dest_port, src=src_hostport )
        return rpc.get_zonefile_inventory( 'atlas_network', src_hostport, dest_hostport, bit_offset, bit_len )


    def rpc_get_atlas_peers( self, src_hostport, dest_hostport ):
        """
        Get the list of peers in this peer's neighbor set, with simulated loss.
        """
        log.debug("atlas network: get_atlas_peers(%s,%s)" % (src_hostport, dest_hostport))
        self.possibly_drop( src_hostport, dest_hostport )

        dest_host, dest_port = url_to_host_port( dest_hostport )
        rpc = BlockstackRPCClient( dest_host, dest_port, src=src_hostport )
        return rpc.get_atlas_peers( 'atlas_network', src_hostport, dest_hostport )


    def rpc_get_zonefiles( self, src_hostport, dest_hostport, zonefile_hashes ):
        """
        Get the list of zonefiles, given the zonefile hashes (with simulated loss)
        Returns [{'zonefile hash': zonefile data}]
        """
        log.debug("atlas network: get_zonefiles(%s,%s)" % (src_hostport, dest_hostport))
        self.possibly_drop( src_hostport, dest_hostport )

        dest_host, dest_port = url_to_host_port( dest_hostport )
        rpc = BlockstackRPCClient( dest_host, dest_port, src=src_hostport )
        return rpc.get_zonefiles( 'atlas_network', src_hostport, dest_hostport, zonefile_hashes )

    
    def rpc_put_zonefiles( self, src_hostport, dest_hostport, zonefile_info ):
        """
        Upload a list of zonefiles, and enqueue them in the pusher
        """
        log.debug("atlas network: put_zonefiles(%s,%s)" % (src_hostport, dest_hostport))
        self.possibly_drop( src_hostport, dest_hostport )

        dest_host, dest_port = url_to_host_port( dest_hostport )
        rpc = BlockstackRPCClient( dest_host, dest_port, src=src_hostport )
        return rpc.put_zonefiles( 'atlas_network', src_hostport, dest_hostport, zonefile_info )


    def rpc_ping( self, src_hostport, dest_hostport ):
        """
        Ping!
        """
        log.debug("atlas network: ping(%s,%s)" % (src_hostport, dest_hostport))
        self.possibly_drop( src_hostport, dest_hostport )

        dest_host, dest_port = url_to_host_port( dest_hostport )
        rpc = BlockstackRPCClient( dest_host, dest_port )
        return rpc.ping( 'atlas_network', src_hostport, dest_hostport )


    def rpc_getinfo( self, src_hostport, dest_hostport ):
        """
        get info
        """
        log.debug("atlas network: getinfo(%s,%s)" % (src_hostport, dest_hostport))
        self.possibly_drop( src_hostport, dest_hostport )

        dest_host, dest_port = url_to_host_port( dest_hostport )
        rpc = BlockstackRPCClient( dest_host, dest_port )
        try:
            return rpc.getinfo( 'atlas_network', src_hostport, dest_hostport )
        except Exception, e:
            log.exception(e)
            return {'error': 'exception caught'}


    def rpc_add_sleep_deadline( self, hostport, procname, value ):
        """
        No-op
        """
        return True


    def rpc_max_neighbors( self ):
        """
        how many neighbors can a peer have?
        """
        return self.max_neighbors


    def rpc_peer_lifetime_interval( self ):
        """
        what's a peer's lifetime interval?
        """
        return self.peer_lifetime_interval


    def rpc_peer_ping_interval( self ):
        """
        what's a peer's ping interval?
        """
        return self.peer_ping_interval

    
    def rpc_time_now( self ):
        """
        No-op
        """
        return time.time()


    def rpc_peer_max_age( self ):
        """
        what's the maximum peer age?
        """
        return self.peer_max_age

    
    def rpc_peer_clean_interval( self ):
        """
        what's the peer clean interval?
        """
        return self.peer_clean_interval

    def rpc_ping_timeout( self ):
        """
        what's the ping timeout?
        """
        return self.ping_timeout

    def rpc_inv_timeout( self ):
        """
        what's the inv timeout?
        """
        return self.inv_timeout

    def rpc_neighbors_timeout( self ):
        """
        what's the getneighbors timeout?
        """
        return self.neighbors_timeout

    def rpc_zonefiles_timeout( self ):
        """
        what's the zonefiles timeout?
        """
        return self.zonefiles_timeout

    def rpc_push_zonefiles_timeout( self ):
        """
        what's the push-zonefiles timeout?
        """
        return self.push_zonefiles_timeout

    
class AtlasNetworkServer( threading.Thread, object ):
    """
    RPC server thread
    """
    def __init__(self, atlas_network):
        super(AtlasNetworkServer, self).__init__()
        self.network = atlas_network

    def run(self):
        """
        Serve until asked to stop
        """
        self.network.serve_forever()

    def stop_server(self):
        """
        Stop serving.  Also stops the thread.
        """
        self.network.shutdown()


def atlas_network_build( peer_ports, seed_relations, blacklist_relations, network_dir ):
    """
    Construct a network with the given initial topology and properties.
    Return a dict of network state, which can be fed into atlas_network_start.
    """

    if os.path.exists(network_dir):
        shutil.rmtree( network_dir )

    # generate config for each peer
    for i in xrange(0, len(peer_ports)):
        peer_port = peer_ports[i]
        hostport = "localhost:%s" % peer_port
        dirp = os.path.join( network_dir, hostport )
        os.makedirs( dirp )

        client_dirp = os.path.join( dirp, 'client')
        os.makedirs( client_dirp )

        # generate server config
        blockstack_conf = blockstack.default_blockstack_opts()
        virtualchain_bitcoin_conf = virtualchain.get_bitcoind_config()

        virtualchain_bitcoin_conf['bitcoind_port'] = 18332
        virtualchain_bitcoin_conf['bitcoind_p2p_port'] = 18444 
        virtualchain_bitcoin_conf['bitcoind_server'] = 'localhost'
        virtualchain_bitcoin_conf['bitcoind_regtest'] = True
        virtualchain_bitcoin_conf['bitcoind_spv_path'] = os.path.join( dirp, "spv_headers.dat" )

        blockstack_conf['rpc_port'] = peer_port
        blockstack_conf['server_version'] = '0.14.0'
        blockstack_conf['zonefiles'] = os.path.join( dirp, 'zonefiles' )
        blockstack_conf['atlas_seeds'] = ",".join( ["localhost:%s" % p for p in seed_relations.get(peer_port, []) ] )
        blockstack_conf['atlas_blacklist'] = ",".join( ["localhost:%s" % p for p in blacklist_relations.get(peer_port, [])] )
        blockstack_conf['atlasdb_path'] = os.path.join( dirp, 'atlas.db' )
        blockstack_conf['atlas_hostname'] = 'localhost'

        bitcoin_conf = {}
        for key in virtualchain_bitcoin_conf.keys():
            if key.startswith("bitcoind_"):
                newkey = key[len('bitcoind_'):]
                bitcoin_conf[newkey] = virtualchain_bitcoin_conf[key]

        conf = {
            'bitcoind': bitcoin_conf,
            'blockstack': blockstack_conf
        }

        conf_path = os.path.join( dirp, 'blockstack-server.ini' )
        log.debug("Save server config for localhost:%s to %s" % (peer_port, conf_path))
        blockstack_client.config.write_config_file( conf, conf_path )

        # copy over client config
        client_config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG")
        client_conf = blockstack_client.config.configure( config_file=client_config_path, force=False, interactive=False )

        # update...
        client_conf['blockstack-client']['queue_path'] = os.path.join(client_dirp, 'queues.db')
        client_conf['blockstack-client']['metadata'] = os.path.join(client_dirp, 'metadata')
        client_conf['blockstack-client']['blockchain_headers'] = virtualchain_bitcoin_conf['bitcoind_spv_path']
        client_conf['blockstack-client']['api_endpoint_port'] = max(peer_ports) + i + 1
        client_conf['blockstack-client']['port'] = peer_port

        new_conf = {
            'blockstack-client': client_conf['blockstack-client'],
            'bitcoind': client_conf['bitcoind'],
            'blockchain-reader': client_conf['blockchain-reader'],
            'blockchain-writer': client_conf['blockchain-writer']
        }

        log.debug("Save client for localhost:%s's to %s" % (peer_port, os.path.join(client_dirp, 'client.ini')))
        blockstack_client.config.write_config_file( new_conf, os.path.join(client_dirp, "client.ini") )

    return {
        'peer_ports': peer_ports,
        'network_dir': network_dir,
        'peers': [],
        'netsrv': None
    }
 

def atlas_network_start( network_des, **network_params ):
    """
    Start runnning the network, given a network state description
    """
    peer_ports = network_des['peer_ports']
    network_dir = network_des['network_dir']

    net = AtlasNetwork( ATLAS_TESTNET_PORT, **network_params )
    srv = AtlasNetworkServer( net )

    srv.start()

    peers = []
    for port in peer_ports:
        hostport = "localhost:%s" % port
        dirp = os.path.join( network_dir, hostport )
        peer = atlas_peer_start( "localhost", port, srv, dirp )
        peers.append(peer)

    network_des['netsrv'] = srv
    network_des['peers'] = peers
    return network_des


def atlas_network_get_peer_conf( network_dir, portnum ):
    """
    Get the peer configuration
    """
    hostport = "localhost:%s" % portnum
    dirp = os.path.join( network_dir, hostport )
    conf_path = os.path.join(dirp, "blockstack-server.ini" )
    conf = blockstack.config.configure( config_file=conf_path, interactive=False )
    return conf


def atlas_network_is_synchronized( network_des, lastblock, num_zonefiles ):
    """
    Is the network synchronized?
    Have all the peers caught up to this block,
    and do they all have the same zonefiles?
    """
    peers = network_des['peers']
    for peer in peers:
        res = atlas_peer_is_synchronized( peer, lastblock, num_zonefiles )
        if res is None:
            raise Exception("Peer %s (%s) failed to respond" % (peer['port'], peer['proc'].pid))

        if not res:
            log.debug("localhost:%s is not synchronized" % peer['port'])
            return False

    return True


def atlas_network_stop( network_des ):
    """
    Stop an atlas network, given a network state description
    """
    srv = network_des['netsrv']
    peers = network_des['peers']

    srv.stop_server()
    for peer in peers:
        log.debug("Join localhost:%s" % peer['port'])
        atlas_peer_join( peer )

    return True


def atlas_peer_start( host, port, srv, working_dir ):
    """
    Start up a peer atlas subprocess
    to communicate on the given network server.
    Return a dict with the peer information.
    """
    net = srv.network
    args = ['blockstack-server', 'start', '--foreground', '--port', str(port)]
    output = os.path.join(working_dir, "blockstack-server.out")

    env = {}

    # preserve test environment variables
    for envar in os.environ.keys():
        if envar.startswith("BLOCKSTACK_") and envar not in ['BLOCKSTACK_CLIENT_CONFIG', 'BLOCKSTACK_SERVER_CONFIG']:
            log.debug("Env: '%s' = '%s'" % (envar, os.environ[envar]))
            env[envar] = os.environ[envar]

    env['VIRTUALCHAIN_WORKING_DIR'] = working_dir
    env['BLOCKSTACK_ATLAS_NETWORK_SIMULATION'] = "1"
    env['BLOCKSTACK_ATLAS_NETWORK_SIMULATION_PEER'] = "1"
    env['BLOCKSTACK_SERVER_CONFIG'] = os.path.join(working_dir, 'blockstack-server.ini')
    env['BLOCKSTACK_CLIENT_CONFIG'] = os.path.join(working_dir, 'client/client.ini')

    env['PATH'] = os.environ['PATH']

    fd = open(output, "w")

    proc = subprocess.Popen( args, stdout=fd, stderr=fd, shell=False, env=env )

    peer_info = {
        'proc': proc,
        'port': port
    }

    return peer_info


def atlas_peer_rpc( peer_info ):
    """
    Get an RPC client to the running peer
    """
    rpc = blockstack_client.BlockstackRPCClient( 'localhost', peer_info['port'], timeout=5 )
    return rpc


def atlas_peer_is_synchronized( peer_info, lastblock, num_zonefiles ):
    """
    Is this peer synchronized?
    Return True if the peer caught up
    Return False if not
    Return None on error
    """

    # see how far we've gotten 
    rpc = atlas_peer_rpc( peer_info )
    info = None
    peer_inv = None

    try:
        info = rpc.getinfo()
    except Exception, e:
        log.exception(e)
        log.error("Peer localhost:%s is down" % (peer_info['port']))
        return False

    if info['last_block_processed'] < lastblock:
        log.debug("Peer localhost:%s is at %s (but we're at %s)" % (peer_info['port'], info['last_block_processed'], lastblock))
        return False

    try:
        peer_inv_info = rpc.get_zonefile_inventory( 0, num_zonefiles )
        peer_inv = atlas_inventory_to_string( base64.b64decode(peer_inv_info['inv']) )
    except Exception, e:
        log.exception(e)
        log.error("Peer localhost:%s is down" % (peer_info['port']))
        return False

    log.debug("inv for localhost:%s is %s.  Require %s zonefiles" % (peer_info['port'], peer_inv, num_zonefiles))
    zonefile_count = 0

    for i in xrange(0, min(len(peer_inv), num_zonefiles)):
        if peer_inv[i] == '1':
            zonefile_count += 1

    if zonefile_count < num_zonefiles:
        return False

    return True


def atlas_peer_join( peer_info ):
    """
    Stop an atlas peer
    """
    proc = peer_info['proc']
    proc.send_signal( signal.SIGTERM )

    time.sleep(0.5)

    rc = proc.returncode
    if rc is None:
        # still running
        time.sleep(1.0)
        if proc.returncode is None:
            try:
                proc.send_signal( signal.SIGKILL )
            except:
                pass
 

def atlas_local_peer_info():
    return {
        "proc": None,
        "port": RPC_SERVER_PORT
    }


def atlas_print_network_state( network_des ):
    """
    Print out the state of the network
    """

    peer_infos = network_des['peers'] + [atlas_local_peer_info()]
    peer_tables = {}

    for i in xrange(0, len(peer_infos)):

        info = None
        neighbor_set = None
        inv_len = None
        peer_inv = None

        if peer_infos[i]['port'] == RPC_SERVER_PORT:
            # don't talk to ourselves
            inv_len = atlas_get_num_zonefiles()
            neighbor_set = atlas_get_all_neighbors()
            peer_inv = atlas_get_zonefile_inventory(0, inv_len)

        else:
            log.debug("query localhost:%s" % peer_infos[i]['port'])
            connected = False
            while True:
                rpc = atlas_peer_rpc( peer_infos[i] )
                try:
                    info = rpc.getinfo()
                    neighbor_set = rpc.get_all_neighbor_info()
                    inv_len = info['zonefile_count']
                    peer_inv = atlas_peer_download_zonefile_inventory( None, "localhost:%s" % peer_infos[i]['port'], inv_len )
                    connected = True
                    break

                except socket.timeout:
                    log.error("Failed to connect to peer localhost:%s" % peer_infos[i]['port'])
                    traceback.print_exc()
                    os.abort()
                except:
                    log.error("Skipping peer localhost:%s" % peer_infos[i]['port'])
                    break

            if not connected:
                return False
        
        peer_inv_str = atlas_inventory_to_string( peer_inv )

        if 'error' in neighbor_set:
            log.error("Failed to get all neighbors: %s" % neighbor_set['error'])
            raise ValueError("Failed to get all neighbor info")

        neighbor_info = []
        for n in neighbor_set.keys():
            h = atlas_peer_get_health( n, peer_table=neighbor_set )
            inv = neighbor_set[n]['zonefile_inv']
            neighbor_info.append( "%s (h=%.3f,inv=%s)" % (n, h, inv))

        node_hostport = str("localhost:%s" % (peer_infos[i]['port']))

        peer_tables[node_hostport] = {}
        peer_tables[node_hostport]['neighbor_set'] = neighbor_set

        # save for later!
        peer_tables[node_hostport]['inv_str'] = peer_inv_str
        peer_tables[node_hostport]['neighbor_info'] = neighbor_info

    for node_hostport in sorted(peer_tables.keys()):
        neighbor_info = peer_tables[str(node_hostport)]['neighbor_info']
        node_inv_str = peer_tables[str(node_hostport)]['inv_str']

        print "-" * 80
        print "%s: %s\nneighbors: %s" % (node_hostport, node_inv_str, ", ".join(neighbor_info))
        print ""

    # measure peer knowledge and zonefile distribution
    peer_count = {}
    for node_hostport in peer_tables.keys():
        peer_table = peer_tables[str(node_hostport)]['neighbor_set']
        for ph in peer_table.keys():
            ph = str(ph)
            if not peer_count.has_key(ph):
                peer_count[ph] = 0

            peer_count[ph] += 1

    print "Neighbor knowledge"
    for node_hostport in sorted(peer_tables.keys()):
        node_inv_str = peer_tables[str(node_hostport)]['inv_str']
        print "%020s (%s): %s" % (node_hostport, node_inv_str, "#" * peer_count.get(str(node_hostport), 0))

    print ""
    sys.stdout.flush()


def atlas_run_simulation( network_des, lastblock, max_iterations=None ):
    """
    Run the network simulation
    """
    network_des = atlas_network_start( network_des )
    itr = 0
    while max_iterations is None or itr < max_iterations:
        atlas_print_network_state( network_des['peers'] )
        time.sleep(1.0)
        if atlas_network_is_synchronized( network_des, lastblock ):
            break

    atlas_network_stop( network_des )
    

'''
class MockDB(object):
    """
    Mock BlockstackDB
    """

    def __init__(self, zonefile_dir):
        self.lastblock = FIRST_BLOCK_MAINNET
        num_per_block = 5
        self.zfstate = {}
        self.num_zonefiles = 0
        self.zonefile_dir = zonefile_dir
        """
        for i in xrange(0, 5):
            self.mock_add_zonefile_hashes(num_per_block + i - 4)

        for i in xrange(0, 5):
            self.mock_dup_zonefile_hashes(self.lastblock - 5)
        """

    def add_zonefile( self, zf ):
        """
        Add a zonefile that we don't have data for.
        """
        zfhash = blockstack_client.get_zonefile_data_hash( str(zf) )
        for height in self.zfstate.keys():
            for zfrec in self.zfstate[height]:
                if zfrec['zonefile_hash'] == zfhash:
                    self.zfstate[height]['zonefile'] = zf


    @classmethod
    def mock_make_zonefile( cls, id_idx ):
        """
        Make a mock zonefile
        """
        new_zf = blockstack_client.user.make_empty_user_zonefile( "testregistration%03d.id" % (id_idx),  
                    "04bd3075d85f2e23d67998ba242e9751036393406bfb17d9b4c0c3652a6d7ff77f601a54bca9e4338336f083a4b6365eef328b55646f22b04979acd5219627b954",
                    ["http://node.blockstack.org:6264/RPC2#testregistration%03d.id" % (id_idx),
                     "file:///home/test/.blockstack/storage-disk/mutable/testregistration%03d.id" % (id_idx)] )

        return new_zf


    def mock_add_zonefile_hashes(self, count, present=True):
        """
        Add zonefiles at block heights
        """
        if not self.zfstate.has_key(self.lastblock):
            self.zfstate[self.lastblock] = []

        for i in xrange(0, count):
            id_idx = len(self.zfstate.keys()) + i
            new_zf = MockDB.mock_make_zonefile( id_idx )
            new_zf_hash = blockstack_client.storage.hash_zonefile( new_zf )

            if not present:
                # have hash, but not zonefile
                new_zf = None

            self.zfstate[self.lastblock].append( {
                "zonefile_hash": new_zf_hash,
                "zonefile": new_zf,
                "inv_index": self.num_zonefiles
            })

            if new_zf is not None:
                log.debug("store zonefile %s" % new_zf['$origin'])
                blockstack.lib.storage.store_cached_zonefile( new_zf, zonefile_dir=self.zonefile_dir )

            self.num_zonefiles += 1

        self.lastblock += 1


    def mock_dup_zonefile_hashes(self, height):
        """
        Duplicate block state from a previous height
        at the current height
        """
        assert height != self.lastblock
        self.zfstate[self.lastblock] = []

        for zfinfo in self.zfstate[height]:
            new_info = {}
            new_info.update( zfinfo )

            new_info['inv_index'] = self.num_zonefiles
            self.num_zonefiles += 1

            self.zfstate[self.lastblock].append( new_info )

        self.lastblock += 1


    def mock_append_zonefile( self, zfhash, zf=None, same_block=False ):
        """
        Push a zonefile hash (and optionally zonefile) into this peer's db.
        """
        if not same_block:
            self.lastblock += 1
            self.zfstate[self.lastblock] = []
        else:
            if not self.zfstate.has_key(self.lastblock):
                self.zfstate[self.lastblock] = []

        if zf is not None:
            assert blockstack_client.storage.hash_zonefile(zf) == zfhash

        new_info = {
            "zonefile_hash": zfhash,
            "zonefile": zf,
            "inv_index": self.num_zonefiles
        }

        self.zfstate[self.lastblock].append( new_info )
        self.num_zonefiles += 1


    def get_value_hashes_at( self, height ):
        return [zf["zonefile_hash"] for zf in self.zfstate.get(height, []) ]


    def get_zonefile( self, zonefile_hash ):
        for _, zfdata in self.zfstate.items():
            for zfrec in zfdata:
                if zfrec['zonefile_hash'] == zonefile_hash:
                    return zfrec['zonefile']

        return None


class AtlasNode(object):
    """
    Simulated atlas node
    """
    def __init__(self, host, port, peer_seeds, peer_blacklist, zonefile_inv, db_path, zonefile_dir, no_db=False):
        """
        Initialize this atlas node's state
        """

        from blockstack import AtlasPeerCrawler, AtlasHealthChecker, AtlasZonefileCrawler

        self.host = host
        self.port = port
        self.db_path = db_path
        self.hostport = "%s:%s" % (host, port)
        self.online = True
        self.zonefile_dir = zonefile_dir

        self.peer_crawler = AtlasPeerCrawler( host, port )
        self.health_checker = AtlasHealthChecker( host, port, path=db_path )
        self.zonefile_crawler = AtlasZonefileCrawler( host, port, zonefile_storage_drivers=["disk"], path=db_path, zonefile_dir=zonefile_dir )
        self.zonefile_pusher = AtlasZonefilePusher( host, port )

        subprocs = [
            "AtlasPeerCrawler",
            "AtlasHealthChecker",
            "AtlasZonefileCrawler",
            "AtlasZonefilePusher"
        ]

        self.sleep_deadlines = dict( [(subp, 0) for subp in subprocs] )
        self.wait_deadlines = dict( [(subp, 0) for subp in subprocs] )

        self.db = MockDB(zonefile_dir)
        
        for i in xrange(0, len(zonefile_inv)):
            for j in xrange(0, 8):
                bit_index = (1 << (7 - j))
                if (ord(zonefile_inv[i]) & bit_index) == 0:
                    self.db.mock_add_zonefile_hashes( 1, present=False )
                else:
                    self.db.mock_add_zonefile_hashes( 1, present=True )

        if not no_db:
            self.peer_table = atlasdb_init( self.db_path, self.db, peer_seeds, peer_blacklist, zonefile_dir=zonefile_dir )

        self.peer_queue = []
        self.zonefile_queue = []
        self.network = None


    def set_network( self, n ):
        self.network = n


    def state_to_string( self ):
        """
        Get a string representation of the node state
        """
        procs_sleep = sorted(self.sleep_deadlines.keys())

        sleep_strs = []
        for p in procs_sleep:
            status = "R"

            if self.is_waiting(p, self.network.time ):
                status = "W"

            elif self.is_asleep(p, self.network.time ):
                status = "S"

            sleep_strs.append( "%s:%s" % (p, status) )

        return " ".join(sleep_strs)


    def updown( self, status ):
        """
        Set availability
        """
        self.online = status


    def set_sleep_deadline( self, procname, deadline ):
        """
        Stay asleep until the given deadline
        """
        self.sleep_deadlines[procname] = deadline


    def set_wait_deadline( self, procname, deadline ):
        """
        Waiting for a blocking operation
        """

        self.wait_deadlines[procname] = deadline


    def is_asleep(self, procname, simtime ):
        """
        Is this node process sleeping at the current simulated time?
        """
        return self.sleep_deadlines[procname] > simtime or self.wait_deadlines[procname] > simtime


    def is_waiting(self, procname, simtime ):
        """
        Is this node process waiting?
        """
        return self.wait_deadlines[procname] > simtime


    def append_zonefile(self, zfhash, zf=None ):
        """
        Add a zonefile to this node's state
        """
        self.db.mock_append_zonefile( zfhash, zf=zf )

        if zf is not None:
            log.debug("store zonefile %s" % zf['$origin'])
            blockstack.lib.storage.store_cached_zonefile( zf, zonefile_dir=self.zonefile_dir )

        atlasdb_add_zonefile_info( zfhash, (zf is not None), self.db.lastblock, path=self.db_path)


class AtlasStaticNetwork( SocketServer.ThreadingMixin, SimpleXMLRPCServer ):
    
    """
    Static network test: don't actually run a network,
    but just call each node's algorithm's step()
    function in a random loop
    """

    def __init__(self, nodes, **network_params):
        """
        @nodes is a list of AtlasNodes
        @network_params includes:
        * drop_probability (callable(hostport)): probability that a message gets dropped
        * peer_delay (callable(hostport)): function that returns the amount of iterations to sleep on getting a peer's neighbors
        * inv_delay (callable(hostport)): function that returns the amount of iterations to sleep on getting a peer's inventory
        * zonefile_delay (callable(hostport, num_zfs)): function that returns the amount of iterations to sleep on getting a peer's zonefiles (given the number of zonefiles)
        * max_neighbors (int): maximum number of node neighbors (defaults to 80)
        * peer_ping_interval (int): maximum ttl of a peer's state before we ask again (default is 60)
        * peer_lifetime_interval (int): maximum ttl of a peer's liveness data
        * zonefile_generator (callable(int) --> hostport): function that takes the current simulator time and returns a (hostport, zonefile) to push
        """
        
        SimpleXMLRPCServer.__init__(self, ('127.0.0.1', RPC_SERVER_PORT), AtlasNetworkRPCHandler, allow_none=True )
        self.time = 0
        self.node_hosts = dict( [(n.hostport, n) for n in nodes] )
        for _, node in self.node_hosts.items():
            node.set_network(self)

        self.drop_probability = network_params.get( "drop_probability", lambda hostport_src, hostport_dst: 0 )
        self.peer_delay = network_params.get( "peer_delay", lambda hostport: 0 )
        self.inv_delay = network_params.get( "inv_delay", lambda hostport: 0 )
        self.zonefile_delay = network_params.get("zonefile_delay", lambda hostport, num_zfs: 0 )
        self.max_neighbors = network_params.get("max_neighbors", 3)
        self.peer_ping_interval = network_params.get("peer_ping_interval", 3)
        self.peer_lifetime_interval = network_params.get("peer_lifetime_interval", 10)
        self.peer_max_age = network_params.get("peer_max_age", 10)
        self.peer_clean_interval = network_params.get("peer_clean_interval", 3)
        self.zonefile_generator = network_params.get("zonefile_generator", lambda cur_time: None)

        # register methods 
        for attr in dir(self):
            if attr.startswith("rpc_"):
                method = getattr(self, attr)
                if callable(method) or hasattr(method, '__call__'):
                    self.register_function( method )


    def step(self):
        """
        Run one step of the simulation
        """

        # run time-based callbacks
        hostport = self.zonefile_generator( self.time )
        if hostport is not None:
            
            zf_id = max( [self.node_hosts[ph].db.num_zonefiles for ph in self.node_hosts.keys()] ) + 1

            for node_hostport in self.node_hosts.keys():

                # make a new zonefile
                new_zf = MockDB.mock_make_zonefile( zf_id )
                zfhash = blockstack_client.storage.hash_zonefile(new_zf)

                if node_hostport == hostport:
                    self.node_hosts[node_hostport].append_zonefile( zfhash, zf=new_zf )
                else:
                    self.node_hosts[node_hostport].append_zonefile( zfhash )

        node_order = self.node_hosts.keys()
        random.shuffle( node_order )
        for node_hostport in node_order:
            n = self.node_hosts[node_hostport]

            print "\n\nStep %s" % node_hostport
            if not n.is_asleep( "AtlasPeerCrawler", self.time ):
                # ready for next neighbor crawl
                if not n.is_waiting( "AtlasPeerCrawler", self.time ):
                    # crawl "initiated", but will wait for it to complete
                    delay = self.peer_delay( n.hostport )
                    n.set_wait_deadline( "AtlasPeerCrawler", self.time + delay )

            if not n.is_waiting( "AtlasPeerCrawler", self.time ):
                # no longer waiting
                inv = atlas_make_zonefile_inventory( 0, atlasdb_zonefile_inv_length(path=n.db_path), path=n.db_path )
                n.peer_crawler.step( local_inv=inv, peer_table=n.peer_table, peer_queue=n.peer_queue, path=n.db_path )
            
            if not n.is_asleep( "AtlasHealthChecker", self.time ):
                # ready for next health check
                if not n.is_waiting( "AtlasHealthChecker", self.time ):
                    # health check "initiated", but will wait for it to complete 
                    delay = self.inv_delay( n.hostport )
                    n.set_wait_deadline( "AtlasHealthChecker", self.time + delay )

            if not n.is_waiting( "AtlasHealthChecker", self.time ):
                # no longer waiting
                n.health_checker.step( peer_table=n.peer_table, path=n.db_path )

            
            if not n.is_asleep( "AtlasZonefileCrawler", self.time ):
                # ready for next zonefile crawl
                if not n.is_waiting( "AtlasZonefileCrawler", self.time ):
                    # crawl "initiated", but will wait for it to complete
                    delay = self.peer_delay( n.hostport )
                    n.set_wait_deadline( "AtlasZonefileCrawler", self.time + delay )

            if not n.is_waiting( "AtlasZonefileCrawler", self.time ):
                # no longer waiting
                n.zonefile_crawler.step( peer_table=n.peer_table, path=n.db_path )
 

            if not n.is_asleep( "AtlasZonefilePusher", self.time ):
                # ready for next zonefile push 
                if not n.is_waiting( "AtlasZonefilePusher", self.time ):
                    # begin push 
                    delay = self.peer_delay( n.hostport )
                    n.set_wait_deadline( "AtlasZonefilePusher", self.time + delay )

            if not n.is_waiting( "AtlasZonefilePusher", self.time ):
                # no longer waiting 
                n.zonefile_pusher.step( peer_table=n.peer_table, zonefile_queue=n.zonefile_queue )

        self.time += 1

   
    def get_node_db( self, hostport ):
        """
        Get a node's blockstack db
        """
        node = self.node_hosts.get(hostport, None)
        assert node is not None
        return node.db


    def get_atlasdb_path( self, hostport ):
        """
        Get the path to a node's atlasdb
        """
        node = self.node_hosts.get(hostport, None)
        assert node is not None
        return node.db_path


    def get_node( self, hostport ):
        """
        Get a node
        """
        node = self.node_hosts.get(hostport, None)
        assert node is not None
        return node


    def get_peer_table( self, hostport ):
        """
        Get a peer table
        """
        node = self.node_hosts.get(hostport, None)
        assert node is not None
        return node.peer_table
        

    def is_dropped( self, dst ):
        """
        will the message to dst be dropped?
        return True if so
        return False if not
        """
        prob = self.drop_probability( dst )
        return random.random() < prob


    def add_node( self, node ):
        """
        Add a node to the network
        """
        assert node.hostport not in self.node_hosts.keys()
        self.node_hosts[node.hostport] = node


    def get_nodes( self ):
        """
        Get all nodes
        """
        return self.node_hosts

    
    def possibly_drop(self, hostport):
        """
        Possibly drop the connection
        """
        prob = self.drop_probability( hostport )
        if random.random() < prob:
            se = socket.error()
            se.errno = errno.ECONNREFUSED
            raise se


    def rpc_get_zonefile_inventory( self, src_hostport, dest_hostport, bit_offset, bit_len ):
        """
        Get zonefile inventory from the given dest hostport, with simulated loss
        """
        self.possibly_drop( dest_hostport )
        atlasdb_path = self.get_atlasdb_path( dest_hostport )
        inv = atlas_make_zonefile_inventory( bit_offset, bit_len, path=atlasdb_path )
        return {'status': True, 'inv': base64.b64encode(inv)}


    def rpc_get_atlas_peers( self, src_hostport, dest_hostport ):
        """
        Get the list of peers in this peer's neighbor set, with simulated loss.
        Give the receiver the src hostport
        """
        self.possibly_drop( dest_hostport )
        peer_table = self.get_peer_table( dest_hostport )

        neighbors = atlas_get_live_neighbors( src_hostport, peer_table=peer_table )
        random.shuffle( neighbors )
        if len(neighbors) > self.max_neighbors:
            neighbors = neighbors[:self.max_neighbors]
       
        # dest remembers src
        node = self.get_node( dest_hostport )
        atlas_peer_enqueue( src_hostport, peer_table=peer_table, peer_queue=node.peer_queue, max_neighbors=self.max_neighbors )

        return {'status': True, 'peers': neighbors}


    def rpc_get_zonefiles( self, src_hostport, dest_hostport, zonefile_hashes ):
        """
        Get the list of zonefiles, given the zonefile hashes (with simulated loss)
        Returns [{'zonefile hash': zonefile data}]
        """
        self.possibly_drop( dest_hostport )
        db = self.get_node_db( dest_hostport )

        ret = []
        for zfh in zonefile_hashes:
            if db.get_zonefile( zfh ) is None:
                # maybe stored
                zf = get_cached_zonefile( zfh, zonefile_dir=db.zonefile_dir )
                if zf is None:
                    log.debug("Node %s does not have zonefile %s in %s" % (dest_hostport, zfh, db.zonefile_dir))
                    continue

                else:
                    ret.append( {zfh: blockstack_zones.make_zone_file(zf)} )

            else:
                ret.append({zfh: blockstack_zones.make_zone_file(db.get_zonefile(zfh))})

        return {'status': True, 'zonefiles': ret}

    
    def rpc_put_zonefiles( self, src_hostport, dest_hostport, zonefile_info ):
        """
        Upload a list of zonefiles, and enqueue them in the pusher
        """
        self.possibly_drop( dest_hostport )
        node = self.get_node( zonefile_info )
        atlasdb_path = self.get_atlasdb_path( dest_hostport )
        db = node.get_node_db( dest_hostport )
        for zfdata in zonefile_info:
            zf = blockstack_zones.parse_zone_file( str(zfdata) )
            zfhash = blockstack_client.get_zonefile_data_hash( str(zfdata) )

            # put to the db
            db.add_zonefile( zf )

            # update atlas
            was_missing = atlasdb_set_zonefile_present( zonefile_hash, True, path=atlasdb_path )
            if was_missing:
                # we didn't have this zonefile.
                # there's a good chance we're not alone (i.e. this request came from a client).
                # see if we can replicate it to them in the background.
                atlas_zonefile_push_enqueue( zonefile_hash, str(zonefile_data), peer_table=node.peer_table, zonefile_queue=node.zonefile_queue, path=atlasdb_path )


    def rpc_ping( self, dest_hostport ):
        """
        Ping!
        """
        return {'alive': True}


    def rpc_add_sleep_deadline( self, hostport, procname, value ):
        """
        make the given host sleep
        """
        deadline = self.time + value
        node = self.get_node( hostport )
        node.set_sleep_deadline( procname, value )


    def rpc_max_neighbors( self ):
        """
        how many neighbors can a peer have?
        """
        return self.max_neighbors


    def rpc_peer_lifetime_interval( self ):
        """
        what's a peer's lifetime interval?
        """
        return self.peer_lifetime_interval


    def rpc_peer_ping_interval( self ):
        """
        what's a peer's ping interval?
        """
        return self.peer_ping_interval

    
    def rpc_time_now( self ):
        """
        what's the time now?
        """
        return self.time


    def rpc_peer_max_age( self ):
        """
        what's the maximum peer age?
        """
        return self.peer_max_age

    
    def rpc_peer_clean_interval( self ):
        """
        what's the peer clean interval?
        """
        return self.peer_clean_interval


def print_static_network_state( network ):
    """
    Print out the state of the network
    """
    node_hostports = sorted(network.get_nodes().keys())
    for node_hostport in node_hostports:
        node = network.get_node( node_hostport )
        peer_table = network.get_peer_table( node_hostport )
        node_inv = atlas_make_zonefile_inventory( 0, atlasdb_zonefile_inv_length(path=node.db_path), path=network.get_atlasdb_path( node_hostport ))
        node_inv_str = atlas_inventory_to_string( node_inv )
        neighbors = sorted(network.get_peer_table( node_hostport ).keys())

        neighbor_info = []
        for n in neighbors:
            h = atlas_peer_get_health( n, peer_table=peer_table )
            inv = atlas_inventory_to_string( peer_table[n]['zonefile_inv'] )
            neighbor_info.append( "%s (h=%.3f,inv=%s)" % (n, h, inv))

        print "-" * 80
        print "%s: %s   State: %s\nneighbors: %s" % (node_hostport, node_inv_str, network.get_node(node_hostport).state_to_string(), ", ".join(neighbor_info))
        print ""

    # measure peer knowledge and zonefile distribution
    peer_count = {}
    for node_hostport in node_hostports:
        peer_count[node_hostport] = 0

    for node_hostport in node_hostports:
        peer_table = network.get_peer_table( node_hostport )
        for ph in peer_table.keys():
            peer_count[ph] += 1

    print "Neighbor knowledge"
    for node_hostport in node_hostports:
        node_inv = atlas_make_zonefile_inventory( 0, atlasdb_zonefile_inv_length(path=node.db_path), path=network.get_atlasdb_path( node_hostport ))
        node_inv_str = atlas_inventory_to_string( node_inv )
        print "%020s (%s): %s" % (node_hostport, node_inv_str, "#" * peer_count[node_hostport])

    print ""


def load_flat_simulation( num_nodes, num_seed_nodes, num_zonefiles, test_root_dir, **network_params ):
    """
    Make a random simulated network,
    with the given number of nodes and a given number
    of seed nodes that everyone knows about.

    Return (network, inventory vector that the seed nodes have)
    """

    shutil.rmtree(test_root_dir)
    os.makedirs(test_root_dir)

    seed_node_hostports = []
    for i in xrange(0, num_seed_nodes):
        seed_node_hostports.append( "seed_%03d:%s" % (i, RPC_SERVER_PORT))

    seed_inv = 0
    for i in xrange(0, num_zonefiles):
        bit_index = 7 - (i % 8)
        byte_index = i / 8
        seed_inv = seed_inv | (1 << (byte_index * 8 + bit_index))

    seed_inv = binascii.unhexlify( "%x" % seed_inv )
    peer_inv = '\0' * len(seed_inv)

    print "seed_inv = %s" % binascii.hexlify(seed_inv)
    print "peer_inv = %s" % binascii.hexlify(peer_inv)

    seed_nodes = []
    for i in xrange(0, num_seed_nodes):
        atlasdb_path = os.path.join(test_root_dir, "atlas_seed_%03d.db" % i)
        zonefile_dir = os.path.join(test_root_dir, "zonefile_seed_%03d.db" % i)

        os.makedirs(zonefile_dir)
        
        node = AtlasNode( "seed_%03d" % i, RPC_SERVER_PORT, [], [], seed_inv, atlasdb_path, zonefile_dir )
        seed_nodes.append( node )

    peer_nodes = []
    last_neighbor = None
    if len(seed_node_hostports) > 0:
        last_neighbor = seed_node_hostports[-1]

    for i in xrange(0, num_nodes):
        atlasdb_path = os.path.join(test_root_dir, "atlas_peer_%03d.db" % i)
        zonefile_dir = os.path.join(test_root_dir, "zonefile_peer_%03d.db" % i)

        os.makedirs(zonefile_dir)

        # node = AtlasNode("peer_%03d" % i, RPC_SERVER_PORT, [last_neighbor], [], peer_inv, atlasdb_path, zonefile_dir )
        # node = AtlasNode("peer_%03d" % i, RPC_SERVER_PORT, seed_node_hostports, [], peer_inv, atlasdb_path, zonefile_dir )
        node = AtlasNode("peer_%03d" % i, RPC_SERVER_PORT, ["peer_000:%s" % RPC_SERVER_PORT], [], peer_inv, atlasdb_path, zonefile_dir )
        
        # if i == 5:
        #    node = AtlasNode("peer_%03d" % i, RPC_SERVER_PORT, ["seed_000:%s" % RPC_SERVER_PORT, "peer_000:%s" % RPC_SERVER_PORT], [], peer_inv, atlasdb_path, zonefile_dir )
        #
        # else:
        #    node = AtlasNode("peer_%03d" % i, RPC_SERVER_PORT, ["peer_000:%s" % RPC_SERVER_PORT], [], peer_inv, atlasdb_path, zonefile_dir )

        peer_nodes.append( node )

        last_neighbor = "peer_%03d" % i

    network = AtlasStaticNetwork( seed_nodes + peer_nodes, **network_params )

    return network, seed_inv


def static_network_is_converged( network, inv ):
    """
    Have all nodes obtained the zonefiles in the given inventory?
    """
    nodes = network.get_nodes()
    for node_hostport in nodes.keys():
        node = nodes[node_hostport]
        peer_table = network.get_peer_table( node_hostport )
        peer_inv = atlas_make_zonefile_inventory( 0, atlasdb_zonefile_inv_length(path=node.db_path), path=node.db_path )
        if atlas_inventory_count_missing( peer_inv, inv ) != 0:
            return False

    return True


def network_shutdown( network ):
    network.stop_server()


def drop_random_50( dest_hostport ):
    r = random.random()
    if r < 0.5:
        # 50% drop
        return True

    else:
        return False


def drop_random_30( dest_hostport ):
    r = random.random()
    if r < 0.3:
        # 30% drop
        return True

    else:
        return False


def drop_random_70( dest_hostport ):
    r = random.random()
    if r < 0.7:
        # 70% drop
        return True

    else:
        return False


def drop_seed_90( dest_hostport ):
    if dest_hostport.startswith("seed_"):
        r = random.random()
        if r < 0.9:
            # 90% drop if seed
            return True

    return False


def push_zonefile_every_5( curtime ):
    if curtime % 5 == 0:
        # push a zonefile to peer_000
        return "peer_000:%s" % RPC_SERVER_PORT 
    else:
        return None


def run_static_simulation( network, seed_inv ):
    """
    Run a static atlas network
    Run until converged
    """
    set_network_state( network )
    network_server = AtlasNetworkServer( network )

    atexit.register( network_shutdown, network_server )
    signal.signal( signal.SIGINT, sys.exit, 0 )
    signal.signal( signal.SIGTERM, sys.exit, 0 )

    network_server.start()
    while True:
        
        network.step()
        
        print "time: %s" % network.time

        print_static_network_state( network )

        if static_network_is_converged( network, seed_inv ):
            break

        time.sleep(1.0)

'''

'''
if __name__ == "__main__":
    zonefile_dir = "/tmp/atlas-zonefiles-flat"
    if os.path.exists(zonefile_dir):
        shutil.rmtree(zonefile_dir)

    os.makedirs(zonefile_dir)
    blockstack_client.session( config_path=sys.argv[1] )

    virtualchain.setup_virtualchain( impl=blockstack.lib.virtualchain_hooks )
    
    network, seed_inv = load_flat_simulation( 10, 0, 1, zonefile_dir, zonefile_generator=push_zonefile_every_5 )
    run_simulation( network, seed_inv )
'''

'''
# unit tests
if __name__ == "__main__":
    
    def test_atlasdb_add_zonefile_info( db, path ):
        """
        Test adding more zonefile hashes
        """
        log.debug("test atlasdb_add_zonefile_info()")
        db.mock_add_zonefile_hashes(5)
        new_zonefile_hashes = db.get_value_hashes_at( db.lastblock )
        for zfh in new_zonefile_hashes:
            atlasdb_add_test_info( zfh, False, db.lastblock, path=path )


    def test_atlasdb_zonefile_info_list( db, block_height, path ):
        """
        Test getting zonefile hashes
        """
        log.debug("test atlasdb_zonefile_info_list(%s)" % block_height)
        zonefile_hashes = db.get_value_hashes_at( block_height )
        zfinfo = atlasdb_zonefile_info_list( block_height, block_height, path=path )

        # order and quantity preserved
        actual_zonefile_hashes = [zf['zonefile_hash'] for zf in zfinfo]
        assert zonefile_hashes == actual_zonefile_hashes, "Expected at %s: %s, actual: %s" % (block_height, zonefile_hashes, actual_zonefile_hashes)


    def test_atlasdb_set_zonefile_present( db, block_height, path ):
        """
        Test setting zonefiles as present or absent
        """
        log.debug("test atlasdb_set_zonefile_present(%s)" % block_height)
        zonefile_hashes = db.get_value_hashes_at( block_height )
        for zfh in zonefile_hashes:
            atlasdb_set_zonefile_present( zfh, True, path=path )
            zfinfo = atlasdb_get_zonefile( zfh, path=path )
            assert zfinfo['present'], "Not present: %s" % zfh

        for zfh in zonefile_hashes:
            atlasdb_set_zonefile_present( zfh, False, path=path )
            zfinfo = atlasdb_get_zonefile( zfh, path=path )
            assert not zfinfo['present'], "Still present: %s" % zfh


    def test_atlasdb_get_zonefile_bits( db, block_height, path ):
        """
        Test getting a zonefile's inventory bits
        """
        log.debug("test atlasdb_get_zonefile_bits(%s)" % block_height)
        zonefile_hashes = db.get_value_hashes_at( block_height )
        for zfh in zonefile_hashes:
            bits = atlasdb_get_zonefile_bits( zfh, path=path )
            
            # must match what we put in
            expected_bits = []
            idx = 0
            for height in sorted(db.zfstate.keys()):
                for zfinfo in db.zfstate[height]:
                    if zfinfo['zonefile_hash'] == zfh:
                        expected_bits.append(idx)

                    idx += 1

            assert expected_bits == bits, "Bits mismatch on %s: %s != %s" % (block_height, bits, expected_bits)


    def test_atlasdb_zonefile_info_list_by_hash( db, zonefile_hash, path ):
        """
        Test listing all zonefile information, from start block to end
        """
        log.debug("test atlasdb_zonefile_info_list_by_hash(%s)" % zonefile_hash)
        zflisting = atlasdb_zonefile_info_list( FIRST_BLOCK_MAINNET, db.lastblock, path=path )
        idx = 0
        while idx < len(zflisting):

            zfl = zflisting[idx]

            # must match what we put in
            bh = zfl['block_height']
            for zfs in db.zfstate[bh]:
                assert zfs['zonefile_hash'] == zflisting[idx]['zonefile_hash'], "zonefile mismatch at index %s: %s != %s" % (idx, zfs['zonefile_hash'], zflisting[idx]['zonefile_hash'])
                assert zfs['inv_index'] == idx, "zonefile inv idx mismatch: %s != %s" % (idx, zfl[idx]['inv_index'])
                idx += 1


    def test_atlas_make_zonefile_inventory( db, path ):
        """
        Test making a zonefile inventory vector
        """
        log.debug("test atlas_make_zonefile_inventory()")

        # mark a subset of zonefiles as "present"
        for height in xrange(FIRST_BLOCK_MAINNET, db.lastblock):
            zonefile_hashes = db.get_value_hashes_at( height )
            if len(zonefile_hashes) > 0 and height % 2 == 0:
                i = random.randint(0, len(zonefile_hashes)-1)
                zfh = zonefile_hashes[i]
                atlasdb_set_zonefile_present( zfh, True, path=path )
                log.debug("   %s is now present" % (zfh))

        inv_vec = atlas_make_zonefile_inventory( 0, atlasdb_zonefile_inv_length(path=path), path=path )

        # convert to array of bools
        inv_bool = []
        for i in xrange(0, len(inv_vec)):

            for j in xrange(7, -1, -1):
                if (ord(inv_vec[i]) & (1 << j)) != 0:
                    inv_bool.append( True )
                else:
                    inv_bool.append( False )

        # verify that it matches the db
        zflisting = atlasdb_zonefile_info_list( FIRST_BLOCK_MAINNET, db.lastblock, path=path )
        assert len(inv_bool) >= len(zflisting), "Less inv than zonefiles"

        for i in xrange(0, len(zflisting)):
            assert zflisting[i]['present'] == inv_bool[i], "Present mismatch at %s: %s" % (i, zflisting[i]['zonefile_hash'])

        assert inv_vec == blockstack.atlas.ZONEFILE_INV, "Inv mismatch: %s != %s" % (binascii.hexlify(inv_vec), binascii.hexlify(blockstack.atlas.ZONEFILE_INV))
    
        

    db = MockDB()
    for i in xrange(0, 5):
        db.mock_add_zonefile_hashes(i + 1)

    for i in xrange(0, 5):
        db.mock_dup_zonefile_hashes(db.lastblock - 5)

    testdir = "/tmp/atlas_unit_tests"
    test_db_path = "/tmp/atlas_unit_tests/atlas.db"
    test_peer_seeds = ['node.blockstack.org:6264']
    zonefile_dir = "/tmp/atlas_unit_tests/zonefiles/"

    if os.path.exists(testdir):
        shutil.rmtree(testdir)

    os.makedirs( os.path.dirname(test_db_path) )
    os.makedirs( zonefile_dir )

    virtualchain.setup_virtualchain( impl=blockstack.lib.virtualchain_hooks )

    PEER_TABLE = atlasdb_init( test_db_path, db, test_peer_seeds, [], zonefile_dir=zonefile_dir )

    """
    Zonefile methods
    """
    if os.environ.get("BLOCKSTACK_ATLAS_UNIT_TEST_DB_SKIP", None) is None:
        test_atlasdb_add_zonefile_info( db, test_db_path )

        for height in xrange(FIRST_BLOCK_MAINNET, db.lastblock-1):
            test_atlasdb_zonefile_info_list( db, height, test_db_path )
            test_atlasdb_set_zonefile_present( db, height, test_db_path )
            test_atlasdb_get_zonefile_bits( db, height, test_db_path )

        for height, zfl in db.zfstate.items():
            for zfs in zfl:
                test_atlasdb_zonefile_info_list_by_hash( db, zfs['zonefile_hash'], test_db_path )

        test_atlas_make_zonefile_inventory( db, test_db_path)

    """
    Peer methods
    """
    peers = ['host1:12345', 'host2:12345', 'host3:12345']
    zonefile_hashes = ["68fbe96e69c0531e9bb741c15e8c1b323f9857b5",
                        "3cee7bb465b00c2495caf5de8724ac3de9b449e2",
                        "e7f84f57c073f9c08bda6a7f07277278ad5aa33c",
                        "28898fdfee4c5f72c09adf97daeb0caeadb12bee",
                        "d4712e9953bbe47450322197e706163af16d09b6",
                        "28898fdfee4c5f72c09adf97daeb0caeadb12bee",    # dup
                        "aba487f174e2a11cc43b621b64433daf72f69d38" ]

    peer_table = {}
    for i in xrange(0, len(peers)):
        atlas_init_peer_info( peer_table, peers[i] )

    # first one is healthy
    # middle one is meh
    # last one is unhealthy
    for i in xrange( 0, 6 ):
        # available 6/6 time
        atlas_peer_update_health( peers[0], True, peer_table=peer_table )

    for i in xrange( 0, 6 ):
        # available 3/6 time
        atlas_peer_update_health( peers[1], i >= 3, peer_table=peer_table )

    for i in xrange( 0, 6 ):
        # available 1/6 time
        atlas_peer_update_health( peers[2], i >= 5, peer_table=peer_table )

    healths = []
    for i in xrange(0, len(peers)):
        healths.append( atlas_peer_get_health(peers[i], peer_table=peer_table) )
    
    assert healths[0] >= 0.99, "health of %s is %s" % (peers[0], healths[0])
    assert healths[1] >= 0.5 and healths[1] <= 0.51, "health of %s is %s" % (peers[1], healths[2])
    assert healths[2] >= 1.0/6.0 and healths[2] <= 0.17, "health of %s is %s" % (peers[2], healths[2])

    assert atlas_peer_is_live( peers[0], peer_table, min_health=0.5 )
    assert atlas_peer_is_live( peers[1], peer_table, min_health=0.49 ), "peer %s is dead (health is %s)" % (peers[1], healths[1])
    assert not atlas_peer_is_live( peers[2], peer_table, min_health=0.5 ), "peer %s is alive (health is %s)" % (peers[2], healths[2])

    # peer 0 is popular--known by everyone
    atlas_peer_add_neighbor( peers[1], peers[0], peer_table=peer_table )
    atlas_peer_add_neighbor( peers[2], peers[0], peer_table=peer_table )

    live_peers = atlas_get_rarest_live_peers( peer_table=peer_table, min_health=0.49 )
    assert live_peers == [peers[1], peers[0]], "rarest live peers = %s" % live_peers

    peers_by_health = atlas_rank_peers_by_health( peer_table=peer_table )
    assert peers_by_health == [peers[0], peers[1], peers[2]]

    # peer 1 knows every zonefile
    # peer 2 knows nothing
    peer2_zonefile_info = []
    peer0_expected_inv_value = 0
    for i in xrange(0, len(zonefile_hashes)):
        bits = []
        for j in xrange(0, len(zonefile_hashes)):
            if zonefile_hashes[j] == zonefile_hashes[i]:
                bits.append(j)

        atlas_peer_set_zonefile_status( peers[0], zonefile_hashes[i], True, zonefile_bits=bits, peer_table=peer_table )
        peer2_zonefile_info.append({
            "inv_index": i,
            "zonefile_hash": zonefile_hashes[i],
            "present": False,
            "block_height": FIRST_BLOCK_MAINNET + i
        })

        peer0_expected_inv_value = peer0_expected_inv_value | (1 << (len(zonefile_hashes) - i))

    peer0_expected_inv = "%x" % peer0_expected_inv_value
    peer0_zonefile_inv = binascii.hexlify( peer_table[peers[0]]['zonefile_inv'] )
    assert peer0_expected_inv == peer0_zonefile_inv, "Inv mismatch: %s != %s" % (peer0_expected_inv, peer0_zonefile_inv)

    # peer 2 should discover that peer 1 has the zonefiles
    res = atlas_find_missing_zonefile_availability( peer_table=peer_table, missing_zonefile_info=peer2_zonefile_info )
    for i in xrange(0, len(zonefile_hashes)):
        zfhash = zonefile_hashes[i]
        zfinfo = res[zfhash]
        assert peers[0] in zfinfo['peers'], "Missing %s for %s\n%s" % (peers[0], zfhash, simplejson.dumps(res, indent=4, sort_keys=True))
        assert zfinfo['popularity'] == 1, "%s popularity is %s\n%s" % (zfhash, zfinfo['popularity'], simplejson.dumps(res, indent=4, sort_keys=True))

        bits = []
        for j in xrange(0, len(zonefile_hashes)):
            if zonefile_hashes[j] == zonefile_hashes[i]:
                bits.append(j)

        assert zfinfo['indexes'] == bits, "bits for %s: %s\n%s" % (zfhash, bits, simplejson.dumps(peer2_zonefile_info, indent=4, sort_keys=True))

'''
