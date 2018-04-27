#!/usr/bin/env python2
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
import virtualchain

from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler

from blockstack.lib.config import FIRST_BLOCK_MAINNET
from virtualchain import get_logger
from blockstack.lib.util import url_to_host_port, atlas_inventory_to_string
from blockstack.lib.client import BlockstackRPCClient
from blockstack.lib.atlas import atlas_peer_download_zonefile_inventory, atlas_get_num_zonefiles, atlas_get_all_neighbors, atlas_get_zonefile_inventory, atlas_peer_get_health

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


    def atlas_peer_exchange(self, remote_peer):
        """
        Exchange this peer with the remote peer's neighbors
        """
        return self.rpc.atlas_peer_exchange('atlas_network', self.src_hostport, self.dest_hostport, remote_peer)


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
            se = socket.error("Connection Refused: dropped {}-{}".format(src_hostport, dest_hostport))
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


    def rpc_atlas_peer_exchange( self, src_hostport, dest_hostport, remote_peer ):
        """
        Get the list of peers in this peer's neighbor set, with simulated loss.
        """
        log.debug("atlas network: atlas_peer_exchange(%s,%s)" % (src_hostport, dest_hostport))
        self.possibly_drop( src_hostport, dest_hostport )

        dest_host, dest_port = url_to_host_port( dest_hostport )
        rpc = BlockstackRPCClient( dest_host, dest_port, src=src_hostport )
        return rpc.atlas_peer_exchange( 'atlas_network', src_hostport, dest_hostport, remote_peer )


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


def atlas_network_build( working_dir, peer_ports, seed_relations, blacklist_relations, network_dir ):
    """
    Construct a network with the given initial topology and properties.
    Return a dict of network state, which can be fed into atlas_network_start.
    """

    import scenarios.testlib as testlib

    if os.path.exists(network_dir):
        shutil.rmtree( network_dir )

    # generate config for each peer
    for i in xrange(0, len(peer_ports)):
        peer_port = peer_ports[i]
        hostport = "localhost:%s" % peer_port
        dirp = os.path.join( network_dir, hostport )

        res = testlib.peer_make_config(working_dir, peer_port, dirp, seed_relations=seed_relations, blacklist_relations=blacklist_relations)
        if not res:
            print("Failed to make config in {}".format(dirp))
            return None

    return {
        'global_working_dir': working_dir,
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
        peer = atlas_peer_start( network_des['global_working_dir'], port, srv, dirp )
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
    conf = blockstack.config.configure( dirp, config_file=conf_path, interactive=False )
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


def atlas_peer_start( global_working_dir, port, srv, working_dir ):
    """
    Start up a peer atlas subprocess
    to communicate on the given network server.
    Return a dict with the peer information.
    """
    import scenarios.testlib as testlib
    return testlib.peer_start( global_working_dir, working_dir, port=port )


def atlas_peer_rpc( peer_info ):
    """
    Get an RPC client to the running peer
    """
    import scenarios.testlib as testlib
    return testlib.peer_rpc( peer_info )


def atlas_peer_is_synchronized( peer_info, lastblock, num_zonefiles ):
    """
    Is this peer synchronized?
    Return True if the peer caught up
    Return False if not
    Return None on error
    """
    import scenarios.testlib as testlib
    return testlib.peer_has_zonefiles(peer_info, lastblock, num_zonefiles)


def atlas_peer_join( peer_info ):
    """
    Stop an atlas peer
    """
    import scenarios.testlib as testlib
    return testlib.peer_join(peer_info)
 

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
                    # os.abort()
                except Exception as e:
                    log.exception(e)
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
    
