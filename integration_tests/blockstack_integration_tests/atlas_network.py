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

import blockstack
import blockstack_client
import virtualchain

from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler

from blockstack_client.config import FIRST_BLOCK_MAINNET
from blockstack_client import BlockstackRPCClient

from blockstack.atlas import *

RPC_SERVER_PORT = 16264

# current simulator time
TIME = 0

# network state
NETWORK_STATE = None

def get_network_state():
    global NETWORK_STATE
    return NETWORK_STATE

def set_network_state( n ):
    global NETWORK_STATE
    NETWORK_STATE = n


def time_now():
    """
    Get the current time
    """
    rpc = AtlasRPCTestClient( "none", 0 )
    return rpc.time_now()


def time_sleep(hostport, procname, value):
    """
    Have this host sleep for a bit
    """
    rpc = AtlasRPCTestClient( "none", 0, src=hostport )
    rpc.add_sleep_deadline( hostport, procname, value )


def atlas_max_neighbors():
    """
    How many neighbors can a peer have?
    """
    rpc = AtlasRPCTestClient( "none", 0 )
    return rpc.max_neighbors()


def atlas_peer_lifetime_interval():
    """
    How long is a peer's request history viable?
    """
    rpc = AtlasRPCTestClient( "none", 0 )
    return rpc.peer_lifetime_interval()


def atlas_peer_ping_interval():
    """
    How long is a peer's last-contact information fresh?
    """
    rpc = AtlasRPCTestClient( "none", 0 )
    return rpc.peer_ping_interval()


class AtlasRPCTestClient(object):
    def __init__(self, host, port, timeout=60, src=None):
        self.rpc = BlockstackRPCClient( "127.0.0.1", RPC_SERVER_PORT, timeout=timeout )
        self.src_hostport = src
        self.dest_hostport = "%s:%s" % (host, port)
        self.timeout = timeout


    def get_atlas_peers( self, src_hostport ):
        """
        Get atlas peers from the destination
        """
        return self.rpc.get_atlas_peers( src_hostport, self.dest_hostport )


    def get_zonefile_inventory( self, bit_offset, bit_len ):
        """
        Get zonefile inventory from the given dest hostport, with simulated loss
        """
        return self.rpc.get_zonefile_inventory( self.src_hostport, self.dest_hostport, bit_offset, bit_len )


    def get_zonefiles( self, zonefile_hashes ):
        """
        Get the list of zonefiles, given the zonefile hashes (with simulated loss)
        Returns [{'zonefile hash': zonefile data}]
        """
        return self.rpc.get_zonefiles( self.src_hostport, self.dest_hostport, zonefile_hashes )

    
    def put_zonefiles( self, zonefile_info ):
        """
        Upload a list of zonefiles, and enqueue them in the pusher
        """
        return self.rpc.put_zonefiles( self.src_hostport, self.dest_hostport, zonefile_info )


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


    def time_now( self ):
        """
        time now
        """
        return self.rpc.time_now()


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


    def mock_add_zonefile_hashes(self, count, present=True):
        """
        Add zonefiles at block heights
        """
        if not self.zfstate.has_key(self.lastblock):
            self.zfstate[self.lastblock] = []

        for i in xrange(0, count):
            id_idx = len(self.zfstate.keys()) + i
            new_zf = blockstack_client.user.make_empty_user_zonefile( "testregistration%03d.id" % (id_idx),  
                    "04bd3075d85f2e23d67998ba242e9751036393406bfb17d9b4c0c3652a6d7ff77f601a54bca9e4338336f083a4b6365eef328b55646f22b04979acd5219627b954",
                    ["http://node.blockstack.org:6264/RPC2#testregistration%03d.id" % (id_idx),
                     "file:///home/test/.blockstack/storage-disk/mutable/testregistration%03d.id" % (id_idx)] )

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
    def __init__(self, host, port, peer_seeds, peer_blacklist, zonefile_inv, db_path, zonefile_dir):
        """
        Initialize this atlas node's state
        """

        from blockstack import AtlasPeerCrawler, AtlasHealthChecker, AtlasZonefileCrawler

        self.host = host
        self.port = port
        self.db_path = db_path
        self.hostport = "%s:%s" % (host, port)
        self.online = True

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
            res = self.server.funcs["rpc_" + str(method)](*params)

            # lol jsonrpc within xmlrpc
            ret = json.dumps(res)
            return ret
        except Exception, e:
            print >> sys.stderr, "\n\n%s\n\n" % traceback.format_exc()
            return rpc_traceback()


class AtlasNetwork( SimpleXMLRPCServer ):
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
        """
        SimpleXMLRPCServer.__init__(self, ('127.0.0.1', RPC_SERVER_PORT), AtlasNetworkRPCHandler, allow_none=True )
        self.time = 0
        self.node_hosts = dict( [(n.hostport, n) for n in nodes] )
        for _, node in self.node_hosts.items():
            node.set_network(self)

        self.drop_probability = network_params.get( "drop_probability", lambda hostport_dst: 0 )
        self.peer_delay = network_params.get( "peer_delay", lambda hostport: 0 )
        self.inv_delay = network_params.get( "inv_delay", lambda hostport: 0 )
        self.zonefile_delay = network_params.get("zonefile_delay", lambda hostport, num_zfs: 0 )
        self.max_neighbors = network_params.get("max_neighbors", 3)
        self.peer_ping_interval = network_params.get("peer_ping_interval", 3)
        self.peer_lifetime_interval = network_params.get("peer_lifetime_interval", 10)

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
        for node_hostport, n in self.node_hosts.items():

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
  
            """
            if not n.is_asleep( "AtlasZonefilePusher", self.time ):
                # ready for next zonefile push 
                if not n.is_waiting( "AtlasZonefilePusher", self.time ):
                    # begin push 
                    delay = self.peer_delay( n.hostport )
                    n.set_wait_deadline( "AtlasZonefilePusher", self.time + delay )

            if not n.is_waiting( "AtlasZonefilePusher", self.time ):
                # no longer waiting 
                n.zonefile_pusher.step( peer_table=n.peer_table, zonefile_queue=n.zonefile_queue )
            """

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
        neighbors = atlas_get_rarest_live_peers( peer_table=peer_table )
       
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

    
    def rpc_put_zonefiles( self, dest_hostport, zonefile_info ):
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


class AtlasNetworkServer( threading.Thread, object ):
    """
    RPC server thread
    """
    def __init__(self, atlas_network ):
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


def inv_to_string( inv ):
    """
    Inventory to string (bitwise big-endian)
    """
    ret = ""
    for i in xrange(0, len(inv)):
        for j in xrange(0, 8):
            bit_index = 1 << (7 - j)
            val = (ord(inv[i]) & bit_index)
            if val != 0:
                ret += "1"
            else:
                ret += "0"

    return ret


def print_network_state( network ):
    """
    Print out the state of the network
    """
    node_hostports = sorted(network.get_nodes().keys())
    for node_hostport in node_hostports:
        node = network.get_node( node_hostport )
        peer_table = network.get_peer_table( node_hostport )
        node_inv = atlas_make_zonefile_inventory( 0, atlasdb_zonefile_inv_length(path=node.db_path), path=network.get_atlasdb_path( node_hostport ))
        node_inv_str = inv_to_string( node_inv )
        neighbors = sorted(network.get_peer_table( node_hostport ).keys())

        neighbor_popularity = []
        for n in neighbors:
            pop = atlas_peer_get_popularity( n, peer_table=peer_table )
            h = atlas_peer_get_health( n, peer_table=peer_table )
            inv = inv_to_string( peer_table[n]['zonefile_inv'] )
            neighbor_popularity.append( (pop, "%s (h=%.3f,p=%s,inv=%s)" % (n, h, pop, inv)))

        neighbor_popularity.sort()
        neighbor_strings = [ s for (_, s) in neighbor_popularity ]

        print "-" * 80
        print "%s: %s   State: %s\nneighbors: %s" % (node_hostport, node_inv_str, network.get_node(node_hostport).state_to_string(), ", ".join(neighbor_strings))
        print ""

    # measure peer knowledge distribution
    peer_count = {}
    for node_hostport in node_hostports:
        peer_count[node_hostport] = 0

    for node_hostport in node_hostports:
        peer_table = network.get_peer_table( node_hostport )
        for ph in peer_table.keys():
            peer_count[ph] += 1

    print "Neighbor knowledge"
    for node_hostport in node_hostports:
        print "%020s: %s" % (node_hostport, "#" * peer_count[node_hostport])

    print ""


def load_flat_simulation( num_nodes, num_seed_nodes, num_zonefiles, test_root_dir ):
    """
    Make a random simulated network,
    with the given number of nodes and a given number
    of seed nodes that everyone knows about.
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
    last_neighbor = seed_node_hostports[-1]
    for i in xrange(0, num_nodes):
        atlasdb_path = os.path.join(test_root_dir, "atlas_peer_%03d.db" % i)
        zonefile_dir = os.path.join(test_root_dir, "zonefile_peer_%03d.db" % i)

        os.makedirs(zonefile_dir)

        # one seed node
        node = AtlasNode("peer_%03d" % i, RPC_SERVER_PORT, [last_neighbor], [], peer_inv, atlasdb_path, zonefile_dir )
        peer_nodes.append( node )

        last_neighbor = "peer_%03d" % i

    network = AtlasNetwork( seed_nodes + peer_nodes )

    return network


def network_shutdown( network ):
    network.stop_server()


def run_simulation( network ):
    """
    Run an atlas network
    Run until converged
    """
    set_network_state( network )
    network_server = AtlasNetworkServer( network )

    atexit.register( network_shutdown, network_server )

    network_server.start()
    while True:
        print "time: %s" % network.time
        
        network.step()
        print_network_state( network )

        time.sleep(1.0)


if __name__ == "__main__":
    zonefile_dir = "/tmp/atlas-zonefiles-flat"
    if os.path.exists(zonefile_dir):
        shutil.rmtree(zonefile_dir)

    os.makedirs(zonefile_dir)
    blockstack_client.session( config_path=sys.argv[1] )

    virtualchain.setup_virtualchain( impl=blockstack.lib.virtualchain_hooks )
    
    network = load_flat_simulation( 10, 1, 1, zonefile_dir )
    run_simulation( network )

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
