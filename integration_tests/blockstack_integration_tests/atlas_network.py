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

import blockstack
import blockstack_client
import virtualchain

from blockstack_client.config import FIRST_BLOCK_MAINNET

from blockstack.atlas import *

# current simulator time
TIME = 0

# network state
NETWORK_STATE = None

def get_network_state():
    global NETWORK_STATE
    return NETWORK_STATE

def time_now():
    global TIME
    return TIME

def time_sleep(hostport, procname, value):
    network = get_network_state()
    now = time_now()
    node = network.get_node( hostport )
    node.set_sleep_deadline( procname, now + value )

def atlas_max_neighbors():
    network = get_network_state()
    return network.max_neighbors

def atlas_peer_lifetime_interval():
    network = get_network_state()
    return network.peer_lifetime_interval

def atlas_peer_ping_interval():
    network = get_network_state()
    return network.peer_ping_interval


class AtlasRPCTestClient(object):
    def __init__(self, host, port, timeout=60):
        self.host = host
        self.port = port
        self.hostport = "%s:%s" % (host, port)
        self.timeout = timeout

    
    def possibly_drop(self):
        """
        Possibly drop a connection.
        Raise socket.error if so
        """
        network = get_network_state()
        if network.is_dropped( self.hostport ):
            # dropped
            se = socket.error
            se.errno = errno.ETIMEDOUT
            raise se


    def ping(self):
        """
        Network ping, with simulated loss
        """
        self.possibly_drop()
        return {'alive': True}


    def get_zonefile_inventory( self, start, end ):
        """
        Get zonefile inventory from the given dest hostport, with simulated loss
        """
        self.possibly_drop()
        network = get_network_state()
        atlasdb_path = network.get_atlasdb_path( self.hostport )
        inv = atlas_make_zonefile_inventory( start, end, path=atlasdb_path )
        return {'status': True, 'inv': base64.b64encode(inv)}


    def get_atlas_peers( self, src_hostport ):
        """
        Get the list of peers in this peer's neighbor set, with simulated loss.
        Give the receiver the src hostport
        """
        self.possibly_drop()
        network = get_network_state()
        peer_table = network.get_peer_table( self.hostport )
        neighbors = atlas_get_rarest_live_peers( peer_table=peer_table )
        
        node = network.get_node( src_hostport )
        atlas_peer_enqueue( src_hostport, peer_table=node.peer_table, peer_queue=node.peer_queue )

        return {'status': True, 'peers': neighbors}


    def get_zonefiles( self, zonefile_hashes ):
        """
        Get the list of zonefiles, given the zonefile hashes (with simulated loss)
        Returns [{'zonefile hash': zonefile data}]
        """
        self.possibly_drop()
        network = get_network_state()
        db = node.get_node_db( self.hostport )

        ret = []
        for zfh in zonefile_hashes:
            if db.get_zonefile( zfh ) is None:
                continue

            ret.append({zfh: blockstack_zones.make_zone_file(db.get_zonefile(zfh))})

        return {'status': True, 'zonefiles': ret}

    
    def put_zonefiles( self, zonefile_info ):
        """
        Upload a list of zonefiles, and enqueue them in the pusher
        """
        self.possibly_drop()
        network = get_network_state()
        node = network.get_node( zonefile_info )
        atlasdb_path = network.get_atlasdb_path( self.hostport )
        db = node.get_node_db( self.hostport )
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



class MockDB(object):
    """
    Mock BlockstackDB
    """
    zfstate = {}
    last_block = FIRST_BLOCK_MAINNET
    num_zonefiles = 0


    def add_zonefile( self, zf ):
        """
        Add a zonefile that we don't have data for.
        """
        zfhash = blockstack_client.get_zonefile_data_hash( str(zf) )
        for height in self.zfstate.keys():
            for zfrec in self.zfstate[height]:
                if zfrec['zonefile_hash'] == zfhash:
                    self.zfstate[height]['zonefile'] = zf


    def mock_add_zonefile_hashes(self, count):
        """
        Add zonefiles at block heights
        """
        if not self.zfstate.has_key(self.lastblock):
            self.zfstate[self.lastblock] = []

        for i in xrange(0, count):
            id_idx = len(self.zfstate.keys()) + i
            new_zf = blockstack_client.user.make_empty_user_zonefile( "testregistration%03s.id" % (id_idx),  
                    "04bd3075d85f2e23d67998ba242e9751036393406bfb17d9b4c0c3652a6d7ff77f601a54bca9e4338336f083a4b6365eef328b55646f22b04979acd5219627b954",
                    ["http://node.blockstack.org:6264/RPC2#testregistration%03s.id" % (id_idx),
                     "file:///home/test/.blockstack/storage-disk/mutable/testregistration%03s.id" % (id_idx)] )

            new_zf_hash = blockstack_client.storage.hash_zonefile( new_zf )

            self.zfstate[self.lastblock].append( {
                "zonefile_hash": new_zf_hash,
                "zonefile": new_zf,
                "inv_index": self.num_zonefiles
            })

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


    def get_value_hashes_at( self, lastblock ):
        return [zf["zonefile_hash"] for zf in self.zfstate.get(lastblock, []) ]


    def get_zonefile( self, zonefile_hash ):
        for _, zfdata in self.zfstate.items():
            for zfrec in zfdata:
                if zfrec['zonefile_hash'] == zonefile_hash:
                    return zfrec['zonefile']

        return None


    def __init__(self):
        self.lastblock = FIRST_BLOCK_MAINNET
        num_per_block = 5
        for i in xrange(0, 5):
            self.mock_add_zonefile_hashes(num_per_block + i - 4)

        for i in xrange(0, 5):
            self.mock_dup_zonefile_hashes(self.lastblock - 5)


class AtlasNode(object):
    """
    Simulated atlas node
    """
    def __init__(self, host, port, peer_seeds, peer_blacklist, db_path, zonefile_dir):
        """
        Initialize this atlas node's state
        """

        from blockstack import AtlasPeerCrawler, AtlasHealthChecker, AtlasZonefileCrawler

        self.host = host
        self.port = port
        self.hostport = "%s:%s" % (host, port)
        self.online = True

        self.peer_crawler = AtlasPeerCrawler( host, port )
        self.health_checker = AtlasHealthChecker( host, port, path=db_path )
        self.zonefile_crawler = AtlasZonefileCrawler( host, port, zonefile_storage_drivers=["disk"], path=db_path, zonefile_dir=zonefile_dir )
        self.zonefile_pusher = AtlasZonefilePusher( host, port )

        self.sleep_deadlines = {
            "AtlasPeerCrawler": 0,
            "AtlasHealthChecker": 0,
            "AtlasZonefileCrawler": 0,
            "AtlasZonefilePusher": 0
        }
        
        self.wait_deadlines = {
            "AtlasPeerCrawler": 0,
            "AtlasHealthChecker": 0,
            "AtlasZonefileChecker": 0,
            "AtlasZonefilePusher": 0
        }

        self.db = MockDB()
        self.peer_table = atlasdb_init( self.db_path, self.db, peer_seeds, peer_blacklist, zonefile_dir=zonefile_dir )
        self.peer_queue = []
        self.zonefile_queue = []
        

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
        return self.sleep_deadlines[procname] >= simtime or self.wait_deadlines[procname] >= simtime


    def is_waiting(self, procname, simtime ):
        """
        Is this node process waiting?
        """
        return self.wait_deadlines[procname] >= simtime


class AtlasNetwork(object):
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
        self.time = 0
        self.node_hosts = dict( [(n.hostport, n) for n in self.nodes] )

        self.drop_probability = network_params.get( "drop_probability", lambda hostport_dst: 0 )
        self.peer_delay = network_params.get( "peer_delay", lambda hostport: 0 )
        self.inv_delay = network_params.get( "inv_delay", lambda hostport: 0 )
        self.zonefile_delay = network_params.get("zonefile_delay", lambda hostport, num_zfs: 0 )
        self.max_neighbors = network_params.get("max_neighbors", 80)
        self.peer_ping_interval = network_params.get("peer_ping_interval", 60)
        self.peer_lifetime_interval = network_params.get("peer_lifetime_interval", 3600)

    def step(self):
        """
        Run one step of the simulation
        """
        self.time += 1
        for n in self.nodes:

            if not n.is_asleep( "AtlasPeerCrawler", self.time ):
                # ready for next neighbor crawl
                if not n.is_waiting( "AtlasPeerCrawler", self.time ):
                    # crawl "initiated", but will wait for it to complete
                    delay = self.peer_delay( n.hostport )
                    n.set_wait_deadline( "AtlasPeerCrawler", self.time + delay )

            if not n.is_waiting( "AtlasPeerCrawler", self.time ):
                # no longer waiting
                n.peer_crawler.step( n.lastblock, peer_table=n.peer_table, peer_queue=n.peer_queue )


            if not n.is_asleep( "AtlasHealthChecker", self.time ):
                # ready for next health check
                if not n.is_waiting( "AtlasHealthChecker", self.time ):
                    # health check "initiated", but will wait for it to complete 
                    delay = self.inv_delay( n.hostport )
                    n.set_wait_deadline( "AtlasHealthChecker", self.time + delay )

            if not n.is_waiting( "AtlasHealthChecker", self.time ):
                # no longer waiting
                n.health_checker.step( FIRST_BLOCK_MAINNET, peer_table=n.peer_table, path=n.path )


            if not n.is_asleep( "AtlasZonefileCrawler", self.time ):
                # ready for next zonefile crawl
                if not n.is_waiting( "AtlasZonefileCrawler", self.time ):
                    # crawl "initiated", but will wait for it to complete
                    delay = self.peer_deay( n.hostport )
                    n.set_wait_deadline( "AtlasZonefileCrawler", self.time + delay )

            if not n.is_waiting( "AtlasZonefileCralwer", self.time ):
                # no longer waiting
                n.zonefile_crawler.step( peer_table=n.peer_table, path=n.path )
  

            if not n.is_asleep( "AtlasZonefilePusher", self.time ):
                # ready for next zonefile push 
                if not n.is_waiting( "AtlasZonefilePusher", self.time ):
                    # begin push 
                    delay = self.peer_delay( n.hostport )
                    n.set_wait_deadline( "AtlasZonefilePusher", self.time + delay )

            if not n.is_waiting( "AtlasZonefilePusher", self.time ):
                # no longer waiting 
                n.zonefile_pusher.step( peer_table=n.peer_table, zonefile_queue=n.zonefile_queue )

   
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


def load_flat_simulation( num_nodes, num_seed_nodes ):
    """
    Make a random simulated network,
    with the given number of nodes and a given number
    of seed nodes that everyone knows about.
    """
    



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


    def test_atlasdb_zonefile_info_list( db, zonefile_hash, path ):
        """
        Test listing all zonefile information, from start block to end
        """
        log.debug("test atlasdb_zonefile_info_list(%s)" % zonefile_hash)
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

        inv_vec = atlas_make_zonefile_inventory( FIRST_BLOCK_MAINNET, db.lastblock, path=path )

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
                test_atlasdb_zonefile_info_list( db, zfs['zonefile_hash'], test_db_path )

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


