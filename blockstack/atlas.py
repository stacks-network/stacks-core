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
import time
import sqlite3
import urllib2
import simplejson
import threading
import random
import struct
import base64
import shutil
import traceback
import copy
import binascii

from pybloom_live import ScalableBloomFilter

if os.environ.get("BLOCKSTACK_TEST", None) == "1" and os.environ.get("BLOCKSTACK_ATLAS_UNIT_TEST", None) is None:
    # use test client
    from blockstack_integration_tests import AtlasRPCTestClient as BlockstackRPCClient
    from blockstack_integration_tests import time_now, time_sleep

else:
    # production
    from blockstack_client import BlockstackRPCClient
    
    def time_now():
        return time.time()

    def time_sleep(hostport, value):
        return time.sleep(value)


import virtualchain
log = virtualchain.get_logger("blockstack-server")

from lib.config import *
from lib.storage import *
from lib import get_db_state

PEER_LIFETIME_INTERVAL = 3600  # 1 hour
PEER_PING_INTERVAL = 300       # 5 minutes
PEER_ZONEFILE_INVENTORY_TTL = 600   # 10 minutes

MIN_PEER_HEALTH = 0.5  # minimum peer health before we forget about it

NUM_NEIGHBORS = 80     # number of neighbors a peer can report
MAX_PEERS = 10000      # max number of peers a node can remember

if os.environ.get("BLOCKSTACK_ATLAS_MAX_PEERS") is not None:
    MAX_PEERS = int(os.environ.get("BLOCKSTACK_ATLAS_MAX_PEERS"))

if os.environ.get("BLOCKSTACK_ATLAS_PEER_LIFETIME") is not None:
    PEER_LIFETIME_INTERVAL = int(os.environ.get("BLOCKSTACK_ATLAS_PEER_LIFETIME"))

if os.environ.get("BLOCKSTACK_ATLAS_PEER_PING_INTERVAL") is not None:
    PEER_PING_INTERVAL = int(os.environ.get("BLOCKSTACK_ATLAS_PEER_PING_INTERVAL"))

if os.environ.get("BLOCKSTACK_ATLAS_ZONEFILE_INVENTORY_TTL") is not None:
    PEER_ZONEFILE_INVENTORY_TTL = int(os.environ.get("BLOCKSTACK_ATLAS_ZONEFILE_INVENTORY_TTL"))

if os.environ.get("BLOCKSTACK_ATLAS_MIN_PEER_HEALTH") is not None:
    MIN_PEER_HEALTH = float(os.environ.get("BLOCKSTACK_ATLAS_MIN_PEER_HEALTH"))

if os.environ.get("BLOCKSTACK_ATLAS_NUM_NEIGHBORS") is not None:
    NUM_NEIGHBORS = int(os.environ.get("BLOCKSTACK_ATLAS_NUM_NEIGHBORS"))

if os.environ.get("BLOCKSTACK_ATLAS_MAX_NEIGHBORS") is not None:
    MAX_PEERS = int(os.environ.get("BLOCKSTACK_ATLAS_MAX_NEIGHBORS"))


ATLASDB_SQL = """
CREATE TABLE zonefiles( inv_index INTEGER PRIMARY KEY AUTOINCREMENT,
                        zonefile_hash STRING NOT NULL,
                        present INTEGER NOT NULL,
                        block_height INTEGER NOT NULL );
"""

PEER_TABLE = {}        # map peer host:port (NOT url) to peer information
                       # each element is {'time': [(responded, timestamp)...], 'popularity': ..., 'popularity_bloom': ..., 'zonefile_lastblock': ..., 'zonefile_inv': ...}
                       # 'zonefile_inv' is a *bitwise big-endian* bit string where bit i is set if the zonefile in the ith NAME_UPDATE transaction has been stored by us (i.e. "is present")
                       # for example, if 'zonefile_inv' is 10110001, then the 0th, 2nd, 3rd, and 7th NAME_UPDATEs' zonefiles have been stored by us
                       # (note that we allow for the possibility of duplicate zonefiles, but this is a rare occurance and we keep track of it in the DB to avoid duplicate transfers)

PEER_TABLE_LOCK = threading.Lock()


def atlas_peer_table_lock():
    """
    Lock the global health info table.
    Return the table.
    """
    global PEER_TABLE_LOCK, PEER_TABLE
    PEER_TABLE_LOCK.acquire()
    return PEER_TABLE


def atlas_peer_table_unlock():
    """
    Unlock the global health info table.
    """
    global PEER_TABLE_LOCK
    PEER_TABLE_LOCK.release()
    return


def atlasdb_row_factory( cursor, row ):
    """
    row factory
    * convert known booleans to booleans
    """
    d = {}
    for idx, col in enumerate( cursor.description ):
        if col[0] == 'present':
            if row[idx] == 0:
                d[col[0]] = False
            elif row[idx] == 1:
                d[col[0]] = True
            else:
                raise Exception("Invalid value for 'present': %s" % row[idx])

        else:
            d[col[0]] = row[idx]

    return d


def atlasdb_path( impl=None ):
    """
    Get the path to the atlas DB
    """
    working_dir = virtualchain.get_working_dir(impl=impl)
    return os.path.join(working_dir, "atlas.db")


def atlasdb_query_execute( cur, query, values ):
    """
    Execute a query.  If it fails, exit.

    DO NOT CALL THIS DIRECTLY.
    """

    try:
        ret = cur.execute( query, values )
        return ret
    except Exception, e:
        log.exception(e)
        log.error("FATAL: failed to execute query (%s, %s)" % (query, values))
        log.error("\n" + "\n".join(traceback.format_stack()))
        sys.exit(1)


def atlasdb_open( path ):
    """
    Open the atlas db.
    Return a connection.
    Return None if it doesn't exist
    """
    if not os.path.exists(path):
        log.debug("Atlas DB doesn't exist at %s" % path)
        return None

    con = sqlite3.connect( path, isolation_level=None )
    con.row_factory = atlasdb_row_factory
    return con


def atlasdb_add_zonefile_info( zonefile_hash, present, block_height, con=None, path=None ):
    """
    Add a zonefile to the database.
    Mark it as present or absent.
    """
    if path is None:
        path = atlasdb_path()

    close = False
    if con is None:
        close = True
        con = atlasdb_open( path )
        assert con is not None

    sql = "INSERT INTO zonefiles (zonefile_hash, present, block_height) VALUES (?,?,?);"
    args = (zonefile_hash, present, block_height)

    cur = con.cursor()
    atlasdb_query_execute( cur, sql, args )
    con.commit()

    if close:
        con.close()

    return True


def atlasdb_get_zonefile( zonefile_hash, con=None, path=None ):
    """
    Look up all information on this zonefile.
    Returns {'zonefile_hash': ..., 'indexes': [...], etc}
    """
    if path is None:
        path = atlasdb_path()

    close = False
    if con is None:
        close = True
        con = atlasdb_open( path )
        assert con is not None

    sql = "SELECT * FROM zonefiles WHERE zonefile_hash = ?;"
    args = (zonefile_hash,)

    cur = con.cursor()
    res = atlasdb_query_execute( cur, sql, args )
    con.commit()

    ret = {
        'zonefile_hash': zonefile_hash,
        'indexes': [],
        'block_heights': [],
        'present': None
    }

    for zfinfo in res:
        ret['indexes'].append( zfinfo['inv_index'] )
        ret['block_heights'].append( zfinfo['block_height'] )
        ret['present'] = zfinfo['present']

    if close:
        con.close()

    return ret


def atlasdb_get_zonefile_info( block_height, con=None, path=None ):
    """
    Get all the zonefile hashes at a block height
    """
    if path is None:
        path = atlasdb_path()

    close = False
    if con is None:
        close = True
        con = atlasdb_open( path )
        assert con is not None

    sql = "SELECT * FROM zonefiles WHERE block_height = ?;"
    args = (block_height,)

    cur = con.cursor()
    res = atlasdb_query_execute( cur, sql, args )
    con.commit()

    ret = []
    for row in res:
        tmp = {}
        tmp.update(row)
        ret.append(tmp)

    if close:
        con.close()

    return ret


def atlasdb_set_zonefile_present( zonefile_hash, present, con=None, path=None ):
    """
    Mark a zonefile as present (i.e. we stored it)
    """
    if path is None:
        path = atlasdb_path()

    close = False
    if con is None:
        close = True
        con = atlasdb_open( path )
        assert con is not None

    if present:
        present = 1
    else:
        present = 0

    sql = "UPDATE zonefiles SET present = ? WHERE zonefile_hash = ?;"
    args = (present, zonefile_hash)

    cur = con.cursor()
    res = atlasdb_query_execute( cur, sql, args )
    con.commit()

    if close:
        con.close()

    return res


def atlasdb_get_zonefile_bits( zonefile_hash, con=None, path=None ):
    """
    What bit(s) in a zonefile inventory does a zonefile hash correspond to?
    Return their indexes in the bit field
    """
    if path is None:
        path = atlasdb_path()

    close = False
    if con is None:
        close = True
        con = atlasdb_open( path )
        assert con is not None

    sql = "SELECT inv_index FROM zonefiles WHERE zonefile_hash = ?;"
    args = (zonefile_hash,)

    cur = con.cursor()
    res = atlasdb_query_execute( cur, sql, args )
    con.commit()

    # NOTE: zero-indexed
    ret = [r['inv_index'] - 1 for r in res]

    if close:
        con.close()

    return ret


def atlasdb_queue_zonefiles( con, db, start_block, zonefile_dir=None, validate=True ):
    """
    Queue all zonefile hashes in the BlockstackDB
    to the zonefile queue
    """
    # populate zonefile queue
    total = 0
    for block_height in xrange(start_block, db.lastblock+1, 1 ):

        zonefile_hashes = db.get_value_hashes_at( block_height )
        for zfhash in zonefile_hashes:
            present = is_zonefile_cached( zfhash, zonefile_dir=zonefile_dir, validate=validate ) 
            atlasdb_add_zonefile_info( zfhash, present, block_height, con=con )
            total += 1

    log.debug("Queued %s zonefiles from %s-%s" % (total, start_block, db.lastblock))
    return True


def atlasdb_init( path, db, peer_seeds, peer_blacklist, validate=False, zonefile_dir=None ):
    """
    Set up the atlas node:
    * create the db if it doesn't exist
    * go through all the names and verify that we have the *current* zonefiles
    * if we don't, queue them for fetching.
    * set up the peer db

    @db should be an instance of BlockstackDB
    @initial_peers should be a list of URLs
    """
    
    global ATLASDB_SQL
    global PEER_TABLE

    if os.path.exists( path ):
        log.debug("Atlas DB exists at %s" % path)

    else:

        lines = [l + ";" for l in ATLASDB_SQL.split(";")]
        con = sqlite3.connect( path, isolation_level=None )

        for line in lines:
            con.execute(line)

        con.row_factory = atlasdb_row_factory

        # populate from db
        log.debug("Queuing all zonefiles")
        atlasdb_queue_zonefiles( con, db, FIRST_BLOCK_MAINNET, validate=validate, zonefile_dir=zonefile_dir )
        con.close()

    PEER_TABLE = {}

    # add initial peer info
    for peer_url in peer_seeds + peer_blacklist:
        host, port = url_to_host_port( peer_url )
        peer_hostport = "%s:%s" % (host, port)

        atlas_init_peer_info( PEER_TABLE, peer_hostport )

        if peer_url in peer_blacklist:
            PEER_TABLE[peer_hostport]['blacklisted'] = True

    return True


def atlasdb_zonefile_info_list( start, end, con=None, path=None ):
    """
    Get a listing of zonefile information
    for a given blockchain range [start, end].
    """
    if path is None:
        path = atlasdb_path()

    close = False
    if con is None:
        close = True
        con = atlasdb_open( path )
        assert con is not None

    sql = "SELECT * FROM zonefiles WHERE block_height >= ? AND block_height <= ?;"
    args = (start, end)

    cur = con.cursor()
    res = atlasdb_query_execute( cur, sql, args )
    con.commit()

    ret = []
    for row in res:
        tmp = {}
        tmp.update(row)
        ret.append(tmp)

    if close:
        con.close()

    return ret


def atlasdb_zonefile_find_missing( offset, count, con=None, path=None ):
    """
    Find out which zonefiles we're still missing.
    Return a list of zonefile rows, where present == 0
    """
    if path is None:
        path = atlasdb_path()

    close = False
    if con is None:
        close = True
        con = atlasdb_open( path )
        assert con is not None

    sql = "SELECT * FROM zonefiles WHERE present = 0 OFFSET ? LIMIT ?;"
    args = (start, end)

    cur = con.cursor()
    res = atlasdb_query_execute( cur, sql, args )
    con.commit()

    ret = []
    for row in res:
        tmp = {}
        tmp.update(row)
        ret.append(tmp)

    if close:
        con.close()

    return ret


def atlas_make_zonefile_inventory( start, end, con=None, path=None, zonefile_dir=None, validate=False ):
    """
    Get a summary description of the list of zonefiles we have
    for the given block range (a "zonefile inventory")

    Zonefile present/absent bits are ordered left-to-right,
    where the leftmost bit is the earliest zonefile in the blockchain.
    """
    
    listing = atlasdb_zonefile_info_list( start, end, con=con, path=path )

    # group by block height, order by tx
    tmp = {}
    for row in listing:
        if not tmp.has_key(row['block_height']):
            tmp[row['block_height']] = []

        tmp[row['block_height']].append( row['present'] )

    # serialize
    bool_vec = []
    for height in sorted(tmp.keys()):
        bool_vec += tmp[height]

    if len(bool_vec) % 8 != 0: 
        # pad 
        bool_vec += [False] * (8 - (len(bool_vec) % 8))

    inv = ""
    for i in xrange(0, len(bool_vec), 8):
        bit_vec = map( lambda b: 1 if b else 0, bool_vec[i:i+8] )
        next_byte = (bit_vec[0] << 7) | \
                    (bit_vec[1] << 6) | \
                    (bit_vec[2] << 5) | \
                    (bit_vec[3] << 4) | \
                    (bit_vec[4] << 3) | \
                    (bit_vec[5] << 2) | \
                    (bit_vec[6] << 1) | \
                    (bit_vec[7])
        inv += chr(next_byte)

    return inv


def atlas_init_peer_info( peer_table, peer_hostport ):
    """
    Initialize peer info table entry
    """
    peer_table[peer_hostport] = {
        "popularity": 1,
        "popularity_bloom": ScalableBloomFilter(),
        "time": [],
        "zonefile_lastblock": FIRST_BLOCK_MAINNET,
        "zonefile_inv": ""
    }


def url_to_host_port( url, port=RPC_SERVER_PORT ):
    """
    Given a URL, turn it into (host, port).
    Return (None, None) on invalid URL
    """
    urlinfo = urllib2.urlparse.urlparse(url)
    hostport = urlinfo.netloc

    parts = hostport.split("@")
    if len(parts) > 2:
        return (None, None)

    if len(parts) == 2:
        hostport = parts[1]

    parts = hostport.split(":")
    if len(parts) > 2:
        return (None, None)

    if len(parts) == 2:
        try:
            port = int(parts[1])
        except:
            return (None, None)

    return parts[0], port


def atlas_peer_is_live( peer_hostport, peer_table, min_health=MIN_PEER_HEALTH ):
    """
    Have we heard from this node recently?
    """
    if not peer_table.has_key(peer_hostport):
        return False

    health_score = atlas_peer_get_health( peer_hostport, peer_table=peer_table )
    return health_score > min_health


def atlas_peer_ping( peer_hostport, timeout=3 ):
    """
    Ping a host
    Return True if alive
    Return False if not
    """
    host, port = url_to_host_port( peer_hostport )
    rpc = BlockstackRPCClient( host, port, timeout=timeout )

    log.debug("Ping %s" % peer_hostport)
    try:
        rpc.ping()
        return True
    except:
        return False


def atlas_get_rarest_live_peers( peer_table=None, min_health=MIN_PEER_HEALTH ):
    """
    Get the list of peers we've heard from recently.
    Use the global peer health table if no health info is given.
    Rank peers by rarest-first.
    """

    locked = False
    if peer_table is None:
        locked = True
        peer_table = atlas_peer_table_lock()
        
    rarity_rank = []    # (popularity, peer_hostport)
    for peer_hostport in peer_table.keys():
        if atlas_peer_is_live( peer_hostport, peer_table, min_health=min_health ):
            # have recently seen
            rarity_rank.append( (peer_table[peer_hostport]['popularity'], peer_hostport) )

    rarity_rank.sort()  # sorts to least-popular first
    if locked:
        atlas_peer_table_unlock()

    return [peer_hostport for _, peer_hostport in rarity_rank]


def atlas_remove_peers( dead_peers, peer_table ):
    """
    Remove all peer information for the given dead peers from the given health info,
    as well as from the db.
    Only preserve unconditionally if we've blacklisted them
    explicitly.

    Return the new health info.
    """

    for peer_hostport in dead_peers:
        if peer_table.has_key(peer_hostport):
            if peer_table[peer_hostport].get("blacklisted", False):
                continue

            log.debug("Forget peer '%s'" % dead_peers)
            del peer_table[peer_hostport]

    return peer_table


def atlas_peer_get_health( peer_hostport, peer_table=None ):
    """
    Get the health score for a peer.
    Health is: (number of responses received / number of requests sent) 
    """
    locked = False
    if peer_table is None:
        locked = True
        peer_table = atlas_peer_table_lock()

    # availability score: number of responses / number of requests
    num_responses = 0
    num_requests = 0
    for (t, r) in peer_table[peer_hostport]['time']:
        num_requests += 1
        if r:
            num_responses += 1

    availability_score = 0.0
    if num_requests > 0:
        availability_score = float(num_responses) / float(num_requests)

    if locked:
        atlas_peer_table_unlock()

    return availability_score


def atlas_peer_update_health( peer_hostport, received_response, peer_table=None ):
    """
    Mark the given peer as alive at this time.
    Update times at which we contacted it,
    and update its health score.

    Use the global health table by default, 
    or use the given health info if set.
    """

    locked = False
    if peer_table is None:
        locked = True    
        peer_table = atlas_peer_table_lock()

    # if blacklisted, then we don't care 
    if peer_table[peer_hostport].get("blacklisted", False):
        if locked:
            atlas_peer_table_unlock()

        return True

    # record that we contacted this peer, and whether or not we useful info from it
    now = time_now()

    # update timestamps; remove old data
    new_times = []
    for (t, r) in peer_table[peer_hostport]['time']:
        if t + PEER_LIFETIME_INTERVAL < now:
            continue
        
        new_times.append((t, r))

    new_times.append((now, received_response))
    peer_table[peer_hostport]['time'] = new_times

    if locked:
        atlas_peer_table_unlock()

    return True


def atlas_peer_add_neighbor( peer_hostport, peer_neighbor_hostport, peer_table=None ):
    """
    Record that peer_hostport knows about peer_neighbor_hostport (if we haven't done so already).
    Add the peers to the peer table if they're not there now.
    Use the global peer table if the given peer table is None
    """
    
    locked = False
    if peer_table is None:
        locked = True    
        peer_table = atlas_peer_table_lock()

    if peer_hostport not in peer_table.keys():
        atlas_init_peer_info( peer_table, new_hostport )

    if peer_neighbor_hostport not in peer_table.keys():
        atlas_init_peer_info( peer_table, peer_neighbor_hostport )

    if peer_neighbor_hostport not in peer_table[peer_hostport]['popularity_bloom']:
        # we didn't know that peer_hostport knew about peer_neighbor_hostport
        peer_table[peer_neighbor_hostport]['popularity'] += 1
        peer_table[peer_hostport]['popularity_bloom'].add( peer_neighbor_hostport )

    if locked:
        atlas_peer_table_unlock()

    return


def atlas_peer_get_zonefile_inventory_range( peer_hostport, startblock, lastblock, timeout=10, peer_table=None ):
    """
    Get the zonefile inventory bit vector for a given peer.
    startblock and lastblock are inclusive.

    Update peer health information as well.

    Return the bit vector on success.
    Return None if we couldn't contact the peer.
    """

    host, port = url_to_host_port( peer_hostport )
    rpc = BlockstackRPCClient( host, port, timeout=timeout )

    zf_inv = {}
    zf_inv_list = None

    try:
        zf_inv = rpc.get_zonefile_inventory( start, end )
        
        # sanity check
        assert type(zf_inv) == dict, "Inventory is not a dict"
        if 'error' not in zf_inv.keys():
            assert 'status' in zf_inv, "Invalid inv reply"
            assert zf_inv['status'], "Invalid inv reply"
            assert 'inv' in zf_inv, "Invalid inv reply"
            assert type(zf_inv['inv']) in [str, unicode], "Invalid inv bit field"
            zf_inv['inv'] = base64.b64decode( str(zf_inv['inv']) )

            # success!
            atlas_peer_update_health( peer_hostport, True, peer_table=peer_table )

        else:
            assert type(zf_inv['error']) in [str, unicode], "Invalid error message"

    except Exception, e:
        if os.environ.get("BLOCKSTACK_DEBUG") == "1":
            log.exception(e)

        log.error("Failed to ask %s for zonefile inventory over %s-%s" % (peer_hostport, start, end))
        atlas_peer_update_health( peer_hostport, False, peer_table=peer_table )
        return None

    if 'error' in zf_inv:
        log.error("Failed to get inventory for %s-%s from %s: %s" % (start, end, peer_hostport, zf_inv['error']))

        atlas_peer_update_health( peer_hostport, False, peer_table=peer_table )
        return None

    return zf_inv['inv']


def atlas_peer_sync_zonefile_inventory( peer_hostport, lastblock, timeout=10, peer_table=None ):
    """
    Synchronize our knowledge of a peer's zonefiles up to a given block height.
    NOT THREAD SAFE; CALL FROM ONLY ONE THREAD.

    Return the new inv vector if we synced it
    Return None if not
    """
    peer_inv = ""
    interval = 10000

    locked = False
    if peer_table is None:
        locked = True    
        peer_table = atlas_peer_table_lock()

    first_block = peer_table[peer_hostport]['zonefile_lastblock']
    peer_inv = peer_table[peerhostport]['zonefile_inv']

    if locked:
        atlas_peer_table_unlock()

    if first_block >= lastblock:
        # synced already
        return peer_inv

    for height in xrange( first_block, lastblock, interval):

        maxheight = min(lastblock, height+interval)
        next_inv = atlas_peer_get_zonefile_inventory_range( peer_hostport, height, maxheight, timeout=timeout, peer_table=peer_table )
        if next_inv is None:
            # partial failure
            log.debug("Failed to sync inventory for %s from %s to %s" % (peer_hostport, height, maxheight))
            break

        peer_inv += next_inv
   
    if locked:
        peer_table = atlas_peer_table_lock()

    peer_table[peer_hostport]['zonefile_inv'] = peer_inv
    peer_table[peer_hostport]['zonefile_lastblock'] = maxheight

    if locked:
        atlas_peer_table_unlock()

    return peer_inv


def atlas_peer_refresh_zonefile_inventory( peer_hostport, firstblock, timeout=10, peer_table=None, con=None, path=None ):
    """
    Refresh a peer's zonefile recent inventory vector entries,
    by removing every bit after firstblock and re-synchronizing them.

    The intuition here is that recent zonefiles are much rarer than older
    zonefiles (which will have been near-100% replicated), meaning the tail
    of the peer's zonefile inventory is a lot less stable than the head (since
    peers will be actively distributing recent zonefiles).

    NOT THREAD SAFE; CALL FROM ONLY ONE THREAD.

    Return True if we synced all the way up to lastblock
    Return False if not.
    """
    locked = False
    if peer_table is None:
        locked = True
        peer_table = atlas_peer_table_lock()

    # reset the peer's zonefile inventory, back to firstblock
    zfinfo = atlasdb_zonefile_info_list( FIRST_BLOCK_MAINNET, firstblock, con=con, path=path)
    offset = len(zfinfo)

    cur_inv = peer_table[peer_hostport]['zonefile_inventory']
    peer_table[peer_hostport]['zonefile_lastblock'] = firstblock
    peer_table[peer_hostport]['zonefile_inventory'] = cur_inv[:offset]

    inv = atlas_peer_sync_zonefile_inventory( peer_hostport, lastblock, timeout=timeout, peer_table=peer_table )

    if inv is not None:
        # success!
        peer_table[peer_hostport]['zonefile_inventory_last_refresh'] = time_now()

    if locked:
        atlas_peer_table_unlock()

    if inv is None:
        return False

    else:
        return True


def atlas_peer_has_fresh_zonefile_inventory( peer_hostport, peer_table=None ):
    """
    Does the given atlas node have a fresh zonefile inventory?
    """
    locked = False
    if peer_table is None:
        locked = True
        peer_table = atlas_peer_table_lock()

    fresh = False
    now = time_now()
    if peer_table[peer_hostport].has_key('zonefile_inventory_last_refresh') and peer_table[peer_hostport]['zonefile_inventory_last_fresh'] + PEER_ZONEFILE_INVENTORY_TTL >= now:
        fresh = True

    if locked:
        atlas_peer_table_unlock()

    return fresh


def atlas_peer_set_zonefile_status( peer_hostport, zonefile_hash, present, zonefile_bits=None, peer_table=None, con=None, path=None ):
    """
    Mark a zonefile as being present or absent on a peer.
    Use this method to update our knowledge of what other peers have,
    based on when we try to ask them for zonefiles (i.e. a peer can
    lie about what zonefiles it has, and if it advertizes the availability
    of a zonefile but doesn't deliver, then we need to remember not
    to ask it again).
    """
    if zonefile_bits is None:
        zonefile_bits = atlasdb_get_zonefile_bits( zonefile_hash, con=con, path=path )

    locked = False
    if peer_table is None:
        locked = True    
        peer_table = atlas_peer_table_lock()

    if peer_table.has_key(peer_hostport):
        peer_inv = peer_table[peer_hostport]['zonefile_inv']
        peer_inv_list = [ord(pi) for pi in list(peer_inv)]

        # expand up to maximum bit index
        max_index = max(zonefile_bits) / 8 + 1
        if len(peer_inv_list) < max_index:
            peer_inv_list += [0] * (max_index - len(peer_inv_list))

        for inv_offset in zonefile_bits:
            byte_offset = inv_offset / 8
            bit_offset = 7 - (inv_offset % 8)
            if present:
                peer_inv_list[byte_offset] = peer_inv_list[byte_offset] | (1 << bit_offset)
            else:
                peer_inv_list[byte_offset] = peer_inv_list[byte_offset] & ~(1 << bit_offset)

        # convert back to byte buffer
        peer_table[peer_hostport]['zonefile_inv'] = "".join( [chr(pi) for pi in peer_inv_list] )
                
    if locked:
        atlas_peer_table_unlock()

    return


def atlas_find_missing_zonefile_availability( peer_table=None, con=None, path=None, missing_zonefile_info=None ):
    """
    Find the set of missing zonefiles, as well as their popularity amongst 
    our neighbors.

    Only consider zonefiles that are known by at least
    one peer; otherwise they're missing from
    our clique (and we'll re-sync our neighborss' inventories
    every so often to make sure we detect when zonefiles
    become available).

    Return a dict, structured as:
    {
        'zonefile hash': {
            'indexes': [...],
            'popularity': ...,
            'peers': [...]
        }
    }
    """

    # which zonefiles do we have?
    offset = 0
    count = 10000
    missing = []
    ret = {}

    if missing_zonefile_info is None:
        while True:
            # TODO: use in-RAM coherent copy of our zonefile inventory
            zfinfo = atlasdb_zonefile_find_missing( offset, count, con=con, path=path )
            if len(zfinfo) == 0:
                break

            missing += zfinfo
            offset += len(zfinfo)

    else:
        missing = missing_zonefile_info

    if len(missing) == 0:
        # none!
        return []

    locked = False
    if peer_table is None:
        locked = True
        peer_table = atlas_peer_table_lock()

    # do any other peers have this zonefile?
    for zfinfo in missing:
        popularity = 0
        byte_index = zfinfo['inv_index'] / 8
        bit_index = 7 - (zfinfo['inv_index'] % 8)
        peers = []

        if not ret.has_key(zfinfo['zonefile_hash']):
            ret[zfinfo['zonefile_hash']] = {
                'indexes': [],
                'popularity': 0,
                'peers': []
            }

        for peer_hostport in peer_table.keys():
            if len(peer_table[peer_hostport]['zonefile_inv']) <= byte_index:
                # too new for this peer
                continue

            if (ord(peer_table[peer_hostport]['zonefile_inv'][byte_index]) & (1 << bit_index)) == 0:
                # this peer doesn't have it
                continue

            if peer_hostport not in ret[zfinfo['zonefile_hash']]['peers']:
                popularity += 1
                peers.append( peer_hostport )


        ret[zfinfo['zonefile_hash']]['indexes'].append( zfinfo['inv_index'] )
        ret[zfinfo['zonefile_hash']]['popularity'] += popularity
        ret[zfinfo['zonefile_hash']]['peers'] += peers

    if locked:
        atlas_peer_table_unlock()

    return ret


def atlas_peer_get_neighbors( peer_hostport, timeout=10, peer_table=None ):
    """
    Ask the peer server at the given URL for its
    K-rarest peers.

    Update the health info in peer_table
    (if not given, the global peer table will be used instead)

    Return the list on success
    Return None on failure to contact
    Raise on invalid URL
    """
   
    host, port = url_to_host_port( peer_hostport )
    if host is None or port is None:
        log.debug("Invalid host/port %s" % peer_hostport)
        raise ValueError("Invalid host/port %s" % peer_hostport)

    rpc = BlockstackRPCClient( host, port, timeout=timeout )
    
    try:
        peer_list = rpc.get_atlas_peers()

        assert type(peer_list) in [dict], "Not a peer list response"

        if 'error' not in peer_list:
            assert 'status' in peer_list, "No status in response"
            assert 'peers' in peer_list, "No peers in response"
            assert type(peer_list['peers']) in [list], "Not a peer list"
            for peer in peer_list['peers']:
                assert type(peer) in [str, unicode], "Invalid peer list"

            # sane limits
            if len(peer_list['peers']) > MAX_PEERS:
                peer_list['peers'] = peer_list['peers'][:MAX_PEERS]

        else:
            assert type(peer_list['error']) in [str, unicode], "Invalid error message"

    except AssertionError, ae:
        if os.environ.get("BLOCKSTACK_DEBUG") == "1":
            log.exception(ae)
        log.error("Invalid peer list response from '%s'" % peer_hostport)
        atlas_peer_update_health( peer_hostport, False, peer_table=peer_table )
        return None

    except Exception, e:
        if os.environ.get("BLOCKSTACK_DEBUG") == "1":
            log.exception(e)
        log.error("Failed to talk to '%s'" % peer_hostport)
        atlas_peer_update_health( peer_hostport, False, peer_table=peer_table )
        return None

    if 'error' in peer_list:
        log.debug("Remote peer error: %s" % peer_list['error'])
        log.error("Remote peer error")
        atlas_peer_update_health( peer_hostport, False, peer_table=peer_table )
        return None

    ret = peer_list['peers']
    atlas_peer_update_health( peer_hostport, True, peer_table=peer_table )
    return ret


def atlas_get_zonefiles( peer_hostport, zonefile_hashes, timeout=60, peer_table=None ):
    """
    Given a list of zonefile hashes.
    go and get them from the given host.

    Update node health

    Return the newly-fetched zonefiles on success (as a dict mapping hashes to zonefile data)
    Return None on error.
    """

    host, port = url_to_host_port( peer_hostport )
    rpc = BlockstackRPCClient( host, port, timeout=timeout )

    try:
        zf_data = rpc.get_zonefiles( zonefile_hashes )
        assert type(zf_data) == dict, "Invalid zonefile listing"
        if 'error' not in zf_data.keys():
            assert 'status' in zf_data.keys(), "Invalid zonefile reply"
            assert zf_data['status'], "Invalid zonefile reply"

            assert 'zonefiles' in zf_data.keys(), "No zonefiles"
            zonefiles = zf_data['zonefiles']

            assert type(zonefiles) == dict, "Invalid zonefiles"
            for zf_hash in zonefiles.keys():
                assert type(zf_hash) in [str, unicode], "Invalid zonefile hash"
                assert len(zf_hash) == LENGTHS['value_hash'], "Invalid zonefile hash length"

                assert type(zonefile[zf_hash]) in [str, unicode], "Invalid zonefile data"
                assert is_valid_zonefile( zonefile[zf_hash], zf_hash ), "Zonefile does not match or is not current" 

        else:
            assert type(zf_data['error']) in [str, unicode], "Invalid error message"

    except Exception, e:
        if os.environ.get("BLOCKSTACK_DEBUG") == "1":
            log.exception(e)

        log.error("Invalid zonefile data from %s" % peer_hostport)

        # unpopular
        atlas_peer_update_health( peer_hostport, False, peer_table=peer_table )
        return None 

    if 'error' in zf_data.keys():
        log.error("Failed to fetch zonefile data from %s: %s" % (peer_hostport, zf_data['error']))
        atlas_peer_update_health( peer_hostport, False, peer_table=peer_table )
        return None 

    atlas_peer_update_health( peer_hostport, True, peer_table=peer_table )
    return zf_data['zonefiles']


def atlas_rank_peers_by_health( peer_list=None, peer_table=None ):
    """
    Get a ranking of peers to contact for a zonefile.
    Peers are ranked by health (i.e. availability ratio)
    """

    locked = False
    if peer_table is None:
        locked = True    
        peer_table = atlas_peer_table_lock()

    if peer_list is None:
        peer_list = peer_table.keys()[:]

    peer_health_ranking = []    # (health score, peer hostport)
    for peer_hostport in peer_list:
        health_score = atlas_peer_get_health( peer_hostport, peer_table=peer_table)
        peer_health_ranking.append( (health_score, peer_hostport) )
    
    if locked:
        atlas_peer_table_unlock()

    # sort on health
    peer_health_ranking.sort()
    peer_health_ranking.reverse()

    return [peer_hp for _, peer_hp in peer_health_ranking]


def atlas_peer_get_last_response_time( peer_hostport, peer_table=None ):
    """
    Get the last time we got a positive response
    from a peer.
    Return the time on success
    Return -1.0 if we never heard from them
    """
    locked = False
    if peer_table is None:
        locked = True    
        peer_table = atlas_peer_table_lock()

    last_time = -1.0
    if peer_hostport in peer_table.keys():
        for (t, r) in peer_table[peer_hostport]['time']:
            if r and t > last_time:
                last_time = peer_table[peer_hostport]['time']
    
    if locked:
        atlas_peer_table_unlock()
    
    return last_time


class AtlasPeerCrawler( threading.Thread ):
    """
    Thread that continuously crawls peers.

    Try to obtain knowledge of as many peers as we can.
    (but we will only report the rarest NUM_NEIGHBORS peers to anyone who asks).
    We'll prune the set of known peers in another thread.

    The peer-selection algorithm works as follows:
    * search for neighbors via random walk: ask peers about their peers, and randomly expand them.
    * remember node popularity--how often we see that a peer knows about another peer, so we can report rare peers to other requesters
    """
    def __init__(self, my_hostname, my_portnum):
        threading.Thread.__init__(self)
        self.running = False
        self.my_hostport = "%s:%s" % (my_hostname, my_portnum)
        self.peer_crawl_list = []


    def step( self, peer_table=None ):
        """
        Execute one round of the peer discovery algorithm:
        select a peer at random, get its neighbors,
        and remember to begin crawling them.
        """
        # talk to peers at random
        peer_hostport = self.peer_crawl_list[ random.randint(0, len(peer_query_list)+1) ]
        if peer_hostport == my_hostport:
            return
  
        log.debug("Crawl peer %s" % peer_hostport)

        # ask this peer for its K-rarest neighbors
        peers = atlas_peer_get_neighbors(peer_hostport, timeout=10 )

        if peers is None:
            log.debug("No peers from %s" % peer_hostport)
            return

        # Update peer table
        locked = False
        if peer_table is None:
            locked = True
            peer_table = atlas_peer_table_lock()

        # add new peers and update popularity
        for newpeer in peers:

            newhost, newport = url_to_host_port( newpeer )
            new_hostport = "%s:%s" % (host, port)
            if new_hostport in peer_query_list:
                continue

            # did we know about this peer?
            if not peer_table.has_key(new_hostport):
                log.debug("New peer %s" % new_hostport)
                self.peer_crawl_list.append( new_hostport )

            atlas_peer_add_neighbor( peer_hostport, new_hostport, peer_table=peer_table )

        if locked:
            atlas_peer_table_unlock()
            peer_table = None


    def run(self):
        self.running = True

        # initial crawl list
        global_peer_table = atlas_peer_table_lock()
        self.peer_crawl_list = global_peer_table.keys()[:]
        atlas_peer_table_unlock()

        while self.running:
            self.step()


    def ask_join(self):
        self.running = False


class AtlasHealthChecker( threading.Thread ):
    """
    Thread that continuously monitors the health
    of our neighbor set.  It will remove unhealthy
    peers if we have too many neighbors (over MAX_PEERS)
    """
    def __init__(self, my_host, my_port, path=None):
        threading.Thread.__init__(self)
        self.running = False
        self.path = path
        self.hostport = "%s:%s" % (my_host, my_port)
        if path is None:
            path = atlasdb_path()


    def step( self, peer_table=None ):
        """
        Run one step of the algorithm:
        * ping peers we haven't heard from in a while (in more than PEER_PING_INTERVAL seconds) 
        * if we have too many peers, then find the unhealthy ones
        and remove them from the peer set
        """

        to_ping = []
        locked = False
        
        if peer_table is None:
            locked = True
            peer_table = atlas_peer_table_lock()
        
        now = time_now()
        for peer_hostport in peer_table.keys():
            last_time = atlas_peer_get_last_response_time( peer_hostport, peer_table=peer_table )
            if last_time + PEER_PING_INTERVAL < now:
                # haven't heard from it in a while
                to_ping.append( peer_hostport )

        if locked:
            atlas_peer_table_unlock()
            peer_table = None

        # update responsiveness
        for peer_hostport in to_ping:
            res = atlas_peer_ping( peer_hostport, timeout=3 )
            atlas_peer_update_health( peer_hostport, res, peer_table=peer_table )

        if locked:
            peer_table = atlas_peer_table_lock()
        
        # remove peers that are dead to us
        if len(peer_table.keys()) > MAX_PEERS:

            # TODO: consider removing peers that don't know about zonefiles we don't have
            peers = atlas_rank_peers_by_health(peer_table=peer_table)[MAX_PEERS:]
            atlas_remove_peers( peers, peer_table )

        if locked:
            atlas_peer_table_unlock()

        return len(to_ping)


    def run(self):
        while self.running:
            num_pinged = self.step()
            if num_pinged == 0:
                time_sleep(self.hostport, 1.0)


    def ask_join(self):
        self.running = False


class AtlasZonefileFinder( threading.Thread ):
    """
    Thread that continuously tries to find out
    the distribution of zonefiles in the peer set.
    Continuously selects the top-K healthiest peers
    and refreshes their zonefile inventories
    """
   
    INV_REFRESH_RANGE = 5000        # periodically refresh the last 5000 blocks of inventory

    def __init__(self, my_host, my_port, path=None):
        threading.Thread.__init__(self)
        self.running = False
        self.path = path
        self.hostport = "%s:%s" % (my_host, my_port)
        if self.path is None:
            self.path = atlasdb_path()
      

    def step(self, peers, lastblock, con=None, path=None, peer_table=None):
        """
        Run one step of this algorithm.
        Loop through the set of neighbors,
        and make sure their zonefile inventories
        are still fresh.

        Return the number of peers refreshed
        """
        if path is None:
            path = self.path

        refresh_count = 0
        for peer_hostport in peers:

            if not atlas_peer_has_fresh_zonefile_inventory( peer_hostport, peer_table=peer_table ):
                log.debug("Refresh zonefile inventory for %s" % peer_hostport)
                res = atlas_peer_refresh_zonefile_inventory( peer_hostport, lastblock - self.INV_REFRESH_RANGE, con=con, path=path, peer_table=peer_table )
                if res is None:
                    log.warning("Failed to refresh zonefile inventory for %s" % peer_hostport)

                else:
                    refresh_count += 1

            # preemption point 
            if not self.running:
                break

        return refresh_count


    def run(self):
        """
        Constantly try to synchronize the zonefile
        inventories.
        """
        self.running = True
        while self.running:

            db = get_db_state()
            lastblock = db.lastblock

            con = atlasdb_open( self.path )
            peers = atlas_rank_peers_by_health()

            # only worry about K neighbors
            if len(peers) > NUM_NEIGHBORS:
                peers = peers[:NUM_NEIGHBORS]

            # but, try them in a random order
            random.shuffle(peers)

            num_refreshed = self.step( peers, lastblock, con=con )
            if num_refreshed == 0:
                # wait for a while
                time_sleep(self.hostport, 1.0)



class AtlasZonefileCrawler( threading.Thread ):
    """
    Thread that continuously tries to find 
    zonefiles that we don't have.
    """

    def __init__(self, my_host, my_port, zonefile_storage_drivers=[], path=None, zonefile_dir=None):
        threading.Thread.__init__(self)
        self.running = False
        self.hostport = "%s:%s" % (my_host, my_port)
        self.path = path 
        self.zonefile_storage_drivers = zonefile_storage_drivers
        self.zonefile_dir = zonefile_dir
        if self.path is None:
            self.path = atlasdb_path()

    
    def step(self, con=None, path=None, peer_table=None):
        """
        Run one step of this algorithm:
        * find the set of missing zonefiles
        * try to fetch each of them
        * store them
        * update our zonefile database

        Fetch rarest zonefiles first, but batch
        whenever possible.

        Return the number of zonefiles fetched
        """

        if path is None:
            path = self.path

        close = False
        if con is None:
            close = True
            con = atlasdb_open( path )

        num_fetched = 0
        locked = False

        if peer_table is None:
            locked = True
            peer_table = atlas_peer_table_lock()

        missing_zfinfo = atlas_find_missing_zonefile_availability( peer_table=peer_table, con=con, path=path )

        if locked:
            atlas_peer_table_unlock()
            peer_table = None

        # ask in rarest-first order
        zonefile_ranking = [ (missing_zfinfo[zfhash]['popularity'], zfhash) for zfhash in missing_zfinfo.keys() ]
        zonefile_ranking.sort()
        zonefile_hashes = [zfhash for (_, zfhash) in zonefile_ranking]

        zonefile_origins = {}   # map peer hostport to list of zonefile hashes

        # which peers can serve each zonefile?
        for zfhash in missing_zfinfo.keys():
            if not zonefile_origins.has_key(peer_hostport):
                zonefile_origins[peer_hostport] = []

            zonefile_origins[peer_hostport].append( zfhash )

        while len(zonefile_hashes) > 0:
            zfhash = zonefile_hashes[0]
            peers = missing_zfinfo[zfhash]['peers']

            # rank peers by popularity
            peers = atlas_rank_peers_by_health( peer_list=peers )
            for peer_hostport in peers:

                # what other zonefiles can we get?
                # only ask for the ones we don't have
                peer_zonefile_hashes = zonefile_origins[peer_hostport]
                already_have = []
                for zfh in peer_zonefile_hashes:
                    if zfh not in zonefile_hashes:
                        already_have.append(zfh)

                for zfh in already_have:
                    peer_zonefile_hashes.remove(zfh)

                if len(peer_zonefile_hashes) == 0:
                    continue

                # get them all
                zonefiles = atlas_get_zonefiles( peer_hostport, peer_zonefile_hashes, peer_table=peer_table )
                if zonefiles is not None:
                    # got zonefiles!
                    for fetched_zfhash in zonefiles.keys():
                        if fetched_zfhash not in peer_zonefile_hashes:
                            # unsolicited
                            log.warn("Unsolicited zonefile %s" % fetched_zfhash)
                            continue

                        rc = store_zonefile_to_storage( zonefiles[fetched_zfhash], required=self.zonefile_storage_drivers, cache=True, zonefile_dir=zonefile_dir )
                        if not rc:
                            log.error("Failed to store zonefile %s" % fetched_zfhash)

                        else:
                            # stored! remember it
                            atlasdb_set_zonefile_present( fetched_zfhash, True, con=con, path=path )
                            zonefile_hashes.remove(fetched_zfhash)
                            peer_zonefile_hashes.remove(fetched_zfhash)
                            num_fetched += 1


                # if the node didn't actually have these zonefiles, then 
                # update their inventories so we don't ask for them again.
                if locked:
                    peer_table = atlas_peer_table_lock()

                for zfhash in peer_zonefile_hashes:
                    atlas_peer_set_zonefile_status( peer_hostport, zfhash, False, zonefile_bits=missing_zfinfo[zfhash]['indexes'], peer_table=peer_table )

                if locked:
                    atlas_peer_table_unlock()
                    peer_table = None

            zonefile_hashes.pop(0)

        if close:
            con.close()

        return num_fetched

    
    def run(self):
        self.running = True
        while self.running:
            con = atlasdb_open( self.path )
            num_fetched = self.step( con=con, path=self.path )
            con.close()
            
            if num_fetched == 0:
                time_sleep(self.hostport, 1.0)


if __name__ == "__main__":
    import blockstack

    # basic unit tests
    class MockDB(object):

        zfstate = {}
        last_block = FIRST_BLOCK_MAINNET
        num_zonefiles = 0

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


        def __init__(self):
            self.lastblock = FIRST_BLOCK_MAINNET
            num_per_block = 5
            for i in xrange(0, 5):
                self.mock_add_zonefile_hashes(num_per_block + i - 4)

            for i in xrange(0, 5):
                self.mock_dup_zonefile_hashes(self.lastblock - 5)


        def get_value_hashes_at( self, lastblock ):
            return [zf["zonefile_hash"] for zf in self.zfstate.get(lastblock, []) ]


    def test_atlasdb_add_zonefile_info( db, path ):
        """
        Test adding more zonefile hashes
        """
        log.debug("test atlasdb_add_zonefile_info()")
        db.mock_add_zonefile_hashes(5)
        new_zonefile_hashes = db.get_value_hashes_at( db.lastblock )
        for zfh in new_zonefile_hashes:
            atlasdb_add_test_info( zfh, False, db.lastblock, path=path )


    def test_atlasdb_get_zonefile_info( db, block_height, path ):
        """
        Test getting zonefile hashes
        """
        log.debug("test atlasdb_get_zonefile_info(%s)" % block_height)
        zonefile_hashes = db.get_value_hashes_at( block_height )
        zfinfo = atlasdb_get_zonefile_info( block_height, path=path )

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


    def test_atlas_make_zonefile_inventory( db, path, zonefile_dir ):
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

        inv_vec = atlas_make_zonefile_inventory( FIRST_BLOCK_MAINNET, db.lastblock, path=path, zonefile_dir=zonefile_dir )
        
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

    atlasdb_init( test_db_path, db, test_peer_seeds, [], zonefile_dir=zonefile_dir )

    """
    Zonefile methods
    """
    if os.environ.get("BLOCKSTACK_ATLAS_UNIT_TEST_DB_SKIP", None) is None:
        test_atlasdb_add_zonefile_info( db, test_db_path )

        for height in xrange(FIRST_BLOCK_MAINNET, db.lastblock-1):
            test_atlasdb_get_zonefile_info( db, height, test_db_path )
            test_atlasdb_set_zonefile_present( db, height, test_db_path )
            test_atlasdb_get_zonefile_bits( db, height, test_db_path )

        for height, zfl in db.zfstate.items():
            for zfs in zfl:
                test_atlasdb_zonefile_info_list( db, zfs['zonefile_hash'], test_db_path )

        test_atlas_make_zonefile_inventory( db, test_db_path, zonefile_dir )

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


