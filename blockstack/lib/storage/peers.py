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
import json
import sys
import urllib2
import stat
import time
import random
import binascii

from ..config import *
from ..nameset import *
from .auth import *
from .monitor import *

import blockstack_client
import blockstack_profiles
import virtualchain
log = virtualchain.get_logger("blockstack-server")

# current set of seed blockchain IDs
PEER_LIST_IDS = [
    "blockstackmirrors.id"
]

def get_seed_blockstack_ids():
    """
    Get the list of blockstack IDs that we use to seed our peer set
    """
    global PEER_LIST_IDS
    return PEER_LIST_IDS


def get_tx( txid ):
    """
    Get a tx from the blockchain, given the txid.
    Return the JSON-ized transaction information on success
    Return None on error
    """
    blockchain_opts = default_bitcoind_opts()
    blockchain_client = virtualchain.connect_bitcoind( blockchain_opts )

    try:
        txdata = blockchain_client.getrawtransaction( txid, 1 )
    except Exception, e:
        log.exception(e)
        log.debug("Failed to get transaction %s" % txid)
        return None

    rc = virtualchain.tx_verify( txdata, txid )
    if not rc:
        log.debug("Transaction data hash mismatch")
        return None 

    return txdata


def lookup_peer_list_url_and_pubkey( blockstack_peer_id, working_dir=None ):
    """
    Given the blockchain ID of a blockstack peer, go and fetch
    and validate its peer-list URL and public key.

    The blockstack peer's zonefile hash (32 bytes) must encode a URL,
    which must refer to a JWT signed with the private key that issued
    the NAME_UPDATE that put the zonefile hash in place.

    Return {'url': url, 'public_key': public_key} on success
    Return None on error
    """
    db = get_db_state()
    name_rec = db.get_name( blockstack_peer_id )
    if name_rec is None:
        # not found
        log.error("Peer '%s' is not in the database")
        return None 

    zonefile_hash = name_rec['value_hash']
    if zonefile_hash is None:
        # no record 
        log.error("Peer '%s' has no zonefile hash")
        return None 

    # does it de-hexlify into a URL?
    zonefile_hash_bin = binascii.unhexlify(zonefile_hash)
    if not zonefile_hash_bin.startswith("http://") and not zonefile_hash_bin.startswith("https://"):
        # not a valid URL 
        log.error("Peer '%s' does not have a URL in the zonefile hash")
        return None 

    url = zonefile_hash_bin.strip("\0")

    # find the txid that created the value hash
    txid = db.get_name_value_hash_txid( blockchain_peer_id, zonefile_hash )
    if txid is None:
        log.error("No txid found for %s (zonefile hash %s)" % (blockstack_peer_id, zonefile_hash))
        return None 

    # get the tx information
    txdata = get_tx( txid )
    if txidata is None:
        log.error("Failed to fetch tx %s" % txid)
        return None
    
    # get the sender information (sender 0 is the sender we care about)
    try:
        sender, amount_in = virtualchain.get_sender_and_amount_in_from_txn( txdata, 0 )
        if sender is None:
            log.error("Failed to extract sender info for tx %s" % txid)
    except Exception, e:
        log.exception(e)
        log.error("Failed to extract sender info from tx %s" % txid)

    # get the public key!
    public_key = sender['sender_pubkey']
    if public_key is None:
        log.error("Incompatible transaction type: NAME_UPDATE input must be a pay-to-pubkey-hash script")
        return None

    return {'url': url, 'public_key': public_key}


def validate_peer_list( peer_list ):
    """
    Validate the structural integrity of a peer list
    Return True if valid
    Return False if not
    """
    if type(peer_list) != list:
        return False

    for peer_entry in peer_list:
        if type(peer_entry) != dict:
            log.debug("Peer %s:%s: malformed peer entry" % (host, port))
            return False

        for k in ['host', 'port']:
            if k not in peer_entry.keys():
                log.debug("Peer %s:%s: missing '%s'" % (host,port,k))
                return False

        peer_host = peer_entry['host']
        peer_port = peer_entry['port']

        try:
            peer_port = int(peer_port)
        except:
            log.debug("Peer %s:%s: invalid port" % (host,port))
            return False

        if peer_port < 0 or peer_port > 65535:
            log.debug("Peer %s:%s: invalid port number" % (host,port))
            return False

        if type(peer_host) not in [str, unicode]:
            log.debug("Peer %s:%s: invalid peer host" % (host,port))
            return False

        if len(peer_host) > 253:
            log.debug("Peer %s:%s: invalid peer hostname" % (host,port))
            return False

    return True


def download_peer_list( url, public_key ):
    """
    Given a URL and a public key,
    fetch and verify a peer list.
    Return a list of {'host': host, 'port': port} on success
    Return None on error
    """
    # fetch the data!
    try:
        peerlist = opener.open( url )
        peer_txt = peerlist.read(1024 * 1024)     # maximum size is 1MB
        peerlist.close()
    except Exception, e:
        log.exception(e)
        log.debug("Failed to fetch peer list from '%s'" % url)
        return None 

    # must be a signed JWT
    try:
        peer_jwt = json.loads(peer_txt)
        peer_info = blockstack_profiles.get_profile_from_tokens( peer_txt, public_key )

        assert peer_info is not None and len(peer_info) > 0, "No peer information could be extracted"
    except Exception, e:
        log.exception(e)
        log.debug("Failed to parse peer list from '%s'" % url)
        return None

    # extract peer information
    try:
        assert peer_info.has_key('peers'), "Missing peers list"
        assert validate_peer_list( peer_info['peers'] ), "Invalid peer list"
    except Exception, e:
        log.exception(e)
        log.debug("Invalid peer list")
        return None

    return peer_info['peers']


def cache_peers( peers, working_dir=None ):
    """
    Cache the list of peers.
    peers should be a list of {'host': host, 'port': port} 
    """
    
    peer_data = []
    for peer in peers:
        peer_data.append({
            "host": peer['host'],
            "port": peer['port']
        })

    peer_txt = json.dumps(peer_data, sort_keys=True)
    peer_filepath = get_peer_cache_filename( working_dir=working_dir )
    with open(peer_filepath, "w") as f:
        f.write(peer_txt)
        f.flush()
        os.fsync(f.fileno())

    return 


def load_cached_peers( working_dir=None ):
    """
    Get the list of cached peers
    Return a list of {'host': host, 'port': port} tuples
    Return [] if there are none cached.
    """
    peer_filepath = get_peer_cache_filename( working_dir=working_dir )
    if not os.path.exists( peer_filepath ):
        return []

    with open(peer_filepath, "r") as f:
        peer_txt = f.read()

    peer_info = json.loads(peer_txt)
    ret = []
    for info in peer_info:
        ret.append({
            'host': info['host'],
            'port': info['port']
        })

    return ret


def explore_peer( host, port, known_peers ):
    """
    Get the list of peers that the given peer knows about.
    Return list of {'host': host, 'port': port} peers on success
    Return [] if we couldn't contact the peer
    Return None if we should never contact this peer again (i.e. they gave
        back invalid data)
    """
    
    blockstack_rpc = blockstack_client.session(server_host=host, server_port=port)
    rpc = MonitoredRPCClient( blockstack_rpc )
    try:
        peer_listing = rpc.list_zonefile_peers()
    except Exception, e:
        log.exception(e)
        log.error("Could not contact %s:%s" % (host, port))
        return []

    if 'error' in peer_listing:
        log.debug("Peer %s:%s says: %s" % (host, port, peer_listing['error']))
        return []

    if 'peers' not in peer_listing:
        log.debug("Peer %s:%s: no peers given" % (host, port))
        return None

    if not validate_peer_list( peer_listing['peers'] ):
        log.debug("Invalid peer list")
        return None

    new_peers = []
    for peer_entry in peer_listing['peers']:

        # have seen?
        hostport = "%s:%s" % (peer_entry['host'], peer_entry['port'])
        if hostport in known_peers.keys():
            continue

        new_peers.append( peer_entry )

    return new_peers


def should_test_peer( last_seen, ttl, jitter ):
    """
    Should we ping a peer to see if it's up?
    """
    offset = (random.rand() - 0.5) * jitter
    return last_seen + ttl + offset < time.time()


def test_peer( host, port, timeout=5 ):
    """
    Ping a peer, and see if it's alive
    and responding in a timely fashion.
    """
    blockstack_rpc = blockstack_client.session( server_host=host, server_port=port )
    rpc = MonitoredRPCClient( blockstack_rpc )

    try:
        ret = rpc.zonefile_ping()
    except:
        return False 

    if 'error' in ret:
        # not alive 
        return False

    return True
    

def prune_offline_peers( peer_list, timeout ):
    """
    Find peers that are online.
    Returned the subset that are.
    """
    ret = []
    for peer_info in peer_list:
        rc = test_peer( peer_info['host'], peer_info['port'], timeout=timeout )
        if rc:
            # alive!
            ret.append( peer_info )

    return ret


def find_initial_peers( seed_blockstack_ids, working_dir=None, existing_peers={} ):
    """
    Use the seed blockstack IDs to find an initial set of peers.
    Return a list of {'host': host, 'port': port} on success
    """

    # get the initial set of peers
    peers = {}
    for blockstack_id in seed_blockstack_ids:
        peer_list_info = lookup_peer_list_url_and_pubkey( blockstack_id )
        if peer_list_info is None:
            log.info("Ignoring peer '%s'" % blockstack_id)
            continue

        peer_infos = download_peer_list( url )
        if peer_infos is None:
            log.info("Ignoring peer list from '%s'" % blockstack_id)
            continue

        # merge into set
        for peer_info in peer_infos:
            hostport = "%s:%s" % (peer_info['host'], peer_info['port'])
            peers[hostport] = peer_info

    return peer_list


def find_frontier_peers( frontier_peers, known_peers, working_dir=None ):
    """
    Given a set of known peers and the last set of frontier peers, go and find the
    new frontier--their known peers that we don't know about.
    Return a list of {'host': host, 'port': port} on success 
    """

    peer_list = frontier_peers.keys()
    random.shuffle(peer_list)

    new_frontier = {}
    all_peers = copy.deepcopy(known_peers)
    all_peers.update( copy.deepcopy(frontier_peers) )

    for i in xrange(0, peer_list):

        peer_info = peers[ peer_list[i] ]
        neighbor_peers = explore_peer( peer_info['host'], peer_info['port'], all_peers )

        new_frontier.update( neighbor_peers )
        all_peers.update( neighbor_peers )

    return [hostinfo for (hostport, hostinfo) in new_frontier.items()]


