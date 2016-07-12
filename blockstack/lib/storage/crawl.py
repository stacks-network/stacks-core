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

from ..config import *
from ..nameset import *
from .auth import *

from ..scripts import is_name_valid

import blockstack_client
from blockstack_client import hash_zonefile

import blockstack_zones

import virtualchain
log = virtualchain.get_logger("blockstack-server")

def get_cached_zonefile( zonefile_hash, zonefile_dir=None ):
    """
    Get a cached zonefile from local disk
    Return None if not found
    """
    if zonefile_dir is None:
        zonefile_dir = get_zonefile_dir()

    zonefile_path = os.path.join( zonefile_dir, zonefile_hash )
    if not os.path.exists( zonefile_path ):
        return None 

    with open(zonefile_path, "r") as f:
        data = f.read()

    # sanity check 
    if not verify_zonefile( data, zonefile_hash ):
        log.debug("Corrupt zonefile '%s'; uncaching" % zonefile_hash)
        remove_cached_zonefile( zonefile_hash, zonefile_dir=zonefile_dir )
        return None

    try:
        zonefile_dict = blockstack_zones.parse_zone_file( data )
        assert blockstack_client.is_user_zonefile( zonefile_dict ), "Not a user zonefile: %s" % zonefile_hash
        return zonefile_dict
    except Exception, e:
        log.error("Failed to parse zonefile")
        return None


def get_zonefile_from_storage( zonefile_hash, drivers=None ):
    """
    Get a zonefile from our storage drivers.
    Return the zonefile dict on success.
    Raise on error
    """
    
    if not is_current_zonefile_hash( zonefile_hash ):
        raise Exception("Unknown zonefile hash")

    zonefile_txt = blockstack_client.storage.get_immutable_data( zonefile_hash, hash_func=blockstack_client.get_blockchain_compat_hash, deserialize=False, drivers=drivers )
    if zonefile_txt is None:
        raise Exception("Failed to get data")

    # verify
    if blockstack_client.storage.get_zonefile_data_hash( zonefile_txt ) != zonefile_hash:
        raise Exception("Corrupt zonefile: %s" % zonefile_hash)
   
    # parse 
    try:
        user_zonefile = blockstack_zones.parse_zone_file( zonefile_txt )
        assert blockstack_client.is_user_zonefile( user_zonefile ), "Not a user zonefile: %s" % zonefile_hash
    except AssertionError, ValueError:
        raise Exception("Failed to load zonefile %s" % zonefile_hash)

    return user_zonefile


def get_zonefile_from_peers( zonefile_hash, peers ):
    """
    Get a zonefile from a peer Blockstack node.
    Ask each peer (as a list of (host, port) tuples)
    for the zonefile via RPC
    Return a zonefile that matches the given hash on success.
    Return None if no zonefile could be obtained.
    Calculate the on-disk path to storing a zonefile's information, given the zonefile hash
    """
 
    for (host, port) in peers:

        rpc = blockstack_client.BlockstackRPCClient( host, port )
        zonefile_data = rpc.get_zonefiles( [zonefile_hash] )

        if type(zonefile_data) != dict:
            # next peer
            log.debug("Peer %s:%s did not reutrn valid data" % (host, port))
            zonefile_data = None
            continue

        if 'error' in zonefile_data:
            # next peer 
            log.debug("Peer %s:%s: %s" % (host, port, zonefile_data['error']) )
            zonefile_data = None
            continue

        if not zonefile_data['zonefiles'].has_key(zonefile_hash):
            # nope
            log.debug("Peer %s:%s did not return %s" % zonefile_hash)
            zonefile_data = None
            continue

        # extract zonefile
        zonefile_data = zonefile_data['zonefiles'][zonefile_hash]

        if type(zonefile_data) != dict:
            # not a dict 
            log.debug("Peer %s:%s did not return a zonefile for %s" % (host, port, zonefile_hash))
            zonefile_data = None
            continue

        # verify zonefile
        h = hash_zonefile( zonefile_data )
        if h != zonefile_hash:
            log.error("Zonefile hash mismatch: expected %s, got %s" % (zonefile_hash, h))
            zonefile_data = None
            continue

        # success!
        break

    return zonefile_data


def cached_zonefile_dir( zonefile_dir, zonefile_hash ):
    """
    Calculate the on-disk path to storing a zonefile's information, given the zonefile hash
    """

    # split into directories, so we don't try to cram millions of files into one directory
    zonefile_dir_parts = []
    for i in xrange(0, len(zonefile_hash), 8):
        zonefile_dir_parts.append( zonefile_hash[i:i+8] )

    zonefile_dir_path = os.path.join(zonefile_dir, "/".join(zonefile_dir_parts))
    return zonefile_dir_path


def store_cached_zonefile( zonefile_dict, zonefile_dir=None ):
    """
    Store a validated zonefile.
    zonefile_data should be a dict.
    The caller should first authenticate the zonefile.
    Return True on success
    Return False on error
    """
    if zonefile_dir is None:
        zonefile_dir = get_zonefile_dir()

    if not os.path.exists(zonefile_dir):
        os.makedirs(zonefile_dir, 0700 )

    try:
        zonefile_data = blockstack_zones.make_zone_file( zonefile_dict )
    except Exception, e:
        log.exception(e)
        log.error("Invalid zonefile dict")
        return False

    zonefile_hash = blockstack_client.get_zonefile_data_hash( zonefile_data )
    zonefile_dir_path = cached_zonefile_dir( zonefile_dir, zonefile_hash )
    if not os.path.exists(zonefile_dir_path):
        os.makedirs(zonefile_dir_path)

    zonefile_path = os.path.join(zonefile_dir_path, "zonefile.txt")
    try:
        with open( zonefile_path, "w" ) as f:
            f.write(zonefile_data)
            f.flush()
            os.fsync(f.fileno())
    except Exception, e:
        log.exception(e)
        return False
        
    return True


def get_zonefile_txid( zonefile_dict ):
    """
    Look up the transaction ID of the transaction
    that wrote this zonefile.
    Return the txid on success
    Return None on error
    """
   
    zonefile_hash = hash_zonefile( zonefile_dict )
    name = zonefile_dict.get('$origin')
    if name is None:
        log.debug("Missing '$origin' in zonefile")
        return None

    # must be a valid name 
    db = get_db_state()
    name_rec = db.get_name( name )
    if name_rec is None:
        log.debug("Invalid name in zonefile")
        return None

    # what's the associated transaction ID?
    txid = db.get_name_value_hash_txid( name, zonefile_hash )
    if txid is None:
        log.debug("No txid for zonefile hash '%s' (for '%s')" % (zonefile_hash, name))
        return None

    return txid


def store_zonefile_to_storage( zonefile_dict, required=[] ):
    """
    Upload a zonefile to our storage providers.
    Return True if at least one provider got it.
    Return False otherwise.
    """
    zonefile_hash = hash_zonefile( zonefile_dict )
    name = zonefile_dict['$origin']
    zonefile_text = blockstack_zones.make_zone_file( zonefile_dict )
   
    # find the tx that paid for this zonefile
    txid = get_zonefile_txid( zonefile_dict )
    if txid is None:
        log.error("No txid for zonefile hash '%s' (for '%s')" % (zonefile_hash, name))
        return False
   
    rc = blockstack_client.storage.put_immutable_data( None, txid, data_hash=zonefile_hash, data_text=zonefile_text, required=required )
    if not rc:
        log.error("Failed to store zonefile '%s' (%s) for '%s'" % (zonefile_hash, txid, name))
        return False

    return True


def remove_cached_zonefile( zonefile_hash, zonefile_dir=None ):
    """
    Remove a zonefile from the local cache.
    """
    if zonefile_dir is None:
        zonefile_dir = get_zonefile_dir()

    path = os.path.join( zonefile_dir, zonefile_hash )
    try:
        os.unlink(path)
        return True
    except:
        return False


def remove_zonefile_from_storage( zonefile_dict, wallet_keys=None ):
    """
    Remove a zonefile from external storage
    Return True on success
    Return False on error
    """
    zonefile_txt = serialize_zonefile( zonefile_dict )
    zonefile_hash = hash_zonefile( zonefile_txt )

    if not is_current_zonefile_hash( zonefile_hash ):
        log.error("Unknown zonefile %s" % zonefile_hash)
        return False

    # find the tx that paid for this zonefile
    txid = get_zonefile_txid( zonefile_dict )
    if txid is None:
        log.error("No txid for zonefile hash '%s' (for '%s')" % (zonefile_hash, name))
        return False
    
    _, data_privkey = blockstack_client.get_data_keypair( wallet_keys=wallet_keys )
    rc = blockstack_client.storage.delete_immutable_data( zonefile_hash, txid, data_privkey )
    if not rc:
        return False

    return True


def clean_cached_zonefile_dir( zonefile_dir=None ):
    """
    Clean out stale entries in the zonefile directory.
    """
    if zonefile_dir is None:
        zonefile_dir = get_zonefile_dir()

    db = get_db_state()
    hashes = os.listdir( zonefile_dir )
    for h in hashes:
        if h in ['.', '..']:
            continue 

        remove_zonefile( h, zonefile_dir=zonefile_dir )

    return

