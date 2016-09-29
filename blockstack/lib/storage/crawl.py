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
from blockstack_client import hash_zonefile, get_zonefile_data_hash

import blockstack_zones

import virtualchain
log = virtualchain.get_logger("blockstack-server")

def get_cached_zonefile_data( zonefile_hash, zonefile_dir=None ):
    """
    Get a serialized cached zonefile from local disk 
    Return None if not found
    """
    if zonefile_dir is None:
        zonefile_dir = get_zonefile_dir()

    zonefile_path_dir = cached_zonefile_dir( zonefile_dir, zonefile_hash )
    zonefile_path = os.path.join( zonefile_path_dir, "zonefile.txt" )
    if not os.path.exists( zonefile_path ):
        log.debug("No zonefile at %s" % zonefile_path )
        return None 

    with open(zonefile_path, "r") as f:
        data = f.read()

    # sanity check 
    if not verify_zonefile( data, zonefile_hash ):
        log.debug("Corrupt zonefile '%s'" % zonefile_hash)
        return None

    return data


def get_cached_zonefile( zonefile_hash, zonefile_dir=None ):
    """
    Get a cached zonefile dict from local disk 
    Return None if not found
    """
    data = get_cached_zonefile_data( zonefile_hash, zonefile_dir=zonefile_dir )
    if data is None:
        log.debug("Not cached: %s" % zonefile_hash)
        return None

    try:
        zonefile_dict = blockstack_zones.parse_zone_file( data )
        assert blockstack_client.is_user_zonefile( zonefile_dict ), "Not a user zonefile: %s" % zonefile_hash
        return zonefile_dict
    except Exception, e:
        log.error("Failed to parse zonefile")
        return None


def get_zonefile_data_from_storage( zonefile_hash, name=None, drivers=None ):
    """
    Get a serialized zonefile from our storage drivers.
    Return the zonefile dict on success.
    Raise on error
    """
    names = [None]
    if name is None:
        db = get_db_state()
        names_with_hash = db.get_names_with_value_hash( zonefile_hash )
        if names_with_hash is not None:
            names = names_with_hash + names
        
    for name in names:
        zonefile_txt = blockstack_client.storage.get_immutable_data( zonefile_hash, hash_func=blockstack_client.get_blockchain_compat_hash, fqu=name, zonefile=True, deserialize=False, drivers=drivers )
        if zonefile_txt is None:
            continue

        # verify
        if blockstack_client.storage.get_zonefile_data_hash( zonefile_txt ) != zonefile_hash:
            log.warn("Corrupted zonefile for '%s'" % name)
            continue

        break

    if zonefile_txt is None:
        raise Exception("Failed to get valid data")
   
    return zonefile_txt


def get_zonefile_from_storage( zonefile_hash, name=None, drivers=None ):
    """
    Get a zonefile from our storage drivers.
    Return the zonefile dict on success.
    Raise on error
    """
    zonefile_txt = get_zonefile_data_from_storage( zonefile_hash, name=name, drivers=drivers )
    if zonefile_txt is None:
        raise Exception("Failed to load zonefile data %s" % zonefile_hash)
   
    # parse 
    try:
        user_zonefile = blockstack_zones.parse_zone_file( zonefile_txt )
        assert blockstack_client.is_user_zonefile( user_zonefile ), "Not a user zonefile: %s" % zonefile_hash
    except AssertionError, ValueError:
        raise Exception("Failed to load zonefile %s" % zonefile_hash)

    return user_zonefile


def cached_zonefile_dir( zonefile_dir, zonefile_hash ):
    """
    Calculate the on-disk path to storing a zonefile's information, given the zonefile hash
    """

    # split into directories, so we don't try to cram millions of files into one directory
    zonefile_dir_parts = []
    interval = 2
    for i in xrange(0, len(zonefile_hash), interval):
        zonefile_dir_parts.append( zonefile_hash[i:i+interval] )

    zonefile_dir_path = os.path.join(zonefile_dir, "/".join(zonefile_dir_parts))
    return zonefile_dir_path


def is_zonefile_cached( zonefile_hash, zonefile_dir=None, validate=False):
    """
    Do we have the cached zonefile?
    if @validate is true, then check that the data in zonefile_dir_path/zonefile.txt matches zonefile_hash
    Return True if so
    Return False if not
    """
    if zonefile_dir is None:
        zonefile_dir = get_zonefile_dir()
    
    zonefile_path_dir = cached_zonefile_dir( zonefile_dir, zonefile_hash )
    zonefile_path = os.path.join(zonefile_path_dir, "zonefile.txt")

    if not os.path.exists(zonefile_path):
        return False

    if validate:
        zf = get_cached_zonefile( zonefile_hash, zonefile_dir=zonefile_dir )
        if zf is None:
            return False

    return True


def store_cached_zonefile_data( zonefile_data, zonefile_dir=None ):
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


def store_cached_zonefile( zonefile_dict, zonefile_dir=None ):
    """
    Store a validated zonefile.
    zonefile_data should be a dict.
    The caller should first authenticate the zonefile.
    Return True on success
    Return False on error
    """
    try:
        zonefile_data = blockstack_zones.make_zone_file( zonefile_dict )
    except Exception, e:
        log.exception(e)
        log.error("Invalid zonefile dict")
        return False

    return store_cached_zonefile_data( zonefile_data, zonefile_dir=zonefile_dir )


def get_zonefile_data_txid( zonefile_data, name ):
    """
    Look up the transaction ID of the transaction
    that wrote this zonefile.
    Return the txid on success
    Return None on error
    """
   
    zonefile_hash = get_zonefile_data_hash( zonefile_data )
    txid = None 

    db = get_db_state()

    name_rec = db.get_name( name )
    if name_rec is None:
        db.close()
        log.debug("Invalid name '%s'" % name)
        return None 
        
    # must be a valid name 
    txid = db.get_name_value_hash_txid( name, zonefile_hash )
    db.close()

    if txid is None:
        log.debug("No txid for zonefile hash '%s' (for '%s')" % (zonefile_hash, name))
        return None

    return txid


def store_zonefile_data_to_storage( zonefile_text, required=[], cache=False, zonefile_dir=None, name=None, tx_required=True ):
    """
    Upload a zonefile to our storage providers.
    Return True if at least one provider got it.
    Return False otherwise.
    """
    zonefile_hash = get_zonefile_data_hash( zonefile_text )
    
    if cache:
        rc = store_cached_zonefile_data( zonefile_text, zonefile_dir=zonefile_dir )
        if not rc:
            log.debug("Failed to cache zonefile %s" % zonefile_hash)

    txid = None

    # this can be turned off in testing in a network simulator 
    if os.environ.get("BLOCKSTACK_ATLAS_NETWORK_SIMULATION") != "1" and name is not None:

        # find the tx that paid for this zonefile
        txid = get_zonefile_data_txid( zonefile_text, name )
        if tx_required and txid is None:
            log.error("No txid for zonefile hash '%s' (for '%s')" % (zonefile_hash, name))
            return False
  
    # NOTE: this can fail if one of the required drivers needs a non-null txid
    rc = blockstack_client.storage.put_immutable_data( None, txid, data_hash=zonefile_hash, data_text=zonefile_text, required=required )
    if not rc:
        log.error("Failed to store zonefile '%s' (%s) for '%s'" % (zonefile_hash, txid, name))
        return False

    return True


def store_zonefile_to_storage( zonefile_dict, required=[], cache=False, zonefile_dir=None ):
    """
    Upload a zonefile to our storage providers.
    Return True if at least one provider got it.
    Return False otherwise.
    """

    try:
        zonefile_data = blockstack_zones.make_zone_file( zonefile_dict )
    except Exception, e:
        log.exception(e)
        log.error("Invalid zonefile dict")
        return False

    name = zonefile_dict.get('$origin')
    return store_zonefile_data_to_storage( zonefile_data, required=required, cache=cache, zonefile_dir=zonefile_dir, name=name )


