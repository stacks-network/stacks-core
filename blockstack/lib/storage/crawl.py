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

from ..config import *
from ..nameset import *
from .auth import *

from ..scripts import is_name_valid

import blockstack_client
from blockstack_client import get_zonefile_data_hash, verify_zonefile

import blockstack_zones

import virtualchain
log = virtualchain.get_logger("blockstack-server")

def _read_cached_zonefile( zonefile_path, zonefile_hash ):
    """
    Read and verify a cached zone file
    """

    with open(zonefile_path, "r") as f:
        data = f.read()

    # sanity check 
    if not verify_zonefile( data, zonefile_hash ):
        log.debug("Corrupt zonefile '%s'" % zonefile_hash)
        return None

    return data


def get_cached_zonefile_data( zonefile_hash, zonefile_dir=None ):
    """
    Get a serialized cached zonefile from local disk 
    Return None if not found
    """
    if zonefile_dir is None:
        zonefile_dir = get_zonefile_dir()

    zonefile_path = cached_zonefile_path(zonefile_dir, zonefile_hash)
    zonefile_path_legacy = cached_zonefile_path_legacy(zonefile_dir, zonefile_hash)

    for zfp in [zonefile_path, zonefile_path_legacy]:

        if not os.path.exists( zfp ):
            continue

        res = _read_cached_zonefile(zfp, zonefile_hash)
        if res:
            return res

    return None


def get_cached_zonefile( zonefile_hash, zonefile_dir=None ):
    """
    Get a cached zonefile dict from local disk 
    Return None if not found
    """
    data = get_cached_zonefile_data( zonefile_hash, zonefile_dir=zonefile_dir )
    if data is None:
        return None

    try:
        zonefile_dict = blockstack_zones.parse_zone_file( data )
        assert blockstack_client.is_user_zonefile( zonefile_dict ), "Not a user zonefile: %s" % zonefile_hash
        return zonefile_dict
    except Exception, e:
        log.error("Failed to parse zonefile")
        return None


def get_zonefile_data_from_storage( name, zonefile_hash, drivers=None ):
    """
    Get a serialized zonefile from our storage drivers.
    Return the zonefile dict on success.
    Raise on error
    """
    log.debug("Get zonefile {} for {} using '{}'".format(zonefile_hash, name, ",".join(drivers if drivers is not None else ["(all)"])))
    zonefile_txt = blockstack_client.storage.get_immutable_data( zonefile_hash, hash_func=blockstack_client.get_blockchain_compat_hash, fqu=name, zonefile=True, drivers=drivers )
    if zonefile_txt is None:
        raise Exception("Failed to get valid zonefile data")

    # verify
    if get_zonefile_data_hash( zonefile_txt ) != zonefile_hash:
        log.warn("Corrupted zonefile for '%s'" % name)
        raise Exception("Corrupt zonefile")
   
    return zonefile_txt


def cached_zonefile_path( zonefile_dir, zonefile_hash ):
    """
    Calculate the on-disk path to storing a zonefile's information, given the zone file hash.
    If the zonefile hash is abcdef1234567890, then the path will be $zonefile_dir/ab/cd/abcdef1234567890.txt

    Returns the path.
    """
    # split into directories, but not too many
    zonefile_dir_parts = []
    interval = 2
    for i in xrange(0, min(len(zonefile_hash), 4), interval):
        zonefile_dir_parts.append( zonefile_hash[i:i+interval] )

    zonefile_path = os.path.join(zonefile_dir, '/'.join(zonefile_dir_parts), '{}.txt'.format(zonefile_hash))
    return zonefile_path


def cached_zonefile_path_legacy( zonefile_dir, zonefile_hash ):
    """
    Calculate the *legacy* on-disk path to storing a zonefile's information, given the zonefile hash.
    If the zonefile hash is abcdef1234567890, then the path will be $zonefile_dir/ab/cd/ef/12/34/56/78/90/zonefile.txt

    This format is no longer used to create new zonefiles, since it takes a lot of inodes to store comparatively few zone files.

    Returns the legacy path
    """

    # split into directories, so we don't try to cram millions of files into one directory
    zonefile_dir_parts = []
    interval = 2
    for i in xrange(0, len(zonefile_hash), interval):
        zonefile_dir_parts.append( zonefile_hash[i:i+interval] )

    zonefile_dir_path = os.path.join(zonefile_dir, "/".join(zonefile_dir_parts))
    return os.path.join(zonefile_dir_path, "zonefile.txt")


def is_zonefile_cached( zonefile_hash, zonefile_dir=None, validate=False):
    """
    Do we have the cached zonefile?  It's okay if it's a non-standard zonefile.
    if @validate is true, then check that the data in zonefile_dir_path/zonefile.txt matches zonefile_hash

    Return True if so
    Return False if not
    """
    if zonefile_dir is None:
        zonefile_dir = get_zonefile_dir()
    
    zonefile_path = cached_zonefile_path(zonefile_dir, zonefile_hash)
    zonefile_path_legacy = cached_zonefile_path_legacy(zonefile_dir, zonefile_hash)

    res = False
    for zfp in [zonefile_path, zonefile_path_legacy]:
        
        if not os.path.exists(zfp):
            continue

        if validate:
            data = _read_cached_zonefile(zfp, zonefile_hash)
            if data:
                # yup!
                res = True
                break

        else:
            res = True
            break

    return res


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

    zonefile_hash = get_zonefile_data_hash( zonefile_data )
    
    # only store to the latest supported directory
    zonefile_path = cached_zonefile_path( zonefile_dir, zonefile_hash )
    zonefile_dir_path = os.path.dirname(zonefile_path)

    if not os.path.exists(zonefile_dir_path):
        os.makedirs(zonefile_dir_path)

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


def remove_cached_zonefile_data( zonefile_hash, zonefile_dir=None ):
    """
    Remove a cached zonefile.
    Idempotent; returns True if deleted or it didn't exist.
    Returns False on error
    """
    if zonefile_dir is None:
        zonefile_dir = get_zonefile_dir()

    if not os.path.exists(zonefile_dir):
        return True

    zonefile_hash = get_zonefile_data_hash( zonefile_data )
    zonefile_path = cached_zonefile_path( zonefile_dir, zonefile_hash )
    zonefile_path_legacy = cached_zonefile_path_legacy( zonefile_dir, zonefile_hash )

    for zfp in [zonefile_path, zonefile_path_legacy]:
        if not os.path.exists(zonefile_path):
            continue

        try:
            os.unlink(zonefile_path)
        except:
            log.error("Failed to unlink zonefile %s (%s)" % (zonefile_hash, zonefile_path))
            return False

    return True


def store_zonefile_data_to_storage( zonefile_text, txid, required=None, skip=None, cache=False, zonefile_dir=None, tx_required=True ):
    """
    Upload a zonefile to our storage providers.
    Return True if at least one provider got it.
    Return False otherwise.
    """
    if tx_required and txid is None:
        log.error("No txid for zonefile hash '%s'" % (zonefile_hash))
        return False

    zonefile_hash = get_zonefile_data_hash( zonefile_text )
    
    if cache:
        rc = store_cached_zonefile_data( zonefile_text, zonefile_dir=zonefile_dir )
        if not rc:
            log.debug("Failed to cache zonefile %s" % zonefile_hash)

    # NOTE: this can fail if one of the required drivers needs a non-null txid
    res = blockstack_client.storage.put_immutable_data( zonefile_text, txid, data_hash=zonefile_hash, required=required, skip=skip, required_exclusive=True )
    if res is None:
        log.error("Failed to store zonefile '%s' for '%s'" % (zonefile_hash, txid))
        return False

    return True


def store_zonefile_to_storage( zonefile_dict, required=None, skip=None, cache=False, zonefile_dir=None ):
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
    log.debug("Store zonefile for {} to drivers '{}'".format(name, ','.join(required if required is not None else [])))
    return store_zonefile_data_to_storage( zonefile_data, required=required, skip=skip, cache=cache, zonefile_dir=zonefile_dir, name=name )


def store_mutable_data_to_storage( blockchain_id, data_id, data_txt, profile=False, required=None, skip=None ):
    """
    Store the given mutable datum to storage providers.
    Used by the storage gateway logic.
    Return True on successful replication to all required drivers
    Return False on error
    """
    nocollide_data_id = None
    if profile:
        nocollide_data_id = blockchain_id

    else:
        nocollide_data_id = '{}-{}'.format(blockchain_id, data_id)

    log.debug("Store {} to drivers '{}', skipping '{}'".format('profile' if profile else 'mutable datum', ','.join(required if required is not None else []), ','.join(skip if skip is not None else [])))
    res = blockstack_client.storage.put_mutable_data(nocollide_data_id, data_txt, sign=False, raw=True, required=required, skip=skip, blockchain_id=blockchain_id)
    return res


def load_mutable_data_from_storage( blockchain_id, data_id, drivers=None ):
    """
    Load mutable data from storage.
    Used by the storage gateway logic.
    Return 
    """
    
    nocollide_data_id = '{}-{}'.format(blockchain_id, data_id)
    res = blockstack_client.storage.get_mutable_data(nocollide_data_id, None, blockchain_id=blockchain_id, drivers=drivers, decode=False)
    return res
   
