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

import blockstack_zones

import virtualchain
log = virtualchain.get_logger("blockstack-server")

def _read_atlas_zonefile( zonefile_path, zonefile_hash ):
    """
    Read and verify an atlas zone file
    """

    with open(zonefile_path, "r") as f:
        data = f.read()

    # sanity check 
    if not verify_zonefile( data, zonefile_hash ):
        log.debug("Corrupt zonefile '%s'" % zonefile_hash)
        return None

    return data


def get_atlas_zonefile_data( zonefile_hash, zonefile_dir ):
    """
    Get a serialized cached zonefile from local disk 
    Return None if not found
    """
    zonefile_path = atlas_zonefile_path(zonefile_dir, zonefile_hash)
    zonefile_path_legacy = atlas_zonefile_path_legacy(zonefile_dir, zonefile_hash)

    for zfp in [zonefile_path, zonefile_path_legacy]:

        if not os.path.exists( zfp ):
            continue

        res = _read_atlas_zonefile(zfp, zonefile_hash)
        if res:
            return res

    return None


def atlas_zonefile_path( zonefile_dir, zonefile_hash ):
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


def atlas_zonefile_path_legacy( zonefile_dir, zonefile_hash ):
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


def is_zonefile_cached( zonefile_hash, zonefile_dir, validate=False):
    """
    Do we have the cached zonefile?  It's okay if it's a non-standard zonefile.
    if @validate is true, then check that the data in zonefile_dir_path/zonefile.txt matches zonefile_hash

    Return True if so
    Return False if not
    """
    zonefile_path = atlas_zonefile_path(zonefile_dir, zonefile_hash)
    zonefile_path_legacy = atlas_zonefile_path_legacy(zonefile_dir, zonefile_hash)

    res = False
    for zfp in [zonefile_path, zonefile_path_legacy]:
        
        if not os.path.exists(zfp):
            continue

        if validate:
            data = _read_atlas_zonefile(zfp, zonefile_hash)
            if data:
                # yup!
                res = True
                break

        else:
            res = True
            break

    return res


def store_atlas_zonefile_data(zonefile_data, zonefile_dir, fsync=True):
    """
    Store a validated zonefile.
    zonefile_data should be a dict.
    The caller should first authenticate the zonefile.
    Return True on success
    Return False on error
    """
    if not os.path.exists(zonefile_dir):
        os.makedirs(zonefile_dir, 0700 )

    zonefile_hash = get_zonefile_data_hash( zonefile_data )
    
    # only store to the latest supported directory
    zonefile_path = atlas_zonefile_path( zonefile_dir, zonefile_hash )
    zonefile_dir_path = os.path.dirname(zonefile_path)

    if not os.path.exists(zonefile_dir_path):
        os.makedirs(zonefile_dir_path)

    try:
        with open( zonefile_path, "w" ) as f:
            f.write(zonefile_data)
            f.flush()
            if fsync:
                os.fsync(f.fileno())

    except Exception, e:
        log.exception(e)
        return False
        
    return True


def remove_atlas_zonefile_data( zonefile_hash, zonefile_dir ):
    """
    Remove a cached zonefile.
    Idempotent; returns True if deleted or it didn't exist.
    Returns False on error
    """
    if not os.path.exists(zonefile_dir):
        return True

    zonefile_path = atlas_zonefile_path( zonefile_dir, zonefile_hash )
    zonefile_path_legacy = atlas_zonefile_path_legacy( zonefile_dir, zonefile_hash )

    for zfp in [zonefile_path, zonefile_path_legacy]:
        if not os.path.exists(zonefile_path):
            continue

        try:
            os.unlink(zonefile_path)
        except:
            log.error("Failed to unlink zonefile %s (%s)" % (zonefile_hash, zonefile_path))
            return False

    return True


def add_atlas_zonefile_data(zonefile_text, zonefile_dir, fsync=True):
    """
    Add a zone file to the atlas zonefiles
    Return True on success
    Return False on error
    """

    rc = store_atlas_zonefile_data(zonefile_text, zonefile_dir, fsync=fsync)
    if not rc:
        zonefile_hash = get_zonefile_data_hash( zonefile_text )
        log.error("Failed to save zonefile {}".format(zonefile_hash))
        rc = False

    return rc

