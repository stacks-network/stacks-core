#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016-2017 by Blockstack.org

    This file is part of Blockstack-client.

    Blockstack-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack-client. If not, see <http://www.gnu.org/licenses/>.
"""

import json
import os
import sys
import time
import jsontokens
import urllib
import virtualchain
import posixpath
import uuid
import errno
import hashlib
import jsontokens
import collections
import threading
import functools
import traceback
import sqlite3

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")
if not parent_dir in sys.path:
    sys.path.insert(0, parent_dir)

from keylib import *

import virtualchain
from virtualchain.lib.ecdsalib import *

from logger import get_logger
from proxy import get_default_proxy
from config import get_config, get_local_device_id
from constants import BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, DEFAULT_DEVICE_ID, CONFIG_PATH
from schemas import *
from storage import sign_data_payload, make_data_tombstone, make_fq_data_id, sign_data_tombstone, parse_data_tombstone, verify_data_tombstone, parse_fq_data_id, \
        hash_data_payload, sign_data_payload, serialize_mutable_data, get_storage_handlers, verify_data_payload, get_mutable_data, get_immutable_data, get_data_hash, \
        put_immutable_data

log = get_logger('gaia-metadata')

MUTABLE_DATA_VERSION_LOCK = threading.Lock()

def serialize_mutable_data_id(data_id):
    """
    Turn a data ID into a suitable filesystem name
    """
    return urllib.quote(urllib.unquote(data_id).replace('\0', '\\0')).replace('/', r'\x2f')


def get_metadata_dir(conf, config_path=CONFIG_PATH):
    """
    Get the absolute path to the metadata directory
    """
    metadata_dir = conf.get('metadata', None)
    assert metadata_dir, "Config file is missing blockstack_client.metadata"

    if posixpath.normpath(os.path.abspath(metadata_dir)) != posixpath.normpath(conf['metadata']):
        # relative path; make absolute
        metadata_dir = posixpath.normpath( os.path.join(os.path.dirname(config_path), metadata_dir) )

    return metadata_dir


def load_mutable_data_version(conf, device_id, fq_data_id, config_path=CONFIG_PATH):
    """
    Get the version field of a piece of mutable data from local cache.
    Return the version on success
    Return None if not found
    Raise on invalid input
    """

    # try to get the current, locally-cached version
    conf = get_config(path=config_path) if conf is None else conf

    if conf is None:
        msg = 'No config found; cannot load version for "{}"'
        log.debug(msg.format(fq_data_id))
        return None

    _, data_id = parse_fq_data_id(fq_data_id)
    assert data_id, "Invalid fqid {}".format(fq_data_id)

    metadata_dir = get_metadata_dir(conf)
    dev_id = serialize_mutable_data_id(device_id)
    d_id = serialize_mutable_data_id(data_id)

    ver_dir = os.path.join(metadata_dir, d_id)
    if not os.path.exists(ver_dir):
        log.debug("No version path found for {}:{}".format(device_id, fq_data_id))
        return None

    ver_path = os.path.join(ver_dir, '{}.ver'.format(dev_id))
    try:
        with open(ver_path, 'r') as f:
            ver_txt = f.read()
            return int(ver_txt.strip())

    except ValueError as ve:
        log.warn("Not an integer: {}".format(ver_path))
    except Exception as e:
        log.warn("Failed to read; {}".format(ver_path))

    return None


def store_mutable_data_version(conf, device_id, fq_data_id, ver, config_path=CONFIG_PATH):
    """
    Locally store the version of a piece of mutable data,
    so we can ensure that its version is incremented on
    subsequent puts.

    Return True if stored
    Return False if not
    Raise on invalid input
    """

    conf = get_config(path=config_path) if conf is None else conf

    if conf is None:
        msg = 'No config found; cannot store version for "{}"'
        log.warning(msg.format(fq_data_id))
        return False

    metadata_dir = get_metadata_dir(conf)

    _, data_id = parse_fq_data_id(fq_data_id)
    assert data_id, "Invalid fqid {}".format(fq_data_id)

    d_id = serialize_mutable_data_id(data_id)
    dev_id = serialize_mutable_data_id(device_id)

    # serialize this 
    with MUTABLE_DATA_VERSION_LOCK:

        if not os.path.isdir(metadata_dir):
            try:
                log.debug("Make metadata directory {}".format(metadata_dir))
                os.makedirs(metadata_dir)
            except Exception, e:
                if BLOCKSTACK_DEBUG:
                    log.exception(e)

                msg = 'No metadata directory created; cannot store version of "{}"'
                log.warning(msg.format(fq_data_id))
                return False

        ver_dir = os.path.join(metadata_dir, d_id)
        if not os.path.isdir(ver_dir):
            try:
                log.debug("Make metadata directory {}".format(ver_dir))
                os.makedirs(ver_dir)
            except OSError, oe:
                if oe.errno != "EEXIST":
                    raise
                else:
                    pass

            except Exception, e:
                if BLOCKSTACK_DEBUG:
                    log.exception(e)

                log.warning("No metadata directory created for {}:{}".format(device_id, fq_data_id))
                return False

        ver_path = os.path.join(ver_dir, '{}.ver'.format(dev_id))
        try:
            with open(ver_path, 'w') as f:
                f.write(str(ver))

            return True

        except Exception as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            log.warn("Failed to store version of {}:{}".format(device_id, fq_data_id))
       
    return False


def delete_mutable_data_version(conf, device_id, fq_data_id, config_path=CONFIG_PATH):
    """
    Locally delete the version of a piece of mutable data.

    Return True if deleted.
    Return False if not
    Raise on invalid input
    """

    conf = get_config(path=config_path) if conf is None else conf

    if conf is None:
        msg = 'No config found; cannot delete version for "{}"'
        return False

    metadata_dir = get_metadata_dir(conf)

    if not os.path.isdir(metadata_dir):
        return True

    _, data_id = parse_fq_data_id(fq_data_id)
    assert data_id, "Invalid fqid {}".format(fq_data_id)

    d_id = serialize_mutable_data_id(data_id)
    dev_id = serialize_mutable_data_id(device_id)

    with MUTABLE_DATA_VERSION_LOCK:
        ver_dir = os.path.join(metadata_dir, d_id)
        if not os.path.isdir(ver_dir):
            return True

        ver_path = os.path.join(ver_dir, '{}.ver'.format(dev_id))
        try:
            if os.path.exists(ver_path):
                os.unlink(ver_path)

        except Exception as e:
            # failed for whatever reason
            msg = 'Failed to remove version file "{}"'
            log.warn(msg.format(ver_path))

    return False


def get_mutable_data_version( data_id, device_ids, config_path=CONFIG_PATH ):
    """
    Get the mutable data version for a datum spread across multiple devices
    Return {'status': True, 'version': version} on success
    """
    new_version = 0
    conf = get_config(config_path)
    assert conf

    for device_id in device_ids:
        fq_data_id = make_fq_data_id(device_id, data_id)
        cur_ver = load_mutable_data_version(conf, device_id, fq_data_id, config_path=config_path)
        if cur_ver is not None:
            new_version = max(new_version, cur_ver)

    return {'status': True, 'version': new_version}


def put_mutable_data_version( data_id, new_version, device_ids, config_path=CONFIG_PATH ):
    """
    Advance all versions of a mutable datum to at least new_version
    Return {'status': True, 'version': new version} on success
    Return {'error': ...} on error
    """

    # advance header version and inode version
    conf = get_config(config_path)
    assert conf

    res = get_mutable_data_version(data_id, device_ids, config_path=CONFIG_PATH)
    new_version = max(res['version'], new_version)

    for device_id in device_ids:
        fq_data_id = make_fq_data_id(device_id, data_id)
        rc = store_mutable_data_version(conf, device_id, fq_data_id, new_version, config_path=config_path)
        if not rc:
            return {'error': 'Failed to advance mutable data version {} to {}'.format(data_id, new_version), 'errno': "EIO"}

    return {'status': True, 'version': new_version}


def get_device_root_version(datastore_id, root_uuid, device_ids, config_path=CONFIG_PATH):
    """
    Get the versioning information for this datastore
    Return {'status': True, 'version': ...} on success
    Return {'error': ...} on error
    """
    root_data_id = '{}.{}'.format(datastore_id, root_uuid)
    res = get_mutable_data_version(root_data_id, device_ids, config_path=config_path)
    return res


def put_device_root_version(datastore_id, root_uuid, timestamp, device_ids, config_path=CONFIG_PATH):
    """
    Store device root version 
    """
    root_data_id = '{}.{}'.format(datastore_id, root_uuid)
    res = put_mutable_data_version(root_data_id, timestamp, device_ids, config_path=config_path)
    return res
