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
        put_immutable_data, parse_signed_data_tombstone, classify_storage_drivers

log = get_logger('gaia-policy')


def get_read_public_storage_drivers(config_path):
    """
    Get the list of "read-public" storage drivers.
    This is according to the driver classification.
 
    Returns the list of driver names
    """
    
    driver_classes = classify_storage_drivers()
    return driver_classes['read_public']


def get_required_write_storage_drivers(config_path):
    """
    Get the list of storage drivers to write with.
    This is according to the 'storage_drivers_required_write' setting

    Returns a list of driver names.
    """
    conf = get_config(config_path)
    assert conf

    storage_drivers = conf.get("storage_drivers_required_write", "").split(',')
    if len(storage_drivers) > 0:
        return storage_drivers

    # fall back to storage drivers 
    storage_drivers = conf.get("storage_drivers", "").split(",")
    if len(storage_drivers) > 0:
        return storage_drivers

    storage_handlers = get_storage_handlers()
    storage_drivers = [sh.__name__ for sh in storage_handlers]
    return storage_drivers


def get_read_storage_drivers(config_path):
    """
    Get the list of storage drivers to read with.
    This is according to the 'storage_drivers' setting

    Returns a list of driver names.
    """
    conf = get_config(config_path)
    assert conf

    storage_drivers = conf.get("storage_drivers", "").split(",")
    if len(storage_drivers) > 0:
        return storage_drivers

    storage_handlers = get_storage_handlers()
    storage_drivers = [sh.__name__ for sh in storage_handlers]
    return storage_drivers


def get_read_local_storage_drivers(config_path, storage_drivers=None):
    """
    Get the list of storage drivers that can read locally.
    Returns a list of driver names
    """
    if storage_drivers is None:
        conf = get_config(config_path)
        assert conf
    
        storage_drivers = conf.get('storage_drivers', '').split(',')

    driver_classes = classify_storage_drivers()
    
    ret = []
    for read_local in driver_classes['read_local']:
        if read_local in storage_drivers:
            ret.append(read_local)

    return ret


def prioritize_read_drivers(config_path, drivers):
    """
    Given a set of drivers, prioritize them in order of read speed.
    Expect local drivers to be faster than remote drivers
    """
    # optimization: try local drivers before non-local drivers 
    local_read_drivers = get_read_local_storage_drivers(config_path, drivers)
    first_drivers = []
    last_drivers = []
    for drvr in drivers:
        if drvr in local_read_drivers:
            first_drivers.append(drvr)
        else:
            last_drivers.append(drvr)

    drivers = first_drivers + last_drivers
    return drivers


