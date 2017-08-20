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
import jsonschema
from jsonschema import ValidationError

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from keylib import *

import virtualchain
from virtualchain.lib.ecdsalib import *

from config import get_config, get_local_device_id
from logger import get_logger
from constants import BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, DEFAULT_DEVICE_ID, CONFIG_PATH
from schemas import *
from storage import sign_data_payload, make_data_tombstone, make_fq_data_id, sign_data_tombstone, parse_signed_data_tombstone, verify_data_tombstone, parse_fq_data_id

log = get_logger('gaia-blob')


def datastore_get_id( pubkey ):
    """
    Get the datastore ID
    """
    return keylib.public_key_to_address( str(pubkey) )


def data_blob_parse( data_blob_payload ):
    """
    Parse a serialized data structure
    Throws on error
    """
    return json.loads(data_blob_payload)


def data_blob_serialize( data_blob ):
    """
    Serialize a data blob (conformant to DATA_BLOB_SCHEMA) into a string
    Throws on error
    """    
    return json.dumps(data_blob, sort_keys=True)


def data_blob_sign( data_blob_str, data_privkey ):
    """
    Sign a serialized data blob
    Returns the signature
    """
    sig = sign_data_payload(data_blob_str, data_privkey)
    return sig


def make_data_tombstones( device_ids, data_id ):
    """
    Make tombstones for mutable data across devices
    """
    ts = [make_data_tombstone( make_fq_data_id(device_id, data_id) ) for device_id in device_ids]
    return ts


def sign_data_tombstones( tombstones, data_privkey ):
    """
    Sign all mutable data tombstones with the given private key.
    Return the list of sigend tombstones
    """
    return [sign_data_tombstone(ts, data_privkey) for ts in tombstones]


def get_device_id_from_signed_tombstone(tombstone):
    """
    Given a signed tombstone, get the device ID
    Return the device ID string on success
    Return None on error
    """

    res = parse_signed_data_tombstone(tombstone)
    if res is None:
        log.error("Failed to parse '{}'".format(tombstone))
        return None

    fq_data_id = res['id']
    
    device_id, data_id = parse_fq_data_id(fq_data_id)
    return device_id


def verify_data_tombstones( tombstones, data_pubkey, device_ids=None ):
    """
    Verify all tombstones
    Return True if they're all signed correctly
    Return False if at least one has an invalid signature (or cannot be parsed)
    """
    ts_device_ids = []
    for ts in tombstones:
        if not verify_data_tombstone(ts, data_pubkey):
            return False
       
        device_id = get_device_id_from_signed_tombstone(ts)
        if device_id:
            ts_device_ids.append(device_id)

    if device_ids:
        # verify that all of the device IDs here are present in the tombstone information 
        for dev_id in device_ids:
            if dev_id not in ts_device_ids:
                log.error("Device ID {} not present in the tombstones".format(dev_id))
                return False

    return True


def make_mutable_data_info(data_id, data_payload, device_ids=None, timestamp=None, blockchain_id=None, config_path=CONFIG_PATH, create=False, is_fq_data_id=False):
    """
    Make mutable data to serialize, sign, and store.
    data_payload must be a string.

    This is a client-side method.

    Return {'fq_data_id': ..., 'data': ..., 'timestamp': ...} on success
    Return {'error': ...} on error
    """
    conf = get_config(path=config_path)
    assert conf
   
    fq_data_id = None
    
    device_id = get_local_device_id(config_dir=os.path.dirname(config_path))
    if device_id is None:
        raise Exception("Failed to get device ID")

    if device_ids is None:
        device_ids = [device_id]

    # v2 mutable data from this device
    if not is_fq_data_id:
        fq_data_id = make_fq_data_id(device_id, data_id)
    else:
        fq_data_id = data_id

    if timestamp is None:
        timestamp = int(time.time() * 1000)

    blob_data = {
        'fq_data_id': fq_data_id,
        'data': data_payload,
        'version': 1,
        'timestamp': timestamp,
    }

    if blockchain_id is not None:
        blob_data['blockchain_id'] = blockchain_id

    return blob_data

