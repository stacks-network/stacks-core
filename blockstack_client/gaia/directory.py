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
import re
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
        hash_data_payload, sign_data_payload, serialize_mutable_data, get_storage_handlers, verify_data_payload

log = get_logger('gaia-directory')

from blob import *
from cache import *
from metadata import *
from mutable import *


def make_empty_device_root_directory(datastore_id, reader_pubkeys, timestamp):
    """
    Make an empty device root directory
    """
    dev_root_dir = {
        'proto_version': 2,
        'type': ROOT_DIRECTORY_LEAF,
        'owner': datastore_id,
        'readers': [keylib.public_key_to_address(rpk) for rpk in reader_pubkeys],
        'timestamp': timestamp,
        'files': {},
        'tombstones': {},
    }
    return dev_root_dir


def _merge_root_directories( roots ):
    """
    Given a list of root directories, merge them into a single directory root listing
    Return {'status': True, 'files': ...} on success
    """
    merged_files = {}
    for root in roots:
        for file_name in root['files'].keys():
            file_entry = root['files'][file_name]
            if not merged_files.has_key(file_name):
                merged_files[file_name] = file_entry
            else:
                if merged_files[file_name]['timestamp'] < file_entry['timestamp']:
                    merged_files[file_name] = file_entry
    
    # process tombstones
    for root in roots:
        for file_name in root['tombstones']:
            tombstone = root['tombstones'][file_name]
            ts_data = parse_data_tombstone(str(tombstone))
            if ts_data is None:
                log.warning("Invalid tombstone '{}'".format(tombstone))
                continue

            # format: datastore/file_name
            fq_file_name = ts_data['id']
            device_id, data_id = parse_fq_data_id(fq_file_name)
            fq_match = re.match('^({}+)/({}+)$'.format(OP_DATASTORE_ID_CLASS, OP_URLENCODED_CLASS), data_id)
            if not fq_match:
                log.warning("Invalid tombstone file name '{}'".format(fq_file_name))
                continue
            
            p = data_id.split('/', 1)
            if len(p) != 2:
                log.warning("Invalid tombstone file name '{}'".format(fq_file_name))
                continue

            if p[1] != file_name:
                log.warning("Invalid tombstone file name '{}'".format(fq_file_name))
                continue

            if merged_files.has_key(file_name):
                if merged_files[file_name]['timestamp'] < ts_data['timestamp']:
                    # this file was deleted
                    del merged_files[file_name]

    return {'status': True, 'files': merged_files}


def get_device_root_directory( datastore_id, root_inode_uuid, drivers, device_id, device_pubkey, timestamp=0, cache_max_lifetime=10, force=False, config_path=CONFIG_PATH, proxy=None, blockchain_id=None):
    """
    Get the root directory for a specific device in a datastore.
    This is a server-side method

    Return {'status': True, 'device_root_page': {...}} on success
    Return {'error': ..., 'errno': ...} on error
    """
    
    # cached?
    res = GLOBAL_CACHE.get_device_root_directory(datastore_id, device_id, root_inode_uuid, cache_max_lifetime)
    if res:
        return {'status': True, 'device_root_page': res}

    if proxy is None:
        proxy = get_default_proxy(config_path)

    conf = get_config(config_path)
    assert conf

    data_id = '{}.{}'.format(datastore_id, root_inode_uuid)
    
    errcode = 0
    for driver in drivers:
        fq_data_id = make_fq_data_id(device_id, data_id)
        res = get_mutable(fq_data_id, device_ids=[device_id], blockchain_id=blockchain_id, timestamp=timestamp, force=force, data_pubkeys=[device_pubkey], storage_drivers=[driver], proxy=proxy, config_path=config_path)
        if 'error' in res:
            log.error("Failed to get device root data {} (stale={}): {}".format(root_inode_uuid, res.get('stale', False), res['error']))
            errcode = "EREMOTEIO"
            if res.get('stale'):
                errcode = "ESTALE"

            continue

        else:
            # success!
            try:
                root_page = json.loads(res['data'])
            except:
                log.error("Invalid root data from {}: not JSON".format(fq_data_id))

                if errcode == 0:
                    errcode = "EIO"

                continue

            try:
                jsonschema.validate(root_page, ROOT_DIRECTORY_SCHEMA)
            except ValidationError as ve:
                if BLOCKSTACK_DEBUG:
                    log.exception(ve)

                log.error("Invalid root data from {}: not a root directory".format(fq_data_id))
                
                if errcode == 0:
                    errcode = "EIO"

                continue
            
            # cache!
            GLOBAL_CACHE.put_device_root_directory(datastore_id, device_id, root_inode_uuid, root_page, cache_max_lifetime)
            
            return {'status': True, 'device_root_page': root_page}
        
    return {'error': 'No data fetched from {}'.format(device_id), 'errno': errcode}


def get_root_directory(datastore_id, root_uuid, drivers, data_pubkeys, timestamp=0, force=False, config_path=CONFIG_PATH, proxy=None, full_app_name=None, blockchain_id=None):
    """
    Get the root directory for a datastore.  Fetch the device-specific directories from all devices and merge them.

    @data_pubkeys is [{$device_id: $data_pubkey}]

    This is a server-side method.

    Return {'status': True, 'root': {'$filename': '$file_entry'}, 'device_root_pages': [root directories]} on success
    Return {'error': ..., 'errno': ...} on error.
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    assert data_pubkeys or (full_app_name and blockchain_id), 'Need either data_pubkeys or both full_app_name and blockchain_id'

    conf = get_config(config_path)
    assert conf

    if data_pubkeys is None:
        # get from token file
        res = lookup_app_pubkeys(blockchain_id, full_app_name, cache=GLOBAL_CACHE, proxy=proxy)
        if 'error' in res:
            res['errno'] = "EINVAL"
            return res
        
        data_pubkeys = [{'device_id': dev_id, 'public_key': res['pubkeys'][dev_id]} for dev_id in data_pubkeys.keys()]

    data_id = '{}.{}'.format(datastore_id, root_uuid)

    # optimization: try local drivers before non-local drivers
    drivers = prioritize_read_drivers(config_path, drivers)

    sg = ScatterGather()
    for data_pubkey_info in data_pubkeys:
        device_id = data_pubkey_info['device_id']
        data_pubkey = data_pubkey_info['public_key']
        task_id = 'fetch_root_{}'.format(device_id)

        fetch_root_directory = functools.partial(get_device_root_directory, datastore_id, root_uuid, drivers, device_id, data_pubkey, timestamp=timestamp, force=force, config_path=config_path, blockchain_id=blockchain_id)
        sg.add_task(task_id, fetch_root_directory)

    sg.run_tasks()
    roots = {}

    for data_pubkey_info in data_pubkeys:
        device_id = data_pubkey_info['device_id']
        data_pubkey = data_pubkey_info['public_key']
        task_id = 'fetch_root_{}'.format(device_id)

        result = sg.get_result(task_id)
        if 'error' in result:
            log.error("Failed to fetch root from {}".format(device_id))

            # no device directory; assume empty
            result = {'device_root_page': make_empty_device_root_directory(datastore_id, [], 0)}

        root_dir = result['device_root_page']
        if root_dir['type'] != ROOT_DIRECTORY_LEAF:
            return {'error': 'Segmented root directories are not yet supported (type={})'.format(root_dir['type'])}
        
        roots[device_id] = root_dir

    # merge root directories
    merged = _merge_root_directories(roots.values())
    if 'error' in merged:
        return {'error': 'Failed to recombine device root directories: {}'.format(merged['error']), 'errno': "EIO"}

    return {'status': True, 'root': merged['files'], 'device_root_pages': roots}


def put_device_root_data(datastore_id, device_id, root_uuid, directory_blob, directory_pubkey, directory_signature, drivers, config_path=CONFIG_PATH, blockchain_id=None):
    """
    Store device-specific root directory data to a set of drivers.

    This is a server-side method.

    Return {'status': True, 'urls': [...]} on success
    Return {'error': ...,} on failure
    """

    fq_data_id = make_fq_data_id(device_id, '{}.{}'.format(datastore_id, root_uuid))
    serialized_root = serialize_mutable_data(directory_blob, data_pubkey=directory_pubkey, data_signature=directory_signature)    
    res = put_raw_data(fq_data_id, serialized_root, drivers, config_path=config_path, blockchain_id=blockchain_id, data_pubkey=directory_pubkey, data_signature=directory_signature) 

    # uncache
    GLOBAL_CACHE.evict_device_root_directory(datastore_id, device_id, root_uuid)
    return res
