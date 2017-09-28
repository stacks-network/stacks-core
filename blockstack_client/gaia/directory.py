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

import virtualchain
import keylib

from ..logger import get_logger
from ..proxy import get_default_proxy
from ..config import get_config, get_local_device_id
from ..constants import BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, DEFAULT_DEVICE_ID, CONFIG_PATH
from ..key_file import lookup_app_pubkeys, lookup_app_listing
from ..schemas import ROOT_DIRECTORY_ENTRY_SCHEMA, ROOT_DIRECTORY_LEAF, OP_DATASTORE_ID_CLASS, OP_URLENCODED_CLASS, ROOT_DIRECTORY_SCHEMA
from ..storage import sign_data_payload, make_data_tombstone, make_fq_data_id, sign_data_tombstone, parse_data_tombstone, verify_data_tombstone, parse_fq_data_id, \
        hash_data_payload, sign_data_payload, serialize_mutable_data, get_storage_handlers, verify_data_payload, sign_raw_data, verify_raw_data
from ..utils import ScatterGather

from .cache import GLOBAL_CACHE
from .blob import data_blob_parse, data_blob_serialize, datastore_get_id
from .mutable import get_mutable, put_raw_data
from .metadata import get_device_root_version
from .policy import prioritize_read_drivers

log = get_logger('gaia-directory')


def make_empty_device_root_directory(datastore_id, reader_pubkeys, timestamp=None):
    """
    Make an empty device root directory
    """
    if timestamp is None:
        timestamp = int(time.time() * 1000)

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


def get_device_root_directory( datastore_id, root_uuid, device_id, device_pubkey, drivers=None, root_urls=None,
                               timestamp=0, cache_max_lifetime=10, force=False, config_path=CONFIG_PATH, proxy=None, blockchain_id=None, full_app_name=None):
    """
    Get the root directory for a specific device in a datastore.
    This is a server-side method

    TODO: with root_urls, this can become a client-side method

    Return {'status': True, 'device_root_page': {...}} on success
    Return {'error': ..., 'errno': ...} on error
    """
    
    from .datastore import get_datastore_info

    assert (datastore_id and device_id and device_pubkey) or (blockchain_id and full_app_name), 'Need drivers, urls, or both blockchain ID and full app name'

    if proxy is None:
        proxy = get_default_proxy(config_path)

    conf = get_config(config_path)
    assert conf

    parsed_key_file = None
    device_ids = [device_id]
    
    # find out datastore info
    if (blockchain_id is not None and full_app_name is not None) and (not root_urls or datastore_id is None or root_uuid is None):
        # get from key file (and get root URLs)
        res = lookup_app_listing(blockchain_id, full_app_name, cache=GLOBAL_CACHE, proxy=proxy, config_path=config_path)
        if 'error' in res:
            res['errno'] = "EINVAL"
            return res

        if len(res['app_info'].keys()) == 0:
            msg = 'Blockchain ID {} is not registered in application {}'.format(blockchain_id, full_app_name)
            log.error(msg)
            return {'error': msg, 'errno': 'EINVAL'}

        if device_id not in res['app_info']:
            return {'error': 'Failed to find data for device {} in key file for {} (application {})'.format(device_id, blockchain_id, full_app_name)}
            
        if not root_urls:
            root_urls = res['app_info'][device_id]['root_urls']

        if device_pubkey is None:
            device_pubkey = res['app_info'][device_id]['public_key']

        parsed_key_file = res['key_file']
        device_ids = res['app_info'].keys()

    # datastore ID?
    if datastore_id is None or root_uuid is None or drivers is None:
        dinfo_res = get_datastore_info(blockchain_id=blockchain_id, datastore_id=datastore_id, device_ids=device_ids, full_app_name=full_app_name, config_path=config_path, proxy=proxy, parsed_key_file=parsed_key_file)
        if 'error' in dinfo_res:
            log.error("No datastore ID given, and could not determine it")
            return {'error': "no datastore ID given, and could not determine it: {}".format(dinfo_res['error'])}

        datastore = dinfo_res['datastore']
        datastore_id = datastore_get_id(datastore['pubkey'])

        if root_uuid is None:
            root_uuid = datastore['root_uuid']

        if drivers is None:
            drivers = datastore['drivers']

    # cached?
    res = GLOBAL_CACHE.get_device_root_directory(datastore_id, device_id, root_uuid, cache_max_lifetime)
    if res:
        return {'status': True, 'device_root_page': res}

    data_id = '{}.{}'.format(datastore_id, root_uuid)
   
    if drivers is None:
        drivers = [None]

    errcode = 0
    for driver in drivers:
        fq_data_id = make_fq_data_id(device_id, data_id)
        device_root_timestamp = timestamp

        if timestamp == 0 and not force:
            res = get_device_root_version(datastore_id, root_uuid, device_ids, config_path=config_path)
            if 'error' in res:
                return {'error': 'Failed to query device root version for {}'.format(fq_data_id)}
        
            device_root_timestamp = res['version']

        if driver:
            res = get_mutable(fq_data_id, device_ids=[device_id], blockchain_id=blockchain_id, timestamp=device_root_timestamp, force=force,
                                          data_pubkeys=[device_pubkey], storage_drivers=[driver], urls=root_urls, proxy=proxy, config_path=config_path)
        else:
            res = get_mutable(fq_data_id, device_ids=[device_id], blockchain_id=blockchain_id, timestamp=device_root_timestamp, force=force,
                                          data_pubkeys=[device_pubkey], urls=root_urls, proxy=proxy, config_path=config_path)

        if 'error' in res:
            log.error("Failed to get device root data {} (stale={}): {}".format(root_uuid, res.get('stale', False), res['error']))
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
            GLOBAL_CACHE.put_device_root_directory(datastore_id, device_id, root_uuid, root_page, cache_max_lifetime)
            
            return {'status': True, 'device_root_page': root_page}
        
    return {'error': 'No data fetched from {}'.format(device_id), 'errno': errcode}


def get_root_directory(datastore_id, root_uuid, data_pubkeys, drivers=None, root_urls=None, timestamp=0, force=False, config_path=CONFIG_PATH, proxy=None, full_app_name=None, blockchain_id=None):
    """
    Get the root directory for a datastore.  Fetch the device-specific directories from all devices and merge them.

    @data_pubkeys is [{$device_id: $data_pubkey}]

    This is a server-side method.

    TODO: with urls, this can become a client-side method

    Return {'status': True, 'root': {'$filename': '$file_entry'}, 'device_root_pages': [root directories]} on success
    Return {'error': ..., 'errno': ...} on error.
    """

    from .datastore import get_datastore_info

    if proxy is None:
        proxy = get_default_proxy(config_path)

    assert (datastore_id and data_pubkeys) or (full_app_name and blockchain_id), 'Need either data_pubkeys or both full_app_name and blockchain_id'

    conf = get_config(config_path)
    assert conf
    
    parsed_key_file = None

    if data_pubkeys:
        device_ids = [dpk['device_id'] for dpk in data_pubkeys]

    if (data_pubkeys is None or root_urls is None or root_uuid is None) and (blockchain_id is not None and full_app_name is not None):
        # get from key file (and use root URLs)
        res = lookup_app_listing(blockchain_id, full_app_name, cache=GLOBAL_CACHE, proxy=proxy, config_path=config_path)
        if 'error' in res:
            res['errno'] = "EINVAL"
            return res
       
        if len(res['app_info'].keys()) == 0:
            msg = 'Blockchain ID {} is not registered in application {}'.format(blockchain_id, full_app_name)
            log.error(msg)
            return {'error': msg, 'errno': 'EINVAL'}

        if data_pubkeys is None:
            data_pubkeys = [{'device_id': dev_id, 'public_key': res['app_info'][dev_id]['public_key']} for dev_id in data_pubkeys.keys()]

        if root_urls is None:
            root_urls = dict([(dev_id, res['app_info'][dev_id]['root_urls']) for dev_id in res['app_info'].keys()])

        parsed_key_file = res['key_file']
        device_ids = res['app_info'].keys()
    
    # datastore info?
    if datastore_id is None or root_uuid is None:
        dinfo_res = get_datastore_info(blockchain_id=blockchain_id, datastore_id=datastore_id, device_ids=device_ids, full_app_name=full_app_name, config_path=config_path, proxy=proxy, parsed_key_file=parsed_key_file)
        if 'error' in dinfo_res:
            log.error("No datastore ID given, and could not determine it")
            return {'error': "no datastore ID given, and could not determine it: {}".format(dinfo_res['error']), 'errno': 'EINVAL'}

        datastore = dinfo_res['datastore']
        if datastore_id is not None and datastore_id != datastore_get_id(datastore['pubkey']):
            return {'error': 'Datastore mismatch: given datastore ID {} does not match queried datastore ID {}'.format(datastore_id, datastore_get_id(datastore['pubkey'])), 'errno': 'EINVAL'}

        datastore_id = datastore_get_id(datastore['pubkey'])

        if root_uuid is None:
            root_uuid = datastore['root_uuid']

        if drivers is None:
            drivers = datastore['drivers']

    data_id = '{}.{}'.format(datastore_id, root_uuid)

    # optimization: try local drivers before non-local drivers
    if drivers:
        drivers = prioritize_read_drivers(config_path, drivers)

    sg = ScatterGather()
    for data_pubkey_info in data_pubkeys:
        device_id = data_pubkey_info['device_id']
        data_pubkey = data_pubkey_info['public_key']
        task_id = 'fetch_root_{}'.format(device_id)
        
        urls = None
        if root_urls:
            assert root_urls.has_key(device_id), root_urls
            urls = root_urls[device_id]

        fetch_root_directory = functools.partial(get_device_root_directory, datastore_id, root_uuid, device_id, data_pubkey,
                                                drivers=drivers, timestamp=timestamp, force=force, root_urls=urls, config_path=config_path, full_app_name=full_app_name, blockchain_id=blockchain_id)

        sg.add_task(task_id, fetch_root_directory)

    sg.run_tasks()
    roots = {}

    for data_pubkey_info in data_pubkeys:
        device_id = data_pubkey_info['device_id']
        data_pubkey = data_pubkey_info['public_key']
        task_id = 'fetch_root_{}'.format(device_id)

        result = sg.get_result(task_id)
        if 'error' in result:
            log.error("Failed to fetch root from {} ({}, errno={})".format(device_id, result['error'], result['errno']))
            if result['errno'] == 'ESTALE' and not force:
                # got a device root directory, but it was stale
                return {'error': 'Stale device root directory: {}'.format(result['error']), 'errno': 'ESTALE'}

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

    Return {'status': True, 'urls': ...]} on success
    Return {'error': ...,} on failure
    """

    fq_data_id = make_fq_data_id(device_id, '{}.{}'.format(datastore_id, root_uuid))
    serialized_root = serialize_mutable_data(directory_blob, data_pubkey=directory_pubkey, data_signature=directory_signature)
    res = put_raw_data(fq_data_id, serialized_root, drivers, config_path=config_path, blockchain_id=blockchain_id, data_pubkey=directory_pubkey, data_signature=directory_signature)

    # uncache
    GLOBAL_CACHE.evict_device_root_directory(datastore_id, device_id, root_uuid)
    return res
