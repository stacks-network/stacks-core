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

import keylib
import virtualchain
from virtualchain.lib.ecdsalib import get_pubkey_hex

from ..logger import get_logger
from ..proxy import get_default_proxy, json_is_error
from ..config import get_config, get_local_device_id
from ..constants import BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, DEFAULT_DEVICE_ID, CONFIG_PATH
from ..key_file import lookup_app_listing
from ..schemas import ROOT_DIRECTORY_ENTRY_SCHEMA
from ..storage import sign_data_payload, make_data_tombstone, make_fq_data_id, sign_data_tombstone, parse_data_tombstone, verify_data_tombstone, parse_fq_data_id, hash_data_payload, sign_data_payload, serialize_mutable_data, \
        sign_raw_data, verify_raw_data

from .blob import datastore_get_id, make_data_tombstones, sign_data_tombstones, verify_data_tombstones, \
        data_blob_parse, data_blob_serialize, make_data_tombstones, sign_data_tombstones, verify_data_tombstones, \
        make_mutable_data_info
from .cache import GLOBAL_CACHE
from .directory import make_empty_device_root_directory
from .datastore import sign_datastore_info
from .metadata import get_device_root_version, put_device_root_version

log = get_logger('gaia-client')


def get_datastore(api_client, datastore_id=None, blockchain_id=None, full_app_name=None, device_ids=None):
    """
    Get the datastore
    """
    assert (blockchain_id and full_app_name) or (datastore_id), 'need either datastore_id, or blockchain_id and full_app_name'
    res = api_client.backend_datastore_get(blockchain_id, full_app_name, datastore_id=datastore_id, device_ids=device_ids)
    return res


def put_datastore(api_client, datastore_info, datastore_privkey, config_path=CONFIG_PATH):
    """
    Given datastore information from make_datastore_info(), sign and put it.
    This is a client-side method

    Return {'status': True, 'root_urls': ..., 'datastore_urls': ...} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    sigs = sign_datastore_info(datastore_info, datastore_privkey, config_path=config_path)
    if 'error' in sigs:
        return sigs

    tombstones = sigs['root_tombstones']
    del sigs['root_tombstones']

    res = api_client.backend_datastore_create(datastore_info, sigs, tombstones)
    if 'error' in res:
        return res

    return {'status': True, 'root_urls': res['root_urls'], 'datastore_urls': res['datastore_urls']}


def delete_datastore(api_client, datastore_privkey, blockchain_id=None, full_app_name=None, datastore_id=None, data_pubkeys=None, config_path=CONFIG_PATH, proxy=None):
    """
    Delete a datastore.

    Client-side method

    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    
    assert (blockchain_id and full_app_name) or (datastore_id and data_pubkeys), 'Need either blockchain_id/full_app_name or datastore_id/data_pubkeys'
    
    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)
    
    device_ids = None

    # find datastore info so we can make tombstones
    if blockchain_id and full_app_name:
        res = lookup_app_listing(blockchain_id, full_app_name, cache=GLOBAL_CACHE, proxy=proxy, config_path=config_path)
        if 'error' in res:
            res['errno'] = "EINVAL"
            return res

        if len(res['app_info'].keys()) == 0:
            msg = 'Blockchain ID {} is not registered in application {}'.format(blockchain_id, full_app_name)
            log.error(msg)
            return {'error': msg, 'errno': 'EINVAL'}

        parsed_key_file = res['key_file']
    
        device_ids = res['app_info'].keys()

        if data_pubkeys is None:
            data_pubkeys = [{'device_id': dev_id, 'public_key': res['app_info'][dev_id]['public_key']} for dev_id in device_ids]
    
    res = get_datastore(api_client, blockchain_id=blockchain_id, datastore_id=datastore_id, full_app_name=full_app_name, device_ids=device_ids)
    if 'error' in res:
        return res

    datastore = res['datastore']

    datastore_id = datastore_get_id(datastore['pubkey'])
    device_ids = [dpk['device_id'] for dpk in data_pubkeys]

    tombstones = make_data_tombstones( device_ids, '{}.datastore'.format(datastore_id) )
    signed_tombstones = sign_data_tombstones(tombstones, datastore_privkey )

    # delete root as well
    root_id = '{}.{}'.format(datastore_id, datastore['root_uuid'])
    root_tombstones = make_data_tombstones( datastore['device_ids'], root_id )
    signed_root_tombstones = sign_data_tombstones( root_tombstones, datastore_privkey )

    res = api_client.backend_datastore_delete(datastore_id, signed_tombstones, signed_root_tombstones, data_pubkeys ) 
    if 'error' in res:
        return res

    return {'status': True}


def datastore_serialize_and_sign( datastore, data_privkey):
    """
    Serialize and sign a datastore for a request.
    This is a client-side method
    """
    datastore_str = json.dumps(datastore, sort_keys=True)
    datastore_sig = sign_raw_data(datastore_str, data_privkey)
    return {'str': datastore_str, 'sig': datastore_sig}


def datastore_verify_and_parse( datastore_str, datastore_sig, data_pubkey ):
    """
    Verify a datastore signed by datastore_serialize_and_sign
    Return {'status': True, 'datastore': ...} on success
    Return {'error': ...} on error
    """
    res = verify_raw_data(datastore_str, data_pubkey, datastore_sig)
    if not res:
        return {'error': 'Invalid datastore signature'}

    datastore = None
    try:
        datastore = json.loads(datastore_str)
    except ValueError:
        return {'error': 'Invalid datastore structure'}

    return {'status': True, 'datastore': datastore}


def datastore_getfile(api_client, file_name, blockchain_id=None, full_app_name=None, datastore_id=None, data_pubkeys=None, timestamp=0, force=False, config_path=CONFIG_PATH, proxy=None ):
    """
    Get a file identified by a path.

    Return {'status': True, 'data': data} on success
    Return {'error': ..., 'errno': ...} on error
    """
    assert (blockchain_id and full_app_name) or (datastore_id and data_pubkeys), "Need either blockchain_id/full_app_name or datastore_id/data_pubkeys"
    
    if proxy is None:
        proxy = get_default_proxy(config_path)

    log.debug("getfile {}/{}".format(datastore_id, file_name))

    file_info = api_client.backend_datastore_getfile(file_name, blockchain_id=blockchain_id, full_app_name=full_app_name, datastore_id=datastore_id, data_pubkeys=data_pubkeys, timestamp=timestamp, force=force)
    if json_is_error(file_info):
        log.error("Failed to get data for {}".format(file_name))
        return file_info
    
    return file_info


def datastore_make_file_entry(data_hash, data_urls):
    """
    Make a root file entry
    Return the file entry on success
    Return {'error': ...} otherwise
    """ 
    # must be valid data
    file_entry = {
        'proto_version': 2,
        'urls': data_urls,
        'data_hash': data_hash,
        'timestamp': int(time.time() * 1000),
    }

    try:
        jsonschema.validate(file_entry, ROOT_DIRECTORY_ENTRY_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        return {'error': 'Invalid file data', 'errno': "EINVAL"}

    return file_entry


def _find_datastore_info(api_client, datastore_id=None, blockchain_id=None, data_pubkeys=None, full_app_name=None, this_device_id=None, config_path=CONFIG_PATH, proxy=None):
    """
    Get datastore information:  pubkey/device pairs, key file, and datastore record.
    Return {'status': True, 'datastore': ..., 'data_pubkeys': ..., 'key_file': ..., 'data_pubkey': ... (this device's public key)} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)
    
    if this_device_id is None:
        this_device_id = get_local_device_id(config_dir=os.path.dirname(config_path))
    
    parsed_key_file = None
    datastore_urls = None
    device_ids = None

    # get key file, if we can 
    if full_app_name is not None and blockchain_id is not None and data_pubkeys is None:
        # get from key file
        res = lookup_app_listing(blockchain_id, full_app_name, cache=GLOBAL_CACHE, proxy=proxy, config_path=config_path)
        if 'error' in res:
            res['errno'] = "EINVAL"
            return res
        
        if len(res['app_info'].keys()) == 0:
            msg = 'Blockchain ID {} is not registered in application {}'.format(blockchain_id, full_app_name)
            log.error(msg)
            return {'error': msg, 'errno': 'EINVAL'}

        if this_device_id not in res['app_info']:
            return {'error': 'Failed to find data for device {} in key file for {} (application {})'.format(this_device_id, blockchain_id, full_app_name)}

        parsed_key_file = res['key_file']
        data_pubkeys = [{'data_pubkey': res['app_info'][dev_id][full_app_name]['public_key'], 'device_id': dev_id} for dev_id in res['app_info'].keys()]

    # get the datastore
    if data_pubkeys:
        device_ids = [dpk['device_id'] for dpk in data_pubkeys]
    else:
        device_ids = [get_local_device_id(config_dir=os.path.dirname(config_path))]

    res = get_datastore(api_client, datastore_id=datastore_id, blockchain_id=blockchain_id, full_app_name=full_app_name, device_ids=device_ids)
    if 'error' in res:
        log.error("Failed to get datastore: {}".format(res['error']))
        return {'error': 'Failed to get datastore: {}'.format(res['error']), 'errno': res.get('errno', 'EPERM')}

    datastore = res['datastore']
    datastore_id = datastore_get_id(datastore['pubkey'])
    root_uuid = datastore['root_uuid']
    drivers = datastore['drivers']
    
    # need pubkey for this device
    data_pubkey = None
    for dpk in data_pubkeys:
        if dpk['device_id'] == this_device_id:
            data_pubkey = dpk['public_key']

    if data_pubkey is None:
        return {'error': 'No data public keys found for {}'.format(this_device_id), 'errno': "EINVAL"}

    ret = {
        'status': True,
        'datastore': datastore,
        'data_pubkeys': data_pubkeys,
        'key_file': parsed_key_file,
        'data_pubkey': data_pubkey
    }

    return ret


def _find_device_root_info( api_client, this_device_id=None, data_pubkeys=None, datastore_id=None, root=None, timestamp=0, force=False, config_path=CONFIG_PATH, proxy=None, blockchain_id=None, full_app_name=None):
    """
    Helper method; do not use externally.

    Find the key file, datastore, and device root, given either the (blockchain_id, full_app_name) or (datastore_id, data_pubkeys) tuples.
    
    Return {'status': True, 'device_root': ..., 'created': True/False, 'datastore': ..., 'key_file': ...} on success
    Return {'error': ..., 'errno': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)
    
    if this_device_id is None:
        this_device_id = get_local_device_id(config_dir=os.path.dirname(config_path))
    
    res = _find_datastore_info(api_client, blockchain_id=blockchain_id, full_app_name=full_app_name, data_pubkeys=data_pubkeys, datastore_id=datastore_id, config_path=config_path, proxy=proxy)
    if 'error' in res:
        return res

    datastore = res['datastore']
    data_pubkeys = res['data_pubkeys']
    parsed_key_file = res['key_file']
    data_pubkey = res['data_pubkey']

    datastore_id = datastore_get_id(datastore['pubkey'])
    root_uuid = datastore['root_uuid']
    drivers = datastore['drivers']
    
    # do we expect this device root to exist?  we might not, if this is the first time we're trying to modify the device root.
    expect_device_root = False
    if keylib.key_formatting.compress(datastore['pubkey']) == keylib.key_formatting.compress(data_pubkey):
        # this device created this datastore
        log.debug("This device ({}) created datastore {}, so we expect its root to exist".format(this_device_id, datastore_id))
        expect_device_root = True

    res = get_device_root_version(datastore_id, root_uuid, [this_device_id], config_path=config_path)
    if 'error' in res:
        return {'error': 'Failed to check device root version for {}'.format(datastore_id), 'errno': "EIO"}

    if res['version'] > 0:
        # previously seen or written
        log.debug("This device ({}) has seen version {} of its root for datastore {}, so we expect its root to exist".format(this_device_id, res['version'], datastore_id))
        expect_device_root = True
    
    device_root = None
    created = False
    res = api_client.backend_datastore_get_device_root(this_device_id, blockchain_id=blockchain_id, full_app_name=full_app_name,
                                                       datastore_id=datastore_id, data_pubkeys=data_pubkeys)

    if 'error' in res:
        if expect_device_root:
            log.error("Failed to get device {} root page for {}.{}: {}".format(this_device_id, datastore_id, root_uuid, res['error']))
            return {'error': res['error'], 'errno': "EREMOTEIO"}
        
        else:
            log.warning("Failed to get device {} root page for {}.{}: {}".format(this_device_id, datastore_id, root_uuid, res['error']))
            log.warning("Creating device root for {}".format(this_device_id))
            
            device_root = make_empty_device_root_directory(datastore_id, [])
            created = True
    else:
        device_root = res['device_root_page']

    return {'status': True, 'device_root': device_root, 'created': created, 'datastore': datastore, 'key_file': parsed_key_file}


def device_root_serialize(device_id, datastore_id, root_uuid, device_root, blockchain_id=None, config_path=CONFIG_PATH):
    """
    Serialize a device root
    Return {'status': True, 'device_root_page_blob': ...}
    """
    device_root_data_id = make_fq_data_id(device_id, '{}.{}'.format(datastore_id, root_uuid))
    device_root_data = data_blob_serialize(device_root)
    device_root_blob = make_mutable_data_info(device_root_data_id, device_root_data, blockchain_id=blockchain_id, config_path=config_path, is_fq_data_id=True)
    return {'status': True, 'device_root_page_blob': device_root_blob}


def device_root_insert(datastore, device_root, file_name, file_entry, device_id, blockchain_id=None, config_path=CONFIG_PATH):
    """
    Create the messages needed to store a file and update the device's root directory.

    Does not upload data; instead, signs and updates the root directory page for this device.

    This is a client-side method

    Returns {'status': True, 'device_root_page_blob': serialized device root page blob} on success
    """

    datastore_id = datastore_get_id(datastore['pubkey'])
    root_uuid = datastore['root_uuid']
    drivers = datastore['drivers']
   
    # advance time 
    device_root['timestamp'] = max(device_root['timestamp'] + 1, int(time.time() * 1000))

    # insert
    device_root['files'][file_name] = file_entry

    res = device_root_serialize(device_id, datastore_id, root_uuid, device_root, blockchain_id=blockchain_id, config_path=config_path)
    return {'status': True, 'device_root_page_blob': res['device_root_page_blob'], 'timestamp': device_root['timestamp']}


def device_root_remove(datastore, device_root, file_name, this_device_file_tombstone, this_device_id, config_path=CONFIG_PATH, blockchain_id=None):
    """
    Create the messages needed to remove a file and update the device's root directory.

    Does not upload data; instead, signs and updates the root directory page for this device.

    This is a client-side method

    Returns {'status': True, 'device_root_page_blob': serialized device root page blob} on success
    """

    datastore_id = datastore_get_id(datastore['pubkey'])
    root_uuid = datastore['root_uuid']
    drivers = datastore['drivers']
    
    # update timestamp
    device_root['timestamp'] = max(device_root['timestamp'] + 1, int(time.time() * 1000))

    # delete: add a tombstone for this file so readers won't "see" it
    device_root['tombstones'][file_name] = this_device_file_tombstone

    # serialize
    res = device_root_serialize(this_device_id, datastore_id, root_uuid, device_root, blockchain_id=blockchain_id, config_path=config_path)
    return {'status': True, 'device_root_page_blob': res['device_root_page_blob'], 'timestamp': device_root['timestamp']}


def datastore_put_device_root(api_client, datastore, this_device_id, device_root, data_privkey_hex, blockchain_id=None, full_app_name=None, synchronous=False, config_path=CONFIG_PATH):
    """
    Save a given device root
    Return {'status': True, 'root_urls': [...]} on success
    Return {'error': ...} on failure

    Note that 'root_urls' will be [] if synchronous is False
    """
    datastore_id = datastore_get_id(datastore['pubkey'])
    root_uuid = datastore['root_uuid']

    # make new signed device root
    res = device_root_serialize(this_device_id, datastore_id, root_uuid, device_root, blockchain_id=blockchain_id, config_path=config_path)
    new_device_root = res['device_root_page_blob']
    new_device_root_version = device_root['timestamp']

    device_root_page_blob = data_blob_serialize(new_device_root)
    device_root_page_blob_sig = sign_data_payload(device_root_page_blob, data_privkey_hex)
    
    # serialize datastore
    datastore_info = datastore_serialize_and_sign(datastore, data_privkey_hex)
    datastore_str = datastore_info['str']
    datastore_sig = datastore_info['sig']

    # put it, possibly synchronously
    data_pubkey = get_pubkey_hex(data_privkey_hex)
    res = api_client.backend_datastore_put_device_root(datastore_str, datastore_sig, device_root_page_blob, device_root_page_blob_sig, this_device_id,
                                                       data_pubkey=data_pubkey, blockchain_id=blockchain_id, full_app_name=full_app_name, synchronous=synchronous)

    if 'error' in res:
        log.error("Failed to replicate new device root for {}".format(datastore_id))
        return res
   
    root_urls = []
    if not synchronous:
        root_urls = res['urls']

    # store root version
    res = put_device_root_version(datastore_id, datastore['root_uuid'], new_device_root_version, [this_device_id], config_path=config_path)
    if 'error' in res:
        return {'error': 'Failed to store new root version for {}'.format(datastore_id), 'errno': "EIO"}

    return {'status': True, 'root_urls': root_urls}


def datastore_putfile(api_client, file_name, file_data_bin, data_privkey_hex, datastore_id=None, data_pubkeys=None,
        this_device_id=None, create=False, synchronous=False, force=False, timestamp=0, config_path=CONFIG_PATH, proxy=None, blockchain_id=None, full_app_name=None):

    """
    Add a file to this datastore.

    This is a client-side method.

    * put the file, get back a url (synchronous)
    * update and sign the root directory
    * queue the new root for replication 

    * replicate the root with the new file data (asynchronous)
    
    Return {'status': True, 'urls': URLs to the file we saved, 'root_urls': URLs to the new root}.
    * if synchronous=False, then 'root_urls' will be None (since saving the root page will be off the critical path)

    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    if this_device_id is None:
        this_device_id = get_local_device_id(config_dir=os.path.dirname(config_path))

    # sanity check: device ID must have a public key 
    data_pubkey = None
    device_ids = []
    for dpk in data_pubkeys:
        device_ids.append(dpk['device_id'])
        if this_device_id == dpk['device_id']:
            data_pubkey = dpk['public_key']

    if data_pubkey is None:
        return {'error': 'Device {} has no public key', 'errno': "EINVAL"}
    
    if get_pubkey_hex(data_privkey_hex) not in [keylib.key_formatting.compress(data_pubkey), keylib.key_formatting.decompress(data_pubkey)]:
        return {'error': 'Data private key does not match device public key {}'.format(data_pubkey)}
    
    # get device root
    res = _find_device_root_info(api_client, this_device_id=this_device_id, datastore_id=datastore_id, data_pubkeys=data_pubkeys, 
                                             blockchain_id=blockchain_id, full_app_name=full_app_name,
                                             timestamp=timestamp, force=force, config_path=config_path, proxy=proxy)
    if 'error' in res:
        return res

    datastore = res['datastore']
    datastore_id = datastore_get_id(datastore['pubkey'])
    device_root = res['device_root']

    # serialize datastore
    datastore_info = datastore_serialize_and_sign(datastore, data_privkey_hex)
    datastore_str = datastore_info['str']
    datastore_sig = datastore_info['sig']
     
    # serialize file header with no URLs (used to verify data payload)
    data_hash = hash_data_payload(file_data_bin)
    file_entry = datastore_make_file_entry(data_hash, [])
    if 'error' in file_entry:
        return file_entry

    file_data_id = '{}/{}'.format(datastore_id, file_name)

    file_entry_blob = make_mutable_data_info(file_data_id, data_blob_serialize(file_entry), blockchain_id=blockchain_id, config_path=config_path, is_fq_data_id=True)
    if 'error' in file_entry_blob:
        return file_entry_blob
           
    file_entry_blob_str = data_blob_serialize(file_entry_blob)
    file_entry_sig = sign_data_payload(file_entry_blob_str, data_privkey_hex)

    log.debug("putfile {}/{}".format(datastore_id, file_name))

    # replicate the file data
    res = api_client.backend_datastore_putfile(datastore_str, datastore_sig, file_name, file_entry_blob_str, file_data_bin, file_entry_sig, this_device_id,
                                                blockchain_id=blockchain_id, full_app_name=full_app_name)

    if 'error' in res:
        log.error("Failed to store {} to {}".format(file_name, datastore_id))
        return {'error': res['error'], 'errno': res.get('errno', "EREMOTEIO")}

    file_urls = res['urls']

    # serialize file header with actual URLs (to be included into the root directory)
    file_entry = datastore_make_file_entry(data_hash, file_urls)
    if 'error' in file_entry:
        return file_entry

    # make new signed device root
    res = device_root_insert(datastore, device_root, file_name, file_entry, this_device_id, blockchain_id=blockchain_id)
    new_device_root = res['device_root_page_blob']
    new_device_root_version = res['timestamp']

    device_root_page_blob = data_blob_serialize(new_device_root)
    device_root_page_blob_sig = sign_data_payload(device_root_page_blob, data_privkey_hex)
    
    # put it, possibly synchronously
    res = api_client.backend_datastore_put_device_root(datastore_str, datastore_sig, device_root_page_blob, device_root_page_blob_sig, this_device_id,
                                                       data_pubkey=data_pubkey, blockchain_id=blockchain_id, full_app_name=full_app_name, synchronous=synchronous)

    if 'error' in res:
        log.error("Failed to replicate new device root for {} on putfile {}".format(datastore_id, file_name))
        return res
   
    root_urls = res['urls']

    # store root version
    res = put_device_root_version(datastore_id, datastore['root_uuid'], new_device_root_version, [this_device_id], config_path=config_path)
    if 'error' in res:
        return {'error': 'Failed to store new root version for {}'.format(datastore_id), 'errno': "EIO"}

    return {'status': True, 'urls': file_urls, 'root_urls': root_urls}


def datastore_deletefile(api_client, file_name, data_privkey_hex, data_pubkeys, this_device_id=None, synchronous=False, force=False, timestamp=0, config_path=CONFIG_PATH, proxy=None,
                         datastore_id=None, full_app_name=None, blockchain_id=None):
    """
    Remove this file from this datastore.

    This is a client-side method.

    * delete the file (synchronous)
    * update and sign the root directory
    * queue the new root for replication

    * replicate the root with the new file data (asynchronous)

    Return {'status': True, 'root_urls': ...} on successful deletion. 'root_urls' is None if synchronous=False
    Return {'error': ..., 'errno': ENOENT} if the file isn't in the root directory
    """

    if this_device_id is None:
        this_device_id = get_local_device_id(config_dir=os.path.dirname(config_path))

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    # sanity check: device ID must have a public key 
    data_pubkey = None
    for dpk in data_pubkeys:
        if this_device_id == dpk['device_id']:
            data_pubkey = dpk['public_key']

    if data_pubkey is None:
        return {'error': 'Device {} has no public key', 'errno': "EINVAL"}

    # get device root
    res = _find_device_root_info(api_client, this_device_id=this_device_id, datastore_id=datastore_id, data_pubkeys=data_pubkeys, 
                                             blockchain_id=blockchain_id, full_app_name=full_app_name,
                                             timestamp=timestamp, force=force, config_path=config_path, proxy=proxy)
    if 'error' in res:
        return res
    
    datastore = res['datastore']
    datastore_id = datastore_get_id(datastore['pubkey'])
    device_root = res['device_root']

    # sanity check: is this file present?
    if file_name not in device_root['files'].keys():
        return {'error': 'No such file "{}"'.format(file_name), 'errno': "ENOENT"}

    # make tombstones
    this_device_file_tombstone = make_data_tombstones([this_device_id], '{}/{}'.format(datastore_id, file_name))[0]
    file_tombstones = make_data_tombstones(datastore['device_ids'], '{}/{}'.format(datastore_id, file_name))
    signed_file_tombstones = sign_data_tombstones(file_tombstones, data_privkey_hex)

    # serialize datastore
    datastore_info = datastore_serialize_and_sign(datastore, data_privkey_hex)
    datastore_str = datastore_info['str']
    datastore_sig = datastore_info['sig']

    log.debug("deletefile {}/{}".format(datastore_id, file_name))

    res = api_client.backend_datastore_deletefile(datastore_str, datastore_sig, signed_file_tombstones, data_pubkeys, blockchain_id=blockchain_id, full_app_name=full_app_name, synchronous=synchronous)
    if 'error' in res:
        return res

    # patch root with tombstones
    res = device_root_remove(datastore, device_root, file_name, this_device_file_tombstone, this_device_id, config_path=config_path, blockchain_id=blockchain_id)

    # sign and serialize new root 
    new_device_root = res['device_root_page_blob']
    new_device_root_version = res['timestamp']
    device_root_page_blob = data_blob_serialize(res['device_root_page_blob'])
    device_root_page_blob_sig = sign_data_payload(device_root_page_blob, data_privkey_hex)
    
    # put it, possibly synchronously
    res = api_client.backend_datastore_put_device_root(datastore_str, datastore_sig, device_root_page_blob, device_root_page_blob_sig, this_device_id,
                                                       data_pubkey=data_pubkey, blockchain_id=blockchain_id, full_app_name=full_app_name, synchronous=synchronous)

    if 'error' in res:
        log.error("Failed to replicate new device root for {} on deletefile {}".format(datastore_id, file_name))
        return res
    
    root_urls = res['urls']

    # store root version
    res = put_device_root_version(datastore_id, datastore['root_uuid'], new_device_root_version, [this_device_id], config_path=config_path)
    if 'error' in res:
        return {'error': 'Failed to store new root version for {}'.format(datastore_id), 'errno': "EIO"}

    return {'status': True, 'urls': root_urls}


def datastore_stat(api_client, file_name, this_device_id, data_pubkeys=None, datastore_id=None, blockchain_id=None, full_app_name=None, force=False, config_path=CONFIG_PATH):
    """
    Stat a file or directory.  Get just the inode metadata.

    Return {'status': True, 'file_info': file header info} on success
    Return {'error': ..., 'errno': ...} on error
    """

    log.debug("stat {}/{}".format(datastore_id, file_name))

    file_info = api_client.backend_datastore_lookup(file_name, this_device_id, datastore_id=datastore_id, data_pubkeys=data_pubkeys, blockchain_id=blockchain_id, full_app_name=full_app_name, force=force )
    if 'error' in file_info:
        log.error("Failed to resolve {}".format(file_name))
        return file_info
    
    return file_info


