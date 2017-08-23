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

from keylib import *

import virtualchain
from virtualchain.lib.ecdsalib import *

from ..logger import get_logger
from ..proxy import get_default_proxy
from ..config import get_config, get_local_device_id
from ..constants import BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, CONFIG_PATH
from ..schemas import *
from ..storage import sign_data_payload, make_data_tombstone, make_fq_data_id, sign_data_tombstone, parse_data_tombstone, verify_data_tombstone, parse_fq_data_id, \
        hash_data_payload, sign_data_payload, serialize_mutable_data, get_storage_handlers, verify_data_payload, decode_mutable_data

from ..key_file import key_file_get, lookup_app_pubkeys, lookup_app_listing

from blob import *
from cache import *
from metadata import *
from file import *
from directory import *
from mutable import *
from policy import *
from write_log import *

log = get_logger('gaia-datastore')


def datastore_get_privkey( master_data_privkey, app_domain, config_path=CONFIG_PATH ):
    """
    Make the public/private key for an application account,
    given the app domain and the master private key

    Its master_data_privkey[sha256(app_domain)]/0', where sha256(app_domain) is the chaincode
    """
    chaincode = hashlib.sha256(str(app_domain)).digest()
    hdwallet = HDWallet( hex_privkey=master_data_privkey, chaincode=chaincode )
    app_private_key = hdwallet.get_child_privkey( index=DATASTORE_SIGNING_KEY_INDEX )

    return app_private_key


def get_datastore_info( blockchain_id=None, datastore_id=None, device_ids=None, full_app_name=None, config_path=CONFIG_PATH, proxy=None, no_cache=False, cache_ttl=None, parsed_key_file=None):
    """
    Get a datastore's information.
    This is a server-side method.

    There are two ways to call this method:
    * supply blockchain_id and full_app_name
    * supply datastore_id, and optionally device_ids 
    
    Returns {'status': True, 'datastore': public datastore info}
    Returns {'error': ..., 'errno':...} on failure
    """
    
    assert (blockchain_id and full_app_name) or (datastore_id and device_ids and len(device_ids) == 1), "Need either both datastore_id and device IDs, or both blockchain_id and full_app_name"

    if proxy is None:
        proxy = get_default_proxy(config_path)

    if cache_ttl is None:
        conf = get_config(config_path)
        assert conf
        cache_ttl = int(conf.get('cache_ttl', 3600))    # 1 hour
        
    cache_hit = False

    # find out which keys and addresses to use
    datastore_addresses = []
    data_ids = []

    # use URLs when possible
    fq_datastore_id = None
    datastore_urls = []

    # prefer token-file path over direct datastore query
    if blockchain_id and full_app_name:

        # multi-reader single-writer storage 
        if parsed_key_file is None:
            res = key_file_get(blockchain_id, cache=GLOBAL_CACHE, proxy=proxy)
            if 'error' in res:
                res['errno'] = "EINVAL"
                return res

            parsed_key_file = res['key_file']
        
        # datastore record may have been written by one of any of the devices.
        # find the one that wrote the URLs
        res = lookup_app_listing(blockchain_id, full_app_name, cache=GLOBAL_CACHE, proxy=proxy, parsed_key_file=parsed_key_file)
        if 'error' in res:
            res['errno'] = "EINVAL"
            return res
        
        app_info = res['app_info']
        if device_ids is None:
            device_ids = app_info.keys()
        
        # at most one device can have created this datastore
        multiple_datastores = {}
        creating_device_id = None
        for dev_id in app_info.keys():
            if len(app_info[dev_id][full_app_name]['datastore_urls']) > 0:
                if len(datastore_urls) > 0:
                    # multiple devices claim to have created this datastore 
                    log.warning("Device {} also created a datastore for {}".format(full_app_name))
                    multiple_datastores[dev_id] = app_info[dev_id][full_app_name]['datastore_urls']
                    continue

                datastore_urls = app_info[dev_id][full_app_name]['datastore_urls']
                fq_datastore_id = app_info[dev_id][full_app_name]['fq_datastore_id']
                creating_device_id = dev_id
        
        if multiple_datastores:
            msg = 'Corrupt key file for {}: the following devices have created datastores for {}: {}'.format(blockchain_id, full_app_name, multiple_datastores.keys() + [creating_device_id])
            log.error(msg)
            return {'error': msg}

        # find the devices that support this datastore
        found_device_ids = []

        for dev_id in device_ids:
            if not app_info.has_key(dev_id):
                log.warning("No public key for device '{}'".format(dev_id))
                continue
            
            if app_info[dev_id] is None:
                log.warning("Skipping device '{}', since it has 'None' public key")
                continue

            found_device_ids.append(dev_id)
            datastore_addresses.append(datastore_get_id(app_info[dev_id][full_app_name]['public_key']))

        device_ids = found_device_ids

    else:
        # single-reader single-writer storage.  do not rely on blockchain ID
        datastore_addresses = [datastore_id]
        fq_datastore_id = make_fq_data_id(device_ids[0], '{}.datastore'.format(datastore_id))

    device_id, datastore_id = parse_fq_data_id(fq_datastore_id)
    if not no_cache:
        if datastore_id is None:
            return {'error': 'Invalid fully-qualified datastore ID "{}"'.format(fq_datastore_id), 'errno': 'EINVAL'}

        res = GLOBAL_CACHE.get_datastore_record(datastore_id, cache_ttl)
        if res:
            datastore = res['datastore']
            return {'status': True, 'datastore': datastore}
    
    # cache miss
    datastore_info = get_mutable(fq_datastore_id, device_ids=device_ids, blockchain_id=blockchain_id, data_addresses=datastore_addresses, urls=datastore_urls, proxy=proxy, config_path=config_path)
    if 'error' in datastore_info:
        if 'notfound' in datastore_info or 'stale' in datastore_info:
            # absent. Store a negative
            log.debug("Not found: {}".format(fq_datastore_id))
            if not no_cache:
                log.debug("Absent or stale datastore record {}".format(fq_datastore_id))
                GLOBAL_CACHE.put_datastore_record(datastore_id, None, cache_ttl)

        return {'error': 'Failed to load public datastore record', 'errno': "ENOENT"}
  
    datastore_str = datastore_info['data']

    # parse and validate
    try:
        datastore = data_blob_parse(datastore_str)
        jsonschema.validate(datastore, DATASTORE_SCHEMA) 
    except (AssertionError, ValidationError) as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Invalid datastore record")
        return {'error': 'Invalid public datastore record', 'errno': "EIO"}

    if not no_cache:
        cache_rec = {'datastore': datastore}
        GLOBAL_CACHE.put_datastore_record(datastore_id, cache_rec, cache_ttl)

    return {'status': True, 'datastore': datastore}
    

def _init_datastore_info( datastore_type, datastore_pubkey, driver_names, device_ids, reader_pubkeys=[], config_path=CONFIG_PATH ):
    """
    Make the private part of a datastore record.
    @datastore_pubkey must be one of the device-specific app-specific public keys.

    Returns {'datastore': ..., 'root_blob': ...} on success
    Returns {'error': ...} on error
    """
    assert datastore_type in ['datastore', 'collection'], datastore_type

    root_uuid = str(uuid.uuid4())
    datastore_id = datastore_get_id(datastore_pubkey)
    timestamp = int(time.time() * 1000)
 
    root_data_id = '{}.{}'.format(datastore_id, root_uuid)

    root_dir = make_empty_device_root_directory(datastore_id, reader_pubkeys, timestamp)
    root_dir_str = data_blob_serialize(root_dir)
    root_dir_struct = make_mutable_data_info(root_data_id, root_dir_str, device_ids=device_ids, timestamp=timestamp, config_path=config_path)
    root_dir_blob = data_blob_serialize(root_dir_struct)

    datastore_info = {
        'type': datastore_type,
        'pubkey': datastore_pubkey,
        'drivers': driver_names,
        'device_ids': device_ids,
        'root_uuid': root_uuid
    }

    return {'datastore_blob': data_blob_serialize(datastore_info), 'root_blob': root_dir_blob}


def make_datastore_info( datastore_type, datastore_pubkey_hex, device_ids, driver_names=None, config_path=CONFIG_PATH ):
    """
    Create a new datastore record with the given name, using the given account_info structure

    This is a client-side method
   
    @datastore_pubkey_hex is the app-specific public key for this device.  It must be one of the public keys in the creator's key file.

    Return {'datastore_blob': public datastore information, 'root_blob_header': root inode header, 'root_blob_idata': root inode data}
    Return {'error': ...} on failure
    """
    if driver_names is None:
        driver_handlers = get_storage_handlers()
        driver_names = [h.__name__ for h in driver_handlers]

    datastore_info = _init_datastore_info( datastore_type, datastore_pubkey_hex, driver_names, device_ids, config_path=config_path)
    if 'error' in datastore_info:
        return datastore_info
   
    root_blob_str = datastore_info['root_blob']
    datastore_id = datastore_get_id(datastore_pubkey_hex)
    datastore_data_id = '{}.datastore'.format(datastore_id)
    datastore_str = datastore_info['datastore_blob']

    data_id = '{}.datastore'.format(datastore_id)
    
    # encapsulate to mutable data
    datastore_info = make_mutable_data_info(data_id, datastore_str, device_ids=device_ids, config_path=config_path)
    if 'error' in datastore_info:
        # only way this fails is if we had create=True and it already existed 
        return {'error': datastore_info['error'], 'errno': datastore_info['errno']}

    datastore_info_str = data_blob_serialize(datastore_info)

    return {'datastore_blob': datastore_info_str, 'root_blob': root_blob_str}


def sign_datastore_info( datastore_info, datastore_privkey_hex, config_path=CONFIG_PATH ):
    """
    Given datastore info from make_datastore_info(), generate the apporpriate signatures
    with the given private key.

    Return {'datastore_sig': ..., 'root_sig': ..., 'root_tombstones': ...} on success
    Return {'error': ...} on failure
    """

    datastore_mutable_data = data_blob_parse(datastore_info['datastore_blob'])
    datastore = data_blob_parse(datastore_mutable_data['data'])

    root_uuid = datastore['root_uuid']
    device_ids = datastore['device_ids']
    datastore_id = datastore_get_id( datastore['pubkey'] )
    
    root_sig = sign_data_payload( datastore_info['root_blob'], datastore_privkey_hex )
    datastore_sig = sign_data_payload( datastore_info['datastore_blob'], datastore_privkey_hex )

    root_id = '{}.{}'.format(datastore_id, root_uuid)
    root_tombstones = make_data_tombstones( datastore['device_ids'], root_uuid )
    signed_tombstones = sign_data_tombstones( root_tombstones, datastore_privkey_hex )

    ret = {'datastore_sig': datastore_sig, 'root_sig': root_sig, 'root_tombstones': signed_tombstones}
    if BLOCKSTACK_TEST:
        assert verify_datastore_info(datastore_info, ret, get_pubkey_hex(datastore_privkey_hex), config_path=config_path)

    return ret


def verify_datastore_info( datastore_info, sigs, datastore_pubkey_hex, config_path=CONFIG_PATH ):
    """
    Given datastore info from make_datastore_info() and signatures from sign_datastore_info,
    verify the datastore information authenticity.

    datastore_info has {'datastore_blob': ..., 'root_blob': ...} (serialized strings)
    sigs has {'datastore_sig': ..., 'root_sig': ...} (base64-encoded signatures)
    
    Return True on success
    Return False on error
    """

    res = verify_data_payload( datastore_info['datastore_blob'], datastore_pubkey_hex, sigs['datastore_sig'] )
    if not res:
        log.debug("Failed to verify datastore blob payload with {} and {}".format(datastore_pubkey_hex, sigs['datastore_sig']))
        if BLOCKSTACK_TEST:
            log.debug("datastore_info: {}".format(json.dumps(datastore_info)))

        return False

    res = verify_data_payload( datastore_info['root_blob'], datastore_pubkey_hex, sigs['root_sig'] )
    if not res:
        log.debug("Failed to verify root inode blob payload with {} and {}".format(datastore_pubkey_hex, sigs['root_sig']))
        return False

    return True


def put_datastore_info( datastore_info, datastore_sigs, root_tombstones, config_path=CONFIG_PATH, proxy=None, blockchain_id=None ):
    """
    Given output from make_datastore_info and sign_datastore_info, store it to mutable data.
    This is a server-side method
    
    Return {'status': True, 'root_urls': ..., 'datastore_urls': ...} on success
    Return {'error': ...} on error
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    datastore_mutable_data = data_blob_parse(datastore_info['datastore_blob'])
    try:
        jsonschema.validate(datastore_mutable_data, DATA_BLOB_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        return {'error': 'Invalid datastore blob'}

    datastore_fqid = datastore_mutable_data['fq_data_id']
    datastore_version = datastore_mutable_data['version']
    datastore_dev_id = None

    try:
        datastore_dev_id, datastore_data_id = parse_fq_data_id(datastore_fqid)
        assert datastore_dev_id, "Invalid fqid"
        assert datastore_data_id, "Invalid fquid"
    except AssertionError as ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        return {'error': 'Invalid datastore ID'}

    datastore = data_blob_parse(datastore_mutable_data['data'])
    try:
        jsonschema.validate(datastore, DATASTORE_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        return {'error': 'Invalid datastore'}

    datastore_id = datastore_get_id(datastore['pubkey'])
    
    # store root 
    res = put_device_root_data(datastore_id, datastore_dev_id, datastore['root_uuid'], datastore_info['root_blob'], datastore['pubkey'], datastore_sigs['root_sig'], datastore['drivers'],
                               config_path=config_path, blockchain_id=blockchain_id)

    if 'error' in res:
        log.error("Failed to store root directory info for {}".format(datastore_id))
        return {'error': res['error'], 'errno': "EREMOTEIO"}

    root_urls = res['urls']

    # store datastore
    res = put_mutable(datastore_fqid, datastore_info['datastore_blob'], datastore['pubkey'], datastore_sigs['datastore_sig'],
                      blockchain_id=blockchain_id, storage_drivers=datastore['drivers'], storage_drivers_exclusive=True, config_path=config_path)

    if 'error' in res:
        log.error("Failed to store datastore record for {}".format(datastore_id))

        # attempt clean up 
        cleanup_res = delete_raw_data([datastore['root_tombstone']], datastore['drivers'], config_path=config_path, blockchain_id=blockchain_id)
        if 'error' in cleanup_res:
            return {'error': 'Failed to clean up from partial datastore creation.  "urls" contains URLs to leaked root directory copies.', 'urls': root_urls}
        else:
            return {'error': res['error'], 'errno': "EREMOTEIO"}

    datastore_urls = res['urls'].values()

    # success
    return {'status': True, 'root_urls': root_urls, 'datastore_urls': datastore_urls}


def delete_datastore_info( datastore_id, datastore_tombstones, root_tombstones, data_pubkeys, blockchain_id=None, force=False, proxy=None, config_path=CONFIG_PATH ):
    """
    Delete a datastore.  Only do so if its root directory is empty (unless force=True).
    Any device can delete the datastore.

    This is a server-side method.

    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)
   
    device_ids = [dk['device_id'] for dk in data_pubkeys]

    # get the datastore first
    datastore_info = get_datastore_info(blockchain_id=blockchain_id, datastore_id=datastore_id, device_ids=device_ids, config_path=config_path, proxy=proxy, no_cache=True)
    if 'error' in datastore_info:
        log.error("Failed to look up datastore information for {}: {}".format(datastore_id, datastore_info['error']))
        return {'error': 'Failed to look up datastore', 'errno': "ENOENT"}
    
    datastore = datastore_info['datastore']
    root_uuid = datastore['root_uuid']
    drivers = datastore['drivers']

    # get root directory
    res = get_root_directory(datastore_id, root_uuid, drivers, data_pubkeys, timestamp=0, force=force, config_path=config_path, proxy=proxy, blockchain_id=blockchain_id)
    if 'error' in res:
        if not force:
            log.error("Failed to get root directory")
            return {'error': 'Failed to check if datastore is empty', 'errno': "EREMOTEIO"}
        else:
            log.warn("Failed to get root directory, but forced to remove it anyway")
    
    if not force and len(res['root']) != 0:
        log.error("Datastore {} not empty (has {} files)".format(datastore_id, len(res['root'])))
        return {'error': 'Datastore not empty', 'errno': "ENOTEMPTY"}
    
    res = delete_mutable(datastore_tombstones, storage_drivers=drivers, storage_drivers_exclusive=True, proxy=proxy, config_path=config_path )
    if 'error' in res:
        log.error("Failed to delete datastore {}".format(datastore_id))
        return {'error': 'Failed to delete datastore', 'errno': "EREMOTEIO"}
    
    res = delete_mutable(root_tombstones, storage_drivers=drivers, storage_drivers_exclusive=True, proxy=proxy, config_path=config_path)
    if 'error' in res:
        log.error("Failed to delete root of {}".format(datastore_id))
        return {'error': 'Failed to delete root directory', 'errno': "EREMOTEIO"}

    GLOBAL_CACHE.evict_datastore_record(datastore_id)

    return {'status': True}


def verify_file_data(full_app_name, datastore, file_name, file_header_blob, payload, signature, device_id, blockchain_id=None, data_pubkey=None, config_path=CONFIG_PATH, proxy=None):
    """
    Server-side method to verify the authenticity and integrity of file data
    
    This is a server-side method

    Returns {'status': True} if valid
    Returns {'error': ..., 'errno': ...} if invalid
    """
    
    assert data_pubkey or (blockchain_id and full_app_name), 'Need either blockchain_id and full_app_name, or data_pubkey'
    if data_pubkey is None:
        # look up from key file
        res = lookup_app_pubkeys(blockchain_id, full_app_name, cache=GLOBAL_CACHE, proxy=proxy)
        if 'error' in res:
            res['errno'] = "EINVAL"
            return res
         
        data_pubkey = res['pubkeys'].get(device_id, None)
        if data_pubkey is None:
            return {'error': 'Unknown device {}'.format(device_id)}

    # must be signed by the device's public key
    try:
        res = verify_data_payload( file_header_blob, data_pubkey, signature )
    except AssertionError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Invalid public key or signature ({}, {})".format(data_pubkey, signature))
        return {'error': 'failed to verify file data: invalid public key or signature', 'errno': "EINVAL"}

    if not res:
        log.error("Failed to verify {} ({}) with {}".format(header_blob, signature, datas_pubkey))
        return {'error': 'failed to verify file data: bad signature', 'errno': "EINVAL"}

    # check payload hash 
    payload_hash = hash_data_payload(payload)
    header_mutable_data_struct = data_blob_parse(file_header_blob)

    # must be a valid mutable data blob 
    try:
        jsonschema.validate(header_mutable_data_struct, DATA_BLOB_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Invalid data blob")
        return {'error': 'invalid file header container (schema mismatch)', 'errno': "EINVAL"}

    # must be a valid header
    header_struct = data_blob_parse(header_mutable_data_struct['data'])
    try:
        jsonschema.validate(header_struct, ROOT_DIRECTORY_ENTRY_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Invalid header struct")
        return {'error': 'invalid file header structure (schema mismatch)', 'errno': "EINVAL"}

    # payload must match header
    if payload_hash != header_struct['data_hash']:
        log.error("Payload hash mismatch: {} != {}".format(payload_hash, header_struct['data_hash']))
        return {'error': "Payload {} does not match file header {}".format(payload_hash, header_struct['data_hash']), 'errno': "EINVAL"}

    return {'status': True}


def verify_root_data(datastore, root_data_blob, signature, device_id, blockchain_id=None, full_app_name=None, data_pubkey=None, config_path=CONFIG_PATH, proxy=None):
    """
    Server-side method to verify the authenticity and integrity of root page data.
    
    This is a server-side method

    Returns {'status': True, 'data_pubkey': ...} if valid
    Returns {'error': ..., 'errno': ...} if invalid
    """
    
    assert data_pubkey or (full_app_name and blockchain_id), 'Need either blockchain_id and full_app_name, or data_pubkey'
    if data_pubkey is None:
        # look up from key file
        res = lookup_app_pubkeys(blockchain_id, full_app_name, cache=GLOBAL_CACHE, proxy=proxy)
        if 'error' in res:
            res['errno'] = "EINVAL"
            return res
         
        data_pubkey = res['pubkeys'].get(device_id, None)
        if data_pubkey is None:
            return {'error': 'Unknown device {}'.format(device_id)}

    # must be signed by the device's public key
    try:
        res = verify_data_payload( root_data_blob, data_pubkey, signature )
    except AssertionError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("failed to verify root directory page: invalid public key or signature ({}, {})".format(data_pubkey, signature))
        return {'error': 'Invalid public key or signature', 'errno': "EINVAL"}

    if not res:
        log.error("Failed to verify {} ({}) with {}".format(header_blob, signature, datas_pubkey))
        return {'error': 'failed to verify root directory page: bad signature', 'errno': "EINVAL"}

    # must be a valid blob 
    device_root_blob = data_blob_parse(root_data_blob)
    try:
        jsonschema.validate(device_root_blob, DATA_BLOB_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Invalid data blob")
        return {'error': 'invalid file header container (schema mismatch)', 'errno': "EINVAL"}

    # must be a valid root directory
    device_root = data_blob_parse(device_root_blob['data'])
    try:
        jsonschema.validate(device_root, ROOT_DIRECTORY_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Invalid root directory page struct")
        return {'error': 'invalid root directory page structure (schema mismatch)', 'errno': "EINVAL"}
    
    # root must not be stale 
    datastore_id = datastore_get_id(datastore['pubkey'])
    res = get_device_root_version(datastore_id, datastore['root_uuid'], datastore['device_ids'], config_path=config_path)
    if 'error' in res:
        log.error("Failed to check root device version for {}".format(datastore_id))
        return {'error': 'Failed to check root device version for {}'.format(datastore_id), 'errno': "EIO"}

    if res['version'] > device_root['timestamp']:
        log.error("Stale data for root {}: expected version >= {}, got {}".format(datastore_id, device_root['timestamp'], res['version']))
        return {'error': 'Device root is stale.  Last version seen: {}'.format(res['version']), 'errno': "ESTALE"}

    return {'status': True, 'pubkey': data_pubkey}


def datastore_get_file_data(datastore, file_name, data_pubkeys, full_app_name=None, force=False, timestamp=0, config_path=CONFIG_PATH, blockchain_id=None, proxy=None):
    """
    Get a file's data from the datastore.  Entry point from the API server.

    @full_app_name is only needed if data_pubkeys is None

    This is a server-side method.

    Return {'status': True, 'data': ...} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    if data_pubkeys is None:
        assert blockchain_id, 'Need blockchain_id if data_pubkeys is None'
        assert full_app_name, 'Need full_app_name if data_pubkeys is None'

        # get from key file
        res = lookup_app_pubkeys(blockchain_id, full_app_name, cache=GLOBAL_CACHE, proxy=proxy)
        if 'error' in res:
            res['errno'] = "EINVAL"
            return res
        
        data_pubkeys = [{'device_id': dev_id, 'public_key': res['pubkeys'][dev_id]} for dev_id in data_pubkeys.keys()]

    return get_file_data(datastore, file_name, data_pubkeys, force=force, timestamp=0, config_path=CONFIG_PATH, blockchain_id=blockchain_id)


def datastore_get_device_root(full_app_name, datastore, device_id, data_pubkey=None, force=False, timestamp=0, config_path=CONFIG_PATH, blockchain_id=None, proxy=None):
    """
    Get a device's root page from the datastore.  Entry point from the API server.

    This is a server-side method

    Return {'status': True, 'device_root_page': ...} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    assert blockchain_id or data_pubkey, 'Need either blockchain_id or data_pubkey'

    if data_pubkey is None:
        # get from key file
        res = lookup_app_pubkeys(blockchain_id, full_app_name, cache=GLOBAL_CACHE, proxy=proxy)
        if 'error' in res:
            res['errno'] = "EINVAL"
            return res

        data_pubkey = res['pubkeys'].get(device_id, None)
        if not data_pubkey:
            return {'error': 'Unknown device ID', 'errno': "EINVAL"}

    datastore_id = datastore_get_id(datastore['pubkey'])
    return get_device_root_directory(datastore_id, datastore['root_uuid'], datastore['drivers'], device_id, data_pubkey, timestamp=timestamp, force=force, config_path=config_path, blockchain_id=blockchain_id)


def datastore_put_file_data(full_app_name, datastore, file_name, file_header_blob, payload, signature, device_id, blockchain_id=None, data_pubkey=None, config_path=CONFIG_PATH):
    """
    Store file data.  Entry point from the API server.

    This is a server-side method

    Return {'status': True, 'urls': [...]} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    
    if data_pubkey is None:
        assert blockchain_id and full_app_name, 'Need both full_app_name and blockchain_id if data_pubkey is not given'

        # get from key file
        res = lookup_app_pubkeys(blockchain_id, full_app_name, cache=GLOBAL_CACHE, proxy=proxy)
        if 'error' in res:
            res['errno'] = "EINVAL"
            return res

        data_pubkey = res['pubkeys'].get(device_id, None)
        if not data_pubkey:
            return {'error': 'Unknown device ID', 'errno': "EINVAL"}

    # must be well-formed, consistent, and authentic
    res = verify_file_data(full_app_name, datastore, file_name, file_header_blob, payload, signature, device_id, blockchain_id=blockchain_id, data_pubkey=data_pubkey, config_path=config_path)
    if 'error' in res:
        return res
    
    datastore_id = datastore_get_id(datastore['pubkey'])

    # store it
    res = put_file_data(datastore_id, device_id, file_name, payload, datastore['drivers'], config_path=config_path, blockchain_id=blockchain_id)
    if 'error' in res:
        return res

    return res


def datastore_put_device_root_data(datastore, device_root_page_blob, signature, device_id, full_app_name=None, blockchain_id=None, data_pubkey=None, config_path=CONFIG_PATH, proxy=None, synchronous=False):
    """
    Store device root directory data.  Entry point from the API server.

    This is a server-side method

    Return {'status': True, 'urls': [...]} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    
    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)
    
    # must be well-formed and authentic 
    res = verify_root_data(datastore, device_root_page_blob, signature, device_id, full_app_name=full_app_name, blockchain_id=blockchain_id, data_pubkey=data_pubkey, config_path=config_path)
    if 'error' in res:
        return res

    datastore_id = datastore_get_id(datastore['pubkey'])
    pubkey = res['pubkey']
    root_urls = None

    signed_device_root_page_blob = serialize_mutable_data(device_root_page_blob, data_signature=signature, data_pubkey=data_pubkey)
    
    # queue for replication, if not synchronous.
    # otherwise, replicate right now.
    if synchronous:
        # replicate
        res = write_log_page_replicate(datastore_id, device_id, datastore['root_uuid'], signed_device_root_page_blob, datastore['drivers'], blockchain_id, config_path=config_path, proxy=proxy)
        if 'error' in res:
            log.error("Failed to replicate signed root page for {}.{}".format(datastore_id, datastore['root_uuid']))
            return {'error': res['error'], 'errno': "EREMOTEIO"}

        root_urls = res['urls']

    else:
        # queue for later replication 
        res = write_log_enqueue(datastore_id, device_id, datastore['root_uuid'], signed_device_root_page_blob, datastore['drivers'], blockchain_id=blockchain_id, config_path=config_path)
        if 'error' in res:
            log.error("Failed to enqueue {}.{} for replication (on put_device_root)".format(datastore_id, datastore['root_uuid']))
            return {'error': res['error'], 'errno': "EIO"}

    return {'status': True, 'urls': root_urls}


def datastore_delete_file_data(datastore, signed_tombstones, blockchain_id=None, full_app_name=None, data_pubkeys=None, config_path=CONFIG_PATH, proxy=None):
    """
    Delete file data.  Entry point from the API server

    This is a server-side method

    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    assert (full_app_name and blockchain_id) or data_pubkeys, 'Need either blockchain_id and full app name, or data_pubkeys'

    if data_pubkeys is None:
        # get from key file
        res = lookup_app_pubkeys(blockchain_id, full_app_name, cache=GLOBAL_CACHE, proxy=proxy)
        if 'error' in res:
            res['errno'] = "EINVAL"
            return res
        
        data_pubkeys = [{'device_id': dev_id, 'public_key': res['pubkeys'][dev_id]} for dev_id in data_pubkeys.keys()]

    # must be well-formed tombstones
    for signed_tombstone in signed_tombstones:
        authentic = False
        for dpk in data_pubkeys:
            authentic = verify_data_tombstones( [signed_tombstone], dpk['public_key'] )
            if authentic:
                break
                
        if not authentic:
            return {'error': 'Invalid tombstone', 'errno': "EINVAL"}

    # delete it
    res = delete_raw_data(signed_tombstones, datastore['drivers'], config_path=config_path, blockchain_id=blockchain_id, proxy=proxy)
    if 'error' in res:
        res['errno'] = "EREMOTEIO"
        return res

    return {'status': True}


def datastore_file_data_verify( datastore_pubkey, headers, payloads, signatures, tombstones, device_ids, config_path=CONFIG_PATH ):
    """
    Given signed file headers, tombstones, and payloads, verify that they were all signed.
    
    NOTE: datastore_pubkey corresponds to the device-specific public key of the caller

    Return {'status': True} if we're all good
    Return {'error': ..., 'errno': ...} on error
    """
    assert len(headers) == len(payloads)
    assert len(payloads) == len(signatures)
    
    datastore_id = datastore_get_id(datastore_pubkey)

    # verify signatures and hashes
    for i in xrange(0, len(headers)):
        header_blob = headers[i]
        payload = payloads[i]
        signature = signatures[i]

        try:
            res = verify_data_payload( header_blob, datastore_pubkey, signature )
        except AssertionError as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            log.error("Invalid public key or signature ({}, {})".format(datastore_pubkey, signature))
            return {'error': 'Invalid public key or signature', 'errno': "EINVAL"}

        if not res:
            log.debug("Failed to verify {} ({}) with {}".format(header_blob, signature, datastore_pubkey))
            return {'error': 'Failed to verify signature', 'errno': "EINVAL"}

        # check hash 
        payload_hash = hash_data_payload(payload)
        header_mutable_data_struct = data_blob_parse(header_blob)
        header_struct = data_blob_parse(header_mutable_data_struct['data'])
        if payload_hash != header_struct['data_hash']:
            log.debug("Payload hash mismatch: {} != {}".format(payload_hash, header_struct['data_hash']))
            return {'error': "Payload {} does not match file header {}".format(payload_hash, header_struct['data_hash']), 'errno': "EINVAL"}

    if len(tombstones) > 0:
        res = verify_mutable_data_tombstones( tombstones, datastore_pubkey, device_ids=device_ids )
        if not res:
            return {'error': 'Failed to verify data tombstones', 'errno': "EINVAL"}

    return {'status': True}

