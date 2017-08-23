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
        put_immutable_data, parse_signed_data_tombstone, put_mutable_data, delete_mutable_data

from utils import ScatterGather

log = get_logger('gaia-mutable')

from blob import *
from policy import *

def get_mutable(fq_data_id, device_ids=None, raw=False, data_pubkeys=None, data_addresses=None, data_hash=None, storage_drivers=None,
                            proxy=None, timestamp=0, force=False, urls=None,
                            config_path=CONFIG_PATH, blockchain_id=None):
    """
    get_mutable 

    Fetch a piece of mutable data from *all* drivers.

    Verification order:
        The data will be verified against *any* public key in data_pubkeys, if given.
        The data will be verified against *any* data address in data_addresses, if given.
    
    Return {'data': the data, 'timestamp': ..., 'drivers': [driver name]} on success
    If raw=True, then only return {'data': ..., 'drivers': ...} on success.

    Return {'error': ...} on error
    """

    proxy = get_default_proxy(config_path) if proxy is None else proxy
    conf = get_config(path=config_path)

    # must have raw=True if we don't have public keys or addresses
    if data_pubkeys is None and data_addresses is None:
        assert raw, "No data public keys or public key hashes are given"

    if storage_drivers is None:
        storage_drivers = get_read_storage_drivers(config_path)
        log.debug("Using default storge drivers {}".format(','.join(storage_drivers)))

    if force:
        timestamp = 0

    log.debug("get_mutable({}, blockchain_id={}, pubkeys={}, addrs={}, hash={}, storage_drivers={}, urls={})".format(
        fq_data_id, blockchain_id, data_pubkeys, data_addresses, data_hash, ','.join(storage_drivers), urls if urls else []
    ))
    
    mutable_data = None
    stale = False
    notfound = True

    mutable_drivers = []
    latest_timestamp = 0

    # optimization: try local drivers before non-local drivers
    storage_drivers = prioritize_read_drivers(config_path, storage_drivers)
     
    # which storage drivers and/or URLs will we use?
    for driver in storage_drivers: 

        log.debug("get_mutable_data({}) from {}".format(fq_data_id, driver))
        
        # get the mutable data itsef
        # NOTE: we only use 'bsk2' data formats; use storage.get_mutable_data() directly for loading things like profiles that have a different format.
        data_str = get_mutable_data(fq_data_id, data_pubkeys, urls=urls, drivers=[driver], data_addresses=data_addresses, data_hash=data_hash, bsk_version=2, blockchain_id=blockchain_id)
        if data_str is None:
            log.error("Failed to get mutable datum {} from {}".format(fq_data_id, driver))
            continue
        
        notfound = False

        if raw:
            # no more work to do
            ret = {
                'data': data_str,
                'drivers': [driver],
            }
            return ret

        # expect mutable data blob.  Parse and validate it.
        data = None
        try:
            data = data_blob_parse(data_str)
            jsonschema.validate(data, DATA_BLOB_SCHEMA)
        except ValidationError as ve:
            if BLOCKSTACK_DEBUG:
                log.exception(ve)

            log.warn("Invalid mutable data from {} for {}".format(driver, fq_data_id))
            continue

        if data['fq_data_id'] != fq_data_id:
            log.warn("Got back an unexpected fq_data_id '{}'".format(data['fq_data_id']))
            continue

        # check consistency
        data_ts = data['timestamp']
        if data_ts < timestamp:
            log.warn("Invalid (stale) data timestamp from {} for {}: data ts = {}, timestamp = {}".format(driver, fq_data_id, data_ts, timestamp))
            stale = True
            continue

        if data_ts < latest_timestamp:
            log.warn("{} from {} is stale ({} < {})".format(fq_data_id, driver, data_ts, latest_timestamp))
            continue

        elif data_ts == latest_timestamp:
            log.debug("{} from {} has the same timestamp as latest ({}), available from {}".format(fq_data_id, driver, latest_timestamp, ','.join(mutable_drivers)))
            mutable_data = data
            mutable_drivers.append(driver)
            continue

        else:
            # got a later version
            # discard all prior drivers; they gave stale data
            latest_timestamp = data_ts
            mutable_data = data
            mutable_drivers = [driver]
            log.debug("Latest timestamp of {} is now {}, available from {}".format(fq_data_id, data_ts, driver))
            continue

    if mutable_data is None:
        log.error("Failed to fetch mutable data for {}".format(fq_data_id))
        res = {'error': 'Failed to fetch mutable data'}
        if stale:
            res['stale'] = stale
            res['error'] = 'Failed to fetch mutable data for {} due to timestamp mismatch.'
            log.error("Failed to fetch mutable data for {} due to timestamp mismatch.".format(fq_data_id))

        if notfound:
            res['notfound'] = True
            log.error("Failed to fetch mutable data for {} since no drivers returned data.".format(fq_data_id))

        return res

    ret = {
        'data': mutable_data['data'],
        'timestamp': latest_timestamp,
        'fq_data_id': mutable_data['fq_data_id'],
        'drivers': mutable_drivers
    }

    return ret


def put_mutable(fq_data_id, mutable_data_str, data_pubkey, data_signature, blockchain_id=None, proxy=None, raw=False, timestamp=None,
                config_path=CONFIG_PATH, storage_drivers=None, storage_drivers_exclusive=False, zonefile_storage_drivers=None ):
    """
    put_mutable.

    Given a serialized data payload from make_mutable_data, a public key, and a signature,
    store it with the configured storage providers.

    This is a very low-level method.  DO NOT USE UNLESS YOU KNOW WHAT YOU ARE DOING

    ** Consistency **


    ** Durability **

    Replication is all-or-nothing with respect to explicitly-listed storage drivers.  Each storage driver in storage_drivers must succeed.
    If any of them fail, then put_mutable fails.  All other storage drivers configured in the config file but not listed in storage_drivers
    will be attempted, but failures will be ignored.

    Notes on usage:
    * if storage_drivers is None, each storage driver under `storage_drivers_required_write=` will be required.
    * if storage_drivers is not None, then each storage driver in storage_drivers *must* succeed
    * If data_signature is not None, it must be the signature over the serialized payload form of data_payload

    Return {'status': True, 'urls': {'$driver_name': '$url'}} on success
    Return {'error': ...} on error
    """

    proxy = get_default_proxy(config_path) if proxy is None else proxy
    conf = get_config(path=config_path)
    assert conf

    # NOTE: this will be None if the fq_data_id refers to a profile
    device_id, _ = parse_fq_data_id(fq_data_id)
    if device_id is None:
        log.warning("No device ID found in {}".format(fq_data_id))
        device_id = DEFAULT_DEVICE_ID

    if storage_drivers is None:
        storage_drivers = get_required_write_storage_drivers(config_path)
        log.debug("Storage drivers equired write defaults: {}".format(','.join(storage_drivers)))

    result = {}

    log.debug("put_mutable({}, signature={}, storage_drivers={}, exclusive={}, raw={})".format(
        fq_data_id, data_signature, ','.join(storage_drivers), storage_drivers_exclusive, raw)
    )

    if not raw:
        # require signature and pubkey, since we'll serialize
        assert data_pubkey
        assert data_signature

    storage_res = put_mutable_data(fq_data_id, mutable_data_str, data_pubkey=data_pubkey, data_signature=data_signature, sign=False, raw=raw, blockchain_id=blockchain_id,
                                   required=storage_drivers, required_exclusive=storage_drivers_exclusive)

    if 'error' in storage_res:
        log.error("failed to put mutable data {}: {}".format(fq_data_id, storage_res['error']))
        result['error'] = 'Failed to store mutable data'
        return result

    return storage_res


def delete_mutable(signed_data_tombstones, proxy=None, storage_drivers=None,
                                           storage_drivers_exclusive=False,
                                           blockchain_id=None, config_path=CONFIG_PATH):
    """
    delete_mutable

    Remove a piece of mutable data. Delete it from
    the storage providers as well.

    Returns a dict with {'status': True} on success
    Returns a dict with {'error': ...} on failure
    """

    proxy = get_default_proxy(config_path) if proxy is None else proxy
    conf = get_config(config_path)
    assert conf

    if storage_drivers is None:
        storage_drivers = get_required_write_storage_drivers(config_path)

    worst_rc = True

    log.debug("delete_mutable(signed_data_tombstones={}, blockchain_id={}, storage_drivers={})".format(
        ','.join(signed_data_tombstones), blockchain_id, ','.join(storage_drivers)
    ))

    # remove the data itself
    for signed_data_tombstone in signed_data_tombstones:
        ts_data = parse_signed_data_tombstone(str(signed_data_tombstone))
        assert ts_data, "Unparseable signed tombstone '{}'".format(signed_data_tombstone)

        fq_data_id = ts_data['id']
        rc = delete_mutable_data(fq_data_id, signed_data_tombstone=signed_data_tombstone, required=storage_drivers, required_exclusive=storage_drivers_exclusive, blockchain_id=blockchain_id)
        if not rc:
            log.error("Failed to delete {} from storage providers".format(fq_data_id))
            worst_rc = False
            continue
    
    if not worst_rc:
        return {'error': 'Failed to delete from all storage providers'}

    return {'status': True}


def put_raw_data( fq_data_id, data_bytes, drivers, config_path=CONFIG_PATH, blockchain_id=None, data_pubkey=None, data_signature=None ):
    """
    Store raw file or serialized directory data to the backend drivers.
    Write to each driver in parallel.
    
    This is a server-side method, and not meant to be public.

    Return {'status': True, 'urls': ...} on success
    Return {'error': ...} on failure
    """

    def _put_data_to_driver(driver):
        """
        Store the data_bytes to a driver
        """
        res = put_mutable(fq_data_id, data_bytes, data_pubkey, data_signature, raw=True, blockchain_id=blockchain_id, storage_drivers=[driver], storage_drivers_exclusive=True, config_path=config_path)
        if 'error' in res:
            log.error("Failed to put data to {}: {}".format(driver, res['error']))
            return {'error': 'Failed to replicate data to {}'.format(driver), 'errno': "EREMOTEIO"}

        url = res['urls'][driver]        
        return {'status': True, 'url': url}

    sg = ScatterGather()
    for driver in drivers:
        put_data_func = functools.partial(_put_data_to_driver, driver)
        task_id = '_put_data_to_driver_{}'.format(driver)
        sg.add_task(task_id, put_data_func)

    sg.run_tasks()

    errors = []
    urls = []
    for driver in drivers:
        task_id = '_put_data_to_driver_{}'.format(driver)
        res = sg.get_result(task_id)
        if 'error' in res:
            errors.append(driver)

        else:
            urls.append(res['url'])

    if len(errors) > 0:
        return {'error': 'Some drivers failed to replicate data: {}'.format(','.join(errors)), 'errno': "EREMOTEIO"}

    return {'status': True, 'urls': urls}


def delete_raw_data( signed_tombstones, drivers, config_path=CONFIG_PATH, blockchain_id=None, proxy=None ):
    """
    Delete data from multiple drivers in parallel.
    
    This is a server-side method, and not meant to be public.

    Return {'status': True} on success
    Return {'error': ..} on failure
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    def _delete_data_from_driver(driver):
        """
        Delete the data from the driver, given the tombstone
        """
        res = delete_mutable(signed_tombstones, proxy=proxy, storage_drivers=[driver], storage_drivers_exclusive=True, blockchain_id=blockchain_id, config_path=config_path)
        if 'error' in res:
            return {'error': 'Failed to delete {} from {}'.format(signed_tombstone, driver)}

        return {'status': True}

    sg = ScatterGather()
    for driver in drivers:
        delete_data_func = functools.partial(_delete_data_from_driver, driver)
        task_id = '_delete_data_from_driver_{}'.format(driver)
        sg.add_task(task_id, delete_data_func)

    sg.run_tasks()

    errors = []
    for driver in drivers:
        task_id = '_delete_data_from_driver_{}'.format(driver)
        res = sg.get_result(task_id)
        if 'error' in res:
            errors.append(driver)

    if len(errors) > 0:
        return {'error': 'Some drivers failed to delete data: {}'.format(','.join(errors)), 'errno': "EREMOTEIO"}

    return {'status': True}


