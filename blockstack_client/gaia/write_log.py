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
import random

from ..logger import get_logger
from ..proxy import get_default_proxy
from ..config import get_config, get_local_device_id
from ..constants import BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, DEFAULT_DEVICE_ID, CONFIG_PATH
from ..storage import sign_data_payload, make_data_tombstone, make_fq_data_id, sign_data_tombstone, parse_data_tombstone, verify_data_tombstone, parse_fq_data_id, \
        hash_data_payload, sign_data_payload, serialize_mutable_data, get_storage_handlers, verify_data_payload, get_mutable_data, get_immutable_data, get_data_hash, \
        put_immutable_data, parse_signed_data_tombstone, classify_storage_drivers, decode_mutable_data

from blob import data_blob_parse
from directory import put_device_root_data
from cache import GLOBAL_CACHE
from mutable import put_raw_data
from metadata import get_metadata_dir

log = get_logger('gaia-write_log')

WRITE_LOG_LOCK = threading.Lock()
WRITE_LOG_PAGE_SIZE = 100

WRITE_LOG_THREAD_SEMAPHORE = threading.Semaphore()

def write_log_notify():
    """
    Wake up the write log thread
    """
    global WRITE_LOG_THREAD_SEMAPHORE
    WRITE_LOG_THREAD_SEMAPHORE.release()


def write_log_path(config_path=CONFIG_PATH):
    """
    Get the path to this device's write log
    """
    conf = get_config(config_path)
    assert conf
    
    metadata_dir = get_metadata_dir(conf, config_path=config_path)
    assert metadata_dir

    path = os.path.join(metadata_dir, 'write_log.db')
    return path


def write_log_row_factory( cursor, row ):
    """
    row factory
    """
    d = {}
    for idx, col in enumerate( cursor.description ):
        d[col[0]] = row[idx]

    return d


def write_log_format_query( query, values ):
    """
    Turn a query into a string for printing.
    Useful for debugging.
    """
    return "".join( ["%s %s" % (frag, "'%s'" % val if type(val) in [str, unicode] else val) for (frag, val) in zip(query.split("?"), values + ("",))] )


def write_log_query_execute( cur, query, values ):
    """
    Execute a query.  If it fails, exit.

    DO NOT CALL THIS DIRECTLY.
    """

    # under heavy contention, this can cause timeouts (which is unacceptable)
    # serialize access to the db just to be safe
    
    global WRITE_LOG_LOCK

    try:
        WRITE_LOG_LOCK.acquire()
        ret = cur.execute( query, values )
        WRITE_LOG_LOCK.release()
        return ret
    except Exception, e:
        log.exception(e)
        log.error("FATAL: failed to execute query (%s, %s)" % (query, values))
        log.error("\n" + "\n".join(traceback.format_stack()))
        os.abort()


def write_log_open( path ):
    """
    Open the write log
    Return a connection.
    Return None if it doesn't exist
    """
    if not os.path.exists(path):
        log.debug("Atlas DB doesn't exist at %s" % path)
        return None

    con = sqlite3.connect( path, isolation_level=None )
    con.row_factory = write_log_row_factory
    return con


def write_log_init(config_path=CONFIG_PATH):
    """
    Set up this device's write log.
    Returns a database connection on success.
    Raise on exception.
    """
    path = write_log_path(config_path=config_path)

    if os.path.exists(path):
        return write_log_open(path)
    
    if not os.path.exists(os.path.dirname(path)):
        os.makedirs(os.path.dirname(path))

    schema = """CREATE TABLE write_log(datastore_id STRING NOT NULL,
                                       device_id STRING NOT NULL,
                                       root_uuid STRING NOT NULL,
                                       signed_device_root_page STRING NOT NULL,
                                       drivers STRING NOT NULL,
                                       blockchain_id STRING,
                                       timestamp INT NOT NULL,
                                       PRIMARY KEY(datastore_id,root_uuid,device_id,timestamp));"""

    path = write_log_path(config_path=config_path)
    con = sqlite3.connect(path, isolation_level=None)

    con.execute(schema)
    con.close()

    return write_log_open(path)


def write_log_enqueue(datastore_id, device_id, root_uuid, signed_device_root_page, drivers, blockchain_id=None, config_path=CONFIG_PATH):
    """
    Enqueue a root page for replication
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    from control import is_gaia_running

    if not is_gaia_running():
        return {'error': 'Gaia is not initialized'}

    path = write_log_path(config_path=config_path)
    if not os.path.exists(path):
        return {'error': 'No such write log at {}'.format(path)}
    
    con = write_log_open(path)
    cur = con.cursor()

    query = "INSERT INTO write_log (datastore_id,device_id,root_uuid,signed_device_root_page,drivers,blockchain_id,timestamp) VALUES (?,?,?,?,?,?,?);"
    args = (datastore_id,device_id,root_uuid,signed_device_root_page,json.dumps(drivers),blockchain_id,int(time.time() * 10**6))

    write_log_query_execute(cur, query, args)
    con.commit()
    con.close()

    write_log_notify()
    return {'status': True}


def write_log_peek(config_path=CONFIG_PATH, offset=0):
    """
    Get any queued datastore root
    Return {'status': True, 'root_uuid': ..., 'signed_device_root_page': ..., 'drivers': ..., 'blockchain_id': ..., 'timestamp': ...} on success
    Return {'error': ...} on failure
    """
    path = write_log_path(config_path=config_path)
    if not os.path.exists(path):
        return {'error': 'No such write log at {}'.format(path)}

    con = write_log_open(path)
    cur = con.cursor()
    
    # select the latest row from all groupings of rows by (datastore_id, root_uuid, device ID)
    query = 'SELECT * FROM (SELECT * FROM write_log GROUP BY datastore_id,root_uuid,device_id ORDER BY timestamp DESC LIMIT 1);'
    args = ()

    rows = write_log_query_execute(cur, query, args)

    rr = []
    for row in rows:
        rr.append(dict(row))

    con.close()
    
    if len(rr) == 0:
        return {'error': 'No such row'}

    random_row = rr[random.randint(0,len(rr)-1)]

    return {'status': True,
            'datastore_id': random_row['datastore_id'],
            'device_id': random_row['device_id'],
            'root_uuid': random_row['root_uuid'],
            'signed_device_root_page': random_row['signed_device_root_page'],
            'drivers': json.loads(random_row['drivers']),
            'blockchain_id': random_row['blockchain_id'],
            'timestamp': random_row['timestamp']}


def write_log_dequeue(datastore_id, root_uuid, device_id, timestamp, config_path=CONFIG_PATH):
    """
    Remove all instances of a write log entry for a device/datastore pair
    Return {'status': True} on success
    Return {'error': ...} on failure
    """
    path = write_log_path(config_path=config_path)
    if not os.path.exists(path):
        return {'error': 'No such write log at {}'.format(path)}

    con = write_log_open(path)
    cur = con.cursor()

    query = 'DELETE FROM write_log WHERE datastore_id = ? AND root_uuid = ? AND device_id = ? AND timestamp <= ?;'
    args = (datastore_id,root_uuid,device_id,timestamp)

    write_log_query_execute(cur, query, args)

    con.close()
    return {'status': True}


def write_log_size(config_path=CONFIG_PATH):
    """
    How many entries are in the write log?
    Return {'status': True, 'count': ...} on success
    Return {'error': ...} on failure
    """
    path = write_log_path(config_path=config_path)
    if not os.path.exists(path):
        return {'error': 'No such write log at {}'.format(path)}

    con = write_log_open(path)
    cur = con.cursor()

    query = 'SELECT COUNT(*) FROM write_log;'
    args = ()
    
    rows = write_log_query_execute(cur, query, args)
    
    count = None
    for row in rows:
        count = int(row['COUNT(*)'])
        break

    con.close()

    return {'status': True, 'count': count}


def write_log_page_replicate(datastore_id, device_id, root_uuid, signed_device_root_page, drivers, blockchain_id, config_path=CONFIG_PATH, proxy=None):
    """
    Replicate a signed write log page to the given list of drivers.
    This is a server-side method.

    blockchain_id may be None.

    Returns {'status': True, 'urls': [...]} on success
    Returns {'error': ...} on error
    """
    from control import is_gaia_running

    if not is_gaia_running():
        return {'error': 'Gaia is not initialized'}

    if proxy is None:
        proxy = get_default_proxy(config_path)

    # what's the fqid?
    info = decode_mutable_data(signed_device_root_page)
    if 'error' in info:
        return {'error': 'malformed signed device root page mutable data'}

    device_root_blob = data_blob_parse(info['data_txt'])
    if not isinstance(device_root_blob, dict) or not device_root_blob.has_key('fq_data_id'):
        return {'error': 'malformed device root page blob'}

    fq_data_id = device_root_blob['fq_data_id']
    
    log.debug("Store signed root page {}".format(fq_data_id))
    res = put_raw_data(fq_data_id, signed_device_root_page, drivers, config_path=config_path, blockchain_id=blockchain_id) 
    if 'error' in res:
        log.error("Failed to replicate page {} of the write log: {}".format(fq_data_id, res['error']))
        return {'error': res['error']}
    
    urls = res['urls']

    GLOBAL_CACHE.evict_device_root_directory(datastore_id, device_id, root_uuid)

    return {'status': True, 'urls': urls}


def write_log_replicate_thread(config_path=CONFIG_PATH):
    """
    Thread body for replicating queued device root pages
    """
    from control import is_gaia_running

    global WRITE_LOG_THREAD_SEMAPHORE

    while is_gaia_running():
        
        # wait for new data
        log.debug("Waiting for new device root pages to replicate...")
        WRITE_LOG_THREAD_SEMAPHORE.acquire()

        next_entry = write_log_peek(config_path=config_path)
        if 'error' in next_entry:
            continue
    
        # replicate this entry 
        res = write_log_page_replicate(next_entry['datastore_id'], next_entry['device_id'], next_entry['root_uuid'], next_entry['signed_device_root_page'], next_entry['drivers'], next_entry['blockchain_id'], config_path=config_path)
        if 'error' in res:
            continue

        # success!
        write_log_dequeue(next_entry['datastore_id'], next_entry['root_uuid'], next_entry['device_id'], next_entry['timestamp'], config_path=config_path)
