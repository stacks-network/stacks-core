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

from keylib import *

import virtualchain
from virtualchain.lib.ecdsalib import *

from ..logger import get_logger
from ..proxy import get_default_proxy
from ..config import get_config, get_local_device_id
from ..constants import BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, DEFAULT_DEVICE_ID, CONFIG_PATH
from ..schemas import *
from ..storage import parse_signed_data_tombstone, decode_mutable_data

log = get_logger('gaia-cache')

class DataCache(object):
    """
    Write-coherent datastore data cache
    """
    def __init__(self, max_dirs=1024, max_datastores=1024, max_key_files=1024):
        self.dir_cache = {}
        self.dir_deadlines = {}
        self.max_dirs = max_dirs

        self.datastore_cache = {}
        self.datastore_deadlines = {}
        self.max_datastores = max_datastores

        self.key_file_cache = {}
        self.key_file_deadlines = {}
        self.max_key_files = max_key_files

        self.dir_lock = threading.Lock()
        self.datastore_lock = threading.Lock()
        self.key_file_lock = threading.Lock()


    def _put_data(self, lock, cache_obj, deadline_tbl, max_obj, key, value, ttl):
        """
        Save data to either the header cache or dir cache
        """
        deadline = int(time.time() + ttl)

        if lock:
            lock.acquire()

        cache_obj[key] = {'value': value, 'deadline': deadline, 'timestamp': time.time()}

        if not deadline_tbl.has_key(deadline):
            deadline_tbl[deadline] = []

        deadline_tbl[deadline].append(key)

        if len(cache_obj.keys()) > max_obj:
            # evict stuff
            to_evict = []
            evict_count = 0
            for deadline in sorted(deadline_tbl.keys()):
                to_evict.append(deadline)
                evict_count += len(deadline_tbl[deadline])
                if len(cache_obj.keys()) - evict_count <= max_obj:
                    break

            for deadline in to_evict:
                evicted_keys = deadline_tbl[deadline]
                del deadline_tbl[deadline]

                for key in evicted_keys:
                    del cache_obj[key]

        if lock:
            lock.release()


    def _get_data(self, lock, cache_obj, deadline_tbl, key, max_age):
        """
        Get data from either the header cache or dir cache or datastore cache
        Returns the cached object, plus the expiry time
        """
        
        with lock:
            if not cache_obj.has_key(key):
                return None, None

            res = cache_obj[key]['value']
            res_insert_time = cache_obj[key]['timestamp']
            res_deadline = cache_obj[key]['deadline']

            if time.time() >= res_deadline:
                # expired
                to_evict = []
                for deadline in sorted(deadline_tbl.keys()):
                    if time.time() <= deadline:
                        break
                    
                    to_evict.append(deadline)

                for deadline in to_evict:
                    evicted_keys = deadline_tbl[deadline]
                    del deadline_tbl[deadline]

                    for key in evicted_keys:
                        del cache_obj[key]

            if time.time() < res_deadline and res_insert_time + max_age >= time.time():
                # fresh 
                return res, res_deadline

            return None, None


    def _evict_data(self, lock, cache_obj, deadline_tbl, key):
        """
        Remove data from a cache
        """
        with lock:
            if not cache_obj.has_key(key):
                return 

            res = cache_obj[key]['value']
            res_deadline = cache_obj[key]['deadline']

            del cache_obj[key]

            if not deadline_tbl.has_key(res_deadline):
                return

            if key not in deadline_tbl[res_deadline]:
                return 

            deadline_tbl[res_deadline].remove(key)
            if len(deadline_tbl[res_deadline]) == 0:
                del deadline_tbl[res_deadline]

            return


    def put_device_root_directory(self, datastore_id, device_id, root_uuid, root_directory, ttl):
        """
        Save a device root directory
        """
        log.debug("Cache directory {}:{}.{} for up to {} seconds".format(device_id, datastore_id, root_uuid, ttl))
        return self._put_data(self.dir_lock, self.dir_cache, self.dir_deadlines, self.max_dirs, '{}:{}.{}'.format(device_id, datastore_id, root_uuid), root_directory, ttl)


    def put_datastore_record(self, datastore_id, datastore_rec, ttl):
        """
        Save a datastore record
        """
        log.debug("Cache datastore {} for up to {} seconds".format(datastore_id, ttl))
        return self._put_data(self.datastore_lock, self.datastore_cache, self.datastore_deadlines, self.max_datastores, datastore_id, datastore_rec, ttl)

    
    def put_key_file(self, blockchain_id, parsed_key_file, ttl):
        """
        Save a parsed key file
        """
        log.debug("Cache key file for {} for up to {} seconds".format(blockchain_id, ttl))
        return self._put_data(self.key_file_lock, self.key_file_cache, self.key_file_deadlines, self.max_key_files, blockchain_id, parsed_key_file, ttl)


    def get_device_root_directory(self, datastore_id, device_id, root_uuid, max_age):
        """
        Get a cached directory header
        Return None if stale or absent
        """
        res, deadline = self._get_data(self.dir_lock, self.dir_cache, self.dir_deadlines, '{}:{}.{}'.format(device_id, datastore_id, root_uuid), max_age)
        if res:
            log.debug("Cache HIT directory {}:{}.{}, expires at {} (now={})".format(device_id, datastore_id, root_uuid, deadline, time.time()))

        else:
            log.debug("Cache MISS {}".format(root_uuid))

        return res


    def get_datastore_record(self, datastore_id, max_age):
        """
        Get a cached datastore record
        Return None if stale or absent
        """
        res, deadline = self._get_data(self.datastore_lock, self.datastore_cache, self.datastore_deadlines, datastore_id, max_age)
        if res:
            log.debug("Cache HIT datastore {}, expires at {} (now={})".format(datastore_id, deadline, time.time()))
        
        else:
            log.debug("Cache MISS {}".format(datastore_id))

        return res


    def get_key_file(self, blockchain_id, max_age):
        """
        Get a cached key file
        Return None if stale or absent
        """
        res, deadline = self._get_data(self.key_file_lock, self.key_file_cache, self.key_file_deadlines, blockchain_id, max_age)
        if res:
            log.debug("Cache HIT key file for {}, expires at {} (now={})".format(blockchain_id, deadline, time.time()))

        else:
            log.debug("Cache MISS {}".format(blockchain_id))

        return res


    def evict_device_root_directory(self, datastore_id, device_id, root_uuid):
        """
        Evict a given directory
        """
        log.debug("Evict device root directory {}:{}.{}".format(device_id, datastore_id, root_uuid))
        return self._evict_data(self.dir_lock, self.dir_cache, self.dir_deadlines, '{}:{}.{}'.format(device_id, datastore_id, root_uuid))


    def evict_datastore_record(self, datastore_id):
        """
        Evict a datastore record
        """
        log.debug("Evict datastore record {}".format(datastore_id))
        return self._evict_data(self.datastore_lock, self.datastore_cache, self.datastore_deadlines, datastore_id)


    def evict_key_file(self, blockchain_id):
        """
        Evict a key file
        """
        log.debug("Evict key file for {}".format(blockchain_id))
        return self._evict_data(self.key_file_lock, self.key_file_cache, self.key_file_deadlines, blockchain_id)

    
    def evict_all(self):
        """
        Clear the entire cache
        """
        with self.dir_lock:
            self.dir_cache = {}
            self.dir_deadlines = {}

        with self.datastore_lock:
            self.datastore_cache = {}
            self.datastore_deadlines = {}

        with self.key_file_lock:
            self.key_file_cache = {}
            self.key_file_deadlines = {}


GLOBAL_CACHE = DataCache()

