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
from storage import parse_signed_data_tombstone, decode_mutable_data

log = get_logger('gaia-cache')

class DataCache(object):
    """
    Write-coherent inode and datastore data cache
    """
    def __init__(self, max_headers=1024, max_dirs=1024, max_datastores=1024):
        self.header_cache = {}
        self.header_deadlines = {}
        self.max_headers = max_headers

        self.dir_cache = {}
        self.dir_deadlines = {}
        self.dir_children = {}
        self.max_dirs = max_dirs

        self.datastore_cache = {}
        self.datastore_deadlines = {}
        self.max_datastores = max_datastores

        self.header_lock = threading.Lock()
        self.dir_lock = threading.Lock()
        self.datastore_lock = threading.Lock()


    def _put_data(self, lock, cache_obj, deadline_tbl, max_obj, key, value, ttl):
        """
        Save data to either the header cache or dir cache
        """
        deadline = int(time.time() + ttl)

        if lock:
            lock.acquire()

        cache_obj[key] = {'value': value, 'deadline': deadline}

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


    def _get_data(self, lock, cache_obj, deadline_tbl, key):
        """
        Get data from either the header cache or dir cache or datastore cache
        Returns the cached object, plus the expiry time
        """
        
        with lock:
            if not cache_obj.has_key(key):
                return None, None

            res = cache_obj[key]['value']
            res_deadline = cache_obj[key]['deadline']

            if time.time() < res_deadline:
                # fresh 
                return res, res_deadline

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


    def put_inode_header(self, datastore_id, inode_header, ttl):
        """
        Save an inode header
        """
        log.debug("Cache inode header {}".format(inode_header['uuid']))
        return self._put_data(self.header_lock, self.header_cache, self.header_deadlines, self.max_headers, '{}:{}'.format(datastore_id, inode_header['uuid']), inode_header, ttl)


    def put_inode_directory(self, datastore_id, inode_directory, ttl):
        """
        Save an inode directory
        """
        log.debug("Cache directory {} (version {})".format(inode_directory['uuid'], inode_directory['version']))

        with self.dir_lock:
            # stash directory
            self._put_data(None, self.dir_cache, self.dir_deadlines, self.max_dirs, '{}:{}'.format(datastore_id, inode_directory['uuid']), inode_directory, ttl)

            # also, map children UUID back to the parent directory so we can properly evict the parent directory
            # when we add/remove/update a file.
            for child_name in inode_directory['idata']['children'].keys():
                child_idata = inode_directory['idata']['children'][child_name]
                child_uuid = child_idata['uuid']
                self.dir_children[child_uuid] = inode_directory['uuid']


    def put_datastore_record(self, datastore_id, datastore_rec, ttl):
        """
        Save a datastore record
        """
        log.debug("Cache datastore {}".format(datastore_id))
        return self._put_data(self.datastore_lock, self.datastore_cache, self.datastore_deadlines, self.max_datastores, datastore_id, datastore_rec, ttl)


    def get_inode_header(self, datastore_id, inode_uuid):
        """
        Get a cached inode header
        Return None if stale or absent
        """
        res, deadline = self._get_data(self.header_lock, self.header_cache, self.header_deadlines, '{}:{}'.format(datastore_id, inode_uuid))
        if res:
            log.debug("Cache HIT header {}, expires at {} (now={})".format(inode_uuid, deadline, time.time()))

        else:
            log.debug("Cache MISS {}".format(inode_uuid))

        return res


    def get_inode_directory(self, datastore_id, inode_uuid):
        """
        Get a cached directory header
        Return None if stale or absent
        """
        res, deadline = self._get_data(self.dir_lock, self.dir_cache, self.dir_deadlines, '{}:{}'.format(datastore_id, inode_uuid))
        if res:
            log.debug("Cache HIT directory {}, version {}, expires at {} (now={})".format(inode_uuid, res['version'], deadline, time.time()))

        else:
            log.debug("Cache MISS {}".format(inode_uuid))

        return res


    def get_datastore_record(self, datastore_id):
        """
        Get a cached datastore record
        Return None if stale or absent
        """
        res, deadline = self._get_data(self.datastore_lock, self.datastore_cache, self.datastore_deadlines, datastore_id)
        if res:
            log.debug("Cache HIT datastore {}, expires at {} (now={})".format(datastore_id, deadline, time.time()))
        
        else:
            log.debug("Cache MISS {}".format(datastore_id))

        return res


    def evict_inode_header(self, datastore_id, inode_uuid):
        """
        Evict a given inode header
        """
        return self._evict_data(self.header_lock, self.header_cache, self.header_deadlines, '{}:{}'.format(datastore_id, inode_uuid))


    def evict_inode_directory(self, datastore_id, inode_uuid):
        """
        Evict a given directory
        """
        return self._evict_data(self.dir_lock, self.dir_cache, self.dir_deadlines, '{}:{}'.format(datastore_id, inode_uuid))


    def evict_datastore_record(self, datastore_id):
        """
        Evict a datastore record
        """
        return self._evict_data(self.datastore_lock, self.datastore_cache, self.datastore_deadlines, datastore_id)


    def evict_inode(self, datastore_id, inode_uuid):
        """
        Evict all inode state
        """
        parent_uuid = None
        with self.dir_lock:
            parent_uuid = self.dir_children.get(inode_uuid, None)

        self.evict_inode_header(datastore_id, inode_uuid)
        self.evict_inode_directory(datastore_id, inode_uuid)
        
        if parent_uuid:
            log.debug("Evict {}, parent of {}".format(parent_uuid, inode_uuid))
            self.evict_inode_header(datastore_id, parent_uuid)
            self.evict_inode_directory(datastore_id, parent_uuid)

            to_remove = []
            for (cuuid, duuid) in self.dir_children.items():
                if duuid == inode_uuid:
                    to_remove.append(cuuid)

            for cuuid in to_remove:
                del self.dir_children[cuuid]

    
    def evict_all(self):
        """
        Clear the entire cache
        """
        with self.header_lock:
            self.header_cache = {}
            self.header_deadlines = {}

        with self.dir_lock:
            self.dir_cache = {}
            self.dir_deadlines = {}

        with self.datastore_lock:
            self.datastore_cache = {}
            self.datastore_deadliens = {}


GLOBAL_CACHE = DataCache()

