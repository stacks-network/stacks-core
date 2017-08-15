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
import time
import jsontokens
import blockstack_profiles
import blockstack_zones
import urllib
import virtualchain
import posixpath
import uuid
import user as user_db
import storage
import errno
import hashlib
import jsontokens
import collections
import threading
import functools

from keylib import *

import virtualchain
from virtualchain.lib.ecdsalib import *

from keys import *
from profile import *
from proxy import *
from storage import hash_zonefile
from zonefile import get_name_zonefile, load_name_zonefile, store_name_zonefile
from utils import ScatterGather

from logger import get_logger
from config import get_config, get_local_device_id
from constants import BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, DATASTORE_SIGNING_KEY_INDEX, BLOCKSTACK_STORAGE_PROTO_VERSION, DEFAULT_DEVICE_ID
from schemas import *
from token_file import lookup_app_pubkeys

from gaia.write_log import *

log = get_logger()

MUTABLE_DATA_VERSION_LOCK = threading.Lock()

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


def serialize_mutable_data_id(data_id):
    """
    Turn a data ID into a suitable filesystem name
    """
    return urllib.quote(urllib.unquote(data_id).replace('\0', '\\0')).replace('/', r'\x2f')


def get_metadata_dir(conf, config_path=CONFIG_PATH):
    """
    Get the absolute path to the metadata directory
    """
    metadata_dir = conf.get('metadata', None)
    assert metadata_dir, "Config file is missing blockstack_client.metadata"

    if posixpath.normpath(os.path.abspath(metadata_dir)) != posixpath.normpath(conf['metadata']):
        # relative path; make absolute
        metadata_dir = posixpath.normpath( os.path.join(os.path.dirname(config_path), metadata_dir) )

    return metadata_dir


def load_mutable_data_version(conf, device_id, fq_data_id, config_path=CONFIG_PATH):
    """
    Get the version field of a piece of mutable data from local cache.
    Return the version on success
    Return None if not found
    Raise on invalid input
    """

    # try to get the current, locally-cached version
    conf = get_config(path=config_path) if conf is None else conf

    if conf is None:
        msg = 'No config found; cannot load version for "{}"'
        log.debug(msg.format(fq_data_id))
        return None

    _, data_id = storage.parse_fq_data_id(fq_data_id)
    assert data_id, "Invalid fqid {}".format(fq_data_id)

    metadata_dir = get_metadata_dir(conf)
    dev_id = serialize_mutable_data_id(device_id)
    d_id = serialize_mutable_data_id(data_id)

    ver_dir = os.path.join(metadata_dir, d_id)
    if not os.path.exists(ver_dir):
        log.debug("No version path found for {}:{}".format(device_id, fq_data_id))
        return None

    ver_path = os.path.join(ver_dir, '{}.ver'.format(dev_id))
    try:
        with open(ver_path, 'r') as f:
            ver_txt = f.read()
            return int(ver_txt.strip())

    except ValueError as ve:
        log.warn("Not an integer: {}".format(ver_path))
    except Exception as e:
        log.warn("Failed to read; {}".format(ver_path))

    return None


def store_mutable_data_version(conf, device_id, fq_data_id, ver, config_path=CONFIG_PATH):
    """
    Locally store the version of a piece of mutable data,
    so we can ensure that its version is incremented on
    subsequent puts.

    Return True if stored
    Return False if not
    Raise on invalid input
    """

    conf = get_config(path=config_path) if conf is None else conf

    if conf is None:
        msg = 'No config found; cannot store version for "{}"'
        log.warning(msg.format(fq_data_id))
        return False

    metadata_dir = get_metadata_dir(conf)

    _, data_id = storage.parse_fq_data_id(fq_data_id)
    assert data_id, "Invalid fqid {}".format(fq_data_id)

    d_id = serialize_mutable_data_id(data_id)
    dev_id = serialize_mutable_data_id(device_id)

    # serialize this 
    with MUTABLE_DATA_VERSION_LOCK:

        if not os.path.isdir(metadata_dir):
            try:
                log.debug("Make metadata directory {}".format(metadata_dir))
                os.makedirs(metadata_dir)
            except Exception, e:
                if BLOCKSTACK_DEBUG:
                    log.exception(e)

                msg = 'No metadata directory created; cannot store version of "{}"'
                log.warning(msg.format(fq_data_id))
                return False

        ver_dir = os.path.join(metadata_dir, d_id)
        if not os.path.isdir(ver_dir):
            try:
                log.debug("Make metadata directory {}".format(ver_dir))
                os.makedirs(ver_dir)
            except OSError, oe:
                if oe.errno != errno.EEXIST:
                    raise
                else:
                    pass

            except Exception, e:
                if BLOCKSTACK_DEBUG:
                    log.exception(e)

                log.warning("No metadata directory created for {}:{}".format(device_id, fq_data_id))
                return False

        ver_path = os.path.join(ver_dir, '{}.ver'.format(dev_id))
        try:
            with open(ver_path, 'w') as f:
                f.write(str(ver))

            return True

        except Exception as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            log.warn("Failed to store version of {}:{}".format(device_id, fq_data_id))
       
    return False


def delete_mutable_data_version(conf, device_id, fq_data_id, config_path=CONFIG_PATH):
    """
    Locally delete the version of a piece of mutable data.

    Return True if deleted.
    Return False if not
    Raise on invalid input
    """

    conf = get_config(path=config_path) if conf is None else conf

    if conf is None:
        msg = 'No config found; cannot delete version for "{}"'
        return False

    metadata_dir = get_metadata_dir(conf)

    if not os.path.isdir(metadata_dir):
        return True

    _, data_id = storage.parse_fq_data_id(fq_data_id)
    assert data_id, "Invalid fqid {}".format(fq_data_id)

    d_id = serialize_mutable_data_id(data_id)
    dev_id = serialize_mutable_data_id(device_id)

    with MUTABLE_DATA_VERSION_LOCK:
        ver_dir = os.path.join(metadata_dir, d_id)
        if not os.path.isdir(ver_dir):
            return True

        ver_path = os.path.join(ver_dir, '{}.ver'.format(dev_id))
        try:
            if os.path.exists(ver_path):
                os.unlink(ver_path)

        except Exception as e:
            # failed for whatever reason
            msg = 'Failed to remove version file "{}"'
            log.warn(msg.format(ver_path))

    return False


def is_obsolete_zonefile(user_zonefile):
    return (
        blockstack_profiles.is_profile_in_legacy_format(user_zonefile) or
        not user_db.is_user_zonefile(user_zonefile)
    )


def get_immutable(name, data_hash, data_id=None, config_path=CONFIG_PATH, proxy=None):
    """
    get_immutable

    Fetch a piece of immutable data.  Use @data_hash to look it up
    in the user's zonefile, and then fetch and verify the data itself
    from the configured storage providers.

    Return {'data': the data, 'hash': hash} on success
    Return {'error': ...} on failure
    """

    proxy = get_default_proxy(config_path) if proxy is None else proxy

    user_zonefile = get_name_zonefile(name, proxy=proxy)
    if 'error' in user_zonefile:
        log.debug("Unable to load zone file for '{}': {}".format(name, user_zonefile['error']))
        return user_zonefile

    user_zonefile = user_zonefile['zonefile']

    if is_obsolete_zonefile(user_zonefile):
        # zonefile is really a legacy profile
        msg = 'Zone file is in a legacy format that does not support immutable data.'
        return {'error': msg}

    if data_id is not None:
        # look up hash by name
        hs = user_db.get_immutable_data_hashes(user_zonefile, data_id)
        if hs is None:
            return {'error': 'No such immutable datum'}

        if len(hs) > 1:
            # this tool doesn't allow this to happen (one ID matches
            # one hash), but that doesn't preclude the user from doing
            # this with other tools.
            if data_hash is not None and data_hash not in hs:
                return {'error': 'Data ID/hash mismatch: {} not in {} (possibly due to invalid zonefile)'.format(data_hash, hs)}
            else:
                msg = 'Multiple matches for "{}": {}'
                return {'error': msg.format(data_id, ','.join(h))}

        h = hs[0]
        if data_hash is not None:
            if h != data_hash:
                return {'error': 'Data ID/hash mismatch: {} != {}'.format(data_hash, h)}
        else:
            data_hash = h

    elif not user_db.has_immutable_data(user_zonefile, data_hash):
        return {'error': 'No such immutable datum'}

    data_url_hint = user_db.get_immutable_data_url(user_zonefile, data_hash)

    data = storage.get_immutable_data(
        data_hash, fqu=name, data_id=data_id, data_url=data_url_hint
    )

    if data is None:
        return {'error': 'No immutable data returned'}

    return {'data': data, 'hash': data_hash}


def get_immutable_by_name(name, data_id, proxy=None):
    """
    get_immutable_by_name

    Fetch a piece of immutable data, using a human-meaningful name.
    Look up the hash in the user's zonefile, and use it to fetch
    and verify the immutable data from the configured storage providers.

    Return {'data': the data, 'hash': hash} on success
    Return {'error': ...} on failure
    """
    return get_immutable(name, None, data_id=data_id, proxy=proxy)


def list_update_history(name, current_block=None, config_path=CONFIG_PATH, proxy=None,
                        from_block=0, return_blockids=False, return_txids=False):
    """
    list_update_history

    List all zonefile hashes of a name, in historic order.
    Return a list of hashes on success.
    Return {'error': ...} on failure
    """

    proxy = get_default_proxy(config_path) if proxy is None else proxy

    if current_block is None:
        try:
            info = getinfo(proxy=proxy)
            if 'last_block_processed' in info:
                current_block = int(info['last_block_processed']) + 1
            elif 'last_block' in info:
                current_block = int(info['last_block']) + 1
            else:
                raise Exception('Invalid getinfo reply')
        except Exception as e:
            log.error('Invalid getinfo reply')
            return {'error': 'Failed to contact Blockstack server'}

    name_history = get_name_blockchain_history( name, from_block, current_block )
    if 'error' in name_history:
        log.error('Failed to get name history for {}: {}'.format(name, name_history['error']))
        return name_history

    all_update_hashes = []
    corresponding_block_ids = []
    corresponding_txids = []
    block_ids = name_history.keys()
    block_ids.sort()
    for block_id in block_ids:
        history_items = name_history[block_id]
        for history_item in history_items:
            value_hash = history_item.get('value_hash', None)
            if value_hash is None:
                continue

            if len(all_update_hashes) > 0 and all_update_hashes[-1] == value_hash:
                continue

            # changed
            all_update_hashes.append(value_hash)
            corresponding_block_ids.append(block_id)
            if return_txids:
                corresponding_txids.append(history_item.get('txid',None))

    rval = (all_update_hashes,)
    if return_blockids:
        rval += (corresponding_block_ids,)
    if return_txids:
        rval += (corresponding_txids,)
    if len(rval) == 1:
        return rval[0]
    return rval


def list_zonefile_history(name, current_block=None, proxy=None, return_hashes = False,
                          from_block=None, return_blockids=False, return_txids=False):
    """
    list_zonefile_history

    List all prior zonefiles of a name, in historic order.
    Return the list of zonefiles.  Each zonefile will be a dict with either the zonefile data,
    or a dict with only the key 'error' defined.  This method can successfully return
    some but not all zonefiles.
    """
    kwargs = {}
    if from_block:
        kwargs['from_block'] = from_block
    if return_blockids:
        kwargs['return_blockids'] = return_blockids
    if return_txids:
        kwargs['return_txids'] = return_txids

    res = list_update_history(
            name, current_block=current_block, proxy=proxy, **kwargs)
    if return_blockids or return_txids:
        zonefile_hashes = res[0]
        return_rest = res[1:]
        do_return_more = True
    else:
        zonefile_hashes = res
        do_return_more = False

    zonefiles = []
    for zh in zonefile_hashes:
        zonefile = load_name_zonefile(name, zh, raw_zonefile=True)
        if zonefile is None:
            zonefile = {'error': 'Failed to load zonefile {}'.format(zh)}
        else:
            msg = 'Invalid zonefile type {}'.format(type(zonefile))
            assert isinstance(zonefile, (str, unicode)), msg

        zonefiles.append(zonefile)

    rval = (zonefiles, )
    if return_hashes:
        rval += (zonefile_hashes,)
    if do_return_more:
        rval += tuple(return_rest)
    if len(rval) == 1:
        return rval[0]
    return rval


def list_immutable_data_history(name, data_id, current_block=None, proxy=None):
    """
    list_immutable_data_history

    List all prior hashes of an immutable datum, given its unchanging ID.
    If the zonefile at a particular update is missing, the string "missing zonefile" will be
    appended in its place.  If the zonefile did not define data_id at that time,
    the string "data not defined" will be placed in the hash's place.

    Returns the list of hashes.
    If there are multiple matches for the data ID in a zonefile, then return the list of hashes for that zonefile.
    """
    zonefiles = list_zonefile_history(name, current_block=current_block, proxy=proxy)
    hashes = []
    for zf in zonefiles:
        if zf is None:
            # not found
            hashes.append('missing zonefile')
            continue

        if isinstance(zf, dict):
            # only happens on error
            if 'error' in zf and len(zf.keys()) == 1:
                # couldn't get it
                hashes.append('missing zonefile')
                continue

        # try to parse
        try:
            zf = blockstack_zones.parse_zone_file(zf)
            zf = dict(zf)  # force dict
        except Exception as e:
            if BLOCKSTACK_TEST is not None:
                log.exception(e)

            # not a standard zonefile
            log.debug('Skip non-standard zonefile')
            hashes.append('non-standard zonefile')
            continue

        if not user_db.is_user_zonefile(zf):
            # legacy profile
            hashes.append('missing zonefile')
            continue

        data_hashes = user_db.get_immutable_data_hashes(zf, data_id)
        if data_hashes is not None:
            hashes += data_hashes
            continue

        hashes.append('data not defined')

    return hashes


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
    sig = storage.sign_data_payload(data_blob_str, data_privkey)
    return sig


def get_mutable(fq_data_id, device_ids=None, raw=False, data_pubkeys=None, data_addresses=None, data_hash=None, storage_drivers=None,
                            proxy=None, timestamp=0, force=False, urls=None, is_fq_data_id=False,
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

    log.debug("get_mutable({}, blockchain_id={}, pubkeys={}, addrs={}, hash={}, storage_drivers={})".format(
        fq_data_id, blockchain_id, data_pubkeys, data_addresses, data_hash, ','.join(storage_drivers)
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
        data_str = storage.get_mutable_data(fq_data_id, data_pubkeys, urls=urls, drivers=[driver], data_addresses=data_addresses, data_hash=data_hash, bsk_version=2, fqu=blockchain_id)
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
            log.warn("Got back an unexpected fq_data_id")
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
            log.debug("Latest timestamp of {} is now {}, vailable from {}".format(fq_data_id, data_ts, driver))
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

        'data_pubkey': data_pubkey,
        'owner_pubkey_hash': data_address,
        'drivers': mutable_drivers
    }

    return ret



def put_immutable(blockchain_id, data_id, data_text, data_url=None, txid=None, proxy=None, wallet_keys=None, config_path=CONFIG_PATH):
    """
    put_immutable

    Given a blockchain ID, the data ID, and a JSON-ified chunk of data,
    put it into the user's zonefile.

    If the user's zonefile corresponds to a legacy profile, then automatically
    convert it into a mutable profile and a modern zonefile, and then proceed
    to add the data record.

    If @txid is given, then don't re-send the NAME_UPDATE.  Just try to store
    the data to the immutable storage providers (again).  This is to allow
    for retries in the case where the NAME_UPDATE went through but the
    storage providers did not receive data.

    On success, the new zonefile will be returned.  THE CALLER SHOULD PUSH THIS NEW ZONEFILE
    TO BLOCKSTACK SERVERS ONCE THE TRANSACTION CONFIRMS.  By default, it will be enqueued
    for replication.

    Return {'status': True, 'transaction_hash': txid, 'immutable_data_hash': data_hash, 'zonefile_hash': ..., 'zonefile': {...} } on success
    Return {'error': ...} on error
    """

    from backend.nameops import async_update

    proxy = get_default_proxy(config_path) if proxy is None else proxy

    # NOTE: only accept non-legacy zone files
    user_zonefile = get_name_zonefile(blockchain_id, proxy=proxy)
    if 'error' in user_zonefile:
        log.debug("Unable to load zone file for '{}': {}".format(blockchain_id, user_zonefile['error']))
        return user_zonefile

    user_zonefile = user_zonefile['zonefile']
    data_hash = storage.get_data_hash(data_text)

    # insert into user zonefile, overwriting if need be
    if user_db.has_immutable_data_id(user_zonefile, data_id):
        log.debug('WARN: overwriting old "{}" with {}'.format(data_id, data_hash))
        old_hashes = user_db.get_immutable_data_hashes(user_zonefile, data_id)

        # NOTE: can be a list, if the name matches multiple hashes.
        # this tool doesn't do this, but it's still possible for the
        # user to use other tools to do this.
        for oh in old_hashes:
            rc = user_db.remove_immutable_data_zonefile(user_zonefile, oh)
            if not rc:
                return {'error': 'Failed to overwrite old immutable data'}

    rc = user_db.put_immutable_data_zonefile(
        user_zonefile, data_id, data_hash, data_url=data_url
    )

    if not rc:
        return {'error': 'Failed to insert immutable data into user zonefile'}

    zonefile_hash = hash_zonefile(user_zonefile)

    # update zonefile, if we haven't already
    if txid is None:
        payment_privkey_info = get_payment_privkey_info(
            wallet_keys=wallet_keys, config_path=proxy.conf['path']
        )

        owner_privkey_info = get_owner_privkey_info(
            wallet_keys=wallet_keys, config_path=proxy.conf['path']
        )

        user_zonefile_txt = blockstack_zones.make_zone_file(user_zonefile)

        update_result = async_update(
            blockchain_id, user_zonefile_txt, None, owner_privkey_info,
            payment_privkey_info, config_path=proxy.conf['path'],
            proxy=proxy, queue_path=proxy.conf['queue_path']
        )

        if 'error' in update_result:
            # failed to replicate user zonefile hash the caller should
            # simply try again, with the 'transaction_hash' given in
            # the result.
            return update_result

        txid = update_result['transaction_hash']

    result = {
        'immutable_data_hash': data_hash,
        'transaction_hash': txid,
        'zonefile_hash': zonefile_hash
    }

    # replicate immutable data
    rc = storage.put_immutable_data(data_text, txid)
    if not rc:
        result['error'] = 'Failed to store immutable data'
        return result

    rc = store_name_zonefile(blockchain_id, user_zonefile, txid)
    if not rc:
        result['error'] = 'Failed to store zonefile'
        return result

    # success!
    result['status'] = True
    result['zonefile'] = user_zonefile

    return result


def make_data_tombstones( device_ids, data_id ):
    """
    Make tombstones for mutable data across devices
    """
    ts = [storage.make_data_tombstone( storage.make_fq_data_id(device_id, data_id) ) for device_id in device_ids]
    return ts


def sign_data_tombstones( tombstones, data_privkey ):
    """
    Sign all mutable data tombstones with the given private key.
    Return the list of sigend tombstones
    """
    return [storage.sign_data_tombstone(ts, data_privkey) for ts in tombstones]


def get_device_id_from_tombstone(tombstone):
    """
    Given a signed tombstone, get the device ID
    Return the device ID string on success
    Return None on error
    """

    res = storage.parse_data_tombstone(tombstone)
    if 'error' in res:
        log.error("Failed to parse '{}'".format(tombstone))
        return None

    fq_data_id = res['tombstone_payload']
    
    device_id, data_id = storage.parse_fq_data_id(fq_data_id)
    return device_id


def verify_data_tombstones( tombstones, data_pubkey, device_ids=None ):
    """
    Verify all tombstones
    Return True if they're all signed correctly
    Return False if at least one has an invalid signature (or cannot be parsed)
    """
    ts_device_ids = []
    for ts in tombstones:
        if not storage.verify_data_tombstone(ts, data_pubkey):
            return False
       
        device_id = get_device_id_from_tombstone(ts)
        if device_id:
            ts_device_ids.append(device_id)

    if device_ids:
        # verify that all of the device IDs here are present in the tombstone information 
        # for dev_id in device_ids:
        for dev_id in [DEFAULT_DEVICE_ID]:
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
        fq_data_id = storage.make_fq_data_id(device_id, data_id)
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
    device_id, _ = storage.parse_fq_data_id(fq_data_id)
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

    storage_res = storage.put_mutable_data(fq_data_id, mutable_data_str, data_pubkey=data_pubkey, data_signature=data_signature, sign=False, raw=raw, blockchain_id=blockchain_id,
                                           required=storage_drivers, required_exclusive=storage_drivers_exclusive)

    if 'error' in storage_res:
        log.error("failed to put mutable data {}: {}".format(fq_data_id, storage_res['error']))
        result['error'] = 'Failed to store mutable data'
        return result

    return storage_res


def delete_immutable(blockchain_id, data_key, data_id=None, proxy=None, txid=None, wallet_keys=None, config_path=CONFIG_PATH):
    """
    delete_immutable

    Remove an immutable datum from a blockchain ID's zonefile, given by @data_key.
    Return a dict with {'status': True, 'zonefile_hash': ..., 'zonefile': ...} on success
    Return a dict with {'error': ...} on failure
    """

    from backend.nameops import async_update

    proxy = get_default_proxy(config_path) if proxy is None else proxy

    user_zonefile = get_name_zonefile(blockchain_id, proxy=proxy, include_name_record=True)
    if 'error' in user_zonefile:
        log.debug("Unable to load zone file for '{}': {}".format(blockchain_id, user_zonefile['error']))
        return user_zonefile

    name_record = user_zonefile['name_record']
    del user_zonefile['name_record']
    user_zonefile = user_zonefile['zonefile']

    if is_obsolete_zonefile(user_zonefile):
        # zonefile is a legacy profile.  There is no immutable data
        log.info('Profile is in legacy format.  No immutable data.')
        return {'error': 'Non-standard or legacy zonefile'}

    if data_key is None:
        if data_id is None:
            return {'error': 'No data hash or data ID given'}

        # look up the key (or list of keys) shouldn't be a
        # list--this tool prevents that--but deal with it
        # nevertheless
        data_keys = user_db.get_immutable_data_hashes(user_zonefile, data_id)
        if data_keys is not None and len(data_keys) > 1:
            msg = 'Multiple hashes for "{}": {}'
            return {'error': msg.format(data_id, ','.join(data_key))}

        data_key = data_keys[0]
        if data_key is None:
            return {'error': 'No hash for "{}"'.format(data_id)}

    # already deleted?
    if not user_db.has_immutable_data(user_zonefile, data_key):
        return {'status': True}

    # remove
    user_db.remove_immutable_data_zonefile(user_zonefile, data_key)

    zonefile_hash = hash_zonefile(user_zonefile)

    if txid is None:
        # actually send the transaction
        payment_privkey_info = get_payment_privkey_info(
            wallet_keys=wallet_keys, config_path=proxy.conf['path']
        )

        owner_privkey_info = get_owner_privkey_info(
            wallet_keys=wallet_keys, config_path=proxy.conf['path']
        )

        user_zonefile_txt = blockstack_zones.make_zone_file(user_zonefile)

        update_result = async_update(
            blockchain_id, user_zonefile_txt, None, owner_privkey_info,
            payment_privkey_info, config_path=proxy.conf['path'],
            proxy=proxy, queue_path=proxy.conf['queue_path']
        )

        if 'error' in update_result:
            # failed to remove from zonefile
            return update_result

        txid = update_result['transaction_hash']

    result = {
        'zonefile_hash': zonefile_hash,
        'zonefile': user_zonefile,
        'transaction_hash': txid
    }

    # put new zonefile
    rc = store_name_zonefile(blockchain_id, user_zonefile, txid)
    if not rc:
        result['error'] = 'Failed to put new zonefile'
        return result

    # delete immutable data
    data_privkey = get_data_privkey_info(user_zonefile, wallet_keys=wallet_keys, config_path=config_path)
    if json_is_error(data_privkey):
        return {'error': data_privkey['error']}
    else:
        assert data_privkey is not None
        assert type(data_privkey) in [str, unicode]

    rc = storage.delete_immutable_data(data_key, txid, data_privkey)
    if not rc:
        result['error'] = 'Failed to delete immutable data'
    else:
        result['status'] = True

    return result


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

    log.debug("delete_mutable({}, signed_data_tombstones={}, blockchain_id={}, storage_drivers={})".format(
        data_id, ','.join(signed_data_tombstones), blockchain_id, ','.join(storage_drivers)
    ))

    # remove the data itself
    for signed_data_tombstone in signed_data_tombstones:
        ts_data = storage.parse_signed_data_tombstone(str(signed_data_tombstone))
        assert ts_data, "Unparseable signed tombstone '{}'".format(signed_data_tombstone)

        fq_data_id = ts_data['id']
        rc = storage.delete_mutable_data(fq_data_id, signed_data_tombstone=signed_data_tombstone, required=storage_drivers, required_exclusive=storage_drivers_exclusive, blockchain_id=blockchain_id)
        if not rc:
            log.error("Failed to delete {} from storage providers".format(fq_data_id))
            worst_rc = False
            continue
    
    if not worst_rc:
        return {'error': 'Failed to delete from all storage providers'}

    return {'status': True}


def list_immutable_data(blockchain_id, proxy=None, config_path=CONFIG_PATH):
    """
    List the names and hashes of all immutable data in a user's zonefile.
    Returns {'data': [{'data_id': data_id, 'hash': hash}]} on success
    Returns {'error': ...} on error
    """
    proxy = get_default_proxy(config_path) if proxy is None else proxy

    user_zonefile = get_name_zonefile(blockchain_id, proxy=proxy)
    if 'error' in user_zonefile:
        log.debug("Unable to load zone file for '{}': {}".format(blockchain_id, user_zonefile['error']))
        return user_zonefile

    user_zonefile = user_zonefile['zonefile']

    if is_obsolete_zonefile(user_zonefile):
        # zonefile is really a legacy profile
        return {'data': []}

    names_and_hashes = user_db.list_immutable_data(user_zonefile)
    listing = [{'data_id': nh[0], 'hash': nh[1]} for nh in names_and_hashes]

    return {'data': listing}


def set_data_pubkey(blockchain_id, data_pubkey, proxy=None, wallet_keys=None, txid=None, config_path=CONFIG_PATH):
    """
    Set the data public key for a blockchain ID
    Overwrites the public key that is present (if given at all).

    WARN: you will need to re-sign your profile after you do this; otherwise
    no one will be able to use your current zonefile contents (with your new
    key) to verify their authenticity.

    Return {'status': True, 'transaction_hash': ..., 'zonefile_hash': ...} on success
    Return {'error': ...} on error
    """

    from backend.nameops import async_update

    legacy = False
    proxy = get_default_proxy(config_path) if proxy is None else proxy

    # NOTE: only accept non-legacy zone files
    user_zonefile = get_name_zonefile(blockchain_id, proxy=proxy)
    if 'error' in user_zonefile:
        log.debug("Unable to load zone file for '{}': {}".format(blockchain_id, user_zonefile['error']))
        return user_zonefile

    user_zonefile = user_zonefile['zonefile']

    user_zonefile = user_db.user_zonefile_set_data_pubkey(user_zonefile, data_pubkey)
    zonefile_hash = hash_zonefile(user_zonefile)

    # update zonefile, if we haven't already
    if txid is None:
        payment_privkey_info = get_payment_privkey_info(
            wallet_keys=wallet_keys, config_path=proxy.conf['path']
        )

        owner_privkey_info = get_owner_privkey_info(
            wallet_keys=wallet_keys, config_path=proxy.conf['path']
        )

        user_zonefile_txt = blockstack_zones.make_zone_file(user_zonefile)

        update_result = async_update(
            blockchain_id, user_zonefile_txt, None, owner_privkey_info,
            payment_privkey_info, config_path=proxy.conf['path'],
            proxy=proxy, queue_path=proxy.conf['queue_path']
        )

        if 'error' in update_result:
            # failed to replicate user zonefile hash the caller should
            # simply try again, with the 'transaction_hash' given in
            # the result.
            return update_result

        txid = update_result['transaction_hash']

    result = {
        'transaction_hash': txid,
        'zonefile_hash': zonefile_hash,
        'zonefile': user_zonefile
    }

    # replicate zonefile
    rc = store_name_zonefile(blockchain_id, user_zonefile, txid)
    if not rc:
        result['error'] = 'Failed to store zonefile'
        return result

    # success!
    result['status'] = True
    return result


def datastore_get_id( pubkey ):
    """
    Get the datastore ID
    """
    return keylib.public_key_to_address( str(pubkey) )


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


def get_datastore( blockchain_id=None, datastore_id=None, device_ids=None, full_app_name=None, config_path=CONFIG_PATH, proxy=None, no_cache=False, cache_ttl=None, parsed_token_file=None):
    """
    Get a datastore's information.
    This is a server-side method.

    There are two ways to call this method:
    * supply blockchain_id and full_app_name
    * supply datastore_id, and optionally device_ids 
    
    # TODO: move datastore ID discovery into its own method 

    Returns {'status': True, 'datastore': public datastore info}
    Returns {'error': ..., 'errno':...} on failure
    """
    
    global GLOBAL_CACHE

    assert (blockchain_id and full_app_name) or (datastore_id), "Need either datastore_id or both blockchain_id and full_app_name"
    
    if proxy is None:
        proxy = get_default_proxy(config_path)

    if cache_ttl is None:
        conf = get_config(config_path)
        assert conf
        cache_ttl = int(conf.get('cache_ttl', 3600))    # 1 hour

    # find out which keys and addresses to use
    datastore_addresses = []
    data_ids = []

    # prefer token-file path over direct datastore query
    if blockchain_id and full_app_name:

        # multi-reader single-writer storage 
        if parsed_token_file is None:
            res = token_file_get(blockchain_id, proxy=proxy)
            if 'error' in res:
                res['errno'] = errno.EINVAL
                return res

            parsed_token_file = res['token_file']

        # datastore record may have been written by one of any of the devices.
        # select the *oldest* record
        res = lookup_app_pubkeys(blockchain_id, full_app_name, proxy=proxy, parsed_token_file=parsed_token_file)
        if 'error' in res:
            res['errno'] = errno.EINVAL
            return res

        pubkeys = res['pubkeys']
        if device_ids is None:
            device_ids = pubkeys.keys()
        
        found_device_ids = []

        for dev_id in device_ids:
            if not pubkeys.has_key(dev_id):
                log.warning("No public key for device '{}'".format(dev_id))
                continue
            
            if pubkeys[dev_id] is None:
                log.warning("Skipping device '{}', since it has 'None' public key")
                continue

            found_device_ids.append(dev_id)
            datastore_addresses.append(datastore_get_id(pubkeys[dev_id]))

        device_ids = found_device_ids
        data_ids = ['{}.datastore'.format(da) for da in datastore_addresses]

    else:
        # single-reader single-writer storage.  do not rely on blockchain ID
        datastore_addresses = [datastore_id]
        data_ids = ['{}.datastore'.format(datastore_id)]

        if not device_ids:
            device_ids = []
    
    datastore_records = {}
    datastore_timestamps = {}
    
    log.debug("Search {} possible datastore record candidate(s)".format(len(data_ids)))

    for (data_id, device_id, data_address) in zip(data_ids, device_ids, datastore_addresses):
        datastore_id = data_id[0:-len('.datastore')]
        datastore = None
        datastore_timestamp = None

        if not no_cache:
            res = GLOBAL_CACHE.get_datastore_record(datastore_id)
            if res:
                datastore = res['datastore']
                datastore_timestamp = res['timestamp']

        if not datastore:
            # cache miss
            # fq_data_id = storage.make_fq_data_id(device_id, data_id)
            fq_data_id = storage.make_fq_data_id(DEFAULT_DEVICE_ID, data_id)
            datastore_info = get_mutable(fq_data_id, device_ids=device_ids, blockchain_id=blockchain_id, data_addresses=datastore_addresses, proxy=proxy, config_path=config_path)
            if 'error' in datastore_info:
                if 'notfound' in datastore_info or 'stale' in datastore_info:
                    # absent. Store a negative
                    log.debug("Not found: {}".format(data_id))
                    if not no_cache:
                        log.debug("Absent or stale datastore record {}".format(data_id))
                        GLOBAL_CACHE.put_datastore_record(datastore_id, None, cache_ttl)
                        continue
                
                else:
                    log.error("Failed to load public datastore information: {}".format(datastore_info['error']))
                    return {'error': 'Failed to load public datastore record', 'errno': errno.ENOENT}

            datastore_str = datastore_info['data']
            datastore_timestamp = datastore_info['timestamp']

            try:
                datastore = data_blob_parse(datastore_str)
                jsonschema.validate(datastore, DATASTORE_SCHEMA) 
            except (AssertionError, ValidationError) as ve:
                if BLOCKSTACK_DEBUG:
                    log.exception(ve)
        
                log.error("Invalid datastore record")
                return {'error': 'Invalid public datastore record', 'errno': errno.EIO}
        
        datastore_records[data_id] = datastore
        datastore_timestamps[data_id] = datastore_timestamp

        # cache, even if we don't use it
        if not no_cache:
            cache_rec = {'datastore': datastore, 'timestamp': datastore_timestamp}
            GLOBAL_CACHE.put_datastore_record(datastore_id, cache_rec, cache_ttl)

    if len(datastore_records) == 0:
        # no datastore record found 
        return {'error': 'No datastore records found', 'errno': errno.ENOENT}

    # select the *oldest* record, since it was the first one written
    oldest_datastore = None
    oldest_timestamp = None
    for data_id in datastore_records.keys():
        timestamp = datastore_timestamps[data_id]
        if oldest_timestamp is None or timestamp < oldest_timestamp:
            oldest_datastore = datastore_records[data_id]
            oldest_timestamp = timestamp

    return {'status': True, 'datastore': oldest_datastore}


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
    root_dir = {
        'proto_version': 2,
        'type': ROOT_DIRECTORY_PARENT,
        'owner': datastore_id,
        'readers': [keylib.public_key_to_address(rpk) for rpk in reader_pubkeys],
        'timestamp': timestamp,
        'files': {}
    }
    
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
   
    @datastore_pubkey_hex is the app-specific public key for this device.  It must be one of the public keys in the creator's token file.

    Return {'datastore_blob': public datastore information, 'root_blob_header': root inode header, 'root_blob_idata': root inode data}
    Return {'error': ...} on failure
    """
    if driver_names is None:
        driver_handlers = storage.get_storage_handlers()
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

    return {'datastore_blob': datastore_info_str, 'root_blob': root_blob}


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
    
    root_sig = storage.sign_data_payload( datastore_info['root_blob'], datastore_privkey_hex )
    datastore_sig = storage.sign_data_payload( datastore_info['datastore_blob'], datastore_privkey_hex )

    root_id = '{}.{}'.format(datastore_id, root_uuid)
    root_tombstones = make_data_tombstones( datastore['device_ids'], root_uuid )
    signed_tombstones = sign_mutable_data_tombstones( root_tombstones, datastore_privkey_hex )

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

    res = storage.verify_data_payload( datastore_info['datastore_blob'], datastore_pubkey_hex, sigs['datastore_sig'] )
    if not res:
        log.debug("Failed to verify datastore blob payload with {} and {}".format(datastore_pubkey_hex, sigs['datastore_sig']))
        if BLOCKSTACK_TEST:
            log.debug("datastore_info: {}".format(json.dumps(datastore_info)))

        return False

    res = storage.verify_data_payload( datastore_info['root_blob'], datastore_pubkey_hex, sigs['root_sig'] )
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
        datastore_dev_id, datastore_data_id = storage.parse_fq_data_id(datastore_fqid)
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
    res = put_device_root_data(datastore_id, datastore_dev_id, datastore['root_uuid'], datastore['pubkey'], datastore_info['root_sig'], datastore['drivers'], config_path=config_path, proxy=proxy, blockchain_id=blockchain_id)
    if 'error' in res:
        log.error("Failed to store root directory info for {}".format(datastore_id))
        return {'error': res['error'], 'errno': errno.EREMOTEIO}

    root_urls = res['urls']

    # store datastore
    res = put_mutable(datastore_fqid, datastore_info['datastore_blob'], datastore['pubkey'], datastore_sigs['datastore_sig'],
                      blockchain_id=blockchain_id, storage_drivers=datastore['drivers'], storage_drivers_exclusive=True, config_path=config_path)
    if 'error' in res:
        log.error("Failed to store datastore record for {}".format(datastore_id))

        # attempt clean up 
        cleanup_res = _delete_raw_data([datastore['root_tombstone']], datastore['drivers'], config_path=config_path, blockchain_id=blockchain_id)
        if 'error' in cleanup_res:
            return {'error': 'Failed to clean up from partial datastore creation.  "urls" contains URLs to leaked root directory copies.', 'urls': root_urls}
        else:
            return {'error': res['error'], 'errno': errno.EREMOTEIO}

    # success
    return res


def delete_datastore_info( datastore_id, datastore_tombstones, root_tombstones, data_pubkeys, blockchain_id=None, force=False, proxy=None, config_path=CONFIG_PATH ):
    """
    Delete a datastore.  Only do so if its root directory is empty (unless force=True).
    This is a server-side method.

    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)
   
    device_ids = [dk['device_id'] for dk in data_pubkeys]

    # get the datastore first
    datastore_info = get_datastore(blockchain_id=blockchain_id, datastore_id=datastore_id, device_ids=device_ids, config_path=config_path, proxy=proxy, no_cache=True )
    if 'error' in datastore_info:
        log.error("Failed to look up datastore information for {}".format(datastore_id))
        return {'error': 'Failed to look up datastore', 'errno': errno.ENOENT}
    
    datastore = datastore_info['datastore']
    root_uuid = datastore['root_uuid']
    drivers = datastore['drivers']

    # get root directory
    res = get_root_directory(datastore_id, root_uuid, drivers, data_pubkeys, timestamp=0, force=force, config_path=config_path, proxy=proxy, blockchain_id=blockchain_id)
    if 'error' in res:
        if not force:
            log.error("Failed to get root directory")
            return {'error': 'Failed to check if datastore is empty', 'errno': errno.EREMOTEIO}
        else:
            log.warn("Failed to get root directory, but forced to remove it anyway")
    
    if not force and len(res['files']) != 0:
        log.error("Datastore {} not empty (has {} files)".format(datastore_id, len(res['files'])))
        return {'error': 'Datastore not empty', 'errno': errno.ENOTEMPTY}

    res = delete_mutable(datastore_tombstones, storage_drivers=drivers, storage_drivers_exclusive=True, proxy=proxy, config_path=config_path )
    if 'error' in res:
        log.error("Failed to delete datastore {}".format(datastore_id))
        return {'error': 'Failed to delete datastore', 'errno': errno.EREMOTEIO}
    
    res = delete_mutable(root_tombstones, storage_drivers=drivers, storage_drivers_exclusive=True, proxy=proxy, config_path=config_path)
    if 'error' in res:
        log.error("Failed to delete root of {}".format(datastore_id))
        return {'error': 'Failed to delete root directory', 'errno': errno.EREMOTEIO}

    return {'status': True}


def put_datastore(api_client, datastore_info, datastore_privkey, config_path=CONFIG_PATH):
    """
    Given datastore information from make_datastore_info(), sign and put it.
    This is a client-side method

    Return {'status': True} on success
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

    return {'status': True}


def delete_datastore(api_client, datastore, datastore_privkey, data_pubkeys, config_path=CONFIG_PATH):
    """
    Delete a datastore.

    Client-side method

    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    datastore_pubkey = get_pubkey_hex(datastore_privkey)
    datastore_id = datastore_get_id(datastore_pubkey)

    tombstones = make_data_tombstones( device_ids, '{}.datastore'.format(datastore_id) )
    signed_tombstones = sign_mutable_data_tombstones(tombstones, datastore_privkey )

    # delete root as well
    root_id = '{}.{}'.format(datastore_id, root_uuid)
    root_tombstones = make_data_tombstones( datastore['device_ids'], root_id )
    signed_root_tombstones = sign_mutable_data_tombstones( root_tombstones, datastore_privkey )

    res = api_client.backend_datastore_delete(datastore_id, signed_tombstones, signed_root_tombstones, data_pubkeys ) 
    if 'error' in res:
        return res

    return {'status': True}


def get_mutable_data_version( data_id, device_ids, config_path=CONFIG_PATH ):
    """
    Get the mutable data version for a datum spread across multiple devices
    Return {'status': True, 'version': version} on success
    """
    new_version = 0
    conf = get_config(config_path)
    assert conf

    for device_id in device_ids:
        fq_data_id = storage.make_fq_data_id(device_id, data_id)
        cur_ver = load_mutable_data_version(conf, device_id, fq_data_id, config_path=config_path)
        if cur_ver is not None:
            new_version = max(new_version, cur_ver)

    return {'status': True, 'version': new_version}


def put_mutable_data_version( data_id, new_version, device_ids, config_path=CONFIG_PATH ):
    """
    Advance all versions of a mutable datum to at least new_version
    Return {'status': True, 'version': new version} on success
    Return {'error': ...} on error
    """

    # advance header version and inode version
    conf = get_config(config_path)
    assert conf

    res = get_mutable_data_version(data_id, device_ids, config_path=CONFIG_PATH)
    new_version = max(res['version'], new_version)

    for device_id in device_ids:
        fq_data_id = storage.make_fq_data_id(device_id, data_id)
        rc = store_mutable_data_version(conf, device_id, fq_data_id, new_version, config_path=config_path)
        if not rc:
            return {'error': 'Failed to advance mutable data version {} to {}'.format(data_id, new_version), 'errno': errno.EIO}

    return {'status': True, 'version': new_version}


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
        for tombstone in root['tombstones']:
            ts_data = storage.parse_data_tombstone(tombstone)
            if not ts_data:
                log.warning("Invalid tombstone")
                continue

            # format: datastore/file_name
            fq_file_name = ts_data['id']
            fq_match = re.match('^({})/({})$'.format(OP_DATASTORE_ID_CLASS, OP_URLENCODED_CHARS), fq_file_name)
            if not fq_match:
                log.warning("Invalid file name '{}'".format(fq_file_name))
                continue
            
            file_name = fq_match.groups()[1]
            if merged_files.has_key(file_name):
                if merged_files[file_name]['timestamp'] < ts_data['timestamp']:
                    # this file was deleted
                    del merged_files[file_name]

    return {'status': True, 'files': merged_files}


def get_device_root_directory( datastore_id, root_inode_uuid, drivers, device_id, device_pubkey, timestamp=0, force=False, config_path=CONFIG_PATH, blockchain_id=None):
    """
    Get the root directory for a specific device in a datastore.
    This is a server-side method

    Return {'status': True, 'device_root_page': {...}} on success
    Return {'error': ..., 'errno': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    conf = get_config(config_path)
    assert conf

    data_id = '{}.{}'.format(datastore_id, root_inode_uuid)
    
    errcode = 0
    for driver in drivers:
        fq_data_id = storage.make_fq_data_id(device_id, data_id)
        res = get_mutable(fq_data_id, device_ids=[device_id], blockchain_id=blockchain_id, timestamp=timestamp, force=force, data_pubkeys=[device_pubkey], storage_drivers=[driver], proxy=proxy, config_path=config_path)
        if 'error' in res:
            log.error("Failed to get inode data {} (stale={}): {}".format(root_inode_uuid, res.get('stale', False), res['error']))
            errcode = errno.EREMOTEIO
            if res.get('stale'):
                errcode = errno.ESTALE

            continue

        else:
            # success!
            try:
                root_page = json.loads(res['data'])
            except:
                log.error("Invalid root data from {}: not JSON".format(fq_data_id))

                if errcode == 0:
                    errcode = errno.EIO

                continue

            try:
                jsonschema.validate(root_page, ROOT_DIRECTORY_SCHEMA)
            except:
                log.error("Invalid root data from {}: not a root directory".formt(fq_data_id))
                
                if errcode == 0:
                    errcode = errno.EIO

                continue

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
        res = lookup_app_pubkeys(blockchain_id, full_app_name, proxy=proxy)
        if 'error' in res:
            res['errno'] = errno.EINVAL
            return res
        
        data_pubkeys = [{'device_id': dev_id, 'public_key': res['pubkeys'][dev_id]} for dev_id in data_pubkeys.keys()]

    data_id = '{}.{}'.format(datastore_id, root_uuid)

    # optimization: try local drivers before non-local drivers
    drivers = prioritize_read_drivers(config_path, drivers)

    sg = ScatterGather()
    for data_pubkey_info in data_pubkeys:
        device_id = data_pubkey_info['device_id']
        data_pubkey = data_pubkey_info['device_pubkey']
        task_id = 'fetch_root_{}'.format(device_id)

        fetch_root_directory = functools.partial(get_device_root_directory, datastore_id, root_uuid, drivers, device_id, device_pubkey, timestamp=timestamp, force=force, config_path=config_path, blockchain_id=blockchain_id)
        sg.add_task(task_id, fetch_root_directory)

    sg.run_tasks()
    roots = {}

    for data_pubkey_info in data_pubkeys:
        device_id = data_pubkey_info['device_id']
        data_pubkey = data_pubkey_info['device_pubkey']
        task_id = 'fetch_root_{}'.format(device_id)

        result = sg.get_result(task_id)
        if 'error' in result:
            log.error("Failed to fetch root from {}".format(device_id))
            return result

        root_dir = result['device_root_page']
        if root_dir['type'] != ROOT_DIRECTORY_LEAF:
            return {'error': 'Segmented root directories are not yet supported'}
        
        roots[device_id] = root_dir

    # merge root directories
    merged = _merge_root_directories(roots.values())
    return {'status': True, 'root': merged, 'device_root_pages': roots}


def get_file_data_from_header(datastore_id, file_header, drivers, config_path=CONFIG_PATH, blockchain_id=blockchain_id):
    """
    Get file data from a header

    This is a server-side method

    Return {'status': True, 'data': the actual data}
    return {'error': ..., 'errno': ...} on error
    """

    urls = file_header['urls']
    data_hash = file_header['data_hash']

    # optimization: try local drivers before non-local drivers
    drivers = prioritize_read_drivers(config_path, drivers)

    # go get it 
    # NOTE: fq_file_name isn't needed since we have URLs, but include it anyway for logging's sake.
    fq_file_name = '{}/{}'.format(datastore_id, file_name)
    file_data = storage.get_mutable_data(fq_file_name, None, urls=urls, data_hash=data_hash, blockchain_id=blockchain_id, drivers=drivers, decode=False)
    if file_data is None:
        return {'error': 'Failed to load {}', 'errno': errno.ENODATA}
    
    return {'status': True, 'data': file_data}


def get_file_data(datastore, file_name, data_pubkeys, force=False, timestamp=0, config_path=CONFIG_PATH, proxy=None, blockchain_id=None): 
    """
    Get file data

    This is a server-side method.

    NOTE: @blockchain_id is not required; it's fed into the drivers as a hint.

    Return {'status': True, 'data': the actual data}
    Return {'error': ..., 'errno': ...} on error
    """
    
    file_info = get_file_info(datastore, file_name, data_pubkeys, "", force=force, timestamp=timestamp, config_path=config_path, proxy=proxy, blockchain_id=blockchain_id)
    if 'error' in file_info:
        return file_info

    datastore_id = datastore_get_id(datastore['pubkey'])
    file_header = file_info['file_header']
    return get_file_data_from_header(datastore_id, file_header, datastore['drivers'], config_path=config_path, blockchain_id=blockchain_id)


def get_file_info( datastore, file_name, data_pubkeys, this_device_id, force=False, timestamp=0, config_path=CONFIG_PATH, proxy=None, blockchain_id=None ):
    """
    Look up all the inodes along the given fully-qualified path, verifying them and ensuring that they're fresh along the way.

    This is a server-side method.
    
    Return {'status': True, 'device_root_page': device_root_dir, 'file_info': header}
    Return {'error': ..., 'errno': ...} on error
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    datastore_id = datastore_get_id(datastore['pubkey'])
    drivers = datastore['drivers']

    log.debug("Lookup {}:{} (idata: {})".format(datastore_id, file_name, get_idata))

    # fetch all device-specific versions of this directory
    # TODO: this will need to be refactored when we have a segmented root directory
    res = get_root_directory(datastore_id, datastore['root_uuid'], drivers, data_pubkeys, timestamp=timestamp, force=force, config_path=config_path, proxy=proxy, blockchain_id=blockchain_id)
    if 'error' in res:
        log.error("Failed to get root directory for datastore {}".format(datastore_id))
        return res

    # NOTE: this is possibly None
    device_root = res['device_root_pages'].get(this_device_id)

    # find the file header
    root_files = res['root']
    if file_name not in root_files.keys():
        log.error("Not found: {}".format(file_name))
        return {'error': 'No such file: {}'.format(file_name)}

    file_header = root_files[file_name]
    ret = {
        'status': True,
        'file_info': file_header,
        'device_root_page': device_root
    }

    return ret


def _put_raw_data( fq_data_id, data_bytes, drivers, config_path=CONFIG_PATH, blockchain_id=None, data_pubkey=None, data_signature=None ):
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
            return {'error': 'Failed to replicate data to {}'.format(driver), 'errno': errno.EREMOTEIO}

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
        return {'error': 'Some drivers failed to replicate data: {}'.format(','.join(errors)), 'errno': errno.EREMOTEIO}

    return {'status': True, 'urls': urls}


def _delete_raw_data( signed_tombstones, drivers, config_path=CONFIG_PATH, blockchain_id=None, proxy=None ):
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
        return {'error': 'Some drivers failed to delete data: {}'.format(','.join(errors)), 'errno': errno.EREMOTEIO}

    return {'status': True}


def put_file_data(datastore_id, device_id, file_name, file_bytes, drivers, config_path=CONFIG_PATH, blockchain_id=None):
    """
    Store file data to a set of drivers.
    
    This is a server-side method

    Return {'status': True, 'urls': [...]} on success
    Return {'error': ...} on failure
    """

    fq_data_id = storage.make_fq_data_id(device_id, '{}/{}'.format(datastore_id, file_name))
    res = _put_raw_data(fq_data_id, file_bytes, drivers, config_path=config_path, blockchain_id=blockchain_id)
    return res


def put_device_root_data(datastore_id, device_id, root_uuid, directory_blob, directory_pubkey, directory_signature, drivers, config_path=CONFIG_PATH, blockchain_id=None):
    """
    Store device-specific root directory data to a set of drivers.

    This is a server-side method.

    Return {'status': True, 'urls': [...]} on success
    Return {'error': ...} on failure
    """

    fq_data_id = storage.make_fq_data_id(device_id, '{}.{}'.format(datastore_id, root_uuid))
    res = _put_raw_data(fq_data_id, signed_directory_blob, drivers, config_path=config_path, blockchain_id=blockchain_id, data_pubkey=directory_pubkey, data_signature=directory_signature)
    return res


def verify_file_data(full_app_name, datastore, file_name, file_header_blob, payload, signature, device_id, blockchain_id=None, data_pubkey=None, config_path=CONFIG_PATH, proxy=None):
    """
    Server-side method to verify the authenticity and integrity of file data
    
    This is a server-side method

    Returns {'status': True} if valid
    Returns {'error': ..., 'errno': ...} if invalid
    """
    
    assert data_pubkey or (blockchain_id and full_app_name), 'Need either blockchain_id and full_app_name, or data_pubkey'
    if data_pubkey is None:
        # look up from token file
        res = lookup_app_pubkeys(blockchain_id, full_app_name, proxy=proxy)
        if 'error' in res:
            res['errno'] = errno.EINVAL
            return res
         
        data_pubkey = res['pubkeys'].get(device_id, None)
        if data_pubkey is None:
            return {'error': 'Unknown device {}'.format(device_id)}

    # must be signed by the device's public key
    try:
        res = storage.verify_data_payload( file_header_blob, data_pubkey, signature )
    except AssertionError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Invalid public key or signature ({}, {})".format(data_pubkey, signature))
        return {'error': 'failed to verify file data: invalid public key or signature', 'errno': errno.EINVAL}

    if not res:
        log.error("Failed to verify {} ({}) with {}".format(header_blob, signature, datas_pubkey))
        return {'error': 'failed to verify file data: bad signature', 'errno': errno.EINVAL}

    # check payload hash 
    payload_hash = storage.hash_data_payload(payload)
    header_mutable_data_struct = data_blob_parse(file_header_blob)

    # must be a valid mutable data blob 
    try:
        jsonschema.validate(header_mutable_data_struct, DATA_BLOB_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Invalid data blob")
        return {'error': 'invalid file header container (schema mismatch)', 'errno': errno.EINVAL}

    # must be a valid header
    header_struct = data_blob_parse(header_mutable_data_struct['data'])
    try:
        jsonschema.validate(header_struct, ROOT_DIRECTORY_ENTRY_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Invalid header struct")
        return {'error': 'invalid file header structure (schema mismatch)', 'errno': errno.EINVAL}

    # payload must match header
    if payload_hash != header_struct['data_hash']:
        log.error("Payload hash mismatch: {} != {}".format(payload_hash, header_struct['data_hash']))
        return {'error': "Payload {} does not match file header {}".format(payload_hash, header_struct['data_hash']), 'errno': errno.EINVAL}

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
        # look up from token file
        res = lookup_app_pubkeys(blockchain_id, full_app_name, proxy=proxy)
        if 'error' in res:
            res['errno'] = errno.EINVAL
            return res
         
        data_pubkey = res['pubkeys'].get(device_id, None)
        if data_pubkey is None:
            return {'error': 'Unknown device {}'.format(device_id)}

    # must be signed by the device's public key
    try:
        res = storage.verify_data_payload( root_data_blob, data_pubkey, signature )
    except AssertionError as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("failed to verify root directory page: invalid public key or signature ({}, {})".format(data_pubkey, signature))
        return {'error': 'Invalid public key or signature', 'errno': errno.EINVAL}

    if not res:
        log.error("Failed to verify {} ({}) with {}".format(header_blob, signature, datas_pubkey))
        return {'error': 'failed to verify root directory page: bad signature', 'errno': errno.EINVAL}

    # must be a valid blob 
    device_root_blob = data_blob_parse(root_data_blob)
    try:
        jsonschema.validate(device_root_blob, DATA_BLOB_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Invalid data blob")
        return {'error': 'invalid file header container (schema mismatch)', 'errno': errno.EINVAL}

    # must be a valid root directory
    device_root = data_blob_parse(device_root_blob['data'])
    try:
        jsonschema.validate(device_root, ROOT_DIRECTORY_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Invalid root directory page struct")
        return {'error': 'invalid root directory page structure (schema mismatch)', 'errno': errno.EINVAL}
    
    # root must not be stale 
    datastore_id = datastore_get_id(datastore['pubkey'])
    root_data_id = '{}.{}'.format(datastore_id, datastore['root_uuid'])
    res = get_mutable_data_version(root_data_id, datastore['device_ids'], config_path=config_path)
    if res['version'] > device_root['timestamp']:
        log.error("Stale data for root {}: expected version >= {}, got {}".format(root_id, device_root['timestamp'], res['version']))
        return {'error': 'Device root is stale.  Last version seen: {}'.format(res['version']), 'errno': errno.ESTALE}

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

        # get from token file
        res = lookup_app_pubkeys(blockchain_id, full_app_name, proxy=proxy)
        if 'error' in res:
            res['errno'] = errno.EINVAL
            return res
        
        data_pubkeys = [{'device_id': dev_id, 'public_key': res['pubkeys'][dev_id]} for dev_id in data_pubkeys.keys()]

    return get_file_data(datastore, file_name, data_pubkeys, force=force, timestamp=0, config_path=CONFIG_PATH, blockchain_id=blockchain_id)


def datastore_get_device_root(full_app_name, datastore, device_id, data_pubkey=None, force=False, timestamp=0, config_path=COFNIG_PATH, blockchain_id=None, proxy=None):
    """
    Get a device's root page from the datastore.  Entry point from the API server.

    This is a server-side method

    Return {'status': True, 'device_root_page': ...} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    assert blockchain_id or data_pubkey, 'Need either blockchain_id or data_pubkey'

    if data_pubkey is None:
        # get from token file
        res = lookup_app_pubkeys(blockchain_id, full_app_name, proxy=proxy)
        if 'error' in res:
            res['errno'] = errno.EINVAL
            return res

        data_pubkey = res['pubkeys'].get(device_id, None)
        if not data_pubkey:
            return {'error': 'Unknown device ID', 'errno': errno.EINVAL}

    datastore_id = datastore_get_id(datastore['pubkey'])
    return get_device_root_directory(datastore_id, datastore['root_uuid'], datastore['drivers'], device_id, data_pubkey, timestamp=timestamp, force=force, config_path=config_path, blockchain_id=blockchain_id)


def datastore_put_file_data(full_app_name, datastore_str, datastore_sig, file_name, file_header_blob, payload, signature, device_id, blockchain_id=None, data_pubkey=None, config_path=CONFIG_PATH):
    """
    Store file data.  Entry point from the API server.

    This is a server-side method

    Return {'status': True, 'urls': [...]} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    
    if data_pubkey is None:
        assert blockchain_id and full_app_name, 'Need both full_app_name and blockchain_id if data_pubkey is not given'

        # get from token file
        res = lookup_app_pubkeys(blockchain_id, full_app_name, proxy=proxy)
        if 'error' in res:
            res['errno'] = errno.EINVAL
            return res

        data_pubkey = res['pubkeys'].get(device_id, None)
        if not data_pubkey:
            return {'error': 'Unknown device ID', 'errno': errno.EINVAL}

    # must be authentic datastore
    res = datastore_verify_and_parse(datastore_str, datastore_sig, data_pubkey)
    if 'error' in res:
        return res

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


def datastore_put_device_root_data(datastore, device_root_page_blob, signature, device_id, full_app_name=None, blockchain_id=None, data_pubkey=None, config_path=CONFIG_PATH, synchronous=False):
    """
    Store device root directory data.  Entry point from the API server.

    This is a server-side method

    Return {'status': True, 'urls': [...]} on success
    Return {'error': ..., 'errno': ...} on failure
    """

    # must be well-formed and authentic 
    res = verify_root_data(datastore, device_root_page_blob, signature, device_id, full_app_name=full_app_name, blockchain_id=blockchain_id, data_pubkey=data_pubkey, config_path=config_path)
    if 'error' in res:
        return res

    datastore_id = datastore_get_id(datastore['pubkey'])
    pubkey = res['data_pubkey']
    root_urls = None

    signed_device_root_page_blob = storage.serialize_mutable_data(device_root_page_blob, data_signature=signature, data_pubkey=data_pubkey)
    
    # queue for replication, if not synchronous.
    # otherwise, replicate right now.
    if synchronous:
        # replicate
        res = write_log_page_replicate(signed_device_root_page_blob, datastore['drivers'], blockchain_id, config_path=config_path, proxy=proxy)
        if 'error' in res:
            log.error("Failed to replicate signed root page for {}.{}".format(datastore_id, root_uuid))
            return {'error': res['error'], 'errno': errno.EREMOTEIO}

        root_urls = res['urls']

    else:
        # queue for later replication 
        res = write_log_enqueue(datastore_id, device_id, datastore['root_uuid'], signed_device_root_page_blob, datastore['drivers'], blockchain_id=blockchain_id, config_path=config_path)
        if 'error' in res:
            log.error("Failed to enqueue {}.{} for replication (on putfile {})".format(datastore_id, root_uuid))
            return {'error': res['error'], 'errno': errno.EIO}

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
        # get from token file
        res = lookup_app_pubkeys(blockchain_id, full_app_name, proxy=proxy)
        if 'error' in res:
            res['errno'] = errno.EINVAL
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
            return {'error': 'Invalid tombstone', 'errno': errno.EINVAL}

    # delete it
    res = _delete_raw_data(signed_tombstones, datastore['drivers'], config_path=config_path, blockchain_id=blockchain_id, proxy=proxy)
    if 'error' in res:
        res['errno'] = errno.EREMOTEIO
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
            res = storage.verify_data_payload( header_blob, datastore_pubkey, signature )
        except AssertionError as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            log.error("Invalid public key or signature ({}, {})".format(datastore_pubkey, signature))
            return {'error': 'Invalid public key or signature', 'errno': errno.EINVAL}

        if not res:
            log.debug("Failed to verify {} ({}) with {}".format(header_blob, signature, datastore_pubkey))
            return {'error': 'Failed to verify signature', 'errno': errno.EINVAL}

        # check hash 
        payload_hash = storage.hash_data_payload(payload)
        header_mutable_data_struct = data_blob_parse(header_blob)
        header_struct = data_blob_parse(header_mutable_data_struct['data'])
        if payload_hash != header_struct['data_hash']:
            log.debug("Payload hash mismatch: {} != {}".format(payload_hash, header_struct['data_hash']))
            return {'error': "Payload {} does not match file header {}".format(payload_hash, header_struct['data_hash']), 'errno': errno.EINVAL}

    if len(tombstones) > 0:
        res = verify_mutable_data_tombstones( tombstones, datastore_pubkey, device_ids=device_ids )
        if not res:
            return {'error': 'Failed to verify data tombstones', 'errno': errno.EINVAL}

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


def datastore_getfile(api_client, blockchain_id, datastore, data_path, data_pubkeys, timestamp=0, force=False, config_path=CONFIG_PATH ):
    """
    Get a file identified by a path.

    Return {'status': True, 'data': data} on success, if not extended
    Return {'status': True, 'inode_info': inode and data, 'path_info': path info}
    Return {'error': ..., 'errno': ...} on error
    """

    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    
    datastore_id = datastore_get_id(datastore['pubkey'])
    drivers = datastore['drivers']
    
    log.debug("getfile {}:{}".format(datastore_id, data_path))
    
    file_info = api_client.backend_datastore_getfile(blockchain_id, datastore, data_path, data_pubkeys, timestamp=timestamp, force=force)
    if 'error' in file_info:
        log.error("Failed to get data for {}".format(data_path))
        return file_info
    
    return file_info


def datastore_make_file_entry(data_hash, data_urls):
    """
    Make a root file entry
    Return {'status': True, 'file_entry': file_entry} on success
    Return {'error': ...} otherwise
    """ 
    # must be valid data
    file_entry = {
        'proto_version': 2,
        'urls': urls,
        'data_hash': data_hash,
        'timestamp': int(time.time() * 1000),
    }

    try:
        jsonschema.validate(file_entry, ROOT_DIRECTORY_ENTRY_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        return {'error': 'Invalid file data', 'errno': errno.EINVAL}

    return {'status': True, 'file_entry': file_entry}


def _find_device_root( api_client, datastore, file_name, data_pubkeys, this_device_id, create, root=None, device_root=None, timestamp=0, force=False, config_path=CONFIG_PATH, blockchain_id=None ):
    """
    Helper method; do not use externally.

    For putfile's and deletefile's purposes, get the device root.
    Honor the putfile's request to create, and use any pre-calculated roots and device roots.

    Return {'status': True, 'device_root': ...} on success
    Return {'error': ..., 'errno'} on failure
    """

    datastore_id = datastore_get_id(datastore['pubkey'])
    root_uuid = datastore['root_uuid']
    drivers = datastore['drivers']
    
    if proxy is None:
        proxy = get_default_proxy(config_path)

    if create:
        # must have whole root
        if root is None:
            res = api_client.backend_datastore_get_root(blockchain_id, datastore, data_pubkeys, timestamp=timestamp, force=force)
            if 'error' in res:
                log.error("Failed to get root directory {}/{}: {}".format(datastore_id, root_uuid, res['error']))
                return {'error': res['error'], 'errno': errno.EREMOTEIO}

            root = res['root']

        if file_name in root.keys():
            log.error("File exists: {}".format(file_name))
            return {'error': 'File exists', 'errno': errno.EEXIST}

        device_root = res['device_root_pages'].get(this_device_id, {})

    else:
        # must have device root 
        if device_root is None:
            # need pubkey for this device
            data_pubkey = None
            for dpk in data_pubkeys:
                if dpk['device_id'] == this_device_id:
                    data_pubkey = dpk['public_key']

            if data_pubkey is None:
                return {'error': 'No data public keys found for {}'.format(this_device_id), 'errno': errno.EINVAL}

            res = api_client.backend_datastore_get_device_root(blockchain_id, datastore, this_device_id, data_pubkey, force=force)
            if 'error' in res:
                log.error("Failed to get device {} root page for {}/{}: {}".format(this_device_id, datastore_id, root_uuid, res['error']))
                return {'error': res['error'], 'errno': errno.EREMOTEIO}

            device_root = res['device_root_page']

    return {'status': True, 'device_root': device_root}


def _putfile_device_root_insert(datastore, device_root, file_name, file_entry):
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
    device_root_data_id = storage.make_fq_data_id(this_device_id, '{}:{}'.format(datastore_id, root_uuid))
    device_root_data = data_blob_serialize(device_root_page)
    device_root_blob = make_mutable_data_blob(root_data_id, device_root_data, blockchain_id=blockchain_id, config_path=config_path, is_fq_data_id=True)

    return {'status': True, 'device_root_page_blob': device_root_blob}


def _deletefile_device_root_remove(datastore, device_root, file_name, this_device_file_tombstone):
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
    device_root_data_id = storage.make_fq_data_id(this_device_id, '{}:{}'.format(datastore_id, root_uuid))
    device_root_data = data_blob_serialize(device_root_page)
    device_root_blob = make_mutable_data_blob(root_data_id, device_root_data, blockchain_id=blockchain_id, config_path=config_path, is_fq_data_id=True)

    return {'status': True, 'device_root_page_blob': device_root_page_blob}


def datastore_putfile(api_client, datastore, file_name, file_data_bin, data_privkey_hex, data_pubkeys,
        this_device_id=None, create=False, synchronous=False, force=False, timestamp=0, config_path=CONFIG_PATH, blockchain_id=None, full_app_name=None):

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
    datastore_id = datastore_get_id(datastore['pubkey'])
    
    if this_device_id is None:
        this_device_id = get_local_device_id(config_dir=os.path.dirname(config_path))

    # sanity check: device ID must have a public key 
    data_pubkey = None
    for dpk in data_pubkeys:
        if this_device_id == dpk['device_id']:
            data_pubkey = dpk['public_key']

    if data_pubkey is None:
        return {'error': 'Device {} has no public key', 'errno': errno.EINVAL}

    # get device root
    res = _find_device_root(api_client, datastore, file_name, data_pubkeys, this_device_id, create, timestamp=timestamp, force=force, config_path=config_path, blockchain_id=blockchain_id)
    if 'error' in res:
        return res

    device_root = res['device_root']

    # serialize datastore
    datastore_info = datastore_serialize_and_sign(datastore, data_privkey_hex)
    datastore_str = datastore_info['str']
    datastore_sig = datastore_info['sig']
     
    # serialize file header with no URLs (used to verify data payload)
    data_hash = storage.hash_data_payload(file_data_bin)
    file_entry = datastore_make_file_entry(data_hash, [])
    file_data_id = '{}/{}'.format(datastore_id, file_name)

    file_entry_blob = make_mutable_data_blob(file_data_id, data_blob_serialize(file_entry), blockchain_id=blockchain_id, config_path=config_path, is_fq_data_id=True)
    file_entry_blob_str = data_blob_serialize(file_entry_blob)
    file_entry_sig = storage.sign_data_payload(file_entry_blob_str, data_privkey)

    # replicate the file data
    res = api_client.backend_datastore_putfile(datastore_str, datastore_sig, file_name, file_entry_blob_str, file_data_bin, file_entry_sig, this_device_id, data_pubkey,
                                                blockchain_id=blockchain_id, full_app_name=full_app_name)

    if 'error' in res:
        log.error("Failed to store {} to {}".format(file_name, datastore_id))
        return {'error': res['error'], 'errno': res.get('errno', errno.EREMOTEIO)}

    file_urls = res['urls']

    # serialize file header with actual URLs (to be included into the root directory)
    file_entry = datastore_make_file_entry(data_hash, file_urls)
    file_entry_blob = make_mutable_data_blob(file_data_id, data_blob_serialize(file_entry), blockchain_id=blockchain_id, config_path=config_path, is_fq_data_id=True)
    file_entry_blob_str = data_blob_serialize(file_entry_blob)
    file_entry_sig = storage.sign_data_payload(file_entry_blob_str, data_privkey)

    # make new signed device root
    res = _putfile_device_root_insert(device_root, file_name, file_entry)
    device_root_page_blob = res['device_root_page_blob']
    device_root_page_blob_sig = storage.sign_data_payload(device_root_page-blob, data_privkey)
    
    # put it, possibly synchronously
    res = api_client.backend_datastore_put_device_root(datastore_str, datastore_sig, device_root_page_blob, device_root_page_blob_sig, this_device_id,
                                                        blockchain_id=blockchain_id, full_app_name=full_app_name, synchronous=synchronous)

    if 'error' in res:
        log.error("Failed to replicate new device root for {} on putfile {}".format(datastore_id, file_name))
        return res

    return {'status': True, 'urls': file_urls, 'root_urls': root_urls}


def datastore_deletefile(api_client, datastore, file_name, data_privkey_hex, data_pubkeys, this_device_id=None, synchronous=False, force=False, timestamp=0, config_path=CONFIG_PATH, full_app_name=None, blockchain_id=None):
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
    
    datastore_id = datastore_get_id(datastore['pubkey'])
    
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
        return {'error': 'Device {} has no public key', 'errno': errno.EINVAL}

    this_device_file_tombstone = make_data_tombstones([this_device_id], '{}/{}'.format(datastore_id, file_name))
    file_tombstones = make_data_tombstones(datastore['device_ids'], '{}/{}'.format(datastore_id, file_name))
    signed_file_tombstones = sign_data_tombstones(file_tombstones, data_privkey_hex)

    # get device root
    res = _find_device_root(api_client, datastore, file_name, data_pubkeys, this_device_id, create, timestamp=timestamp, force=force, config_path=config_path, blockchain_id=blockchain_id)
    if 'error' in res:
        return res
    
    device_root = res['device_root']

    # serialize datastore
    datastore_info = datastore_serialize_and_sign(datastore, data_privkey_hex)
    datastore_str = datastore_info['str']
    datastore_sig = datastore_info['sig']

    res = api_client.backend_datastore_deletefile(datastore_str, datastore_sig, signed_file_tombstones, data_pubkeys, blockchain_id=blockchain_id, full_app_name=full_app_name)
    if 'error' in res:
        return res

    # patch root with tombstones
    _deletefile_device_root_remove(datastore, device_root, file_name, this_device_file_tombstone)

    # sign and serialize new root 
    signed_device_root_page_blob = storage.serialize_mutable_data(device_root_page_blob, data_privkey=data_privkey_hex)
    root_urls = None

    # queue for replication, if not synchronous.
    # otherwise, replicate right now.
    if synchronous:
        # replicate
        res = write_log_page_replicate(signed_device_root_page_blob, drivers, blockchain_id, config_path=config_path, proxy=proxy)
        if 'error' in res:
            log.error("Failed to replicate signed root page for {}.{}".format(datastore_id, root_uuid))
            return {'error': res['error'], 'errno': errno.EREMOTEIO}

        root_urls = res['urls']

    else:
        # queue for later replication 
        res = write_log_enqueue(datastore_id, this_device_id, root_uuid, signed_device_root_page_blob, drivers, blockchain_id=blockchain_id, config_path=config_path)
        if 'error' in res:
            log.error("Failed to enqueue {}.{} for replication (on putfile {})".format(datastore_id, root_uuid, file_name))
            return {'error': res['error'], 'errno': errno.EIO}

    return {'status': True, 'root_urls': root_urls}


def datastore_stat(api_client, blockchain_id, datastore, data_path, data_pubkeys, this_device_id, force=False, config_path=CONFIG_PATH):
    """
    Stat a file or directory.  Get just the inode metadata.

    Return {'status': True, 'file_info': inode info} on success
    Return {'error': ..., 'errno': ...} on error
    """

    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    datastore_id = datastore_get_id(datastore['pubkey'])
    drivers = datastore['drivers']
    
    log.debug("stat {}:{}".format(datastore_id, data_path))

    file_info = api_client.backend_datastore_lookup(blockchain_id, datastore, 'files', data_path, data_pubkeys, this_device_id, force=force, idata=False )
    if 'error' in file_info:
        log.error("Failed to resolve {}".format(data_path))
        return file_info
    
    return file_info


def get_read_public_storage_drivers(config_path):
    """
    Get the list of "read-public" storage drivers.
    This is according to the driver classification.
 
    Returns the list of driver names
    """
    
    driver_classes = storage.classify_storage_drivers()
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

    storage_handlers = storage.get_storage_handlers()
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

    storage_handlers = storage.get_storage_handlers()
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

    driver_classes = storage.classify_storage_drivers()
    
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


if __name__ == "__main__":
    # unit tests!
    import blockstack_client
    import subprocess
    import requests

    blockstack_client.session()

    class CLIArgs(object):
        pass

    def get_session( blockchain_id, app_privkey, app_domain, api_methods, device_ids, public_keys, config_path=CONFIG_PATH ):
        """
        sign in and get a token
        """
        args = CLIArgs()

        args.blockchain_id = blockchain_id
        args.app_domain = app_domain
        args.api_methods = ','.join(api_methods)
        args.privkey = app_privkey

        device_ids = ','.join(device_ids)
        public_keys = ','.join(public_keys)
        args.device_ids = device_ids
        args.public_keys = public_keys

        res = blockstack_client.cli_app_signin( args, config_path=config_path )
        if 'error' in res:
            raise Exception("Error: {}".format(res['error']))
        else:
            return res['token']

    datastore_pk = keylib.ECPrivateKey().to_hex()
    datastore_pubk = get_pubkey_hex(datastore_pk)
    datastore_id = datastore_get_id(datastore_pubk)
    this_device_id = '0'

    conf = get_config()
    assert conf

    ses = get_session(None, datastore_pk, 'foo.com.x', ['store_write'], [this_device_id], [datastore_pubk])

    rpc = blockstack_client.rpc.local_api_connect(api_session=ses)
    assert rpc

    # authenticate 
    ds_info = make_datastore_info("datastore", datastore_pubk, [this_device_id], driver_names=['disk'])
    if 'error' in ds_info:
        print "make_datastore_info: {}".format(ds_info)
        sys.exit(1)

    res = put_datastore( rpc, ds_info, datastore_pk )
    if 'error' in res:
        print 'put_datastore_info: {}'.format(res)
        sys.exit(1)

    ds_res = rpc.backend_datastore_get( None, None, datastore_id, device_ids=[this_device_id] )
    if 'error' in ds_res:
        print 'get_datastore: {}'.format(ds_res)
        sys.exit(1)

    datastore = ds_res

    data_pubkeys = [{'device_id': this_device_id, 'public_key': datastore_pubk}]

    # do this all twice
    for i in xrange(0, 2):
        
        res = datastore_putfile(rpc, datastore, 'hello_world', 'hello world\x00\x01\x02\x04\x05', datastore_pk, data_pubkeys, this_device_id=this_device_id, synchronous=True)
        if 'error' in res:
            print 'datastore_putfile: {}'.format(res)
            sys.exit(1)

        res = rpc.backend_datastore_get_root(None, datastore, data_pubkeys)
        if 'error' in res:
            print 'datastore_get_root /: {}'.format(res)
            sys.exit(1)

        # sanity check 
        if 'hello_world' not in res['root']:
            print 'root is {}'.format(res['root'])
            sys.exit(1)

        res = datastore_getfile(rpc, None, datastore, 'hello_world', data_pubkeys)
        if 'error' in res:
            print 'getfile failed: {}'.format(res)
            sys.exit(1)

        # sanity check
        if res['data'] != 'hello world\x00\x01\x02\x03\x04\x05':
            print 'datastore_getfile /dir1/dir2/hello: {}'.format(res)
            sys.exit(1)

        # should fail
        res = delete_datastore(rpc, datastore, datastore_pk)
        if 'error' not in res:
            print 'deleted datastore: {}'.format(res)
            sys.exit(1)

        if res['errno'] != errno.ENOTEMPTY:
            print 'wrong errno on ENOTEMPTY delete datastore: {}'.format(res)
            sys.exit(1)

        res = datastore_deletefile(rpc, datastore, 'hello_world', datastore_privk, data_pubkeys, this_device_id=this_device_id, synchronous=True)
        if 'error 'in res:
            print 'datastore_deletefile: {}'.format(res)
            sys.exit(1)

        # sanity check 
        res = rpc.backend_datastore_get_root(None, datastore, data_pubkeys)
        if 'error' in res:
            print 'datastore_get_root /: {}'.format(res)
            sys.exit(1)

        if 'hello_world' in res['root']:
            print 'hello_world still present'
            print res['root']
            sys.exit(1)

        # sanity check
        res = datastore_getfile(rpc, None, datastore, 'hello_world', data_pubkeys)
        if 'error' in res:
            if not res.has_key('errno') or res['errno'] != errno.ENOENT:
                print 'getfile failed: {}'.format(res)
                sys.exit(1)
        
        else:
            print 'accidentally succeeded to getfile: {}'.format(res)
            sys.exit(1)

    # clear datastore 
    res = delete_datastore(rpc, datastore, datastore_pk)
    if 'error' in res:
        print 'failed to delete empty datastore: {}'.format(res)
        sys.exit(1)

    sys.exit(0)

