#!/usr/bin/env python2
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
import os, sys
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
import copy
import jsonschema
from jsonschema import ValidationError

import keylib
from keylib import ECPrivateKey

import virtualchain
from virtualchain.lib.ecdsalib import sign_raw_data, get_pubkey_hex

from .keys import (get_payment_privkey_info, get_owner_privkey_info, HDWallet)

from .profile import get_data_privkey_info

from .proxy import (
    getinfo, get_name_blockchain_history, get_default_proxy, json_is_error)
from .storage import hash_zonefile
from .zonefile import get_name_zonefile, load_name_zonefile, store_name_zonefile
from .utils import ScatterGather

from .logger import get_logger
from .config import get_config, get_local_device_id
from .constants import (
    BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, DATASTORE_SIGNING_KEY_INDEX,
    BLOCKSTACK_STORAGE_PROTO_VERSION, DEFAULT_DEVICE_ID,
    CONFIG_PATH
)

from .schemas import (
    DATA_BLOB_SCHEMA,
    DATASTORE_SCHEMA,
    MUTABLE_DATUM_DIR_SCHEMA,
    MUTABLE_DATUM_INODE_HEADER_SCHEMA,
    MUTABLE_DATUM_DIR_TYPE,
    MUTABLE_DATUM_FILE_TYPE)

log = get_logger()

MUTABLE_DATA_VERSION_LOCK = threading.Lock()

# not defined on all platforms (looking at you, Mac OS)
EREMOTEIO = 121

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
        Get data from either the header cache or dir cache
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


def load_user_data_pubkey_addr( name, storage_drivers=None, proxy=None, config_path=CONFIG_PATH ):
    """
    Get a user's default data public key and/or owner address by getting it's zone file.

    Returns {'pubkey': ..., 'address': ...} on success
    Return {'error': ...} on error
    """
    # need to find pubkey to use
    user_zonefile = get_name_zonefile( name, storage_drivers=storage_drivers, proxy=proxy, include_name_record=True)
    if 'error' in user_zonefile:
        log.debug("Unable to load zone file for '{}': {}".format(name, user_zonefile['error']))
        return {'error': 'Failed to load zonefile'}

    # recover name record
    name_record = user_zonefile.pop('name_record')
    user_zonefile = user_zonefile['zonefile']

    # get user's data public key and owner address
    data_pubkey = None
    data_address = name_record['address']
    
    assert data_address is not None
    data_address = str(data_address)

    # data address cannot be a p2sh address
    if data_address is not None and virtualchain.is_multisig_address(data_address):
        log.warning("Address {} cannot be a data address".format(data_address))
        data_address = None

    try:
        data_pubkey = user_db.user_zonefile_data_pubkey(user_zonefile)
        if data_pubkey is not None:
            log.debug("Zone file data public key for {} is {}".format(name, data_pubkey))

    except ValueError:
        # multiple keys
        data_pubkey = None

    if data_pubkey is None and data_address is None:
        log.error("No public key or address usable")
        return {'error': 'No usable data public key or address'}

    return {'pubkey': data_pubkey, 'address': data_address}


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


def get_mutable(data_id, device_ids, raw=False, blockchain_id=None, data_pubkey=None, data_address=None, data_hash=None, storage_drivers=None,
                                     proxy=None, ver_min=None, ver_max=None, force=False, urls=None, is_fq_data_id=False,
                                     config_path=CONFIG_PATH):
    """
    get_mutable 

    Fetch a piece of mutable data from *all* drivers.

    If @ver_min is given, ensure the data's version is greater or equal to it.
    If @ver_max is given, ensure the data's version is less than it.
    
    If data_pubkey or data_address is given, then blockchain_id will be ignored (but it will be passed as a hint to the drivers)
    If data_hash is given, then all three will be ignored

    Return {'data': the data, 'version': the version, 'timestamp': ..., 'data_pubkey': ..., 'owner_pubkey_hash': ..., 'drivers': [driver name]} on success
    If raw=True, then only return {'data': ..., 'drivers': ...} on success.

    Return {'error': ...} on error
    """

    proxy = get_default_proxy(config_path) if proxy is None else proxy
    conf = get_config(path=config_path)
    
    # find all possible fqids for this datum
    fq_data_ids = []
    if is_fq_data_id:
        fq_data_ids = [data_id]

    else:
        for device_id in device_ids:
            fq_data_ids.append( storage.make_fq_data_id(device_id, data_id) )
    
    lookup = False
    if data_address is None and data_pubkey is None and data_hash is None:
        # TODO: cut this code path
        if blockchain_id is None:
            raise ValueError("No data public key, data address, or blockchain ID given")

        # need to find pubkey to use
        pubkey_info = load_user_data_pubkey_addr( blockchain_id, storage_drivers=storage_drivers, proxy=proxy, config_path=config_path )
        if 'error' in pubkey_info:
            return pubkey_info

        data_pubkey = pubkey_info['pubkey']
        data_address = pubkey_info['address']

        if data_pubkey is None and data_address is None:
            log.error("No data public key or address available")
            return {'error': 'No data public key or address available'}

        lookup = True

    if storage_drivers is None:
        storage_drivers = get_read_storage_drivers(config_path)
        log.debug("Using default storge drivers {}".format(','.join(storage_drivers)))

    expected_version = 0

    if not force:
        # require specific version min
        version_info = get_mutable_data_version(data_id, device_ids, config_path=config_path)
        expected_version = version_info['version']

    log.debug("get_mutable({}, device_ids={}, blockchain_id={}, pubkey={} ({}), addr={}, hash={}, expected_version={}, storage_drivers={})".format(
        data_id, device_ids, blockchain_id, data_pubkey, lookup, data_address, data_hash, expected_version, ','.join(storage_drivers)
    ))
    
    mutable_data = None
    stale = False
    mutable_drivers = []
    latest_version = expected_version

    # optimization: try local drivers before non-local drivers
    storage_drivers = prioritize_read_drivers(config_path, storage_drivers)

    # which storage drivers and/or URLs will we use?
    for driver in storage_drivers: 
        for fq_data_id in fq_data_ids:

            log.debug("get_mutable_data({}) from {}".format(fq_data_id, driver))

            # get the mutable data itsef
            # NOTE: we only use 'bsk2' data formats; use storage.get_mutable_data() directly for loading things like profiles that have a different format.
            data_str = storage.get_mutable_data(fq_data_id, data_pubkey, urls=urls, drivers=[driver], data_address=data_address, data_hash=data_hash, blockchain_id=blockchain_id, bsk_version=2)
            if data_str is None:
                log.error("Failed to get mutable datum {} from {}".format(fq_data_id, driver))
                continue
            
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
            version = data['version']
            if ver_min is not None and ver_min > version:
                log.warn("Invalid (stale) data version from {} for {}: ver_min = {}, version = {}".format(driver, fq_data_id, ver_min, version))
                continue

            elif ver_max is not None and ver_max <= version:
                log.warn("Invalid (future) data version from {} for {}: ver_max = {}, version = {}".format(driver, fq_data_id, ver_max, version))
                stale = True
                continue

            elif expected_version > version:
                log.warn("Invalid (stale) data version from {} for {}: expected = {}, version = {}".format(driver, fq_data_id, expected_version, version))
                stale = True
                continue

            # keep searching 
            if version < latest_version:
                log.warn("{} from {} is stale ({} < {})".format(fq_data_id, driver, version, latest_version))
                continue

            elif version == latest_version:
                log.debug("{} from {} has the same version as latest ({}), available from {}".format(fq_data_id, driver, latest_version, ','.join(mutable_drivers)))
                mutable_data = data
                mutable_drivers.append(driver)
                continue

            else:
                # got a later version
                # discard all prior drivers; they gave stale data
                latest_version = version
                mutable_data = data
                mutable_drivers = [driver]
                log.debug("Latest version of {} is now {}, vailable from {}".format(fq_data_id, version, driver))
                continue

    if mutable_data is None:
        log.error("Failed to fetch mutable data for {}".format(data_id))
        res = {'error': 'Failed to fetch mutable data'}
        if stale:
            res['stale'] = stale
            res['error'] = 'Failed to fetch mutable data for {} due to version mismatch.'
            log.error("Failed to fetch mutable data for {} due to version mismatch.".format(data_id))

        return res

    rc = put_mutable_data_version(data_id, version, device_ids, config_path=config_path)
    if 'error' in rc:
        return {'error': 'Failed to store consistency information'}

    ret = {
        'data': mutable_data['data'],
        'version': version,
        'timestamp': mutable_data['timestamp'],
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


def make_mutable_data_tombstones( device_ids, data_id ):
    """
    Make tombstones for mutable data across devices
    """
    ts = [storage.make_data_tombstone( storage.make_fq_data_id(device_id, data_id) ) for device_id in device_ids]
    return ts


def sign_mutable_data_tombstones( tombstones, data_privkey ):
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


def verify_mutable_data_tombstones( tombstones, data_pubkey, device_ids=None ):
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
        for dev_id in device_ids:
            if dev_id not in ts_device_ids:
                log.error("Device ID {} not present in the tombstones".format(dev_id))
                return False

    return True


def make_mutable_data_info(data_id, data_payload, device_ids=None, version=None, timestamp=None, blockchain_id=None, min_version=None, config_path=CONFIG_PATH, create=False, is_fq_data_id=False):
    """
    Make mutable data to serialize, sign, and store.
    data_payload must be a string.

    This is a client-side method.

    Return {'fq_data_id': ..., 'data': ..., 'version': ..., 'timestamp': ...} on success
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

    # get the version to use across all devices
    if version is None:
        version_info = get_mutable_data_version( data_id, device_ids, config_path=config_path)
        if version_info['version'] > 0 and create:
            log.error("Already exists: {}".format(fq_data_id))
            return {'error': 'Data exists', 'errno': errno.EEXIST}

        version = version_info['version'] + 1

    if version < min_version:
        version = min_version + 1

    if timestamp is None:
        timestamp = int(time.time())

    blob_data = {
        'fq_data_id': fq_data_id,
        'data': data_payload,
        'version': version,
        'timestamp': timestamp,
    }

    if blockchain_id is not None:
        blob_data['blockchain_id'] = blockchain_id

    return blob_data


def put_mutable(fq_data_id, mutable_data_str, data_pubkey, data_signature, version, blockchain_id=None, proxy=None, raw=False,
                config_path=CONFIG_PATH, storage_drivers=None, storage_drivers_exclusive=False, zonefile_storage_drivers=None ):
    """
    put_mutable.

    Given a fully-qualified data identifier (i.e. prefixed by the device ID), a serialized data payload from make_mutable_data, a public key, a signature, and a version,
    store it with the configured storage providers.

    This is a very low-level method.  DO NOT USE UNLESS YOU KNOW WHAT YOU ARE DOING

    ** Consistency **

    @version, if given, is the version to include in the data.
    If not given, then 1 will be used if no version exists locally, or the local version will be auto-incremented from the local version.
    Readers will only accept the version if it is "recent" (i.e. it falls into the given version range, or it is fresher than the last-seen version).

    ** Durability **

    Replication is all-or-nothing with respect to explicitly-listed storage drivers.  Each storage driver in storage_drivers must succeed.
    If any of them fail, then put_mutable fails.  All other storage drivers configured in the config file but not listed in storage_drivers
    will be attempted, but failures will be ignored.

    Notes on usage:
    * if storage_drivers is None, each storage driver under `storage_drivers_required_write=` will be required.
    * if storage_drivers is not None, then each storage driver in storage_drivers *must* succeed
    * If data_signature is not None, it must be the signature over the serialized payload form of data_payload

    Return {'status': True} on success
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

    log.debug("put_mutable({}, signature={}, storage_drivers={}, version={}, exclusive={}, raw={})".format(
        fq_data_id, data_signature, ','.join(storage_drivers), version, storage_drivers_exclusive, raw)
    )

    if not raw:
        # require signature and pubkey, since we'll serialize
        assert data_pubkey
        assert data_signature

    rc = storage.put_mutable_data(fq_data_id, mutable_data_str, data_pubkey=data_pubkey, data_signature=data_signature, sign=False, raw=raw, blockchain_id=blockchain_id,
                                  required=storage_drivers, required_exclusive=storage_drivers_exclusive)

    if not rc:
        log.error("failed to put mutable data {}".format(fq_data_id))
        result['error'] = 'Failed to store mutable data'
        return result

    # remember which version this was
    rc = store_mutable_data_version(conf, device_id, fq_data_id, version, config_path=config_path)
    if not rc:
        log.error("failed to put mutable data version {}.{}".format(fq_data_id, version))
        result['error'] = 'Failed to store mutable data version'
        return result

    if BLOCKSTACK_TEST is not None:
        msg = 'Put "{}" mutable data (version {}) for blockchain ID {}'
        log.debug(msg.format(fq_data_id, version, blockchain_id))

    return {'status': True}


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


def delete_mutable(data_id, signed_data_tombstones, proxy=None, storage_drivers=None, device_ids=None,
                                                    delete_version=True, storage_drivers_exclusive=False,
                                                    blockchain_id=None, is_fq_data_id=False, config_path=CONFIG_PATH):
    """
    delete_mutable

    Remove a piece of mutable data. Delete it from
    the storage providers as well.

    Optionally (by default) delete cached version information

    Returns a dict with {'status': True} on success
    Returns a dict with {'error': ...} on failure
    """

    proxy = get_default_proxy(config_path) if proxy is None else proxy
    conf = get_config(config_path)
    assert conf

    if device_ids is None:
        device_ids = filter(lambda x: x is not None, [get_device_id_from_tombstone(ts) for ts in signed_data_tombstones])
        assert len(device_ids) == len(signed_data_tombstones), "Invalid tombstones"

    fq_data_ids = []
    if is_fq_data_id:
        fq_data_ids = [data_id]

    else:
        for device_id in device_ids:
            fq_data_id = storage.make_fq_data_id(device_id, data_id)
            fq_data_ids.append(fq_data_id)
   
    if storage_drivers is None:
        storage_drivers = get_required_write_storage_drivers(config_path)

    worst_rc = True

    log.debug("delete_mutable({}, signed_data_tombstones={}, blockchain_id={}, storage_drivers={}, delete_version={})".format(
        data_id, ','.join(signed_data_tombstones), blockchain_id, ','.join(storage_drivers), delete_version
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
    
    if worst_rc and delete_version:
        # only do this if we actually succeeded in deleting from all storage providers
        for device_id in device_ids:
            for fq_data_id in fq_data_ids:
                delete_mutable_data_version(conf, device_id, fq_data_id, config_path=config_path)

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

    # TODO: back up old public key to wallet and mutable storage

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


def _init_datastore_info( datastore_type, datastore_pubkey, driver_names, device_ids, reader_pubkeys=[], config_path=CONFIG_PATH ):
    """
    Make the private part of a datastore record.
    Returns {'datastore': ..., 'root': ...} on success
    Returns {'error': ...} on error
    """
    assert datastore_type in ['datastore', 'collection'], datastore_type

    root_uuid = str(uuid.uuid4())
    datastore_id = keylib.public_key_to_address(datastore_pubkey)

    root_blob = make_dir_inode_data(datastore_id, datastore_id, root_uuid, {}, device_ids, reader_pubkeys=reader_pubkeys, config_path=config_path, create=True )
    if 'error' in root_blob:
        return root_blob

    datastore_info = {
        'type': datastore_type,
        'pubkey': datastore_pubkey,
        'drivers': driver_names,
        'device_ids': device_ids,
        'root_uuid': root_uuid
    }

    return {'datastore_blob': data_blob_serialize(datastore_info), 'root_blob_header': root_blob['header'], 'root_blob_idata': root_blob['idata']}


def get_datastore( blockchain_id, datastore_id, device_ids, config_path=CONFIG_PATH, proxy=None, no_cache=False, cache_ttl=None):
    """
    Get a datastore's information.
    This is a server-side method.

    TODO: remove datastore_id and device_ids; resolve tokens file and go from there 

    Returns {'status': True, 'datastore': public datastore info}
    Returns {'error': ..., 'errno':...} on failure
    """
    
    global GLOBAL_CACHE
    
    # cached?
    if not no_cache:
        res = GLOBAL_CACHE.get_datastore_record(datastore_id)
        if res:
            return {'status': True, 'datastore': res}

    if proxy is None:
        proxy = get_default_proxy(config_path)

    if cache_ttl is None:
        conf = get_config(config_path)
        assert conf
        cache_ttl = int(conf.get('cache_ttl', 3600))    # 1 hour

    data_id = '{}.datastore'.format(datastore_id)
    datastore_info = get_mutable(data_id, device_ids, blockchain_id=blockchain_id, data_address=datastore_id, proxy=proxy, config_path=config_path)
    if 'error' in datastore_info:
        log.error("Failed to load public datastore information: {}".format(datastore_info['error']))
        return {'error': 'Failed to load public datastore record', 'errno': errno.ENOENT}

    datastore_str = datastore_info['data']
    try:
        datastore = data_blob_parse(datastore_str)
        jsonschema.validate(datastore, DATASTORE_SCHEMA) 
    except (AssertionError, ValidationError) as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)
        
        log.error("Invalid datastore record")
        return {'error': 'Invalid public datastore record', 'errno': errno.EIO}

    # cache 
    if not no_cache:
        GLOBAL_CACHE.put_datastore_record(datastore_id, datastore, cache_ttl)

    return {'status': True, 'datastore': datastore}


def make_datastore_info( datastore_type, datastore_pubkey_hex, device_ids, driver_names=None, config_path=CONFIG_PATH ):
    """
    Create a new datastore record with the given name, using the given account_info structure
    This is a client-side method
    
    Return {'datastore_blob': public datastore information, 'root_blob_header': root inode header, 'root_blob_idata': root inode data}
    Return {'error': ...} on failure
    """
    if driver_names is None:
        driver_handlers = storage.get_storage_handlers()
        driver_names = [h.__name__ for h in driver_handlers]

    datastore_info = _init_datastore_info( datastore_type, datastore_pubkey_hex, driver_names, device_ids, config_path=config_path)
    if 'error' in datastore_info:
        return datastore_info
   
    root_blob_header = datastore_info['root_blob_header']
    root_blob_idata = datastore_info['root_blob_idata']
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

    return {'datastore_blob': datastore_info_str, 'root_blob_header': root_blob_header, 'root_blob_idata': root_blob_idata}


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
    
    root_sig = storage.sign_data_payload( datastore_info['root_blob_header'], datastore_privkey_hex )
    datastore_sig = storage.sign_data_payload( datastore_info['datastore_blob'], datastore_privkey_hex )

    root_tombstones = make_inode_tombstones( datastore_id, root_uuid, device_ids )
    signed_tombstones = sign_mutable_data_tombstones( root_tombstones, datastore_privkey_hex )

    ret = {'datastore_sig': datastore_sig, 'root_sig': root_sig, 'root_tombstones': signed_tombstones}
    if BLOCKSTACK_TEST:
        assert verify_datastore_info(datastore_info, ret, get_pubkey_hex(datastore_privkey_hex), config_path=config_path)

    return ret


def verify_datastore_info( datastore_info, sigs, datastore_pubkey_hex, config_path=CONFIG_PATH ):
    """
    Given datastore info from make_datastore_info() and signatures from sign_datastore_info,
    verify the datastore information authenticity.

    datastore_info has {'datastore_blob': ..., 'root_blob_header': ..., 'root_blob_idata': ...} (serialized strings)
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

    res = storage.verify_data_payload( datastore_info['root_blob_header'], datastore_pubkey_hex, sigs['root_sig'] )
    if not res:
        log.debug("Failed to verify root inode blob payload with {} and {}".format(datastore_pubkey_hex, sigs['root_sig']))
        return False

    root_header_mutable_data = data_blob_parse(datastore_info['root_blob_header'])
    root_header = data_blob_parse(root_header_mutable_data['data'])
    data_hash = storage.hash_data_payload(datastore_info['root_blob_idata'])
    if root_header['data_hash'] != data_hash:
        log.error("Root idata mismatch: {} != {}".format(root_header['data_hash'], data_hash))
        return False

    return True


def put_datastore_info( datastore_info, datastore_sigs, root_tombstones, config_path=CONFIG_PATH, proxy=None ):
    """
    Given output from make_datastore_info and sign_datastore_info, store it to mutable data.
    This is a server-side method
    
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    global GLOBAL_CACHE

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
    
    res = put_inode_data( datastore, datastore_info['root_blob_header'], datastore_sigs['root_sig'], datastore_info['root_blob_idata'], config_path=config_path, proxy=proxy)
    if 'error' in res:
        log.error("Failed to store root inode info for {}".format(datastore_id))
        return {'error': res['error'], 'errno': EREMOTEIO}

    res = put_mutable( datastore_fqid, datastore_info['datastore_blob'], datastore['pubkey'], datastore_sigs['datastore_sig'], datastore_version,
                       proxy=proxy, config_path=config_path, storage_drivers_exclusive=True )

    if 'error' in res:
        log.error("Faield to store datastore record for {}".format(datastore_id))

        # try to clean up 
        res = delete_inode_data( datastore, root_tombstones, proxy=proxy, config_path=config_path )
        if 'error' in res:
            log.error("Failed to clean up root inode for {}".format(datastore_id))

        return {'error': 'Failed to store datastore information', 'errno': EREMOTEIO}

    # evict 
    GLOBAL_CACHE.evict_datastore_record(datastore_id)

    # success!
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


def make_datastore_tombstones( datastore_id, device_ids ):
    """
    Make datastore tombstones

    TODO: expand to include all devices (requires token file)
    """
    datastore_tombstones = make_mutable_data_tombstones( device_ids, '{}.datastore'.format(datastore_id) )
    return datastore_tombstones


def delete_datastore_info( datastore_id, datastore_tombstones, root_tombstones, data_pubkeys, blockchain_id=None, force=False, proxy=None, config_path=CONFIG_PATH ):
    """
    Delete a datastore.  Only do so if its root directory is empty (unless force=True).
    This is a server-side method.

    TODO: expand to include all public keys and devices (requires token file)

    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    global GLOBAL_CACHE

    if proxy is None:
        proxy = get_default_proxy(config_path)
   
    device_ids = [dk['device_id'] for dk in data_pubkeys]

    # get the datastore first
    datastore_info = get_datastore(blockchain_id, datastore_id, device_ids, config_path=config_path, proxy=proxy, no_cache=True )
    if 'error' in datastore_info:
        log.error("Failed to look up datastore information for {}".format(datastore_id))
        return {'error': 'Failed to look up datastore', 'errno': errno.ENOENT}
    
    datastore = datastore_info['datastore']
    root_uuid = datastore['root_uuid']
    drivers = datastore['drivers']

    # get root inode
    res = get_inode_data(None, datastore_id, root_uuid, MUTABLE_DATUM_DIR_TYPE, datastore['drivers'], data_pubkeys, force=force, config_path=config_path)
    if 'error' in res:
        if not force:
            log.error("Failed to list /")
            return {'error': 'Failed to check if datastore is empty', 'errno': EREMOTEIO}
        else:
            log.warn("Failed to list /, but forced to remove it anyway")

    if not force and len(res['inode']['idata']['children']) != 0:
        log.error("Datastore not empty\n{}\n".format(json.dumps(res['inode']['idata']['children'], indent=4, sort_keys=True)))
        return {'error': 'Datastore not empty', 'errno': errno.ENOTEMPTY}

    data_id = '{}.datastore'.format(datastore_id)
    res = delete_mutable(data_id, datastore_tombstones, storage_drivers=drivers, storage_drivers_exclusive=True, proxy=proxy, config_path=config_path )
    if 'error' in res:
        log.error("Failed to delete datastore {}".format(datastore_id))
        return {'error': 'Failed to delete datastore', 'errno': EREMOTEIO}

    res = delete_inode_data( datastore, root_tombstones, proxy=proxy, config_path=config_path )
    if 'error' in res:
        log.error("Failed to delete root inode {}".format(root_uuid))
        return {'error': 'Failed to delete root inode', 'errno': EREMOTEIO}

    # evict 
    GLOBAL_CACHE.evict_datastore_record(datastore_id)
    return {'status': True}


def delete_datastore(api_client, datastore, datastore_privkey, data_pubkeys, config_path=CONFIG_PATH):
    """
    Delete a datastore.

    Client-side method

    TODO: expand to use token file

    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    datastore_pubkey = get_pubkey_hex(datastore_privkey)
    datastore_id = datastore_get_id(datastore_pubkey)

    tombstones = make_datastore_tombstones(datastore_id, datastore['device_ids'])
    signed_tombstones = sign_mutable_data_tombstones(tombstones, datastore_privkey )

    # delete root as well
    root_tombstones = make_inode_tombstones( datastore_id, datastore['root_uuid'], datastore['device_ids'] )
    signed_root_tombstones = sign_mutable_data_tombstones( root_tombstones, datastore_privkey )

    res = api_client.backend_datastore_delete(datastore_id, signed_tombstones, signed_root_tombstones, data_pubkeys ) 
    if 'error' in res:
        return res

    return {'status': True}


def get_inode_data(blockchain_id, datastore_id, inode_uuid, inode_type, drivers, data_pubkeys, config_path=CONFIG_PATH, data_privkey=None, force=False, idata=True, proxy=None, file_idata=True, header_info=None, 
        no_cache=False, cache_ttl=None ):

    """
    Get an inode from non-local mutable storage.  Verify that it has an
    equal or later version number than the one we have locally.
    
    This is a server-side method.

    TODO: remove datastore_id; generate each per-device datastore ID from data_pubkeys

    Return {'status': True, 'inode': inode info, 'version': version, 'drivers': drivers} on success.
    * 'inode' will be raw file data if this is a file.  Otherwise, it will be a structured directory listing
    * ret['inode']['data'] will contain the relevant information for the inode

    Return {'error': ..., 'errno': ...} on error
    """
   
    global GLOBAL_CACHE

    if proxy is None:
        proxy = get_default_proxy(config_path)

    conf = get_config(config_path)
    assert conf

    if cache_ttl is None:
        cache_ttl = int(conf.get('cache_ttl', 3600))     # 3600 by default

    header_version = 0
    inode_header = None
    inode_info = None
    res = None

    if header_info is None:
        log.debug("Get inode header for {}.{}".format(datastore_id, inode_uuid))

        # get latest header from all drivers 
        res = get_inode_header(blockchain_id, datastore_id, inode_uuid, drivers, data_pubkeys, force=force, config_path=config_path, proxy=proxy )
        if 'error' in res:
            log.error("Failed to get inode header for {}: {}".format(inode_uuid, res['error']))
            return res
        
    else:
        res = header_info
        log.debug("Reuse header info: {}".format(res))

    header_version = res['version']
    inode_header = res['inode']
    drivers_to_try = res['drivers']
    data_hash = inode_header['data_hash']

    if inode_uuid != inode_header['uuid']:
        log.error("Got invalid inode header with wrong UUID")
        return {'error': 'Invalid inode header', 'errno': errno.EIO}

    if not idata:
        # only wanted header 
        return {'status': True, 'inode': inode_header, 'version': header_version, 'drivers': drivers_to_try}

    if inode_header['type'] == MUTABLE_DATUM_FILE_TYPE and not file_idata:
        # this is a file; only return header 
        return {'status': True, 'inode': inode_header, 'version': header_version, 'drivers': drivers_to_try}

    # check cache for directories...
    if inode_type == MUTABLE_DATUM_DIR_TYPE and not no_cache:
        res = GLOBAL_CACHE.get_inode_directory(datastore_id, inode_uuid)
        if res:
            # check version 
            if res['version'] == header_version:
                log.debug("Get CACHED inode data for {}.{}, version {}: {}".format(datastore_id, inode_uuid, res['version'], res))
                return {'status': True, 'inode': res, 'version': res['version'], 'drivers': drivers} 
            else:
                # stale directory
                log.debug("Evict stale directory {}".format(inode_uuid))
                GLOBAL_CACHE.evict_inode_directory(datastore_id, inode_uuid)


    log.debug("Get inode data for {}.{} from {}, version {}".format(datastore_id, inode_uuid, drivers_to_try, header_version))

    # get inode from only the driver(s) that gave back fresh information.
    # expect raw data.  It will either be idata (for a file), or a dir listing (for a directory)
    data_id = '{}.{}'.format(datastore_id, inode_uuid)
    ver_min = header_version 
    if force:
        ver_min = 0

    have_stale = False
    have_data = False
    res = None
    device_ids = [dk['device_id'] for dk in data_pubkeys]

    drivers_to_try = prioritize_read_drivers(config_path, drivers_to_try)

    for driver_to_try in drivers_to_try:
        # try each driver, until we find one with the right hash.
        # try all devices IDs.
        res = get_mutable(data_id, device_ids, blockchain_id=blockchain_id, ver_min=ver_min, raw=True, data_hash=data_hash, storage_drivers=drivers_to_try, proxy=proxy, config_path=config_path)
        if 'error' in res:
            log.error("Failed to get inode {} from {} (stale={}): {}".format(inode_uuid, ','.join(drivers_to_try), res.get("stale", False), res['error']))
            if res.get('stale'):
                have_stale = True

            continue

        else:
            have_data = True
            break

    if not have_data:
        err = {'error': 'Failed to find fresh inode', 'errno': EREMOTEIO}
        if have_stale:
            err['errno'] = errno.ESTALE

        return err

    # success!  recover full inode
    inode_info_str = res['data']
    full_inode = copy.deepcopy(inode_header)
    del full_inode['data_hash']

    if inode_type == MUTABLE_DATUM_DIR_TYPE:
        reader_pubkeys = None

        # must be a directory listing 
        try:
            dir_idata, reader_pubkeys = inode_dir_idata_parse(inode_info_str, data_privkey)
            full_inode['idata'] = dir_idata
            jsonschema.validate(full_inode, MUTABLE_DATUM_DIR_SCHEMA)
        except Exception as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            return {'error': 'Invalid directory structure', 'errno': errno.EIO}

        # must match owner 
        # data_address = keylib.public_key_to_address(data_pubkey_hex)
        if full_inode['owner'] != datastore_id:   # data_address:
            log.error("Inode {} not owned by {} (but by {})".format(full_inode['uuid'], datastore_id, full_inode['owner']))
            return {'error': 'Invalid owner'}
    
        # preserve reader pubkeys 
        full_inode['reader_pubkeys'] = reader_pubkeys

    else:
        # raw file (or raw inode request)
        full_inode['idata'] = inode_info_str
    
    if not force:
        res = _put_inode_consistency_info(datastore_id, inode_uuid, header_version, device_ids, config_path=config_path)
        if 'error' in res:
            return res

    if not no_cache and inode_type == MUTABLE_DATUM_DIR_TYPE:
        GLOBAL_CACHE.put_inode_directory(datastore_id, full_inode, cache_ttl)

    return {'status': True, 'inode': full_inode, 'version':  header_version, 'drivers': drivers_to_try}


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


def _put_inode_consistency_info(datastore_id, inode_uuid, new_version, device_ids, config_path=CONFIG_PATH):
    """
    Advance all versions of an inode locally
    Return {'status': True} on success
    Return {'error': ...} on error
    """

    # advance header version and inode version
    inode_data_id = '{}.{}'.format(datastore_id, inode_uuid)
    hdr_data_id = '{}.{}.hdr'.format(datastore_id, inode_uuid)

    res = put_mutable_data_version(inode_data_id, new_version, device_ids, config_path=CONFIG_PATH)
    if 'error' in res:
        return res

    hdr_ver = res['version']
    res = put_mutable_data_version(hdr_data_id, hdr_ver, device_ids, config_path=CONFIG_PATH)
    if 'error' in res:
        return res

    if res['version'] > hdr_ver:
        # headers had later version 
        inode_ver = res['version']
        res = put_mutable_data_version(inode_data_id, inode_ver, device_ids, config_path=CONFIG_PATH)
        if 'error' in res:
            return res

    return {'status': True}


def get_inode_header(blockchain_id, datastore_id, inode_uuid, drivers, data_pubkeys, inode_hdr_version=None, force=False, config_path=CONFIG_PATH, proxy=None, no_cache=False, cache_ttl=None ):
    """
    Get an inode's header data.  Verify it matches the inode info.
    Fetch the header from *all* drivers.

    This is a server-side method.

    TODO: remove datastore_id; expand to use all datastore IDs derived from data_pubkeys structure 

    Return {'status': True, 'inode': inode_full_info, 'version': version, 'drivers': drivers that were used} on success.
    Return {'error': ..., 'errno': ...} on error.
    """

    global GLOBAL_CACHE

    if not no_cache:
        res = GLOBAL_CACHE.get_inode_header(datastore_id, inode_uuid)
        if res:
            return {'status': True, 'inode': res, 'version': res['version'], 'drivers': drivers}

    if proxy is None:
        proxy = get_default_proxy(config_path)

    conf = get_config(config_path)
    assert conf

    if cache_ttl is None:
        cache_ttl = int(conf.get('cache_ttl', 3600))  # 1 hour by default

    # get latest inode and inode header version
    inode_id = '{}.{}'.format(datastore_id, inode_uuid)
    inode_hdr_id = '{}.{}.hdr'.format(datastore_id, inode_uuid)

    inode_version = 0
    inode_hdr_version = 0

    # latest version the *server* has seen
    device_ids = [dk['device_id'] for dk in data_pubkeys]
    res = get_mutable_data_version( inode_id, device_ids, config_path=CONFIG_PATH )
    inode_version = res['version']

    if inode_hdr_version is None:
        res = get_mutable_data_version( inode_hdr_id, device_ids, config_path=CONFIG_PATH )
        inode_hdr_version = res['version']
     
    # get from *all* drivers so we know that if we succeed, we have a fresh version
    # (unless force, in which case, ignore the version)
    data_id = '{}.{}.hdr'.format(datastore_id, inode_uuid)
    ver_min = max(inode_version, inode_hdr_version)
    if force:
        ver_min = 0

    res = None
    errcode = None
    have_data = False

    # optimization: try local drivers before non-local drivers
    drivers = prioritize_read_drivers(config_path, drivers)

    for driver in drivers:
        for data_pubkey_info in data_pubkeys:
            device_id = data_pubkey_info['device_id']
            device_pubkey = data_pubkey_info['public_key']

            res = get_mutable(data_id, [device_id], blockchain_id=blockchain_id, ver_min=ver_min, force=force, data_pubkey=device_pubkey, storage_drivers=[driver], proxy=proxy, config_path=config_path)
            if 'error' in res:
                log.error("Failed to get inode data {} (stale={}): {}".format(inode_uuid, res.get('stale', False), res['error']))
                errcode = EREMOTEIO
                if res.get('stale'):
                    errcode = errno.ESTALE

                continue

            else:
                # success!
                have_data = True
                break

        if have_data:
            break

    if 'error' in res:
        return {'error': 'Failed to get inode data', 'errno': errcode}

    # validate 
    inode_hdr_str = res['data']
    try:
        inode_hdr = data_blob_parse(inode_hdr_str)
    except:
        if BLOCKSTACK_TEST:
            log.error("Unparseable header: {}".format(inode_hdr_str))

        return {'error': "Unparseable inode header", 'errno': errno.EIO}

    inode_hdr_version = res['version']
    inode_drivers = res['drivers']
    
    try:
        jsonschema.validate(inode_hdr, MUTABLE_DATUM_INODE_HEADER_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        return {'error': "Invalid inode header", 'errno': errno.EIO}

    # advance header version and inode version, so the server never gets stale data again (unless force=True)
    if not force:
        res = _put_inode_consistency_info(datastore_id, inode_uuid, max(inode_hdr_version, inode_version), device_ids, config_path=config_path)
        if 'error' in res:
            return {'error': res['error'], 'errno': res['errno']}

    if not no_cache:
        inode_hdr['version'] = max(inode_hdr_version, inode_version)
        GLOBAL_CACHE.put_inode_header(datastore_id, inode_hdr, cache_ttl)

    return {'status': True, 'inode': inode_hdr, 'version': max(inode_hdr_version, inode_version), 'drivers': inode_drivers}


def make_inode_header_blob( datastore_id, inode_type, owner, inode_uuid, data_hash, device_ids, readers=[], min_version=None, config_path=CONFIG_PATH, create=False, include_raw=False ):
    """
    Make an inode header structure for storage in mutable data.
    Return {'status': True, 'header': serialized inode header} on success.  The caller should sign this, and replicate it and the signature.
    Return {'error': ...} on error
    """
    version = 1
    if min_version:
        version = min_version + 1

    res = {
        'type': inode_type,
        'owner': owner,
        'uuid': inode_uuid,
        'readers': readers,
        'data_hash': data_hash,
        'version': version,
        'proto_version': BLOCKSTACK_STORAGE_PROTO_VERSION,
    }

    jsonschema.validate(res, MUTABLE_DATUM_INODE_HEADER_SCHEMA)
    
    data_id = '{}.{}.hdr'.format(datastore_id, inode_uuid)
    inode_hdr_str = data_blob_serialize(res)

    info = make_mutable_data_info( data_id, inode_hdr_str, config_path=config_path, device_ids=device_ids, min_version=min_version, create=create )
    if 'error' in info:
        return {'error': info['error'], 'errno': info['errno']}

    ret = {'status': True, 'header': data_blob_serialize(info)}
    if include_raw:
        ret['header_raw'] = res

    return ret


def make_file_inode_data( datastore_id, owner, inode_uuid, data_payload_hash, device_ids, readers=[], config_path=CONFIG_PATH, min_version=None, create=False ):
    """
    Initialize an inode header and hash for file data
    Return {'status': True, 'header': serialized inode header} on success.  The caller should sign this, and replicate it and the signature.
    Return {'error': ...} on error
    """
    header_blob = make_inode_header_blob( datastore_id, MUTABLE_DATUM_FILE_TYPE, owner, inode_uuid, data_payload_hash, device_ids, readers=readers, config_path=config_path, min_version=min_version, create=create )
    if 'error' in header_blob:
        return header_blob

    return {'status': True, 'header': header_blob['header']}


def make_dir_inode_data( datastore_id, owner, inode_uuid, dir_listing, device_ids, reader_pubkeys=[], config_path=CONFIG_PATH, min_version=None, create=False ):
    """
    Initialize an inode header and hash for dir data.
    Return {'status': True, 'header': serialized inode header, 'idata': idata string} on success.  The caller should sign this, and replicate it and the signature.
    Return {'error': ...} on error
    """

    readers = [keylib.public_key_to_address(rpubk) for rpubk in reader_pubkeys]

    # include the header in the idata (but with an empty hash)
    data_hash = "00" * 32
    header_blob = make_inode_header_blob( datastore_id, MUTABLE_DATUM_DIR_TYPE, owner, inode_uuid, data_hash, device_ids, readers=readers, config_path=config_path, min_version=min_version, create=create, include_raw=True )
    if 'error' in header_blob:
        return header_blob

    idata = {
        'children': dir_listing,
        'header': header_blob['header_raw']
    }

    # now make the idata
    idata_payload = inode_dir_idata_serialize(idata, reader_pubkeys)
    data_hash = storage.hash_data_payload(idata_payload)

    header_blob = make_inode_header_blob( datastore_id, MUTABLE_DATUM_DIR_TYPE, owner, inode_uuid, data_hash, device_ids, readers=readers, config_path=config_path, min_version=min_version, create=create )
    if 'error' in header_blob:
        return header_blob

    return {'status': True, 'header': header_blob['header'], 'idata': idata_payload}


def inode_dir_idata_parse(dir_inode_info, data_privkey):
    """
    Given the data payload for a directory inode, extract the directory listing.

    Return a data structure compatible with MUTABLE_DATUM_DIR_IDATA_SCHEMA, and the reader public keys
    """

    # TODO: decrypt with my private key, or raise an exception if it's encrypted and I can't read it
    return (data_blob_parse(dir_inode_info), [])


def inode_dir_idata_serialize(dir_idata, reader_pubkeys=[]):
    """
    Given the directory listing for an inode, and optionally a list of public keys for
    allowed readers, serialize the directory listing.

    Return the serialized idata
    """

    # TODO: serialize and encrypt with each of the public keys
    return data_blob_serialize(dir_idata)


def sign_inode_header_blob( header_blob, data_privkey ):
    """
    Sign a serialized inode header blob.
    Return the signature
    """
    sig = storage.sign_data_payload(header_blob, data_privkey)
    return sig


def analyze_inode_header_blob( datastore_id, inode_header_blob_str ):
    """
    Get some useful information from a mutable data blob containing a serialized inode header blob.

    Return the useful info on success (as a dict)
    Return {'error': ..., 'errno': ...} on error.
    """

    inode_header_blob = data_blob_parse(inode_header_blob_str)
    try:
        jsonschema.validate(inode_header_blob, DATA_BLOB_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        return {'error': 'Invalid inode header blob: expected mutable data blob'}

    try:
        header_fqid = inode_header_blob['fq_data_id']
        dev_id, header_id = storage.parse_fq_data_id(header_fqid)
        assert dev_id, "Invalid header fqid {}".format(header_fqid)
        assert header_id, "Invalid header fqid {}".format(header_fqid)

        version = inode_header_blob['version']

        parts = header_id.split('.')

        assert len(parts) == 3, "len is {}".format(len(parts))
        assert parts[2] == 'hdr', "{} != {}".format(parts[2], 'hdr')
        assert parts[0] == datastore_id, "{} != {}".format(parts[0], datastore_id)
        
        inode_uuid = parts[1]
        idata_fqid = storage.make_fq_data_id(dev_id, '{}.{}'.format(datastore_id, inode_uuid))
        data = inode_header_blob['data']

    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Invalid inode fqid {}".format(header_fqid))
        return {'error': 'Invalid inode info', 'errno': errno.EINVAL}

    ret = {
        'uuid': inode_uuid,
        'device_id': dev_id,
        'header_id': header_id,
        'version': version,
        'header_fqid': header_fqid,
        'idata_fqid': idata_fqid,
        'data': data,
    }

    return ret


def put_inode_data( datastore, header_blob_str, header_blob_sig, idata_str, config_path=CONFIG_PATH, proxy=None, no_cache=False, cache_ttl=None ):
    """
    Store an inode and its idata to mutable storage.  Update local consistency info on success.
    The caller should call datastore_operation_check() before calling this method.

    This is a server-side method.

    TODO: datastore is ambiguous.  We need to be certain that datastore corresponds to the device-specific datastore record for the caller user

    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    global GLOBAL_CACHE

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)
    
    datastore_id = datastore_get_id(datastore['pubkey'])
    drivers = datastore['drivers']

    header_info = analyze_inode_header_blob(datastore_id, header_blob_str)
    if 'error' in header_info:
        return header_info

    version = header_info['version']
    inode_uuid = header_info['uuid']
    header_fqid = header_info['header_fqid']
    idata_fqid = header_info['idata_fqid']
    data_str = header_info['data']
    inode_hdr = None
    inode_type = None
    
    try:
        inode_hdr = json.loads(data_str)
        jsonschema.validate(inode_hdr, MUTABLE_DATUM_INODE_HEADER_SCHEMA)
        inode_type = inode_hdr['type']

    except (ValueError, ValidationError) as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        return {'error': 'Corrupt inode header'}

    # replicate best-effort to each driver
    # replicate (header, payload) per driver, instead of (headers) to driver and then (payloads) to driver.
    # this way, if some services are offline but others are not, this write can partially succeed to readers,
    # and the user can retry the write (from this or another device) to "complete" it.
    log.debug("Store inode {} (version {})".format(inode_uuid, version))
    save_idata = lambda di: put_mutable(idata_fqid, idata_str, None, None, version, raw=True, storage_drivers=[di], storage_drivers_exclusive=True, config_path=config_path, proxy=proxy)
    save_header = lambda dh: put_mutable(header_fqid, header_blob_str, datastore['pubkey'], header_blob_sig, version, storage_drivers=[dh], storage_drivers_exclusive=True, config_path=config_path, proxy=proxy)

    def _save_inode_fastpath(driver):
        """
        Save the inode to a specific driver.
        Save the header and idata in parallel (fast path)

        Return {'status': True} on success
        Return {'error': ...} on failure
        """
        sg = ScatterGather()
        driver_save_idata = functools.partial(save_idata, driver)
        driver_save_header = functools.partial(save_header, driver)
        sg.add_task( "save_idata", driver_save_idata)
        sg.add_task( "save_header", driver_save_header)

        sg.run_tasks()

        res = sg.get_result('save_idata')
        if 'error' in res:
            log.error('Fastpath: Failed to replicate inode data {}: {}'.format(idata_fqid, res['error']))
            return {'error': 'Failed to replicate inode data {}'.format(idata_fqid)}

        res = sg.get_result('save_header')
        if 'error' in res:
            log.error('Fastpath: Failed to replicate inode header {}: {}'.format(header_fqid, res['error']))
            return {'error': 'Failed to replicate inode header {}'.format(header_fqid)}

        return {'status': True}


    def _save_inode_slowpath(driver):
        """
        Save the inode to a specific driver.
        Save the idata, and then the header (slow path)

        Return {'status': True} on success
        Return {'error': ...} on failure
        """
        res = save_idata(driver)
        if 'error' in res:
            log.error("Slowpath: Failed to replicate inode data {}: {}".format(idata_fqid, res['error']))
            return {'error': 'Failed to replicate inode data {}'.format(idata_fqid)}

        res = save_header(driver)
        if 'error' in res:
            log.error("Slowpath: Failed to replicate inode header {}: {}".format(header_fqid, res['error']))
            return {'error': 'Failed to replicate inode header {}'.format(header_fqid)}

        return {'status': True}


    driver_failed = False
    driver_succeeded = False

    driver_sg = ScatterGather()
    for dname in drivers:
        save_inode_data = functools.partial(_save_inode_fastpath, dname)
        driver_sg.add_task(dname, save_inode_data)

    driver_sg.run_tasks()
    for dname in drivers:
        result = driver_sg.get_result(dname)
        if 'error' in result:
            log.error("Driver {} failed to replicate: {}".format(dname, result['error']))
            driver_failed = True

        else:
            log.debug("Driver {} succeeded to replicate".format(dname))
            driver_succeeded = True

    '''
    driver_failed = False
    for driver in drivers:

        # TODO: can we do this in parallel along a "fast path", and then try them individually on a "slow path" if one of them fails?

        # store payload (no signature; we'll use the header's hash)
        res = put_mutable(idata_fqid, idata_str, None, None, version, raw=True, storage_drivers=[driver], storage_drivers_exclusive=True, config_path=config_path, proxy=proxy )
        if 'error' in res:
            log.error("Failed to replicate inode {}: {}".format(idata_fqid, res['error']))
            driver_failed = True
            continue

        # store header
        res = put_mutable(header_fqid, header_blob_str, datastore['pubkey'], header_blob_sig, version, storage_drivers=[driver], storage_drivers_exclusive=True, config_path=config_path, proxy=proxy )
        if 'error' in res:
            log.error("Failed to replicate inode header for {}: {}".format(header_fqid, res['error']))
            driver_failed = True
    '''
    
    if driver_succeeded:
        # at least one write succeeded; make sure the next read loads fresh data 
        # evict 
        GLOBAL_CACHE.evict_inode(datastore_id, inode_hdr['uuid'])

    if driver_failed:
        return {'error': 'Failed to replicate inode data to at least one driver', 'errno': EREMOTEIO}

    # save consistency info
    res = _put_inode_consistency_info(datastore_id, inode_uuid, version, datastore['device_ids'], config_path=config_path)
    return res


def make_inode_tombstones( datastore_id, inode_uuid, device_ids ):
    """
    Make inode tombstones.  The caller must sign them to delete the actual data.
    Return the list of them.
    """
    assert len(device_ids) > 0
    header_id = '{}.{}.hdr'.format(datastore_id, inode_uuid)
    header_tombstones = make_mutable_data_tombstones( device_ids, header_id )

    idata_id = '{}.{}'.format(datastore_id, inode_uuid)
    idata_tombstones = make_mutable_data_tombstones( device_ids, idata_id )

    return header_tombstones + idata_tombstones


def delete_inode_data( datastore, signed_tombstones, proxy=None, config_path=CONFIG_PATH ):
    """
    Given the list of header and idata tombstones, go and delete the actual data
    * signed_tombstones is a list of signed data tombstones for inode headers and idata.

    This is a server-side method.

    TODO: datastore is ambiguous.  We need to be certain that it corresponds to the caller's device-specific datastore

    Return {'status': True} on success
    Return {'error': ...} on error
    """
    global GLOBAL_CACHE

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    datastore_id = datastore_get_id( datastore['pubkey'] )
    drivers = datastore['drivers']
    device_ids = datastore['device_ids']
    
    # identify header and idata tombstones
    inode_tombstones = {}
    for ts in signed_tombstones:
        ts_data = storage.parse_signed_data_tombstone(ts)
        assert ts_data, ts
        
        # format of ts_data['id'] is fqid(datastore_id.inode_uuid[.hdr])
        try:
            dev_id, data_id = storage.parse_fq_data_id(ts_data['id'])
            assert dev_id, "Invalid tombstone data {}".format(ts_data['id'])
            assert data_id, "Invalid tombstone data {}".format(ts_data['id'])

            parts = data_id.split('.', 1)
            assert len(parts) == 2
            assert datastore_id == parts[0]
            
            parts = parts[1].split('.', 1)
            if len(parts) == 2:
                assert parts[1] == 'hdr'

            inode_uuid = parts[0]
            if not inode_tombstones.has_key(inode_uuid):
                inode_tombstones[inode_uuid] = {'header_tombstones': [], 'idata_tombstones': []}

        except Exception as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)
            
            log.error("Invalid tombstone {}".format(ts))
            return {'error': 'Invalid tombstone', 'errno': errno.EINVAL}

        if ts_data['id'].endswith('.hdr'):
            inode_tombstones[inode_uuid]['header_tombstones'].append(ts)
        else:
            inode_tombstones[inode_uuid]['idata_tombstones'].append(ts)
   
    failed_driver = False

    # evict 
    for inode_uuid in inode_tombstones.keys():
        GLOBAL_CACHE.evict_inode(datastore_id, inode_uuid)

    # delete inode idata first
    for inode_uuid in inode_tombstones.keys():

        # delete inode 
        data_id = '{}.{}'.format(datastore_id, inode_uuid)
        res = delete_mutable(data_id, inode_tombstones[inode_uuid]['idata_tombstones'], 
                             proxy=proxy, storage_drivers=drivers, storage_drivers_exclusive=True, device_ids=device_ids, config_path=config_path )

        if 'error' in res:
            log.error("Failed to delete inode {}: {}".format(inode_uuid, res['error']))
            failed_driver = True

    if failed_driver:
        return {'error': 'Failed to delete inode data', 'errno': EREMOTEIO}

    # delete inode headers once all idata is gone
    for inode_uuid in inode_tombstones.keys():
        hdata_id = '{}.{}.hdr'.format(datastore_id, inode_uuid)
        res = delete_mutable(hdata_id, inode_tombstones[inode_uuid]['header_tombstones'], 
                             proxy=proxy, storage_drivers=drivers, storage_drivers_exclusive=True, device_ids=device_ids, config_path=config_path)

        if 'error' in res:
            log.error("Faled to delete idata for {}: {}".format(inode_uuid, res['error']))
            return res

    # evict (again) 
    for inode_uuid in inode_tombstones.keys():
        GLOBAL_CACHE.evict_inode(datastore_id, inode_uuid)

    return {'status': True}



def inode_resolve_path( blockchain_id, datastore, path, data_pubkeys, get_idata=True, force=False, config_path=CONFIG_PATH, proxy=None ):
    """
    Given a fully-qualified data path, the user's datastore record, and a private key,
    go and traverse the directory heirarchy encoded
    in the data path and fetch the data at the leaf.

    This is a server-side method.

    TODO: use data_pubkeys, not datastore_id, for identifying the data owner's device-specific written information (requires token file support)

    Return the resolved path on success.  If the path was '/a/b/c', then return
    {
        '/': {'name': '', 'uuid': ...., 'parent': '',  'inode': directory},
        '/a': {'name': 'a', 'uuid': ...,  'parent': '/', 'inode': directory},
        '/a/b': {'name': 'b', 'uuid': ..., 'parent': '/a', 'inode': directory},
        '/a/b/c': {'name': 'c', 'uuid': ..., 'parent': '/a/b', 'inode' file}
    }

    Return {'error': ..., 'errno': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    log.debug("Resolve {}".format(path))

    def _make_path_entry(  name, child_uuid, child_entry, prefix ):
        """
        Make a path entry to return
        """
        path_ent = {
            'name': name,
            'uuid': child_uuid,
            'inode': child_entry,
            'parent': prefix,
        }
        if len(path_ent['parent']) > 1:
            path_ent['parent'] = path_ent['parent'].rstrip('/')

        return path_ent

    path = posixpath.normpath(path).strip("/")
    path_parts = path.split('/')
    prefix = '/'

    datastore_id = datastore_get_id(datastore['pubkey'])
    drivers = datastore['drivers']
    device_ids = datastore['device_ids']
    root_uuid = datastore['root_uuid']
   
    # getting only the root?
    root_inode = get_inode_data(blockchain_id, datastore_id, root_uuid, MUTABLE_DATUM_DIR_TYPE, drivers, data_pubkeys, force=force, config_path=CONFIG_PATH, proxy=proxy)
    if 'error' in root_inode:
        log.error("Failed to get root inode: {}".format(root_inode['error']))
        return {'error': root_inode['error'], 'errno': root_inode['errno']}

    ret = {
        '/': {'uuid': root_uuid, 'name': '', 'parent': '', 'inode': root_inode['inode']}
    }
 
    if len(path) == 0:
        # looked up /
        return ret
  
    # walk 
    i = 0
    child_uuid = None
    name = None
    cur_dir = root_inode['inode']
    child_entry = None
    child_type = None
    last_header_info = None

    for i in xrange(0, len(path_parts)):

        # find child UUID
        name = path_parts[i]
        child_dirent = cur_dir['idata']['children'].get(name, None)

        if child_dirent is None:
            if BLOCKSTACK_TEST:
                log.debug('No child "{}" in "{}"\ninode:\n{}'.format(name, prefix, json.dumps(cur_dir, indent=4, sort_keys=True)))
            else:
                log.debug('No child "{}" in "{}"'.format(name, prefix))

            return {'error': 'No such file or directory', 'errno': errno.ENOENT}
       
        child_uuid = child_dirent['uuid']
        child_type = child_dirent['type']

        if child_type == MUTABLE_DATUM_FILE_TYPE and not get_idata:
            # done searching, and don't want data
            break
        
        # get child, and only get the idata if it's a directory
        log.debug("Get {} at '{}'".format(child_uuid, '/' + '/'.join(path_parts[:i+1])))
        child_entry = get_inode_data(blockchain_id, datastore_id, child_uuid, child_type, drivers, data_pubkeys, force=force, config_path=CONFIG_PATH, proxy=proxy, file_idata=False)
        if 'error' in child_entry:
            log.error("Failed to get inode {} at {}: {}".format(child_uuid, prefix + name, child_entry['error']))
            return {'error': child_entry['error'], 'errno': child_entry['errno']}

        last_header_info = child_entry
        child_entry = child_entry['inode']
        assert child_entry['type'] == child_dirent['type'], "Corrupt inode {}".format(storage.make_fq_data_id(datastore_id,child_uuid))

        path_ent = _make_path_entry(name, child_uuid, child_entry, prefix)
        ret[prefix + name] = path_ent
    
        if child_type == MUTABLE_DATUM_FILE_TYPE or i == len(path_parts) - 1:
            # only care if this is a file 
            if child_type != MUTABLE_DATUM_FILE_TYPE:
                last_header_info = None

            break

        # keep walking
        cur_dir = child_entry
        prefix += name + '/'


    # did we reach the end?
    if i+1 < len(path_parts):
        log.debug('Out of path at "{}" (stopped at {} in {})'.format(prefix + name, i, path_parts))
        return {'error': 'Not a directory', 'errno': errno.ENOTDIR}

    if child_type == MUTABLE_DATUM_DIR_TYPE or (get_idata and child_type == MUTABLE_DATUM_FILE_TYPE):
        # get file data too 
        # NOTE: last_header_info will be the return value from the last call to get_inode_data()
        assert ret.has_key(prefix + name), "BUG: missing {}".format(prefix + name)
        child_entry = get_inode_data(blockchain_id, datastore_id, child_uuid, child_type, drivers, data_pubkeys, force=force, config_path=CONFIG_PATH, proxy=proxy, header_info=last_header_info )

    else:
        # get only inode header.
        # didn't request idata, so add a path entry here
        assert not ret.has_key(prefix + name), "BUG: already defined {}".format(prefix + name)

        path_ent = _make_path_entry(name, child_uuid, child_entry, prefix)
        ret[prefix + name] = path_ent

        child_entry = get_inode_header(blockchain_id, datastore_id, child_uuid, drivers, data_pubkeys, force=force, config_path=config_path, proxy=proxy)

    if 'error' in child_entry:
        log.error("Failed to get file data for {} at {}: {}".format(child_uuid, prefix + name, child_entry['error']))
        return {'error': child_entry['error'], 'errno': child_entry['errno']}
    
    child_entry = child_entry['inode']

    # update ret
    ret[prefix + name]['inode'] = child_entry
    
    log.debug("Resolved /{}".format(path))
    return ret


def _mutable_data_make_inode( inode_type, owner_address, inode_uuid, data_hash=None ):
    """
    Set up the basic properties of an inode.
    """
    ret = {
        'type':  inode_type,
        'owner': owner_address,
        'uuid': inode_uuid,
    }

    if data_hash:
        # meant for headers only
        ret['data_hash'] = data_hash

    return ret


def _mutable_data_inode_hash( inode_str ):
    """
    Calculate the inode hash
    """
    h = hashlib.sha256()
    h.update( inode_str )

    if BLOCKSTACK_TEST:
        d_fmt = inode_str
        if len(inode_str) > 100:
            d_fmt = inode_str[:100] + '...'

        log.debug("Hash is {} from '{}'".format(h.hexdigest(), d_fmt))

    return h.hexdigest()


def _mutable_data_dir_link( parent_dir, child_type, child_name, child_uuid, exists=False ):
    """
    Attach a child inode to a diretory.
    Update the directory version
    Return the new parent directory, and the added dirent
    """
    assert 'idata' in parent_dir
    assert exists or child_name not in parent_dir['idata']['children'].keys()

    new_dirent = {
        'uuid': child_uuid,
        'type': child_type, 
        'version': 1,
    }

    if parent_dir['idata']['children'].has_key(child_name):
        new_dirent['version'] = parent_dir['idata']['children'][child_name]['version'] + 1

    parent_dir['idata']['children'][child_name] = new_dirent
    parent_dir['version'] += 1

    return parent_dir, new_dirent


def _mutable_data_dir_unlink( parent_dir, child_name ):
    """
    Detach a child inode from a directory.
    Update the directory version
    Return the new parent directory.
    """
    assert 'idata' in parent_dir
    assert child_name in parent_dir['idata']['children'].keys()

    dead_child = parent_dir['idata']['children'][child_name]
    del parent_dir['idata']['children'][child_name]
    parent_dir['version'] += 1

    return parent_dir, dead_child


def _parse_data_path( data_path ):
    """
    Parse a data path into various helpful fields
    """
    path = posixpath.normpath(data_path).strip('/')
    path_parts = path.split('/')

    name = path_parts[-1]
    dirpath = '/' + '/'.join(path_parts[:-1])
    path = '/' + '/'.join(path_parts)

    return {'iname': name, 'parent_path': dirpath, 'data_path': path}


def inode_path_lookup(blockchain_id, datastore, data_path, data_pubkeys, get_idata=True, force=False, config_path=CONFIG_PATH, proxy=None ):
    """
    Look up all the inodes along the given fully-qualified path, verifying them and ensuring that they're fresh along the way.

    This is a server-side method.

    Return {'status': True, 'path_info': path info, 'inode_info': inode info} on success
    Return {'error': ..., 'errno': ...} on error
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    log.debug("Lookup {}:{} (idata: {})".format(datastore_get_id(datastore['pubkey']), data_path, get_idata))

    info = _parse_data_path( data_path )

    name = info['iname']
    dirpath = info['parent_path']
    data_path = info['data_path']

    # find the parent directory
    path_info = inode_resolve_path(blockchain_id, datastore, data_path, data_pubkeys, get_idata=get_idata, force=force, config_path=config_path, proxy=proxy )
    if 'error' in path_info:
        log.error('Failed to resolve {}'.format(dirpath))
        return path_info

    assert data_path in path_info.keys(), "Invalid path data, missing {}:\n{}".format(data_path, json.dumps(path_info, indent=4, sort_keys=True))
    inode_info = path_info[data_path]

    return {'status': True, 'path_info': path_info, 'inode_info': inode_info}


def datastore_inodes_check_consistent( datastore_id, inode_headers, creates, exists, device_ids, config_path=CONFIG_PATH ):
    """
    Given a list of signed, serialized inode headers, go and verify that they're at least as
    new as the local versioning information we have.  Also, if we expect to create an inode,
    verify that we haven't seen it yet.

    NOTE: datastore_id refers to the device-specific datastore record

    This is the server-side method.

    Return {'status': True} if everything is in order
    Return {'error': ..., 'errno': ...} otherwise
    """
    assert len(creates) == len(inode_headers)
    assert len(exists) == len(inode_headers)

    for i in xrange(0, len(inode_headers)):
        inode_header_str = inode_headers[i]
        create = creates[i]
        exist = exists[i]

        # parse 
        header_info = analyze_inode_header_blob(datastore_id, inode_header_str)
        if 'error' in header_info:
            return header_info

        version = header_info['version']
        device_id = header_info['device_id']
        header_id = header_info['header_id']

        if device_id not in device_ids:
            log.error("Device {} not in datastore".format(device_id))
            return {'error': 'Inode not from a datastore device', 'errno': errno.EXDEV}

        # check version
        version_info = get_mutable_data_version( header_id, device_ids, config_path=config_path )
        if 'error' in version_info:
            log.error("Failed to query version info for {}".format(header_id))
            return {'error': 'Failed to query version info for inode', 'errno': errno.EIO}

        if version < version_info['version']:
            # stale 
            log.error("Stale inode {}".format(header_id))
            return {'error': 'Stale inode', 'errno': errno.ESTALE}

        if version_info['version'] > 0 and create:
            # exists but we expected to create
            log.error("Inode {} exists".format(header_id))
            return {'error': 'Inode exists', 'errno': errno.EEXIST}

        if version_info['version'] == 0 and exist:
            # does not exist, but we expected it
            log.error("Inode {} does not exist".format(header_id))
            return {'error': 'Inode does not exist', 'errno': errno.ENOENT}

    return {'status': True}


def datastore_inodes_verify( datastore_pubkey, inode_headers, inode_payloads, inode_signatures, inode_tombstones, device_ids, config_path=CONFIG_PATH ):
    """
    Given signed inodes, tombstones, and payloads, verify that they were all signed.
    
    NOTE: datastore_pubkey corresponds to the device-specific public key of the caller

    Return {'status': True} if we're all good
    Return {'error': ..., 'errno': ...} on error
    """
    assert len(inode_headers) == len(inode_payloads)
    assert len(inode_payloads) == len(inode_signatures)
    
    datastore_id = datastore_get_id(datastore_pubkey)

    # verify signatures and hashes
    for i in xrange(0, len(inode_headers)):
        header_blob = inode_headers[i]
        payload = inode_payloads[i]
        signature = inode_signatures[i]

        try:
            res = storage.verify_data_payload( header_blob, datastore_pubkey, signature )
        except AssertionError as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            log.error("Invalid public key or signature ({}, {})".format(datastore_pubkey, signature))
            return {'error': 'Invalid public key or signature', 'errno': errno.EINVAL}

        if not res:
            log.debug("Failed to verify {} ({}) with {}".format(header_blob, signature, datastore_pubkey))
            return {'error': 'Failed to verify inode signature', 'errno': errno.EINVAL}

        # check hash 
        payload_hash = storage.hash_data_payload(payload)
        header_mutable_data_struct = data_blob_parse(header_blob)
        header_struct = data_blob_parse(header_mutable_data_struct['data'])
        if payload_hash != header_struct['data_hash']:
            log.debug("Inode hash mismatch: {} != {}".format(payload_hash, header_struct['data_hash']))
            return {'error': "Payload {} does not match inode header {}".format(payload_hash, header_struct['data_hash']), 'errno': errno.EINVAL}

    if len(inode_tombstones) > 0:
        res = verify_mutable_data_tombstones( inode_tombstones, datastore_pubkey, device_ids=device_ids )
        if not res:
            return {'error': 'Failed to verify data tombstones', 'errno': errno.EINVAL}

    return {'status': True}


def datastore_operation_check( datastore_pubkey, inode_headers, inode_payloads, inode_signatures, inode_tombstones, creates, exists, device_ids, config_path=CONFIG_PATH ):
    """
    Verify that each header and tombstone is signed, that each payload's hash is in the header, and that each 
    inode header is a current or later version
    
    This is a server-side method.

    NOTE: datastore_pubkey corresponds to the device-specific datastore

    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    datastore_id = datastore_get_id(datastore_pubkey)
    res = datastore_inodes_verify( datastore_pubkey, inode_headers, inode_payloads, inode_signatures, inode_tombstones, device_ids, config_path=config_path)
    if 'error' in res:
        log.debug("Failed to verify inode and tombstone signatures") 
        return res

    res = datastore_inodes_check_consistent( datastore_id, inode_headers, creates, exists, device_ids, config_path=config_path )
    if 'error' in res:
        log.debug("Failed to verify data is consistent")
        return res

    return {'status': True}


def datastore_do_inode_operation( datastore, inode_headers, inode_payloads, inode_signatures, inode_tombstones, config_path=CONFIG_PATH, proxy=None ):
    """
    Given signed inodes, tombstones, and payloads, go and actually put/delete the data.
    This is a server-side method.

    * inode_headers[i], inode_payloads[i], inode_signatures[i] all correspond to the same inode.
    * inode_tombstones is a list of tombstones for the same inode (at most one inode will be deleted per data operation)

    Do not call this method directly.  Call the op-specific helper methods instead.

    Return {'status': True} on success
    Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    assert len(inode_headers) == len(inode_payloads)
    assert len(inode_payloads) == len(inode_signatures)

    # process tombstones first
    if len(inode_tombstones) > 0:
        res = delete_inode_data( datastore, inode_tombstones, proxy=proxy, config_path=config_path)
        if 'error' in res:
            log.debug("Failed to delete inode with {}".format(','.join(inode_tombstones)))
            return res

    # store data
    for i in xrange(0, len(inode_headers)):
        header_blob = inode_headers[i]
        payload = inode_payloads[i]
        signature = inode_signatures[i]

        res = put_inode_data( datastore, header_blob, signature, payload, config_path=config_path, proxy=proxy)
        if 'error' in res:
            log.debug("Failed to put inode {}".format(header_blob))
            return res

    return {'status': True}


def datastore_serialize_and_sign( datastore, data_privkey):
    """
    Serialize and sign a datastore for a request
    """
    datastore_str = json.dumps(datastore, sort_keys=True)
    datastore_sig = sign_raw_data(datastore_str, data_privkey)
    return {'str': datastore_str, 'sig': datastore_sig}


def datastore_mkdir_make_inodes(api_client, datastore, data_path, data_pubkeys, reader_pubkeys=[], parent_dir=None, force=False, config_path=CONFIG_PATH):
    """
    Make a directory at the given path.  The parent directory must exist.
    Do not actually carry out the mutations; only generate the requisite inodes.

    This is a client-side method.
   
    TODO: rework datastore and datastore_id; we need to be sure that we're making inodes to write to this device's datastore and data_pubkeys corresponds to the owner's other devices
   
    Return {'status': True, 'inodes': [...], 'payloads': [...], 'tombstones': [...]} on success
    Return {'error': ..., 'errno': ...} on failure (optionally with 'stored_child': True set)
    """

    datastore_id = datastore_get_id(datastore['pubkey'])
    path_info = _parse_data_path( data_path )
    parent_path = path_info['parent_path']
    data_path = path_info['data_path']
    name = path_info['iname']

    log.debug("mkdir {}:{}".format(datastore_id, data_path))

    drivers = datastore['drivers']
    device_ids = datastore['device_ids']

    if parent_dir is None:
        parent_info = api_client.backend_datastore_lookup(None, datastore, 'directories', parent_path, data_pubkeys, extended=True, force=force )
        if 'error' in parent_info:
            log.error('Failed to resolve {}'.format(parent_path))
            return parent_info
       
        parent_dir_info = parent_info['inode_info']
        parent_dir = parent_dir_info['inode']

    parent_uuid = parent_dir['uuid']

    if parent_dir['type'] != MUTABLE_DATUM_DIR_TYPE:
        log.error('Not a directory: {}'.format(parent_path))
        return {'error': 'Not a directory', 'errno': errno.ENOTDIR}

    # does a file or directory already exist?
    if name in parent_dir['idata']['children'].keys():
        log.error('Already exists: {}'.format(name))
        return {'error': 'Entry already exists', 'errno': errno.EEXIST}
    
    # make a directory!
    child_uuid = str(uuid.uuid4())

    # update parent 
    parent_dir, child_dirent = _mutable_data_dir_link( parent_dir, MUTABLE_DATUM_DIR_TYPE, name, child_uuid )

    # make the new inodes
    child_dir_info = make_dir_inode_data( datastore_id, datastore_id, child_uuid, {}, device_ids, reader_pubkeys=reader_pubkeys, config_path=config_path, min_version=parent_dir['version'], create=True )
    if 'error' in child_dir_info:
        log.error("Failed to create directory {}: {}".format(data_path, child_dir_info['error']))
        return {'error': 'Failed to create child directory', 'errno': errno.EIO}

    parent_dir_info = make_dir_inode_data( datastore_id, datastore_id, parent_uuid, parent_dir['idata']['children'], device_ids, reader_pubkeys=parent_dir['reader_pubkeys'], min_version=parent_dir['version'], config_path=config_path )
    if 'error' in parent_dir_info:
        log.error("Failed to update directory {}: {}".format(parent_path, parent_dir_info['error']))
        return {'error': 'Failed to create parent directory', 'errno': errno.EIO}
        

    ret = {
        'status': True,
        'inodes': [
            child_dir_info['header'],
            parent_dir_info['header'],
        ],
        'payloads': [
            child_dir_info['idata'],
            parent_dir_info['idata'],
        ],
        'tombstones': []
    }

    return ret


def datastore_mkdir_put_inodes( datastore, data_path, header_blobs, payloads, signatures, tombstones, config_path=CONFIG_PATH, proxy=None ):
    """
    Given the header blobs and payloads from datastore_mkdir_make_inodes() and client-given signatures,
    go and store them all.

    This is a server-side method.

    Order matters:
    header_blobs[0], payloads[0], and signatures[0] are for the child.
    header_blobs[1], payloads[1], and signatures[1] are for the parent.

    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    assert len(header_blobs) == 2
    assert len(payloads) == 2
    assert len(signatures) == 2
    assert len(tombstones) == 0
    creates = [True, False]     # create child
    exists = [False, True]      # parent must exist

    device_ids = datastore['device_ids']
    data_pubkey = datastore['pubkey']
    res = datastore_operation_check( data_pubkey, header_blobs, payloads, signatures, tombstones, creates, exists, device_ids, config_path=config_path )
    if 'error' in res:
        log.debug("Failed to check operation: {}".format(res['error']))
        return res

    return datastore_do_inode_operation( datastore, header_blobs, payloads, signatures, tombstones, config_path=config_path, proxy=proxy )


def datastore_mkdir(api_client, datastore, data_path, data_privkey_hex, data_pubkeys, parent_dir=None, force=False, config_path=CONFIG_PATH):
    """
    Method to make a directory.
    * generate the directory inodes
    * sign them
    * replicate them.

    This is a client-side method

    TODO: rework datastore and datastore_id; we need to be sure that we're making inodes to write to this device's datastore and data_pubkeys corresponds to the owner's other devices

    Return {'status': True} on success
    Return {'error': ...} on error
    """
    data_pubkey = get_pubkey_hex(str(data_privkey_hex))
    datastore_id = datastore_get_id(data_pubkey)
    device_ids = datastore['device_ids']
    drivers = datastore['drivers']

    inode_info = datastore_mkdir_make_inodes( api_client, datastore, data_path, data_pubkeys, parent_dir=parent_dir, force=force, config_path=config_path )
    if 'error' in inode_info:
        return inode_info

    inode_signatures = []
    for inode_header_blob in inode_info['inodes']:
        signature = sign_inode_header_blob( inode_header_blob, data_privkey_hex )
        inode_signatures.append( signature )
    
    datastore_info = datastore_serialize_and_sign(datastore, data_privkey_hex)
    res = api_client.backend_datastore_mkdir( datastore_info['str'], datastore_info['sig'], data_path, inode_info['inodes'], inode_info['payloads'], inode_signatures, inode_info['tombstones'] )
    if 'error' in res:
        log.debug("Failed to put mkdir inodes")
        return res

    return {'status': True}


def datastore_rmdir_make_inodes(api_client, datastore, data_path, data_pubkeys, parent_dir=None, force=False, config_path=CONFIG_PATH ):
    """
    Remove a directory at the given path.  The directory must be empty.
    This does not actually carry out the operation, but instead generates the new parent directory inode blobs
    and generates tombstones for the directory to be deleted.  Both must be signed and acted upon.

    TODO: rework datastore and datastore_id; we need to be sure that we're making inodes to write to this device's datastore and data_pubkeys corresponds to the owner's other devices

    Return {'status': True, 'blobs': [...], 'payloads': [...], 'tombstones': [...]} on success
    Return {'error': ..., 'errno': ...} on error
    """
   
    datastore_id = datastore_get_id(datastore['pubkey'])
    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    name = path_info['iname']
    creates = [False, False]

    if data_path == '/':
        # can't do this 
        log.error("Will not delete /")
        return {'error': 'Tried to delete root', 'errno': errno.EINVAL}

    drivers = datastore['drivers']
    device_ids = datastore['device_ids']

    log.debug("rmdir {}:{} (force={})".format(datastore_id, data_path, force))

    parent_dir_uuid = None
    parent_dir_inode = None

    if parent_dir is None:
        dir_info = api_client.backend_datastore_lookup(None, datastore, 'directories', data_path, data_pubkeys, extended=True, force=force )
        if 'error' in dir_info:
            log.error('Failed to resolve {}'.format(data_path))
            return {'error': dir_info['error'], 'errno': dir_info['errno']}

        # is this a directory?
        dir_inode_info = dir_info['inode_info']
        dir_inode_uuid = dir_inode_info['uuid']
        dir_inode = dir_inode_info['inode']

        if dir_inode['type'] != MUTABLE_DATUM_DIR_TYPE:
            log.error('Not a directory: {}'.format(data_path))
            return {'error': 'Not a directory', 'errno': errno.ENOTDIR}
    
        # get parent of this directory
        parent_path = dir_inode_info['parent']
        parent_dir_inode_info = dir_info['path_info'][parent_path]
        parent_dir_uuid = parent_dir_inode_info['uuid']
        parent_dir_inode = parent_dir_inode_info['inode']

    else:
        parent_dir_inode = parent_dir
        parent_dir_uuid = parent_dir['uuid']

    # is this directory empty?
    if len(dir_inode['idata']['children']) > 0:
        log.error("Directory {} has {} entries".format(data_path, len(dir_inode['idata']['children'])))
        return {'error': 'Directory not empty', 'errno': errno.ENOTEMPTY}

    # update the parent 
    parent_dir_inode, dead_child = _mutable_data_dir_unlink( parent_dir_inode, name )
    min_version = max(dead_child['version'], parent_dir_inode['version'])

    parent_dir_info = make_dir_inode_data( datastore_id, datastore_id, parent_dir_uuid, parent_dir_inode['idata']['children'], device_ids,
                                           reader_pubkeys=parent_dir_inode['reader_pubkeys'], min_version=min_version, config_path=config_path )

    if 'error' in parent_dir_info:
        log.error("Failed to update directory {}: {}".format(os.path.dirname(data_path), parent_dir_info['error']))
        return {'error': 'Failed to create parent directory', 'errno': errno.EIO}

    # make tombstones for the child
    child_tombstones = make_inode_tombstones( datastore_id, dir_inode_uuid, device_ids)
    ret = {
        'status': True,
        'inodes': [
            parent_dir_info['header'],
        ],
        'payloads': [
            parent_dir_info['idata'],
        ],
        'tombstones': child_tombstones
    }

    return ret


def datastore_rmdir_put_inodes( datastore, data_path, header_blobs, payloads, signatures, tombstones, config_path=CONFIG_PATH, proxy=None ):
    """
    Given the header blobs and payloads from datastore_rmdir_make_inodes() and cliet-given signatures and signed tombstones,
    go and store them all.

    Order matters:
    header_blobs[0], payloads[0], and signatures[0] are for the parent
    tombstones[0] is for the child deleted

    This is a server-side method.

    TODO: rework datastore and datastore_id; we need to be sure that we're making inodes to write to this device's datastore and data_pubkeys corresponds to the owner's other devices

    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    assert len(header_blobs) == 1, header_blobs
    assert len(payloads) == 1, payloads
    assert len(signatures) == 1, signatures
    assert len(tombstones) >= 1, tombstones
    creates = [False]
    exists = [True]

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    # directory must actually be empty 

    device_ids = datastore['device_ids']
    data_pubkey = datastore['pubkey']
    res = datastore_operation_check( data_pubkey, header_blobs, payloads, signatures, tombstones, creates, exists, device_ids, config_path=config_path )
    if 'error' in res:
        log.debug("Failed to check operation: {}".format(res['error']))
        return res

    return datastore_do_inode_operation( datastore, header_blobs, payloads, signatures, tombstones, config_path=config_path, proxy=proxy )


def datastore_rmdir(api_client, datastore, data_path, data_privkey_hex, data_pubkeys, force=False, config_path=CONFIG_PATH):
    """
    Client-side method to removing a directory.
    * generate the directory inodes
    * sign them
    * replicate them.

    TODO: rework datastore and datastore_id; we need to be sure that we're making inodes to write to this device's datastore and data_pubkeys corresponds to the owner's other devices

    Return {'status': True} on success
    Return {'error': ...} on error
    """
    data_pubkey = get_pubkey_hex(str(data_privkey_hex))
    datastore_id = datastore_get_id(data_pubkey)
    device_ids = datastore['device_ids']
    drivers = datastore['drivers']

    inode_info = datastore_rmdir_make_inodes( api_client, datastore, data_path, data_pubkeys, force=force, config_path=config_path )
    if 'error' in inode_info:
        return inode_info

    inode_signatures = []
    for inode_header_blob in inode_info['inodes']:
        signature = sign_inode_header_blob( inode_header_blob, data_privkey_hex )
        inode_signatures.append( signature )

    signed_tombstones = sign_mutable_data_tombstones( inode_info['tombstones'], data_privkey_hex )
    assert len(signed_tombstones) > 0

    datastore_info = datastore_serialize_and_sign(datastore, data_privkey_hex)
    res = api_client.backend_datastore_rmdir( datastore_info['str'], datastore_info['sig'], data_path, inode_info['inodes'], inode_info['payloads'], inode_signatures, signed_tombstones )
    if 'error' in res:
        log.debug("Failed to put rmdir inodes")
        return res

    return {'status': True}


def datastore_getfile(api_client, blockchain_id, datastore, data_path, data_pubkeys, extended=False, force=False, config_path=CONFIG_PATH ):
    """
    Get a file identified by a path.

    TODO: rework datastore and datastore_id; we need to be sure that we're making inodes to write to this device's datastore and data_pubkeys corresponds to the owner's other devices

    Return {'status': True, 'data': data} on success, if not extended
    Return {'status': True, 'inode_info': inode and data, 'path_info': path info}
    Return {'error': ..., 'errno': ...} on error
    """

    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    
    datastore_id = datastore_get_id(datastore['pubkey'])
    drivers = datastore['drivers']
    
    log.debug("getfile {}:{}".format(datastore_id, data_path))

    file_info = api_client.backend_datastore_lookup(blockchain_id, datastore, 'files', data_path, data_pubkeys, force=force, extended=True, idata=True )
    if 'error' in file_info:
        log.error("Failed to resolve {}".format(data_path))
        return file_info

    if file_info['inode_info']['inode']['type'] != MUTABLE_DATUM_FILE_TYPE:
        log.error("Not a file: {}".format(data_path))
        return {'error': 'Not a file', 'errno': errno.EISDIR}

    ret = None
    if extended:
        ret = {
            'status': True,
            'inode_info': file_info['inode_info'],
            'path_info': file_info['path_info'],
        }

    else:
        ret = {
            'status': True,
            'data': file_info['inode_info']['inode']['idata']
        }

    return ret


def datastore_listdir(api_client, blockchain_id, datastore, data_path, data_pubkeys, extended=False, force=False, config_path=CONFIG_PATH ):
    """
    Get a file identified by a path.

    TODO: rework datastore and datastore_id; we need to be sure that we're making inodes to write to this device's datastore and data_pubkeys corresponds to the owner's other devices

    Return the {'status': True, 'data': directory information} on success, or if extended==True, then return {'status': True, 'inode_info': ..., 'path_info': ...}
    Return {'error': ..., 'errno': ...} on error
    """

    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    
    datastore_id = datastore_get_id(datastore['pubkey'])
    drivers = datastore['drivers']
    
    log.debug("listdir {}:{}".format(datastore_id, data_path))

    dir_info = api_client.backend_datastore_lookup(blockchain_id, datastore, 'directories', data_path, data_pubkeys, extended=True, force=force )
    if 'error' in dir_info:
        log.error("Failed to resolve {}".format(data_path))
        return dir_info

    if dir_info['inode_info']['inode']['type'] != MUTABLE_DATUM_DIR_TYPE:
        log.error("Not a directory: {}".format(data_path))
        return {'error': 'Not a directory', 'errno': errno.ENOTDIR}

    # TODO: verify idata's header matches header for this inode

    ret = {
        'status': True,
    }

    ret = None
    if extended:
        ret = {
            'status': True,
            'path_info': dir_info['path_info'],
            'inode_info': dir_info['inode_info'],
        }

    else:
        ret = {
            'status': True,
            'data': dir_info['inode_info']['inode']['idata']
        }

    return ret


def datastore_putfile_make_inodes(api_client, datastore, data_path, file_data_hash, data_pubkeys, readers=[], parent_dir=None, create=False, force=False, config_path=CONFIG_PATH ):
    """
    Store a file identified by a path.
    If @create is True, then will only succeed if created.

    Does not actually upload data, but instead makes new inode blobs for the 
    parent directory and the new file inode.

    file_data_hash needs to be a payload (netstring) hash, i.e., sha256( "{}:{},".format(len(payload), payload) )

    TODO: rework datastore and datastore_id; we need to be sure that we're making inodes to write to this device's datastore and data_pubkeys corresponds to the owner's other devices

    Return {'status': True, 'inodes': [...], 'payloads': [...], 'tombstones': [...]} on success
    Return {'error': ..., 'errno': ...} on error.
    """

    datastore_id = datastore_get_id(datastore['pubkey'])
    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    name = path_info['iname']
    parent_dirpath = path_info['parent_path']

    drivers = datastore['drivers']
    device_ids = datastore['device_ids']

    log.debug("putfile {}:{}".format(datastore_id, data_path))
    
    parent_dir_inode = None
    parent_uuid = None

    if parent_dir is None:
        parent_path_info = api_client.backend_datastore_lookup(None, datastore, 'directories', parent_dirpath, data_pubkeys, extended=True, force=force )
        if 'error' in parent_path_info:
            log.error("Failed to resolve {}".format(data_path))
            return parent_path_info

        parent_dir_info = parent_path_info['inode_info']
        parent_uuid = parent_dir_info['uuid']
        parent_dir_inode = parent_dir_info['inode']
    else:
        parent_dir_inode = parent_dir
        parent_uuid = parent_dir['uuid']

    # make sure the file doesn't exist
    if name in parent_dir_inode['idata']['children'].keys() and create:
        # already exists
        log.error('Already exists: {}'.format(data_path))
        return {'error': 'Already exists', 'errno': errno.EEXIST}

    child_uuid = None

    # exists?
    if name in parent_dir_inode['idata']['children'].keys():
        child_uuid = parent_dir_inode['idata']['children'][name]['uuid']
        parent_dir_inode, child_dirent = _mutable_data_dir_link( parent_dir_inode, MUTABLE_DATUM_FILE_TYPE, name, child_uuid, exists=True )

    else:
        # make a file!
        child_uuid = str(uuid.uuid4())
        parent_dir_inode, child_dirent = _mutable_data_dir_link( parent_dir_inode, MUTABLE_DATUM_FILE_TYPE, name, child_uuid )
   
    min_version = max(parent_dir_inode['version'], child_dirent['version'])
    log.debug("Version of {} ({}) will be max({}, {}) = {}".format(data_path, child_uuid, parent_dir_inode['version'], child_dirent['version'], min_version))

    # make the new inode info
    child_file_info = make_file_inode_data( datastore_id, datastore_id, child_uuid, file_data_hash, device_ids, readers=[], config_path=config_path, min_version=min_version, create=create )
    if 'error' in child_file_info:
        log.error("Failed to create file {}: {}".format(data_path, child_file_info['error']))
        return {'error': 'Failed to create file', 'errno': errno.EIO}

    parent_dir_info = make_dir_inode_data( datastore_id, datastore_id, parent_uuid, parent_dir_inode['idata']['children'], device_ids, reader_pubkeys=parent_dir_inode['reader_pubkeys'], min_version=min_version, config_path=config_path )
    if 'error' in parent_dir_info:
        log.error("Failed to update directory {}: {}".format(parent_dirpath, parent_dir_info['error']))
        return {'error': 'Failed to create parent directory', 'errno': errno.EIO}

    ret = {
        'status': True,
        'inodes': [
            child_file_info['header'],
            parent_dir_info['header'],
        ],
        'payloads': [
            None,   # caller has this
            parent_dir_info['idata'],
        ],
        'tombstones': [],    # nothing deleted
    }

    return ret


def datastore_putfile_put_inodes( datastore, data_path, header_blobs, payloads, signatures, tombstones, create=False, exist=False, config_path=CONFIG_PATH, proxy=None ):
    """
    Given the header blobs and payloads from datastore_putfile_make_inodes() and client-given signatures and the actual file data,
    go and store them all.

    TODO: rework datastore and datastore_id; we need to be sure that we're making inodes to write to this device's datastore and data_pubkeys corresponds to the owner's other devices

    Order matters:
    header_blobs[0], payloads[0], and signatures[0] are for the parent directory
    header_blobs[1], payloads[1], and signatures[1] are for the child file.
    payloads[1] should be the client-supplied payload 
    tombstones[0] is for the child deleted

    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    assert len(header_blobs) == 2
    assert len(payloads) == 2
    assert len(signatures) == 2
    assert len(tombstones) == 0
    creates = [create, False]    # parent will not be created
    exists = [exist, True]      # parent must exist

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    device_ids = datastore['device_ids']
    data_pubkey = datastore['pubkey']
    res = datastore_operation_check( data_pubkey, header_blobs, payloads, signatures, tombstones, creates, exists, device_ids, config_path=config_path )
    if 'error' in res:
        log.debug("Failed to check operation: {}".format(res['error']))
        return res

    return datastore_do_inode_operation( datastore, header_blobs, payloads, signatures, tombstones, config_path=config_path, proxy=proxy )


def datastore_putfile(api_client, datastore, data_path, file_data_bin, data_privkey_hex, data_pubkeys, create=False, exist=False, force=False, config_path=CONFIG_PATH):
    """
    Client-side method to store a file.  MEANT FOR TESTING PURPOSES
    * generate the directory inodes
    * sign them
    * replicate them.

    TODO: rework datastore and datastore_id; we need to be sure that we're making inodes to write to this device's datastore and data_pubkeys corresponds to the owner's other devices

    Return {'status': True} on success
    Return {'error': ...} on error
    """
    data_pubkey = get_pubkey_hex(str(data_privkey_hex))
    datastore_id = datastore_get_id(data_pubkey)
    device_ids = datastore['device_ids']
    drivers = datastore['drivers']
   
    file_hash = storage.hash_data_payload(file_data_bin)

    inode_info = datastore_putfile_make_inodes( api_client, datastore, data_path, file_hash, data_pubkeys, create=create, force=force, config_path=config_path )
    if 'error' in inode_info:
        return inode_info

    inode_signatures = []
    for inode_header_blob in inode_info['inodes']:
        signature = sign_inode_header_blob( inode_header_blob, data_privkey_hex )
        inode_signatures.append( signature )

    assert inode_info['payloads'][0] is None
    inode_info['payloads'][0] = file_data_bin

    datastore_info = datastore_serialize_and_sign(datastore, data_privkey_hex)
    res = api_client.backend_datastore_putfile( datastore_info['str'], datastore_info['sig'], data_path, inode_info['inodes'], inode_info['payloads'], inode_signatures, inode_info['tombstones'], create=create, exist=exist )
    if 'error' in res:
        log.debug("Failed to put putfile inodes")
        return res

    return {'status': True}


def datastore_deletefile_make_inodes(api_client, datastore, data_path, data_pubkeys, parent_dir=None, force=False, config_path=CONFIG_PATH ):
    """
    Delete a file from a directory.
    Don't actually delete the file; just generate a new parent inode and child tombstones.

    TODO: rework datastore and datastore_id; we need to be sure that we're making inodes to write to this device's datastore and data_pubkeys corresponds to the owner's other devices

    Return {'status': True, 'blobs': [...], 'tombstones': [...]} on success
    Return {'error': ..., 'errno': ...} on error
    """
    datastore_id = datastore_get_id(datastore['pubkey'])
    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    name = path_info['iname']
    parent_dirpath = path_info['parent_path']

    drivers = datastore['drivers']
    device_ids = datastore['device_ids']

    log.debug("deletefile {}:{}".format(datastore_id, data_path))
    
    parent_dir_inode = None
    parent_dir_uuid = None

    if parent_dir is None:
        file_path_info = api_client.backend_datastore_lookup(None, datastore, 'files', data_path, data_pubkeys, idata=False, force=force, extended=True )
        if 'error' in file_path_info:
            log.error('Failed to resolve {}'.format(data_path))
            return file_path_info

        file_inode_info = file_path_info['inode_info']
        file_uuid = file_inode_info['uuid']
        file_inode = file_inode_info['inode']
    
        # is this a directory?
        if file_inode['type'] != MUTABLE_DATUM_FILE_TYPE:
            log.error('Not a file: {}'.format(data_path))
            return {'error': 'Not a file', 'errno': errno.EISDIR}
    
        # get parent of this directory
        parent_dir_inode_info = file_path_info['path_info'][file_inode_info['parent']]
        parent_dir_uuid = parent_dir_inode_info['uuid']
        parent_dir_inode = parent_dir_inode_info['inode']

    else:
        parent_dir_inode = parent_dir
        parent_dir_uuid = parent_dir['uuid']

    # unlink 
    parent_dir_inode, dead_child = _mutable_data_dir_unlink(parent_dir_inode, name)
    min_version = max(parent_dir_inode['version'], dead_child['version'])

    # update the parent 
    parent_dir_info = make_dir_inode_data( datastore_id, datastore_id, parent_dir_uuid, parent_dir_inode['idata']['children'], device_ids,
                                           reader_pubkeys=parent_dir_inode['reader_pubkeys'], min_version=min_version, config_path=config_path )

    if 'error' in parent_dir_info:
        log.error("Failed to update directory {}: {}".format(parent_dir, parent_dir_info['error']))
        return {'error': 'Failed to create parent directory', 'errno': errno.EIO}

    # make a child tombstone 
    child_tombstones = make_inode_tombstones( datastore_id, file_uuid, device_ids)
    ret = {
        'status': True,
        'inodes': [
            parent_dir_info['header'],
        ],
        'payloads': [
            parent_dir_info['idata']
        ],
        'tombstones': child_tombstones
    }

    return ret


def datastore_deletefile_put_inodes( datastore, data_path, header_blobs, payloads, signatures, tombstones, config_path=CONFIG_PATH, proxy=None ):
    """
    Given the header blobs and payloads from datastore_deletfile_make_inodes() and cliet-given signatures and signed tombstones,
    go and store them all.

    TODO: rework datastore and datastore_id; we need to be sure that we're making inodes to write to this device's datastore and data_pubkeys corresponds to the owner's other devices

    Order matters:
    header_blobs[0], payloads[0], and signatures[0] are for the parent
    tombstones[0] is for the child deleted

    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    assert len(header_blobs) == 1
    assert len(payloads) == 1
    assert len(signatures) == 1
    assert len(tombstones) >= 1
    creates = [False]
    exists = [True]

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    device_ids = datastore['device_ids']
    data_pubkey = datastore['pubkey']
    res = datastore_operation_check( data_pubkey, header_blobs, payloads, signatures, tombstones, creates, exists, device_ids, config_path=config_path )
    if 'error' in res:
        log.debug("Failed to check operation: {}".format(res['error']))
        return res

    return datastore_do_inode_operation( datastore, header_blobs, payloads, signatures, tombstones, config_path=config_path, proxy=proxy )


def datastore_deletefile(api_client, datastore, data_path, data_privkey_hex, data_pubkeys, force=False, config_path=CONFIG_PATH):
    """
    Client-side method to removing a file.  MEANT FOR TESTING PURPOSES
    * generate the directory inodes
    * sign them
    * replicate them.

    TODO: rework datastore and datastore_id; we need to be sure that we're making inodes to write to this device's datastore and data_pubkeys corresponds to the owner's other devices

    Return {'status': True} on success
    Return {'error': ...} on error
    """
    data_pubkey = get_pubkey_hex(str(data_privkey_hex))
    datastore_id = datastore_get_id(data_pubkey)
    device_ids = datastore['device_ids']
    drivers = datastore['drivers']

    inode_info = datastore_deletefile_make_inodes( api_client, datastore, data_path, data_pubkeys, force=force, config_path=config_path )
    if 'error' in inode_info:
        return inode_info

    inode_signatures = []
    for inode_header_blob in inode_info['inodes']:
        signature = sign_inode_header_blob( inode_header_blob, data_privkey_hex )
        inode_signatures.append( signature )

    signed_tombstones = sign_mutable_data_tombstones(inode_info['tombstones'], data_privkey_hex)
    assert len(signed_tombstones) > 0

    datastore_info = datastore_serialize_and_sign(datastore, data_privkey_hex)
    res = api_client.backend_datastore_deletefile( datastore_info['str'], datastore_info['sig'], data_path, inode_info['inodes'], inode_info['payloads'], inode_signatures, signed_tombstones )
    if 'error' in res:
        log.debug("Failed to put deletefile inodes")
        return res

    return {'status': True}


def datastore_stat(api_client, blockchain_id, datastore, data_path, data_pubkeys, extended=False, force=False, config_path=CONFIG_PATH):
    """
    Stat a file or directory.  Get just the inode metadata.

    TODO: rework datastore and datastore_id; we need to be sure that we're making inodes to write to this device's datastore and data_pubkeys corresponds to the owner's other devices

    Return {'status': True, 'inode': inode info} on success
    Return {'error': ..., 'errno': ...} on error
    """

    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    datastore_id = datastore_get_id(datastore['pubkey'])
    drivers = datastore['drivers']
    
    log.debug("stat {}:{}".format(datastore_id, data_path))

    inode_info = api_client.backend_datastore_lookup(blockchain_id, datastore, 'inodes', data_path, data_pubkeys, extended=True, force=force, idata=False )
    if 'error' in inode_info:
        log.error("Failed to resolve {}".format(data_path))
        return inode_info
    
    ret = {
        'status': True,
    }

    if extended:
        ret['path_info'] = inode_info['path_info']
        ret['inode_info'] = inode_info['inode_info']
    
    else:
        ret['data'] = inode_info['inode_info']['inode']

    return ret


def datastore_getinode(api_client, blockchain_id, datastore, inode_uuid, extended=False, force=False, idata=False, config_path=CONFIG_PATH ):
    """
    Get an inode directly
    
    TODO: rework datastore and datastore_id; we need to be sure that we're making inodes to write to this device's datastore and data_pubkeys corresponds to the owner's other devices

    Return {'status': True, 'inode': ...}
    Return {'error'': ..., 'errno': ...} on error
    """

    datastore_id = datastore_get_id(datastore['pubkey'])
    drivers = datastore['drivers']
    
    log.debug("getinode {}:{}".format(datastore_id, inode_uuid))

    inode_info = api_client.backend_datastore_getinode(blockchain_id, datastore, inode_uuid, datastore['pubkey'], extended=extended, force=force, idata=idata)
    if 'error' in inode_info:
        log.error("Failed to resolve {}".format(inode_uuid))
        return inode_info
    
    ret = {
        'status': True,
    }

    if extended:
        ret['path_info'] = inode_info['path_info']
        ret['inode_info'] = inode_info['inode']

    else:
        ret['inode'] = inode_info['inode']

    return ret


def datastore_rmtree_make_inodes(api_client, datastore, data_path, data_pubkeys, root_dir=None, force=False, config_path=CONFIG_PATH, proxy=None):
    """
    Remove a directory tree and all its children.
    Does not actually modify the datastore; just generates
    the headers and tombstones for the caller to sign.
    
    Client-side method
    
    TODO: rework datastore and datastore_id; we need to be sure that we're making inodes to write to this device's datastore and data_pubkeys corresponds to the owner's other devices

    Return {'status': True, 'headers': [...], 'payloads': [...], 'tombstones': [...]} on success
    Return {'error': ..., 'errno': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)
 
    datastore_id = datastore_get_id(datastore['pubkey'])
    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']

    drivers = datastore['drivers']
    device_ids = datastore['device_ids']

    inode_stack = []        # stack of {'type': ..., 'inode': ...}

    dir_inode = None
    dir_uuid = None

    if root_dir is None:
        dir_path_info = api_client.backend_datastore_lookup(None, datastore, 'directories', data_path, data_pubkeys, idata=False, force=force, extended=True )
        if 'error' in dir_path_info:
            log.error('Failed to resolve {}'.format(data_path))
            return dir_path_info

        dir_inode_info = dir_path_info['inode_info']
        dir_uuid = dir_inode_info['uuid']
        dir_inode = dir_inode_info['inode']
    
    else:
        dir_inode = root_dir
        dir_uuid = root_dir['uuid']

    # is this a directory?
    if dir_inode['type'] != MUTABLE_DATUM_DIR_TYPE:
        # file.  remove 
        return datastore_deletefile_make_inodes(datastore, data_path, data_pubkeys, config_path=config_path, proxy=proxy)

    
    def _stack_push( dirents, stack ):
        """
        add files and directories to the deletion stack
        Return {'status': True, 'stack': stack, 'num_added': ...}
        """
        # push files
        for dirent_name, dirent_data in dirents.items():
            d_type = dirent_data['type']
            d_uuid = dirent_data['uuid']
            
            stack_ent = {'type': d_type, 'uuid': d_uuid, 'searched': False}

            if d_type == MUTABLE_DATUM_FILE_TYPE:
                stack.append( stack_ent )

        # push directories 
        for dirent_name, dirent_data in dirents.items():
            d_type = dirent_data['type']
            d_uuid = dirent_data['uuid']

            stack_ent = {'type': d_type, 'uuid': d_uuid, 'searched': False}

            if d_type == MUTABLE_DATUM_DIR_TYPE:
                stack.append( stack_ent )

        return {'status': True, 'stack': stack, 'num_added': len(dirents)}


    def _search( dir_inode_uuid, stack ):
        """
        Search a path for entries to remove.
        Push files onto the stack, and then directories.
        Return {'status': True, 'stack': stack, 'num_added': ...} on success
        Return {'error': ...} on error
        """
        log.debug("Search {}".format(dir_inode_uuid))
        
        res = api_client.backend_datastore_getinode(None, datastore, dir_inode_uuid, data_pubkeys, idata=True, force=force, extended=True)
        if 'error' in res:
            return res
        
        if res['inode']['type'] == MUTABLE_DATUM_FILE_TYPE:
            return {'status': True, 'stack': stack, 'num_added': 0}

        dirent_info = json.loads(res['inode']['idata'])
        dirents = dirent_info['children']

        return _stack_push( dirents, stack )

    
    inode_stack = []
    res = _stack_push( dir_inode['idata']['children'], inode_stack )
    inode_stack = res['stack']

    headers = []
    tombstones = []
    
    while len(inode_stack) > 0:

        # next entry to delete 
        inode_info = inode_stack[-1]

        if inode_info['type'] == MUTABLE_DATUM_FILE_TYPE:
            # files can be deleted immediately 
            log.debug("Delete file {}".format(inode_info['uuid']))
            child_tombstones = make_inode_tombstones( datastore_id, inode_info['uuid'], device_ids)

            # done 
            inode_stack.pop()
            tombstones += child_tombstones

        else:
            # already explored?
            if inode_info['searched']:
                # already explored this directory.  Can remove now
                log.debug("Delete directory {}".format(inode_info['uuid']))
                child_tombstones = make_inode_tombstones( datastore_id, inode_info['uuid'], device_ids)

                # done
                inode_stack.pop()
                tombstones += child_tombstones

            else:
                # explore directories.  Only remove empty ones.
                inode_stack[-1]['searched'] = True
                res = _search(inode_info['uuid'], inode_stack)
                if 'error' in res:
                    return res

                inode_stack = res['stack']

    # clear this inode's children
    dir_inode_info = make_dir_inode_data( datastore_id, datastore_id, dir_uuid, {}, device_ids, reader_pubkeys=dir_inode['reader_pubkeys'], config_path=config_path )
    if 'error' in dir_inode_info:
        return dir_inode_info

    headers = [dir_inode_info['header']]
    payloads = [dir_inode_info['idata']]

    ret = {
        'status': True,
        'inodes': headers,
        'payloads': payloads,
        'tombstones': tombstones,
    }

    return ret


def datastore_rmtree_put_inodes( datastore, header_blobs, payloads, signatures, tombstones, config_path=CONFIG_PATH, proxy=None ):
    """
    Given the header blobs and payloads from datastore_rmtree_make_inodes() and cliet-given signatures and signed tombstones,
    go and store them all.

    Order matters:
    header_blobs[0], payloads[0], and signatures[0] are for the parent
    tombstones[0] is for the child deleted

    Server-side method

    TODO: rework datastore and datastore_id; we need to be sure that we're making inodes to write to this device's datastore and data_pubkeys corresponds to the owner's other devices

    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on failure
    """
    # only putting the now-empty directory
    assert len(header_blobs) <= 1, header_blobs
    assert len(payloads) <= 1, payloads
    assert len(signatures) <= 1
    assert len(tombstones) >= 0

    assert len(header_blobs) == len(payloads)
    assert len(payloads) == len(signatures)
    
    creates = [False] * len(header_blobs)
    exists = [True] * len(header_blobs)

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    device_ids = datastore['device_ids']
    data_pubkey = datastore['pubkey']
    res = datastore_operation_check( data_pubkey, header_blobs, payloads, signatures, tombstones, creates, exists, device_ids, config_path=config_path )
    if 'error' in res:
        log.debug("Failed to check operation: {}".format(res['error']))
        return res

    return datastore_do_inode_operation( datastore, header_blobs, payloads, signatures, tombstones, config_path=config_path, proxy=proxy )


def datastore_rmtree(api_client, datastore, data_path, data_privkey_hex, data_pubkeys, force=False, config_path=CONFIG_PATH):
    """
    Client-side method to removing a directory tree.
    * generate the directory inodes and tombstones
    * sign them
    * replicate them.

    TODO: rework datastore and datastore_id; we need to be sure that we're making inodes to write to this device's datastore and data_pubkeys corresponds to the owner's other devices

    Return {'status': True} on success
    Return {'error': ...} on error
    """

    data_pubkey = get_pubkey_hex(str(data_privkey_hex))
    datastore_id = datastore_get_id(data_pubkey)
    device_ids = datastore['device_ids']
    drivers = datastore['drivers']

    inode_info = datastore_rmtree_make_inodes( api_client, datastore, data_path, data_pubkeys, force=force, config_path=config_path )
    if 'error' in inode_info:
        return inode_info

    inode_signatures = []
    for inode_header_blob in inode_info['inodes']:
        signature = sign_inode_header_blob( inode_header_blob, data_privkey_hex )
        inode_signatures.append( signature )

    signed_tombstones = sign_mutable_data_tombstones(inode_info['tombstones'], data_privkey_hex)
    datastore_info = datastore_serialize_and_sign(datastore, data_privkey_hex)

    # do batches 
    for i in xrange(0, len(signed_tombstones), 10):
        ts = signed_tombstones[i:min(i+10, len(signed_tombstones))]
        res = api_client.backend_datastore_rmtree( datastore_info['str'], datastore_info['sig'], [], [], [], ts )
        if 'error' in res:
            log.error("Failed to delete inodes: {}".format(res['error']))
            return res

    # update root
    res = api_client.backend_datastore_rmtree( datastore_info['str'], datastore_info['sig'], inode_info['inodes'], inode_info['payloads'], inode_signatures, [] )
    if 'error' in res:
        log.error("Failed to update root tree: {}".format(res['error']))
        return res

    return {'status': True}


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

    def get_session( api_password, private_key, port=6270 ):
        """
        Connect to the local blockstack node.
        Get back a session.

        Return the session (a JWT string) on success
        Raise on error
        """

        # will call `GET http://localhost:{port}/v1/auth?authRequest={auth JWT}`
        # will get back a session JWT

        # request permission to access the API 
        auth_request = {
            'app_domain': 'datastore.unit.tests',
            'methods': ['store_read', 'store_write', 'store_admin'],
            'app_public_key': keylib.key_formatting.decompress( ECPrivateKey(private_key).public_key().to_hex() ),
        }

        # authentication: bearer {password}
        headers = {
            'Authorization': 'bearer {}'.format(api_password)
        }

        # make the authentication token
        signer = jsontokens.TokenSigner()
        auth_token = signer.sign(auth_request, private_key)

        # ask for a session token
        url = 'http://localhost:{}/v1/auth?authRequest={}'.format(port, auth_token)
        req = requests.get(url, headers=headers )

        if req.status_code == 200:
            # good to go!
            # expect {'token': ses token} JSON response
            payload = req.json()
            session = payload['token']
            return session

        else:
            # whoops!
            raise Exception("HTTP status {} from Blockstack on {}".format(req.status_code, url))

    datastore_pk = keylib.ECPrivateKey().to_hex()
    datastore_pubk = get_pubkey_hex(datastore_pk)
    datastore_id = datastore_get_id(datastore_pubk)

    conf = get_config()
    assert conf

    ses = get_session(conf['api_password'], datastore_pk)
    rpc = blockstack_client.rpc.local_api_connect(api_session=ses)
    assert rpc

    # authenticate 
    
    ds_info = make_datastore_info( 'datastore', datastore_pubk, ['disk'] )
    if 'error' in ds_info:
        print "make_datastore_info: {}".format(ds_info)
        sys.exit(1)

    res = put_datastore( rpc, ds_info, datastore_pk )
    if 'error' in res:
        print 'put_datastore_info: {}'.format(res)
        sys.exit(1)

    ds_res = rpc.backend_datastore_get( None, datastore_id )
    if 'error' in ds_res:
        print 'get_datastore: {}'.format(ds_res)
        sys.exit(1)

    datastore = ds_res

    # do this all twice
    for i in xrange(0, 2):
        res = datastore_mkdir(rpc, datastore, '/dir1', datastore_pk)
        if 'error' in res:
            print 'datastore_mkdir: {}'.format(res)
            sys.exit(1)

        res = datastore_mkdir(rpc, datastore, '/dir1/dir2', datastore_pk)
        if 'error' in res:
            print 'datastore_mkdir: {}'.format(res)
            sys.exit(1)

        res = datastore_putfile(rpc, datastore, '/dir1/dir2/hello', 'hello world\x00\x01\x02\x03\x04\x05', datastore_pk)
        if 'error' in res:
            print 'datastore_putfile: {}'.format(res)
            sys.exit(1)

        res = datastore_listdir(rpc, None, datastore, '/')
        if 'error' in res:
            print 'datastore_listdir /: {}'.format(res)
            sys.exit(1)

        # sanity check 
        if 'dir1' not in res['data']['children'].keys():
            print 'invalid listdir /: {}'.format(res)
            sys.exit(1)

        res = datastore_listdir(rpc, None, datastore, '/dir1')
        if 'error' in res:
            print 'datastore_listdir /dir1: {}'.format(res)
            sys.exit(1)

        # sanity check 
        if 'dir2' not in res['data']['children'].keys():
            print 'invalid listdir /dir1: {}'.format(res)
            sys.exit(1)

        res = datastore_listdir(rpc, None, datastore, '/dir1/dir2')
        if 'error' in res:
            print 'datastore_listdir /dir1/dir2: {}'.format(res)
            sys.exit(1)

        # sanity check 
        if 'hello' not in res['data']['children'].keys():
            print 'invalid listdir /dir1: {}'.format(res)
            sys.exit(1)

        res = datastore_getfile(rpc, None, datastore, '/dir1/dir2/hello')
        if 'error'in res:
            print 'datastore_getfile /dir1/dir2/hello: {}'.format(res)
            sys.exit(1)

        # sanity check
        if res['data'] != 'hello world\x00\x01\x02\x03\x04\x05':
            print 'datastore_getfile /dir1/dir2/hello: {}'.format(res)
            sys.exit(1)

        # break here to test rmtree
        if i == 1:
            break

        # should fail
        res = datastore_rmdir(rpc, datastore, '/dir1/dir2', datastore_pk)
        if 'error' not in res:
            print 'succeeded in removing non-empty dir: {}'.format(res)
            sys.exit(1)

        if res['errno'] != errno.ENOTEMPTY:
            print 'wrong errno on ENOTEMPTY: {}'.format(res)
            sys.exit(1)

        # should fail 
        res = datastore_getfile(rpc, None, datastore, '/dir1/dir2')
        if 'error' not in res:
            print 'succeeded in getfile on /dir1/dir2: {}'.format(res)
            sys.exit(1)

        if res['errno'] != errno.EISDIR:
            print 'wrong errno on EISDIR: {}'.format(res)
            sys.exit(1)

        # should fail 
        res = datastore_listdir(rpc, None, datastore, '/dir1/dir2/hello')
        if 'error' not in res:
            print 'succeeded in listdir on /dir1/dir2/hello: {}'.format(res)
            sys.exit(1)

        if res['errno'] != errno.ENOTDIR:
            print 'wrong errno on ENOTDIR: {}'.format(res)
            sys.exit(1)

        # should fail 
        res = datastore_getfile(rpc, None, datastore, '/dir1/dir2/none')
        if 'error' not in res:
            print 'datastore_getfile succeeded on none: {}'.format(res)
            sys.exit(1)

        if res['errno'] != errno.ENOENT:
            print 'datastore_getfile ENOENT missing: {}'.format(res)
            sys.exit(1)

        # should fail 
        res = datastore_listdir(rpc, None, datastore, '/dir1/dir2/none')
        if 'error' not in res:
            print 'datastore_listdir succeeded on none: {}'.format(res)
            sys.exit(1)

        if res['errno'] != errno.ENOENT:
            print 'datastore_listdir ENOENT missing: {}'.format(res)
            sys.exit(1)

        # should fail 
        res = datastore_deletefile(rpc, datastore, '/dir1/dir2/none', datastore_pk)
        if 'error' not in res:
            print 'datastore_deletefile succeeded on none: {}'.format(res)
            sys.exit(1)

        if res['errno'] != errno.ENOENT:
            print 'datastore_deletefile ENOENT missing: {}'.format(res)
            sys.exit(1)

        # should fail 
        res = datastore_rmdir(rpc, datastore, '/dir1/dir2/none', datastore_pk)
        if 'error' not in res:
            print 'datastore_rmdir succeeded on none: {}'.format(res)
            sys.exit(1)

        if res['errno'] != errno.ENOENT:
            print 'datastore_rmdir ENOENT missing: {}'.format(res)
            sys.exit(1)

        # should fail
        res = delete_datastore(rpc, datastore, datastore_pk)
        if 'error' not in res:
            print 'deleted datastore: {}'.format(res)
            sys.exit(1)

        if res['errno'] != errno.ENOTEMPTY:
            print 'wrong errno on ENOTEMPTY delete datastore: {}'.format(res)
            sys.exit(1)

        # try deleting stuff
        res = datastore_deletefile(rpc, datastore, '/dir1/dir2/hello', datastore_pk)
        if 'error' in res:
            print 'failed to delete file: {}'.format(res)
            sys.exit(1)

        # should fail 
        res = datastore_getfile(rpc, None, datastore, '/dir1/dir2/hello')
        if 'error' not in res:
            print 'succeeded at getting deleted file: {}'.format(res)
            sys.exit(1)

        if res['errno'] != errno.ENOENT:
            print 'wrong errno for reading deleted file: {}'.format(res)
            sys.exit(1)

        # rmdir 
        res = datastore_rmdir(rpc, datastore, '/dir1/dir2', datastore_pk)
        if 'error' in res:
            print 'failed to rmdir: {}'.format(res)
            sys.exit(1)

        # should fail
        res = datastore_listdir(rpc, None, datastore, '/dir1/dir2')
        if 'error' not in res:
            print 'succeeded at getting deleted directory: {}'.format(res)
            sys.exit(1)

        if res['errno'] != errno.ENOENT:
            print 'wrong errno for reading deleted directory: {}'.format(res)
            sys.exit(1)

        # clean up 
        res = datastore_rmdir(rpc, datastore, '/dir1', datastore_pk)
        if 'error' in res:
            print 'failed to rmdir /dir1: {}'.format(res)
            sys.exit(1)
    
    # clear tree 
    res = datastore_rmtree(rpc, datastore, '/', datastore_pk)
    if 'error' in res:
        print 'failed to rmtree: {}'.format(res)
        sys.exit(1)

    # clear datastore 
    res = delete_datastore(rpc, datastore, datastore_pk)
    if 'error' in res:
        print 'failed to delete empty datastore: {}'.format(res)
        sys.exit(1)

    sys.exit(0)

