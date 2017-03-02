#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

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
import re
import jsontokens
import blockstack_profiles
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
from keylib import *

from .keys import *
from .profile import *
from .proxy import *
from .storage import hash_zonefile
from .zonefile import get_name_zonefile, load_name_zonefile, url_to_uri_record, store_name_zonefile

from .config import get_logger, get_config, get_local_device_id, get_all_device_ids
from .constants import BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, DATASTORE_SIGNING_KEY_INDEX
from .schemas import *

log = get_logger()

DIR_CACHE = None      # cached directories (maps inode uuid to dir data)

class InodeCache(object):
    """
    Cache inode-uuid --> inode data
    in an LRU style
    """
    def __init__(self, capacity=10000):
        self.capacity = capacity
        self.cache = collections.OrderedDict()

    def get(self, inode_uuid):
        """
        Get cached inode data
        """
        try:
            value = self.cache.pop(inode_uuid)
            self.cache[inode_uuid] = value
            return value

        except KeyError:
            return None

    def put(self, inode_uuid, inode_data):
        """
        Cache inode data
        """
        try:
            self.cache.pop(inode_uuid)
        except KeyError:
            if len(self.cache) >= self.capacity:
                self.cache.popitem(last=False)

        self.cache[inode_uuid] = inode_data


    def evict(self, inode_uuid):
        """
        Evict inode data
        """
        try:
            self.cache.pop(inode_uuid)
        except KeyError:
            pass


def serialize_mutable_data_id(data_id):
    """
    Turn a data ID into a suitable filesystem name
    """
    return urllib.quote(urllib.unquote(data_id).replace('\0', '\\0')).replace('/', r'\x2f')


def get_metadata_dir(conf):
    """
    Get the absolute path to the metadata directory
    """
    metadata_dir = conf.get('metadata', None)
    assert metadata_dir, "Config file is missing blockstack_client.metadata"

    if posixpath.normpath(os.path.abspath(metadata_dir)) != posixpath.normpath(conf['metadata']):
        # relative path; make absolute
        metadata_dir = posixpath.normpath( os.path.join(os.path.dirname(config_path), metadata_dir) )

    return metadata_dir


def load_mutable_data_version(conf, device_id, data_id, config_path=CONFIG_PATH):
    """
    Get the version field of a piece of mutable data from local cache.
    """

    # try to get the current, locally-cached version
    conf = get_config(path=config_path) if conf is None else conf

    if conf is None:
        msg = 'No config found; cannot load version for "{}"'
        log.debug(msg.format(data_id))
        return None

    metadata_dir = get_metadata_dir(conf)
    dev_id = serialize_mutable_data_id(device_id)
    d_id = serialize_mutable_data_id(data_id)

    ver_dir = os.path.join(metadata_dir, d_id)
    if not os.path.exists(ver_dir):
        log.debug("No version path found for {}:{}".format(device_id, data_id))
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


def store_mutable_data_version(conf, device_id, data_id, ver, config_path=CONFIG_PATH):
    """
    Locally store the version of a piece of mutable data,
    so we can ensure that its version is incremented on
    subsequent puts.

    Return True if stored
    Return False if not
    """

    conf = get_config(path=config_path) if conf is None else conf

    if conf is None:
        msg = 'No config found; cannot store version for "{}"'
        log.warning(msg.format(data_id))
        return False

    metadata_dir = get_metadata_dir(conf)

    if not os.path.isdir(metadata_dir):
        try:
            log.debug("Make metadata directory {}".format(metadata_dir))
            os.makedirs(metadata_dir)
        except Exception, e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            msg = 'No metadata directory created; cannot store version of "{}"'
            log.warning(msg.format(data_id))
            return False

    d_id = serialize_mutable_data_id(data_id)
    dev_id = serialize_mutable_data_id(device_id)

    ver_dir = os.path.join(metadata_dir, d_id)
    if not os.path.isdir(ver_dir):
        try:
            log.debug("Make metadata directory {}".format(ver_dir))
            os.makedirs(ver_dir)
        except Exception, e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            log.warning("No metadata directory created for {}:{}".format(device_id, data_id))
            return False

    ver_path = os.path.join(ver_dir, '{}.ver'.format(dev_id))
    try:
        with open(ver_path, 'w') as f:
            f.write(str(ver))
            f.flush()
        return True

    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.warn("Failed to store version of {}:{}".format(device_id, data_id))
       
    return False


def delete_mutable_data_version(conf, device_id, data_id, config_path=CONFIG_PATH):
    """
    Locally delete the version of a piece of mutable data.

    Return True if deleted.
    Return False if not
    """

    conf = get_config(path=config_path) if conf is None else conf

    if conf is None:
        msg = 'No config found; cannot delete version for "{}"'
        return False

    metadata_dir = get_metadata_dir(conf)

    if not os.path.isdir(metadata_dir):
        return True

    d_id = serialize_mutable_data_id(data_id)
    dev_id = serialize_mutable_data_id(device_id)

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
        log.warn(msg.format(ver_file_path))

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
            if data_hash is not None and data_hash not in h:
                return {'error': 'Data ID/hash mismatch: {} not in {} (possibly due to invalid zonefile)'.format(data_hash, h)}
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


def list_update_history(name, current_block=None, config_path=CONFIG_PATH, proxy=None):
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

    name_history = get_name_blockchain_history( name, 0, current_block )
    if 'error' in name_history:
        log.error('Failed to get name history for {}: {}'.format(name, name_history['error']))
        return name_history

    all_update_hashes = []
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

    return all_update_hashes


def list_zonefile_history(name, current_block=None, proxy=None):
    """
    list_zonefile_history

    List all prior zonefiles of a name, in historic order.
    Return the list of zonefiles.  Each zonefile will be a dict with either the zonefile data,
    or a dict with only the key 'error' defined.  This method can successfully return
    some but not all zonefiles.
    """
    zonefile_hashes = list_update_history(
        name, current_block=current_block, proxy=proxy
    )

    zonefiles = []
    for zh in zonefile_hashes:
        zonefile = load_name_zonefile(name, zh, raw_zonefile=True)
        if zonefile is None:
            zonefile = {'error': 'Failed to load zonefile {}'.format(zh)}
        else:
            msg = 'Invalid zonefile type {}'.format(type(zonefile))
            assert isinstance(zonefile, (str, unicode)), msg

        zonefiles.append(zonefile)

    return zonefiles


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
    if data_address is not None and virtualchain.is_p2sh_address(data_address):
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


def _data_blob_chomp( s ):
    """
    Given "len(s):type:s,remainder", return (type, s, remainder)
    """
    # grab length and remainder
    parts = s.split(":", 1)
    s_len = None
    s_type = None
    try:
        s_len = int(parts[0])
        assert parts[1][s_len] == ','
    except:
        raise ValueError("Invalid length field {} (from {})".format(parts[0], s))

    type_payload = parts[1][:s_len]
    s_remainder = ""
    if s_len < len(parts[1]):
        s_remainder = parts[1][s_len+1:]

    # grab type and payload
    parts = type_payload.split(':', 1)
    s_type = parts[0]
    try:
        assert s_type in ['d', 's', 'i', 'l']
    except:
        raise ValueError("Invalid type field (from {})".format(s))
    
    s_payload = parts[1]
    return s_type, s_payload, s_remainder


def _data_blob_parse_work( data_blob_payload ):
    """
    Parse a serialized data blob back into a structure
    Return (parsed data, remainder)
    """

    p_type, payload, remainder = _data_blob_chomp( data_blob_payload )
    
    if p_type is None:
        # empty 
        return '', ''

    if p_type == 'i':
        return int(payload), remainder

    elif p_type == 's':
        return str(payload), remainder 

    elif p_type in ['l', 'd']:
        # payload is "blob,blob,blob..." string
        parts = None
        if p_type == 'l':
            parts = []
        else:
            parts = {}

        if len(payload) == 0:
            # empty 
            return parts, remainder

        if p_type == 'l':
            # list
            while True:
                p_type, p_payload, p_remainder = _data_blob_chomp( payload )

                # parse just this blob
                part, r = _data_blob_parse_work('{}:{}:{},'.format(len(p_payload) + 2, p_type, p_payload))
                assert len(r) == 0

                parts.append(part)

                if len(p_remainder) == 0:
                    break

                payload = p_remainder

            return parts, remainder

        elif p_type == 'd':
            # dict
            while True:
                k_type, k_payload, k_remainder = _data_blob_chomp( payload )
                assert len(k_remainder) > 0, "dict underrun from '{}'".format(payload)

                v_type, v_payload, v_remainder = _data_blob_chomp( k_remainder )
                 
                k_part, r = _data_blob_parse_work('{}:{}:{},'.format(len(k_payload) + 2, k_type, k_payload))
                assert len(r) == 0

                v_part, r = _data_blob_parse_work('{}:{}:{},'.format(len(v_payload) + 2, v_type, v_payload))
                assert len(r) == 0

                parts[k_part] = v_part

                if len(v_remainder) == 0:
                    break

                payload = v_remainder

            return parts, remainder

        else:
            # unreachable
            assert False
    
    else:
        raise ValueError("Invalid type {}".format(p_type))


def data_blob_parse( data_blob_payload ):
    """
    Parse a serialized data structure
    """
    
    data_blob, r = _data_blob_parse_work(data_blob_payload)
    assert len(r) == 0, "Underrun while parsing"
    return data_blob


def data_blob_serialize( data_blob ):
    """
    Serialize a data blob (conformant to DATA_BLOB_SCHEMA) into a string
    """

    if isinstance(data_blob, (int, long)):
        data_blob = str(data_blob)
        return '{}:i:{},'.format(len(data_blob) + 2, data_blob)

    if isinstance(data_blob, (str, unicode)):
        data_blob = str(data_blob)
        return '{}:s:{},'.format(len(data_blob) + 2, data_blob)

    if isinstance(data_blob, list):
        data_blob_parts = [data_blob_serialize(x) for x in data_blob]
        data_blob = ''.join(data_blob_parts)
        data_blob = 'l:{}'.format(data_blob)

        return '{}:{},'.format(len(data_blob), data_blob)

    if isinstance(data_blob, dict):
        payload_parts = []

        for k in sorted(data_blob.keys()):
            k_part = data_blob_serialize(k)
            v_part = data_blob_serialize(data_blob[k])
            payload_parts.append(k_part)
            payload_parts.append(v_part)

        values = ''.join(payload_parts)
        payload = 'd:{}'.format(values)

        return '{}:{},'.format(len(payload), payload)

    raise ValueError('Unserializable type {}'.format(type(data_blob)))


def get_mutable(data_id, blockchain_id=None, data_pubkey=None, data_address=None, data_hash=None, storage_drivers=None,
                         proxy=None, ver_min=None, ver_max=None, urls=None, device_ids=None, fully_qualified_data_id=False,
                         config_path=CONFIG_PATH, all_drivers=False):
    """
    get_mutable 

    Fetch a piece of mutable data.

    If @ver_min is given, ensure the data's version is greater or equal to it.
    If @ver_max is given, ensure the data's version is less than it.
    
    If data_pubkey or data_address is given, then blockchain_id will be ignored (but it will be passed as a hint to the drivers)
    If data_hash is given, then all three will be ignored

    Return {'data': the data, 'version': the version, 'timestamp': ..., 'data_pubkey': ..., 'owner_pubkey_hash': ..., 'drivers': [driver name]} on success
    Return {'error': ...} on error
    """

    proxy = get_default_proxy(config_path) if proxy is None else proxy
    conf = get_config(path=config_path)
    
    fq_data_ids = []
    if device_ids is None:
        device_ids = get_all_device_ids(config_path=config_path)

    if not fully_qualified_data_id:
        # v2 mutable data
        for device_id in device_ids:
            fq_data_ids.append( storage.make_fq_data_id(device_id, data_id) )

    else:
        # already fully-qualified
        fq_data_ids = [data_id]

    lookup = False
    if data_address is None and data_pubkey is None and data_hash is None:
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

    version_info = _get_mutable_data_versions(data_id, device_ids, config_path=config_path)
    if 'error' in version_info:
        return {'error': 'Failed to load latest data version'}

    expected_version = version_info['version']

    log.debug("get_mutable({}, blockchain_id={}, pubkey={} ({}), addr={}, hash={}, expected_version={}, storage_drivers={})".format(
        data_id, blockchain_id, data_pubkey, lookup, data_address, data_hash, expected_version, ','.join(storage_drivers)
    ))

    mutable_data = None
    mutable_drivers = []
    latest_version = expected_version

    for fq_data_id in fq_data_ids:

        # which storage drivers and/or URLs will we use?
        for driver in storage_drivers: 

            # get the mutable data itsef
            data_str = storage.get_mutable_data(fq_data_id, data_pubkey, urls=urls, drivers=[driver], data_address=data_address, data_hash=data_hash, blockchain_id=blockchain_id)
            if data_str is None:
                log.error("Failed to get mutable datum {}".format(fq_data_id))
                return {'error': 'Failed to look up mutable datum'}
            
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
                continue

            elif expected_version > version:
                log.warn("Invalid (stale) data version from {} for {}: expected = {}, version = {}".format(driver, fq_data_id, expected_version, version))
                continue

            if not all_drivers:
                # success!
                mutable_data = data
                mutable_drivers.append(driver)
                break

            # keep searching 
            if version < latest_version:
                continue

            # got a later version
            # discard all prior drivers; they gave stale data
            version = latest_version
            mutable_data = data
            mutable_drivers = [driver]

        if mutable_data is not None:
            # success!
            break

    if mutable_data is None:
        log.error("Failed to fetch mutable data for {}".format(fq_data_id))
        return {'error': 'Failed to fetch mutable data'}

    rc = _put_mutable_data_versions(data_id, version, device_ids, config_path=config_path)
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



def put_immutable(blockchain_id, data_id, data_json, data_url=None, txid=None, proxy=None, wallet_keys=None, config_path=CONFIG_PATH):
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

    data_text = storage.serialize_immutable_data(data_json)
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
    rc = storage.put_immutable_data(data_json, txid)
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


def load_user_data_privkey( blockchain_id, storage_drivers=None, proxy=None, config_path=CONFIG_PATH, wallet_keys=None ):
    """
    Get the user's data private key from his/her wallet.
    Verify it matches the zone file for this blockchain ID

    Return {'privkey': ...} on success
    Return {'error': ...} on error
    """
    conf = get_config(path=CONFIG_PATH)
    user_zonefile = get_name_zonefile( blockchain_id, storage_drivers=storage_drivers, proxy=proxy)
    if 'error' in user_zonefile:
        log.debug("Unable to load zone file for '{}': {}".format(blockchain_id, user_zonefile['error']))
        return {'error': 'Failed to load zonefile'}

    # recover name record and zonefile
    user_zonefile = user_zonefile['zonefile']

    # get the data key
    data_privkey = get_data_privkey_info(user_zonefile, wallet_keys=wallet_keys, config_path=config_path)
    if json_is_error(data_privkey):
        # error text
        return {'error': data_privkey['error']}

    else:
        assert data_privkey is not None

    return {'privkey': data_privkey}


def put_mutable(data_id, data_payload, blockchain_id=None, data_privkey=None, proxy=None, fully_qualified_data_id=False,
                                       storage_drivers=None, storage_drivers_exclusive=False, zonefile_storage_drivers=None, version=None, wallet_keys=None,
                                       config_path=CONFIG_PATH, create=False):
    """
    put_mutable.

    Given an arbitrary name, an ID for the data, and the data itself, sign and upload the data to the
    configured storage providers.

    If data_privkey is not given, then use blockchain_id to look it up.

    ** Consistency **

    @version, if given, is the version to include in the data.
    If not given, then 1 will be used if no version exists locally, or the local version will be auto-incremented from the local version.
    Readers will only accept the version if it is "recent" (i.e. it falls into the given version range, or it is fresher than the last-seen version).

    ** Durability **

    Replication is best-effort.  If one storage provider driver succeeds, the put_mutable succeeds.  If they all fail, then put_mutable fails.
    More complex behavior can be had by creating a "meta-driver" that calls existing drivers' methods in the desired manner.

    Notes on usage:
    * wallet_keys is only needed if data_privkey is None
    * if storage_drivers is None, each storage driver under `storage_drivers_required_write=` will be attempted.
    * if storage_drivers is not None, then each storage driver in storage_drivers *must* succeed

    Returns a dict with {'status': True, 'version': version, ..., 'fq_data_id': ...} on success
    Returns a dict with 'error' set on failure
    """

    assert type(data_payload) in [str, unicode, dict, list, int, long, float]

    proxy = get_default_proxy(config_path) if proxy is None else proxy
    conf = get_config(path=config_path)
    assert conf
   
    fq_data_id = None
    device_id = ''
    
    if not fully_qualified_data_id:
        # v2 mutable data
        device_id = get_local_device_id(config_dir=os.path.dirname(config_path))
        if device_id is None:
            raise Exception("Failed to get device ID")

        fq_data_id = storage.make_fq_data_id(device_id, data_id)
    
    else:
        # (no device ID)
        fq_data_id = data_id

    if storage_drivers is None:
        storage_drivers = get_write_storage_drivers(config_path)

    lookup = False
    if data_privkey is None:
        if blockchain_id is None:
            raise ValueError("Missing data_privkey and blockchain_id")

        data_privkey_info = load_user_data_privkey( blockchain_id, storage_drivers=zonefile_storage_drivers, proxy=proxy, config_path=config_path, wallet_keys=wallet_keys )
        if 'error' in data_privkey_info:
            log.error("Failed to load data private key")
            return {'error': 'Failed to load data private key'}

        data_privkey = data_privkey_info['privkey']
        lookup = True

    # get the version to use
    if version is None:
        version = load_mutable_data_version(conf, device_id, data_id, config_path=config_path)
        if version is not None and create:
            log.error("Already exists: {}".format(fq_data_id))
            return {'error': 'Data exists'}

        version = 1 if version is None else version + 1

    # put the mutable data record itself
    # TODO: make this a binary string
    data_json = {
        'fq_data_id': fq_data_id,
        'data': data_payload,
        'version': version,
        'timestamp': int(time.time())
    }

    if blockchain_id is not None:
        data_json['blockchain_id'] = blockchain_id
    
    data = data_blob_serialize(data_json)
    result = {}

    log.debug("put_mutable({}, blockchain_id={}, lookup_privkey={}, version={}, storage_drivers={}, exclusive={})".format(fq_data_id, blockchain_id, lookup, version, ','.join(storage_drivers), storage_drivers_exclusive))
    rc = storage.put_mutable_data(fq_data_id, data, data_privkey, blockchain_id=blockchain_id, required=storage_drivers, required_exclusive=storage_drivers_exclusive)
    if not rc:
        log.error("failed to put mutable data {}".format(fq_data_id))
        result['error'] = 'Failed to store mutable data'
        return result

    # remember which version this was
    rc = store_mutable_data_version(conf, device_id, data_id, version, config_path=config_path)
    if not rc:
        log.error("failed to put mutable data version {}.{}".format(data_id, version))
        result['error'] = 'Failed to store mutable data version'
        return result

    result['status'] = True
    result['version'] = version
    result['fq_data_id'] = fq_data_id
    result['timestamp'] = data_json['timestamp']

    if BLOCKSTACK_TEST is not None:
        msg = 'Put "{}" mutable data (version {}) for blockchain ID {}'
        log.debug(msg.format(data_id, version, blockchain_id))

    return result


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


def delete_mutable(data_id, data_privkey=None, proxy=None, storage_drivers=None, storage_drivers_exclusive=False,
                            device_ids=None, wallet_keys=None, delete_version=True, fully_qualified_data_id=False,
                            blockchain_id=None, config_path=CONFIG_PATH):
    """
    delete_mutable

    Remove a piece of mutable data. Delete it from
    the storage providers as well.

    Optionally (by default) delete cached version information

    If data_privkey is given, then blockchain_id can be arbitrary

    Returns a dict with {'status': True} on success
    Returns a dict with {'error': ...} on failure
    """

    proxy = get_default_proxy(config_path) if proxy is None else proxy
    conf = get_config(config_path)
    assert conf

    if device_ids is None:
        device_ids = get_all_device_ids(config_path=config_path)

    fq_data_ids = []
    if not fully_qualified_data_id:
        for device_id in device_ids:
            fq_data_id = storage.make_fq_data_id(device_id, data_id)
            fq_data_ids.append(fq_data_id)
    
    else:
        fq_data_ids = [data_id]

    if storage_drivers is None:
        storage_drivers = get_write_storage_drivers(config_path)

    if data_privkey is None:
        data_privkey_info = load_user_data_privkey( blockchain_id, storage_drivers=storage_drivers, proxy=proxy, config_path=config_path, wallet_keys=wallet_keys )
        if 'error' in data_privkey_info:
            log.error("Failed to load data private key")
            return {'error': 'Failed to load data private key'}

        data_privkey = data_privkey_info['privkey']

    worst_rc = True

    log.debug("delete_mutable({}, blockchain_id={}, storage_drivers={}, delete_version={})".format(
        data_id, blockchain_id, ','.join(storage_drivers), delete_version
    ))

    # remove the data itself
    for fq_data_id in fq_data_ids:
        rc = storage.delete_mutable_data(fq_data_id, data_privkey, required=storage_drivers, required_exclusive=storage_drivers_exclusive, blockchain_id=blockchain_id)
        if not rc:
            log.error("Failed to delete {} from storage providers".format(fq_data_id))
            worst_rc = False
            continue

    if delete_version:
        for device_id in device_ids:
            delete_mutable_data_version(conf, device_id, data_id, config_path=config_path)

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


def _make_datastore_info( datastore_type, datastore_privkey_hex, driver_names, device_ids, config_path=CONFIG_PATH ):
    """
    Make the private part of a datastore record.
    Returns {'datastore': ..., 'root': ...} on success
    Returns {'error': ...} on error
    """
    root_uuid = str(uuid.uuid4())
    datastore_pubkey = get_pubkey_hex(datastore_privkey_hex)
    datastore_id = keylib.public_key_to_address(datastore_pubkey)
    datastore_root = _mutable_data_make_dir( datastore_id, root_uuid, {} )

    assert datastore_type in ['datastore', 'collection'], datastore_type

    datastore_info = {
        'type': datastore_type,
        'pubkey': datastore_pubkey,
        'drivers': driver_names,
        'device_ids': device_ids,
        'root_uuid': root_uuid
    }

    # sign
    signer = jsontokens.TokenSigner()
    token = signer.sign( datastore_info, datastore_privkey_hex )

    return {'datastore': datastore_info, 'datastore_token': token, 'root': datastore_root}


def get_datastore( datastore_id, config_path=CONFIG_PATH, proxy=None):
    """
    Get a datastore's information.
    Returns {'status': True, 'datastore': public datastore info}
    Returns {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    nonlocal_storage_drivers = get_nonlocal_storage_drivers(config_path)

    data_id = '{}.datastore'.format(datastore_id)
    datastore_info = get_mutable(data_id, data_address=datastore_id, proxy=proxy, config_path=config_path, storage_drivers=nonlocal_storage_drivers)
    if 'error' in datastore_info:
        log.error("Failed to load public datastore information: {}".format(datastore_info['error']))
        return {'error': 'Failed to load public datastore record', 'errno': errno.ENOENT}

    datastore = datastore_info['data']
    try:
        jsonschema.validate(datastore, DATASTORE_SCHEMA) 
    except (AssertionError, ValidationError) as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)
        
        log.error("Invalid datastore record")
        return {'error': 'Invalid public datastore record', 'errno': errno.EIO}

    return {'status': True, 'datastore': datastore}


def make_datastore( datastore_type, datastore_privkey_hex, driver_names=None, device_ids=None, config_path=CONFIG_PATH ):
    """
    Create a new datastore record with the given name, using the given account_info structure
    Return {'datastore': public datastore information, 'datastore_token': datastore JWT, 'root': root inode}
    Return {'error': ...} on failure
    """
    if driver_names is None:
        driver_handlers = storage.get_storage_handlers()
        driver_names = [h.__name__ for h in driver_handlers]

    if device_ids is None:
        device_ids = get_all_device_ids(config_path=config_path)

    datastore_info = _make_datastore_info( datastore_type, datastore_privkey_hex, driver_names, device_ids, config_path=config_path)
    return {'datastore': datastore_info['datastore'],  'datastore_token': datastore_info['datastore_token'], 'root': datastore_info['root']}


def put_datastore(datastore_info, datastore_privkey, proxy=None, config_path=CONFIG_PATH ):
    """
    Create and put a new datastore.
    @datastore_info should be the structure returned by make_datastore()

    Return {'status': True} on success
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    conf = get_config(path=config_path)
    assert conf
    device_id = get_local_device_id(config_dir=os.path.dirname(config_path))

    datastore = datastore_info['datastore']
    datastore_id = datastore_get_id( datastore['pubkey'] )
    datastore_token = datastore_info['datastore_token']
    root = datastore_info['root']
    drivers = datastore['drivers']
    device_ids = datastore['device_ids']
    all_device_ids = get_all_device_ids(config_path=config_path)
    data_id = '{}.datastore'.format(datastore_id)

    # this datastore must not exist
    old_datastore_version = load_mutable_data_version(conf, device_id, data_id, config_path=config_path)
    if old_datastore_version is not None:
        log.error("Already exists: {}".format(data_id))
        return {'error': 'Datastore already exists', 'errno': errno.EEXIST}

    # replicate root inode
    res = _put_inode(datastore_id, root, datastore_privkey, drivers, device_ids, config_path=CONFIG_PATH, proxy=proxy, create=True )
    if 'error' in res:
        log.error("Failed to put root inode for datastore {}".format(datastore_id))
        return {'error': 'Failed to replicate datastore metadata', 'errno': errno.EREMOTEIO}

    # replicate public datastore record
    res = put_mutable( data_id, datastore, data_privkey=datastore_privkey, storage_drivers=drivers, storage_drivers_exclusive=True, config_path=config_path, proxy=proxy )
    if 'error' in res:
        log.error("Failed to put datastore metadata for {}".format(datastore_fq_id))

        # try to clean up...
        res = _delete_inode(datastore_id, root['uuid'], datastore_privkey, drivers, device_ids, proxy=proxy, config_path=config_path)
        if 'error' in res:
            log.error("Failed to clean up root inode {}".format(root['uuid']))

        return {'error': 'Failed to replicate datastore metadata', 'errno': errno.EREMOTEIO}

    datastore_rec_version = res['version']

    # advance version for all devices
    res = _put_mutable_data_versions(data_id, datastore_rec_version, all_device_ids, config_path=config_path)
    if 'error' in res:
        log.error("Failed to advance consistency data for datastore record")
        res['errno'] = errno.EIO
        return res

    return {'status': True}


def delete_datastore( datastore_privkey, force=False, config_path=CONFIG_PATH, proxy=None ):
    """
    Delete a datastore's information, given the app user structure and the datastore name
    If force is True, then delete the root inode even if it's not empty.

    Return {'status': True} on success
    Return {'error': ...} on error
    """

    global DIR_CACHE

    if proxy is None:
        proxy = get_default_proxy(config_path)
   
    if DIR_CACHE is None:
        DIR_CACHE = InodeCache()

    datastore_pubkey = get_pubkey_hex(datastore_privkey)
    datastore_id = datastore_get_id(datastore_pubkey)

    # get the datastore first
    datastore_info = get_datastore(datastore_id, config_path=config_path, proxy=proxy )
    if 'error' in datastore_info:
        log.error("Failed to look up datastore information for {}".format(datastore_id))
        return {'error': 'Failed to look up datastore', 'errno': errno.ENOENT}
    
    datastore = datastore_info['datastore']

    # remove root inode 
    res = datastore_listdir( datastore, '/', config_path=config_path, proxy=proxy )
    if 'error' in res:
        if not force:
            log.error("Failed to list /")
            return {'error': 'Failed to check if datastore is empty', 'errno': errno.EREMOTEIO}
        else:
            log.warn("Failed to list /, but forced to remove it anyway")

    if not force and len(res['dir']['idata']) != 0:
        log.error("Datastore not empty\n{}\n".format(json.dumps(res['dir']['idata'], indent=4, sort_keys=True)))
        return {'error': 'Datastore not empty', 'errno': errno.ENOTEMPTY}

    res = _delete_inode(datastore_id, datastore['root_uuid'], datastore_privkey, datastore['drivers'], datastore['device_ids'], proxy=proxy, config_path=config_path, cache=DIR_CACHE) 
    if 'error' in res:
        log.error("Failed to delete root inode {}".format(datastore['root_uuid']))
        return {'error': res['error'], 'errno': errno.EREMOTEIO}

    # remove public datastore record
    data_id = '{}.datastore'.format(datastore_id)
    res = delete_mutable(data_id, data_privkey=datastore_privkey, storage_drivers=datastore['drivers'], storage_drivers_exclusive=True, proxy=proxy, config_path=config_path )
    if 'error' in res:
        log.error("Failed to delete public datastore record: {}".format(res['error']))
        return {'error': 'Failed to delete public datastore record', 'errno': errno.EREMOTEIO}

    return {'status': True}


def _is_cacheable(inode_info):
    """
    Can we cache this inode?
    """
    if inode_info['type'] == MUTABLE_DATUM_DIR_TYPE and len(inode_info['idata']) < 1024:
        return True
    else:
        return False


def _get_inode(datastore_id, inode_uuid, inode_type, data_pubkey_hex, drivers, device_ids, config_path=CONFIG_PATH, proxy=None, cache=None ):
    """
    Get an inode from non-local mutable storage.  Verify that it has an
    equal or later version number than the one we have locally.

    If cache is not None, and if the inode is a directory, then check
    the cache for the data and add it if it is not present

    # TODO: check data hash against inode header

    Return {'status': True, 'inode': inode info} on success.
    Return {'error': ...} on error
    """
    
    if proxy is None:
        proxy = get_default_proxy(config_path)

    conf = get_config(config_path)
    assert conf

    '''
    # cached?
    if cache is not None and inode_type == MUTABLE_DATUM_DIR_TYPE:
        inode_data = cache.get(inode_uuid)
        if inode_data is not None:
            # already-fetched
            log.debug("Cache HIT on {}".format(inode_uuid))
            inode_version = max(inode_data[
            return {'status': True, 'inode': inode_data}
    '''

    header_version = 0
    inode_header = None
    inode_info = None
    inode_version = None

    # get latest header from all drivers 
    res = _get_inode_header(datastore_id, inode_uuid, data_pubkey_hex, drivers, device_ids, config_path=config_path, proxy=proxy, cache=cache)
    if 'error' in res:
        log.error("Failed to get inode header for {}: {}".format(inode_uuid, res['error']))
        return res

    header_version = res['version']
    inode_header = res['inode']
    drivers_to_try = res['drivers']
    data_hash = inode_header['data_hash']

    # get inode from only the driver(s) that gave back fresh information 
    data_id = '{}.{}'.format(datastore_id, inode_uuid)
    res = get_mutable(data_id, ver_min=header_version, data_hash=data_hash, storage_drivers=drivers_to_try, proxy=proxy, config_path=config_path)
    if 'error' in res:
        log.error("Failed to get inode {} from {}: {}".format(inode_uuid, ','.join(drivers_to_try), res['error']))
        return {'error': 'Failed to find fresh inode'}

    # success!
    inode_info_str = res['data']
    try:
        inode_info = data_blob_parse(inode_info_str)
    except:
        if BLOCKSTACK_TEST:
            log.error("Unparseable inode: {}".format(inode_info_str))

        return {'error': 'Unparseable inode data'}

    inode_version = res['version']

    # must be an inode 
    inode_schema = None
    if inode_type == MUTABLE_DATUM_DIR_TYPE:
        inode_schema = MUTABLE_DATUM_DIR_SCHEMA
    elif inode_type == MUTABLE_DATUM_FILE_TYPE:
        inode_schema = MUTABLE_DATUM_FILE_SCHEMA
    else:
        raise ValueError("Invalid inode type")

    try:
        jsonschema.validate(inode_info, inode_schema)
    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        return {'error': 'Invalid inode structure'}

    # must match owner 
    data_address = keylib.public_key_to_address(data_pubkey_hex)
    if inode_info['owner'] != data_address:
        log.error("Inode {} not owned by {} (but by {})".format(inode_info['uuid'], data_address, inode_info['owner']))
        return {'error': 'Invalid owner'}

    '''
    # yup!
    # cache small directories
    if cache is not None and _is_cacheable(inode_info):
        log.debug("Cache PUT {}".format(inode_uuid))
        cache.put( inode_uuid, inode_info )
    '''

    res = _put_inode_consistency_info(datastore_id, inode_uuid, max(inode_version, header_version), device_ids, config_path=config_path)
    if 'error' in res:
        return res

    return {'status': True, 'inode': inode_info, 'version': max(inode_version, header_version)}


def _get_mutable_data_versions( data_id, device_ids, config_path=CONFIG_PATH ):
    """
    Get the mutable data version for a datum spread across multiple devices
    Return {'status': True, 'version': version} on success
    Return {'error': ...} on error
    """
    new_version = 0
    conf = get_config(config_path)
    assert conf

    for device_id in device_ids:
        cur_ver = load_mutable_data_version(conf, device_id, data_id, config_path=config_path)
        if cur_ver is not None:
            new_version = max(new_version, cur_ver)

    return {'status': True, 'version': new_version}


def _put_mutable_data_versions( data_id, new_version, device_ids, config_path=CONFIG_PATH ):
    """
    Advance all versions of a mutable datum to at least new_version
    Return {'status': True, 'version': new version} on success
    Return {'error': ...} on error
    """

    # advance header version and inode version
    conf = get_config(config_path)
    assert conf

    res = _get_mutable_data_versions(data_id, device_ids, config_path=CONFIG_PATH)
    if 'error' in res:
        return res

    new_version = max(res['version'], new_version)

    for device_id in device_ids:
        rc = store_mutable_data_version(conf, device_id, data_id, new_version, config_path=config_path)
        if not rc:
            return {'error': 'Failed to advance mutable data version {} to {}'.format(data_id, new_version)}

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

    res = _put_mutable_data_versions(inode_data_id, new_version, device_ids, config_path=CONFIG_PATH)
    if 'error' in res:
        return res

    hdr_ver = res['version']
    res = _put_mutable_data_versions(hdr_data_id, hdr_ver, device_ids, config_path=CONFIG_PATH)
    if 'error' in res:
        return res

    if res['version'] > hdr_ver:
        # headers had later version 
        inode_ver = res['version']
        res = _put_mutable_data_versions(inode_data_id, inode_ver, device_ids, config_path=CONFIG_PATH)
        if 'error' in res:
            return res

    return {'status': True}


def _get_inode_header(datastore_id, inode_uuid, data_pubkey_hex, drivers, device_ids, inode_hdr_version=None, config_path=CONFIG_PATH, proxy=None, cache=None):
    """
    Get an inode's header data.  Verify it matches the inode info.
    Fetch the header from *all* drivers

    Return {'status': True, 'inode': inode_full_info, 'version': version, 'drivers': drivers that were used} on success.
    Return {'error': ...} on error.
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    conf = get_config(config_path)
    assert conf

    # get latest inode and inode header version
    inode_id = '{}.{}'.format(datastore_id, inode_uuid)
    inode_hdr_id = '{}.{}.hdr'.format(datastore_id, inode_uuid)

    inode_version = 0
    inode_hdr_version = 0

    res = _get_mutable_data_versions( inode_id, device_ids, config_path=CONFIG_PATH )
    if 'error' in res:
        return res

    inode_version = res['version']

    if inode_hdr_version is None:
        res = _get_mutable_data_versions( inode_hdr_id, device_ids, config_path=CONFIG_PATH )
        if 'error' in res:
            return res

        inode_hdr_version = res['version']
        
    '''
    if cache is not None:
        inode_data = cache.get(inode_uuid)
        if inode_data is not None:
            # reconstruct header 
            inode_hdr = {}
            for k in inode_data.keys():
                if k != 'idata':
                    inode_hdr[k] = copy.deepcopy(inode_data[k])

            log.debug("Cache HIT on {}".format(inode_uuid))
            return {'status': True, 'inode': inode_hdr}
    '''

    # get from *all* drivers so we know that if we succeed, we have a fresh version
    data_id = '{}.{}.hdr'.format(datastore_id, inode_uuid)
    res = get_mutable(data_id, ver_min=max(inode_version, inode_hdr_version), data_pubkey=data_pubkey_hex, storage_drivers=drivers, device_ids=device_ids, proxy=proxy, config_path=config_path, all_drivers=True)
    if 'error' in res:
        log.error("Failed to get inode data {}: {}".format(inode_uuid, res['error']))
        return {'error': 'Failed to get inode data'}

    # validate 
    inode_hdr_str = res['data']
    try:
        inode_hdr = data_blob_parse(inode_hdr_str)
    except:
        if BLOCKSTACK_TEST:
            log.error("Unparseable header: {}".format(inode_hdr_str))

        return {'error': "Unparseable inode header"}

    inode_hdr_version = res['version']
    inode_drivers = res['drivers']
    
    try:
        jsonschema.validate(inode_hdr, MUTABLE_DATUM_INODE_HEADER_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        return {'error': "Invalid inode header"}

    # advance header version and inode version
    res = _put_inode_consistency_info(datastore_id, inode_uuid, max(inode_hdr_version, inode_version), device_ids, config_path=config_path)
    if 'error' in res:
        return res

    return {'status': True, 'inode': inode_hdr, 'version': max(inode_hdr_version, inode_version), 'drivers': inode_drivers}


def _put_inode(datastore_id, _inode, data_privkey, drivers, device_ids, config_path=CONFIG_PATH, proxy=None, create=False, cache=None ):
    """
    Store an inode and its associated idata
    If cache is given, invalidate the cache.
    Return {'status': True} on success
    Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    # separate data from metadata.
    # put metadata as a separate record.
    data_id = '{}.{}'.format(datastore_id, _inode['uuid'])
    inode_data = data_blob_serialize(_inode)

    res = put_mutable(data_id, inode_data, data_privkey=data_privkey, storage_drivers=drivers, storage_drivers_exclusive=True, config_path=config_path, proxy=proxy, create=create )
    if 'error' in res:
        log.error("Failed to replicate inode {}: {}".format(_inode['uuid'], res['error']))
        return {'error': 'Failed to replicate inode'}

    inode_version = res['version']

    # make header
    inode_hdr = {}
    for prop in MUTABLE_DATUM_SCHEMA_BASE_PROPERTIES.keys():
        inode_hdr[prop] = copy.deepcopy(_inode[prop])

    # what will get_mutable() return?
    inode_payload = {
        'data': inode_data,
        'version': inode_version,
        'fq_data_id': res['fq_data_id'],
        'timestamp': res['timestamp']
    }

    # put hash of inode payload
    inode_hdr['data_hash'] = _mutable_data_inode_hash( data_blob_serialize(inode_payload) )

    data_hdr_id = '{}.{}.hdr'.format(datastore_id, inode_hdr['uuid'])
    inode_hdr_data = data_blob_serialize(inode_hdr)
    res = put_mutable(data_hdr_id, inode_hdr_data, data_privkey=data_privkey, storage_drivers=drivers, storage_drivers_exclusive=True, config_path=config_path, proxy=proxy, create=create )
    if 'error' in res:
        log.error("Failed to replicate inode header for {}: {}".format(inode['uuid'], res['error']))
        return {'error': 'Failed to replicate inode header'}

    inode_hdr_version = res['version']

    res = _put_inode_consistency_info(datastore_id, _inode['uuid'], max(inode_version, inode_hdr_version), device_ids, config_path=config_path)
    if 'error' in res:
        return res

    '''
    # coherently cache
    if cache is not None and _is_cacheable(_inode):
        log.debug("Cache PUT {}".format(_inode['uuid']))
        cache.put(_inode['uuid'], _inode)
    '''

    return {'status': True}


def _delete_inode(datastore_id, inode_uuid, data_privkey, drivers, device_ids, config_path=CONFIG_PATH, proxy=None, cache=None ):
    """
    Delete an inode and its associated data.
    Return {'status': True} on success
    Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    # delete inode header
    idata_id = '{}.hdr'.format(inode_uuid)
    hdata_id = '{}.{}'.format(datastore_id, idata_id)
    res = delete_mutable(hdata_id, data_privkey=data_privkey, proxy=proxy, storage_drivers=drivers, storage_drivers_exclusive=True, device_ids=device_ids, config_path=config_path)
    if 'error' in res:
        log.error("Faled to delete idata for {}: {}".format(inode_uuid, res['error']))
        return res

    # delete inode 
    data_id = '{}.{}'.format(datastore_id, inode_uuid)
    res = delete_mutable(data_id, data_privkey=data_privkey, proxy=proxy, storage_drivers=drivers, storage_drivers_exclusive=True, device_ids=device_ids, config_path=config_path )
    if 'error' in res:
        log.error("Failed to delete inode {}: {}".format(inode_uuid, res['error']))
        return res

    # invalidate cache 
    if cache is not None:
        cache.evict(inode_uuid)

    return {'status': True}
    

def _resolve_path( datastore, path, data_pubkey, get_idata=True, config_path=CONFIG_PATH, proxy=None ):
    """
    Given a fully-qualified data path, the user's datastore record, and a private key,
    go and traverse the directory heirarchy encoded
    in the data path and fetch the data at the leaf.

    Return the resolved path on success.  If the path was '/a/b/c', then return
    {
        '/': {'uuid': ..., 'name': '', 'uuid': ...., 'parent': '',  'inode': directory},
        '/a': {'uuid': ..., 'name': 'a', 'uuid': ...,  'parent': '/', 'inode': directory},
        '/a/b': {'uuid': ..., 'name': 'b', 'uuid': ..., 'parent': '/a', 'inode': directory},
        '/a/b/c': {'uuid': ..., 'name': 'c', 'uuid': ..., 'parent': '/a/b', 'inode' file}
    }

    Return {'error': ..., 'errno': ...} on error
    """

    global DIR_CACHE

    if proxy is None:
        proxy = get_default_proxy(config_path)

    if DIR_CACHE is None:
        DIR_CACHE = InodeCache()

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
    root_inode = _get_inode(datastore_id, root_uuid, MUTABLE_DATUM_DIR_TYPE, data_pubkey, drivers, device_ids, config_path=CONFIG_PATH, proxy=proxy, cache=DIR_CACHE)
    if 'error' in root_inode:
        log.error("Failed to get root inode: {}".format(root_inode['error']))
        return {'error': root_inode['error'], 'errno': errno.EIO}

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

    for i in xrange(0, len(path_parts)):

        # find child UUID
        name = path_parts[i]
        child_dirent = cur_dir['idata'].get(name, None)

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
        
        # get child
        child_entry = _get_inode(datastore_id, child_uuid, child_type, data_pubkey, drivers, device_ids, config_path=CONFIG_PATH, proxy=proxy, cache=DIR_CACHE)
        if 'error' in child_entry:
            log.error("Failed to get inode {} at {}: {}".format(child_uuid, prefix + name, child_entry['error']))
            return {'error': child_entry['error'], 'errno': errno.EIO}

        child_entry = child_entry['inode']
        assert child_entry['type'] == child_dirent['type'], "Corrupt inode {}".format(storage.make_fq_data_id(datastore_id,child_uuid))

        path_ent = _make_path_entry(name, child_uuid, child_entry, prefix)
        ret[prefix + name] = path_ent
    
        if child_type == MUTABLE_DATUM_FILE_TYPE or i == len(path_parts) - 1:
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
        assert ret.has_key(prefix + name), "BUG: missing {}".format(prefix + name) 
        child_entry = _get_inode(datastore_id, child_uuid, child_type, data_pubkey, drivers, device_ids, config_path=CONFIG_PATH, proxy=proxy )

    else:
        # get only inode header.
        # didn't request idata, so add a path entry here
        assert not ret.has_key(prefix + name), "BUG: already defined {}".format(prefix + name)

        path_ent = _make_path_entry(name, child_uuid, child_entry, prefix)
        ret[prefix + name] = path_ent

        child_entry = _get_inode_header(datastore_id, child_uuid, data_pubkey, drivers, device_ids, config_path=config_path, proxy=proxy, cache=DIR_CACHE)

    if 'error' in child_entry:
        log.error("Failed to get file data for {} at {}: {}".format(child_uuid, prefix + name, child_entry['error']))
        return {'error': child_entry['error'], 'errno': errno.EIO}
    
    child_entry = child_entry['inode']

    # update ret
    ret[prefix + name]['inode'] = child_entry

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


def _mutable_data_make_dir( data_address, inode_uuid, child_links ):
    """
    Set up inode state for a directory
    """
    inode_state = _mutable_data_make_inode( MUTABLE_DATUM_DIR_TYPE, data_address, inode_uuid )
    inode_state['idata'] = child_links
    return inode_state 


def _mutable_data_make_file( data_address, inode_uuid, data_payload ):
    """
    Set up inode state for a file
    """
    inode_state = _mutable_data_make_inode( MUTABLE_DATUM_FILE_TYPE, data_address, inode_uuid )
    inode_state['idata'] = data_payload
    return inode_state


def _mutable_data_dir_link( parent_dir, child_type, child_name, child_uuid, child_links ):
    """
    Attach a child inode to a diretory.
    Return the new parent directory, and the added dirent
    """
    assert 'idata' in parent_dir

    child_links_schema = {
        'type': 'array',
        'items': URI_RECORD_SCHEMA
    }

    assert child_name not in parent_dir['idata'].keys()
    jsonschema.validate(child_links, child_links_schema)

    new_dirent = {
        'uuid': child_uuid,
        'type': child_type,
        'links': child_links
    }

    parent_dir['idata'][child_name] = new_dirent
    return parent_dir, new_dirent


def _mutable_data_dir_unlink( parent_dir, child_name ):
    """
    Detach a child inode from a directory.
    Return the new parent directory.
    """
    assert 'idata' in parent_dir
    assert child_name in parent_dir['idata'].keys()

    del parent_dir['idata'][child_name]
    return parent_dir


def _mutable_data_make_links(datastore_id, inode_uuid, urls=None, driver_names=None ):
    """
    Make a bundle of URI record links for the given inode data.
    This constitutes the directory's idata
    """
    fq_data_id = storage.make_fq_data_id(datastore_id, inode_uuid)

    if urls is None:
        if driver_names is None:
            drivers = storage.get_storage_handlers()
        else:
            drivers = [storage.lookup_storage_handler(name) for name in driver_names]

        urls = storage.get_driver_urls( fq_data_id, drivers )

    data_links = [url_to_uri_record(u) for u in urls]
    return data_links


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


def _lookup(datastore, data_path, data_pubkey, get_idata=True, config_path=CONFIG_PATH, proxy=None ):
    """
    Look up all the inodes along the given fully-qualified path, verifying them and ensuring that they're fresh along the way.

    Return {'status': True, 'path_info': path info: path, 'inode_info': inode info} on success
    Return {'error': ..., 'errno': ...} on error
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    info = _parse_data_path( data_path )

    name = info['iname']
    dirpath = info['parent_path']
    data_path = info['data_path']
    data_pubkey = str(data_pubkey)

    # find the parent directory
    path_info = _resolve_path(datastore, data_path, data_pubkey, get_idata=get_idata, config_path=config_path, proxy=proxy )
    if 'error' in path_info:
        log.error('Failed to resolve {}'.format(dirpath))
        return path_info

    assert data_path in path_info.keys(), "Invalid path data, missing {}:\n{}".format(data_path, json.dumps(path_info, indent=4, sort_keys=True))
    inode_info = path_info[data_path]

    return {'status': True, 'path_info': path_info, 'inode_info': inode_info}


def datastore_mkdir(datastore, data_path, data_privkey_hex, config_path=CONFIG_PATH, proxy=None ):
    """
    Make a directory at the given path.  The parent directory must exist.
    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on failure (optionally with 'stored_child': True set)
    """

    global DIR_CACHE

    if proxy is None:
        proxy = get_default_proxy(config_path)

    if DIR_CACHE is None:
        DIR_CACHE = InodeCache()

    datastore_id = datastore_get_id(datastore['pubkey'])
    path_info = _parse_data_path( data_path )
    parent_path = path_info['parent_path']
    data_path = path_info['data_path']
    name = path_info['iname']

    log.debug("mkdir {}:{}".format(datastore_id, data_path))

    drivers = datastore['drivers']
    device_ids = datastore['device_ids']
    data_pubkey = get_pubkey_hex(str(data_privkey_hex))
    data_address = keylib.public_key_to_address(data_pubkey)

    parent_info = _lookup(datastore, parent_path, data_pubkey, config_path=config_path, proxy=proxy )
    if 'error' in parent_info:
        log.error('Failed to resolve {}'.format(parent_path))
        return parent_info
    
    parent_dir_info = parent_info['inode_info']
    parent_dir = parent_dir_info['inode']
    parent_uuid = parent_dir_info['uuid']

    if parent_dir['type'] != MUTABLE_DATUM_DIR_TYPE:
        log.error('Not a directory: {}'.format(dirpath))
        return {'error': 'Not a directory', 'errno': errno.ENOTDIR}

    # does a file or directory already exist?
    if name in parent_dir['idata'].keys():
        log.error('Already exists: {}'.format(name))
        return {'error': 'Entry already exists', 'errno': errno.EEXIST}
    
    # make a directory!
    child_uuid = str(uuid.uuid4())
    child_dir_links = _mutable_data_make_links(datastore_id, child_uuid, driver_names=drivers )
    child_dir_inode = _mutable_data_make_dir( data_address, child_uuid, {} )

    # update parent 
    parent_dir, child_dirent = _mutable_data_dir_link( parent_dir, MUTABLE_DATUM_DIR_TYPE, name, child_uuid, child_dir_links )

    # replicate the new child
    res = _put_inode(datastore_id, child_dir_inode, str(data_privkey_hex), drivers, device_ids, config_path=config_path, proxy=proxy, create=True, cache=DIR_CACHE )
    if 'error' in res:
        log.error("Failed to create directory {}: {}".format(data_path, res['error']))
        return {'error': 'Failed to store child directory', 'errno': errno.EIO}

    # replicate the new parent 
    res = _put_inode(datastore_id, parent_dir, str(data_privkey_hex), drivers, device_ids, config_path=config_path, proxy=proxy, cache=DIR_CACHE )
    if 'error' in res:
        log.error("Failed to update directory {}: {}".format(parent_path, res['error']))
        return {'error': 'Failed to store parent directory', 'stored_child': True, 'errno': errno.EIO}

    return {'status': True}


def datastore_rmdir(datastore, data_path, data_privkey_hex, config_path=CONFIG_PATH, proxy=None ):
    """
    Remove a directory at the given path.  The directory must be empty.
    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on error
    """
    global DIR_CACHE

    if proxy is None:
        proxy = get_default_proxy(config_path)
   
    if DIR_CACHE is None:
        DIR_CACHE = InodeCache()

    datastore_id = datastore_get_id(datastore['pubkey'])
    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    name = path_info['iname']

    if data_path == '/':
        # can't do this 
        log.error("Will not delete /")
        return {'error': 'Tried to delete root', 'errno': errno.EINVAL}

    drivers = datastore['drivers']
    device_ids = datastore['device_ids']
    data_pubkey = get_pubkey_hex(str(data_privkey_hex))

    log.debug("rmdir {}:{}".format(datastore_id, data_path))

    dir_info = _lookup(datastore, data_path, data_pubkey, config_path=config_path, proxy=proxy )
    if 'error' in dir_info:
        log.error('Failed to resolve {}'.format(data_path))
        return {'error': dir_info['error'], 'errno': errno.ENOENT}

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

    # is this directory empty?
    if len(dir_inode['idata']) > 0:
        log.error("Directory {} has {} entries".format(data_path, len(dir_inode['idata'])))
        return {'error': 'Directory not empty', 'errno': errno.ENOTEMPTY}

    # good to do.  Update parent 
    parent_dir_inode = _mutable_data_dir_unlink( parent_dir_inode, name )
    res = _put_inode(datastore_id, parent_dir_inode, str(data_privkey_hex), drivers, device_ids, config_path=config_path, proxy=proxy, cache=DIR_CACHE )
    if 'error' in res:
        log.error("Failed to update directory {}: {}".format(parent_path, res['error']))
        return {'error': 'Failed to update directory', 'errno': errno.EIO}

    # delete the child
    res = _delete_inode(datastore_id, dir_inode_uuid, str(data_privkey_hex), drivers, device_ids, config_path=config_path, proxy=proxy, cache=DIR_CACHE )
    if 'error' in res:
        log.error("Failed to delete directory {}: {}".format(data_path, res['error']))
        return {'error': 'Failed to delete directory', 'errno': errno.EIO}

    return {'status': True}


def datastore_getfile(datastore, data_path, config_path=CONFIG_PATH, proxy=None ):
    """
    Get a file identified by a path.
    Return {'status': True, 'file': inode and data}
    Return {'error': ..., 'errno': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    
    datastore_id = datastore_get_id(datastore['pubkey'])
    drivers = datastore['drivers']
    
    log.debug("getfile {}:{}".format(datastore_id, data_path))

    file_info = _lookup(datastore, data_path, datastore['pubkey'], config_path=CONFIG_PATH, proxy=proxy )
    if 'error' in file_info:
        log.error("Failed to resolve {}".format(data_path))
        return file_info

    if file_info['inode_info']['inode']['type'] != MUTABLE_DATUM_FILE_TYPE:
        log.error("Not a file: {}".format(data_path))
        return {'error': 'Not a file', 'errno': errno.EISDIR}

    return {'status': True, 'file': file_info['inode_info']['inode']}


def datastore_listdir(datastore, data_path, config_path=CONFIG_PATH, proxy=None ):
    """
    Get a file identified by a path.
    Return {'status': True, 'dir': inode and data}
    Return {'error': ..., 'errno': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    
    datastore_id = datastore_get_id(datastore['pubkey'])
    drivers = datastore['drivers']
    
    log.debug("listdir {}:{}".format(datastore_id, data_path))

    dir_info = _lookup(datastore, data_path, datastore['pubkey'], config_path=CONFIG_PATH, proxy=proxy )
    if 'error' in dir_info:
        log.error("Failed to resolve {}".format(data_path))
        return dir_info

    if dir_info['inode_info']['inode']['type'] != MUTABLE_DATUM_DIR_TYPE:
        log.error("Not a file: {}".format(data_path))
        return {'error': 'Not a file', 'errno': errno.EISDIR}

    return {'status': True, 'dir': dir_info['inode_info']['inode']}


def datastore_putfile(datastore, data_path, file_data, data_privkey_hex, create=False, config_path=CONFIG_PATH, proxy=None ):
    """
    Store a file identified by a path.
    If @create is True, then will only succeed if created.
    Return {'status': True} on success.
    Return {'error': ..., 'errno': ...} on error.
    """

    global DIR_CACHE

    if proxy is None:
        proxy = get_default_proxy(config_path)
 
    if DIR_CACHE is None:
        DIR_CACHE = InodeCache()

    datastore_id = datastore_get_id(datastore['pubkey'])
    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    name = path_info['iname']
    parent_dirpath = path_info['parent_path']

    drivers = datastore['drivers']
    device_ids = datastore['device_ids']

    data_pubkey = get_pubkey_hex(str(data_privkey_hex))
    data_address = keylib.public_key_to_address(data_pubkey)
    
    log.debug("putfile {}:{}".format(datastore_id, data_path))

    # make sure the file doesn't exist
    parent_path_info = _lookup(datastore, parent_dirpath, data_pubkey, config_path=config_path, proxy=proxy )
    if 'error' in parent_path_info:
        log.error("Failed to resolve {}".format(data_path))
        return parent_path_info

    parent_dir_info = parent_path_info['inode_info']
    parent_uuid = parent_dir_info['uuid']
    parent_dir_inode = parent_dir_info['inode']

    if name in parent_dir_inode['idata'].keys() and create:
        # already exists
        log.error('Already exists: {}'.format(data_path))
        return {'error': 'Already exists', 'errno': errno.EEXIST}

    # make a file!
    child_uuid = str(uuid.uuid4())
    child_file_links = _mutable_data_make_links( datastore_id, child_uuid, driver_names=drivers )
    child_file_inode = _mutable_data_make_file( data_address, child_uuid, file_data )

    # update parent 
    parent_dir_inode, child_dirent = _mutable_data_dir_link( parent_dir_inode, MUTABLE_DATUM_FILE_TYPE, name, child_uuid, child_file_links )
    
    # replicate the new child (but don't cache files)
    res = _put_inode(datastore_id, child_file_inode, str(data_privkey_hex), drivers, device_ids, config_path=config_path, proxy=proxy, create=create )
    if 'error' in res:
        log.error("Failed to replicate file {}: {}".format(data_path, res['error']))
        return {'error': 'Failed to store file', 'errno': errno.EIO}

    # replicate the new parent
    res = _put_inode(datastore_id, parent_dir_inode, str(data_privkey_hex), drivers, device_ids, config_path=config_path, proxy=proxy, cache=DIR_CACHE )
    if 'error' in res:
        log.error("Failed to update directory {}: {}".format(parent_dirpath, res['error']))
        return {'error': 'Failed to update directory', 'errno': errno.EIO}

    return {'status': True}


def datastore_deletefile(datastore, data_path, data_privkey_hex, config_path=CONFIG_PATH, proxy=None ):
    """
    Delete a file from a directory.
    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on error
    """

    global DIR_CACHE

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)
 
    if DIR_CACHE is None:
        DIR_CACHE = InodeCache()

    datastore_id = datastore_get_id(datastore['pubkey'])
    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    name = path_info['iname']
    parent_dirpath = path_info['parent_path']

    drivers = datastore['drivers']
    device_ids = datastore['device_ids']

    data_pubkey = get_pubkey_hex(str(data_privkey_hex))

    log.debug("deletefile {}:{}".format(datastore_id, data_path))

    file_path_info = _lookup( datastore, data_path, data_pubkey, get_idata=False, config_path=config_path, proxy=proxy )
    if 'error' in file_path_info:
        log.error('Failed to resolve {}'.format(data_path))
        return file_path_info

    # is this a directory?
    file_inode_info = file_path_info['inode_info']
    file_uuid = file_inode_info['uuid']
    file_inode = file_inode_info['inode']

    if file_inode['type'] != MUTABLE_DATUM_FILE_TYPE:
        log.error('Not a file: {}'.format(data_path))
        return {'error': 'Not a file', 'errno': errno.EISDIR}
    
    # get parent of this directory
    parent_dir_inode_info = file_path_info['path_info'][file_inode_info['parent']]
    parent_dir_uuid = parent_dir_inode_info['uuid']
    parent_dir_inode = parent_dir_inode_info['inode']

    # Update parent 
    parent_dir_inode = _mutable_data_dir_unlink( parent_dir_inode, name )
    res = _put_inode(datastore_id, parent_dir_inode, str(data_privkey_hex), drivers, device_ids, config_path=config_path, proxy=proxy, cache=DIR_CACHE )
    if 'error' in res:
        log.error("Failed to update directory {}: {}".format(dir_path, res['error']))
        return {'error': 'Failed to update directory', 'errno': errno.EIO}

    # delete child 
    res = _delete_inode(datastore_id, file_uuid, str(data_privkey_hex), drivers, device_ids, config_path=config_path, proxy=proxy )
    if 'error' in res:
        log.error("Failed to delete file {}: {}".format(data_path, res['error']))
        return {'error': 'Failed to delete file', 'errno': errno.EIO}

    return {'status': True}


def datastore_stat(datastore, data_path, config_path=CONFIG_PATH, proxy=None ):
    """
    Stat a file.  Get just the inode metadata.
    Return {'status': True, 'inode': inode info} on success
    Return {'error': ..., 'errno': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    datastore_id = datastore_get_id(datastore['pubkey'])
    drivers = datastore['drivers']
    
    log.debug("stat {}:{}".format(datastore_id, data_path))

    inode_info = _lookup(datastore, data_path, datastore['pubkey'], get_idata=False, config_path=CONFIG_PATH, proxy=proxy )
    if 'error' in inode_info:
        log.error("Failed to resolve {}".format(data_path))
        return inode_info

    return {'status': True, 'inode': inode_info['inode_info']['inode']}


def datastore_rmtree(datastore, data_path, data_privkey_hex, config_path=CONFIG_PATH, proxy=None):
    """
    Remove a directory tree and all its children.
    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on error
    """

    global DIR_CACHE

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)
 
    if DIR_CACHE is None:
        DIR_CACHE = InodeCache()

    datastore_id = datastore_get_id(datastore['pubkey'])
    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    data_pubkey_hex = get_pubkey_hex(data_privkey_hex)
    data_address = keylib.public_key_to_address(data_pubkey_hex)

    drivers = datastore['drivers']
    device_ids = datastore['device_ids']

    inode_stack = []        # stack of {'type': ..., 'inode': ...}

    dir_path_info = _lookup( datastore, data_path, data_pubkey_hex, config_path=config_path, proxy=proxy )
    if 'error' in dir_path_info:
        log.error('Failed to resolve {}'.format(data_path))
        return dir_path_info

    # is this a directory?
    dir_inode_info = dir_path_info['inode_info']
    dir_uuid = dir_inode_info['uuid']
    dir_inode = dir_inode_info['inode']

    if dir_inode['type'] != MUTABLE_DATUM_DIR_TYPE:
        # file.  remove 
        return datastore_deletefile(datastore, data_path, data_privkey_hex, config_path=config_path, proxy=proxy)

    
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

        res = _get_inode(datastore_id, dir_inode_uuid, MUTABLE_DATUM_DIR_TYPE, str(data_pubkey_hex), drivers, device_ids, config_path=config_path, proxy=proxy, cache=DIR_CACHE)
        if 'error' in res:
            return res
        
        if res['inode']['type'] == MUTABLE_DATUM_FILE_TYPE:
            return {'status': True, 'stack': stack, 'num_added': 0}

        dirents = res['inode']['idata']

        return _stack_push( dirents, stack )

    
    inode_stack = []
    res = _stack_push( dir_inode['idata'], inode_stack )
    inode_stack = res['stack']

    while len(inode_stack) > 0:

        # next entry to delete 
        inode_info = inode_stack[-1]

        if inode_info['type'] == MUTABLE_DATUM_FILE_TYPE:
            # files can be deleted immediately 
            log.debug("Delete file {}".format(inode_info['uuid']))
            res = _delete_inode(datastore_id, inode_info['uuid'], str(data_privkey_hex), drivers, device_ids, config_path=config_path, proxy=proxy )
            if 'error' in res:
                return res

            # done 
            inode_stack.pop()

        else:
            # already explored?
            if inode_info['searched']:
                # already explored this directory.  Can remove now
                log.debug("Delete directory {}".format(inode_info['uuid']))
                res = _delete_inode(datastore_id, inode_info['uuid'], str(data_privkey_hex), drivers, device_ids, config_path=config_path, proxy=proxy, cache=DIR_CACHE)
                if 'error' in res:
                    return res

                # done
                inode_stack.pop()

            else:
                # explore directories.  Only remove empty ones.
                inode_stack[-1]['searched'] = True
                res = _search(inode_info['uuid'], inode_stack)
                if 'error' in res:
                    return res

                inode_stack = res['stack']

    # clear this inode's children
    dir_inode_info = _mutable_data_make_dir( data_address, dir_uuid, {} )
    res = _put_inode(datastore_id, dir_inode_info, str(data_privkey_hex), drivers, device_ids, config_path=config_path, proxy=proxy, create=False, cache=DIR_CACHE )
    if 'error' in res:
        return res

    return {'status': True}


def get_nonlocal_storage_drivers(config_path, key='storage_drivers'):
    """
    Get the list of non-local storage drivers.
    That is, the ones which write to a globally-visible read-write medium.
    """

    conf = get_config(config_path)
    assert conf

    storage_drivers = conf.get(key, '').split(',')
    local_storage_drivers = conf.get('storage_drivers_local', '').split(',')

    for drvr in local_storage_drivers:
        if drvr in storage_drivers:
            storage_drivers.remove(drvr)

    return storage_drivers


def get_write_storage_drivers(config_path):
    """
    Get the list of storage drivers to write with.
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

