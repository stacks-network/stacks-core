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

from .config import get_logger, get_config
from .constants import BLOCKSTACK_TEST, BLOCKSTACK_DEBUG
from .schemas import *

log = get_logger()

DATASTORE_CACHE = {}
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
    return urllib.quote(data_id.replace('\0', '\\0')).replace('/', r'\x2f')


def load_mutable_data_version(conf, fq_data_id):
    """
    Get the version field of a piece of mutable data from local cache.
    """

    # try to get the current, locally-cached version
    conf = config.get_config() if conf is None else conf

    if conf is None:
        msg = 'No config found; cannot load version for "{}"'
        log.debug(msg.format(fq_data_id))
        return None

    metadata_dir = conf.get('metadata', None)
    if metadata_dir is None or not os.path.isdir(metadata_dir):
        return None

    # find the version file for this data
    serialized_data_id = serialize_mutable_data_id(fq_data_id)
    version_file_path = os.path.join(metadata_dir, '{}.ver'.format(serialized_data_id))

    if not os.path.exists(version_file_path):
        log.debug('No version path found at {}'.format(version_file_path))
        return None

    try:
        with open(version_file_path, 'r') as f:
            ver_txt = f.read()
            # success!
            return int(ver_txt.strip())
    except ValueError as ve:
        log.warn('Not an integer: "{}"'.format(version_file_path))
    except Exception as e:
        log.warn('Failed to read "{}"'.format(version_file_path))

    return None


def store_mutable_data_version(conf, fq_data_id, ver):
    """
    Locally store the version of a piece of mutable data,
    so we can ensure that its version is incremented on
    subsequent puts.

    Return True if stored
    Return False if not
    """

    conf = config.get_config() if conf is None else conf

    if conf is None:
        msg = 'No config found; cannot store version for "{}"'
        log.warning(msg.format(fq_data_id))
        return False

    metadata_dir = conf.get('metadata', '')

    assert metadata_dir, 'Missing metadata directory'

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

    serialized_data_id = serialize_mutable_data_id(fq_data_id)
    version_file_path = os.path.join(
        metadata_dir, '{}.ver'.format(serialized_data_id)
    )

    try:
        with open(version_file_path, 'w') as f:
            f.write(str(ver))
            f.flush()
            os.fsync(f.fileno())
        return True

    except Exception as e:
        # failed for whatever reason
        log.exception(e)
        msg = 'Failed to store version of "{}" to "{}"'
        log.warn(msg.format(fq_data_id, version_file_path))

    return False


def delete_mutable_data_version(conf, data_id):
    """
    Locally delete the version of a piece of mutable data.

    Return True if deleted.
    Return False if not
    """

    conf = config.get_config() if conf is None else conf

    if conf is None:
        msg = 'No config found; cannot store version for "{}"'
        log.warning(msg.format(data_id))
        return False

    metadata_dir = conf['metadata']
    if not os.path.isdir(metadata_dir):
        msg = 'No metadata directory found; cannot store version of "{}"'
        log.warning(msg.format(data_id))
        return False

    serialized_data_id = data_id.replace('/', '\x2f').replace('\0', '\\0')
    version_file_path = os.path.join(
        metadata_dir, '{}.ver'.format(serialized_data_id)
    )

    try:
        os.unlink(version_file_path)
        return True
    except Exception as e:
        # failed for whatever reason
        msg = 'Failed to remove version file "{}"'
        log.warn(msg.format(version_file_path))

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
    if user_zonefile is None:
        return {'error': 'No user zonefile defined'}

    if 'error' in user_zonefile:
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
                return {'error': 'Data ID/hash mismatch'}
            else:
                msg = 'Multiple matches for "{}": {}'
                return {'error': msg.format(data_id, ','.join(h))}

        h = hs[0]
        if data_hash is not None:
            if h != data_hash:
                return {'error': 'Data ID/hash mismatch'}
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
    for block_id in block_ids:
        history_items = name_history[block_id]
        for history_item in history_items:
            value_hash = history_item.get('value_hash', None)
            if value_hash is None:
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


def load_user_data_pubkey_addr( name, storage_drivers=None, proxy=None ):
    """
    Get a user's default data public key and/or owner address.

    Returns {'pubkey': ..., 'address': ...} on success
    Return {'error': ...} on error
    """
    # need to find pubkey to use
    user_zonefile = get_name_zonefile( name, storage_drivers=storage_drivers, proxy=proxy, include_name_record=True)
    if user_zonefile is None:
        log.error("No zonefile for {}".format(name))
        return {'error': 'No zonefile'}

    if 'error' in user_zonefile:
        log.error("Failed to load zonefile for {}: {}".format(name, user_zonefile['error']))
        return {'error': 'Failed to load zonefile'}

    # recover name record
    name_record = user_zonefile.pop('name_record')
    user_zonefile = user_zonefile['zonefile']

    # get user's data public key and owner address
    data_pubkey = user_db.user_zonefile_data_pubkey(user_zonefile)
    data_address = name_record['address']
    if data_pubkey is None:
        log.warn('Falling back to owner address for authentication')

    if data_address is None:
        log.error("No public key or address usable")
        return {'error': 'No usable data public key or address'}

    return {'pubkey': data_pubkey, 'address': data_address}


def get_mutable(name, data_id, data_pubkey=None, data_address=None, storage_drivers=None, proxy=None, ver_min=None, ver_max=None, urls=None, config_path=CONFIG_PATH):
    """
    get_mutable 

    Fetch a piece of mutable data.

    If @ver_min is given, ensure the data's version is greater or equal to it.
    If @ver_max is given, ensure the data's version is less than it.
    
    If data_pubkey or data_address is given, then name can be arbitrary

    Return {'data': the data, 'version': the version, 'timestamp': ..., 'data_pubkey': ..., 'owner_pubkey_hash': ...} on success
    Return {'error': ...} on error
    """

    proxy = get_default_proxy(config_path) if proxy is None else proxy
    conf = config.get_config(path=config_path)

    fq_data_id = None
    if data_id is not None and len(data_id) > 0:
        fq_data_id = storage.make_fq_data_id(name, data_id)
    else:
        fq_data_id = name

    if data_address is None and data_pubkey is None:
        # need to find pubkey to use
        pubkey_info = load_user_data_pubkey_addr( name, storage_drivers=storage_drivers, proxy=proxy )
        if 'error' in pubkey_info:
            return pubkey_info

        data_pubkey = pubkey_info['pubkey']
        data_address = pubkey_info['address']

        if data_pubkey is None and data_address is None:
            log.error("No data public key or address available")
            return {'error': 'No data public key or address available'}

    expected_version = load_mutable_data_version(conf, fq_data_id)
    expected_version = 1 if expected_version is None else expected_version

    if storage_drivers is None:
        storage_drivers = get_read_storage_drivers(config_path)

    mutable_data = None

    # which storage drivers and/or URLs will we use?
    for driver in storage_drivers: 

        mutable_data = None 

        # get the mutable data itsef
        mutable_data = storage.get_mutable_data(fq_data_id, data_pubkey, urls=urls, drivers=[driver], data_address=data_address)
        if mutable_data is None:
            log.error("Failed to get mutable datum {}".format(fq_data_id))
            return {'error': 'Failed to look up mutable datum'}

        try:
            jsonschema.validate(mutable_data, DATA_BLOB_SCHEMA)
        except ValidationError as ve:
            if BLOCKSTACK_DEBUG:
                log.exception(ve)

            log.warn("Invalid mutable data from {} for {}".format(driver, fq_data_id))
            continue

        # check consistency
        version = mutable_data['version']
        if ver_min is not None and ver_min > version:
            log.warn("Invalid (stale) data version from {} for {}: ver_min = {}, version = {}".format(driver, fq_data_id, ver_min, version))
            continue

        elif ver_max is not None and ver_max <= version:
            log.warn("Invalid (future) data version from {} for {}: ver_max = {}, version = {}".format(driver, fq_data_id, ver_max, version))
            continue

        elif expected_version > version:
            log.warn("Invalid (stale) data version from {} for {}: expected = {}, version = {}".format(driver, fq_data_id, expected_version, version))
            continue

        # success!
        break

    if mutable_data is None:
        log.error("Failed to fetch mutable data for {}".format(fq_data_id))
        return {'errror': 'Failed to fetch mutable data'}

    rc = store_mutable_data_version(conf, fq_data_id, version)
    if not rc:
        return {'error': 'Failed to store consistency information'}

    ret = {
        'data': mutable_data['data'],
        'version': version,
        'timestamp': mutable_data['timestamp'],
        'data_pubkey': data_pubkey,
        'owner_pubkey_hash': data_address
    }

    return ret



def put_immutable(name, data_id, data_json, data_url=None, txid=None, proxy=None, wallet_keys=None, config_path=CONFIG_PATH):
    """
    put_immutable

    Given a user's name, the data ID, and a JSON-ified chunk of data,
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

    if not isinstance(data_json, dict):
        raise ValueError('Immutable data must be a dict')

    proxy = get_default_proxy(config_path) if proxy is None else proxy

    # NOTE: only accept non-legacy zone files
    user_zonefile = get_name_zonefile(name, proxy=proxy)
    if user_zonefile is None:
        log.debug("Unable to load zone file for '{}'".format(name))
        return {'error': 'Unparseable zone file'}

    user_zonefile = user_zonefile['zonefile']

    data_text = storage.serialize_immutable_data(data_json)
    data_hash = storage.get_data_hash(data_text)

    # insert into user zonefile, overwriting if need be
    if user_db.has_immutable_data_id(user_zonefile, data_id):
        log.debug('WARN: overwriting old "{}"'.format(data_id))
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
            name, user_zonefile_txt, None, owner_privkey_info,
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

    rc = store_name_zonefile(name, user_zonefile, txid)
    if not rc:
        result['error'] = 'Failed to store zonefile'
        return result

    # success!
    result['status'] = True
    result['zonefile'] = user_zonefile

    return result


def load_user_data_privkey( name, storage_drivers=None, proxy=None, config_path=CONFIG_PATH, wallet_keys=None ):
    """
    Get the user's data private key from his/her wallet.
    Verify it matches the zone file for this name.

    Return {'privkey': ...} on success
    Return {'error': ...} on error
    """
    conf = get_config(path=CONFIG_PATH)
    user_zonefile = get_name_zonefile( name, storage_drivers=storage_drivers, proxy=proxy)
    if user_zonefile is None:
        log.error("No zonefile for {}".format(name))
        return {'error': 'No zonefile'}

    if 'error' in user_zonefile:
        log.error("Failed to load zonefile for {}: {}".format(name, user_zonefile['error']))
        return {'error': 'Failed to load zonefile'}

    # recover name record and zonefile
    user_zonefile = user_zonefile['zonefile']

    # get the data key
    data_privkey = get_data_privkey_info(user_zonefile, wallet_keys=wallet_keys, config_path=config_path)
    if 'error' in data_privkey:
        # error text
        return {'error': data_privkey['error']}

    else:
        data_privkey = data_privkey['privatekey']
        assert data_privkey is not None

    return {'privkey': data_privkey}


def put_mutable(name, data_id, data_payload, data_privkey=None, proxy=None, storage_drivers=None, zonefile_storage_drivers=None, version=None, wallet_keys=None, config_path=CONFIG_PATH, create=False):
    """
    put_mutable.

    Given a name, an ID for the data, and the data itself, sign and upload the data to the
    configured storage providers.

    If data_privkey is given, then name can be arbitrary

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

    Returns a dict with {'status': True, 'version': version, ...} on success
    Returns a dict with 'error' set on failure
    """

    proxy = get_default_proxy(config_path) if proxy is None else proxy
    fq_data_id = storage.make_fq_data_id(name, data_id)
    conf = config.get_config(path=config_path)

    if storage_drivers is None:
        storage_drivers = get_write_storage_drivers(config_path)

    if data_privkey is None:
        data_privkey_info = load_user_data_privkey( name, storage_drivers=zonefile_storage_drivers, proxy=proxy, config_path=config_path, wallet_keys=wallet_keys )
        if 'error' in data_privkey_info:
            log.error("Failed to load data private key")
            return {'error': 'Failed to load data private key'}

        data_privkey = data_privkey_info['privkey']

    # get the version to use
    if version is None:
        version = load_mutable_data_version(conf, fq_data_id)
        if version is not None and create:
            log.error("Already exists: {}".format(fq_data_id))
            return {'error': 'Data exists'}

        version = 1 if version is None else version + 1

    # put the mutable data record itself
    data_json = {
        'data': data_payload,
        'version': version,
        'timestamp': int(time.time())
    }
    
    result = {}

    rc = storage.put_mutable_data(fq_data_id, data_json, data_privkey, required=storage_drivers)
    if not rc:
        result['error'] = 'Failed to store mutable data'
        return result

    # remember which version this was
    rc = store_mutable_data_version(conf, fq_data_id, version)
    if not rc:
        result['error'] = 'Failed to store mutable data version'
        return result

    result['status'] = True
    result['version'] = version

    if BLOCKSTACK_TEST is not None:
        msg = 'Put "{}" to {} mutable data (version {})'
        log.debug(msg.format(data_id, name, version))

    return result


def delete_immutable(name, data_key, data_id=None, proxy=None, txid=None, wallet_keys=None, config_path=CONFIG_PATH):
    """
    delete_immutable

    Remove an immutable datum from a name's zonefile, given by @data_key.
    Return a dict with {'status': True, 'zonefile_hash': ..., 'zonefile': ...} on success
    Return a dict with {'error': ...} on failure
    """

    from backend.nameops import async_update

    proxy = get_default_proxy(config_path) if proxy is None else proxy

    user_zonefile = get_name_zonefile(name, proxy=proxy, include_name_record=True)
    if user_zonefile is None:
        if 'error' in user_zonefile:
            return user_zonefile

        return {'error': 'No user zonefile'}

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
            name, user_zonefile_txt, None, owner_privkey_info,
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
    rc = store_name_zonefile(name, user_zonefile, txid)
    if not rc:
        result['error'] = 'Failed to put new zonefile'
        return result

    # delete immutable data
    data_privkey = get_data_privkey_info(user_zonefile, wallet_keys=wallet_keys, config_path=config_path)
    if 'error' in data_privkey:
        return {'error': data_privkey['error']}
    else:
        data_privkey = data_privkey['privatekey']
        assert data_privkey is not None

    rc = storage.delete_immutable_data(data_key, txid, data_privkey)
    if not rc:
        result['error'] = 'Failed to delete immutable data'
    else:
        result['status'] = True

    return result


def delete_mutable(name, data_id, data_privkey=None, proxy=None, storage_drivers=None, wallet_keys=None, delete_version=True, config_path=CONFIG_PATH):
    """
    delete_mutable

    Remove a piece of mutable data. Delete it from
    the storage providers as well.

    Optionally (by default) delete cached version information

    If data_privkey is given, then name can be arbitrary

    Returns a dict with {'status': True} on success
    Returns a dict with {'error': ...} on failure
    """

    proxy = get_default_proxy(config_path) if proxy is None else proxy
    conf = get_config(config_path)
    assert conf

    fq_data_id = storage.make_fq_data_id(name, data_id)
    
    if data_privkey is None:
        data_privkey_info = load_user_data_privkey( name, storage_drivers=storage_drivers, proxy=proxy, config_path=config_path, wallet_keys=wallet_keys )
        if 'error' in data_privkey_info:
            log.error("Failed to load data private key")
            return {'error': 'Failed to load data private key'}

        data_privkey = data_privkey_info['privkey']

    # remove the data itself
    rc = storage.delete_mutable_data(fq_data_id, data_privkey, only_use=storage_drivers)
    if not rc:
        return {'error': 'Failed to delete mutable data from storage providers'}

    if delete_version:
        delete_mutable_data_version(conf, fq_data_id)

    return {'status': True}


def list_immutable_data(name, proxy=None, config_path=CONFIG_PATH):
    """
    List the names and hashes of all immutable data in a user's zonefile.
    Returns {'data': [{'data_id': data_id, 'hash': hash}]} on success
    Returns {'error': ...} on error
    """
    proxy = get_default_proxy(config_path) if proxy is None else proxy

    user_zonefile = get_name_zonefile(name, proxy=proxy)
    if user_zonefile is None:
        return {'error': 'No user zonefile defined'}

    if 'error' in user_zonefile:
        return user_zonefile

    user_zonefile = user_zonefile['zonefile']

    if is_obsolete_zonefile(user_zonefile):
        # zonefile is really a legacy profile
        return {'data': []}

    names_and_hashes = user_db.list_immutable_data(user_zonefile)
    listing = [{'data_id': nh[0], 'hash': nh[1]} for nh in names_and_hashes]

    return {'data': listing}


def set_data_pubkey(name, data_pubkey, proxy=None, wallet_keys=None, txid=None, config_path=CONFIG_PATH):
    """
    Set the data public key for a name.
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
    user_zonefile = get_name_zonefile(name, proxy=proxy)
    if user_zonefile is None:
        log.debug("Unable to load zone file for '{}'".format(name))
        return {'error': 'Unparseable zone file'}

    user_zonefile = user_zonefile['zonefile']

    user_db.user_zonefile_set_data_pubkey(user_zonefile, data_pubkey)
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
            name, user_zonefile_txt, None, owner_privkey_info,
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
    rc = store_name_zonefile(name, user_zonefile, txid)
    if not rc:
        result['error'] = 'Failed to store zonefile'
        return result

    # success!
    result['status'] = True
    return result


def datastore_dir(config_path=CONFIG_PATH):
    """
    Get the directory that holds all datastore state
    """
    conf = get_config(path=config_path)
    assert conf

    datastore_dir = conf['datastores']
    if posixpath.normpath(os.path.abspath(datastore_dir)) != posixpath.normpath(conf['datastores']):
        # relative path; make absolute
        datastore_dir = posixpath.normpath( os.path.join(os.path.dirname(config_path), datastore_dir) )

    return datastore_dir


def _make_datastore_name( user_id, datastore_name ):
    """
    Make a datastore name
    """
    assert re.match(OP_USER_ID_PATTERN, user_id)
    assert re.match(OP_DATASTORE_ID_PATTERN, datastore_name)
    return "{}@{}".format(user_id, datastore_name)


def datastore_path(user_id, datastore_name, config_path=CONFIG_PATH):
    """
    Get the path to the private datastore information.
    """
    datastore_filename = _make_datastore_name(user_id, datastore_name) + ".datastore"
    datastore_dirp = datastore_dir(config_path=config_path)

    return os.path.join(datastore_dirp, datastore_filename)


def datastore_list(config_path=CONFIG_PATH, pubkey_hex=None):
    """
    Get the list of datastores controlled on this host.
    Return {'datastore_name': ..., 'user_id': ...} list on success
    """
    datastore_dirp = datastore_dir(config_path=config_path)
    if not os.path.exists(datastore_dirp) or not os.path.isdir(datastore_dirp):
        log.error("No datastore directory")
        return []

    names = os.listdir(datastore_dirp)
    names = filter(lambda n: n.endswith(".datastore"), names)

    ret = []
    for name in names:
        datastore_info = _datastore_load_path(os.path.join(datastore_dirp, name), pubkey_hex, config_path=config_path)
        if 'error' in datastore_info:
            continue

        ret.append( datastore_info['datastore'] )

    return ret
    

def datastore_store(token, config_path=CONFIG_PATH):
    """
    Store a datastore record (as a JWT) locally
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    global DATASTORE_CACHE

    jwt = jsontokens.decode_token(token)
    payload = jwt['payload']
    jsonschema.validate(payload, DATASTORE_SCHEMA)

    user_id = payload['user_id']
    datastore_name = payload['datastore_name']
    path = datastore_path( user_id, datastore_name, config_path=config_path)
    try:
        pathdir = os.path.dirname(path)
        if not os.path.exists(pathdir):
            os.makedirs(pathdir)

        with open(path, "w") as f:
            f.write(token)

    except:
        log.error("Failed to store datastore record {}".format(path))
        return {'error': 'Failed to store datastore record'}

    cache_name = _make_datastore_name(user_id, datastore_name)
    if DATASTORE_CACHE.has_key(cache_name):
        del DATASTORE_CACHE[cache_name]

    return {'status': True}
   

def datastore_unlink( user_id, datastore_name, config_path=CONFIG_PATH ):
    """
    Delete a local datastore record
    Return {'status': True} on success
    """
    global DATASTORE_CACHE

    path = datastore_path(user_id, datastore_name, config_path=config_path)
    if not os.path.exists(path):
        return {'error': 'No such datastore'}

    try:
        os.unlink(path)
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to unlink'}

    cache_name = _make_datastore_name(user_id, datastore_name)
    if DATASTORE_CACHE.has_key(cache_name):
        del DATASTORE_CACHE[cache_name]

    return {'status': True}


def _datastore_load_path(path, data_pubkey_hex, config_path=CONFIG_PATH):
    """
    Load a datastore from a given path
    Verify it conforms to the DATASTORE_SCHEMA
    Return {'datastore': ..., 'datastore_token': ...} on success
    Return {'error': ...} on error
    """

    jwt = None
    try:
        with open(path, "r") as f:
            jwt = f.read()

    except:
        log.error("Failed to load {}".format(path))
        return {'error': 'Failed to read datastore'}

    if data_pubkey_hex is not None:
        # verify
        verifier = jsontokens.TokenVerifier()
        valid = verifier.verify( jwt, data_pubkey_hex )
        if not valid:
            return {'error': 'Failed to verify datastore JWT data'}

    data = jsontokens.decode_token( jwt )
    jsonschema.validate(data['payload'], DATASTORE_SCHEMA)
    return {'datastore': data['payload'], 'datastore_token': jwt}


def datastore_load(user_id, datastore_name, data_pubkey_hex, config_path=CONFIG_PATH):
    """
    Load a datastore record from disk
    Return {'datastore': datastore, 'datastore_token': token} on success
    Return {'error': ...} on error
    """
    global DATASTORE_CACHE

    cache_name = _make_datastore_name(user_id, datastore_name)
    if DATASTORE_CACHE.has_key(cache_name):
        log.debug("Datastore {} is cached".format(cache_name))
        return DATASTORE_CACHE[cache_name]

    path = datastore_path( user_id, datastore_name, config_path=config_path)
    res = _datastore_load_path(path, data_pubkey_hex, config_path=config_path)
    if 'error' in res:
        return res

    DATASTORE_CACHE[cache_name] = res
    return res
    

def datastore_get_user_id( datastore ):
    """
    Get the datastore user ID
    """
    return datastore['user_id']


def _make_datastore_info( datastore_type, user_id, datastore_name, datastore_privkey_hex, driver_names, config_path=CONFIG_PATH ):
    """
    Make the private part of a datastore record.
    Returns {'datastore': ..., 'root': ...} on success
    Returns {'error': ...} on error
    """

    root_uuid = str(uuid.uuid4())
    datastore_pubkey = get_pubkey_hex(datastore_privkey_hex)
    datastore_address = keylib.public_key_to_address(datastore_pubkey)
    datastore_root = _mutable_data_make_dir( datastore_address, root_uuid, {} )
    datastore_root['idata'] = {}

    assert datastore_type in ['datastore', 'collection'], datastore_type

    datastore_info = {
        'type': datastore_type,
        'datastore_name': datastore_name, 
        'user_id': user_id,
        'owner_pubkey': datastore_pubkey,
        'drivers': driver_names,
        'root_uuid': root_uuid
    }

    # sign
    signer = jsontokens.TokenSigner()
    token = signer.sign( datastore_info, datastore_privkey_hex )

    return {'datastore': datastore_info, 'datastore_token': token, 'root': datastore_root}


def get_datastore(user_id, datastore_name, datastore_pubkey, config_path=CONFIG_PATH, proxy=None):
    """
    Get a datastore's information.
    @user_id can be a pet name if the datastore is only owned locally.
    However, @user_id must be a blockchain ID if the datastore is accessible
    across hosts.

    Returns {'status': True, 'datastore': public datastore info}
    Returns {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    # try local first
    datastore_info = datastore_load(user_id, datastore_name, datastore_pubkey, config_path=config_path)
    if 'error' not in datastore_info:
        return {'status': True, 'datastore': datastore_info['datastore']}

    nonlocal_storage_drivers = get_nonlocal_storage_drivers(config_path)

    # fall back to mutable storage.
    datastore_info = get_mutable(user_id, datastore_name, datastore_pubkey, proxy=proxy, config_path=config_path, storage_drivers=nonlocal_storage_drivers)
    if 'error' in datastore_info:
        log.error("Failed to load public datastore information: {}".format(datastore_info['error']))
        return {'error': 'Failed to load public datastore record'}

    datastore = datastore_info['data']

    try:
        jsonschema.validate(datastore, DATASTORE_SCHEMA) 
        assert datastore['datastore_name'] == datastore_name, "Datastore name mismatch"
    except (AssertionError, ValidationError) as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)
        
        log.error("Invalid datastore record")
        return {'error': 'Invalid public datastore record'}

    return {'status': True, 'datastore': datastore}


def make_datastore(user_id, datastore_name, datastore_privkey_hex, driver_names=None, config_path=CONFIG_PATH, datastore_type='datastore' ):
    """
    Create a new datastore record with the given name, using the given account_info structure
    Return {'datastore': public datastore information, 'datastore_token': datastore JWT, 'root': root inode}
    Return {'error': ...} on failure
    """
    if driver_names is None:
        driver_handlers = storage.get_storage_handlers()
        driver_names = [h.__name__ for h in driver_handlers]

    datastore_info = _make_datastore_info( datastore_type, user_id, datastore_name, datastore_privkey_hex, driver_names, config_path=config_path)
    return {'datastore': datastore_info['datastore'],  'datastore_token': datastore_info['datastore_token'], 'root': datastore_info['root']}


def put_datastore(user_id, datastore_name, datastore_info, datastore_privkey, proxy=None, config_path=CONFIG_PATH ):
    """
    Create and put a new datastore.
    @datastore_info should be the structure returned by make_datastore()

    Return {'status': True} on success
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    datastore = datastore_info['datastore']
    datastore_token = datastore_info['datastore_token']
    user_id = datastore['user_id']
    root = datastore_info['root']
    drivers = datastore['drivers']

    assert datastore_name == datastore['datastore_name']
    assert re.match(OP_USER_ID_PATTERN, user_id), user_id
    assert re.match(OP_DATASTORE_ID_PATTERN, datastore_name), datastore_name

    # replicate root inode
    res = _put_inode(user_id, root, datastore_privkey, drivers, config_path=CONFIG_PATH, proxy=proxy, create=True )
    if 'error' in res:
        log.error("Failed to put root inode for datastore {}".format(datastore_name))
        return {'error': 'Failed to replicate datastore metadata'}

    # replicate public datastore record 
    res = put_mutable( user_id, datastore_name, datastore, data_privkey=datastore_privkey, storage_drivers=drivers, config_path=config_path, proxy=proxy )
    if 'error' in res:
        log.error("Failed to put datastore metadata for {}".format(datastore_fq_id))

        # try to clean up...
        res = _delete_inode(user_id, root['uuid'], datastore_privkey, drivers, proxy=proxy, config_path=config_path)
        if 'error' in res:
            log.error("Failed to clean up root inode {}".format(root['uuid']))

        return {'error': 'Failed to replicate datastore metadata'}

    # store local record 
    res = datastore_store(datastore_token, config_path=config_path)
    if 'error' in res:
        log.error("Failed to store local datastore record")
        return {'error': 'Failed to store local datastore record'}

    return {'status': True}


def delete_datastore(user_id, datastore_name, datastore_privkey, force=False, config_path=CONFIG_PATH, proxy=None ):
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

    # get the datastore first
    datastore_info = get_datastore(user_id, datastore_name, datastore_pubkey, config_path=config_path, proxy=proxy )
    if 'error' in datastore_info:
        log.error("Failed to look up datastore information for {}:{}".format(user_id, datastore_name))
        return {'error': 'Failed to look up datastore'}
    
    datastore = datastore_info['datastore']

    # remove root inode 
    res = datastore_listdir( datastore, '/', config_path=config_path, proxy=proxy )
    if 'error' in res:
        if not force:
            log.error("Failed to list /")
            return {'error': 'Failed to check if datastore is empty'}
        else:
            log.warn("Failed to list /, but forced to remove it anyway")

    if not force and len(res['dir']['idata']) != 0:
        log.error("Datastore not empty\n{}\n".format(json.dumps(res['dir']['idata'], indent=4, sort_keys=True)))
        return {'error': 'Datastore not empty'}

    res = _delete_inode(user_id, datastore['root_uuid'], datastore_privkey, datastore['drivers'], proxy=proxy, config_path=config_path, cache=DIR_CACHE) 
    if 'error' in res:
        log.error("Failed to delete root inode {}".format(datastore['root_uuid']))
        return {'error': res['error']}

    # remove public datastore record
    datastore_name = datastore['datastore_name']
    res = delete_mutable(user_id, datastore_name, data_privkey=datastore_privkey, proxy=proxy, config_path=config_path, delete_version=False )
    if 'error' in res:
        log.error("Failed to delete public datastore record: {}".format(res['error']))
        return {'error': 'Failed to delete public datastore record'}

    # remove local private datastore record 
    res = datastore_unlink(user_id, datastore_name, config_path=config_path)
    if 'error' in res:
        log.error("Failed to delete local datastore record: {}".format(res['error']))
        return {'error': 'Failed to delete local datastore record'}

    return {'status': True}


def _is_cacheable(inode_info):
    """
    Can we cache this inode?
    """
    if inode_info['type'] == MUTABLE_DATUM_DIR_TYPE and len(inode_info['idata']) < 1024:
        return True
    else:
        return False


def _get_inode(user_id, inode_uuid, inode_type, data_pubkey_hex, drivers, config_path=CONFIG_PATH, proxy=None, cache=None ):
    """
    Get an inode from non-local mutable storage.  Verify that it has an
    equal or later version number than the one we have locally.

    If cache is not None, and if the inode is a directory, then check
    the cache for the data and add it if it is not present

    Return {'status': True, 'inode': inode info} on success.
    Return {'error': ...} on error
    """
    
    if proxy is None:
        proxy = get_default_proxy(config_path)

    # cached?
    if cache is not None and inode_type == MUTABLE_DATUM_DIR_TYPE:
        inode_data = cache.get(inode_uuid)
        if inode_data is not None:
            # already-fetched
            log.debug("Cache HIT on {}".format(inode_uuid))
            return {'status': True, 'inode': inode_data}

    res = get_mutable(user_id, inode_uuid, data_pubkey=data_pubkey_hex, storage_drivers=drivers, proxy=proxy, config_path=config_path)
    if 'error' in res:
        log.error("Failed to get inode {}: {}".format(inode_uuid, res['error']))
        return {'error': 'Failed to get inode'}

    inode_info = res['data']

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

    # yup!
    # cache small directories
    if cache is not None and _is_cacheable(inode_info):
        log.debug("Cache PUT {}".format(inode_uuid))
        cache.put( inode_uuid, inode_info )

    return {'status': True, 'inode': inode_info}


def _get_inode_header(user_id, inode_uuid, data_pubkey_hex, drivers, config_path=CONFIG_PATH, proxy=None, cache=None):
    """
    Get an inode's header data.  Verify it matches the inode info.

    Return {'status': True, 'inode': inode_full_info} on success.
    Return {'error': ...} on error.
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

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

    header_id = '{}.hdr'.format(inode_uuid)
    res = get_mutable(user_id, header_id, data_pubkey=data_pubkey_hex, storage_drivers=drivers, proxy=proxy, config_path=config_path)
    if 'error' in res:
        log.error("Failed to get inode data {}: {}".format(inode_uuid, res['error']))
        return {'error': 'Failed to get inode data'}

    inode_hdr = res['data']
    return {'status': True, 'inode': inode_hdr}


def _put_inode(user_id, _inode, data_privkey, drivers, config_path=CONFIG_PATH, proxy=None, create=False, cache=None ):
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
    res = put_mutable(user_id, _inode['uuid'], _inode, data_privkey=data_privkey, storage_drivers=drivers, config_path=config_path, proxy=proxy, create=create )
    if 'error' in res:
        log.error("Failed to replicate inode {}: {}".format(_inode['uuid'], res['error']))
        return {'error': 'Failed to replicate inode'}

    inode_hdr = None
    if _inode.has_key('idata'):
        # store a metadata copy separately, for stat(2)
        inode_hdr = {}
        for k in _inode.keys():
            if k != 'idata':
                inode_hdr[k] = copy.deepcopy(_inode[k])

        inode_hdr_id = '{}.hdr'.format(_inode['uuid'])
        res = put_mutable(user_id, inode_hdr_id, inode_hdr, data_privkey=data_privkey, storage_drivers=drivers, config_path=config_path, proxy=proxy, create=create )
        if 'error' in res:
            log.error("Failed to replicate inode header for {}: {}".format(inode['uuid'], res['error']))
            return {'error': 'Failed to replicate inode header'}

    # coherently cache
    if cache is not None and _is_cacheable(_inode):
        log.debug("Cache PUT {}".format(_inode['uuid']))
        cache.put(_inode['uuid'], _inode)

    return {'status': True}


def _delete_inode(user_id, inode_uuid, data_privkey, drivers, config_path=CONFIG_PATH, proxy=None, cache=None ):
    """
    Delete an inode and its associated data.
    Return {'status': True} on success
    Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    # delete inode header
    idata_id = '{}.hdr'.format(inode_uuid)
    res = delete_mutable(user_id, idata_id, data_privkey=data_privkey, proxy=proxy, storage_drivers=drivers, delete_version=False, config_path=config_path)
    if 'error' in res:
        log.error("Faled to delete idata for {}: {}".format(inode_uuid, res['error']))
        return res

    # delete inode 
    res = delete_mutable(user_id, inode_uuid, data_privkey=data_privkey, proxy=proxy, storage_drivers=drivers, delete_version=False, config_path=config_path )
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

    user_id = datastore_get_user_id(datastore)
    path = posixpath.normpath(path).strip("/")
    path_parts = path.split('/')
    prefix = '/'

    drivers = datastore['drivers']
    root_uuid = datastore['root_uuid']
   
    # getting only the root?
    root_inode = _get_inode(user_id, root_uuid, MUTABLE_DATUM_DIR_TYPE, data_pubkey, drivers, config_path=CONFIG_PATH, proxy=proxy, cache=DIR_CACHE)
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
            log.debug('No child "{}" in "{}"\ninode:\n{}'.format(name, prefix, json.dumps(cur_dir, indent=4, sort_keys=True)))
            return {'error': 'No such file or directory', 'errno': errno.ENOENT}
       
        child_uuid = child_dirent['uuid']
        child_type = child_dirent['type']

        if child_type == MUTABLE_DATUM_FILE_TYPE and not get_idata:
            # done searching, and don't want data
            break
        
        # get child
        child_entry = _get_inode(user_id, child_uuid, child_type, data_pubkey, drivers, config_path=CONFIG_PATH, proxy=proxy, cache=DIR_CACHE)
        if 'error' in child_entry:
            log.error("Failed to get inode {} at {}: {}".format(child_uuid, prefix + name, child_entry['error']))
            return {'error': child_entry['error'], 'errno': errno.EIO}

        child_entry = child_entry['inode']
        assert child_entry['type'] == child_dirent['type'], "Corrupt inode {}".format(storage.make_fq_data_id(user_id,child_uuid))

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
        child_entry = _get_inode(user_id, child_uuid, child_type, data_pubkey, drivers, config_path=CONFIG_PATH, proxy=proxy )

    else:
        # get only inode header.
        # didn't request idata, so add a path entry here
        assert not ret.has_key(prefix + name), "BUG: already defined {}".format(prefix + name)

        path_ent = _make_path_entry(name, child_uuid, child_entry, prefix)
        ret[prefix + name] = path_ent

        child_entry = _get_inode_header(user_id, child_uuid, data_pubkey, drivers, config_path=config_path, proxy=proxy, cache=DIR_CACHE)

    if 'error' in child_entry:
        log.error("Failed to get file data for {} at {}: {}".format(child_uuid, prefix + name, child_entry['error']))
        return {'error': child_entry['error'], 'errno': errno.EIO}
    
    child_entry = child_entry['inode']

    # update ret
    ret[prefix + name]['inode'] = child_entry

    return ret


def _mutable_data_make_inode( inode_type, owner_address, inode_uuid, data_hash ):
    """
    Set up the basic properties of an inode.
    """
    return {
        'type':  inode_type,
        'owner': owner_address,
        'uuid': inode_uuid,
        'data_hash': data_hash,
    }


def _mutable_data_dir_hash( child_links ):
    """
    Calculate the idata hash for a directory's links
    """
    d = json.dumps(child_links, sort_keys=True)
    h = hashlib.sha256()
    h.update( d )
    return h.hexdigest()


def _mutable_data_file_hash( data_payload_utf8 ):
    """
    Calculate the idata hash for a file's data
    """
    h = hashlib.sha256()
    h.update(data_payload_utf8)
    return h.hexdigest()


def _mutable_data_make_dir( data_address, inode_uuid, child_links ):
    """
    Set up inode state for a directory
    """
    data_hash = _mutable_data_dir_hash(child_links)
    inode_state = _mutable_data_make_inode( MUTABLE_DATUM_DIR_TYPE, data_address, inode_uuid, data_hash )
    inode_state['idata'] = child_links
    return inode_state 


def _mutable_data_make_file( data_address, inode_uuid, data_payload ):
    """
    Set up inode state for a file
    """
    data_hash = _mutable_data_file_hash(data_payload.encode('utf-8'))
    inode_state = _mutable_data_make_inode( MUTABLE_DATUM_FILE_TYPE, data_address, inode_uuid, data_hash )
    inode_state['idata'] = data_payload.encode('utf-8')
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
    parent_dir['data_hash'] = _mutable_data_dir_hash(parent_dir['idata'])
    return parent_dir, new_dirent


def _mutable_data_dir_unlink( parent_dir, child_name ):
    """
    Detach a child inode from a directory.
    Return the new parent directory.
    """
    assert 'idata' in parent_dir
    assert child_name in parent_dir['idata'].keys()

    del parent_dir['idata'][child_name]
    parent_dir['data_hash'] = _mutable_data_dir_hash(parent_dir['idata'])
    return parent_dir


def _mutable_data_make_links(user_id, inode_uuid, urls=None, driver_names=None ):
    """
    Make a bundle of URI record links for the given inode data.
    This constitutes the directory's idata
    """
    fq_data_id = storage.make_fq_data_id(user_id, inode_uuid)

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

    log.debug("mkdir {}:{}".format(datastore['datastore_name'], data_path))

    user_id = datastore_get_user_id(datastore)
    path_info = _parse_data_path( data_path )
    parent_path = path_info['parent_path']
    data_path = path_info['data_path']
    name = path_info['iname']

    drivers = datastore['drivers']
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
    child_dir_links = _mutable_data_make_links(user_id, child_uuid, driver_names=drivers )
    child_dir_inode = _mutable_data_make_dir( data_address, child_uuid, {} )

    # update parent 
    parent_dir, child_dirent = _mutable_data_dir_link( parent_dir, MUTABLE_DATUM_DIR_TYPE, name, child_uuid, child_dir_links )

    # replicate the new child
    res = _put_inode(user_id, child_dir_inode, str(data_privkey_hex), drivers, config_path=config_path, proxy=proxy, create=True, cache=DIR_CACHE )
    if 'error' in res:
        log.error("Failed to create directory {}: {}".format(data_path, res['error']))
        return {'error': 'Failed to store child directory', 'errno': errno.EIO}

    # replicate the new parent 
    res = _put_inode(user_id, parent_dir, str(data_privkey_hex), drivers, config_path=config_path, proxy=proxy, cache=DIR_CACHE )
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

    user_id = datastore_get_user_id(datastore)
    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    name = path_info['iname']

    if data_path == '/':
        # can't do this 
        log.error("Will not delete /")
        return {'error': 'Tried to delete root', 'errno': errno.EINVAL}

    drivers = datastore['drivers']
    data_pubkey = get_pubkey_hex(str(data_privkey_hex))

    log.debug("rmdir {}:{}".format(datastore['datastore_name'], data_path))

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
    res = _put_inode(user_id, parent_dir_inode, str(data_privkey_hex), drivers, config_path=config_path, proxy=proxy, cache=DIR_CACHE )
    if 'error' in res:
        log.error("Failed to update directory {}: {}".format(parent_path, res['error']))
        return {'error': 'Failed to update directory', 'errno': errno.EIO}

    # delete the child
    res = _delete_inode(user_id, dir_inode_uuid, str(data_privkey_hex), drivers, config_path=config_path, proxy=proxy, cache=DIR_CACHE )
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

    drivers = datastore['drivers']
    
    log.debug("getfile {}:{}".format(datastore['datastore_name'], data_path))

    file_info = _lookup(datastore, data_path, datastore['owner_pubkey'], config_path=CONFIG_PATH, proxy=proxy )
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

    drivers = datastore['drivers']
    
    log.debug("listdir {}:{}".format(datastore['datastore_name'], data_path))

    dir_info = _lookup(datastore, data_path, datastore['owner_pubkey'], config_path=CONFIG_PATH, proxy=proxy )
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

    user_id = datastore_get_user_id(datastore)
    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    name = path_info['iname']
    parent_dirpath = path_info['parent_path']

    drivers = datastore['drivers']
    data_pubkey = get_pubkey_hex(str(data_privkey_hex))
    data_address = keylib.public_key_to_address(data_pubkey)

    log.debug("putfile {}:{}".format(datastore['datastore_name'], data_path))

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
    child_file_links = _mutable_data_make_links( user_id, child_uuid, driver_names=drivers )
    child_file_inode = _mutable_data_make_file( data_address, child_uuid, file_data )

    # update parent 
    parent_dir_inode, child_dirent = _mutable_data_dir_link( parent_dir_inode, MUTABLE_DATUM_FILE_TYPE, name, child_uuid, child_file_links )
    
    # replicate the new child (but don't cache files)
    res = _put_inode(user_id, child_file_inode, str(data_privkey_hex), drivers, config_path=config_path, proxy=proxy, create=True )
    if 'error' in res:
        log.error("Failed to replicate file {}: {}".format(data_path, res['error']))
        return {'error': 'Failed to store file', 'errno': errno.EIO}

    # replicate the new parent
    res = _put_inode(user_id, parent_dir_inode, str(data_privkey_hex), drivers, config_path=config_path, proxy=proxy, cache=DIR_CACHE )
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

    user_id = datastore_get_user_id(datastore)
    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    name = path_info['iname']
    parent_dirpath = path_info['parent_path']

    drivers = datastore['drivers']
    data_pubkey = get_pubkey_hex(str(data_privkey_hex))

    log.debug("deletefile {}:{}".format(datastore['datastore_name'], data_path))

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
    res = _put_inode(user_id, parent_dir_inode, str(data_privkey_hex), drivers, config_path=config_path, proxy=proxy, cache=DIR_CACHE )
    if 'error' in res:
        log.error("Failed to update directory {}: {}".format(dir_path, res['error']))
        return {'error': 'Failed to update directory', 'errno': errno.EIO}

    # delete child 
    res = _delete_inode(user_id, file_uuid, str(data_privkey_hex), drivers, config_path=config_path, proxy=proxy )
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

    drivers = datastore['drivers']
    
    log.debug("stat {}:{}".format(datastore['datastore_name'], data_path))

    inode_info = _lookup(datastore, data_path, datastore['owner_pubkey'], get_idata=False, config_path=CONFIG_PATH, proxy=proxy )
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

    user_id = datastore_get_user_id(datastore)
    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    data_pubkey_hex = get_pubkey_hex(data_privkey_hex)
    data_address = keylib.public_key_to_address(data_pubkey_hex)

    drivers = datastore['drivers']

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

        res = _get_inode(user_id, dir_inode_uuid, MUTABLE_DATUM_DIR_TYPE, str(data_pubkey_hex), drivers, config_path=config_path, proxy=proxy, cache=DIR_CACHE)
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
            res = _delete_inode(user_id, inode_info['uuid'], str(data_privkey_hex), drivers, config_path=config_path, proxy=proxy )
            if 'error' in res:
                return res

            # done 
            inode_stack.pop()

        else:
            # already explored?
            if inode_info['searched']:
                # already explored this directory.  Can remove now
                log.debug("Delete directory {}".format(inode_info['uuid']))
                res = _delete_inode(user_id, inode_info['uuid'], str(data_privkey_hex), drivers, config_path=config_path, proxy=proxy, cache=DIR_CACHE)
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
    res = _put_inode(user_id, dir_inode_info, str(data_privkey_hex), drivers, config_path=config_path, proxy=proxy, create=False, cache=DIR_CACHE )
    if 'error' in res:
        return res

    return {'status': True}


def get_nonlocal_storage_drivers(config_path, key='storage_drivers'):
    """
    Get the list of non-local storage drivers.
    That is, the ones which write to a globally-visible read-write medium.
    """

    conf = config.get_config(config_path)
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
    conf = config.get_config(config_path)
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
    conf = config.get_config(config_path)
    assert conf

    storage_drivers = conf.get("storage_drivers", "").split(",")
    if len(storage_drivers) > 0:
        return storage_drivers

    storage_handlers = storage.get_storage_handlers()
    storage_drivers = [sh.__name__ for sh in storage_handlers]
    return storage_drivers



def get_user(user_id, local_master_data_pubkey, config_path=CONFIG_PATH, proxy=None):
    """
    Get a user's information.

    A user is simply a named public key.  The name for the user (the user_id)
    may be a blockchain ID (i.e. globally-unique, written to Blockstack's blockchain),
    or it may be a local pet name for a public key.

    Either way, the user's public key is derived from the owner's master data public key.

    State for a user is stored locally on the owner's computer, and backed up to the owner's
    storage providers as mutable data under the *same data ID as the user ID*.
    In order to look up the user, the requester either
    needs to be the owner (so as to get to the local state), or the user ID must be a
    blockchain ID (so as to find and resolve the publicly-replicated state).

    This method tries to fetch the user data locally and authenticate it with the given master
    public key.  Failing that, this method tries to fetch the user data from mutable storage.

    Return {'status': True, 'user': user state, 'master_data_pubkey': ..., 'owned': ....} on success,
    where 'master_data_pubkey' is the public key that signed off on the user (i.e. the user's owner's
    data public key)

    Return {'error': ...} on failure
    """
     
    if proxy is None:
        proxy = get_default_proxy(config_path)

    # does this user exist locally?  i.e. was it signed by the requester's
    # local master data key?
    user_info = user_db.user_load(user_id, local_master_data_pubkey, config_path=config_path)
    if 'error' not in user_info:
        user = user_info['user']
        return {'status': True, 'user': user, 'master_data_pubkey': local_master_data_pubkey, 'owned': True}

    nonlocal_storage_drivers = get_nonlocal_storage_drivers(config_path)

    # nope.  We don't own this user.
    # try treating user_id as a blockchain ID.
    # be sure to check non-local storage only; don't want to hit stale disk data
    user_data = get_mutable(user_id, user_id, proxy=proxy, config_path=config_path, storage_drivers=nonlocal_storage_drivers)
    if 'error' in user_data:
        log.error("Failed to fetch user data from storage")
        return user_data

    user_jwt = user_data['data']
    user_pubkey = user_data['data_pubkey']
    
    if user_pubkey is None:
        log.error("No user public key available")
        return {'error': 'No user public key available'}
                
    # validate 
    user = user_db.user_validate(user_jwt)
    if 'error' in user:
        log.error("Failed to validate user data")
        return user

    owned = user_db.user_verify(user_jwt, local_master_data_pubkey)
    
    # success!
    return {'status': True, 'user': user, 'master_data_pubkey': user_pubkey, 'owned': owned}


def get_user_list(master_data_pubkey, proxy=None, config_path=CONFIG_PATH):
    """
    Get our replicated list of users
    Return {'status': True, 'user_ids': [list of user IDs]}
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    nonlocal_storage_drivers = get_nonlocal_storage_drivers(config_path)

    addr = keylib.public_key_to_address(master_data_pubkey)
    listing_info = get_mutable(addr, 'user_ids', data_pubkey=master_data_pubkey, proxy=proxy, config_path=config_path, storage_drivers=nonlocal_storage_drivers)
    if 'error' in listing_info:
        log.error("Failed to get user list")
        return listing_info

    user_listing = listing_info['data']
    try:
        jsonschema.validate(user_listing, {'type': 'array', 'items': {'type': 'string', 'pattern': OP_USER_ID_PATTERN}})
    except ValidationError:
        return {'error': 'Invalid user listing'}

    return {'status': True, 'user_ids': user_listing}


def put_user_list(master_data_privkey, user_listing, proxy=None, config_path=CONFIG_PATH):
    """
    Put our replicated list of users
    Return {'status': True} on success
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)
    
    try:
        jsonschema.validate(user_listing, {'type': 'array', 'items': {'type': 'string', 'pattern': OP_USER_ID_PATTERN}})
    except ValidationError:
        return {'error': 'Invalid user listing'}

    master_data_pubkey = get_pubkey_hex(master_data_privkey)
    addr = keylib.public_key_to_address(master_data_pubkey)
    res = put_mutable(addr, 'user_ids', user_listing, data_privkey=master_data_privkey, proxy=proxy, config_path=config_path)
    if 'error' in res:
        return res

    return {'status': True}


def put_user(user_info, master_data_privkey, config_path=CONFIG_PATH, proxy=None):
    """
    Store a user to local storage and our data storage providers.
    The user info will be signed off by the given master private key

    Return {'status': True} on success
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    # sign and serialize
    res = user_db.user_serialize(user_info, master_data_privkey)
    if 'error' in res:
        return res

    user_token = res['token']
    master_data_pubkey = get_pubkey_hex(master_data_privkey)

    # get the list of users so we can insert this user into it.
    user_list_info = get_user_list(master_data_pubkey, proxy=proxy, config_path=config_path)
    if 'error' in user_list_info:
        log.error("Failed to get user list")
        return {'error': 'Failed to get user list'}

    user_list = user_list_info['user_ids']
    if user_info['user_id'] in user_list:
        log.error("User {} already exists".format(user_info['user_id']))
        return {'error': 'User already exists'}

    # store locally
    res = user_db.user_store( user_token, config_path=config_path )
    if 'error' in res:
        log.error("Failed to store user state locally")
        return res

    # set a private key index for this user's accounts 
    user_addr = keylib.public_key_to_address(user_info['public_key'])
    user_privkey = user_db.user_get_privkey(master_data_privkey, user_info)
    res = set_privkey_index( user_privkey, 1, config_path=config_path, proxy=proxy )
    if 'error' in res:
        log.error("Failed to give user {} a private key index".format(user_info['user_id']))
        return res

    # replicate, signing with the master private key 
    res = put_mutable(user_info['user_id'], user_info['user_id'], user_info, data_privkey=master_data_privkey, proxy=proxy, config_path=config_path)
    if 'error' in res:
        log.error("Failed to replicate user")
        return {'error': 'Failed to replicate user'}
   
    # update user list 
    user_list.append(user_info['user_id'])
    res = put_user_list(master_data_privkey, user_list, proxy=proxy, config_path=config_path)
    if 'error' in res:
        # undo
        delres = delete_mutable(user_info['user_id'], user_info['user_id'], data_privkey=master_data_privkey, proxy=proxy, config_path=config_path)
        user_delete(user_info['user_id'], config_path=config_path)
        if 'error' in delres:
            log.error("Failed to delete user {}: {}".format(user_info['user_id'], delres['error']))
        
        return res

    return {'status': True}


def delete_user(user_id, master_data_privkey, config_path=None, proxy=None):
    """
    Delete a user.  Remove its local state, and delete it from our storage providers.

    Return {'status': True} on success
    Return {'error': ...} on failure
    """

    if not user_db.user_is_local(user_id):
        return {'error': 'User is not locally owned'}

    if proxy is None:
        proxy = get_default_proxy(config_path)

    # get the list of users so we can insert this user into it.
    master_data_pubkey = get_pubkey_hex(master_data_privkey)
    user_list_info = get_user_list(master_data_pubkey, proxy=proxy, config_path=config_path)
    if 'error' in user_list_info:
        log.error("Failed to get user list")
        return {'error': 'Failed to get user list'}

    user_list = user_list_info['user_ids']

    # clear out from list
    if user_id in user_list:
        user_list.remove(user_id)
        res = put_user_list(master_data_privkey, user_list, config_path=config_path, proxy=proxy)
        if 'error' in res:
            log.error("Failed to update user listing")
            return res

    # delete from storage providers 
    res = delete_mutable(user_id, user_id, data_privkey=master_data_privkey, proxy=proxy, config_path=config_path, delete_version=False)
    if 'error' in res:
        log.error("Failed to delete from storage providers")
        return {'error': 'Failed to delete from storage providers'}

    # delete locally, but it's okay if this fails due to our not having it
    user_db.user_delete(user_id, config_path=config_path)
    return {'status': True}


def next_privkey_index( data_privkey, config_path=None, proxy=None, create=False):
    """
    Get the next private key index.  Update the replica on our storage providers.

    Return {'status': True, 'index': ...} on success
    Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    data_pubkey = get_pubkey_hex(data_privkey)
    addr = keylib.public_key_to_address(data_pubkey)

    nonlocal_storage_drivers = get_nonlocal_storage_drivers(config_path)

    privkey_index_info = get_mutable(addr, 'privkey_index', data_pubkey=data_pubkey, config_path=config_path, storage_drivers=nonlocal_storage_drivers)
    if 'error' in privkey_index_info:
        if create:
            # try to create
            res = set_privkey_index( data_privkey, 0, config_path=config_path, proxy=proxy )
            if 'error' in res:
                return res

            privkey_index_info = {'data': 0}

        else:
            log.error("Failed to get current private key index")
            return privkey_index_info

    privkey_index = privkey_index_info['data']

    try:
        privkey_index = int(privkey_index)
    except:
        log.error("Invalid private key index")
        return {'error': 'Invalid private key index'}

    ret = privkey_index
    privkey_index += 1
    res = set_privkey_index(data_privkey, privkey_index, config_path=config_path, proxy=proxy)
    if 'error' in res:
        return res

    return {'status': True, 'index': ret}
   

def set_privkey_index( data_privkey, value, config_path=None, proxy=None ):
    """
    Set the current private key index
    Return {'status': True} on success
    return {'error': ...} on error
    """
    
    data_pubkey = get_pubkey_hex(data_privkey)
    addr = keylib.public_key_to_address(data_pubkey)

    try:
        value = int(value)
    except:
        return {'error': 'Invalid value'}

    res = put_mutable(addr, 'privkey_index', value, data_privkey=data_privkey, proxy=proxy, config_path=config_path)
    if 'error' in res:
        log.error("Failed to put new private key index")
        return {'error': 'Failed to put new private key index'}

    return {'status': True}


def have_seen( user_id, data_id, config_path=CONFIG_PATH ):
    """
    Have we ever seen this datum before?
    """

    conf = get_config(config_path)
    assert conf

    fq_data_id = storage.make_fq_data_id(user_id, data_id)
    expected_version = load_mutable_data_version(conf, fq_data_id)

    return (expected_version is not None)


def data_setup( password, wallet_keys=None, config_path=CONFIG_PATH, proxy=None):
    """
    Do the one-time setup necessary for using the data functions.
    The wallet must be set up first.

    Return {'status': True} on success
    Return {'error': ...} on error
    """

    from .wallet import load_wallet

    if proxy is None:
        proxy = get_default_proxy(config_path)

    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)
    conf = get_config(config_path)

    if not os.path.exists(wallet_path):
        return {'error': 'Wallet does not exist'}

    # put a new private key index?
    if wallet_keys is None:
        wallet_info = load_wallet(password, config_path=config_path, wallet_path=wallet_path, include_private=True)
        if 'error' in wallet_info:
            return wallet_info

        wallet_keys = wallet_info['wallet']

    # make sure we also have a private key index 
    master_data_privkey = wallet_keys['data_privkey']
    master_data_pubkey = get_pubkey_hex(master_data_privkey)
    addr = keylib.public_key_to_address(master_data_pubkey)

    res = next_privkey_index( master_data_privkey, config_path=config_path )
    if 'error' in res:

        if have_seen('privkey_index', 'privkey_index', config_path=config_path ):
            # some other error
            return res

        # try creating
        res = next_privkey_index( master_data_privkey, config_path=config_path, create=True )
        if 'error' in res:
            return res

    # put an empty user list, if we don't have one
    res = get_user_list(master_data_pubkey, config_path=config_path)
    if 'error' in res:

        if have_seen(addr, 'user_ids'):
            # some other error
            return res

        # try putting one
        res = put_user_list(master_data_privkey, [], proxy=proxy, config_path=config_path)
        if 'error' in res:
            return res

    return {'status': True}

