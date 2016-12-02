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

from keylib import *

from .keys import *
from .profile import *
from .proxy import *
from .storage import hash_zonefile

from .config import get_logger
from .constants import BLOCKSTACK_TEST

log = get_logger()


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

    msg = 'data ID must be a Blockstack DNS name or a fully-qualified data ID'
    assert (
        storage.is_fq_data_id(fq_data_id) or
        storage.is_valid_name(fq_data_id)
    ), msg

    conf = config.get_config() if conf is None else conf

    if conf is None:
        msg = 'No config found; cannot store version for "{}"'
        log.warning(msg.format(fq_data_id))
        return False

    metadata_dir = conf.get('metadata', '')

    assert metadata_dir, 'Missing metadata directory'

    if not os.path.isdir(metadata_dir):
        msg = 'No metadata directory found; cannot store version of "{}"'
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


def get_immutable(name, data_hash, data_id=None, proxy=None):
    """
    get_immutable

    Fetch a piece of immutable data.  Use @data_hash to look it up
    in the user's zonefile, and then fetch and verify the data itself
    from the configured storage providers.

    Return {'data': the data, 'hash': hash} on success
    Return {'error': ...} on failure
    """

    proxy = get_default_proxy() if proxy is None else proxy

    user_zonefile = get_name_zonefile(name, proxy=proxy)
    if user_zonefile is None:
        return {'error': 'No user zonefile defined'}

    if 'error' in user_zonefile:
        return user_zonefile

    user_zonefile = user_zonefile['zonefile']

    if is_obsolete_zonefile(user_zonefile):
        # zonefile is really a legacy profile
        msg = 'Profile is in a legacy format that does not support immutable data.'
        return {'error': msg}

    if data_id is not None:
        # look up hash by name
        h = user_db.get_immutable_data_hash(user_zonefile, data_id)
        if h is None:
            return {'error': 'No such immutable datum'}

        if isinstance(h, list):
            # this tool doesn't allow this to happen (one ID matches
            # one hash), but that doesn't preclude the user from doing
            # this with other tools.
            if data_hash is not None and data_hash not in h:
                return {'error': 'Data ID/hash mismatch'}
            else:
                msg = 'Multiple matches for "{}": {}'
                return {'error': msg.format(data_id, ','.join(h))}

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


def list_update_history(name, current_block=None, proxy=None):
    """
    list_update_history

    List all prior zonefile hashes of a name, in historic order.
    Return a list of hashes on success.
    Return None on error
    """

    proxy = get_default_proxy() if proxy is None else proxy

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
            return None

    name_history = get_name_blockchain_history( name, 0, current_block )
    if 'error' in name_history:
        log.error('Failed to get name history for {}: {}'.format(name, name_history['error']))
        return name_history

    all_update_hashes = []
    for block_id in block_ids:
        history_items = name_history[block_id]
        for history_item in history_items:
            value_hash = history_item.get('value_hash', None)
            if value_hash is None:
                continue
            if all_update_hashes or all_update_hashes[-1] == value_hash:
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

        data_hash_or_hashes = user_db.get_immutable_data_hash(zf, data_id)
        if data_hash_or_hashes is not None:
            hashes.append(data_hash_or_hashes)
            continue

        hashes.append('data not defined')

    return hashes


def load_user_data_pubkey_addr( name, storage_drivers=None, proxy=None ):
    """
    Get a user's default data public key and/or address.
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

    return {'pubkey': data_pubkey, 'address': data_address}


def get_mutable(name, data_id, data_pubkey=None, storage_drivers=None, proxy=None, ver_min=None, ver_max=None, urls=None, config_path=CONFIG_PATH):
    """
    get_mutable 

    Fetch a piece of mutable data.

    If @ver_min is given, ensure the data's version is greater or equal to it.
    If @ver_max is given, ensure the data's version is less than it.

    Return {'data': the data, 'version': the version} on success
    Return {'error': ...} on error
    """

    proxy = get_default_proxy() if proxy is None else proxy
    conf = config.get_config(path=config_path)

    fq_data_id = storage.make_fq_data_id(name, data_id)
    data_address = None

    if data_pubkey is None:
        # need to find pubkey to use
        pubkey_info = load_user_data_pubkey_addr( name, storage_drivers=storage_drivers, proxy=proxy )

        data_pubkey = pubkey_info['pubkey']
        data_address = pubkey_info['address']

    # get the mutable data itself
    mutable_data = storage.get_mutable_data(fq_data_id, data_pubkey, urls=urls, data_address=data_address)
    if mutable_data is None:
        log.error("Failed to get mutable datum {}".format(fq_data_id))
        return {'error': 'Failed to look up mutable datum'}

    jsonschema.validate(mutable_data, DATA_BLOB_SCHEMA)

    expected_version = load_mutable_data_version(conf, fq_data_id)
    expected_version = 1 if expected_version is None else expected_version

    # check consistency
    version = mutable_data['version']
    if ver_min is not None and ver_min > version:
        return {'error': 'Mutable data is stale'}

    elif ver_max is not None and ver_max <= version:
        return {'error': 'Mutable data is in the future'}

    elif expected_version > version:
        msg = 'Mutable data is stale; a later version was previously fetched'
        return {'error': msg}

    rc = store_mutable_data_version(conf, fq_data_id, version)
    if not rc:
        return {'error': 'Failed to store consistency information'}

    return {'data': mutable_data['data'], 'version': version, 'timestamp': mutable_data['timestamp']}


def put_immutable(name, data_id, data_json, data_url=None, txid=None, proxy=None, wallet_keys=None):
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

    legacy = False
    proxy = get_default_proxy() if proxy is None else proxy

    user_profile, user_zonefile, legacy = get_and_migrate_profile(
        name, create_if_absent=True, proxy=proxy, wallet_keys=wallet_keys
    )

    if 'error' in user_profile:
        log.debug('Unable to load user zonefile for "{}"'.format(name))
        return user_profile

    if legacy:
        log.debug('User zonefile is in legacy or non-standard')
        msg = (
            'User zonefile is in legacy or non-standard format, and '
            'does not support this operation.  You must first migrate '
            'it with the "migrate" command.'
        )

        return {'error': msg}

    user_zonefile = user_zonefile['zonefile']
    user_profile = user_profile['profile']

    data_text = storage.serialize_immutable_data(data_json)
    data_hash = storage.get_data_hash(data_text)

    # insert into user zonefile, overwriting if need be
    if user_db.has_immutable_data_id(user_zonefile, data_id):
        log.debug('WARN: overwriting old "{}"'.format(data_id))
        old_hash = user_db.get_immutable_data_hash(user_zonefile, data_id)

        # NOTE: can be a list, if the name matches multiple hashes.
        # this tool doesn't do this, but it's still possible for the
        # user to use other tools to do this.
        if not isinstance(old_hash, list):
            old_hash = [old_hash]

        for oh in old_hash:
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
    Get the user's data private key from his/her wallet
    Return {'privkey': ...} on success
    Return {'error': ...} on error
    """
    conf = get_config(path=CONFIG_PATH)
    user_zonefile = get_name_zonefile( name, storage_drivers=storage_drivers, proxy=proxy, include_name_record=True)
    if user_zonefile is None:
        log.error("No zonefile for {}".format(name))
        return {'error': 'No zonefile'}

    if 'error' in user_zonefile:
        log.error("Failed to load zonefile for {}: {}".format(name, user_zonefile['error']))
        return {'error': 'Failed to load zonefile'}

    # recover name record and zonefile
    name_record = user_zonefile.pop('name_record')
    user_zonefile = user_zonefile['zonefile']

    # get the appropriate key
    data_privkey = get_data_or_owner_privkey(user_zonefile, name_record['address'], wallet_keys=wallet_keys, config_path=config_path)
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

    ** Consistency **

    @version, if given, is the version to include in the data.
    If not given, then 1 will be used if no version exists locally, or the local version will be auto-incremented from the local version.
    Readers will only accept the version if it is "recent" (i.e. it falls into the given version range, or it is fresher than the last-seen version).

    ** Durability **

    Replication is best-effort.  If one storage provider driver succeeds, the put_mutable succeeds.  If they all fail, then put_mutable fails.
    More complex behavior can be had by creating a "meta-driver" that calls existing drivers' methods in the desired manner.

    Notes on usage:
    * wallet_keys is only needed if data_privkey is None
    * if storage_drivers is None, each storage driver will be attempted.
    * if storage_drivers is not None, then each storage driver in storage_drivers *must* succeed

    Returns a dict with {'status': True, 'version': version, ...} on success
    Returns a dict with 'error' set on failure
    """

    # data must be serializable
    try:
        json.dumps(data_payload)
    except:
        if BLOCKSTACK_DEBUG:
            log.error("Data must serialize to JSON: {}".format(data_payload))

        raise ValueError("Data must serialize to JSON")

    proxy = get_default_proxy() if proxy is None else proxy
    fq_data_id = storage.make_fq_data_id(name, data_id)
    conf = config.get_config(path=config_path)

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

    rc = storage.put_mutable_data(fq_data_id, data_json, data_privkey, required=storage_drivers)
    if not rc:
        result['error'] = 'Failed to store mutable data'
        return result

    # remember which version this was
    rc = store_mutable_data_version(conf, fq_data_id, version)
    if not rc:
        result['error'] = 'Failed to store mutable data version'
        return result

    result = {}
    result['status'] = True
    result['version'] = version

    if BLOCKSTACK_TEST is not None:
        msg = 'Put "{}" to {} mutable data (version {})\nData:\n{}'
        data = json.dumps(data_json, indent=4, sort_keys=True)
        log.debug(msg.format(data_id, name, version, data))

    return result


def delete_immutable(name, data_key, data_id=None, proxy=None, txid=None, wallet_keys=None):
    """
    delete_immutable

    Remove an immutable datum from a name's zonefile, given by @data_key.
    Return a dict with {'status': True, 'zonefile_hash': ..., 'zonefile': ...} on success
    Return a dict with {'error': ...} on failure
    """

    from backend.nameops import async_update

    proxy = get_default_proxy() if proxy is None else proxy

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
        data_key = user_db.get_immutable_data_hash(user_zonefile, data_id)
        if isinstance(data_key, list):
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
    data_privkey = get_data_or_owner_privkey(
        user_zonefile, name_record['address'],
        wallet_keys=wallet_keys, config_path=proxy.conf['path']
    )

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

    Returns a dict with {'status': True} on success
    Returns a dict with {'error': ...} on failure
    """

    proxy = get_default_proxy() if proxy is None else proxy

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


def list_immutable_data(name, proxy=None):
    """
    List the names and hashes of all immutable data in a user's zonefile.
    Returns {'data': [{'data_id': data_id, 'hash': hash}]} on success
    """
    proxy = get_default_proxy() if proxy is None else proxy

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


def set_data_pubkey(name, data_pubkey, proxy=None, wallet_keys=None, txid=None):
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
    proxy = get_default_proxy() if proxy is None else proxy

    user_profile, user_zonefile, legacy = get_and_migrate_profile(
        name, create_if_absent=True, proxy=proxy, wallet_keys=wallet_keys
    )

    if 'error' in user_profile:
        log.debug('Unable to load user zonefile for "{}"'.format(name))
        return user_profile

    if legacy:
        log.debug('User zonefile is non-standard or legacy')
        msg = (
            'User zonefile is in legacy or non-standard format, and does not support '
            'this operation.  You must first migrate it with the "migrate" command.'
        )

        return {'error': msg}

    user_zonefile = user_zonefile['zonefile']
    user_profile = user_profile['profile']

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


def _make_datastore_name( fqu, datastore_name ):
    """
    Make a datastore name
    """
    return "{}@{}".format(datastore_name, fqu)


def datastore_path(fqu, datastore_name, config_path=CONFIG_PATH):
    """
    Get the path to the private datastore information.
    """
    datastore_filename = _make_datastore_name(fqu, datastore_name) + ".datastore"
    datastore_dirp = datastore_dir(config_path=config_path)

    return os.path.join(datastore_dirp, datastore_filename)


def datastore_list(config_path=CONFIG_PATH):
    """
    Get the list of private datastores on this host.
    Return {'datastore_name': ..., 'name': ...} list on success
    """
    datastore_dirp = datastore_dir(config_path=config_path)
    if not os.path.exists(datastore_dirp) or not os.path.isdir(datastore_dirp):
        log.error("No datastore directory")
        return []

    names = os.listdir(datastore_dirp)
    names = filter(lambda n: n.endswith(".datastore"), names)

    # format: datastore name (url-encoded) @ blockchain name .datastore
    regex = r"^([a-zA-Z0-9\-_.~%]+)@([a-z0-9\-_.+]{{{},{}}}).datastore".format(3, LENGTH_MAX_NAME)
    ret = []
    for name in names:
        grp = re.match(regex, name)
        if grp is None:
            continue
       
        datastore_name, fqu = grp.groups()
        ret.append( {
            'datastore_name': datastore_name,
            'name': fqu
        })

    return ret


def datastore_load_privinfo(fqu, datastore_name, master_data_pubkey, config_path=CONFIG_PATH):
    """
    Get the private datastore information
    Return {'datastore_priv': decoded datastore info} on success
    Return {'error':...} if not found
    """
    dpath = datastore_path(fqu, datastore_name, config_path=CONFIG_PATH)
    if not os.path.exists(dpath):
        log.error("No such private datastore record {}".format(dpath))
        return {'error': 'No such datastore'}
    
    dinfo_txt = None
    try:
        with open(dpath, "r") as f:
            dinfo_txt = f.read()

    except:
        log.error("Failed to read private datastore record {}".format(dpath))
        return {'error': 'Failed to read datastore'}

    # will be tokenized...
    dinfo = None
    try:
        verifier = jsontokens.TokenVerifier()
        res = verifier.verify(dinfo_txt, master_data_pubkey)
        if not res:
            log.error("Failed to verify {}".format(dpath))
            return {'error': 'Failed to verify token'}

        dinfo_jwt = jsontokens.decode_token(dinfo_txt)
        dinfo = dinfo_jwt['payload']
        jsonschema.validate(dinfo, PRIVATE_DATASTORE_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Failed to parse datastore information from {}".format(dpath))
        return {'error': 'Failed to parse datastore'}

    return {'datastore_priv': dinfo}


def datastore_store_privinfo(fqu, datastore_name, datastore_priv, master_data_privkey, config_path=CONFIG_PATH ):
    """
    Store private datastore information.
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    dpath = datastore_path(fqu, datastore_name, config_path=CONFIG_PATH)
    if os.path.exists(dpath):
        log.error("Datastore already exists at {}".format(dpath))
        return {'error': 'Datastore already exists'}

    signer = jsontokens.TokenSigner()
    dstok = signer.sign(datastore_priv, ECPrivateKey(master_data_privkey).to_hex())
    try:
        with open(dpath, "w") as f:
            f.write(dstok)
            f.flush()
            os.fsync(f.fileno())

    except:
        log.error("Failed to store datastore record to {}".format(dpath))
        return {'error': 'Failed to store datastore record'}

    return {'status': True}
    

def datastore_remove_privinfo(fqu, datastore_name, config_path=CONFIG_PATH):
    """
    Delete private datastore information
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    dpath = datastore_path(fqu, datastore_name, config_path=CONFIG_PATH)
    if not os.path.exists(dpath):
        log.debug("No such datastore {}".format(dpath))
        return {'error': 'No such datastore'}

    try:
        os.unlink(dpath)
    except:
        pass

    return {'status': True}


def _make_datastore_pubinfo( datastore_name, datastore_pubkey, driver_names ):
    """
    Create a new, empty datastore record and a root directory.  This consititutes the public information.
    Returns {'datastore_pub': datastore, 'root': root} on success (always succeeds)
    """

    root_uuid = str(uuid.uuid4())
    datastore_address = ECPublicKey(str(datastore_pubkey)).address()
    datastore_root = _mutable_data_make_dir( datastore_address, root_uuid, {} )

    datastore_pubinfo = {
        'datastore_name': datastore_name,
        'owner_pubkey': datastore_pubkey,
        'drivers': [str(name) for name in driver_names],
        'root_uuid': root_uuid
    }

    datastore_root['idata'] = {}

    return {'datastore_pub': datastore_pubinfo, 'root': datastore_root}


def _get_datastore_privkey( fqu, datastore_name, master_data_privkey, datastore_priv=None, config_path=CONFIG_PATH ):
    """
    Calculate the datastore private key
    return {'status': True, 'datastore_privkey': ...} on success
    return {'error': ...} on error
    """

    if datastore_priv is None:
        master_data_pubkey = ECPrivateKey(str(master_data_privkey)).public_key().to_hex()
        datastore_priv = datastore_load_privinfo(fqu, datastore_name, master_data_pubkey, config_path=CONFIG_PATH )
        if 'error' in datastore_priv:
            log.error("Failed to load private datastore record: {}".format(datastore_priv['error']))
            return {'error': 'Failed to load private datastore record'}

        datastore_priv = datastore_priv['datastore_priv']

    hdwallet = HDWallet( hex_privkey=ECPrivateKey(str(master_data_privkey)).to_hex())
    datastore_privkey = hdwallet.get_child_privkey( index=datastore_priv['privkey_index'] )

    return {'status': True, 'datastore_privkey': datastore_privkey}


def _make_datastore_info( fqu, datastore_name, master_data_privkey, privkey_index, driver_names, config_path=CONFIG_PATH ):
    """
    Make the private part of a datastore record.
    Returns {'datastore_priv': ..., 'datastore_pub': ..., 'root': ...} on success
    Returns {'error': ...} on error
    """
    datastore_priv = {
        'privkey_index': privkey_index,
        'datastore_name': datastore_name
    }

    datastore_privkey_info = _get_datastore_privkey( fqu, datastore_name, master_data_privkey, datastore_priv=datastore_priv, config_path=CONFIG_PATH )
    if 'error' in datastore_privkey_info:
        log.error("Failed to load datastore private key")
        return {'error': 'Failed to generate datastore info'}

    datastore_privkey = datastore_privkey_info['datastore_privkey']
    datastore_pubkey = ECPrivateKey(str(datastore_privkey)).public_key().to_hex()

    datastore_pub_info = _make_datastore_pubinfo( datastore_name, datastore_pubkey, driver_names )

    return {
        'datastore_priv': datastore_priv,
        'datastore_pub': datastore_pub_info['datastore_pub'],
        'root': datastore_pub_info['root']
    }


def get_datastore(fqu, datastore_name, master_datastore_pubkey=None, master_datastore_privkey=None, wallet_keys=None, config_path=CONFIG_PATH, proxy=None, **kw ):
    """
    Get the user's data store information (both public and private parts) 
    Returns {'status': True, 'datastore': public datastore info, 'datastore_public_key': public key, 'datastore_private_key': datastore private key (if local)}
    Returns {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy()

    if wallet_keys is None and master_datastore_privkey is None:
        log.debug("No wallet keys and no master datastore private key; no datastore private key will be loaded")

    if wallet_keys is not None and master_datastore_privkey is None:
        master_data_privkey_info = load_user_data_privkey( fqu, proxy=proxy, config_path=config_path, wallet_keys=wallet_keys )
        if 'error' in master_data_privkey_info:
            log.error("Failed to load master data private key: {}".format(master_data_privkey_info['error']))
            return {'error': 'Failed to load master data private key'}

        master_datastore_privkey = master_data_privkey_info['privkey']

    if master_datastore_privkey is not None:
        master_datastore_pubkey = ECPrivateKey(str(master_datastore_privkey)).public_key().to_hex()

    if master_datastore_pubkey is None:
        # look up
        pubkey_info = load_user_data_pubkey_addr( fqu, proxy=proxy )
        if 'error' in pubkey_info:
            log.error("Failed to load user data public key information for {}".format(fqu))
            return {'error': 'Failed to get master data public key'}

        master_datastore_pubkey = pubkey_info['pubkey']

    pub_datastore_info = get_mutable(fqu, datastore_name, data_pubkey=master_datastore_pubkey, proxy=proxy, config_path=config_path )
    if 'error' in pub_datastore_info:
        log.error("Failed to load public datastore information: {}".format(pub_datastore_info['error']))
        return {'error': 'Failed to load public datastore record'}

    pub_datastore = pub_datastore_info['data']

    try:
        jsonschema.validate(pub_datastore, PUBLIC_DATASTORE_SCHEMA) 
    except ValidationError as ve:
        if BLOLCKSTACK_DEBUG:
            log.exception(ve)
        
        log.error("Invalid public datastore record")
        return {'error': 'Invalid public datastore record'}

    # maybe private too?
    datastore_priv_info = None
    if master_datastore_privkey is not None:
        datastore_priv_info = datastore_load_privinfo(fqu, datastore_name, master_datastore_pubkey, config_path=config_path )
        if 'error' in datastore_priv_info:
            log.warning("Failed to load datastore private information for {}".format(datastore_name))
            

    ret = {
        'status': True,
        'datastore': pub_datastore,
        'datastore_public_key': pub_datastore['owner_pubkey'],
    }

    if datastore_priv_info is not None and 'error' not in datastore_priv_info:
        # sanity check...
        datastore_priv = datastore_priv_info['datastore_priv']
        datastore_privkey_info = _get_datastore_privkey(fqu, datastore_name, master_datastore_privkey, datastore_priv=datastore_priv, config_path=config_path)
        if 'error' in datastore_privkey_info:
            log.error("Failed to get datastore private key info")
            return {'error': 'Failed to load datastore private key'}

        datastore_privkey = datastore_privkey_info['datastore_privkey']
        datastore_pubkey = ECPrivateKey(str(datastore_privkey)).public_key().to_hex()
        datastore_address = ECPublicKey(str(datastore_pubkey)).address()

        try:
            assert datastore_priv['datastore_name'] == pub_datastore['datastore_name']
            assert datastore_address == ECPublicKey(str(pub_datastore['owner_pubkey'])).address()
        except AssertionError, ae:
            if BLOCKSTACK_DEBUG:
                log.exception(ae)

            log.error("Public datastore record does not match private datastore record")
            return {'error': 'Public datastore record does not match private datastore record'}

        ret['datastore_private_key'] = datastore_privkey

    return ret


def _get_next_datastore_privkey_index( config_path=CONFIG_PATH ):
    """
    Make a one-time-use nonce for a signed URL
    """
    datastore_dirp = datastore_dir(config_path=config_path)
    if not os.path.exists(datastore_dirp):
        os.makedirs(datastore_dirp)

    nonce_path = os.path.join(datastore_dirp, ".privkey_index")
    nonce = 1

    if os.path.exists(nonce_path):
        try:
            with open(nonce_path, "r") as f:
                nonce = int(f.read().strip())

        except:
            log.warning("Failed to read datastore private key index from {}".format(nonce_path))

    nonce = max(1, nonce + 1)

    try:
        with open(nonce_path, "w") as f:
            f.write("{}".format(nonce))
            f.flush()
            os.fsync(f.fileno())
    
    except:
        log.error("Failed to store datastore private key index to {}".format(nonce_path))
        return None

    return nonce
    

def make_datastore(fqu, datastore_name, master_data_privkey, driver_names, config_path=CONFIG_PATH ):
    """
    Create a new datastore record (both public and private parts)
    It will be given a wholly-new private key.
    Return {'status': True, 'datastore_pub': public datastore information, 'root': root inode, 'datastore_priv': private datastore information}
    Return {'error': ...} on failure
    """

    datastore_privkey_index = _get_next_datastore_privkey_index(config_path=config_path)
    datastore_info = _make_datastore_info( fqu, datastore_name, master_data_privkey, datastore_privkey_index, driver_names, config_path=config_path )
    return {'status': True, 'datastore_pub': datastore_info['datastore_pub'], 'datastore_priv': datastore_info['datastore_priv'], 'root': datastore_info['root']}


def put_datastore( fqu, datastore_name, drivers=None, master_data_privkey=None, wallet_keys=None, proxy=None, config_path=CONFIG_PATH ):
    """
    Create and put a new datastore with the given name

    Return {'status': True} on success
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy()

    if master_data_privkey is None:
        master_data_privkey_info = load_user_data_privkey( fqu, proxy=proxy, config_path=config_path, wallet_keys=wallet_keys )
        if 'error' in master_data_privkey_info:
            log.error("Failed to load data private key")
            return {'error': 'Failed to load data private key'}

        master_data_privkey = master_data_privkey_info['privkey']

    if drivers is None:
        driver_handlers = storage.get_storage_handlers()
        drivers = [h.__name__ for h in driver_handlers]

    datastore_info = make_datastore(fqu, datastore_name, master_data_privkey, drivers, config_path=config_path )
    if 'error' in datastore_info:
        log.error("Failed to create datastore information: {}".format(datastore_info['error']))
        return {'error': 'Failed to create datastore'}

    datastore = datastore_info['datastore_pub']
    datastore_priv = datastore_info['datastore_priv']
    root = datastore_info['root']

    datastore_privkey_info = _get_datastore_privkey(fqu, datastore_name, master_data_privkey, datastore_priv=datastore_priv, config_path=config_path)
    if 'error' in datastore_privkey_info:
        log.error("Failed to get datastore private key info")
        return {'error': 'Failed to load datastore private key'}

    datastore_privkey = datastore_privkey_info['datastore_privkey']
    datastore_pubkey = ECPrivateKey(str(datastore_privkey)).public_key().to_hex()
    datastore_address = ECPublicKey(str(datastore_pubkey)).address()

    assert datastore_priv['datastore_name'] == datastore_name
    assert datastore_address == ECPublicKey(str(datastore['owner_pubkey'])).address()

    # store private datastore information
    res = datastore_store_privinfo(fqu, datastore_name, datastore_priv, master_data_privkey, config_path=config_path )
    if 'error' in res:
        log.error("Failed to store private datastore record: {}".format(res['error']))
        return {'error': 'Failed to store private datastore record'}

    # replicate root inode
    res = _put_inode(fqu, root, datastore_privkey, drivers, config_path=CONFIG_PATH, proxy=proxy, create=True )
    if 'error' in res:
        log.error("Failed to put root inode for datastore {}".format(datastore_name))

        res = datastore_remove_privinfo( fqu, datastore_id, config_path=config_path )
        if 'error' in res:
            log.error("Failed to remove private datastore info: {}".format(res['error']))

        return {'error': 'Failed to replicate datastore metadata'}

    # replicate public datastore record 
    res = put_mutable( fqu, datastore_name, datastore, data_privkey=master_data_privkey, storage_drivers=drivers, config_path=config_path, proxy=proxy )
    if 'error' in res:
        log.error("Failed to put datastore metadata for {}".format(datastore_fq_id))

        # try to clean up...
        res = _delete_inode(fqu, root['uuid'], datastore_privkey, drivers, proxy=proxy, config_path=config_path)
        if 'error' in res:
            log.error("Failed to clean up root inode {}".format(root['uuid']))

        res = datastore_remove_privinfo( fqu, datastore_id, config_path=config_path )
        if 'error' in res:
            log.error("Failed to remove private datastore info: {}".format(res['error']))

        return {'error': 'Failed to replicate datastore metadata'}

    # WARN: don't delete inode metadata locally.
    # keep them as tombstones.
    return {'status': True}


def delete_datastore(fqu, datastore_name, master_data_privkey=None, wallet_keys=None, force=False, config_path=CONFIG_PATH, proxy=None ):
    """
    Delete a datastore's information.
    If force is True, then delete the root inode even if it's not empty.

    Return {'status': True} on success
    Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy()
    
    if master_data_privkey is None:
        master_data_privkey_info = load_user_data_privkey( fqu, proxy=proxy, config_path=config_path, wallet_keys=wallet_keys )
        if 'error' in master_data_privkey_info:
            log.error("Failed to load data private key")
            return {'error': 'Failed to load data private key'}

        master_data_privkey = master_data_privkey_info['privkey']

    master_data_pubkey = ECPrivateKey(str(master_data_privkey)).public_key().to_hex()

    # get the datastore first
    datastore_info = get_datastore(fqu, datastore_name, wallet_keys=wallet_keys, master_data_pubkey=master_data_pubkey, config_path=config_path, proxy=proxy )
    if 'error' in datastore_info:
        log.error("Failed to look up datastore information for {}".format(datastore_name))
        return {'error': 'Failed to look up datastore'}
    
    datastore = datastore_info['datastore']
    if not datastore_info.has_key('datastore_private_key'):
        log.error("Datastore is not owned by this host: {}".format(datastore_info))
        return {'error': 'No datastore private key found'}

    datastore_privkey = datastore_info['datastore_private_key']

    # remove root inode 
    res = datastore_listdir(fqu, datastore, '/', config_path=config_path, proxy=proxy )
    if 'error' in res:
        if not force:
            log.error("Failed to list /")
            return {'error': 'Failed to check if datastore is empty'}
        else:
            log.warn("Failed to list /, but forced to remove it anyway")

    if not force and len(res['dir']['idata']) != 0:
        log.error("Datastore not empty")
        return {'error': 'Datastore not empty'}

    res = delete_mutable(fqu, datastore['root_uuid'], data_privkey=datastore_privkey, proxy=proxy, storage_drivers=datastore['drivers'], delete_version=False, config_path=config_path )
    if 'error' in res:
        log.error("Failed to delete root inode {}".format(datastore['root_uuid']))
        return {'error': res['error']}

    # remove public datastore record
    datastore_name = datastore['datastore_name']
    res = delete_mutable( fqu, datastore_name, data_privkey=master_data_privkey, proxy=proxy, config_path=config_path, delete_version=False )
    if 'error' in res:
        log.error("Failed to delete public datastore record: {}".format(res['error']))
        return {'error': 'Failed to delete public datastore record'}

    # remove private datastore record 
    res = datastore_remove_privinfo(fqu, datastore_name, config_path=config_path)
    if 'error' in res:
        log.error("Failed to delete private datastore record: {}".format(res['error']))
        return {'error': 'Failed to delete private datastore record'}

    return {'status': True}


def _get_inode( fqu, inode_uuid, data_pubkey, drivers, config_path=CONFIG_PATH, get_idata=True, proxy=None ):
    """
    Get an inode from mutable storage.  Verify that it has an
    equal or later version number than the one we have locally.

    Return {'status': True, 'inode': inode info} on success.  ret['inode]['idata'] will be defined if get_idata is True
    Return {'error': ...} on error
    """
    
    if proxy is None:
        proxy = get_default_proxy(config_path)

    conf = get_config(config_path)
    assert conf

    res = get_mutable(fqu, inode_uuid, data_pubkey=data_pubkey, storage_drivers=drivers, proxy=proxy, config_path=config_path )
    if 'error' in res:
        log.error("Failed to get inode {}: {}".format(inode_uuid, res['error']))
        return {'error': 'Failed to get inode'}

    inode_info = res['data']

    # must be an inode 
    try:
        jsonschema.validate(inode_info, MUTABLE_DATUM_INODE_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        return {'error': 'Invalid inode structure'}

    # must match owner 
    data_address = ECPublicKey(str(data_pubkey)).address()
    if inode_info['owner'] != data_address:
        log.error("Inode {} not owned by {} (but by {})".format(inode['uuid'], data_address, inode_info['owner']))
        return {'error': 'Invalid owner'}

    if not get_idata:
        # only wanted the inode
        return {'status': True, 'inode': inode_info}

    # get idata as well 
    idata_id = '{}.data'.format(inode_uuid)
    res = get_mutable(fqu, idata_id, data_pubkey=data_pubkey, storage_drivers=drivers, proxy=proxy, config_path=config_path )
    if 'error' in res:
        log.error("Failed to get inode data {}: {}".format(inode_uuid, res['error']))
        return {'error': 'Failed to get inode data'}

    idata = res['data']
    inode_info['idata'] = idata
    data_hash = None

    if inode_info['type'] == MUTABLE_DATUM_DIR_TYPE:
        try:
            jsonschema.validate(inode_info, MUTABLE_DATUM_DIR_SCHEMA)
        except ValidationError as ve:
            if BLOCKSTACK_DEBUG:
                log.exception(ve)

            return {'error': 'Invalid directory structure'}

        data_hash = _mutable_data_dir_hash(idata)

    else:
        try:
            jsonschema.validate(inode_info, MUTABLE_DATUM_FILE_SCHEMA)
        except ValidationError as ve:
            if BLOCKSTACK_DEBUG:
                log.exception(ve)

            return {'error': 'Invalid file strcuture'}

        data_hash = _mutable_data_file_hash(idata)

    # hashes must match
    if data_hash != inode_info['data_hash']:
        log.error("Inode data mismatch: expected {}, got {}".format(data_hash, inode_info['data_hash']))
        return {'error': 'Inode data mismatch'}

    return {'status': True, 'inode': inode_info}


def _put_inode( fqu, _inode, data_privkey, drivers, config_path=CONFIG_PATH, proxy=None, create=False ):
    """
    Store an inode and its associated idata
    Return {'status': True} on success
    Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    # separate data from metadata 
    idata = None
    inode = None
    if _inode.has_key('idata'):
        idata = _inode['idata']
        del _inode['idata']
        inode = _inode.copy()
        _inode['idata'] = idata

    else:
        inode = _inode.copy()

    if idata is not None:
        if inode['type'] == MUTABLE_DATUM_DIR_TYPE:
            assert _mutable_data_dir_hash(idata) == inode['data_hash']
        else:
            assert _mutable_data_file_hash(idata) == inode['data_hash']

        # put new idata 
        idata_id = '{}.data'.format(inode['uuid'])
        res = put_mutable(fqu, idata_id, idata, data_privkey=data_privkey, storage_drivers=drivers, config_path=config_path, proxy=proxy, create=create )
        if 'error' in res:
            log.error("Failed to replicate idata for {}: {}".format(inode['uuid'], res['error']))
            return {'error': 'Failed to replicate idata'}

    # put new inode 
    res = put_mutable(fqu, inode['uuid'], inode, data_privkey=data_privkey, storage_drivers=drivers, config_path=config_path, proxy=proxy, create=create )
    if 'error' in res:
        log.error("Failed to replicate inode {}: {}".format(inode['uuid'], res['error']))
        return {'error': 'Failed to replicate inode'}

    return {'status': True}


def _delete_inode( fqu, inode_uuid, data_privkey, drivers, config_path=CONFIG_PATH, proxy=None ):
    """
    Delete an inode and its associated data.
    Return {'status': True} on success
    Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    # delete idata 
    idata_id = '{}.data'.format(inode_uuid)
    res = delete_mutable(fqu, idata_id, data_privkey=data_privkey, proxy=proxy, storage_drivers=drivers, delete_version=False, config_path=config_path)
    if 'error' in res:
        log.error("Faled to delete idata for {}: {}".format(inode_uuid, res['error']))

    # delete inode 
    res = delete_mutable(fqu, inode_uuid, data_privkey=data_privkey, proxy=proxy, storage_drivers=drivers, delete_version=False, config_path=config_path )
    if 'error' in res:
        log.error("Failed to delete inode {}: {}".format(inode_uuid, res['error']))

    return {'status': True}
    

def _resolve_path( fqu, datastore, path, data_pubkey, config_path=CONFIG_PATH, proxy=None ):
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

    if proxy is None:
        proxy = get_default_proxy(config_path)

    path = posixpath.normpath(path).strip("/")
    path_parts = path.split('/')
    prefix = '/'

    drivers = datastore['drivers']
    root_uuid = datastore['root_uuid']

    root_inode = _get_inode( fqu, root_uuid, data_pubkey, drivers, config_path=CONFIG_PATH, proxy=proxy )
    if 'error' in root_inode:
        log.error("Failed to get root inode: {}".format(root_inode['error']))
        return {'error': root_inode['error'], 'errno': errno.EIO}

    ret = {
        '/': {'uuid': root_uuid, 'name': '', 'parent': '', 'inode': root_inode['inode']}
    }
   
    # walk 
    i = 0
    child_uuid = None
    name = None
    cur_dir = root_inode['inode']

    if len(path) == 0:
        # looked up /
        return ret

    for i in xrange(0, len(path_parts)):

        # find child UUID
        name = path_parts[i]
        child_dirent = cur_dir['idata'].get(name, None)

        if child_dirent is None:
            log.error('No child "{}" in "{}"\ninode:\n{}'.format(name, prefix, json.dumps(cur_dir, indent=4, sort_keys=True)))
            return {'error': 'No such file or directory', 'errno': errno.ENOENT}
       
        child_uuid = child_dirent['uuid']
        
        # get child
        child_entry = _get_inode( fqu, child_uuid, data_pubkey, drivers, config_path=CONFIG_PATH, proxy=proxy )
        if 'error' in child_entry:
            log.error("Failed to get inode {} at {}: {}".format(child_uuid, prefix + '/' + name, child_entry['error']))
            return {'error': child_entry['error'], 'errno': errno.EIO}

        child_entry = child_entry['inode']
        assert child_entry['type'] == child_dirent['type'], "Corrupt inode {}".format(storage.make_fq_data_id(fqu,child_uuid))

        path_ent = {
            'name': name,
            'uuid': child_uuid,
            'inode': child_entry,
            'parent': prefix,
        }
        if len(path_ent['parent']) > 1:
            path_ent['parent'] = path_ent['parent'].rstrip('/')

        prefix += name
        ret[prefix] = path_ent

        if child_dirent['type'] == MUTABLE_DATUM_DIR_TYPE:
            # next directory
            cur_dir = child_entry
            prefix += '/'

        else:
            # at a file
            break

    # did we reach the end?
    if i+1 < len(path_parts):
        log.debug('Out of path at "{}" (stopped at {} in {})'.format(prefix, i, path_parts))
        return {'error': 'Not a directory', 'errno': errno.ENOTDIR}

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


def _mutable_data_make_links( fqu, inode_uuid, urls=None, drivers=None ):
    """
    Make a bundle of URI record links for the given inode data.
    This constitutes the directory's idata
    """
    if drivers is None:
        drivers = storage.get_storage_handlers()

    fq_data_id = storage.make_fq_data_id(fqu, inode_uuid)

    if urls is None:
        urls = storage.get_driver_urls( fq_data_id, drivers )

    data_links = [user_db.url_to_uri_record(u) for u in urls]
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


def _lookup( fqu, datastore, data_path, data_pubkey, config_path=CONFIG_PATH, proxy=None ):
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

    # find the parent directory
    path_info = _resolve_path( fqu, datastore, data_path, data_pubkey, config_path=config_path, proxy=proxy )
    if 'error' in path_info:
        log.error('Failed to resolve {}'.format(dirpath))
        return path_info

    assert data_path in path_info.keys(), "Invalid path data, missing {}:\n{}".format(data_path, json.dumps(path_info, indent=4, sort_keys=True))
    inode_info = path_info[data_path]

    return {'status': True, 'path_info': path_info, 'inode_info': inode_info}


def datastore_mkdir( fqu, datastore, data_path, data_privkey, config_path=CONFIG_PATH, proxy=None ):
    """
    Make a directory at the given path.  The parent directory must exist.
    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on failure (optionally with 'stored_child': True set)
    """

    if proxy is None:
        proxy = get_default_proxy()

    path_info = _parse_data_path( data_path )
    parent_path = path_info['parent_path']
    data_path = path_info['data_path']
    name = path_info['iname']

    drivers = datastore['drivers']
    pubk = ECPrivateKey(str(data_privkey)).public_key()
    data_pubkey = pubk.to_hex()
    data_address = pubk.address()

    log.debug("mkdir {}:{}".format(datastore['datastore_name'], data_path))

    parent_info = _lookup( fqu, datastore, parent_path, data_pubkey, config_path=config_path, proxy=proxy )
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
        log.error('Already exists: {}'.format(path))
        return {'error': 'Path already exists', 'errno': errno.EEXIST}

    # make a directory!
    child_uuid = str(uuid.uuid4())
    child_dir_links = _mutable_data_make_links( fqu, child_uuid, drivers=drivers )
    child_dir_inode = _mutable_data_make_dir( data_address, child_uuid, {} )

    # update parent 
    parent_dir, child_dirent = _mutable_data_dir_link( parent_dir, MUTABLE_DATUM_DIR_TYPE, name, child_uuid, child_dir_links )
    
    # replicate the new child
    res = _put_inode(fqu, child_dir_inode, data_privkey, drivers, config_path=config_path, proxy=proxy, create=True )
    if 'error' in res:
        log.error("Failed to create directory {}: {}".format(data_path, res['error']))
        return {'error': 'Failed to store child directory', 'errno': errno.EIO}

    # replicate the new parent 
    res = _put_inode(fqu, parent_dir, data_privkey, drivers, config_path=config_path, proxy=proxy )
    if 'error' in res:
        log.error("Failed to update directory {}: {}".format(parent_path, res['error']))
        return {'error': 'Failed to store parent directory', 'stored_child': True, 'errno': errno.EIO}

    # TODO: cache traversed path

    return {'status': True}


def datastore_rmdir( fqu, datastore, data_path, data_privkey, config_path=CONFIG_PATH, proxy=None ):
    """
    Remove a directory at the given path.  The directory must be empty.
    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on error
    """
    
    if proxy is None:
        proxy = get_default_proxy()
   
    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    name = path_info['iname']

    if data_path == '/':
        # can't do this 
        log.error("Will not delete /")
        return {'error': 'Tried to delete root', 'errno': errno.EINVAL}

    drivers = datastore['drivers']
    data_pubkey = ECPrivateKey(str(data_privkey)).public_key().to_hex()

    log.debug("rmdir {}:{}".format(datastore['datastore_name'], data_path))

    dir_info = _lookup( fqu, datastore, data_path, data_pubkey, config_path=config_path, proxy=proxy )
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
    res = _put_inode( fqu, parent_dir_inode, data_privkey, drivers, config_path=config_path, proxy=proxy )
    if 'error' in res:
        log.error("Failed to update directory {}: {}".format(parent_path, res['error']))
        return {'error': 'Failed to update directory', 'errno': errno.EIO}

    # delete the child
    res = _delete_inode( fqu, dir_inode_uuid, data_privkey, drivers, config_path=config_path, proxy=proxy )
    if 'error' in res:
        log.error("Failed to delete directory {}: {}".format(data_path, res['error']))
        return {'error': 'Failed to delete directory', 'errno': errno.EIO}

    # TODO: invalidate cached data

    return {'status': True}


def datastore_getfile( fqu, datastore, data_path, config_path=CONFIG_PATH, proxy=None ):
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

    file_info = _lookup( fqu, datastore, data_path, datastore['owner_pubkey'], config_path=CONFIG_PATH, proxy=proxy )
    if 'error' in file_info:
        log.error("Failed to resolve {}".format(data_path))
        return file_info

    if file_info['inode_info']['inode']['type'] != MUTABLE_DATUM_FILE_TYPE:
        log.error("Not a file: {}".format(data_path))
        return {'error': 'Not a file', 'errno': errno.EISDIR}

    # TODO: cache
    return {'status': True, 'file': file_info['inode_info']['inode']}


def datastore_listdir( fqu, datastore, data_path, config_path=CONFIG_PATH, proxy=None ):
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

    dir_info = _lookup( fqu, datastore, data_path, datastore['owner_pubkey'], config_path=CONFIG_PATH, proxy=proxy )
    if 'error' in dir_info:
        log.error("Failed to resolve {}".format(data_path))
        return dir_info

    if dir_info['inode_info']['inode']['type'] != MUTABLE_DATUM_DIR_TYPE:
        log.error("Not a file: {}".format(data_path))
        return {'error': 'Not a file', 'errno': errno.EISDIR}

    # TODO: cache
    return {'status': True, 'dir': dir_info['inode_info']['inode']}


def datastore_putfile( fqu, datastore, data_path, file_data, data_privkey, config_path=CONFIG_PATH, proxy=None ):
    """
    Store a file identified by a path, creating it if need be.
    Return {'status': True} on success.
    Return {'error': ..., 'errno': ...} on error.
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    name = path_info['iname']
    parent_dirpath = path_info['parent_path']

    drivers = datastore['drivers']
    data_pubkey = ECPrivateKey(str(data_privkey)).public_key().to_hex()
    data_address = ECPublicKey(str(data_pubkey)).address()

    log.debug("putfile {}:{}".format(datastore['datastore_name'], data_path))

    # make sure the file doesn't exist
    parent_path_info = _lookup( fqu, datastore, parent_dirpath, data_pubkey, config_path=config_path, proxy=proxy )
    if 'error' in parent_path_info:
        log.error("Failed to resolve {}".format(data_path))
        return parent_path_info

    parent_dir_info = parent_path_info['inode_info']
    parent_uuid = parent_dir_info['uuid']
    parent_dir_inode = parent_dir_info['inode']

    if name in parent_dir_inode['idata'].keys():
        # already exists
        log.error('Already exists: {}'.format(data_path))
        return {'error': 'Already exists', 'errno': errno.EEXIST}

    # make a file!
    child_uuid = str(uuid.uuid4())
    child_file_links = _mutable_data_make_links( fqu, child_uuid, drivers=drivers )
    child_file_inode = _mutable_data_make_file( data_address, child_uuid, file_data )

    # update parent 
    parent_dir_inode, child_dirent = _mutable_data_dir_link( parent_dir_inode, MUTABLE_DATUM_FILE_TYPE, name, child_uuid, child_file_links )
    
    # replicate the new child
    res = _put_inode(fqu, child_file_inode, data_privkey, drivers, config_path=config_path, proxy=proxy, create=True )
    if 'error' in res:
        log.error("Failed to replicate file {}: {}".format(data_path, res['error']))
        return {'error': 'Failed to store file', 'errno': errno.EIO}

    # replicate the new parent
    res = _put_inode(fqu, parent_dir_inode, data_privkey, drivers, config_path=config_path, proxy=proxy )
    if 'error' in res:
        log.error("Failed to update directory {}: {}".format(parent_dirpath, res['error']))
        return {'error': 'Failed to update directory', 'errno': errno.EIO}

    # TODO: cache traversed path

    return {'status': True}


def datastore_deletefile( fqu, datastore, data_path, data_privkey, config_path=CONFIG_PATH, proxy=None ):
    """
    Delete a file from a directory.
    Return {'status': True} on success
    Return {'error': ..., 'errno': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    path_info = _parse_data_path( data_path )
    data_path = path_info['data_path']
    name = path_info['iname']
    parent_dirpath = path_info['parent_path']

    drivers = datastore['drivers']
    data_pubkey = ECPrivateKey(str(data_privkey)).public_key().to_hex()

    log.debug("deletefile {}:{}".format(datastore['datastore_name'], data_path))

    file_path_info = _lookup( fqu, datastore, data_path, data_pubkey, config_path=config_path, proxy=proxy )
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
    res = _put_inode(fqu, parent_dir_inode, data_privkey, drivers, config_path=config_path, proxy=proxy )
    if 'error' in res:
        log.error("Failed to update directory {}: {}".format(dir_path, res['error']))
        return {'error': 'Failed to update directory', 'errno': errno.EIO}

    # delete child 
    res = _delete_inode(fqu, file_uuid, data_privkey, drivers, config_path=config_path, proxy=proxy )
    if 'error' in res:
        log.error("Failed to delete file {}: {}".format(data_path, res['error']))
        return {'error': 'Failed to delete file', 'errno': errno.EIO}

    # TODO: invalidate cached data

    return {'status': True}

