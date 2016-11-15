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
import blockstack_profiles
import urllib
import virtualchain

import user as user_db
import storage

from .keys import *
from .profile import *
from .proxy import *
from .storage import hash_zonefile
from .accounts import get_profile_accounts

from .config import get_logger
from .constants import BLOCKSTACK_TEST

log = get_logger()


def serialize_mutable_data_id(data_id):
    """
    Turn a data ID into a suitable filesystem name
    """
    return urllib.quote(data_id.replace('\0', '\\0')).replace('/', r'\x2f')


def load_mutable_data_version(conf, name, fq_data_id):
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
        log.debug('No version path found')
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
        with open(version_file_path, 'w+') as f:
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
            info = proxy.getinfo()
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


def get_mutable(name, data_id, proxy=None, ver_min=None, ver_max=None,
                ver_check=None, conf=None, wallet_keys=None):
    """
    get_mutable

    Fetch a piece of mutable data.  Use @data_id to look it up in the user's
    profile, and then fetch and erify the data itself from the configured
    storage providers.

    If @ver_min is given, ensure the data's version is greater or equal to it.
    If @ver_max is given, ensure the data's version is less than it.
    If @ver_check is given, it must be a callable that takes the name, data and version and returns True/False

    Return {'data': the data, 'version': the version} on success
    Return {'error': ...} on error
    """

    proxy = get_default_proxy() if proxy is None else proxy
    conf = proxy.conf if conf is None else conf

    fq_data_id = storage.make_fq_data_id(name, data_id)

    user_profile, user_zonefile = get_name_profile(
        name, proxy=proxy, include_name_record=True
    )

    if user_profile is None:
        return user_zonefile  # will be an error message

    # recover name record
    name_record = user_zonefile.pop('name_record')

    if is_obsolete_zonefile(user_zonefile):
        # profile has not been converted to the new zonefile format yet.
        msg = 'Profile is in a legacy format that does not support mutable data.'
        return {'error': msg}

    # get the mutable data zonefile
    if not user_db.has_mutable_data(user_profile, data_id):
        return {'error': 'No such mutable datum'}

    mutable_data_info = user_db.get_mutable_data_profile(user_profile, data_id)
    msg = 'BUG: could not look up mutable datum "{}"."{}"'
    assert mutable_data_info is not None, msg.format(name, data_id)

    # get user's data public key and owner address
    data_pubkey = user_db.user_zonefile_data_pubkey(user_zonefile)
    data_address = name_record['address']
    if data_pubkey is None:
        log.warn('Falling back to owner address for authentication')

    # get the mutable data itself
    urls = user_db.mutable_data_urls(mutable_data_info)
    mutable_data = storage.get_mutable_data(
        fq_data_id, data_pubkey, urls=urls, data_address=data_address
    )

    if mutable_data is None:
        return {'error': 'Failed to look up mutable datum'}

    expected_version = load_mutable_data_version(conf, name, data_id)
    expected_version = 0 if expected_version is None else expected_version

    # check consistency
    version = user_db.mutable_data_version(user_profile, data_id)
    if ver_min is not None and ver_min > version:
        return {'error': 'Mutable data is stale'}

    if ver_max is not None and ver_max <= version:
        return {'error': 'Mutable data is in the future'}

    if ver_check is not None:
        rc = ver_check(name, mutable_data, version)
        if not rc:
            return {'error': 'Mutable data consistency check failed'}
    elif expected_version > version:
        msg = 'Mutable data is stale; a later version was previously fetched'
        return {'error': msg}
    else:
        assert False

    rc = store_mutable_data_version(conf, fq_data_id, version)
    if not rc:
        return {'error': 'Failed to store consistency information'}

    return {'data': mutable_data, 'version': version}


def app_data_sanity_check(name, user_profile, service_id,
                          account_id, data_id, data_privkey):
    """
    Perform basic sanity checks on a profile before
    doing a data operation on app data.
    Return {'status': True, 'storage_drivers': ..., 'data_pubkey': ...} on success
    Return {'error': ...} on failure
    """

    # sanity checks...
    # account must exist
    accounts = get_profile_accounts(user_profile, service_id, account_id)
    if len(accounts) != 1:
        log.error('No such account {}.{} in {}'.format(service_id, account_id, name))
        return {'error': 'No such account'}

    account = accounts[0]

    data_pubkey = str(account.get('data_pubkey', ''))

    # account public key must exist, and match the private key
    if not data_pubkey:
        msg = 'No data public key for account {}.{} in {}'
        log.error(msg.format(service_id, account_id, name))
        return {'error': 'Account is missing data public key'}

    # must be valid pubkey
    try:
        virtualchain.BitcoinPublicKey(data_pubkey)
    except Exception as e:
        return {'error': 'Invalid public key'}

    if data_privkey is not None:
        data_pk = virtualchain.BitcoinPrivateKey(data_privkey).public_key().to_hex()
        if str(data_pk) != data_pubkey:
            msg = 'Unexpected public key ({} != {})'
            log.error(msg.format(data_pk, data_pubkey))
            return {'error': 'Account has invalid public key'}

    # account must have storage drivers
    if 'storage_drivers' not in account:
        msg = 'No data storage drivers for account {}.{} in {}'
        log.error(msg.format(service_id, account_id, name))
        return {'error': 'Account is missing data storage drivers'}

    storage_drivers = account['storage_drivers']

    return {'status': True, 'storage_drivers': storage_drivers, 'data_pubkey': data_pubkey}


def app_account_data_id(service_id, account_id, data_id):
    """
    Make a fully-qualified data name that also identifies the
    service and account.
    """
    return '{}.{}.{}'.format(service_id, account_id, data_id)


def get_app_data(name, service_id, account_id, data_id, version=None, proxy=None, conf=None):
    """
    Get app-specific data, using the app's account.
    Authenticate it with the public key in the account.
    Return {'status': True, 'data': ..., 'version': ...} on success
    Return {'error': ...} on failure
    """

    proxy = get_default_proxy() if proxy is None else proxy
    conf = proxy.conf if conf is None else conf

    # look name up
    user_profile, user_zonefile = get_name_profile(name, proxy=proxy)
    if user_profile is None:
        return user_zonefile  # will be an error message

    if is_obsolete_zonefile(user_zonefile):
        # zonefile is a legacy profile.  There is no account data
        log.info('Profile is in legacy format.  No account data.')
        return {'status': True}

    res = app_data_sanity_check(
        name, user_profile, service_id, account_id, data_id, None
    )

    if 'error' in res:
        return res

    storage_drivers = res['storage_drivers']
    data_pubkey = res['data_pubkey']

    # NOTE: account data paths include service and account IDs
    account_data_id = app_account_data_id(service_id, account_id, data_id)
    fq_data_id = storage.make_fq_data_id(name, account_data_id)
    urls = storage.make_mutable_data_urls(fq_data_id, use_only=storage_drivers)

    if version is None:
        version = load_mutable_data_version(conf, name, account_data_id)
        version = 1 if version is None else version

    # get the data
    mutable_data = storage.get_mutable_data(fq_data_id, data_pubkey, urls=urls)
    if mutable_data is None:
        return {'error': 'Failed to look up mutable datum'}

    is_valid_application_data = (
        not isinstance(mutable_data, dict) or
        'data' not in mutable_data or
        'version' not in mutable_data
    )

    if not is_valid_application_data:
        msg = 'Invalid application data {}.{}.{} in {}'
        log.error(msg.format(service_id, account_id, data_id, name))
        return {'error': 'Invalid application data'}

    try:
        app_data = mutable_data['data']
        ver = int(mutable_data['version'])
    except Exception as e:
        log.exception(e)
        return {'error': 'Invalid application data'}

    if ver < version:
        # stale
        msg = 'Stale data (got {}, expected {} or higher)'
        log.error(msg.format(ver, version))
        return {'error': 'Stale data'}

    # remember that we've seen this
    rc = store_mutable_data_version(conf, fq_data_id, ver)
    if not rc:
        return {'error': 'Failed to store consistency information'}

    return {'status': True, 'data': app_data, 'version': ver}


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


def put_mutable_get_version(user_profile, data_id, data_json, make_version=None):
    """
    Given the user profile, data_id, desired version, and callback to create a version,
    find out what the next version of the mutable datum should be.
    """

    mutable_version = user_db.mutable_data_version(user_profile, data_id)
    if make_version is not None:
        return make_version(data_id, data_json, mutable_version)

    return 1 if mutable_version is None else mutable_version + 1


def put_mutable(name, data_id, data_json, proxy=None, create_only=False, update_only=False,
                txid=None, version=None, make_version=None, wallet_keys=None):
    """
    put_mutable

    Given a name, an ID for the data, and the data itself, sign and upload the data to the
    configured storage providers.  Add an entry for it into the user's profile as well.

    ** Consistency **

    @version, if given, is the version to include in the data.
    @make_version, if given, is a callback that takes the data_id, data_json, and current version as arguments, and generates the version to be included in the data record uploaded.
    If ver is not given, but make_ver is, then make_ver will be used to generate the version.
    If neither ver nor make_ver are given, the mutable data (if it already exists) is fetched, and the version is calculated as the larget known version + 1.

    ** Durability **

    Replication is best-effort.  If one storage provider driver succeeds, the put_mutable succeeds.  If they all fail, then put_mutable fails.
    More complex behavior can be had by creating a "meta-driver" that calls existing drivers' methods in the desired manner.

    Returns a dict with {'status': True, 'version': version, ...} on success
    Returns a dict with 'error' set on failure
    """

    if not isinstance(data_json, dict):
        raise ValueError('Mutable data must be a dict')

    proxy = get_default_proxy() if proxy is None else proxy

    fq_data_id = storage.make_fq_data_id(name, data_id)

    name_record = None
    user_profile, user_zonefile, created_new_zonefile = get_and_migrate_profile(
        name, create_if_absent=True, proxy=proxy,
        wallet_keys=wallet_keys, include_name_record=True
    )

    if 'error' in user_profile:
        return user_profile

    if created_new_zonefile:
        log.debug('User profile is in non-standard or legacy format')
        msg = (
            'User profile is in legacy format, which does not support this '
            'operation.  You must first migrate it with the "migrate" command.'
        )
        return {'error': msg}

    name_record = user_zonefile.pop('name_record')
    user_profile = user_profile['profile']
    user_zonefile = user_zonefile['zonefile']

    exists = user_db.has_mutable_data(user_profile, data_id)
    if not exists and update_only:
        return {'error': 'Mutable datum does not exist'}

    if exists and create_only:
        return {'error': 'Mutable datum already exists'}

    # get the version to use
    if version is None:
        version = put_mutable_get_version(
            user_profile, data_id, data_json, make_version=make_version
        )

    # generate the mutable zonefile
    data_privkey = get_data_or_owner_privkey(
        user_zonefile, name_record['address'],
        wallet_keys=wallet_keys, config_path=proxy.conf['path']
    )

    if 'error' in data_privkey:
        # error text
        return {'error': data_privkey['error']}
    else:
        data_privkey = data_privkey['privatekey']
        assert data_privkey is not None

    urls = storage.make_mutable_data_urls(fq_data_id)
    mutable_info = user_db.make_mutable_data(data_id, version, urls)

    # add the mutable data to the profile
    rc = user_db.put_mutable_data_profile(user_profile, data_id, version, mutable_info)
    assert rc, 'Failed to put mutable data zonefile'

    # for legacy migration...
    result = {}

    # update the profile with the new zonefile
    user_profile = set_profile_timestamp(user_profile)
    rc = storage.put_mutable_data(name, user_profile, data_privkey)
    if not rc:
        result['error'] = 'Failed to store mutable data zonefile to profile'
        return result

    # put the mutable data record itself
    rc = storage.put_mutable_data(fq_data_id, data_json, data_privkey)
    if not rc:
        result['error'] = 'Failed to store mutable data'
        return result

    # remember which version this was
    rc = store_mutable_data_version(proxy.conf, fq_data_id, version)
    if not rc:
        result['error'] = 'Failed to store mutable data version'
        return result

    result['status'] = True
    result['version'] = version

    if BLOCKSTACK_TEST is not None:
        msg = 'Put "{}" to {} mutable data (version {})\nProfile is now:\n{}'
        data = json.dumps(user_profile, indent=4, sort_keys=True)
        log.debug(msg.format(data_id, name, version, data))

    return result


def put_app_data(name, service_id, account_id, data_id, data_bin, data_privkey,
                 proxy=None, version=None, conf=None):
    """
    Put application data.

    The data will be signed by the given private key, and replicated
    to all storage providers (the operation only succeeds if it reaches
    all storage providers listed in @required_storage_drivers).

    The data will be uploaded to all the URLs given by the account
    that matches the given (service_id, account_id) pair.

    Return {'status': True, 'version': 'data': ...} on success
    Return {'error': ...} on error.
    """

    proxy = get_default_proxy() if proxy is None else proxy
    conf = proxy.conf if conf is None else conf

    # look name up
    user_profile, user_zonefile = get_name_profile(name, proxy=proxy)
    if user_profile is None:
        return user_zonefile    # will be an error message

    if is_obsolete_zonefile(user_zonefile):
        # zonefile is a legacy profile.  There is no account data
        log.info('Profile is in legacy format.  No account data.')
        return {'status': True}

    res = app_data_sanity_check(
        name, user_profile, service_id, account_id, data_id, data_privkey
    )

    if 'error' in res:
        return res

    storage_drivers = res['storage_drivers']

    # NOTE: account data paths include service and account IDs
    account_data_id = app_account_data_id(service_id, account_id, data_id)
    fq_data_id = storage.make_fq_data_id(name, account_data_id)

    # store a signed version along with this data
    if version is None:
        version = load_mutable_data_version(conf, name, account_data_id)
        version = 1 if version is None else version

    result = {}

    # put the mutable data record itself
    app_data = {
        'data': data_bin,
        'version': version
    }

    rc = storage.put_mutable_data(
        fq_data_id, app_data, data_privkey, use_only=storage_drivers
    )

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

    return result


def delete_immutable(name, data_key, data_id=None, proxy=None, txid=None, wallet_keys=None):
    """
    delete_immutable

    Remove an immutable datum from a name's profile, given by @data_key.
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


def delete_mutable(name, data_id, proxy=None, wallet_keys=None):
    """
    delete_mutable

    Remove a piece of mutable data from the user's profile. Delete it from
    the storage providers as well.

    Returns a dict with {'status': True} on success
    Returns a dict with {'error': ...} on failure
    """

    proxy = get_default_proxy() if proxy is None else proxy

    fq_data_id = storage.make_fq_data_id(name, data_id)

    user_profile, user_zonefile = get_name_profile(
        name, proxy=proxy, include_name_record=True
    )

    if user_profile is None:
        return user_zonefile    # will be an error message

    name_record = user_zonefile.pop('name_record')

    if is_obsolete_zonefile(user_zonefile):
        # zonefile is a legacy profile.  There is no mutable data
        log.info('Non-standard or legacy zonefile')
        return {'error': 'Non-standard or legacy zonefile'}

    # already deleted?
    if not user_db.has_mutable_data(user_profile, data_id):
        return {'status': True}

    # unlink
    user_db.remove_mutable_data_profile(user_profile, data_id)

    # put new profile
    data_privkey = get_data_or_owner_privkey(
        user_zonefile, name_record['address'],
        wallet_keys=wallet_keys, config_path=proxy.conf['path']
    )

    if 'error' in data_privkey:
        return {'error': data_privkey['error']}
    else:
        data_privkey = data_privkey['privatekey']
        assert data_privkey is not None

    # advance timestamp
    user_profile = set_profile_timestamp(user_profile)
    rc = storage.put_mutable_data(name, user_profile, data_privkey)
    if not rc:
        return {'error': 'Failed to unlink mutable data from profile'}

    # remove the data itself
    rc = storage.delete_mutable_data(fq_data_id, data_privkey)
    if not rc:
        return {'error': 'Failed to delete mutable data from storage providers'}

    return {'status': True}


def delete_app_data(name, service_id, account_id, data_id, data_privkey, proxy=None):
    """
    Delete some app-specific data.

    Returns a dict with {'status': True} on success
    Returns a dict with {'error': ...} on failure
    """

    proxy = get_default_proxy() if proxy is None else proxy

    user_profile, user_zonefile = get_name_profile(name, proxy=proxy)
    if user_profile is None:
        return user_zonefile    # will be an error message

    if is_obsolete_zonefile(user_zonefile):
        # zonefile is a legacy profile.  There is no account data
        log.info('Profile is in legacy format.  No account data.')
        return {'status': True}

    # get drivers and do a sanity check on the key
    res = app_data_sanity_check(
        name, user_profile, service_id, account_id, data_id, data_privkey
    )

    if 'error' in res:
        return res

    account_data_id = app_account_data_id(service_id, account_id, data_id)
    fq_data_id = storage.make_fq_data_id(name, account_data_id)

    # remove the data itself
    rc = storage.delete_mutable_data(fq_data_id, data_privkey)
    if not rc:
        return {'error': 'Failed to delete mutable data from storage providers'}

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


def list_mutable_data(name, proxy=None, wallet_keys=None):
    """
    List the names and versions of all mutable data in a user's zonefile
    Returns {'data': [{'data_id': data ID, 'version': version}]}
    """
    proxy = get_default_proxy() if proxy is None else proxy

    user_profile, user_zonefile = get_name_profile(name, proxy=proxy)
    if user_zonefile is None:
        # user_profile will contain an error message
        return user_profile

    if is_obsolete_zonefile(user_zonefile):
        # zonefile is really a legacy profile
        return {'data': []}

    names_and_versions = user_db.list_mutable_data(user_profile)
    listing = [{'data_id': nv[0], 'version': nv[1]} for nv in names_and_versions]
    return {'data': listing}


def blockstack_url_fetch(url, proxy=None, wallet_keys=None):
    """
    Given a blockstack:// url, fetch its data.
    If the data is an immutable data url, and the hash is not given, then look up the hash first.
    If the data is a mutable data url, and the version is not given, then look up the version as well.

    Return {'data': data} on success
    Return {'error': error message} on error
    """
    mutable = False
    blockchain_id, data_id, version = None, None, None
    data_hash, account_id, service_id = None, None, None

    try:
        blockchain_id, data_id, version, account_id, service_id = (
            storage.blockstack_mutable_data_url_parse(url)
        )
        mutable = True
    except ValueError as ve:
        log.exception(ve)
        blockchain_id, data_id, data_hash = (
            storage.blockstack_immutable_data_url_parse(url)
        )

    if mutable:
        if data_id is None:
            # list data
            return list_mutable_data(blockchain_id, proxy=proxy, wallet_keys=wallet_keys)

        if account_id is not None and service_id is not None:
            # get single account data
            return get_app_data(
                blockchain_id, service_id, account_id,
                data_id, version=version, proxy=proxy
            )

        # get single data
        if version is None:
            return get_mutable(blockchain_id, data_id, proxy=proxy, wallet_keys=wallet_keys)

        return get_mutable(
            blockchain_id, data_id, proxy=proxy, wallet_keys=wallet_keys,
            ver_min=version, ver_max=version + 1
        )

    # process immutable data

    if data_id is None:
        # list data
        return list_immutable_data(blockchain_id, proxy=proxy)

    # get single data
    if data_hash is None:
        return get_immutable_by_name(blockchain_id, data_id, proxy=proxy)

    return get_immutable(blockchain_id, data_hash, data_id=data_id, proxy=proxy)


def data_get(blockstack_url, proxy=None, wallet_keys=None, **kw):
    """
    Resolve a blockstack URL to data (be it mutable or immutable).
    """
    begin, end = None, None

    begin = time.time()
    ret = blockstack_url_fetch(blockstack_url, proxy=proxy, wallet_keys=wallet_keys)
    end = time.time()

    if BLOCKSTACK_TEST is not None:
        log.debug('[BENCHMARK] data_get {}'.format(end - begin))

    return ret


def data_put(blockstack_url, data, proxy=None,
             wallet_keys=None, data_privkey=None, **kw):
    """
    Put data to a blockstack URL (be it mutable or immutable).
    @data_privkey is required for app-specific data.

    Return {'status': True} on success
    Return {'error': ...} on failure
    Raise on invalid input
    """
    parts = storage.blockstack_data_url_parse(blockstack_url)
    assert parts is not None, 'invalid url "{}"'.format(blockstack_url)

    begin, end = None, None

    if parts['type'] == 'immutable':
        begin = time.time()

        ret = put_immutable(
            parts['blockchain_id'], parts['data_id'], data,
            proxy=proxy, wallet_keys=wallet_keys, **kw
        )

        end = time.time()
    else:
        begin = time.time()

        if not parts['app']:
            # profile data
            ret = put_mutable(
                parts['blockchain_id'], parts['data_id'], data,
                proxy=proxy, wallet_keys=wallet_keys, **kw
            )
        else:
            if data_privkey is None:
                raise ValueError('data_privkey is None')

            # app-specific data
            fields = parts['fields']
            version = fields.get('version', None)
            ret = put_app_data(
                parts['blockchain_id'], fields['service_id'], fields['account_id'],
                parts['data_id'], data, data_privkey, proxy=proxy, version=version
            )

        end = time.time()

    if BLOCKSTACK_TEST is not None:
        log.debug('[BENCHMARK] data_put {}'.format(end - begin))

    return ret


def data_delete(blockstack_url, proxy=None, wallet_keys=None, **kw):
    """
    Delete data from a blockstack URL (be it mutable or immutable).
    """
    parts = storage.blockstack_data_url_parse(blockstack_url)
    assert parts is not None, 'invalid url "{}"'.format(blockstack_url)

    if parts['type'] == 'immutable':
        return delete_immutable(
            parts['blockchain_id'], parts['fields']['data_hash'],
            data_id=parts['data_id'], proxy=proxy, wallet_keys=wallet_keys, **kw
        )

    ret = None
    if not parts['app']:
        ret = delete_mutable(
            parts['blockchain_id'], parts['data_id'],
            proxy=proxy, wallet_keys=wallet_keys
        )
        return ret

    # app-specific delete
    fields = parts['fields']
    # BUG: required parameter "data_privkey" is not provided as argument
    ret = delete_app_data(
        parts['blockchain_id'], fields['service_id'],
        fields['account_id'], parts['data_id'], proxy=proxy
    )

    return ret


def data_list(name, proxy=None, wallet_keys=None):
    """
    List all data for a blockchain ID
    Return {'status': True, 'listing': [...]} on success
    Return {'error': ...} on failure
    """
    immutable_listing = list_immutable_data(name, proxy=proxy)
    mutable_listing = list_mutable_data(name, proxy=proxy, wallet_keys=wallet_keys)

    if 'error' in immutable_listing:
        return immutable_listing

    if 'error' in mutable_listing:
        return mutable_listing

    return {'status': True, 'listing': immutable_listing['data'] + mutable_listing['data']}


def set_data_pubkey(name, data_pubkey, proxy=None, wallet_keys=None, txid=None):
    """
    Set the data public key for a name.
    Overwrites the public key that is present (if given at all).

    WARN: you will need to re-sign all your data after you do this; otherwise
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
