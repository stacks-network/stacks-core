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
import time
import copy
import blockstack_profiles
import blockstack_zones
import base64
import httplib
import virtualchain

from .proxy import *
from blockstack_client import storage
from blockstack_client import user as user_db

from .config import get_logger, get_config
from .constants import USER_ZONEFILE_TTL, CONFIG_PATH, BLOCKSTACK_TEST, BLOCKSTACK_DEBUG

from .zonefile import load_data_pubkey_for_new_zonefile, get_name_zonefile, make_empty_zonefile
from .keys import get_data_privkey_info, get_pubkey_hex 

log = get_logger()


def set_profile_timestamp(profile, now=None):
    """
    Set the profile's timestamp to now
    """
    now = time.time() if now is None else now
    profile['timestamp'] = now

    return profile


def get_profile_timestamp(profile):
    """
    Get profile timestamp
    """
    return profile['timestamp']


def load_legacy_user_profile(name, expected_hash):
    """
    Load a legacy user profile, and convert it into
    the new zonefile-esque profile format that can
    be serialized into a JWT.

    Verify that the profile hashses to the above expected hash
    """

    # fetch...
    storage_host = 'onename.com'
    assert name.endswith('.id')

    name_without_namespace = '.'.join(name.split('.')[:-1])
    storage_path = '/{}.json'.format(name_without_namespace)

    try:
        req = httplib.HTTPConnection(storage_host)
        resp = req.request('GET', storage_path)
        data = resp.read()
    except Exception as e:
        log.error('Failed to fetch http://{}/{}: {}'.format(storage_host, storage_path, e))
        return None

    try:
        data_json = json.loads(data)
    except Exception as e:
        log.error('Unparseable profile data')
        return None

    data_hash = storage.get_blockchain_compat_hash(data_json)
    if expected_hash != data_hash:
        log.error('Hash mismatch: expected {}, got {}'.format(expected_hash, data_hash))
        return None

    assert blockstack_profiles.is_profile_in_legacy_format(data_json)
    new_profile = blockstack_profiles.get_person_from_legacy_format(data_json)
    return new_profile



def put_profile(name, new_profile, blockchain_id=None, user_data_privkey=None, user_zonefile=None,
                   proxy=None, wallet_keys=None, required_drivers=None, config_path=CONFIG_PATH):
    """
    Set the new profile data.  CLIENTS SHOULD NOT CALL THIS METHOD DIRECTLY.
    Return {'status: True} on success
    Return {'error': ...} on failure.
    """

    ret = {}

    proxy = get_default_proxy() if proxy is None else proxy
    config = proxy.conf
    
    # deduce storage drivers
    required_storage_drivers = None
    if required_drivers is not None:
        required_storage_drivers = required_drivers
    else:
        required_storage_drivers = config.get('storage_drivers_required_write', None)
        if required_storage_drivers is not None:
            required_storage_drivers = required_storage_drivers.split(',')
        else:
            required_storage_drivers = config.get('storage_drivers', '').split(',')

    # deduce private key
    if user_data_privkey is None:
        user_data_privkey = get_data_privkey_info(user_zonefile, wallet_keys=wallet_keys, config_path=config_path)
        if json_is_error(user_data_privkey):
            log.error("Failed to get data private key: {}".format(user_data_privkey['error']))
            return {'error': 'No data key defined'}

    profile_payload = copy.deepcopy(new_profile)
    profile_payload = set_profile_timestamp(profile_payload)

    if BLOCKSTACK_DEBUG:
        # NOTE: don't calculate this string unless we're actually debugging...
        log.debug('Save updated profile for "{}" to {} at {} by {}'.format(
            name, ','.join(required_storage_drivers), get_profile_timestamp(profile_payload), get_pubkey_hex(user_data_privkey))
        )

    rc = storage.put_mutable_data(
        name, profile_payload, user_data_privkey,
        required=required_storage_drivers,
        profile=True, blockchain_id=blockchain_id
    )

    if rc:
        ret['status'] = True
    else:
        ret['error'] = 'Failed to update profile'

    return ret


def delete_profile(blockchain_id, user_data_privkey=None, user_zonefile=None,
                   proxy=None, wallet_keys=None):
    """
    Delete profile data.  CLIENTS SHOULD NOT CALL THIS DIRECTLY
    Return {'status: True} on success
    Return {'error': ...} on failure.
    """

    ret = {}

    proxy = get_default_proxy() if proxy is None else proxy
    config = proxy.conf
    
    # deduce private key
    if user_data_privkey is None:
        user_data_privkey = get_data_privkey_info(user_zonefile, wallet_keys=wallet_keys, config_path=proxy.conf['path'])
        if json_is_error(user_data_privkey):
            log.error("Failed to get data private key: {}".format(user_data_privkey['error']))
            return {'error': 'No data key defined'}

    rc = storage.delete_mutable_data(blockchain_id, user_data_privkey)
    if rc:
        ret['status'] = True
    else:
        ret['error'] = 'Failed to update profile'

    return ret


def get_profile(name, zonefile_storage_drivers=None, profile_storage_drivers=None,
                proxy=None, user_zonefile=None, name_record=None,
                include_name_record=False, include_raw_zonefile=False, use_zonefile_urls=True,
                use_legacy=False, use_legacy_zonefile=True, decode_profile=True):
    """
    Given a name, look up an associated profile.
    Do so by first looking up the zonefile the name points to,
    and then loading the profile from that zonefile's public key.

    Notes on backwards compatibility (activated if use_legacy=True and use_legacy_zonefile=True):
    
    * (use_legacy=True) If the user's zonefile is really a legacy profile from Onename, then
    the profile returned will be the converted legacy profile.  The returned zonefile will still
    be a legacy profile, however.
    The caller can check this and perform the conversion automatically.

    * (use_legacy_zonefile=True) If the name points to a current zonefile that does not have a 
    data public key, then the owner address of the name will be used to verify
    the profile's authenticity.

    Returns (profile, zonefile) on success.  If include_name_record is True, then zonefile['name_record'] will be defined and will contain the user's blockchain information
    Returns (None, {'error': ...}) on failure
    """

    proxy = get_default_proxy() if proxy is None else proxy

    raw_zonefile = None
    if user_zonefile is None:
        user_zonefile = get_name_zonefile(
            name, proxy=proxy,
            name_record=name_record, include_name_record=True,
            storage_drivers=zonefile_storage_drivers,
            include_raw_zonefile=include_raw_zonefile,
            allow_legacy=True
        )

        if 'error' in user_zonefile:
            return None, user_zonefile

        raw_zonefile = None
        if include_raw_zonefile:
            raw_zonefile = user_zonefile.pop('raw_zonefile')

        user_zonefile = user_zonefile['zonefile']

    # is this really a legacy profile?
    if blockstack_profiles.is_profile_in_legacy_format(user_zonefile):
        if not use_legacy:
            return (None, {'error': 'Profile is in legacy format'})

        # convert it
        log.debug('Converting legacy profile to modern profile')
        user_profile = blockstack_profiles.get_person_from_legacy_format(user_zonefile)

    elif not user_db.is_user_zonefile(user_zonefile):
        if not use_legacy:
            return (None, {'error': 'Name zonefile is non-standard'})

        # not a legacy profile, but a custom profile
        log.debug('Using custom legacy profile')
        user_profile = copy.deepcopy(user_zonefile)

    else:
        # get user's data public key
        data_address, owner_address = None, None

        try:
            user_data_pubkey = user_db.user_zonefile_data_pubkey(user_zonefile)
            if user_data_pubkey is not None:
                user_data_pubkey = str(user_data_pubkey)
                data_address = virtualchain.BitcoinPublicKey(user_data_pubkey).address()

        except ValueError:
            # multiple keys defined; we don't know which one to use
            user_data_pubkey = None

        if not use_legacy_zonefile and user_data_pubkey is None:
            # legacy zonefile without a data public key 
            return (None, {'error': 'Name zonefile is missing a public key'})

        # find owner address
        if name_record is None:
            name_record = get_name_blockchain_record(name, proxy=proxy)
            if name_record is None or 'error' in name_record:
                log.error('Failed to look up name record for "{}"'.format(name))
                return None, {'error': 'Failed to look up name record'}

        assert 'address' in name_record.keys(), json.dumps(name_record, indent=4, sort_keys=True)
        owner_address = name_record['address']

        # get user's data public key from the zonefile
        urls = None
        if use_zonefile_urls and user_zonefile is not None:
            urls = user_db.user_zonefile_urls(user_zonefile)

        user_profile = storage.get_mutable_data(
            name, user_data_pubkey,
            data_address=data_address, owner_address=owner_address,
            urls=urls, drivers=profile_storage_drivers, decode=decode_profile,
        )

        if user_profile is None or json_is_error(user_profile):
            if user_profile is None:
                log.debug('WARN: no user profile for {}'.format(name))
            else:
                log.debug('WARN: failed to load profile for {}: {}'.format(name, user_profile['error']))

            return None, {'error': 'Failed to load user profile'}

    # finally, if the caller asked for the name record, and we didn't get a chance to look it up,
    # then go get it.
    if include_name_record:
        if name_record is None:
            name_record = get_name_blockchain_record(name, proxy=proxy)

        if name_record is None or 'error' in name_record:
            log.error('Failed to look up name record for "{}"'.format(name))
            return None, {'error': 'Failed to look up name record'}

        user_zonefile['name_record'] = name_record

    if include_raw_zonefile:
        if raw_zonefile is not None:
            user_zonefile['raw_zonefile'] = raw_zonefile

    return user_profile, user_zonefile


