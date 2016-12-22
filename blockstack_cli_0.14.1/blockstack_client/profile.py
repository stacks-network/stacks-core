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
from .keys import get_data_or_owner_privkey
from blockstack_client import storage
from blockstack_client import user as user_db

from .config import get_logger, get_config
from .constants import USER_ZONEFILE_TTL, CONFIG_PATH, BLOCKSTACK_TEST, BLOCKSTACK_DEBUG

from .zonefile import load_data_pubkey_for_new_zonefile, get_name_zonefile, make_empty_zonefile

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


def deduce_profile_privkey( user_zonefile=None, owner_address=None, wallet_keys=None, proxy=None, config_path=CONFIG_PATH ):
    """
    Deduce the private key for a profile, given profile information
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    # deduce private key
    if user_zonefile is None or owner_address is None or wallet_keys is None:
        raise Exception("Could not deduce private key")

    data_privkey_res = get_data_or_owner_privkey(
        user_zonefile, owner_address,
        wallet_keys=wallet_keys, config_path=proxy.conf['path']
    )

    if 'error' in data_privkey_res:
        return {'error': data_privkey_res['error']}

    data_privkey = data_privkey_res['privatekey']
    assert data_privkey is not None
    return data_privkey


def get_user_profile(user_id, user_data_pubkey=None, user_zonefile=None, data_address=None, owner_address=None,
                      use_zonefile_urls=True, storage_drivers=None, decode=True):
    """
    Fetch and load a user profile, given a zonefile.
    Try to verify using the public key in the zonefile (if one
    is present), and fall back to the user-address if need be
    (it should be the hash of the profile JWT's public key).

    user_id can be an arbitrary string.

    At least one of the following is required:
    * the public key
    * the public key from the zonefile
    * the data address
    * the owner address

    Return the user profile on success (either as a dict, or as a string if decode=False)
    Return None on error
    Raise on invalid arguments
    """
    # get user's data public key
    if user_data_pubkey is None and user_zonefile is not None:
        try:
            user_data_pubkey = user_db.user_zonefile_data_pubkey(user_zonefile)
        except ValueError as v:
            # user decided to put multiple keys into the zonefile.
            # so don't use them.
            log.exception(v)
            user_data_pubkey = None

    if user_zonefile is None and use_zonefile_urls:
        raise Exception("No zonefile given, but requested zonefile URLs")

    if user_data_pubkey is None and data_address is None and owner_address is None:
        raise Exception('Missing user data public key and address; cannot verify profile')

    if user_data_pubkey is None:
        msg = (
            'No data public key set; falling back to hash of data '
            'and/or owner public key for profile authentication'
        )
        log.warn(msg)

    # get user's data public key from the zonefile
    urls = None
    if use_zonefile_urls and user_zonefile is not None:
        urls = user_db.user_zonefile_urls(user_zonefile)

    user_profile = storage.get_mutable_data(
        user_id, user_data_pubkey,
        data_address=data_address, owner_address=owner_address,
        urls=urls, drivers=storage_drivers, decode=decode
    )

    return user_profile


def put_profile(name, new_profile, user_data_privkey=None, user_zonefile=None, owner_address=None,
                   proxy=None, wallet_keys=None, required_drivers=None):
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
        user_data_privkey = deduce_profile_privkey( user_zonefile=user_zonefile, owner_address=owner_address, wallet_keys=wallet_keys, proxy=proxy )

    profile_payload = copy.deepcopy(new_profile)
    profile_payload = set_profile_timestamp(profile_payload)

    log.debug('Save updated profile for "{}" to {} at {}'.format(
        name, ','.join(required_storage_drivers), get_profile_timestamp(profile_payload))
    )

    rc = storage.put_mutable_data(
        name, profile_payload, user_data_privkey,
        required=required_storage_drivers,
        profile=True
    )

    if rc:
        ret['status'] = True
    else:
        ret['error'] = 'Failed to update profile'

    return ret


def delete_profile(name, user_data_privkey=None, user_zonefile=None, owner_address=None,
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
        user_data_privkey = deduce_profile_privkey( user_zonefile=user_zonefile, owner_address=owner_address, wallet_keys=wallet_keys, proxy=proxy )

    rc = storage.delete_mutable_data(name, user_data_privkey)
    if rc:
        ret['status'] = True
    else:
        ret['error'] = 'Failed to update profile'

    return ret


def get_name_profile(name, zonefile_storage_drivers=None, profile_storage_drivers=None,
                     create_if_absent=False, proxy=None, user_zonefile=None, name_record=None,
                     include_name_record=False, include_raw_zonefile=False, use_zonefile_urls=True,
                     use_legacy=False, decode_profile=True):
    """
    Given a name, look up an associated profile.
    Do so by first looking up the zonefile the name points to,
    and then loading the profile from that zonefile's public key.

    This only works for *names on the blockchain*, where the profile's user ID is the name itself.
    It *will not work* for arbitrary user_ids.  Use get_user_profile for that.

    Notes on backwards compatibility (activated if use_legacy=True):
    * If the user's zonefile is really a legacy profile, then
    the profile returned will be the converted legacy profile.  The
    returned zonefile will still be a legacy profile, however.
    The caller can check this and perform the conversion automatically.
    * If the name points to a current zonefile that does not have a 
    public key, then the owner address of the name will be used to verify
    the profile's authenticity.

    Returns (profile, zonefile) on success.  If include_name_record is True, then zonefile['name_record'] will be defined and will contain the user's blockchain information
    Returns (None, {'error': ...}) on failure
    """

    proxy = get_default_proxy() if proxy is None else proxy

    raw_zonefile = None

    if user_zonefile is None:
        user_zonefile = get_name_zonefile(
            name, create_if_absent=create_if_absent, proxy=proxy,
            name_record=name_record, include_name_record=True,
            storage_drivers=zonefile_storage_drivers,
            include_raw_zonefile=include_raw_zonefile
        )

        if user_zonefile is None:
            return None, {'error': 'No user zonefile'}

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
        user_address, old_address = None, None

        try:
            user_data_pubkey = user_db.user_zonefile_data_pubkey(user_zonefile)
            if user_data_pubkey is not None:
                user_data_pubkey = str(user_data_pubkey)
                user_address = virtualchain.BitcoinPublicKey(user_data_pubkey).address()

        except ValueError:
            # user decided to put multiple keys under the same name into the zonefile.
            # so don't use them.
            user_data_pubkey = None

        if not use_legacy and user_data_pubkey is None:
            # legacy zonefile without a data public key 
            return (None, {'error': 'Name zonefile is missing a public key'})

        # convert to address
        if name_record is None:
            name_record = get_name_blockchain_record(name, proxy=proxy)
            if name_record is None or 'error' in name_record:
                log.error('Failed to look up name record for "{}"'.format(name))
                return None, {'error': 'Failed to look up name record'}

        assert 'address' in name_record.keys(), json.dumps(name_record, indent=4, sort_keys=True)
        old_address = name_record['address']

        # cut to the chase
        user_address = old_address if user_address is None else user_address

        user_profile = get_user_profile(
            name, user_zonefile=user_zonefile, data_address=user_address, owner_address=old_address,
            use_zonefile_urls=use_zonefile_urls,
            storage_drivers=profile_storage_drivers,
            decode=decode_profile
        )

        if user_profile is None or (not isinstance(user_profile, (str, unicode)) and 'error' in user_profile):
            if user_profile is None:
                log.debug('WARN: no user profile for {}'.format(name))
            else:
                log.debug('WARN: failed to load profile for {}: {}'.format(name, user_profile['error']))

            if create_if_absent:
                user_profile = user_db.make_empty_user_profile()
            else:
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


def get_and_migrate_profile(name, zonefile_storage_drivers=None, profile_storage_drivers=None,
                            proxy=None, create_if_absent=False, wallet_keys=None, include_name_record=False):
    """
    Get a name's profile and zonefile, optionally creating a new one along the way.  Migrate the profile to a new zonefile,
    if the profile is in legacy format.

    Only pass 'create_if_absent=True' for names we own

    If @include_name_record is set, then the resulting zonefile will have a key called 'name_record' that includes the name record.

    @wallet_keys, if given, only needs the data public key set.

    Return ({'profile': user_profile}, {'zonefile': user_zonefile}, migrated:bool) on success
    Return ({'error': ...}, None, False) on error
    """

    proxy = get_default_proxy() if proxy is None else proxy

    created_new_zonefile, created_new_profile = False, False

    name_record = None
    user_zonefile = get_name_zonefile(
        name, storage_drivers=zonefile_storage_drivers, proxy=proxy,
        wallet_keys=wallet_keys, include_name_record=True
    )

    if user_zonefile is not None and 'error' not in user_zonefile:
        name_record = user_zonefile.pop('name_record')
        user_zonefile = user_zonefile['zonefile']
    else:
        if not create_if_absent:
            return {'error': 'No such zonefile'}, None, False

        # creating. we'd better have a data public key
        log.debug('Creating new profile and zonefile for name "{}"'.format(name))

        data_pubkey = load_data_pubkey_for_new_zonefile(
            wallet_keys=wallet_keys, config_path=proxy.conf['path']
        )

        if data_pubkey is None:
            log.warn('No data keypair set; will fall back to owner private key for data signing')

        user_profile = user_db.make_empty_user_profile()
        user_zonefile = make_empty_zonefile(name, data_pubkey)

        # look up name too
        name_record = get_name_blockchain_record(name, proxy=proxy)
        if name_record is None:
            return {'error': 'No such name'}, None, False

        if 'error' in name_record:
            return {'error': 'Failed to look up name: {}'.format(name_record['error'])}, None, False

        created_new_zonefile, created_new_profile = True, True

    if blockstack_profiles.is_profile_in_legacy_format(user_zonefile) or not user_db.is_user_zonefile(user_zonefile):
        log.debug('Migrating legacy profile to modern zonefile for name "{}"'.format(name))

        data_pubkey = load_data_pubkey_for_new_zonefile(
            wallet_keys=wallet_keys, config_path=proxy.conf['path']
        )

        if data_pubkey is None:
            log.warn('No data keypair set; will fall back to owner private key for data signing')

        user_profile = {}
        if blockstack_profiles.is_profile_in_legacy_format(user_zonefile):
            # traditional profile
            user_profile = blockstack_profiles.get_person_from_legacy_format(user_zonefile)
        else:
            # custom profile
            user_profile = copy.deepcopy(user_zonefile)

        user_zonefile = make_empty_zonefile(name, data_pubkey)

        created_new_zonefile, created_new_profile = True, True
    else:
        if not created_new_profile:
            user_profile, error_msg = get_name_profile(
                name, zonefile_storage_drivers=zonefile_storage_drivers,
                profile_storage_drivers=profile_storage_drivers,
                proxy=proxy, user_zonefile=user_zonefile, name_record=name_record,
                use_legacy=True
            )

            if user_profile is None:
                return error_msg, None, False

        elif create_if_absent:
            log.debug('Creating new profile for existing zonefile for name "{}"'.format(name))
            user_profile = user_db.make_empty_user_profile()
            created_new_profile = True
        else:
            raise Exception('Should be unreachable')

    ret_user_profile = {'profile': user_profile}
    ret_user_zonefile = {'zonefile': user_zonefile}

    if include_name_record:
        # put it back
        ret_user_zonefile['name_record'] = name_record

    return ret_user_profile, ret_user_zonefile, created_new_zonefile

