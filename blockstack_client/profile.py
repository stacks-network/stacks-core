#!/usr/bin/env python2
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
import httplib
import virtualchain
import jsonschema
import virtualchain
from virtualchain.lib.ecdsalib import get_pubkey_hex
import keylib

from .proxy import (
    json_is_error, get_name_blockchain_history, get_name_blockchain_record,
    get_default_proxy)

from blockstack_client import storage, subdomains
from blockstack_client import user as user_db

from .logger import get_logger
from .constants import USER_ZONEFILE_TTL, CONFIG_PATH, BLOCKSTACK_TEST, BLOCKSTACK_DEBUG

from .zonefile import get_name_zonefile
from .keys import get_data_privkey_info
from .schemas import PROFILE_ACCOUNT_SCHEMA
from .config import get_config
from .constants import BLOCKSTACK_REQUIRED_STORAGE_DRIVERS_WRITE

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

    if user_data_privkey is given, then wallet_keys does not need to be given.

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
        name, profile_payload, data_privkey=user_data_privkey,
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

    Returns {'status': True, 'profile': profile, 'zonefile': zonefile, 'public_key': ...} on success.
    * If include_name_record is True, then include 'name_record': name_record with the user's blockchain information
    * If include_raw_zonefile is True, then include 'raw_zonefile': raw_zonefile with unparsed zone file

    Returns {'error': ...} on error
    """

    proxy = get_default_proxy() if proxy is None else proxy
    user_profile_pubkey = None

    res = subdomains.is_address_subdomain(str(name))
    if res:
        subdomain, domain = res[1]
        try:
            return subdomains.resolve_subdomain(subdomain, domain)
        except subdomains.SubdomainNotFound as e:
            log.exception(e)
            return {'error' : "Failed to find name {}.{}".format(subdomain, domain)}

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
            return user_zonefile

        raw_zonefile = None
        if include_raw_zonefile:
            raw_zonefile = user_zonefile.pop('raw_zonefile')

        user_zonefile = user_zonefile['zonefile']

    # is this really a legacy profile?
    if blockstack_profiles.is_profile_in_legacy_format(user_zonefile):
        if not use_legacy:
            return {'error': 'Profile is in legacy format'}

        # convert it
        log.debug('Converting legacy profile to modern profile')
        user_profile = blockstack_profiles.get_person_from_legacy_format(user_zonefile)

    elif not user_db.is_user_zonefile(user_zonefile):
        if not use_legacy:
            return {'error': 'Name zonefile is non-standard'}

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
                data_address = keylib.ECPublicKey(user_data_pubkey).address()

        except ValueError:
            # multiple keys defined; we don't know which one to use
            user_data_pubkey = None

        if not use_legacy_zonefile and user_data_pubkey is None:
            # legacy zonefile without a data public key 
            return {'error': 'Name zonefile is missing a public key'}

        # find owner address
        if name_record is None:
            name_record = get_name_blockchain_record(name, proxy=proxy)
            if name_record is None or 'error' in name_record:
                log.error('Failed to look up name record for "{}"'.format(name))
                return {'error': 'Failed to look up name record'}

        assert 'address' in name_record.keys(), json.dumps(name_record, indent=4, sort_keys=True)
        owner_address = name_record['address']

        # get user's data public key from the zonefile
        urls = None
        if use_zonefile_urls and user_zonefile is not None:
            urls = user_db.user_zonefile_urls(user_zonefile)

        user_profile = None
        user_profile_pubkey = None

        try:
            user_profile_res = storage.get_mutable_data(
                name, user_data_pubkey, blockchain_id=name,
                data_address=data_address, owner_address=owner_address,
                urls=urls, drivers=profile_storage_drivers, decode=decode_profile,
                return_public_key=True
            )
           
            if user_profile_res is None:
                log.error("Failed to get profile for {}".format(name))
                return {'error': 'Failed in parsing and fetching profile for {}'.format(name)}

            user_profile = user_profile_res['data']
            user_profile_pubkey = user_profile_res['public_key']

        except Exception as e:
            log.exception(e)
            return {'error' : 'Failure in parsing and fetching profile for {}'.format(name)}

        if user_profile is None or json_is_error(user_profile):
            if user_profile is None:
                log.error('no user profile for {}'.format(name))
            else:
                log.error('failed to load profile for {}: {}'.format(name, user_profile['error']))

            return {'error': 'Failed to load user profile'}

    # finally, if the caller asked for the name record, and we didn't get a chance to look it up,
    # then go get it.
    ret = {
        'status': True,
        'profile': user_profile,
        'zonefile': user_zonefile,
        'public_key': user_profile_pubkey
    }

    if include_name_record:
        if name_record is None:
            name_record = get_name_blockchain_record(name, proxy=proxy)

        if name_record is None or 'error' in name_record:
            log.error('Failed to look up name record for "{}"'.format(name))
            return {'error': 'Failed to look up name record'}

        ret['name_record'] = name_record

    if include_raw_zonefile:
        if raw_zonefile is not None:
            ret['raw_zonefile'] = raw_zonefile

    return ret


def _get_person_profile(name, proxy=None):
    """
    Get the person's zonefile and profile.
    Handle legacy zonefiles, but not legacy profiles.
    Return {'profile': ..., 'zonefile': ..., 'person': ...} on success
    Return {'error': ...} on error
    """

    res = get_profile(name, proxy=proxy, use_legacy_zonefile=True)
    if 'error' in res:
        return {'error': 'Failed to load zonefile: {}'.format(res['error'])}

    profile = res.pop('profile')
    zonefile = res.pop('zonefile')

    if blockstack_profiles.is_profile_in_legacy_format(profile):
        return {'error': 'Legacy profile'}

    person = None
    try:
        person = blockstack_profiles.Person(profile)
    except Exception as e:
        log.exception(e)
        return {'error': 'Failed to parse profile data into a Person record'}
    
    return {'profile': profile, 'zonefile': zonefile, 'person': person}


def _save_person_profile(name, zonefile, profile, wallet_keys, user_data_privkey=None, blockchain_id=None, proxy=None, config_path=CONFIG_PATH):
    """
    Save a person's profile, given information fetched with _get_person_profile.
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    conf = get_config(config_path)
    assert conf

    required_storage_drivers = conf.get(
        'storage_drivers_required_write',
        BLOCKSTACK_REQUIRED_STORAGE_DRIVERS_WRITE
    )
    required_storage_drivers = required_storage_drivers.split()

    res = put_profile(name, profile, user_zonefile=zonefile,
                       wallet_keys=wallet_keys, user_data_privkey=user_data_privkey, proxy=proxy,
                       required_drivers=required_storage_drivers, blockchain_id=name,
                       config_path=config_path )

    return res


def profile_list_accounts(name, proxy=None):
    """
    Get the list of accounts in a name's Person-formatted profile.
    Return {'accounts': ...} on success
    Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy()

    name_info = _get_person_profile(name, proxy=proxy)
    if 'error' in name_info:
        return name_info

    profile = name_info.pop('profile')
    zonefile = name_info.pop('zonefile')
    person = name_info.pop('person')

    accounts = []
    if hasattr(person, 'account'):
        accounts = person.account

    output_accounts = []
    for acct in accounts:
        try:
            jsonschema.validate(acct, PROFILE_ACCOUNT_SCHEMA)
            output_accounts.append(acct)
        except jsonschema.ValidationError as e:
            log.exception(e)
            continue

    return {'accounts': output_accounts}


def profile_get_account(blockchain_id, service, identifier, config_path=CONFIG_PATH, proxy=None):
    """
    Get an account.  The first hit is returned.
    Return {'status': True, 'account': ...} on success
    Return {'error': ...} on error
    """

    account_info = profile_list_accounts(blockchain_id, proxy=proxy )
    if 'error' in account_info:
        return account_info

    accounts = account_info['accounts']
    for account in accounts:
        if account['service'] == service and account['identifier'] == identifier:
            return {'status': True, 'account': account}

    return {'error': 'No such account'}


def profile_find_accounts(cur_profile, service, identifier):
    """
    Given an profile, find accounts that match the service and identifier
    Returns a list of accounts on success
    """
    accounts = [] 
    for acct in cur_profile.get('account', []):
        try:
            jsonschema.validate(acct, PROFILE_ACCOUNT_SCHEMA)
            if acct['service'] == service and acct['identifier'] == identifier:
                accounts.append(acct)

        except jsonschema.ValidationError:
            continue

    return accounts


def profile_patch_account(cur_profile, service, identifier, content_url, extra_data):
    """
    Patch a given profile to add an account
    Return the new profile
    """
    profile = copy.deepcopy(cur_profile)

    # make data
    new_account = {
        'service': service,
        'identifier': identifier,
    }

    if content_url:
        new_account['contentUrl'] = content_url

    if extra_data:
        new_account.update(extra_data)

    if not profile.has_key('account'):
        profile['account'] = []

    # overwrite existing, if given 
    replaced = False
    for i in xrange(0, len(profile['account'])):

        account = profile['account'][i]

        try:
            jsonschema.validate(account, PROFILE_ACCOUNT_SCHEMA)
        except jsonschema.ValidationError:
            continue

        if account['service'] == service and account['identifier'] == identifier:
            profile['account'][i] = new_account
            replaced = True
            break

    if not replaced:
        profile['account'].append(new_account)

    return profile


def profile_put_account(blockchain_id, service, identifier, content_url, extra_data, wallet_keys, user_data_privkey=None, config_path=CONFIG_PATH, proxy=None):
    """
    Save a new account to a profile.
    Return {'status': True, 'replaced': True/False} on success
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy()

    person_info = _get_person_profile(blockchain_id, proxy=proxy)
    if 'error' in person_info:
        return person_info

    zonefile = person_info.pop('zonefile')
    profile = person_info.pop('profile')
    profile = profile_patch_account(profile, service, identifier, content_url, extra_data)

    # save
    result = _save_person_profile(blockchain_id, zonefile, profile, wallet_keys, user_data_privkey=user_data_privkey, blockchain_id=blockchain_id, proxy=proxy, config_path=config_path)
    if 'error' in result:
        return result

    return {'status': True}


def profile_delete_account(blockchain_id, service, identifier, wallet_keys, user_data_privkey=None, config_path=CONFIG_PATH, proxy=None):
    """
    Delete an account, given the blockchain ID, service, and identifier
    Return {'status': True} on success
    Return {'error': ...} on error
    """

    person_info = _get_person_profile(blockchain_id, proxy=proxy)
    if 'error' in person_info:
        return person_info

    zonefile = person_info['zonefile']
    profile = person_info['profile']
    if not profile.has_key('account'):
        # nothing to do
        return {'error': 'No such account'}

    found = False
    for i in xrange(0, len(profile['account'])):
        account = profile['account'][i]

        try:
            jsonschema.validate(account, PROFILE_ACCOUNT_SCHEMA)
        except jsonschema.ValidationError:
            continue

        if account['service'] == service and account['identifier'] == identifier:
            profile['account'].pop(i)
            found = True
            break

    if not found:
        return {'error': 'No such account'}

    result = _save_person_profile(blockchain_id, zonefile, profile, wallet_keys, user_data_privkey=user_data_privkey, blockchain_id=blockchain_id, proxy=proxy, config_path=config_path)
    if 'error' in result:
        return result

    return {'status': True}


def profile_list_device_ids( blockchain_id, proxy=None ):
    """
    Given a blockchain ID, identify the set of device IDs for it.

    Returns {'status': True, 'device_ids': ...} on success
    Returns {'error': ...} on error
    """
    raise NotImplementedError("Token file logic is not implemented yet")


def profile_add_device_id( blockchain_id, device_id, wallet_keys, config_path=CONFIG_PATH, proxy=None):
    """
    Add a device ID to a profile
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    raise NotImplementedError("Token file logic is not implemented yet")
    

def profile_remove_device_id( blockchain_id, device_id, wallet_keys, config_path=CONFIG_PATH, proxy=None):
    """
    Remove a device ID from a profile
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    raise NotImplementedError("Token file logic is not implemented yet")


