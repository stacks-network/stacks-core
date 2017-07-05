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
import httplib
import virtualchain
import jsonschema
import virtualchain
from virtualchain.lib.ecdsalib import *
import keylib

from .proxy import *
from blockstack_client import storage
from blockstack_client import user as user_db

from .logger import get_logger
from .constants import USER_ZONEFILE_TTL, CONFIG_PATH, BLOCKSTACK_TEST, BLOCKSTACK_DEBUG

from .token_file import token_file_parse, token_file_update_profile, token_file_get, token_file_put
from .zonefile import get_name_zonefile
from .keys import get_data_privkey_info
from .schemas import *
from .config import get_config
from .constants import BLOCKSTACK_REQUIRED_STORAGE_DRIVERS_WRITE

log = get_logger()

def get_profile(name, **kw):
    """
    Legacy compatibility method for get_token_file().
    Wraps get_token_file, and if a token file is successfully resolved, returns
    {'status': True, 
    'profile': profile, 
    'zonefile': zonefile, 
    'token_file': token_file,
    'raw_zonefile': unparsed zone file
    'token_file': actual token file (if present)
    'legacy': whether or not the profile was legacy}

    Returns {'error': ...} on error
    """
    res = token_file_get(name, **kw)
    if 'error' in res:
        return res

    token_file = res['token_file']
    zonefile = res['zonefile']

    profile = None
    legacy = False
    if res.get('legacy_profile') is not None:
        profile = res['legacy_profile']
        legacy = True
    
    else:
        profile = token_file['profile']
    
    raw_zonefile = res.get('raw_zonefile')
    name_record = res.get('name_record')
    token_file = res.get('token_file')

    ret = {
        'status': True,
        'profile': profile,
        'zonefile': zonefile,
        'raw_zonefile': raw_zonefile,
        'name_record': name_record,
        'token_file': token_file,
        'legacy': legacy
    }

    return ret


def _get_person_profile(name, proxy=None):
    """
    Get the person's profile.
    Works for raw profiles, and for profiles within token files.
    Only works if the profile is a Persona.

    Return {'profile': ..., 'person': ...} on success
    Return {'error': ...} on error
    """

    res = get_profile(name, proxy=proxy)
    if 'error' in res:
        return {'error': 'Failed to load profile: {}'.format(res['error'])}

    if res['legacy']:
        return {'error': 'Failed to load profile: legacy format'}

    profile = res.pop('profile')
    person = None
    try:
        person = blockstack_profiles.Person(profile)
    except Exception as e:
        log.exception(e)
        return {'error': 'Failed to parse profile data into a Person record'}
    
    return {'profile': profile, 'zonefile': zonefile, 'person': person}


def _save_person_profile(name, profile, signing_private_key, blockchain_id=None, proxy=None, config_path=CONFIG_PATH):
    """
    Save a person's profile, given information fetched with _get_person_profile.
    Return {'status': True} on success
    Return {'error': ...} on error
    """

    conf = get_config(config_path)
    assert conf

    required_storage_drivers = conf.get('storage_drivers_required_write', BLOCKSTACK_REQUIRED_STORAGE_DRIVERS_WRITE)
    required_storage_drivers = required_storage_drivers.split()

    res = token_file_update_profile(name, profile, signing_private_key)
    if 'error' in res:
        return res

    new_token_file = res['token_file']
    res = token_file_put(name, new_token_file, signing_private_key, proxy=proxy, required_drivers=required_storage_drivers, config_path=config_path)
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
    person = name_info.pop('person')

    accounts = []
    if hasattr(person, 'account'):
        accounts = person.account

    for acct in accounts:
        try:
            jsonschema.validate(acct, PROFILE_ACCOUNT_SCHEMA)
            accounts.append(acct)
        except jsonschema.ValidationError:
            continue

    return {'accounts': accounts}


def profile_get_account(blockchain_id, service, identifier, config_path=CONFIG_PATH, proxy=None):
    """
    Get an account.  The first hit is returned.
    Return {'status': True, 'account': ...} on success
    Return {'error': ...} on error
    """

    account_info = _list_accounts(blockchain_id, proxy=proxy )
    if 'error' in account_info:
        return account_info

    accounts = account_info['accounts']
    for account in accounts:
        if account['service'] == service and account['identifier'] == identifier:
            return {'status': True, 'account': account}

    return {'error': 'No such account', 'errno': errno.ENOENT}


def profile_find_accounts(cur_profile, service, identifer):
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


def profile_put_account(blockchain_id, service, identifier, content_url, extra_data, signing_private_key, config_path=CONFIG_PATH, proxy=None):
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

    profile = person_info.pop('profile')
    profile = profile_patch_account(profile, service, identifier, content_url, extra_data)

    # save
    result = _save_person_profile(blockchain_id, profile, signing_private_key, blockchain_id=blockchain_id, proxy=proxy, config_path=config_path)
    if 'error' in result:
        return result

    return {'status': True}


def profile_delete_account(blockchain_id, service, identifier, signing_private_key, config_path=CONFIG_PATH, proxy=None):
    """
    Delete an account, given the blockchain ID, service, and identifier
    Return {'status': True} on success
    Return {'error': ...} on error
    """

    person_info = _get_person_profile(blockchain_id, proxy=proxy)
    if 'error' in person_info:
        return person_info

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

    result = _save_person_profile(blockchain_id, profile, signing_private_key, blockchain_id=blockchain_id, proxy=proxy, config_path=config_path)
    if 'error' in result:
        return result

    return {'status': True}


def profile_list_device_ids( blockchain_id, proxy=None ):
    """
    Given a blockchain ID, identify the set of device IDs for it.

    Returns {'status': True, 'device_ids': ...} on success
    Returns {'error': ...} on error
    """
    raise NotImplemented("Token file logic is not implemented yet")


def profile_add_device_id( blockchain_id, device_id, wallet_keys, config_path=CONFIG_PATH, proxy=None):
    """
    Add a device ID to a profile
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    raise NotImplemented("Token file logic is not implemented yet")
    

def profile_remove_device_id( blockchain_id, device_id, wallet_keys, config_path=CONFIG_PATH, proxy=None):
    """
    Remove a device ID from a profile
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    raise NotImplemented("Token file logic is not implemented yet")


