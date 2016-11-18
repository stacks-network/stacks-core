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

from .keys import *
from .proxy import *
from .profile import *

log = get_logger()


def get_profile_accounts(profile, service, identifier):
    """
    List all accounts in a profile with the given service ID and account ID (identifier).
    """
    accounts = profile.get('account', [])

    return [
        acc for acc in accounts if
        service == acc.get('service', None) and
        identifer == acc.get('identifier', None)
    ]


def list_accounts(name, proxy=None):
    """
    List all of the accounts in a user's profile
    Each account will have at least the following:
        service:  the type of service
        identifier:  a type-specific ID
        role:  a type-specific role

    Return {'error': ...} on error
    """

    proxy = get_default_proxy() if proxy is None else proxy

    user_profile, user_zonefile = get_name_profile(name, proxy=proxy)
    if user_profile is None:
        # user_zonefile will contain an error message
        return user_zonefile

    # user_profile will be in the new zonefile format
    return {'accounts': user_profile.get('account', [])}


def get_account(name, service, identifier, proxy=None):
    """
    Get an account by identifier.  Return duplicates
    Return {'account': account information} on success
    Return {'error': ...} on error
    """
    proxy = get_default_proxy() if proxy is None else proxy

    accounts = list_accounts(name, proxy=proxy)
    if 'error' in accounts:
        return accounts

    ret = [
        acc for acc in accounts['accounts'] if
        service == acc.get('service', None) and
        identifier == acc.get('identifier', None)
    ]

    return {'account': ret}


def put_account(name, service, identifier, content_url, create=True, replace=False,
                proxy=None, wallet_keys=None, txid=None, required_drivers=None, **extra_fields):
    """
    Put an account's information into a profile.

    If @create is True and @replace is False, then this method appends a new account with @service and @identifier (even if one already exists)
    If @create is True and @replace is True, then this method creates an account and replaces one that has the same @service and @identifier.
        If there are no accounts to replace, then a new account is created.
    If @create is False and @replace is True, then this method replaces an existing account with the same @service and @identifier.
        If there are no such accounts, then this method fails.

    NOTE: the account must already be in the latest form.

    Return a dict with {'status': True} on success (optionally also with 'transaction_hash' set if we updated the zonefile)
    Return a dict with {'error': ...} set on failure.
    """

    if not create and not replace:
        return {'error': 'Invalid create/replace arguments'}

    proxy = get_default_proxy() if proxy is None else proxy

    need_update = False

    user_profile, user_zonefile, need_update = get_and_migrate_profile(
        name, proxy=proxy, create_if_absent=True,
        wallet_keys=wallet_keys, include_name_record=True
    )

    if 'error' in user_profile:
        return user_profile

    if need_update:
        return {'error': 'Profile is in legacy format. Please migrate it with the `migrate` command.'}

    name_record = user_zonefile.pop('name_record')

    user_zonefile, user_profile = user_zonefile['zonefile'], user_profile['profile']

    # user_profile will be in the new zonefile format
    user_profile.setdefault('account', [])

    new_account = {}
    new_account.update(extra_fields)
    new_account.update({
        'service': service,
        'identifier': identifier,
        'contentUrl': content_url
    })

    replaced = False
    if replace:
        # replace one instance of this account
        for i in range(len(user_profile['account'])):
            acc = user_profile['account'][i]
            if identifier == acc['identifier'] and service == acc['service']:
                user_profile['account'][i] = new_account
                replaced = True
                break

    if not replaced:
        if create:
            user_profile['account'].append(new_account)
        else:
            return {'error': 'No such existing account'}

    return profile_update(
        name, user_zonefile, user_profile, name_record['address'],
        proxy=proxy, wallet_keys=wallet_keys, required_drivers=required_drivers
    )


def delete_account(name, service, identifier, proxy=None, wallet_keys=None):
    """
    Remove an account's information.
    Return {'status': True, 'removed': [list of removed accounts], ...} on success
    Return {'error': ...} on error
    """

    proxy = get_default_proxy() if proxy is None else proxy

    need_update, removed = False, False

    user_profile, user_zonefile, need_update = get_and_migrate_profile(
        name, proxy=proxy, create_if_absent=True,
        wallet_keys=wallet_keys, include_name_record=True
    )

    if 'error' in user_profile:
        return user_profile

    if need_update:
        return {
            'error': (
                'Profile is in legacy format. '
                'Please migrate it using with the `migrate` command.'
            )
        }

    name_record = user_zonefile.pop('name_record')

    user_zonefile, user_profile = user_zonefile['zonefile'], user_profile['profile']

    # user_profile will be in the new zonefile format
    removed = []
    for account in user_profile.get('account', []):
        if service == account['service'] and identifier == account['identifier']:
            user_profile['account'].remove(account)
            removed.append(account)

    if not removed:
        return {'status': True, 'removed': []}

    res = profile_update(
        name, user_zonefile,
        user_profile, name_record['address'],
        proxy=proxy, wallet_keys=wallet_keys
    )

    if 'error' in res:
        return res

    res['removed'] = removed
    return res


