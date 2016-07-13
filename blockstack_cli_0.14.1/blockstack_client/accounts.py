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

import argparse
import sys
import json
import traceback
import types
import socket
import uuid
import os
import importlib
import pprint
import random
import time
import copy
import blockstack_profiles
import urllib

import pybitcoin
import bitcoin
import binascii
from utilitybelt import is_hex

from keys import *
from proxy import *
from profile import *

from config import get_logger, DEBUG, MAX_RPC_LEN, find_missing, BLOCKSTACKD_SERVER, \
    BLOCKSTACKD_PORT, BLOCKSTACK_METADATA_DIR, BLOCKSTACK_DEFAULT_STORAGE_DRIVERS, \
    FIRST_BLOCK_MAINNET, NAME_OPCODES, OPFIELDS, CONFIG_DIR, SPV_HEADERS_PATH, BLOCKCHAIN_ID_MAGIC, \
    NAME_PREORDER, NAME_REGISTRATION, NAME_UPDATE, NAME_TRANSFER, NAMESPACE_PREORDER, NAME_IMPORT, \
    USER_ZONEFILE_TTL, CONFIG_PATH

log = get_logger()

import virtualchain


def list_accounts( name, proxy=None, wallet_keys=None ):
    """
    List all of the accounts in a user's profile
    Each account will have at least the following:
        service:  the type of service
        identifier:  a type-specific ID
        role:  a type-specific role

    Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy()

    user_profile, user_zonefile = get_name_profile( name, proxy=proxy, wallet_keys=wallet_keys )
    if user_profile is None:
        # user_zonefile will contain an error message
        return user_zonefile
        
    # user_profile will be in the new zonefile format 
    if not user_profile.has_key("account"):
        return {'accounts': []}

    else:
        return {'accounts': user_profile['account']}


def get_account( name, service, identifier, proxy=None, wallet_keys=None ):
    """
    Get an account by identifier.  Return duplicates
    Return {'account': account information} on success
    Return {'error': ...} on error
    """
    if proxy is None:
        proxy = get_default_proxy()

    accounts = list_accounts( name, proxy=proxy, wallet_keys=wallet_keys )
    if 'error' in accounts:
        return accounts

    ret = []
    for acc in accounts['accounts']:
        if acc['identifier'] == identifier and acc['service'] == service:
            ret.append(acc)

    return {'account': ret}


def put_account( name, service, identifier, content_url, proxy=None, wallet_keys=None, txid=None, required_drivers=None, **extra_fields ):
    """
    Put an account's information into a profile.
    NOTE: the account must already be in the latest form.

    Return a dict with {'status': True} on success (optionally also with 'transaction_hash' set if we updated the zonefile)
    Return a dict with {'error': ...} set on failure.
    """

    if proxy is None:
        proxy = get_default_proxy()

    need_update = False

    user_profile, user_zonefile, need_update = get_and_migrate_profile( name, proxy=proxy, create_if_absent=True, wallet_keys=wallet_keys, include_name_record=True )
    if 'error' in user_profile:
        return user_profile

    if need_update:
        return {'error': 'Profile is in legacy format.  Please migrate it with the `migrate` command.'}

    name_record = user_zonefile['name_record']
    del user_zonefile['name_record']

    # user_profile will be in the new zonefile format 
    if not user_profile.has_key("account"):
        user_profile['account'] = []

    new_profile = {}
    new_profile.update( extra_fields )
    new_profile.update( {
        "service": service,
        "identifier": identifier,
        "contentUrl": content_url
    })

    user_profile['account'].append(new_profile)

    return profile_update( name, user_zonefile, user_profile, name_record['address'], proxy=proxy, wallet_keys=wallet_keys, required_drivers=required_drivers )


def delete_account( name, service, identifier, proxy=None, wallet_keys=None ):
    """
    Remove an account's information.
    Return {'status': True, 'removed': [list of removed accounts], ...} on success
    Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy()

    need_update = False 
    removed = False

    user_profile, user_zonefile, need_update = get_and_migrate_profile( name, proxy=proxy, create_if_absent=True, wallet_keys=wallet_keys, include_name_record=True )
    if 'error' in user_profile:
        return user_profile 

    if need_update:
        return {'error': 'Profile is in legacy format.  Please migrate it with the `migrate` command.'}

    name_record = user_zonefile['name_record']
    del user_zonefile['name_record']

    # user_profile will be in the new zonefile format
    removed = []
    for account in user_profile.get('account', []):
        if account['service'] == service and account['identifier'] == identifier:
            user_profile['account'].remove( account )
            removed.append( account )

    if len(removed) == 0:
        return {'status': True, 'removed': []}

    else:
        res = profile_update( name, user_zonefile, user_profile, name_record['address'], proxy=proxy, wallet_keys=wallet_keys )
        if 'error' in res:
            return res 

        else:
            res['removed'] = removed
            return res

