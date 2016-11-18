#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

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
import os
import keylib

import wallet
import accounts
import config
from .proxy import *

from .constants import CONFIG_PATH, APP_WALLET_DIRNAME, BLOCKSTACK_TEST
from .schemas import *

import jsonschema
from jsonschema import ValidationError

def app_wallet_path(config_dir, name, app_name, app_account_id):
    """
    Get the path to an app wallet
    """
    app_wallet_dir = os.path.join(config_dir, APP_WALLET_DIRNAME)
    wallet_name = '{}.{}@{}.json'.format(app_account_id, app_name, name)
    wallet_path = os.path.join(app_wallet_dir, wallet_name)

    return wallet_path


def create_app_account(app_name, storage_drivers, app_data_pubkey,
                       proxy=None, wallet_keys=None, **extra_fields):
    """
    Make a Blockstck application account.
    This account is different than one created by `put_account`, since
    it is constructed specifically for Blockstack applications.
    It has a few other goodies in it.

    Return {'status': True} on success
    Return {'error': ...} on failure

    Raise on invalid input
    """

    if storage_drivers is None or not storage_drivers:
        raise ValueError('No storage drivers given')

    return put_account(
        name, service, identifier, app_url, create=True, replace=False,
        proxy=proxy, wallet_keys=wallet_keys, data_pubkey=data_pubkey,
        storage_drivers=storage_drivers, **extra_fields
    )


def delete_app_account(name, service, identifier, wallet_keys=None, proxy=None):
    """
    Delete an application-specific account

    Return {'status': True} on success
    Return {'error': ...} on failure
    """

    res = delete_account(name, service, identifier, proxy=proxy, wallet_keys=wallet_keys)

    return res if 'error' in res else {'status': True}


def app_register(name, app_name, app_account_id, app_url, app_storage_drivers=None, app_account_fields={},
                 wallet_keys=None, password=None, interactive=False, config_path=CONFIG_PATH, proxy=None):
    """
    Add new application-specific state to a profile.
    * add an account for the application
    * create a keypair for the application
    * store an app-specific wallet

    If no password is given and interative is set, then prompt for a password.

    Return {'status': True} on success
    Return {'error': ...} on error
    """

    if not interactive and password is None:
        raise ValueError('Non-interactive use requires a password')

    config_dir = os.path.dirname(config_path)
    app_wallet_dir = os.path.join(config_dir, APP_WALLET_DIRNAME)
    if not os.path.exists(app_wallet_dir):
        try:
            os.makedirs(app_wallet_dir, 0700)
        except Exception as e:
            log.exception(e)
            return {'error': 'Failed to create app wallet directory'}

    # create the wallet
    wallet_path = app_wallet_path(config_dir, name, app_name, app_account_id)
    if os.path.exists(wallet_path):
        return {'error': 'Wallet already exists ({})'.format(wallet_path)}

    if password is None and interactive:
        prompt = 'Creating new application wallet'
        password = ''
        while len(password) < config.WALLET_PASSWORD_LENGTH:
            res = wallet.make_wallet_password(prompt=prompt, password=password)
            if 'error' not in res:
                password = res['password']
                break
            print(res['error'])

    pk_hex = keylib.ECPrivateKey().to_hex()
    res = wallet.initialize_wallet(
        password=password, interactive=interactive,
        hex_privkey=pk_hex, config_dir=config_dir, wallet_path=wallet_path
    )
    if 'error' in res:
        msg = 'Failed to create wallet "{}.{}@{}": {}'
        log.error(msg.format(app_account_id, app_name, name, res['error']))
        return res

    pub_hex = keylib.ECPrivateKey(pk_hex).public_key().to_hex()

    # preferred storage drivers?
    conf = config.get_config(config_path)
    app_storage_drivers = app_storage_drivers or conf['storage_drivers']
    proxy = proxy or get_default_proxy(config_path=config_path)

    # create an app account
    res = accounts.create_app_account(
        name, app_name, app_account_id, app_url,
        app_storage_drivers, pub_hex, proxy=proxy,
        wallet_keys=wallet_keys, **app_account_fields
    )
    if 'error' in res:
        msg = 'Failed to create app account "{}.{}@{}": {}'
        log.error(msg.format(app_account_id, app_name, name, res['error']))
        return res

    return {'status': True}


def app_unregister(name, app_name, app_account_id, interactive=False, wallet_keys=None, proxy=None, config_path=CONFIG_PATH):
    """
    Unregister an application account:
    * delete the account from the profile
    * delete the wallet

    Return {'status': True} on success
    Return {'error': ...} on errur
    """

    proxy = proxy or get_default_proxy(config_path=config_path)

    if interactive:
        print('WARNING: This cannot be undone!')
        response = ''
        while response not in ['YES', 'no']:
            response = raw_input('Are you sure? (YES/no): ')
            if response not in ['y', 'yes']:
                print('Not deleting')
                response = 'no'
                continue

            print('Please type YES')
            response = ''

        if response == 'no':
            return {'error': 'User declined'}

    # delete the account
    res = accounts.delete_app_account(
        name, app_name, app_account_id, wallet_keys=wallet_keys, proxy=proxy
    )
    if 'error' in res:
        msg = 'Failed to delete app account "{}.{}@{}": {}'
        log.error(msg.format(app_account_id, app_name, name, res['error']))
        return {'error': 'Failed to delete app account'}

    # delete the wallet
    config_dir = os.path.dirname(config_path)
    wallet_path = app_wallet_path(config_dir, name, app_name, app_account_id)
    if os.path.exists(wallet_path):
        try:
            os.unlink(wallet_path)
        except:
            return {'error': 'Failed to delete wallet at "{}"'.format(wallet_path)}

    return {'status': True}


def app_get_wallet(name, app_name, app_account_id, interactive=False, password=None, config_path=CONFIG_PATH):
    """
    Unlock and return a decrypted application wallet.
    Return {'status': True, 'wallet': ...} on success
    Return {'error': ...} on failure
    Raise on invalid input
    """

    config_dir = os.path.dirname(config_path)
    wallet_path = app_wallet_path(config_dir, name, app_name, app_account_id)
    if not os.path.exists(wallet_path):
        log.error('No such wallet "{}"'.format(wallet_path))
        return {'error': 'No such wallet'}

    if not interactive and password is None:
        raise ValueError('Password required in non-interactive mode')

    if interactive and password is not None:
        password = raw_input('Enter password for "{}.{}@{}": '.format(app_account_id, app_name, name))

    return wallet.load_wallet(password=password, config_dir=config_dir, wallet_path=wallet_path, include_private=True)
