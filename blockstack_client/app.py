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
import re
import hashlib
import posixpath
import jsonschema
from jsonschema.exceptions import ValidationError
import time

from keylib import *

import jsontokens
import urllib
import urllib2
import wallet
import config
import storage
import data
import user as user_db
from .proxy import *

from config import get_config
from .constants import CONFIG_PATH, BLOCKSTACK_TEST, LENGTH_MAX_NAME, ACCOUNT_SIGNING_KEY_INDEX
from .schemas import *
from keys import HDWallet, get_pubkey_hex


def app_make_session( app_domain, methods, master_data_privkey_hex, app_user_id=None, app_user_privkey=None, session_lifetime=None, blockchain_ids=None, config_path=CONFIG_PATH ):
    """
    Make a session JWT for this application.
    Verify with user private key
    Sign with master private key
    Return {'session': session jwt, 'session_token': session token} on success
    Return {'error': ...} on error
    """
    if session_lifetime is None:
        conf = get_config(path=config_path)
        assert conf
        session_lifetime = conf.get('default_session_lifetime', 1e80)

    if app_user_id is None:
        if app_user_privkey is None:
            if master_data_privkey_hex is not None:
                assert app_domain is not None, "need app domain to derive app key"
                app_user_privkey = data.datastore_get_privkey(master_data_privkey_hex, app_domain, config_path=config_path)

            else:
                # TODO: load from disk
                raise NotImplemented("Local app user private keys are not supported at this time")

        app_user_pubkey = get_pubkey_hex(app_user_privkey)
        app_user_id = data.datastore_get_id(app_user_pubkey)

    ses = {
        'app_domain': app_domain,
        'methods': methods,
        'app_user_id': app_user_id,
        'timestamp': int(time.time()),
        'expires': int(time.time() + session_lifetime),
    }

    if blockchain_ids is not None:
        ses['blockchain_ids'] = blockchain_ids

    jsonschema.validate(ses, APP_SESSION_SCHEMA)

    signer = jsontokens.TokenSigner()
    session_token = signer.sign( ses, master_data_privkey_hex )
    session = jsontokens.decode_token(session_token)

    return {'session': session, 'session_token': session_token}


def app_verify_session( app_session_token, data_pubkey_hex, config_path=CONFIG_PATH ):
    """
    Verify and decode a JWT app session token.
    The session is valid if the signature matches and the token is not expired.
    Return the decoded session token payload on success
    Return None on error
    """
    pubkey = str(data_pubkey_hex)
    verifier = jsontokens.TokenVerifier()
    valid = verifier.verify( app_session_token, pubkey )
    if not valid:
        log.debug("Failed to verify with {}".format(pubkey))
        return None

    session_jwt = jsontokens.decode_token(app_session_token)
    session = session_jwt['payload']

    # must match session structure 
    try:
        jsonschema.validate(session, APP_SESSION_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_TEST:
            log.exception(ve)

        return None

    # session must not be expired
    if session['expires'] < time.time():
        log.debug("Token is expired")
        return None

    return session


def app_publish( dev_blockchain_id, app_domain, app_method_list, app_index_uris, app_index_file, app_driver_hints=[], data_privkey=None, proxy=None, wallet_keys=None, config_path=CONFIG_PATH ):
    """
    Instantiate an application.
    * replicate the (opaque) app index file to "index.html" to each URL in app_uris
    * replicate the list of URIs and the list of methods to ".blockstack" via each of the client's storage drivers.

    This succeeds even if the app already exists (in which case,
    it will be overwritten).  This method is idempotent, so it
    can be retried on failure.

    data_privkey should be the publisher's private key (i.e. their data key)
    name should be the blockchain ID that points to data_pubkey
   
    Return {'status': True, 'config_fq_data_id': config's fully-qualified data ID, 'index_fq_data_id': index file's fully-qualified data ID} on success
    Return {'error': ...} on error
    """

    proxy = get_default_proxy() if proxy is None else proxy

    # replicate configuration data (method list and app URIs)
    app_cfg = {
        'blockchain_id': dev_blockchain_id,
        'app_domain': app_domain,
        'index_uris': app_index_uris,
        'api_methods': app_method_list,
        'driver_hints': app_driver_hints,
    }

    jsonschema.validate(app_cfg, APP_CONFIG_SCHEMA)

    config_data_id = '{}/.blockstack'.format(app_domain)
    res = data.put_mutable(config_data_id, app_cfg, blockchain_id=dev_blockchain_id, data_privkey=data_privkey, wallet_keys=wallet_keys, config_path=config_path, fully_qualified_data_id=True)
    if 'error' in res:
        log.error('Failed to replicate application configuration {}: {}'.format(config_data_id, res['error']))
        return {'error': 'Failed to replicate application config'}

    # what drivers to use for the index file?
    urls = user_db.urls_from_uris(app_index_uris)
    driver_names = []

    for url in urls:
        drivers = storage.get_drivers_for_url(url)
        driver_names += [d.__name__ for d in drivers]

    driver_names = list(set(driver_names))
    index_data_id = "{}/index.html".format(app_domain)
    
    # replicate app index file (at least one must succeed)
    # NOTE: the publisher is free to use alternative URIs that are not supported; they'll just be ignored.
    res = data.put_mutable( index_data_id, app_index_file, blockchain_id=dev_blockchain_id, data_privkey=data_privkey, storage_drivers=driver_names, wallet_keys=wallet_keys, config_path=config_path, fully_qualified_data_id=True)
    if 'error' in res:
        log.error("Failed to replicate application index file to {}: {}".format(",".join(urls), res['error']))
        return {'error': 'Failed to replicate index file'}

    return {'status': True, 'config_fq_data_id': config_data_id, 'index_fq_data_id': index_data_id}


def app_get_config( blockchain_id, app_domain, data_pubkey=None, proxy=None, config_path=CONFIG_PATH ):
    """
    Get application configuration bundle.
    
    data_pubkey should be the publisher's public key.

    Return {'status': True, 'config': config} on success
    Return {'error': ...} on error
    """

    proxy = get_default_proxy() if proxy is None else proxy

    # go get config 
    config_data_id = '{}/.blockstack'.format(app_domain)
    res = data.get_mutable( config_data_id, data_pubkey=data_pubkey, proxy=proxy, config_path=config_path, blockchain_id=blockchain_id, fully_qualified_data_id=True )
    if 'error' in res:
        log.error("Failed to get application config file {}: {}".format(config_data_id, res['error']))
        return res

    app_cfg = None
    try:
        app_cfg = res['data']
        jsonschema.validate(app_cfg, APP_CONFIG_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_TEST:
            log.exception(ve)

        log.error("Invalid application config file {}".format(config_data_id))
        return {'error': 'Invalid application config'}

    return {'status': True, 'config': app_cfg}


def app_get_resource( blockchain_id, app_domain, res_name, app_config=None, data_pubkey=None, proxy=None, config_path=CONFIG_PATH ):
    """
    Get a named application resource from mutable storage

    data_pubkey should be the publisher's public key 

    If app_config is not None, then the driver hints will be honored.
    
    Return {'status': True, 'res': resource} on success
    Return {'error': ...} on error
    """

    proxy = get_default_proxy() if proxy is None else proxy

    res_data_id = '{}/{}'.format(app_domain, res_name)

    urls = None
    if app_config is not None:
        # use driver hints
        driver_hints = app_config['driver_hints']
        urls = storage.get_driver_urls( res_data_id, storage.get_storage_handlers() )

    res = data.get_mutable( res_data_id, data_pubkey=data_pubkey, proxy=proxy, config_path=config_path, urls=urls, blockchain_id=blockchain_id, fully_qualified_data_id=True )
    if 'error' in res:
        log.error("Failed to get resource {}: {}".format(res_data_id, res['error']))
        return {'error': 'Failed to load resource'}

    return {'status': True, 'res': res['data']}
   

def app_put_resource( blockchain_id, app_domain, res_name, res_data, app_config=None, data_privkey=None, proxy=None, wallet_keys=None, config_path=CONFIG_PATH ):
    """
    Store data to a named application resource in mutable storage.

    data_privkey should be the publisher's private key
    name should be a blockchain ID that points to the public key

    if app_config is not None, then the driver hints will be honored.

    Return {'status': True, 'version': ...} on success
    Return {'error': ...} on error
    """

    proxy = get_default_proxy() if proxy is None else proxy

    res_data_id = '{}/{}'.format(app_domain, res_name)

    driver_hints = None
    if app_config is not None:
        # use driver hints
        driver_hints = app_config['driver_hints']

    res = data.put_mutable(res_data_id, res_data, blockchain_id=blockchain_id, data_privkey=data_privkey, proxy=proxy, storage_drivers=driver_hints, wallet_keys=wallet_keys, config_path=config_path, fully_qualified_data_id=True)
    if 'error' in res:
        log.error("Failed to store resource {}: {}".format(res_data_id, res['error']))
        return {'error': 'Failed to store resource'}

    return {'status': True, 'version': res['version']}


def app_delete_resource( blockchain_id, app_domain, res_name, app_config=None, data_privkey=None, proxy=None, wallet_keys=None, config_path=CONFIG_PATH ):
    """
    Remove data from a named application resource in mutable storage.

    data_privkey should be the publisher's private key
    name should be a blockchain ID that points to the public key

    if app_config is not None, then the driver hints will be honored.

    Return {'status': True, 'version': ...} on success
    Return {'error': ...} on error
    """

    proxy = get_default_proxy() if proxy is None else proxy

    res_data_id = '{}/{}'.format(app_domain, res_name)

    driver_hints = None
    if app_config is not None:
        # use driver hints
        driver_hints = app_config['driver_hints']

    res = data.delete_mutable(res_data_id, blockchain_id=blockchain_id, data_privkey=data_privkey, proxy=proxy, storage_drivers=driver_hints, wallet_keys=wallet_keys, config_path=config_path, fully_qualified_data_id=True)
    if 'error' in res:
        log.error("Failed to delete resource {}: {}".format(res_data_id, res['error']))
        return {'error': 'Failed to delete resource'}

    return {'status': True}


def app_unpublish( blockchain_id, app_domain, force=False, data_privkey=None, app_config=None, wallet_keys=None, proxy=None, config_path=CONFIG_PATH ):
    """
    Unpublish an application
    Deletes its config and index.
    Does NOT delete its resources.
    Does NOT delete user data.

    if force is True, then we will try to delete the app state even if we can't load the app config
    WARNING: force can be dangerous, since it can delete data via drivers that were never meant for this app.  Use with caution!

    Return {'status': True, 'app_config': ..., 'retry': ...} on success.  If retry is True, then retry this method with the given app_config
    Return {'error': ...} on error
    """

    proxy = get_default_proxy() if proxy is None else proxy

    if app_config is None:
        # find out where to delete from
        data_pubkey = None
        if data_privkey is not None:
            data_pubkey = get_pubkey_hex(str(data_privkey))

        app_config = app_get_config(blockchain_id, app_domain, data_pubkey=data_pubkey, proxy=proxy, config_path=CONFIG_PATH )
        if 'error' in app_config:
            if not force:
                log.error("Failed to load app config for {}'s {}".format(blockchain_id, app_domain))
                return {'error': 'Failed to load app config'}
            else:
                # keep going 
                app_config = None
                log.warning("Failed to load app config, but proceeding at caller request")

    config_data_id = '{}/.blockstack'.format(app_domain)
    index_data_id = "{}/index.html".format(app_domain)

    storage_drivers = None
    if app_config is not None:
        # only use the ones we have to 
        urls = user_db.urls_from_uris(app_config['index_uris'])
        driver_names = []

        for url in urls:
            drivers = storage.get_drivers_for_url(url)
            driver_names += [d.__name__ for d in drivers]

        storage_drivers = list(set(driver_names))
    
    ret = {}

    # delete the index
    res = data.delete_mutable( config_data_id, data_privkey=data_privkey, proxy=proxy, wallet_keys=wallet_keys, delete_version=False, storage_drivers=storage_drivers )
    if 'error' in res:
        log.warning("Failed to delete index file {}".format(index_data_id))
        ret['app_config'] = app_config
        ret['retry'] = True

    # delete the config 
    res = data.delete_mutable( index_data_id, data_privkey=data_privkey, proxy=proxy, wallet_keys=wallet_keys, delete_version=False )
    if 'error' in res:
        log.warning("Failed to delete config file {}".format(config_data_id))
        if not ret.has_key('app_config'):
            ret['app_config'] = app_config

        ret['retry'] = True

    ret['status'] = True
    return ret


