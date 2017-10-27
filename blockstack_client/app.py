#!/usr/bin/env python2
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
import json
import jsonschema
from jsonschema.exceptions import ValidationError
import time

import virtualchain
from virtualchain.lib.ecdsalib import get_pubkey_hex

import re
import jsontokens
import storage
import data
import urlparse
import keylib
import user as user_db
from .proxy import get_default_proxy

from config import get_config, get_logger
from .constants import CONFIG_PATH, BLOCKSTACK_TEST, LENGTH_MAX_NAME, DEFAULT_API_PORT, DEFAULT_API_HOST
from .schemas import APP_CONFIG_SCHEMA, APP_SESSION_SCHEMA, OP_APP_NAME_PATTERN
from .storage import classify_storage_drivers

log = get_logger()


def is_valid_app_name(app_name):
    """
    Is the given application name valid?
    i.e. does it match either of our app name schemas?
    """
    if not re.match(OP_APP_NAME_PATTERN, app_name):
        return False
    else:
        return True
   

def app_domain_to_app_name(app_domain):
    """
    Convert an app comain (e.g. an Origin: string, a DNS name)
    to its fully-qualified application name for use in the token file.

    This method is idempotent.
    """
    if is_valid_app_name(app_domain):
        return app_domain

    urlinfo = urlparse.urlparse(app_domain)
    if not urlinfo.netloc:
        # try as URL:
        urlinfo = urlparse.urlparse("http://{}/".format(app_domain))
    assert urlinfo.netloc, app_domain

    if ':' in urlinfo.netloc:
        p = urlinfo.netloc.split(':', 1)
        return '{}.1:{}'.format(p[0], p[1])

    else:
        return '{}.1'.format(urlinfo.netloc)


def app_make_session( blockchain_id, app_public_key, app_domain, methods, app_public_keys, requester_device_id, master_data_privkey, session_lifetime=None, config_path=CONFIG_PATH ):
    """
    Make a session JWT for this application.
    Verify with user private key
    Sign with master private key

    Return {'session': session jwt, 'session_token': session token} on success
    Return {'error': ...} on error
    """
    conf = get_config(path=config_path)
    assert conf

    if session_lifetime is None:
        session_lifetime = conf.get('default_session_lifetime', 1e80)

    # blockstack-storage.js assumes it needs to use an
    #  uncompressed address. let's do that if we need to

    app_datastore_public_key = keylib.key_formatting.decompress(app_public_key)

    app_user_id = data.datastore_get_id(app_datastore_public_key)

    api_endpoint_host = conf.get('api_endpoint_host', DEFAULT_API_HOST)
    api_endpoint_port = conf.get('api_endpoint_port', DEFAULT_API_PORT)

    api_endpoint = '{}:{}'.format(api_endpoint_host, api_endpoint_port)

    ses = {
        'version': 1,
        'blockchain_id': blockchain_id,
        'app_domain': app_domain,
        'methods': methods,
        'app_public_keys': app_public_keys,
        'app_user_id': app_user_id,
        'api_endpoint': api_endpoint,
        'device_id': requester_device_id,
        'storage': {
            'classes': classify_storage_drivers(),
            'preferences': {}
        },
        'timestamp': int(time.time()),
        'expires': int(time.time() + session_lifetime),
    }

    jsonschema.validate(ses, APP_SESSION_SCHEMA)

    signer = jsontokens.TokenSigner()
    session_token = signer.sign( ses, master_data_privkey )
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
    
    valid = False

    try:
        valid = verifier.verify( app_session_token, pubkey )
        if not valid:
            log.debug("Failed to verify with {}".format(pubkey))
            return None
    except:
        log.debug("Not a valid token")
        return None

    session = None
    session_jwt = None

    try:
        session_jwt = jsontokens.decode_token(app_session_token)
        session = session_jwt['payload']
    except:
        log.debug("Failed to decode token")
        return None

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


def app_get_datastore_pubkey( session ):
    """
    Given a session, identify and return the datastore public key
    Return None on invalid session
    """
    device_id = session['device_id']
    for apk in session['app_public_keys']:
        if apk['device_id'] == device_id:
            return apk['public_key']

    return None


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

    if data_privkey is None:
        assert wallet_keys, 'Missing both data private key and wallet keys'
        data_privkey = wallet_keys.get('data_privkey')
        assert data_privkey, "Wallet does not have a data private key"

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
    
    data_pubkey = get_pubkey_hex(data_privkey)
    config_data_id = storage.make_fq_data_id(app_domain, '.blockstack')

    app_cfg_blob = data.make_mutable_data_info(config_data_id, app_cfg, is_fq_data_id=True)
    app_cfg_str = data.data_blob_serialize(app_cfg_blob)
    app_cfg_sig = data.data_blob_sign( app_cfg_str, data_privkey )
    res = data.put_mutable(config_data_id, app_cfg_str, data_pubkey, app_cfg_sig, app_cfg_blob['version'], blockchain_id=dev_blockchain_id, config_path=config_path)
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
    index_data_id = storage.make_fq_data_id(app_domain, 'index.html')
    
    # replicate app index file (at least one must succeed)
    # NOTE: the publisher is free to use alternative URIs that are not supported; they'll just be ignored.
    app_index_blob = data.make_mutable_data_info(index_data_id, app_index_file, is_fq_data_id=True)
    app_index_blob_str = data.data_blob_serialize(app_index_blob)
    app_index_sig = data.data_blob_sign(app_index_blob_str, data_privkey)
    res = data.put_mutable( index_data_id, app_index_blob_str, data_pubkey, app_index_sig, app_index_blob['version'], blockchain_id=dev_blockchain_id, config_path=config_path, storage_drivers=app_driver_hints )
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
    res = data.get_mutable( ".blockstack", [app_domain], data_pubkey=data_pubkey, proxy=proxy, config_path=config_path, blockchain_id=blockchain_id )
    if 'error' in res:
        log.error("Failed to get application config file: {}".format(res['error']))
        return res

    app_cfg = None
    try:
        app_cfg = res['data']
        jsonschema.validate(app_cfg, APP_CONFIG_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_TEST:
            log.exception(ve)

        log.error("Invalid application config file {}".format(app_cfg))
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

    urls = None
    if app_config is not None:
        # use driver hints
        driver_hints = app_config['driver_hints']
        urls = storage.get_driver_urls( res_data_id, storage.get_storage_handlers() )

    res = data.get_mutable( res_name, [app_domain], data_pubkey=data_pubkey, proxy=proxy, config_path=config_path, urls=urls, blockchain_id=blockchain_id )
    if 'error' in res:
        log.error("Failed to get resource {}: {}".format(res_name, res['error']))
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

    assert isinstance(res_data, (str, unicode)), "Resource must be a string"
    try:
        json.dumps(res_data)
    except:
        raise AssertionError("Resource must be a JSON-serializable string")

    if data_privkey is None:
        assert wallet_keys, 'Missing both data private key and wallet keys'
        data_privkey = wallet_keys.get('data_privkey')
        assert data_privkey, "Wallet does not have a data private key"

    proxy = get_default_proxy() if proxy is None else proxy

    res_data_id = storage.make_fq_data_id(app_domain, res_name)
    data_pubkey = get_pubkey_hex(data_privkey)

    driver_hints = None
    if app_config is not None:
        # use driver hints
        driver_hints = app_config['driver_hints']

    res_blob = data.make_mutable_data_info(res_data_id, res_data, is_fq_data_id=True)
    res_blob_str = data.data_blob_serialize(res_blob)
    res_sig = data.data_blob_sign(res_blob_str, data_privkey)
    res = data.put_mutable(res_data_id, res_blob_str, data_pubkey, res_sig, res_blob['version'], blockchain_id=blockchain_id, config_path=config_path, storage_drivers=driver_hints)
    if 'error' in res:
        log.error("Failed to store resource {}: {}".format(res_data_id, res['error']))
        return {'error': 'Failed to store resource'}

    return {'status': True, 'version': res_blob['version']}


def app_delete_resource( blockchain_id, app_domain, res_name, app_config=None, data_privkey=None, proxy=None, wallet_keys=None, config_path=CONFIG_PATH ):
    """
    Remove data from a named application resource in mutable storage.

    data_privkey should be the publisher's private key
    name should be a blockchain ID that points to the public key

    if app_config is not None, then the driver hints will be honored.

    Return {'status': True, 'version': ...} on success
    Return {'error': ...} on error
    """

    if data_privkey is None:
        assert wallet_keys, "No data private key or wallet given"
        data_privkey = wallet_keys.get('data_privkey', None)
        assert data_privkey, "Wallet does not contain a data private key"

    data_pubkey = get_pubkey_hex(data_privkey)

    proxy = get_default_proxy() if proxy is None else proxy

    res_data_id = storage.make_fq_data_id(app_domain, res_name)

    driver_hints = None
    if app_config is not None:
        # use driver hints
        driver_hints = app_config['driver_hints']

    tombstone = storage.make_data_tombstone(res_data_id)
    signed_tombstone = storage.sign_data_tombstone(res_data_id, data_privkey)
    res = data.delete_mutable(res_data_id, [signed_tombstone], proxy=proxy, storage_drivers=driver_hints, blockchain_id=blockchain_id, is_fq_data_id=True, config_path=config_path)
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

    # find out where to delete from
    data_pubkey = None
    if data_privkey is not None:
        data_pubkey = get_pubkey_hex(str(data_privkey))

    if app_config is None:
        app_config = app_get_config(blockchain_id, app_domain, data_pubkey=data_pubkey, proxy=proxy, config_path=CONFIG_PATH )
        if 'error' in app_config:
            if not force:
                log.error("Failed to load app config for {}'s {}".format(blockchain_id, app_domain))
                return {'error': 'Failed to load app config'}
            else:
                # keep going 
                app_config = None
                log.warning("Failed to load app config, but proceeding at caller request")

    config_data_id = storage.make_fq_data_id(app_domain, '.blockstack')
    index_data_id = storage.make_fq_data_id(app_domain, 'index.html')

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
    index_tombstone = storage.make_data_tombstone(index_data_id)
    signed_index_tombstone = storage.sign_data_tombstone(index_data_id, data_privkey)
    res = data.delete_mutable(index_data_id, [signed_index_tombstone], proxy=proxy, storage_drivers=storage_drivers, blockchain_id=blockchain_id, is_fq_data_id=True, config_path=config_path)
    if 'error' in res:
        log.warning("Failed to delete index file {}".format(index_data_id))
        ret['app_config'] = app_config
        ret['retry'] = True

    # delete the config 
    config_tombstone = storage.make_data_tombstone(config_data_id)
    signed_config_tombstone = storage.sign_data_tombstone(config_data_id, data_privkey)
    res = data.delete_mutable(config_data_id, [signed_config_tombstone], proxy=proxy, blockchain_id=blockchain_id, is_fq_data_id=True, config_path=config_path)
    if 'error' in res:
        log.warning("Failed to delete config file {}".format(config_data_id))
        if not ret.has_key('app_config'):
            ret['app_config'] = app_config

        ret['retry'] = True

    ret['status'] = True
    return ret


