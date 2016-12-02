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
import posixpath
import jsonschema
from jsonschema.exceptions import ValidationError
import time

from keylib import *

import jsontokens
import urllib
import urllib2
import wallet
import accounts
import config
import storage
import data
import user as user_db
from .proxy import *

from config import get_config
from .constants import CONFIG_PATH, APP_ACCOUNT_DIRNAME, BLOCKSTACK_TEST, LENGTH_MAX_NAME
from .schemas import *

def app_account_dir(config_path=CONFIG_PATH):
    """
    Get the directory that holds all app account state
    """
    conf = get_config(path=config_path)
    assert conf

    account_dir = conf['app_accounts']
    if posixpath.normpath(os.path.abspath(account_dir)) != posixpath.normpath(conf['app_accounts']):
        # relative path; make absolute
        account_dir = posixpath.normpath( os.path.join(os.path.dirname(config_path), account_dir) )

    return account_dir


def app_account_path(data_address, app_fqu, app_name, config_path=CONFIG_PATH):
    """
    Get the path to an app account.
    An app account contains all the sensitive, persistent information 
    for a user to both authenticate itself to the application and for 
    the application to authenticate itself to the user.
    """
    for part in [data_address, app_fqu, app_name]:
        assert '@' not in part, "{} has @".format(part)
        assert ':' not in part, "{} has :".format(part)

    account_dir = app_account_dir(config_path=config_path)
    account_name = '{}@{}:{}.account'.format(data_address, app_name, app_fqu)
    account_path = os.path.join(account_dir, account_name)

    return account_path


def app_account_list(config_path=CONFIG_PATH):
    """
    Get the list of accounts.
    Return {'data_address': ..., 'app_fqu': ..., 'app_name': ...} list
    """
    account_dir = app_account_dir(config_path=CONFIG_PATH)
    if not os.path.exists(account_dir) or not os.path.isdir(account_dir):
        log.error("No app accounts directory")
        return []

    names = os.listdir(account_dir)
    names = filter(lambda n: n.endswith(".account"), names)

    # format: address, url-encoded app name, b40 name
    regex = r"^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)@([a-zA-Z0-9\-_.~%]+):([a-z0-9\-_.+]{{{},{}}}).account$".format(3, LENGTH_MAX_NAME)
    ret = []
    for name in names:
        grp = re.match(regex, name)
        if grp is None:
            continue
        
        data_address, app_name, app_fqu = grp.groups()
        ret.append( {
            'data_address': data_address,
            'app_name': app_name,
            'app_fqu': app_fqu
        } )

    return ret


def app_load_account(app_fqu, app_name, data_pubkey, config_path=CONFIG_PATH):
    """
    Load the app account for the given (username, appname) pair.
    Return {'account': account jwt, 'account_token': token} on success
    Return {'error': ...} on error
    """
    data_pubkey = ECPublicKey(data_pubkey).to_hex()
    data_address = ECPublicKey(data_pubkey).address()
    account_path = app_account_path(data_address, app_fqu, app_name, config_path=config_path)
    account_jwt = None

    try:
        with open(account_path, "r") as f:
            account_jwt = f.read()

    except:
        log.error("Failed to load {}".format(account_path))
        return {'error': 'Failed to read account'}

    # verify
    verifier = jsontokens.TokenVerifier()
    valid = verifier.verify( account_jwt, data_pubkey )
    if not valid:
        return {'error': 'Failed to verify account data'}

    account_data = jsontokens.decode_token( account_jwt )
    return {'account': account_data, 'account_token': account_jwt}


def app_make_account( origin_name, appname, api_methods, data_privkey, config_path=CONFIG_PATH, session_lifetime=3600*24*7):
    """
    Make a signed application account JWT.
    Return {'account': account jwt, 'account_token': token} on success
    Return {'error': ...} on error
    """

    # make app-specific private key 
    app_privkey = ECPrivateKey().to_wif()
    data_privkey = ECPrivateKey(data_privkey).to_hex()

    account_info = {
        'name': origin_name,
        'appname': appname,
        'methods': api_methods,
        'private_key': app_privkey,
        'session_lifetime': session_lifetime
    }

    # sign
    signer = jsontokens.TokenSigner()
    account_token = signer.sign( account_info, data_privkey )
    account = jsontokens.decode_token(account_token)
    return {'account': account, 'account_token': account_token}


def app_store_account(app_fqu, appname, account_token, data_pubkey, config_path=CONFIG_PATH):
    """
    Store the app account for the given (username, appname) pair.
    Overwrites aren't allowed.
    The account_data is an encoded JWT.
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    data_address = ECPublicKey(data_pubkey).address()
    account_path = app_account_path(data_address, app_fqu, appname, config_path=config_path)
    if os.path.exists(account_path):
        return {'error': 'account exists'}

    # verify that this is a well-formed account
    acct_jwt = jsontokens.decode_token(account_token)
    acct = acct_jwt['payload']
    jsonschema.validate(acct, APP_ACCOUNT_SCHEMA)

    try:
        account_dir = os.path.dirname(account_path)
        if not os.path.exists(account_dir):
            os.makedirs(account_dir)

        with open(account_path, "w") as f:
            f.write(account_token)

    except:
        log.error("Failed to store {}".format(account_path))
        return {'error': 'Failed to store account'}

    return {'status': True}


def app_delete_account(name, app_fqu, appname, data_pubkey, config_path=CONFIG_PATH):
    """
    Remove an app account for a given (username, appname) pair.
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    data_address = ECPublicKey(data_pubkey).address()
    account_path = app_account_path(data_address, app_fqu, appname, config_path=config_path)
    if not os.path.exists(account_path):
        return {'error': 'No such account'}

    try:
        os.unlink(account_path)
    except:
        log.error("Failed to remove {}".format(account_path))
        return {'error': 'Failed to remove account'}

    return {'status': True}


def app_make_session( app_account, data_privkey, config_path=CONFIG_PATH ):
    """
    Make a session JWT for this application.
    Return {'session': session jwt, 'session_token': session token} on success
    Return {'error': ...} on error
    """
    conf = get_config(path=config_path)
    default_lifetime = conf.get('default_session_lifetime', 1e80)

    ses = {
        'name': app_account['name'],
        'appname': app_account['appname'],
        'methods': app_account['methods'],
        'timestamp': int(time.time()),
        'expires': int(time.time() + min(default_lifetime, app_account['session_lifetime']))
    }

    privkey = ECPrivateKey(data_privkey).to_hex()

    signer = jsontokens.TokenSigner()
    session_token = signer.sign( ses, privkey )
    session = jsontokens.decode_token(session_token)

    return {'session': session, 'session_token': session_token}


def app_verify_session( app_session_token, data_pubkey, config_path=CONFIG_PATH ):
    """
    Verify and decode a JWT app session token.
    The session is valid if the signature matches and the token is not expired.
    Return the decoded session token payload on success
    Return None on error
    """
    pubkey = ECPublicKey(data_pubkey).to_hex()
    verifier = jsontokens.TokenVerifier()
    valid = verifier.verify( app_session_token, data_pubkey )
    if not valid:
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

    if session['expires'] < time.time():
        # expired
        log.debug("Token is expired")
        return None

    return session


def _get_url_nonce( config_path=CONFIG_PATH ):
    """
    Get the current URL nonce
    Return None if we can't read from the nonce file
    """
    nonce = 0
    account_dir = app_account_dir(config_path=config_path)
    nonce_path = os.path.join(account_dir, ".signin_nonce")
    if os.path.exists(nonce_path):
        try:
            with open(nonce_path, "r") as f:
                nonce_str = f.read().strip()
                nonce = int(nonce_str)
        except:
            return None

    return nonce


def _make_url_nonce( config_path=CONFIG_PATH ):
    """
    Make a one-time-use nonce for a signed URL
    """
    account_dir = app_account_dir(config_path=config_path)
    if not os.path.exists(account_dir):
        os.makedirs(account_dir)

    nonce_path = os.path.join(account_dir, ".signin_nonce")
    nonce = _get_url_nonce(config_path=config_path)
    if nonce is None:
        # couldn't read
        log.error("Failed to read url nonce file {}".format(nonce_path))
        return None

    nonce = nonce + 1

    try:
        with open(nonce_path, "w") as f:
            f.write("{}".format(nonce))
            f.flush()
            os.fsync(f.fileno())
    
    except:
        log.error("Failed to store url nonce to {}".format(nonce_path))
        return None

    return nonce


def _url_qs_append( url, qs_extra ):
    """
    Append the query information to the URL
    """
    url_info = urllib2.urlparse.urlparse(url)
    if len(url_info.query) > 0:
        qs_extra = url_info.query + '&' + qs_extra

    new_url_info = urllib2.urlparse.ParseResult( scheme=url_info.scheme, netloc=url_info.netloc, path=url_info.path, params=url_info.params, query=qs_extra, fragment=url_info.fragment )
    url = urllib2.urlparse.urlunparse( new_url_info )
    return url


def app_sign_url( url, data_privkey, config_path=CONFIG_PATH ):
    """
    Sign a URL and append the signature to its query string
    Return the signed URL on success
    Return None on error
    """
    # normalize
    url = urllib2.urlparse.urlunparse( urllib2.urlparse.urlparse(url) )

    nonce = _make_url_nonce(config_path=config_path)
    if nonce is None:
        log.error("Failed to make URL nonce")
        return None

    url = _url_qs_append( url, 'nonce={}'.format(nonce) )

    # sign nonce too
    sig = storage.sign_raw_data(url, data_privkey)
    sigurl = urllib.quote(sig)

    log.debug("Sign '{}'".format(url))
    url = _url_qs_append( url, 'sig={}'.format(sigurl) )
    return url


def app_verify_url( url, data_pubkey, config_path=CONFIG_PATH ):
    """
    Verify a URL and strip the signature.
    Return {'url': stripped verified URl, 'nonce': nonce} on success
    Return None on error
    """
    url_info = urllib2.urlparse.urlparse(url)
    qs_parts = urllib2.urlparse.parse_qsl(url_info.query, keep_blank_values=1, strict_parsing=1)
    if len(qs_parts) == 0:
        # no sig
        log.debug("Invalid URL; no sig=")
        return None

    # must be exactly one signature and exactly one nonce
    sigb64 = None
    nonce = None
    for (qs_varname, qs_value) in qs_parts:
        if qs_varname == 'sig':
            if sigb64 is not None:
                # duplicate
                log.debug("Duplicate sig=")
                return None
            
            try:
                # must be base64 string
                sig = urllib.unquote(qs_value)
                base64.b64decode(sig)
            except Exception as e:
                log.debug("Not a base64-encoded signature: {}".format(qs_value))
                return None

            sigb64 = urllib.unquote(qs_value)

        elif qs_varname == 'nonce':
            if nonce is not None:
                # duplicate
                log.debug("Duplicate nonce=")
                return None 

            try:
                nonce = int(qs_value)
            except:
                log.debug("Invalid nonce")
                return None

    new_query_parts = []
    for (qs_varname, qs_value) in qs_parts:
        if qs_varname in ['sig']:
            continue

        new_query_parts.append( '{}={}'.format(urllib.quote(qs_varname), urllib.quote(qs_value)) )

    new_query = '&'.join(new_query_parts)
    orig_url_info = urllib2.urlparse.ParseResult( scheme=url_info.scheme, netloc=url_info.netloc, path=url_info.path, params=url_info.params, query=new_query, fragment=url_info.fragment )
    orig_url = urllib2.urlparse.urlunparse( orig_url_info )
    
    log.debug("Verify '{}'".format(orig_url))
    res = storage.verify_raw_data(orig_url, data_pubkey, sigb64 )
    if not res:
        log.debug("Failed to verify URL signature")
        return None

    # was signed by us, but is it fresh?
    cur_nonce = _get_url_nonce(config_path=config_path)
    if cur_nonce is None:
        # I/O error
        log.error("Failed to read nonce file")
        return None

    if nonce < cur_nonce:
        log.error("Stale URL: expected nonce >= {}, got {}".format(cur_nonce, nonce))
        return None

    return {'url': orig_url, 'nonce': nonce}


def app_url_signin( app_fqu, appname, signin_descriptor, data_privkey, config_path=CONFIG_PATH ):
    """
    Make a URL that resolves to the signin page.  The URL will be signed by the daemon and will be
    one-time-use, so other apps can't redirect users to the sign-in page.

    A GET on this URL should load the sign-in page, so the user can create a session.
    """
    config = get_config(path=config_path)
    qs = "&".join(["{}={}".format(k,v) for (k, v) in signin_descriptor.items()])
    if len(qs) > 0:
        qs = "?{}".format(qs)

    url = "http://localhost:{}/signin/{}/{}{}".format(config['api_endpoint_port'], app_fqu, appname, qs)
    return app_sign_url(url, data_privkey, config_path=config_path)


def app_url_allow_deny( app_fqu, appname, app_descriptor, data_privkey, config_path=CONFIG_PATH ):
    """
    Make a URL that resolves to the page that asks whether or not 
    the app is allowed to interact with the user's profile.
    The URL will be signed, so apps can't direct users to this page.

    A GET on this URL should load the account-creation page, so the user can create an app account.
    """
    config = get_config(path=config_path)
    qs = "&".join(["{}={}".format(k,v) for (k, v) in app_descriptor.items()])
    if len(qs) > 0:
        qs = '?{}'.format(qs)

    url = "http://localhost:{}/allowdeny/{}/{}{}".format(config['api_endpoint_port'], app_fqu, appname, qs)
    return app_sign_url(url, data_privkey, config_path=config_path)


def app_url_create_account( app_fqu, appname, account_descriptor, data_privkey, config_path=CONFIG_PATH ):
    """
    Make a URL that, when GET'ed, will create an account.  A GET on this URL creates the account,
    and redirects the GET'er to a URL with the session (via app_url_auth_finish)

    Returns the URL
    """
    config = get_config(path=config_path)
    qs = "&".join(["{}={}".format(k,v) for (k, v) in account_descriptor.items()])
    if len(qs) > 0:
        qs = '?{}'.format(qs)

    url = "http://localhost:{}/newaccount/{}/{}{}".format(config['api_endpoint_port'], app_fqu, appname, qs)
    return app_sign_url(url, data_privkey, config_path=config_path)


def app_url_auth_abort(config_path=CONFIG_PATH):
    """
    Make a URL that aborts the authentication
    """
    config = get_config(path=config_path)
    url = "http://localhost:{}/home".format(config['api_endpoint_port'])
    return url

    
def app_url_auth_finish( data_privkey, session_token, config_path=CONFIG_PATH ):
    """
    Make a URL that redirects back to the app, passing the session JWT
    as part of the query string.  The URL will be signed, so apps can't
    generate this URL without the daemon's blessing.

    A GET on this URL should load the app's index.html file (or similar).
    """
    config = get_config(path=config_path)
    qs = '?session={}'.format(session_token)

    url = 'http://localhost:{}/index.html{}'.format(config['api_endpoint_port'], qs)
    return app_sign_url(url, data_privkey, config_path=config_path)


def app_auth_begin( app_fqu, appname, data_privkey, config_path=CONFIG_PATH ):
    """
    Make an authentication URL to redirect the app-loader's request to run the app.
    
    If the app's account account exists, then use it to generate a session JWT
    and return the URL for the daemon to redirect the requester.

    If the app's account account does not exist, then we need to determine what capabilities
    the app needs and ask the user to create the account.  In this case, reply
    a URL that, when queried, will load up page to ask the user if they want to create a account.

    Return the URL
    """
    assert data_privkey, "Could not look up data private key"

    data_address = ECPrivateKey(data_privkey).public_key().address()
    account_path = app_account_path( data_address, app_fqu, appname, config_path=config_path)
    if not os.path.exists(account_path):
        # app is not known to us.
        # redirect to allow/deny page.
        url = app_url_allow_deny( app_fqu, appname, {}, data_privkey, config_path=config_path )
        return url

    else:
        # we're trying to sign in.
        # redirect to sign-in page
        url = app_url_signin( app_fqu, appname, {}, data_privkey, config_path=config_path )
        return url


def app_auth_finish( app_fqu, appname, data_pubkey, config_path=CONFIG_PATH):
    """
    Finish authenticating.
    Load up and return a session JWT
    Return {'session': session} on success
    Return {'error': ...} on error
    """

    # load up the account...
    app_account = app_load_account(app_fqu, appname, data_pubkey, config_path=config_path)
    if 'error' in app_account:
        log.error("Failed to load app account for {}".format(appname))
        return {'error': 'Failed to load app account'}

    app_account = app_account['account']

    # generate a session JWT
    ses = app_make_session( app_account, config_path=config_path )
    return ses


def app_publish( name, appname, app_method_list, app_index_uris, app_index_file, app_driver_hints=[], data_privkey=None, proxy=None, wallet_keys=None, config_path=CONFIG_PATH ):
    """
    Instantiate an application.
    * replicate the (opaque) app index file to "index.html" to each URL in app_uris
    * replicate the list of URIs and the list of methods to ".blockstack" via each of the client's storage drivers.
    * the index file will be located at "$name:$appname/index.html"
    * the .blockstack file will be located at "$name:$appname/.blockstack"

    This succeeds even if the app already exists (in which case,
    it will be overwritten).  This method is idempotent, so it
    can be retried on failure.

    data_privkey should be the publisher's private key (i.e. their data key)
   
    Return {'status': True, 'fq_data_id': index file's fully-qualified data ID} on success
    Return {'error': ...} on error
    """

    proxy = get_default_proxy() if proxy is None else proxy

    # replicate configuration data (method list and app URIs)
    app_cfg = {
        'index_uris': app_index_uris,
        'api_methods': app_method_list,
        'driver_hints': app_driver_hints,
    }

    jsonschema.validate(app_cfg, APP_CONFIG_SCHEMA)

    config_data_id = '{}/.blockstack'.format(appname)
    res = data.put_mutable(name, config_data_id, app_cfg, data_privkey=data_privkey, wallet_keys=wallet_keys, config_path=config_path )
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
    index_data_id = "{}/index.html".format(appname)
    
    # replicate app index file (at least one must succeed)
    # NOTE: the publisher is free to use alternative URIs that are not supported; they'll just be ignored.
    res = data.put_mutable( name, index_data_id, app_index_file, data_privkey=data_privkey, storage_drivers=driver_names, wallet_keys=wallet_keys, config_path=config_path )
    if 'error' in res:
        log.error("Failed to replicate application index file to {}: {}".format(",".join(urls), res['error']))
        return {'error': 'Failed to replicate index file'}

    return {'status': True, 'fq_data_id': storage.make_fq_data_id(name, index_data_id)}


def app_get_config( name, appname, data_pubkey=None, proxy=None, config_path=CONFIG_PATH ):
    """
    Get application configuration bundle.
    
    data_pubkey should be the publisher's public key.

    Return {'status': True, 'config': config} on success
    Return {'error': ...} on error
    """

    proxy = get_default_proxy() if proxy is None else proxy

    # go get config 
    config_data_id = '{}/.blockstack'.format(appname)
    res = data.get_mutable( name, config_data_id, data_pubkey=data_pubkey, proxy=proxy, config_path=config_path )
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


def app_make_resource_data_id( name, appname, res_name ):
    """
    Make a fully-qualified application resource data ID
    """
    res_data_id = '{}/{}'.format(appname, res_name)
    fq_res_data_id = storage.make_fq_data_id(name, res_data_id)
    return fq_res_data_id


def app_get_index_file( name, appname, app_config=None, data_pubkey=None, proxy=None, config_path=CONFIG_PATH ):
    """
    Get the application's index file.
    Follows the URLs in the app_config structure (from app_get_config)
    Return {status': True, 'index_file': index_file_text} on success
    Return {'error': ...} on error
    """
    proxy = get_default_proxy() if proxy is None else proxy
    res_data_id = '{}/index.html'.format(appname)

    if app_config is None:
        app_config = app_get_config(name, appname, data_pubkey=data_pubkey, proxy=proxy, config_path=CONFIG_PATH )
        if 'error' in app_config:
            log.error("Failed to load application config: {}".format(app_config['error']))
            return {'error': 'Failed to load app config'}

        app_config = app_config['config']

    urls = user_db.urls_from_uris( app_config['index_uris'] )
    res = data.get_mutable( name, res_data_id, data_pubkey=data_pubkey, proxy=proxy, config_path=config_path, urls=urls )
    if 'error' in res:
        log.error("Failed to get index file: {}".format(res['error']))
        return {'error': 'Failed to load index'}

    return {'status': True, 'index_file': res['data']}


def app_get_resource( name, appname, res_name, app_config=None, data_pubkey=None, proxy=None, config_path=CONFIG_PATH ):
    """
    Get a named application resource from mutable storage

    data_pubkey should be the publisher's public key 

    If app_config is not None, then the driver hints will be honored.
    
    Return {'status': True, 'res': resource} on success
    Return {'error': ...} on error
    """

    proxy = get_default_proxy() if proxy is None else proxy

    res_data_id = '{}/{}'.format(appname, res_name)
    fq_res_data_id = storage.make_fq_data_id( name, res_data_id )

    urls = None
    if app_config is not None:
        # use driver hints
        driver_hints = app_config['driver_hints']
        urls = storage.get_driver_urls( fq_res_data_id, storage.get_storage_handlers() )

    res = data.get_mutable( name, res_data_id, data_pubkey=data_pubkey, proxy=proxy, config_path=config_path, urls=urls )
    if 'error' in res:
        log.error("Failed to get resource {}: {}".format(fq_res_data_id, res['error']))
        return {'error': 'Failed to load resource'}

    return {'status': True, 'res': res['data']}
   

def app_put_resource( name, appname, res_name, res_data, app_config=None, data_privkey=None, proxy=None, wallet_keys=None, config_path=CONFIG_PATH ):
    """
    Store data to a named application resource in mutable storage.

    data_privkey should be the publisher's private key

    if app_config is not None, then the driver hints will be honored.

    Return {'status': True, 'version': ...} on success
    Return {'error': ...} on error
    """

    proxy = get_default_proxy() if proxy is None else proxy

    res_data_id = '{}/{}'.format(appname, res_name)
    fq_res_data_id = storage.make_fq_data_id( name, res_data_id )

    driver_hints = None
    if app_config is not None:
        # use driver hints
        driver_hints = app_config['driver_hints']

    res = data.put_mutable(name, res_data_id, res_data, data_privkey=data_privkey, proxy=proxy, storage_drivers=driver_hints, wallet_keys=wallet_keys, config_path=CONFIG_PATH)
    if 'error' in res:
        log.error("Failed to store resource {}: {}".format(fq_res_data_id, res['error']))
        return {'error': 'Failed to store resource'}

    return {'status': True, 'version': res['version']}


def app_unpublish( name, appname, force=False, data_privkey=None, app_config=None, wallet_keys=None, proxy=None, config_path=CONFIG_PATH ):
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
            data_pubkey = ECPrivateKey(data_privkey).public_key().to_hex()

        app_config = app_get_config(name, appname, data_pubkey=data_pubkey, proxy=proxy, config_path=CONFIG_PATH )
        if 'error' in app_config:
            if not force:
                log.error("Failed to load app config for {}:{}".format(name, appname))
                return {'error': 'Failed to load app config'}
            else:
                # keep going 
                app_config = None
                log.warning("Failed to load app config, but proceeding at caller request")

    config_data_id = '{}/.blockstack'.format(appname)
    index_data_id = "{}/index.html".format(appname)

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
    res = data.delete_mutable( name, index_data_id, data_privkey=data_privkey, proxy=proxy, wallet_keys=wallet_keys, delete_version=False, storage_drivers=storage_drivers )
    if 'error' in res:
        log.warning("Failed to delete index file {}".format(index_data_id))
        ret['app_config'] = app_config
        ret['retry'] = True

    # delete the config 
    res = data.delete_mutable( name, config_data_id, data_privkey=data_privkey, proxy=proxy, wallet_keys=wallet_keys, delete_version=False )
    if 'error' in res:
        log.warning("Failed to delete config file {}".format(config_data_id))
        if not ret.has_key('app_config'):
            ret['app_config'] = app_config

        ret['retry'] = True

    ret['status'] = True
    return ret


