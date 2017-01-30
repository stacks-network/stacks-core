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
    along with Blockstack-client.  If not, see <http://www.gnu.org/licenses/>.
"""

import socket
import base64
import json
import storage
import config
import posixpath
import jsontokens
import jsonschema
from jsonschema.exceptions import ValidationError
import re
import keylib

from .schemas import *
from .constants import BLOCKSTACK_TEST, CONFIG_PATH, BLOCKSTACK_DEBUG, USER_DIRNAME
from .keys import HDWallet, get_pubkey_hex
import scripts

log = config.get_logger()

USER_CACHE = {}

def user_dir(config_path=CONFIG_PATH):
    """
    Get the path to the directory 
    that stores user information (like private keys).
    """
    conf = config.get_config(path=config_path)
    assert conf

    dirp = conf['users']
    if posixpath.normpath(os.path.abspath(dirp)) != posixpath.normpath(conf['users']):
        # relative path; make absolute
        dirp = posixpath.normpath( os.path.join(os.path.dirname(config_path), dirp) )

    return dirp
    

def user_name(user_id):
    """
    Get the on-disk name of a file that stores the user information
    """
    return "{}.user".format(user_id.replace('/', '\\x2f'))


def user_path(user_id, config_path=CONFIG_PATH):
    """
    Get the path to a user account state bundle
    """
    dirp = user_dir(config_path=config_path)
    return os.path.join(dirp, user_name(user_id))


def user_init( user_id, master_data_privkey_hex, blockchain_id=None, config_path=CONFIG_PATH ):
    """
    Generate a new local user with the given user ID
    Returns {'user': ..., 'user_token': ...} on success
    Returns {'error': ... on error}
    raises on fatal error
    """
    
    from .data import next_privkey_index
    next_privkey_index_info = next_privkey_index(master_data_privkey_hex, config_path=config_path)
    if 'error' in next_privkey_index_info:
        return next_privkey_index_info

    next_privkey_index = next_privkey_index_info['index']
    
    hdwallet = HDWallet( hex_privkey=master_data_privkey_hex)
    user_privkey = hdwallet.get_child_privkey( index=next_privkey_index )

    info = {
        'user_id': user_id,
        'public_key': get_pubkey_hex(user_privkey),
        'privkey_index': next_privkey_index
    }
    if blockchain_id is not None:
        info['blockchain_id'] = blockchain_id

    res = user_serialize(info, master_data_privkey_hex)
    if 'error' in res:
        return res

    token = res['token']

    # log.debug("\ncreate user with {}:\n{}\n".format(master_data_privkey, json.dumps(info, indent=4, sort_keys=True)))

    return {'user': info, 'user_token': token}


def user_serialize( user_info, data_privkey_hex ):
    """
    Sign and serialize a user into a JWT
    Return {'status': True, 'token': ...} on success
    Return {'error': ...} on failure
    """
    try:
        jsonschema.validate(user_info, USER_SCHEMA)
    except ValidationError:
        return {'error': 'Not a valid user'}

    signer = jsontokens.TokenSigner()
    token = signer.sign(user_info, data_privkey_hex)
    return {'status': True, 'token': token}


def user_store( token, config_path=CONFIG_PATH ):
    """
    Store the user data locally.
    @token must be a JWT encoded user data token
    Verify it conforms to USER_SCHEMA
    Returns {'status': True} on success
    Returns {'error': ...} on error
    """

    global USER_CACHE

    # verify that this is a well-formed user
    jwt = jsontokens.decode_token(token)
    payload = jwt['payload']
    jsonschema.validate(payload, USER_SCHEMA)

    # store locally
    user_id = payload['user_id']
    path = user_path( user_id, config_path=config_path)
    try:
        pathdir = os.path.dirname(path)
        if not os.path.exists(pathdir):
            os.makedirs(pathdir)

        with open(path, "w") as f:
            f.write(token)

    except:
        log.error("Failed to store user {}".format(path))
        return {'error': 'Failed to store user'}

    name = user_name(user_id)
    if USER_CACHE.has_key(name):
        del USER_CACHE[name]

    return {'status': True}


def user_delete( user_id, config_path=CONFIG_PATH ):
    """
    Delete a user
    Return {'status': True} on success
    """
    
    global USER_CACHE

    path = user_path(user_id, config_path=config_path)
    if not os.path.exists(path):
        return {'error': 'No such user'}

    log.debug("delete user {} ({})".format(user_id, path))

    try:
        os.unlink(path)
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to unlink'}

    name = user_name(user_id)
    if USER_CACHE.has_key(name):
        del USER_CACHE[name]

    return {'status': True}
   

def user_verify(user_jwt, data_pubkey_hex):
    """
    Verify a user token with the given public key
    Return True if valid
    Return False if not
    """
    verifier = jsontokens.TokenVerifier()
    valid = verifier.verify( user_jwt, str(data_pubkey_hex) )
    return valid


def user_parse(user_jwt):
    """
    Parse and validate a user token
    Return {'status': True, 'user': ...} on success
    Return {'error': ...} on failure
    """
    try:
        data = jsontokens.decode_token(user_jwt)
        jsonschema.validate(data['payload'], USER_SCHEMA)
        return {'status': True, 'user': data['payload']}
    except (ValueError, ValidationError) as ve:
        return {'error': 'Failed to parse and validate'}


def user_is_local(user_id, config_path=CONFIG_PATH):
    """
    Is a user owned by the local host?
    """
    path = user_path( user_id, config_path=config_path)
    return os.path.exists(path)


def _user_load_path(path, data_pubkey_hex, config_path=CONFIG_PATH):
    """
    Load a user from a given path
    Verify it conforms to the USER_SCHEMA
    Return {'user': ..., 'user_token': ...} on success
    Return {'error': ...} on error
    """
    jwt = None
    try:
        with open(path, "r") as f:
            jwt = f.read()

    except:
        log.error("Failed to load {}".format(path))
        return {'error': 'Failed to read user'}

    # verify
    if data_pubkey_hex is not None:
        valid = user_verify(jwt, data_pubkey_hex)
        if not valid:
            return {'error': 'Failed to verify user JWT data'}

    data = jsontokens.decode_token( jwt )
    jsonschema.validate(data['payload'], USER_SCHEMA)
    return {'user': data['payload'], 'user_token': jwt}


def user_load( user_id, data_pubkey, config_path=CONFIG_PATH):
    """
    Load the app account for the given (user_id, app owner name, appname) triple
    Return {'user': jwt, 'user_token': token} on success
    Return {'error': ...} on error
    """
    global USER_CACHE

    name = user_name(user_id)
    if USER_CACHE.has_key(name):
        log.debug("User {} is cached".format(name))
        return USER_CACHE[name]

    path = user_path( user_id, config_path=config_path)
    res = _user_load_path( path, data_pubkey, config_path=config_path )
    if 'error' in res:
        return res

    USER_CACHE[name] = res
    return res


def users_list(data_pubkey, config_path=CONFIG_PATH):
    """
    Get the list of all users
    Return a list of USER_SCHEMA-formatted objects
    """
    dirp = user_dir(config_path=config_path)
    if not os.path.exists(dirp) or not os.path.isdir(dirp):
        log.error("No user directory")
        return []

    names = os.listdir(dirp)
    names = filter(lambda n: n.endswith(".user"), names)
    ret = []
    for name in names:
        path = os.path.join( dirp, name )
        info = _user_load_path( path, data_pubkey, config_path=config_path )
        if 'error' in info:
            continue

        ret.append(info['user'])

    return ret


def user_get_privkey( master_privkey_hex, user_info ):
    """
    Given the master data private key and a user structure, calculate the private key
    for the user.
    Return the private key
    """
    user_privkey = HDWallet.get_privkey(master_privkey_hex, user_info['privkey_index'])
    return user_privkey


def is_user_zonefile(d):
    """
    Is the given dict (or dict-like object) a user zonefile?
    * the zonefile must have a URI record
    """

    try:
        jsonschema.validate(d, USER_ZONEFILE_SCHEMA)
        return True
    except ValidationError as ve:
        if BLOCKSTACK_TEST:
            log.exception(ve)

        return False


def has_mutable_data_section(d):
    """
    Does the given dictionary have a mutable data section?
    """
    try:
        assert isinstance(d, dict)
        if 'data' not in d.keys():
            return False

        jsonschema.validate(d, PROFILE_MUTABLE_DATA_SCHEMA)
        return True
    except ValidationError as ve:
        if BLOCKSTACK_TEST:
            log.exception(ve)
    
        return False
    
    except AssertionError:
        return False


def user_zonefile_data_pubkey(user_zonefile, key_prefix='pubkey:data:'):
    """
    Get a user's data public key from their zonefile.
    There can be only one.

    Return the uncompressed data public key on success
    Return None if not defined
    Raise if there are multiple ones.
    """
    assert is_user_zonefile(user_zonefile)

    if 'txt' not in user_zonefile:
        return None

    data_pubkey = None
    # check that there is only one of these
    for txtrec in user_zonefile['txt']:
        if not txtrec['txt'].startswith(key_prefix):
            continue

        if data_pubkey is not None:
            log.error('Invalid zone file: multiple data keys')
            raise ValueError('{} starting with "{}"'.format(msg, key_prefix))

        data_pubkey = txtrec['txt'][len(key_prefix):]

        # must be DER-encoded EC public key--either uncompressed or compressed
        if not re.match(r'^[0-9a-fA-F]{66}$', data_pubkey) and not re.match(r'[0-9a-fA-F]{130}$', data_pubkey):
            data_pubkey = None

    if data_pubkey is None:
        return None

    # uncompressed!
    if keylib.key_formatting.get_pubkey_format(data_pubkey) == 'hex_compressed':
        data_pubkey = keylib.key_formatting.decompress(data_pubkey)

    return data_pubkey


def user_zonefile_set_data_pubkey(user_zonefile, pubkey_hex, key_prefix='pubkey:data:'):
    """
    Set the data public key in the zonefile.
    NOTE: you will need to re-sign all your data!
    """
    assert is_user_zonefile(user_zonefile)

    user_zonefile.setdefault('txt', [])

    txt = '{}{}'.format(key_prefix, str(pubkey_hex))

    for txtrec in user_zonefile['txt']:
        if txtrec['txt'].startswith(key_prefix):
            # overwrite
            txtrec['txt'] = txt
            return user_zonefile

    # not present.  add.
    name_txt = {'name': 'pubkey', 'txt': txt}
    user_zonefile['txt'].append(name_txt)

    return user_zonefile


def user_zonefile_remove_data_pubkey(user_zonefile, key_prefix='pubkey:data:'):
    """
    Remove the data public key in the zonefile.
    NOTE: you will need to re-sign all your data!
    """
    assert is_user_zonefile(user_zonefile)

    user_zonefile.setdefault('txt', [])

    new_txts = []
    for txtrec in user_zonefile['txt']:
        if not txtrec['txt'].startswith(key_prefix):
            new_txts.append(txtrec)

    user_zonefile['txt'] = new_txts
    return user_zonefile


def user_zonefile_urls(user_zonefile):
    """
    Given a user's zonefile, get the profile URLs
    """
    assert is_user_zonefile(user_zonefile)

    if 'uri' not in user_zonefile:
        return None

    ret = []
    for urirec in user_zonefile['uri']:
        if 'target' in urirec:
            ret.append(urirec['target'].strip('"'))

    return ret


def add_user_zonefile_url(user_zonefile, url):
    """
    Add a url to a zonefile
    Return the new zonefile on success
    Return None on error or on duplicate URL
    """
    assert is_user_zonefile(user_zonefile)

    user_zonefile.setdefault('uri', [])

    # avoid duplicates
    for urirec in user_zonefile['uri']:
        target = urirec.get('target', '')
        if target.strip('"') == url:
            return None

    new_urirec = url_to_uri_record(url)
    user_zonefile['uri'].append(new_urirec)

    return user_zonefile


def remove_user_zonefile_url(user_zonefile, url):
    """
    Remove a url from a zonefile
    Return the new zonefile on success
    Return None on error.
    """

    assert is_user_zonefile(user_zonefile)

    if 'uri' not in user_zonefile:
        return None

    for urirec in user_zonefile['uri']:
        target = urirec.get('target', '')
        if target.strip('"') == url:
            user_zonefile['uri'].remove(urirec)

    return user_zonefile


def make_empty_user_profile():
    """
    Given a user's name, create an empty profile.
    """
    ret = {
        '@type': 'Person',
        'accounts': [],
    }

    return ret


def put_immutable_data_zonefile(user_zonefile, data_id, data_hash, data_url=None):
    """
    Add a data hash to a user's zonefile.  Make sure it's a valid hash as well.
    Return True on success
    Return False otherwise.
    """

    assert is_user_zonefile(user_zonefile)

    data_hash = str(data_hash)
    assert scripts.is_valid_hash(data_hash)

    k = get_immutable_data_hashes(user_zonefile, data_id)
    if k is not None:
        # exists or name collision
        return k[0] == data_hash

    txtrec = '#{}'.format(data_hash)
    if data_url is not None:
        txtrec = '{}{}'.format(data_url, txtrec)

    user_zonefile.setdefault('txt', [])

    name_txt = {'name': data_id, 'txt': txtrec}
    user_zonefile['txt'].append(name_txt)

    return True


def get_immutable_hash_from_txt(txtrec):
    """
    Given an immutable data txt record,
    get the hash.
    The hash is the suffix that begins with #.
    Return None if invalid or not present
    """
    if '#' not in txtrec:
        return None

    h = txtrec.split('#')[-1]
    if not scripts.is_valid_hash(h):
        return None

    return h


def get_immutable_url_from_txt(txtrec):
    """
    Given an immutable data txt record,
    get the URL hint.
    This is everything that starts before the last #.
    Return None if there is no URL, or we can't parse the txt record
    """
    if '#' not in txtrec:
        return None

    url = '#'.join(txtrec.split('#')[:-1])

    return url or None


def remove_immutable_data_zonefile(user_zonefile, data_hash):
    """
    Remove a data hash from a user's zonefile.
    Return True if removed
    Return False if not present
    """
    assert is_user_zonefile(user_zonefile)

    data_hash = str(data_hash)
    assert scripts.is_valid_hash(data_hash), 'Invalid data hash "{}"'.format(data_hash)

    if 'txt' not in user_zonefile:
        return False

    for txtrec in user_zonefile['txt']:
        h = None
        try:
            h = get_immutable_hash_from_txt(txtrec['txt'])
            if h is None:
                continue

            assert scripts.is_valid_hash(h)

        except AssertionError as ae:
            log.debug("Invalid immutable data hash")
            continue

        if data_hash == h:
            user_zonefile['txt'].remove(txtrec)
            return True

    return False


def has_immutable_data(user_zonefile, data_hash):
    """
    Does the given user have the given immutable data?
    Return True if so
    Return False if not
    """
    assert is_user_zonefile(user_zonefile)

    data_hash = str(data_hash)
    assert scripts.is_valid_hash(data_hash), 'Invalid data hash "{}"'.format(data_hash)

    if 'txt' not in user_zonefile:
        return False

    for txtrec in user_zonefile['txt']:
        h = None
        try:
            h = get_immutable_hash_from_txt(txtrec['txt'])
            if h is None:
                continue

            assert scripts.is_valid_hash(h)

        except AssertionError as ae:
            log.error("Invalid immutable data hash")
            continue

        if data_hash == h:
            return True

    return False


def has_immutable_data_id(user_zonefile, data_id):
    """
    Does the given user have the given immutable data?
    Return True if so
    Return False if not
    """
    assert is_user_zonefile(user_zonefile)

    if 'txt' not in user_zonefile:
        return False

    for txtrec in user_zonefile['txt']:
        d_id = None
        try:
            d_id = txtrec['name']
            h = get_immutable_hash_from_txt(txtrec['txt'])
            if h is None:
                continue

            assert scripts.is_valid_hash(h)
        except AssertionError:
            continue

        if data_id == d_id:
            return True

    return False


def get_immutable_data_hashes(user_zonefile, data_id):
    """
    Get the hash of an immutable datum by name.
    Return None if there is no match.
    Return the list of hashes otherwise
    """
    assert is_user_zonefile(user_zonefile)

    if 'txt' not in user_zonefile:
        return None

    ret = None
    for txtrec in user_zonefile['txt']:
        h, d_id = None, None

        try:
            d_id = txtrec['name']
            if data_id != d_id:
                continue

            h = get_immutable_hash_from_txt(txtrec['txt'])
            if h is None:
                continue

            msg = 'Invalid data hash for "{}" (got "{}" from {})'
            assert scripts.is_valid_hash(h), msg.format(d_id, h, txtrec['txt'])
        except AssertionError as ae:
            if BLOCKSTACK_TEST is not None:
                log.exception(ae)

            continue

        if ret is None:
            ret = [h]
        else:
            ret.append(h)

    return ret


def get_immutable_data_url(user_zonefile, data_hash):
    """
    Given the hash of an immutable datum, find the associated
    URL hint (if given)
    Return None if not given, or not found.
    """

    assert is_user_zonefile(user_zonefile)

    if 'txt' not in user_zonefile:
        return None

    for txtrec in user_zonefile['txt']:
        h = None
        try:
            h = get_immutable_hash_from_txt(txtrec['txt'])
            if h is None:
                continue

            assert scripts.is_valid_hash(h)

            if data_hash != h:
                continue

            url = get_immutable_url_from_txt(txtrec['txt'])
        except AssertionError as ae:
            log.debug("Invalid immutable data hash {}".format(h))
            continue

        return url

    return None


def list_immutable_data(user_zonefile):
    """
    Get the IDs and hashes of all immutable data
    Return [(data ID, hash)]
    """
    assert is_user_zonefile(user_zonefile)

    ret = []
    if 'txt' not in user_zonefile:
        return ret

    for txtrec in user_zonefile['txt']:
        try:
            d_id = txtrec['name']
            h = get_immutable_hash_from_txt(txtrec['txt'])
            assert scripts.is_valid_hash(h)
            ret.append((d_id, h))
        except AssertionError as ae:
            log.error("Invalid immutable data hash")
            continue

    return ret


def urls_from_uris( uri_records ):
    """
    Get the list of URLs from a list of URI records
    """
    return [u['target'].strip('"') for u in uri_records]


def mutable_data_urls(mutable_info):
    """
    Get the URLs from a mutable data zonefile
    """
    uri_records = mutable_info.get('uri')

    if uri_records is None:
        return None

    return urls_from_uris( uri_records )
