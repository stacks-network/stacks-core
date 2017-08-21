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
    along with Blockstack-client.  If not, see <http://www.gnu.org/licenses/>.
"""

import config
import jsonschema
from jsonschema.exceptions import ValidationError
import re
import keylib
import copy
import urlparse

import virtualchain

from .schemas import USER_ZONEFILE_SCHEMA, OP_URI_TARGET_PATTERN
from .constants import BLOCKSTACK_TEST, CONFIG_PATH, BLOCKSTACK_DEBUG

import scripts

from .logger import get_logger

log = get_logger()

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


def user_zonefile_data_pubkey(user_zonefile, key_prefix='pubkey:data:'):
    """
    Get a user's data public key from their zonefile.
    There can be only one.

    Return the uncompressed data public key on success
    Return None if not defined
    Raise if there are multiple ones.
    """
    if not is_user_zonefile(user_zonefile):
        log.debug("invalid zone file")
        return None

    if 'txt' not in user_zonefile:
        return None

    data_pubkey = None
    # check that there is only one of these
    for txtrec in user_zonefile['txt']:
        if isinstance(txtrec['txt'], list) or not txtrec['txt'].startswith(key_prefix):
            continue

        if data_pubkey is not None:
            msg = 'Invalid zone file: multiple data keys'
            log.error(msg)
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

    # compressed...
    pubkey_hex = keylib.key_formatting.compress(pubkey_hex)

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

    # if there's no scheme, then assume https://
    fixed_urls = []
    for url in ret:
        parts = urlparse.urlparse(url)
        if len(parts.scheme) == 0:
            url = 'https://' + url

        fixed_urls.append(url)

    return fixed_urls


def user_zonefile_txts(user_zonefile):
    """
    Given a user's zonefile, get the txt records.
    Return [{'name': name, 'txt': txt}]
    """
    assert is_user_zonefile(user_zonefile)

    if 'txt' not in user_zonefile:
        return None

    ret = copy.deepcopy(user_zonefile.get('txt', []))
    return ret


def add_user_zonefile_url(user_zonefile, url):
    """
    Add a url to a zonefile
    Return the new zonefile on success
    Return None on error or on duplicate URL
    """
    from .zonefile import url_to_uri_record

    assert is_user_zonefile(user_zonefile)

    # be strict--require a scheme!
    assert re.match(OP_URI_TARGET_PATTERN, url)

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


def add_user_zonefile_txt(user_zonefile, txt_name, txt_data):
    """
    Add a TXT record to a zone file
    Return the new zone file on success
    Return None on duplicate or error
    """

    assert is_user_zonefile(user_zonefile)
    user_zonefile.setdefault('txt', [])

    # avoid duplicates
    for txtrec in user_zonefile['txt']:
        name = txtrec['name']
        if txt_name == name:
            return None

    new_txtrec = {
        'name': txt_name,
        'txt': txt_data
    }

    user_zonefile['txt'].append(new_txtrec)
    assert is_user_zonefile(user_zonefile)
    return user_zonefile


def remove_user_zonefile_txt(user_zonefile, txt_name):
    """
    Remove a TXT record from a zone file.
    Return the new zone file on success.
    Return None on not found
    """

    assert is_user_zonefile(user_zonefile)
    
    if 'txt' not in user_zonefile:
        return None

    for txtrec in user_zonefile['txt']:
        name = txtrec['name']
        if name == txt_name:
            user_zonefile['txt'].remove(txtrec)

    return user_zonefile


def swap_user_zonefile_urls(user_zonefile, url_1, url_2):
    """
    Swap the locations of the URLs in a zonefile
    Return the new zonefile on success
    Return None on error
    """

    assert is_user_zonefile(user_zonefile)

    if 'uri' not in user_zonefile:
        return None

    if len(user_zonefile['uri']) <= url_1:
        return None

    if len(user_zonefile['uri']) <= url_2:
        return None

    tmp = user_zonefile['uri'][url_2]
    user_zonefile['uri'][url_2] = user_zonefile['uri'][url_1]
    user_zonefile['uri'][url_1] = tmp

    return user_zonefile


def make_empty_user_profile( config_path=CONFIG_PATH ):
    """
    Given a user's name, create an empty profile.
    """
    
    ret = {
        '@type': 'Person',
        'accounts': []
    }

    return ret


def put_immutable_data_zonefile(user_zonefile, data_id, data_hash, data_url=None):
    """
    Add a data hash to a user's zonefile.  Make sure it's a valid hash as well.
    Return True on success
    Return False otherwise.
    """

    if not is_user_zonefile(user_zonefile):
        log.debug("Invalid zone file structure")
        return False

    data_hash = str(data_hash)
    assert scripts.is_valid_hash(data_hash)

    k = get_immutable_data_hashes(user_zonefile, data_id)
    if k is not None and len(k) > 0:
        # exists or name collision
        log.debug("collision on {} ({})".format(data_id, k))
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
    if not is_user_zonefile(user_zonefile):
        log.debug("Not a valid zone file")
        return False

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
