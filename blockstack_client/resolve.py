#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016-2017 by Blockstack.org

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
import re
import json
import hashlib
import urllib
import urllib2
import base64
import posixpath
import errno

import data
from keys import get_pubkey_hex
import app
import user as user_db
import wallet
import schemas

from config import get_logger
from constants import CONFIG_PATH, BLOCKSTACK_TEST, BLOCKSTACK_DEBUG
from scripts import is_name_valid, is_valid_hash
import string

class PasswordRequiredException(Exception):
    pass

log = get_logger('blockstack-client')

B40_CHARS = string.digits + string.lowercase + '-_.+'
B40_CLASS = '[a-z0-9\-_.+]'
B40_NO_PERIOD_CLASS = '[a-z0-9\-_+]'
B40_REGEX = '^{}*$'.format(B40_CLASS)
URLENCODED_CLASS = '[a-zA-Z0-9\-_.~%]'
URLENCODED_PATH_CLASS = '[a-zA-Z0-9\-_.~%/]'


def get_datastore_creds( master_data_privkey=None, app_domain=None, app_user_privkey=None, config_path=CONFIG_PATH ):
    """
    Get datastore credentials
    Return {'status': True, 'datastore_privkey': ..., 'datastore_id': ...} on success
    Return {'error': ...} on error
    """

    assert app_user_privkey is not None or (master_data_privkey is not None and app_domain is not None), "Invalid creds: need app_domain and master_data_privkey, or app_user_privkey"

    if app_user_privkey is None:
        app_user_privkey = data.datastore_get_privkey( master_data_privkey, app_domain, config_path=CONFIG_PATH )
        if app_user_privkey is None:
            return {'error': 'Failed to load app user private key', 'errno': errno.EPERM}

    app_user_pubkey = get_pubkey_hex(app_user_privkey)
    datastore_id = data.datastore_get_id(app_user_pubkey)

    ret = {
        'status': True,
        'datastore_privkey': app_user_privkey,
        'datastore_pubkey': app_user_pubkey,
        'datastore_id': datastore_id
    }

    return ret


def get_datastore_info( datastore_id=None, app_user_privkey=None, master_data_privkey=None, app_domain=None, config_path=CONFIG_PATH, proxy=None ):
    """
    Get information about an account datastore.
    At least, get the user and account owner.

    Return {'status': True, 'datastore': ..., 'datastore_id': ..., ['datastore_privkey': ...}] on success.

    Return {'error': ...} on failure
    """

    datastore_privkey = None

    if app_user_privkey is not None or (master_data_privkey is not None and app_domain is not None):
        creds = get_datastore_creds(master_data_privkey, app_domain=app_domain, app_user_privkey=app_user_privkey, config_path=config_path)
        if 'error' in creds:
            return creds
        
        if datastore_id is not None:
            assert datastore_id == creds['datastore_id'], "Datastore mismatch: {} != {}".format(datastore_id, creds['datastore_id'])

        datastore_privkey = creds['datastore_privkey']
        datastore_id = creds['datastore_id']

    assert datastore_id, 'No datastore ID given'

    res = data.get_datastore(datastore_id, config_path=config_path, proxy=proxy )
    if 'error' in res:
        return res

    if datastore_privkey is not None:
        res['datastore_privkey'] = datastore_privkey

    if datastore_id is not None:
        res['datastore_id'] = datastore_id
    else:
        res['datastore_id'] = data.datastore_get_id(res['datastore']['pubkey'])

    return res


def blockstack_mutable_data_url(blockchain_id, data_id, version):
    """
    Make a blockstack:// URL for mutable data
    data_id must be url-quoted
    """
    assert re.match(schemas.OP_URLENCODED_PATTERN, data_id)

    if version is None:
        return 'blockstack://{}/{}'.format(
            urllib.quote(blockchain_id), data_id
        )

    if not isinstance(version, (int, long)):
        raise ValueError('Verison must be an int or long')

    return 'blockstack://{}/{}#{}'.format(
        urllib.quote(blockchain_id), data_id, str(version)
    )


def blockstack_immutable_data_url(blockchain_id, data_id, data_hash):
    """
    Make a blockstack:// URL for immutable data
    data_id must be url-quoted
    """
    assert re.match(schemas.OP_URLENCODED_PATTERN, data_id)

    if data_hash is not None and not is_valid_hash(data_hash):
        raise ValueError('Invalid hash: {}'.format(data_hash))

    if data_hash is not None:
        return 'blockstack://{}.{}/#{}'.format(
            data_id, urllib.quote(blockchain_id), data_hash
        )

    return 'blockstack://{}.{}'.format(
        data_id, urllib.quote(blockchain_id)
    )


def blockstack_datastore_url( datastore_id, app_domain, path, version=None ):
    """
    Make a blockstack:// URL for a datastore record
    """
    assert re.match(schemas.OP_URLENCODED_PATTERN, datastore_id)
    assert re.match(schemas.OP_URLENCODED_PATTERN, app_domain)
    assert '@' not in datastore_id

    path = '/'.join( [urllib.quote(p) for p in posixpath.normpath(path).split('/')] )

    if version is not None:
        return 'blockstack://{}@{}/{}#{}'.format(urllib.quote(datastore_id), urllib.quote(app_domain), path, version)
    else:
        return 'blockstack://{}@{}/{}'.format(urllib.quote(datastore_id), urllib.quote(app_domain), path)


def blockstack_mutable_data_url_parse(url):
    """
    Parse a blockstack:// URL for mutable data
    Return (blockchain ID, data ID, data version, datastore ID) on success.
    The data ID will be a path if user ID and datastore ID are given; if the path ends in '/', then a directory is specifically requested.
    The version may be None if not given (in which case, the latest value is requested).
    """

    url = str(url)
    mutable_url_data_regex = r'^blockstack://({}+)[/]+({}+)[/]*(#[0-9]+)?$'.format(B40_CLASS, URLENCODED_CLASS)
    datastore_url_data_regex = r"^blockstack://({}+)@({}+)[/]+({}+)[/]*(#[0-9]+)?$".format(URLENCODED_CLASS, URLENCODED_CLASS, URLENCODED_PATH_CLASS, URLENCODED_CLASS)

    blockchain_id, data_id, version, app_domain = None, None, None, None
    is_dir = False

    # mutable?
    m = re.match(mutable_url_data_regex, url)
    if m:

        blockchain_id, data_id, version = m.groups()
        if not is_name_valid(blockchain_id):
            raise ValueError('Invalid blockchain ID "{}"'.format(blockchain_id))

        # version?
        if version is not None:
            version = version.strip('#/')
            version = int(version)

        return urllib.unquote(blockchain_id), data_id, version, None

    # datastore?
    m = re.match(datastore_url_data_regex, url)
    if m:

        datastore_id, app_domain, path, version = m.groups()
        if path.endswith('/'):
            is_dir = True
        
        # version?
        if version is not None:
            version = version.strip('#/')
            version = int(version)

        # unquote 
        path = '/' + '/'.join([urllib.unquote(p) for p in posixpath.normpath(path).split('/')])
        if is_dir:
            path += '/'

        return urllib.unquote(datastore_id), urllib.unquote(path), version, urllib.unquote(app_domain)

    return None, None, None, None


def blockstack_immutable_data_url_parse(url):
    """
    Parse a blockstack:// URL for immutable data
    Return (blockchain ID, data ID, data hash)
    * The hash may be None if not given, in which case, the hash should be looked up from the blockchain ID's profile.
    * The data ID may be None, in which case, the list of immutable data is requested.

    Raise on bad data
    """

    url = str(url)
    immutable_data_regex = r'^blockstack://({}+)\.({}+)\.({}+)[/]*([/]+#[a-fA-F0-9]+)?$'.format(
        URLENCODED_CLASS, B40_NO_PERIOD_CLASS, B40_NO_PERIOD_CLASS
    )
    immutable_listing_regex = r'^blockstack://({}+)[/]+#immutable$'.format(B40_CLASS)

    m = re.match(immutable_data_regex, url)
    if m:
        data_id, blockchain_name, namespace_id, data_hash = m.groups()
        blockchain_id = '{}.{}'.format(blockchain_name, namespace_id)

        if not is_name_valid(blockchain_id):
            log.debug('Invalid blockstack ID "{}"'.format(blockchain_id))
            raise ValueError('Invalid blockstack ID')

        if data_hash is not None:
            data_hash = data_hash.lower().strip('#/')
            if not is_valid_hash(data_hash):
                log.debug('Invalid data hash "{}"'.format(data_hash))
                raise ValueError('Invalid data hash')

        return urllib.unquote(blockchain_id), data_id, data_hash
    else:
        # maybe a listing?
        m = re.match(immutable_listing_regex, url)
        if not m:
            log.debug('Invalid immutable URL "{}"'.format(url))
            raise ValueError('Invalid immutable URL')

        blockchain_id = m.groups()[0]
        return urllib.unquote(blockchain_id), None, None

    return None, None, None


def blockstack_data_url_parse(url):
    """
    Parse a blockstack:// URL
    Return {
        'type': immutable|mutable
        'blockchain_id': blockchain ID
        'data_id': data_id
        'fields': { fields }
    } on success
    Fields will be either {'data_hash'} on immutable
    or {'version'} on mutable

    Return None on error
    """

    blockchain_id, data_id, url_type = None, None, None
    fields = {}

    try:
        blockchain_id, data_id, data_hash = blockstack_immutable_data_url_parse(url)
        assert blockchain_id is not None

        url_type = 'immutable'
        fields.update({'data_hash': data_hash})

        log.debug("Immutable data URL: {}".format(url))

    except (ValueError, AssertionError) as e1:
        log.debug("Not an immutable data URL: {}".format(url))

        try:
            blockchain_or_datastore_id, data_id, version, app_domain = (
                blockstack_mutable_data_url_parse(url)
            )

            url_type = 'mutable'
            if version:
                fields['version'] = version

            if app_domain is not None:
                fields['app_domain'] = app_domain
                fields['datastore_id'] = blockchain_or_datastore_id

            else:
                blockchain_id = blockchain_or_datastore_id
                fields['blockchain_id'] = blockchain_or_datastore_id

            log.debug("Mutable data URL: {}".format(url))

        except (ValueError, AssertionError) as e2:
            if BLOCKSTACK_TEST:
                log.exception(e2)

            log.debug('Unparseable URL "{}"'.format(url))
            return None

    ret = {
        'type': url_type,
        'blockchain_id': blockchain_id,
        'data_id': data_id,
        'fields': fields
    }

    return ret


def blockstack_url_fetch(url, proxy=None, config_path=CONFIG_PATH, wallet_keys=None):
    """
    Given a blockstack:// url, fetch its data.
    If the data is an immutable data url, and the hash is not given, then look up the hash first.
    If the data is a mutable data url, and the version is not given, then look up the version as well.

    Data from datastores requires wallet_keys

    Return {"data": data} on success
    Return {"error": error message} on error
    """
    mutable = False
    immutable = False
    blockchain_id = None
    data_id = None
    version = None
    data_hash = None
    
    url_info = blockstack_data_url_parse(url)
    if url_info is None:
        return {'error': 'Failed to parse {}'.format(url)}

    data_id = url_info['data_id']
    blockchain_id = url_info['blockchain_id']
    url_type = url_info['type']
    fields = url_info['fields']

    if url_type == 'mutable':
        datastore_id = fields.get('datastore_id')
        version = fields.get('version')
        app_domain = fields.get('app_domain')
        mutable = True

    else:
        data_hash = fields.get('data_hash')
        immutable = True

    if mutable:
        if app_domain is not None:
            # get from datastore
            datastore_info = get_datastore_info( datastore_id=datastore_id, config_path=config_path, proxy=proxy)
            if 'error' in datastore_info:
                return datastore_info

            datastore = datastore_info['datastore']
            if data.datastore_get_id(datastore['pubkey']) != datastore_id:
                return {'error': 'Invalid datastore ID'}

            # file or directory?
            is_dir = data_id.endswith('/')
            if is_dir:
                return data.datastore_listdir( datastore, data_id, config_path=config_path, proxy=proxy )
            else:
                return data.datastore_getfile( datastore, data_id, config_path=config_path, proxy=proxy )

        elif blockchain_id is not None:
            # get single data
            if version is not None:
                return data.get_mutable( data_id, proxy=proxy, ver_min=version, ver_max=version+1, blockchain_id=blockchain_id, fully_qualified_data_id=True )
            else:
                return data.get_mutable( data_id, proxy=proxy, blockchain_id=blockchain_id, fully_qualified_data_id=True )
       
        else:
            return {'error': 'Invalid URL'}

    else:
        if data_id is not None:
            # get single data
            if data_hash is not None:
                return data.get_immutable( blockchain_id, data_hash, data_id=data_id, proxy=proxy )

            else:
                return data.get_immutable_by_name( blockchain_id, data_id, proxy=proxy )

        else:
            # list data
            return data.list_immutable_data( blockchain_id, proxy=proxy, config_path=config_path )


class BlockstackURLHandle(object):
    """
    A file-like object that handles reads on blockstack URLs
    """

    def __init__(self, url, data=None, full_response=False, config_path=CONFIG_PATH, wallet_keys=None):
        self.name = url
        self.data = data
        self.full_response = full_response
        self.fetched = False
        self.config_path = config_path
        self.wallet_keys = wallet_keys

        self.offset = 0
        self.closed = False
        self.softspace = 0

        if data is None:
            self.newlines = None
        else:
            self.data_len = len(data)
            self.fetched = True
            self.newlines = self.make_newlines(data)

    def make_newlines(self, data):
        """
        Set up newlines
        """

        return tuple(nls for nls in ('\n', '\r', '\r\n') if nls in data)

    def fetch(self):
        """
        Lazily fetch the data on read
        """

        if not self.fetched:
            from .proxy import get_default_proxy

            proxy = get_default_proxy(config_path=self.config_path)
            data = blockstack_url_fetch(
                self.name, proxy=proxy, config_path=self.config_path
            )

            if data is None:
                msg = 'Failed to fetch "{}"'
                raise urllib2.URLError(msg.format(self.name))

            if 'error' in data:
                msg = 'Failed to fetch "{}": {}'
                raise urllib2.URLError(msg.format(self.name, data['error']))

            if self.full_response:
                self.data = json.dumps(data)
            else:
                self.data = data['data']
                if not isinstance(self.data, (str, unicode)):
                    self.data = json.dumps(data['data'])

            self.newlines = self.make_newlines(data)
            self.data_len = len(self.data)
            self.fetched = True

    def close(self):
        self.data = None
        self.closed = True

    def flush(self):
        pass

    def __iter__(self):
        return self

    def next(self):
        line = self.readline()
        if len(line) == 0:
            raise StopIteration()
        else:
            return line

    def read(self, numbytes=None):
        self.fetch()
        if self.offset >= self.data_len:
            return ''

        ret = []
        if numbytes is not None:
            ret = self.data[self.offset:min(self.data_len, self.offset + numbytes)]
            self.offset += numbytes
            self.offset = self.data_len if self.offset > self.data_len else self.offset
        else:
            ret = self.data[self.offset:]
            self.offset = self.data_len
            self.data = None

        return ret

    def readline(self, numbytes=None):
        if self.data is None:
            return ''

        next_newline_offset = self.data[self.offset:].find('\n')
        if next_newline_offset < 0:
            # no more newlines
            return self.read()
        else:
            line_data = self.read(next_newline_offset + 1)
            return line_data

    def readlines(self, sizehint=None):
        sizehint = self.data_len if sizehint is None else sizehint

        total_len = 0
        lines = []
        while total_len < sizehint:
            line = self.readline()
            lines.append(line)
            total_len += len(line)

        return lines


class BlockstackHandler(urllib2.BaseHandler):
    """
    URL opener for blockstack:// URLs.
    Usable with urllib2.
    """

    def __init__(self, full_response=False, config_path=CONFIG_PATH):
        self.full_response = full_response
        self.config_path = config_path

    def blockstack_open(self, req):
        """
        Open a blockstack URL
        """
        bh = BlockstackURLHandle(
            req.get_full_url(), full_response=self.full_response,
            config_path=self.config_path
        )

        return bh
