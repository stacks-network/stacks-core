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

import data
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

def _get_account_datastore_name(account_info):
    """
    Get the name for an account datastore
    """
    user_id = account_info['user_id']
    app_fqu = account_info['name']
    appname = account_info['appname']

    datastore_name = app.app_account_datastore_name( app.app_account_name(user_id, app_fqu, appname) )
    return datastore_name


def get_account_datastore_creds( account_info, user_privkey_hex ):
    """
    Get an account datastore's name and private key
    """
    datastore_privkey_hex = app.app_account_get_privkey( user_privkey_hex, account_info )
    user_id = account_info['user_id']
    datastore_name = _get_account_datastore_name(account_info)

    return {'user_id': user_id, 'datastore_name': datastore_name, 'datastore_privkey': datastore_privkey_hex}


def get_account_datastore(account_info, proxy=None, config_path=CONFIG_PATH ):
    """
    Get the datastore for the given account
    @account_info is the account information
    return {'status': True} on success
    return {'error': ...} on failure
    """
    user_id = account_info['user_id']
    datastore_name = _get_account_datastore_name(account_info)
    datastore_pubkey = str(account_info['public_key'])
    log.debug("Get account datastore {}".format(datastore_name))
    return data.get_datastore(user_id, datastore_name, datastore_pubkey, config_path=config_path, proxy=proxy ) 


def get_user_datastore(user_info, datastore_name, proxy=None, config_path=CONFIG_PATH ):
    """
    Get the datastore for the given user
    @account_info is the account information
    return {'status': True} on success
    return {'error': ...} on failure
    """
    user_id = user_info['user_id']
    datastore_pubkey = str(user_info['public_key'])
    log.debug("Get user datastore {}".format(datastore_name))
    return data.get_datastore(user_id, datastore_name, datastore_pubkey, config_path=config_path, proxy=proxy ) 


def get_account_datastore_info( master_data_privkey, user_id, app_fqu, app_name, config_path=CONFIG_PATH, proxy=None ):
    """
    Get information about an account datastore.
    At least, get the user and account owner.

    Return {'status': True, 'user': user, 'user_privkey': ..., 'account': account, 'datastore': ..., 'datastore_privkey': ...} on success.
    If master_data_privkey is not given, then user_privkey and datastore_privkey will not be provided.

    Return {'error': ...} on failure
    """
  
    master_data_pubkey = get_pubkey_hex(master_data_privkey)

    # get user info
    user_info = data.get_user(user_id, master_data_privkey, config_path=config_path)
    if 'error' in user_info:
        return user_info

    if not user_info['owned']:
        # we have to own this user, since this is an account-specific datastore
        return {'error': 'This wallet does not own this user'}

    user = user_info['user']

    user_privkey_hex = user_db.user_get_privkey(master_data_privkey, user, config_path=config_path)
    if user_privkey_hex is None:
        return {'error': 'Failed to load user private key'}
    
    res = app.app_load_account(user_id, app_fqu, app_name, user['public_key'], config_path=config_path)
    if 'error' in res:
        return res

    acct = res['account']

    res = get_account_datastore(acct, proxy=proxy, config_path=config_path)
    if 'error' in res:
        log.debug("Failed to get datastore for {}".format(user_id))
        return res

    datastore = res['datastore']
    datastore_privkey_hex = None

    if user_privkey_hex is not None:
        datastore_privkey_hex = app.app_account_get_privkey( user_privkey_hex, acct )
        if datastore_privkey_hex is None:
            return {'error': 'Failed to load app account private key'}


    ret = {
        'user': user,
        'account': acct,
        'datastore': datastore,
        'status': True
    }

    if user_privkey_hex is not None:
        ret['user_privkey'] = user_privkey_hex

    if datastore_privkey_hex is not None:
        ret['datastore_privkey'] = datastore_privkey_hex

    return ret


def get_user_datastore_info( master_data_privkey, user_id, datastore_name, config_path=CONFIG_PATH, proxy=None ):
    """
    Get information about a datastore that belongs directly to a user (without an account)
    If master_data_privkey is not None, then also get the datastore private key.

    Return {'status': True, 'user': user, 'user_privkey': ..., 'datastore': ..., 'datastore_privkey': ...} on success.
    If master_data_privkey is not given, then user_privkey and datastore_privkey will not be provided.

    Return {'error': ...} on failure
    """
    
    master_data_pubkey = get_pubkey_hex(master_data_privkey)

    res = data.get_user(user_id, master_data_privkey, config_path=config_path)
    if 'error' in res:
        return res

    user = res['user']
    user_pubkey = user['public_key']
        
    user_privkey_hex = user_db.user_get_privkey(master_data_privkey, user, config_path=config_path)
    if user_privkey_hex is None:
        return {'error': 'Failed to load user private key'}
    
    res = get_user_datastore(user, datastore_name, proxy=proxy, config_path=config_path)
    if 'error' in res:
        return res
    
    datastore = res['datastore']
    datastore_privkey_hex = user_privkey_hex

    ret = {
        'user': user,
        'datastore': datastore,
        'status': True
    }

    if datastore_privkey_hex is not None:
        ret['datastore_privkey'] = datastore_privkey_hex

    return ret


def get_datastore_name_info( user_id, datastore_id ):
    """
    Parse a datastore ID into an application blockchain ID and name, if 
    the datastore ID refers to an account-owned datastore.
    
    Return {'app_fqu': app_fqu, 'appname': appname, 'datastore_name': datastore_name} on success
    Return {'error': ...} on error
    """
    account_name_parts = app.app_account_parse_datastore_name(datastore_id)
    app_fqu = None
    appname = None
    datastore_name = None

    if account_name_parts is not None:
        # this is an account-specific datastore
        if user_id != account_name_parts['user_id']:
            return {'error': 'Invalid user ID for given data store name'}

        app_fqu = account_name_parts['app_blockchain_id']
        appname = account_name_parts['app_name']
    
    else:
        # this is a generic datastore
        datastore_name = datastore_id

    return {'app_fqu': app_fqu, 'appname': appname, 'datastore_name': datastore_name}    


def get_datastore_info( user_id, datastore_id, wallet_keys, include_private=False, config_path=CONFIG_PATH, proxy=None, password=None ):
    """
    Get datastore information.  If the datastore information is not locally hosted, then user_id must be a blockchain ID that points to the
    zone file with the master public key.

    Returns {
        'datastore': datastore record,
        'datastore_privkey': datastore private key (if include_private is True and we have the ciphertext locally).  Hex-encoded
        'app_fqu': name that points to owner of the application for which this datastore holds the user's data (if defined)
        'appname': name of application for which this datastore holds the user's data the datastore (if defined)
        'datastore_name': name of datastore
        'master_data_pubkey': master data public key
        'master_data_privkey': master data private key (only given if include_private is True)
    }

    Returns {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    config_dir = os.path.dirname(config_path)

    account_name_parts = app.app_account_parse_datastore_name(datastore_id)
    app_fqu = None
    appname = None
    datastore_name = None
    master_data_privkey = None
    datastore_privkey_hex = None

    name_info = get_datastore_name_info(user_id, datastore_id)
    if 'error' in name_info:
        # user ID mismatch
        return name_info

    app_fqu = name_info['app_fqu']
    appname = name_info['appname']
    datastore_name = name_info['datastore_name']

    assert wallet_keys
    assert wallet_keys.has_key('data_privkey')
    master_data_privkey = wallet_keys['data_privkey']
    master_data_pubkey = get_pubkey_hex(master_data_privkey)

    datastore_info = None
    datastore = None

    if app_fqu is not None and appname is not None:
        log.debug("Datastore {} is an account datastore".format(datastore_id))
        datastore_info = get_account_datastore_info( master_data_privkey, user_id, app_fqu, appname, config_path=config_path, proxy=proxy )

    else:
        log.debug("Datastore {} is a user datastore".format(datastore_id))
        datastore_info = get_user_datastore_info( master_data_privkey, user_id, datastore_name, config_path=config_path, proxy=proxy )

    if 'error' in datastore_info:
        log.error("Failed to get datastore information")
        return datastore_info

    datastore = datastore_info['datastore']
    if include_private:
        datastore_privkey_hex = datastore_info['datastore_privkey']
        
    ret = {
        'datastore': datastore,
        'datastore_privkey': datastore_privkey_hex,
        'datastore_info': datastore_info,
        'app_fqu': app_fqu,
        'appname': appname,
        'datastore_name': datastore_name,
        'master_data_pubkey': master_data_pubkey,
    }
    
    if include_private:
        ret['master_data_privkey'] = master_data_privkey

    return ret


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


def blockstack_datastore_url( user_id, datastore_id, path ):
    """
    Make a blockstack:// URL for a datastore record
    """
    assert re.match(schemas.OP_URLENCODED_PATTERN, user_id)
    assert re.match(schemas.OP_URLENCODED_PATTERN, datastore_id)

    path = '/'.join( [urllib.quote(p) for p in posixpath.normpath(path).split('/')] )

    return 'blockstack://{}@{}/{}'.format(urllib.quote(datastore_id), urllib.quote(user_id), path)


def blockstack_mutable_data_url_parse(url):
    """
    Parse a blockstack:// URL for mutable data
    Return (blockchain ID, data ID, data version, user ID, datastore ID) on success.
    The data ID will be a path if user ID and datastore ID are given; if the path ends in '/', then a directory is specifically requested.
    The version may be None if not given (in which case, the latest value is requested).
    """

    url = str(url)
    mutable_url_data_regex = r'^blockstack://({}+)[/]+({}+)[/]*(#[0-9]+)?$'.format(B40_CLASS, URLENCODED_CLASS)
    datastore_url_data_regex = r"^blockstack://({}+)@({}+)[/]+({}+)$".format(schemas.OP_DATASTORE_ID_CLASS, schemas.OP_USER_ID_CLASS, URLENCODED_PATH_CLASS)

    blockchain_id, data_id, version, user_id, datastore_id = None, None, None, None, None
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

        return urllib.unquote(blockchain_id), data_id, version, None, None

    # datastore?
    m = re.match(datastore_url_data_regex, url)
    if m:

        datastore_id, user_id, path = m.groups()
        if path.endswith('/'):
            is_dir = True
        
        # unquote 
        path = '/' + '/'.join([urllib.unquote(p) for p in posixpath.normpath(path).split('/')])
        if is_dir:
            path += '/'

        return None, urllib.unquote(path), version, user_id, datastore_id

    return None, None, None, None, None


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
            blockchain_id, data_id, version, user_id, datastore_id = (
                blockstack_mutable_data_url_parse(url)
            )

            url_type = 'mutable'
            assert (blockchain_id is None and user_id is not None and datastore_id is not None) or (blockchain_id is not None and user_id is None and datastore_id is None)

            if blockchain_id is not None:
                fields['version'] = version

            else:
                fields['datastore_id'] = datastore_id
                fields['user_id'] = user_id

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


def blockstack_data_url(field_dict):
    """
    Make a blockstack:// URL from constituent fields.
    Takes the output of blockstack_data_url_parse
    Return the URL on success
    Raise on error
    """
    assert 'blockchain_id' in field_dict
    assert 'type' in field_dict
    assert field_dict['type'] in ['mutable', 'immutable']
    assert 'data_id' in field_dict
    assert 'fields' in field_dict
    assert 'data_hash' in field_dict['fields'] or 'version' in field_dict['fields']

    if field_dict['type'] == 'immutable':
        return blockstack_immutable_data_url(
            field_dict['blockchain_id'], field_dict['data_id'], field_dict['fields']['data_hash']
        )

    if field_dict['fields'].has_key('user_id') and field_dict['fields'].has_key('datastore_id'):
        return blockstack_datastore_url(
            field_dict['fields']['user_id'], field_dict['fields']['datastore_id'], field_dict['data_id']
        )

    return blockstack_mutable_data_url(
        field_dict['blockchain_id'], field_dict['data_id'], field_dict['fields']['version']
    )


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
    user_id = None
    datastore_id = None
    
    url_info = blockstack_data_url_parse(url)
    if url_info is None:
        return {'error': 'Failed to parse {}'.format(url)}

    data_id = url_info['data_id']
    blockchain_id = url_info['blockchain_id']
    url_type = url_info['type']
    fields = url_info['fields']

    if url_type == 'mutable':
        version = fields.get('version')
        user_id = fields.get('user_id')
        datastore_id = fields.get('datastore_id')
        mutable = True

    else:
        data_hash = fields.get('data_hash')
        immutable = True

    if mutable:
        if user_id is not None and datastore_id is not None:
            # get from datastore
            if wallet_keys is None:
                raise PasswordRequiredException("need wallet keys to access data stores")

            assert wallet_keys, "Need wallet keys to access data stores"
            datastore_info = get_datastore_info(user_id, datastore_id, config_path=config_path, proxy=proxy, wallet_keys=wallet_keys)
            if 'error' in datastore_info:
                return datastore_info

            datastore = datastore_info['datastore']

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
