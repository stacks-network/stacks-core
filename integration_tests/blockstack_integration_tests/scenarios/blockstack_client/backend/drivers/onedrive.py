#!/usr/bin/env python2
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
import sys
import logging
import posixpath
import tempfile
import urllib
import base64
import urlparse
import time

import onedrivesdk
from onedrivesdk.helpers import GetAuthCodeServer
from common import get_driver_settings_dir, DEBUG, get_logger, compress_chunk, decompress_chunk, setup_scratch_space, make_scratch_file

from ConfigParser import SafeConfigParser

log = get_logger('blockstack-client-onedrive')

SESSION_SALE_PATH = None
REDIRECT_URL = None
CLIENT_ID = None
CLIENT_SECRET = None
CLIENT_SCOPES = ['wl.signin', 'wl.offline_access', 'onedrive.readwrite']
ONEDRIVE_FOLDER_NAME = None
ONEDRIVE_FOLDER_ID = None
ONEDRIVE_HANDLE = None
ONEDRIVE_COMPRESS = False
RELOAD_DRIVE = False
DOWNLOAD_SCRATCH_SPACE = None

def get_onedrive_handle(session_path=None):
    """
    Sign into Onedrive. 
    Return a session proxy on success
    Return None on error
    """
    global RELOAD_DRIVE, ONEDRIVE_HANDLE

    assert CLIENT_ID
    assert CLIENT_SECRET
    assert REDIRECT_URL

    if RELOAD_DRIVE:
        RELOAD_DRIVE = False
        ONEDRIVE_HANDLE = None

    if ONEDRIVE_HANDLE is not None:
        return ONEDRIVE_HANDLE

    if session_path is None:
        assert SESSION_SAVE_PATH
        session_path = SESSION_SAVE_PATH

    client = onedrivesdk.get_default_client(client_id=CLIENT_ID, scopes=CLIENT_SCOPES)
    if os.path.exists(session_path):
        # load session 
        log.debug("Load saved session")
        client.auth_provider.load_session(path=session_path)
        client.auth_provider.refresh_token()

    else:
        dirp = os.path.dirname(session_path)
        if not os.path.exists(dirp):
            try:
                os.makedirs(dirp)
                os.chmod(dirp, 0700)
            except Exception as e:
                if DEBUG:
                    log.exception(e)

                log.error("Failed to make directories to store session")
                return None

        # log in
        auth_url = client.auth_provider.get_auth_url(REDIRECT_URL)

        code = GetAuthCodeServer.get_auth_code(auth_url, REDIRECT_URL)
        client.auth_provider.authenticate(code, REDIRECT_URL, CLIENT_SECRET)

        # save for future user 
        client.auth_provider.save_session(path=session_path)

    ONEDRIVE_HANDLE = client
    return client


def get_blockstack_folder_id(client, folder_name):
    """
    Get the blockstack-designated folder id
    TODO: support any folder, not just a top-level folder

    Return the ID on success
    Return None on error
    """
    try:
        folder_info = client.item(drive='me', id='root').children[folder_name].get()
        assert folder_info.id is not None
        return folder_info.id
    except Exception as e:
        if DEBUG:
            log.exception(e)

        log.error("Failed to get folder '{}'".format(folder_name))
        return None


def get_chunk_via_http(url):
    """
    Get a shared Onedrive URL's data
    Return the data on success
    Return None on failure
    """
    try:
        req = requests.get(url)
        if req.status_code != 200:
            log.debug("GET %s status code %s" % (url, req.status_code))
            return None

        return req.c
    except Exception, e:
        log.exception(e)
        return None


def get_chunk_via_onedrive(drive, data_id):
    """
    Get data via Onedrive's API
    Return the data on success
    Return None on failure
    """
    global ONEDRIVE_FOLDER_ID, ONEDRIVE_FOLDER_NAME

    assert DOWNLOAD_SCRATCH_SPACE

    if ONEDRIVE_FOLDER_ID is None:
        assert ONEDRIVE_FOLDER_NAME
        fid = get_blockstack_folder_id(drive, ONEDRIVE_FOLDER_NAME)
        if fid is None:
            return None 

        ONEDRIVE_FOLDER_ID = fid
    
    scratch_path = make_scratch_file(DOWNLOAD_SCRATCH_SPACE)

    try:
        drive.item(drive='me', id=ONEDRIVE_FOLDER_ID).children[data_id].download(scratch_path)
    except Exception as e:
        if DEBUG:
            log.exception(e)
        
        log.error("Failed to download {}".format(data_id))
        return None

    data = None
    with open(scratch_path, 'r') as f:
        data = f.read()

    try:
        os.unlink(scratch_path)
    except:
        pass

    return data


def get_chunk(url):
    """
    Get a chunk from onedrive, given its URL.
    Decompress and return it.
    """
    res = None
    data = None

    urltype, urlres = get_url_type(url)
    if urltype is None and urlres is None:
        log.error("Invalid URL {}".format(url))
        return None

    if urltype == 'onedrive':

        # request via OneDrive
        drive = get_onedrive_handle()
        log.debug("Fetch {} via onedrive ({})".format(url, urlres))
        data = get_chunk_via_onedrive(drive, urlres) 

    else:

        # request via HTTP
        log.debug("Fetch {} via HTTP".format(url))
        data = get_chunk_via_http(url)

    if data is None:
        return None

    # decompress 
    if ONEDRIVE_COMPRESS:
        try:
            res = decompress_chunk(data)
        except:
            res = data
            
    else:
        res = data

    return res


def put_chunk( drive, name, chunk_buf ):
    """
    Put a chunk into onedrive.
    Compress it first.
    Return True on success
    Return False on error
    """
    global ONEDRIVE_FOLDER_ID, DOWNLOAD_SCRATCH_SPACE
    assert DOWNLOAD_SCRATCH_SPACE

    if ONEDRIVE_COMPRESS:
        compressed_chunk = compress_chunk(chunk_buf)
    else:
        compressed_chunk = chunk_buf

    name = base64.b64encode(name).replace('/', '_').replace('+', '-').replace('=', '~')
    
    fid = None
    if ONEDRIVE_FOLDER_ID is not None:
        fid = ONEDRIVE_FOLDER_ID
    else:
        assert ONEDRIVE_FOLDER_NAME
        ONEDRIVE_FOLDER_ID = get_blockstack_folder_id(drive, ONEDRIVE_FOLDER_NAME)
        if ONEDRIVE_FOLDER_ID is None:
            return False

        fid = ONEDRIVE_FOLDER_ID
   
    scratch_path = make_scratch_file(DOWNLOAD_SCRATCH_SPACE)
    with open(scratch_path, 'w') as f:
        f.write(chunk_buf)

    rc = None

    try:
        drive.item(drive='me', id=fid).children[name].upload(scratch_path)
        rc = True
    except Exception, e:
        if DEBUG:
            log.exception(e)

        log.error("Failed to save {} to OneDrive".format(name))
        rc = False

    finally:
        try:
            os.unlink(scratch_path)
        except:
            pass

    return rc


def delete_chunk( drive, name ):
    """
    Delete a chunk from onedrive.
    Return True on success
    Return False on error
    """
    global ONEDRIVE_FOLDER_ID, ONEDRIVE_FOLDER_NAME
    if ONEDRIVE_FOLDER_ID is None:
        assert ONEDRIVE_FOLDER_NAME
        fid = get_blockstack_folder_id(drive, ONEDRIVE_FOLDER_NAME)
        if fid is None:
            return None

        ONEDRIVE_FOLDER_ID = fid

    name = base64.b64encode(name).replace('/', '_').replace('+', '-').replace('=', '~')
    try:
        drive.item(drive='me', id=ONEDRIVE_FOLDER_ID).children[name].delete()
        return True

    except Exception as e:
        if DEBUG:
            log.exception(e)

        log.error("Failed to delete {}".format(name))
        return False
    

def get_url_type(url):
    """
    How do we handle this URL?
    Return ('http', url) if we use http to get this data
    Return ('onedrive', data_id) if we use gdrive to get this data
    Return None, None on invalid URL
    """

    # is this a direct URL to a onedrive resource,
    # or is this a URL generated with get_mutable_url()?
    urlparts = urlparse.urlparse(url)
    urlpath = posixpath.normpath(urlparts.path)
    urlpath_parts = urlpath.strip('/').split('/')

    if len(urlpath_parts) != 2:
        log.error("Invalid URL {}".format(url))
        return None

    if urlpath_parts[0] == 'blockstack':
        return ('onedrive', urlpath_parts[1])

    else:
        return ('http', url)


def handles_url( url ):
    """
    Do we handle this URL?
    Must point to a onedrive link
    """
    urltype, urlres = get_url_type(url)
    if urltype is None and urlres is None:
        # can't handle this
        return False

    urlparts = urlparse.urlparse(url)
    return urlparts.netlock.endswith("onedrive.live.com")


def make_mutable_url( data_id ):
    """
    Make a mutable data URL.
    It's not guaranteed to resolve to data via HTTP; it may instead
    encode information used by the driver.
    """
    data_id = base64.b64encode(data_id).replace('/', '_').replace('+', '-').replace('=', '~')
    url = 'https://onedrive.live.com/blockstack/{}'.format(data_id)
    return url


def get_immutable_handler( key, **kw ):
    """
    Get data by hash
    """
    drive = get_onedrive_handle()
    key = base64.b64encode( 'immutable-{}'.format(key) ).replace('/', '_').replace('+', '-').replace('=', '~')
    return get_chunk_via_onedrive(drive, key)


def get_mutable_handler( url, **kw ):
    """
    Get data by URL
    """
    return get_chunk(url)


def put_immutable_handler( key, data, txid, **kw ):
    """
    Put data by hash and txid
    """
    drive = get_onedrive_handle()
    return put_chunk(drive, "immutable-{}".format(key), data)


def put_mutable_handler( data_id, data_bin, **kw ):
    """
    Put data by file ID
    """
    drive = get_onedrive_handle()
    return put_chunk(drive, data_id, data_bin)


def delete_immutable_handler( key, txid, sig_key_txid, **kw ):
    """
    Delete by hash
    """
    drive = get_onedrive_handle()
    return delete_chunk(drive, "immutable-{}".format(key))


def delete_mutable_handler( data_id, signature, **kw ):
    """
    Delete by data ID
    """
    drive = get_onedrive_handle()
    return delete_chunk(drive, data_id.format(data_id))


def storage_init(conf, **kw):
    """
    Set up and load storage
    """
    global ONEDRIVE_FOLDER_NAME, ONEDRIVE_FOLDER_ID, ONEDRIVE_COMPRESS
    global CLIENT_ID, CLIENT_SECRET, REDIRECT_URL, SESSION_SAVE_PATH, RELOAD_DRIVE
    global DOWNLOAD_SCRATCH_SPACE
    
    config_path = conf['path']
    settings_dir = get_driver_settings_dir(config_path, 'onedrive')
    DOWNLOAD_SCRATCH_SPACE = os.path.join(settings_dir, ".scratch")
    SESSION_SAVE_PATH = os.path.join(settings_dir, 'onedrive.session')

    RELOAD_DRIVE = False

    if ONEDRIVE_FOLDER_ID is None or ONEDRIVE_HANDLE is None:
        RELOAD_DRIVE = True

    if os.path.exists( config_path ):

        parser = SafeConfigParser()
        
        try:
            parser.read(config_path)
        except Exception, e:
            log.exception(e)
            return False

        if parser.has_section('onedrive'):
            for required_section in ['folder', 'application_id', 'application_password']:
                if not parser.has_option('onedrive', required_section):
                    log.error("Config file {}: section 'onedrive' is missing '{}'".format(config_path, required_section))
                    return False

            if parser.get('onedrive', 'folder') != ONEDRIVE_FOLDER_NAME:
                RELOAD_DRIVE = True
            
            ONEDRIVE_FOLDER_NAME = parser.get('onedrive', 'folder')
            CLIENT_ID = parser.get('onedrive', 'application_id')
            CLIENT_SECRET = parser.get('onedrive', 'application_password')
            
            if parser.has_option('onedrive', 'compress'):
                ONEDRIVE_COMPRESS = (parser.get('onedrive', 'compress').lower() in ['1', 'true', 'yes'])

            if parser.has_option('onedrive', 'redirect_uri'):
                REDIRECT_URL = parser.get('onedrive', 'redirect_uri')
            else:
                REDIRECT_URL = "http://localhost:8080/"
            
        else:
            log.error("Config file {}: no 'onedrive' section")
            return False

    if not os.path.exists(settings_dir):
        try:
            os.makedirs(settings_dir)
            os.chmod(settings_dir, 0700)
        except Exception as e:
            if DEBUG:
                log.exception(e)

            log.error("Failed to set up settings directory")
            return False

    rc = setup_scratch_space(DOWNLOAD_SCRATCH_SPACE)
    if not rc:
        log.error("Failed to set up scratch space")
        return False

    return True


def get_classes():
    return ['read_public', 'write_private']


if __name__ == "__main__":
     
   import keylib
   import json 
   import virtualchain
   from virtualchain.lib.hashing import hex_hash160
   
   # hack around absolute paths
   current_dir =  os.path.abspath(os.path.dirname(__file__))
   sys.path.insert(0, current_dir)
   
   current_dir =  os.path.abspath(os.path.join( os.path.dirname(__file__), "..") )
   sys.path.insert(0, current_dir)
   
   from blockstack_client.storage import parse_mutable_data, serialize_mutable_data
   from blockstack_client.config import log, get_config
   
   CONFIG_PATH = os.environ.get('BLOCKSTACK_CONFIG_PATH', None)
   assert CONFIG_PATH, "Missing BLOCKSTACK_CONFIG_PATH from environment"

   conf = get_config(CONFIG_PATH)
   print json.dumps(conf, indent=4, sort_keys=True)

   pk = keylib.ECPrivateKey()
   data_privkey = pk.to_hex()
   data_pubkey = pk.public_key().to_hex()

   test_data = [
      ["my_first_datum",        "hello world",                              1, "unused", None],
      ["/my/second/datum",      "hello world 2",                            2, "unused", None],
      ["user\"_profile",          '{"name":{"formatted":"judecn"},"v":"2"}',  3, "unused", None],
      ["empty_string",          "",                                         4, "unused", None],
   ]
   
   def hash_data( d ):
      return hex_hash160( d )
   
   rc = storage_init(conf)
   if not rc:
      raise Exception("Failed to initialize")
  
   if len(sys.argv) > 1:
       # try to get these profiles 
       for name in sys.argv[1:]:
           prof = get_mutable_handler( make_mutable_url( name ) )
           if prof is None:
               raise Exception("Failed to get %s" % name)

           print json.dumps(prof, indent=4, sort_keys=True)
  
       sys.exit(0)

   # put_immutable_handler
   print "put_immutable_handler"
   for i in xrange(0, len(test_data)):
      
      d_id, d, n, s, url = test_data[i]
      
      print "store {} ({})".format(d_id, hash_data(d))

      rc = put_immutable_handler( hash_data( d ), d, "unused" )
      if not rc:
         raise Exception("put_immutable_handler('%s') failed" % d)
      
      
   # put_mutable_handler
   print "put_mutable_handler"
   for i in xrange(0, len(test_data)):
      
      d_id, d, n, s, url = test_data[i]
      
      data_url = make_mutable_url( d_id )
      
      print 'store {} with {}'.format(d_id, data_privkey)
      data_json = serialize_mutable_data( json.dumps({"id": d_id, "nonce": n, "data": d}), data_privkey)
      
      rc = put_mutable_handler( d_id, data_json )
      if not rc:
         raise Exception("put_mutable_handler('%s', '%s') failed" % (d_id, d))
     
      test_data[i][4] = data_url
      
   # get_immutable_handler
   print "get_immutable_handler"
   for i in xrange(0, len(test_data)):
      
      d_id, d, n, s, url = test_data[i]

      print "get {}".format(hash_data(d))
      rd = get_immutable_handler( hash_data( d ) )
      if rd != d:
         raise Exception("get_mutable_handler('%s'): '%s' != '%s'" % (hash_data(d), d, rd))
     

   # get_mutable_handler
   print "get_mutable_handler"
   for i in xrange(0, len(test_data)):
      
      d_id, d, n, s, url = test_data[i]
      
      print "get {}".format(d_id)
      rd_json = get_mutable_handler( url )
      if rd_json is None:
          raise Exception("Failed to get data {}".format(d_id))

      rd = parse_mutable_data( rd_json, data_pubkey )
      if rd is None:
         raise Exception("Failed to parse mutable data '%s'" % rd_json)
    
      rd = json.loads(rd)
      if rd['id'] != d_id:
         raise Exception("Data ID mismatch: '%s' != '%s'" % (rd['id'], d_id))
      
      if rd['nonce'] != n:
         raise Exception("Nonce mismatch: '%s' != '%s'" % (rd['nonce'], n))
      
      if rd['data'] != d:
         raise Exception("Data mismatch: '%s' != '%s'" % (rd['data'], d))
      
   # delete_immutable_handler
   print "delete_immutable_handler"
   for i in xrange(0, len(test_data)):
      
      d_id, d, n, s, url = test_data[i]
     
      print "delete {}".format(hash_data(d))
      rc = delete_immutable_handler( hash_data(d), "unused", "unused" )
      if not rc:
         raise Exception("delete_immutable_handler('%s' (%s)) failed" % (hash_data(d), d))
      
   # delete_mutable_handler
   print "delete_mutable_handler"
   for i in xrange(0, len(test_data)):
      
      d_id, d, n, s, url = test_data[i]
      
      print "delete {}".format(d_id)
      rc = delete_mutable_handler( d_id, "unused" )
      if not rc:
         raise Exception("delete_mutable_handler('%s') failed" % d_id)
