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


from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
import urlparse
import os
import posixpath
import logging
import sys
import urllib
from ConfigParser import SafeConfigParser
from common import get_logger, DEBUG, compress_chunk, decompress_chunk, get_driver_settings_dir

log = get_logger("blockstack-storage-drivers-gdrive")
log.setLevel( logging.DEBUG if DEBUG else logging.INFO )

GDRIVE_FOLDER_NAME = None
GDRIVE_FOLDER_ID = None
GDRIVE_COMPRESS = False
GDRIVE_HANDLE = None
GDRIVE_SETTINGS_PATH = None
RELOAD_DRIVE = False

GDRIVE_SETTINGS_YAML_TEMPLATE = """
client_config_backend: file
client_config_file: {}
save_credentials: True
save_credentials_backend: file
save_credentials_file: {}
get_refresh_token: True
"""

def make_config_file_contents(config_file_path, credentials_path):
    return GDRIVE_SETTINGS_YAML_TEMPLATE.format(config_file_path, credentials_path)


def get_gdrive_handle(settings_path=None, folder_name=None):
    """
    Sign into google drive, and set a few global variables
    that will be used in subsequent storage calls.
    """
    global GDRIVE_HANDLE, RELOAD_DRIVE

    if RELOAD_DRIVE:
        # trigger reload
        GDRIVE_HANDLE = None
        RELOAD_DRIVE = False

    if GDRIVE_HANDLE is not None:
        return GDRIVE_HANDLE

    if settings_path is None:
        assert GDRIVE_SETTINGS_PATH
        settings_path = GDRIVE_SETTINGS_PATH

    if folder_name is None:
        assert GDRIVE_FOLDER_NAME
        folder_name = GDRIVE_FOLDER_NAME

    gauth = GoogleAuth(settings_file=settings_path)
    gauth.LocalWebserverAuth()
    drive = GoogleDrive(gauth)

    GDRIVE_HANDLE = drive
    GDRIVE_FOLDER_ID = get_blockstack_folder_id(GDRIVE_HANDLE, folder_name)

    return drive


def get_blockstack_folder_id(drive, folder):
    """
    Make sure the blockstack-specific data folder exists.
    Return the folder ID
    """
    fid = None
    file_list = drive.ListFile({'q': "'root' in parents and trashed=false"}).GetList()
    for f in file_list:
        if f['title'] == folder:
            fid = f['id']

    if fid is not None:
        return fid

    # what's the root ID?
    f = drive.CreateFile({'title': folder, 'mimeType': 'application/vnd.google-apps.folder'})
    f.Upload()
    return f['id']


def get_chunk_via_http(url):
    """
    Get a shared Google Drive URL's data
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


def get_chunk_via_gdrive(drive, data_id):
    """
    Get data via Google Drive's API
    Return the data on success
    Return None on failure
    """
    global GDRIVE_FOLDER_ID, GDRIVE_FOLDER_NAME
    if GDRIVE_FOLDER_ID is None:
        fid = get_blockstack_folder_id(drive, GDRIVE_FOLDER_NAME)
        GDRIVE_FOLDER_ID = fid

    try:
        flist = drive.ListFile({'q': "title='{}' and '{}' in parents".format(data_id, GDRIVE_FOLDER_ID)}).GetList()
        for f in flist:
            if f['title'] == data_id:
                return f.GetContentString()
    
    except Exception as e:
        if DEBUG:
            log.exception(e)

        log.error("Failed to get {} from Google Drive".format(data_id))
        return False
    
    # not found
    log.debug("Not found: {}".format(data_id))
    return None


def get_url_type(url):
    """
    How do we handle this URL?
    Return ('http', url) if we use http to get this data
    Return ('gdrive', data_id) if we use gdrive to get this data
    Return None, None on invalid URL
    """

    # is this a direct URL to a google drive resource,
    # or is this a URL generated with get_mutable_url()?
    urlparts = urlparse.urlparse(url)
    urlpath = posixpath.normpath(urlparts.path)
    urlpath_parts = urlpath.strip('/').split('/')

    if len(urlpath_parts) != 2:
        log.error("Invalid URL {}".format(url))
        return None

    if urlpath_parts[0] == 'blockstack':
        return ('gdrive', urlpath_parts[1])

    else:
        return ('http', url)


def get_chunk(url):
    """
    Get a chunk from google drive, given its URL.
    Decompress and return it.
    """
    res = None
    data = None

    urltype, urlres = get_url_type(url)
    if urltype is None and urlres is None:
        log.error("Invalid URL {}".format(url))
        return None

    if urltype == 'gdrive':

        # request via Google Drive
        drive = get_gdrive_handle()
        log.debug("Fetch {} via gdrive ({})".format(url, urlres))
        data = get_chunk_via_gdrive(drive, urlres) 

    else:

        # request via HTTP
        log.debug("Fetch {} via HTTP".format(url))
        data = get_chunk_via_http(url)

    if data is None:
        return None

    # decompress 
    if GDRIVE_COMPRESS:
        try:
            res = decompress_chunk(data)
        except:
            res = data
            
    else:
        res = data

    return res


def put_chunk( drive, name, chunk_buf ):
    """
    Put a chunk into google drive.
    Compress it first.
    Return the URL
    """
    global GDRIVE_FOLDER_ID
    if GDRIVE_COMPRESS:
        compressed_chunk = compress_chunk(chunk_buf)
    else:
        compressed_chunk = chunk_buf

    name = urllib.quote(name.replace( "/", r"-2f" ))
    
    fid = None
    if GDRIVE_FOLDER_ID is not None:
        fid = GDRIVE_FOLDER_ID
    else:
        GDRIVE_FOLDER_ID = get_blockstack_folder_id(drive, GDRIVE_FOLDER_NAME)
        fid = GDRIVE_FOLDER_ID

    try:
        f = drive.CreateFile({'title': name, "parents": [{"kind": "drive#fileLink", "id": fid}]})

        if len(compressed_chunk) > 0:
            f.SetContentString(compressed_chunk)

        f.Upload()
        f.InsertPermission({'type': 'anyone', 'value': 'anyone', 'role': 'reader'})
        log.debug("File {} available at {}".format(name, f['webContentLink']))
        return True

    except Exception, e:
        if DEBUG:
            log.exception(e)

        log.error("Failed to save {} to Google Drive".format(name))
        return False


def delete_chunk( drive, name ):
    """
    Delete a chunk from google drive.
    Return True on success
    Return False on error
    """
    global GDRIVE_FOLDER_ID, GDRIVE_FOLDER_NAME
    if GDRIVE_FOLDER_ID is None:
        fid = get_blockstack_folder_id(drive, GDRIVE_FOLDER_NAME)
        GDRIVE_FOLDER_ID = fid

    name = urllib.quote(name.replace( "/", r"-2f" ))

    try:
        flist = drive.ListFile({'q': 'title="{}" and "{}" in parents'.format(name, GDRIVE_FOLDER_ID)}).GetList()
        for f in flist:
            if f['title'] == name:
                f.Delete()
                return True

    except Exception as e:
        if DEBUG:
            log.exception(e)

        log.error("Failed to delete {} from Google Drive".format(name))
        return False

    return False
    

def handles_url( url ):
    """
    Do we handle this URL?
    Must point to a Google Drive link
    """
    urltype, urlres = get_url_type(url)
    if urltype is None and urlres is None:
        # can't handle this
        return False

    urlparts = urlparse.urlparse(url)
    return urlparts.netlock.endswith("drive.google.com")


def make_mutable_url( data_id ):
    """
    Make a mutable data URL
    """
    data_id = urllib.quote( data_id.replace('/', '-2f') )
    url = 'https://drive.google.com/blockstack/{}'.format(data_id)
    return url


def get_immutable_handler( key, **kw ):
    """
    Get data by hash
    """
    drive = get_gdrive_handle()
    return get_chunk_via_gdrive(drive, 'immutable-{}'.format(key))


def get_mutable_handler( url, **kw ):
    """
    Get data by URL
    """
    return get_chunk(url)


def put_immutable_handler( key, data, txid, **kw ):
    """
    Put data by hash and txid
    """
    drive = get_gdrive_handle()
    return put_chunk(drive, "immutable-{}".format(key), data)


def put_mutable_handler( data_id, data_bin, **kw ):
    """
    Put data by file ID
    """
    drive = get_gdrive_handle()
    return put_chunk(drive, data_id, data_bin)


def delete_immutable_handler( key, txid, sig_key_txid, **kw ):
    """
    Delete by hash
    """
    drive = get_gdrive_handle()
    return delete_chunk(drive, "immutable-{}".format(key))


def delete_mutable_handler( data_id, signature, **kw ):
    """
    Delete by data ID
    """
    drive = get_gdrive_handle()
    return delete_chunk(drive, data_id.format(data_id))
    

def storage_init(conf, **kw):
    """
    Initialize google drive storage driver
    """
    global GDRIVE_FOLDER_NAME, GDRIVE_FOLDER_ID, GDRIVE_COMPRESS, GDRIVE_SETTINGS_PATH, RELOAD_DRIVE
    
    settings_path = None
    config_path = conf['path']

    if GDRIVE_FOLDER_ID is None or GDRIVE_HANDLE is None:
        RELOAD_DRIVE = True

    if os.path.exists( config_path ):

        parser = SafeConfigParser()
        
        try:
            parser.read(config_path)
        except Exception, e:
            log.exception(e)
            return False

        if parser.has_section('gdrive'):
            if not parser.has_option('gdrive', 'folder'):
                log.error("Config file {}: section 'gdrive' is missing 'folder'".format(config_path))
                return False

            if not parser.has_option('gdrive', 'settings'):
                log.warn("Config file {}: section 'gdrive' is missing 'settings'".format(config_path))
                settings_dir = get_driver_settings_dir(config_path, "gdrive")
                settings_path = os.path.join(settings_dir, "settings.yaml")
            else:
                settings_path = parser.get('gdrive', 'settings')

            if parser.get('gdrive', 'folder') != GDRIVE_FOLDER_NAME:
                RELOAD_DRIVE = True
            
            GDRIVE_FOLDER_NAME = parser.get('gdrive', 'folder')
            
            if parser.has_option('gdrive', 'compress'):
                GDRIVE_COMPRESS = (parser.get('gdrive', 'compress').lower() in ['1', 'true', 'yes'])

        else:
            log.error("Config file {}: no 'gdrive' section")
            return False

    if not os.path.exists(settings_path):
        # write default settings
        log.warn("Making default settings file at {}".format(settings_path))
        
        settings_dir = get_driver_settings_dir(config_path, "gdrive")
        if not os.path.exists(settings_dir):
            try:
                os.makedirs(settings_dir)
                os.chmod(settings_dir, 0700)
            except Exception as e:
                if DEBUG:
                    log.exception(e)
                log.error("Failed to make directories {}".format(settings_dir))
                return False

        client_config_path = os.path.join(settings_dir, "client_secrets.json")
        credentials_path = os.path.join(settings_dir, "credentials.json")
        config_file_text = make_config_file_contents(client_config_path, credentials_path)

        with open(settings_path, 'w') as f:
            f.write(config_file_text)

    GDRIVE_SETTINGS_PATH = settings_path
    return True


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
