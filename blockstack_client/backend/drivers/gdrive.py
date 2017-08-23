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


from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
import urlparse
import os
import posixpath
import logging
import sys
import urllib
from ConfigParser import SafeConfigParser
from common import *

log = get_logger("blockstack-storage-drivers-gdrive")
log.setLevel( logging.DEBUG if DEBUG else logging.INFO )

GDRIVE_FOLDER_NAME = None
GDRIVE_FOLDER_ID = None
GDRIVE_COMPRESS = False
GDRIVE_HANDLE = None
GDRIVE_SETTINGS_PATH = None
RELOAD_DRIVE = False
DVCONF = None
INDEX_DIRNAME = "/index"

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


def gdrive_put_chunk( dvconf, chunk_buf, name ):
    """
    Driver-level call to put data.

    Returns the URL to the data stored on success.
    Returns None on error
    """
    global GDRIVE_FOLDER_ID
    if GDRIVE_COMPRESS:
        compressed_chunk = compress_chunk(chunk_buf)
    else:
        compressed_chunk = chunk_buf

    name = urllib.quote(name.replace( "/", r"-2f" ))
    drive = get_gdrive_handle()

    fid = None
    if GDRIVE_FOLDER_ID is not None:
        fid = GDRIVE_FOLDER_ID
    else:
        GDRIVE_FOLDER_ID = get_blockstack_folder_id(drive, GDRIVE_FOLDER_NAME)
        fid = GDRIVE_FOLDER_ID

    # does this file already exist?
    existing_fid = None
    try:
        flist = drive.ListFile({'q': 'title="{}" and "{}" in parents and trashed=false'.format(name, GDRIVE_FOLDER_ID)}).GetList()
        for f in flist:
            if f['title'] == name:
                existing_fid = f['id']
                log.debug("'{}' exists as '{}'".format(name, existing_fid))
                break

    except Exception, e:
        if DEBUG:
            log.exception(e)

        log.error("Failed to query {}".format(name))
        return None

    try:
        params = {'title': name, 'parents': [{'kind': 'drive#fileLink', 'id': fid}]}
        if existing_fid:
            params['fid'] = existing_fid

        f = drive.CreateFile(params)

        if len(compressed_chunk) > 0:
            f.SetContentString(compressed_chunk)

        f.Upload()

        if not existing_fid:
            f.InsertPermission({'type': 'anyone', 'value': 'anyone', 'role': 'reader'})
            log.debug("File {} available at {}".format(name, f['webContentLink']))

        else:
            log.debug("File {} already available at {}".format(name, f['webContentLink']))

        return f['webContentLink']

    except Exception, e:
        if DEBUG:
            log.exception(e)

        log.error("Failed to save {} to Google Drive".format(name))
        return None


def gdrive_delete_chunk(dvconf, name):
    """
    Delete a chunk from google drive
    Return True on success
    Return False on error
    """
    
    global GDRIVE_FOLDER_ID, GDRIVE_FOLDER_NAME
    if GDRIVE_FOLDER_ID is None:
        fid = get_blockstack_folder_id(drive, GDRIVE_FOLDER_NAME)
        GDRIVE_FOLDER_ID = fid

    name = urllib.quote(name.replace( "/", r"-2f" ))
    drive = get_gdrive_handle()

    try:
        flist = drive.ListFile({'q': 'title="{}" and "{}" in parents and trashed=false'.format(name, GDRIVE_FOLDER_ID)}).GetList()
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


def gdrive_get_chunk(dvconf, name):
    """
    Get a chunk via google drive
    Return the data on success
    Return None on error
    """
    global GDRIVE_FOLDER_ID, GDRIVE_FOLDER_NAME
    if GDRIVE_FOLDER_ID is None:
        fid = get_blockstack_folder_id(drive, GDRIVE_FOLDER_NAME)
        GDRIVE_FOLDER_ID = fid

    name = urllib.quote(name.replace( "/", r"-2f" ))
    drive = get_gdrive_handle()
    
    try:
        flist = drive.ListFile({'q': "title='{}' and '{}' in parents and trahsed=false".format(name, GDRIVE_FOLDER_ID)}).GetList()
        for f in flist:
            if f['title'] == name:
                return f.GetContentString()
    
    except Exception as e:
        if DEBUG:
            log.exception(e)

        log.error("Failed to get {} from Google Drive".format(name))
        return None
    
    # not found
    log.debug("Not found: {}".format(name))
    return None
        

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
    return urlparts.netloc.endswith("drive.google.com")


def make_mutable_url( data_id ):
    """
    The URL here is a misnomer, since only Dropbox.com
    can create public URLs.

    This URL here will instruct get_chunk() to go and search through
    the index for the target data.
    """
    return index_make_mutable_url('www.dropbox.com', data_id)


def get_immutable_handler( key, **kw ):
    """
    Get data by hash
    """
    return index_get_immutable_handler(DVCONF, key, **kw)


def get_mutable_handler( url, **kw ):
    """
    Get data by URL
    """
    return index_get_mutable_handler(DVCONF, url, **kw)


def put_immutable_handler( key, data, txid, **kw ):
    """
    Put data by hash and txid
    """
    return index_put_immutable_handler(DVCONF, key, data, txid, **kw)


def put_mutable_handler( data_id, data_bin, **kw ):
    """
    Put data by file ID
    """
    return index_put_mutable_handler(DVCONF, data_id, data_bin, **kw)


def delete_immutable_handler( key, txid, sig_key_txid, **kw ):
    """
    Delete by hash
    """
    return index_delete_immutable_handler(DVCONF, key, txid, sig_key_txid, **kw)


def delete_mutable_handler( data_id, signature, **kw ):
    """
    Delete by data ID
    """
    return index_delete_mutable_handler(DVCONF, data_id, signature, **kw)
    

def storage_init(conf, index=False, force_index=False, **kw):
    """
    Initialize google drive storage driver
    """
    global GDRIVE_FOLDER_NAME, GDRIVE_FOLDER_ID, GDRIVE_COMPRESS, GDRIVE_SETTINGS_PATH, RELOAD_DRIVE, DVCONF
    
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

    # set up driver 
    DVCONF = driver_config("gdrive", config_path, gdrive_get_chunk, gdrive_put_chunk, gdrive_delete_chunk, index_stem=INDEX_DIRNAME, compress=GDRIVE_COMPRESS)
    if index:
        # instantiate the index 
        url = index_setup(DVCONF, force=force_index)
        if not url:
            log.error("Failed to set up index")
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
