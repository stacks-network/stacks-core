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
import requests
import urlparse
import zlib
import logging
import posixpath
import urllib
import hashlib
import threading

from ConfigParser import SafeConfigParser
from common import *

def import_non_local(name, custom_name=None):
    import imp, sys

    custom_name = custom_name or name

    f, pathname, desc = imp.find_module(name, sys.path[1:])
    module = imp.load_module(custom_name, f, pathname, desc)

    if f:
        f.close()

    return module

dropbox = import_non_local("dropbox")

log = get_logger("blockstack-storage-drivers-dropbox")
log.setLevel( logging.DEBUG if DEBUG else logging.INFO )

DROPBOX_TOKEN = None
INDEX_DIRNAME = "index"
DVCONF = None

BLOCKSTACK_DEBUG = (os.environ.get("BLOCKSTACK_DEBUG") == "1")


def dropbox_url_reformat(url):
    """
    Dropbox URLs end in ?dl=0 sometimes.
    Switch this to ?dl=1
    """
    if url.endswith("?dl=0"):
        url = url[:len(url) - len("?dl=0")] + "?dl=1"

    return url


def dropbox_put_chunk( dvconf, chunk_buf, name ):
    """
    Driver-level call to put data.

    Returns the URL to the data stored on success.
    Returns None on error
    """
    log.debug("Putting on dropbox")
    driver_info = dvconf['driver_info']
    dropbox_token = driver_info['dropbox_token']
    if dropbox_token is None:
        log.warn("No dropbox token set")
        return None


    dbx = dropbox.Dropbox(dropbox_token)
    log.debug("Connected dropbox")

    chunk_buf = str(chunk_buf)

    try:
        file_info = dbx.files_upload(chunk_buf, name, mode=dropbox.files.WriteMode('overwrite'))

        # share it
        link_info = dbx.sharing_create_shared_link(name, short_url=False)
        url = dropbox_url_reformat(link_info.url)

        log.debug("{} available at {}".format(name, url))
        return url
    except Exception as e:
        if DEBUG:
            log.exception(e)

        log.error("Failed to save {} bytes to {} in Dropbox".format(len(chunk_buf), name))
        return None


def dropbox_delete_chunk(dvconf, name):
    """
    Delete a chunk from dropbox
    Return True on success
    Return False on error
    """
    
    driver_info = dvconf['driver_info']
    dropbox_token = driver_info['dropbox_token']
    if dropbox_token is None:
        log.warn("No dropbox token set")
        return None

    dbx = dropbox.Dropbox(dropbox_token)

    try:
        dbx.files_delete(name)
        return True
    except Exception, e:
        log.exception(e)
        return False


def dropbox_get_chunk(dvconf, name):
    """
    Get a chunk via dropbox
    Return the data on success
    Return None on error
    """

    driver_info = dvconf['driver_info']
    dropbox_token = driver_info['dropbox_token']
    if dropbox_token is None:
        log.warn("No dropbox token set")
        return None

    dbx = dropbox.Dropbox(dropbox_token)

    try:
        metadata, req = dbx.files_download(name)
        if req.status_code != 200:
            log.debug("Dropbox files_download {} status code {}".format(name, req.status_code))
            return None

        return req.text
    except Exception, e:
        log.error("Failed to load {}".format(name))
        return None
    

def storage_init(conf, index=False, force_index=False, **kwargs):
    """
    Initialize dropbox storage driver
    """
    global DROPBOX_TOKEN, DVCONF
    compress = False
    config_path = conf['path']

    if os.path.exists( config_path ):

        parser = SafeConfigParser()
        
        try:
            parser.read(config_path)
        except Exception, e:
            log.exception(e)
            return False

        if parser.has_section('dropbox'):
            if parser.has_option('dropbox', 'token'):
                DROPBOX_TOKEN = parser.get('dropbox', 'token')

            if parser.has_option('dropbox', 'compress'):
                compress = (parser.get('dropbox', 'compress').lower() in ['1', 'true', 'yes'])

    # need the token 
    if DROPBOX_TOKEN is None:
        log.warn("Config file '{}': section 'dropbox' is missing 'token'.  Write access will be disabled".format(config_path))

    # set up driver 
    DVCONF = driver_config("dropbox", config_path, dropbox_get_chunk, dropbox_put_chunk, dropbox_delete_chunk, driver_info={'dropbox_token': DROPBOX_TOKEN}, index_stem=INDEX_DIRNAME, compress=compress)
    if index:
        # instantiate the index 
        url = index_setup(DVCONF, force=force_index)
        if not url:
            log.error("Failed to set up index")
            return False

    return True


def handles_url( url ):
    """
    Do we handle this URL?
    Must point to a dropbox link
    """
    urltype, urlres = get_url_type(url)
    if urltype is None and urlres is None:
        # can't handle this
        return False

    urlparts = urlparse.urlparse(url)
    return urlparts.netloc.endswith(".dropbox.com")
    

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
  
   index_manifest_url = index_setup(DVCONF)
   assert index_manifest_url

   if len(sys.argv) > 1:
       # try to get these profiles 
       for name in sys.argv[1:]:
           prof = get_mutable_handler( make_mutable_url( name ), index_manifest_url=index_manifest_url, blockchain_id='test.id' )
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
      rd = get_immutable_handler( hash_data( d ), index_manifest_url=index_manifest_url, fqu='test.id' )
      if rd != d:
         raise Exception("get_immutable_handler('%s'): '%s' != '%s'" % (hash_data(d), d, rd))
      
   # get_mutable_handler
   print "get_mutable_handler"
   for i in xrange(0, len(test_data)):
      
      d_id, d, n, s, url = test_data[i]
      
      print "get {}".format(d_id)
      rd_json = get_mutable_handler( url, index_manifest_url=index_manifest_url, fqu='test.id' )
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
