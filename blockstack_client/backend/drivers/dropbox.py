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
DROPBOX_COMPRESS = False
CONFIG_PATH = None
SETUP_INDEX = False
INDEX_DIRNAME = "index"

BLOCKSTACK_DEBUG = (os.environ.get("BLOCKSTACK_DEBUG") == "1")


def dropbox_url_reformat(url):
    """
    Dropbox URLs end in ?dl=0 sometimes.
    Switch this to ?dl=1
    """
    if url.endswith("?dl=0"):
        url = url[:len(url) - len("?dl=0")] + "?dl=1"

    return url


def index_make_bucket(bucket):
    """
    Make an index bucket.
    Return the URL
    """
    try:
        dbx = dropbox.Dropbox(DROPBOX_TOKEN)
        log.debug("Make index bucket {}".format(bucket))

        index_page = {}
        index_page_data = serialize_index_page(index_page)
        dbx.files_upload(index_page_data, bucket)
        link_info = dbx.sharing_create_shared_link(bucket, short_url=False)
        url = dropbox_url_reformat(link_info.url)
        return url
    except Exception as e:
        if DEBUG:
            log.exception(e)

        log.error("Failed to make bucket {}".format(bucket))
        return None


def index_setup():
    """
    Set up our index if we haven't already
    Return the index manifest URL on success
    Return True if already setup
    Return False on error
    """
    global SETUP_INDEX, CONFIG_PATH, DROPBOX_TOKEN
    assert CONFIG_PATH
    settings_dir = get_driver_settings_dir(CONFIG_PATH, "dropbox")
    assert os.path.exists(settings_dir)

    index_manifest_url_path = os.path.join(settings_dir, 'index_manifest_url')
    if os.path.exists(index_manifest_url_path):
        url = None
        with open(index_manifest_url_path, 'r') as f:
            url = f.read().strip()

        return url

    index_bucket_names = get_index_bucket_names()
    fq_index_bucket_names = ['/' + os.path.join(INDEX_DIRNAME, p) for p in index_bucket_names]

    index_manifest = {}
    for b in fq_index_bucket_names:
        bucket_url = index_make_bucket(b)
        if bucket_url is None:
            log.error("Failed to create bucket {}".format(b))
            return False

        index_manifest[b] = bucket_url

    # save index manifest 
    index_manifest_data = serialize_index_page(index_manifest)
    index_manifest_url = None
    try:
        dbx = dropbox.Dropbox(DROPBOX_TOKEN)
        dbx.files_upload(index_manifest_data, "/{}/index.manifest".format(INDEX_DIRNAME))
        link_info = dbx.sharing_create_shared_link("/{}/index.manifest".format(INDEX_DIRNAME), short_url=False)
        index_manifest_url = dropbox_url_reformat(link_info.url)
    except Exception as e:
        if DEBUG:
            log.exception(e)

        log.error("Failed to create index manifest")
        return False

    try:
        # flag it on disk
        log.debug("Save index manifest URL {} to {}".format(index_manifest_url, index_manifest_url_path))
        with open(index_manifest_url_path, 'w') as f:
            f.write(index_manifest_url)

    except:
        return False

    SETUP_INDEX = True
    return index_manifest_url


def index_get_page(**kw):
    """
    Get an index page
    Return the dict on success
    Return None on error
    """
    url = kw.get('url')
    dbx = kw.get('dbx')
    path = kw.get('path')

    assert url or (dbx and path)
    
    serialized_index_page = None
    if url:
        log.debug("Fetch index page {}".format(url))
        serialized_index_page = get_chunk_via_http(url)
    else:
        log.debug("Fetch index page {} via Dropbox".format(path))
        serialized_index_page = get_chunk_via_dropbox(dbx, path)

    if serialized_index_page is None:
        # failed to get index
        log.error("Failed to get index page {}".format(path))
        return None
    
    log.debug("Fetched {} bytes (type {})".format(len(serialized_index_page), type(serialized_index_page)))
    index_page = parse_index_page(serialized_index_page)
    if index_page is None:
        # invalid
        log.error("Invalid index page {}".format(path))
        return None

    return index_page


def index_set_page(dbx, path, index_page):
    """
    Store an index page
    Return True on success
    Return False on error
    """
    assert index_setup()

    new_serialized_index_page = serialize_index_page(index_page)
    rc = put_chunk(dbx, path, new_serialized_index_page, raw=True, index=False)
    if not rc:
        # failed 
        log.error("Failed to store index page {}".format(path))
        return False

    return True  


def index_insert( dbx, name, url ):
    """
    Insert a url into the index.
    Return True on success
    Return False if not.
    """
    assert index_setup()

    path = get_index_page_path(name, INDEX_DIRNAME)
    index_page = index_get_page(dbx=dbx, path=path)
    if index_page is None:
        index_page = {}

    index_page[name] = url
    return index_set_page(dbx, path, index_page)
    

def index_remove( dbx, name, url ):
    """
    Remove a url from the index.
    Return True on success
    Return False if not.
    """
    assert index_setup()

    path = get_index_page_path(name, INDEX_DIRNAME)
    index_page = index_get_page(dbx=dbx, path=path)
    if index_page is None:
        log.error("Failed to get index page {}".format(path))
        return False

    if name not in index_page:
        # already gone
        return True

    del index_page[name]
    return index_set_page(dbx, path, index_page)


def index_lookup( index_manifest_url, name ):
    """
    Given the name, find the URL
    Return the URL on success
    Return None on error
    """
    path = get_index_page_path(name, INDEX_DIRNAME)
    manifest_page = index_get_page(url=index_manifest_url)
    if manifest_page is None:
        log.error("Failed to get manifest page {}".format(index_manifest_url))
        return None

    if path not in manifest_page.keys():
        log.error("Bucket {} not in manifest".format(bucket))
        return None

    bucket_url = manifest_page[path]
    index_page = index_get_page(url=bucket_url)
    if index_page is None:
        log.error("Failed to get index page {}".format(path))
        return None

    return index_page.get(name, None)


def put_chunk( dbx, path, chunk_buf, raw=False, index=True ):
    """
    Put a chunk into dropbox.
    Compress it first.
    Return True on success
    Return False on error
    """
    if DROPBOX_COMPRESS and not raw:
        compressed_chunk = compress_chunk(chunk_buf)
    else:
        compressed_chunk = chunk_buf

    try:
        file_info = dbx.files_upload(compressed_chunk, path, mode=dropbox.files.WriteMode('overwrite'))

        # make it shared
        link_info = dbx.sharing_create_shared_link(path, short_url=False)
        url = dropbox_url_reformat(link_info.url)

        log.debug("{} available at {}".format(path, url))

        # preserve listing
        if index:
            name = os.path.basename(path)
            rc = index_insert( dbx, name, url )
            if not rc:
                log.error("Failed to insert {}, {}".format(name, url))
                return False

        return True

    except Exception, e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to save {} to Dropbox".format(path))
        return False


def get_chunk_via_dropbox(dbx, data_path):
    """
    Get a mutable datum by data ID, using a Dropbox handle
    data_path must be the full path to the data

    Return the data on success
    Return None on failure
    """
    try:
        metadata, req = dbx.files_download(data_path)
        if req.status_code != 200:
            log.debug("Dropbox files_download {} status code {}".format(data_path, req.status_code))
            return None

        return req.text
    except Exception, e:
        log.error("Failed to load {}".format(data_path))
        return None


def get_url_type(url):
    """
    How do we handle this URL?
    Return ('http', url) if we use http to get this data
    Return ('dropbox', data_id) if we use dropbox to get this data
    Return None, None on invalid URL
    """

    # is this a direct URL to a dropbox resource,
    # or is this a URL generated with get_mutable_url()?
    urlparts = urlparse.urlparse(url)
    urlpath = posixpath.normpath( urllib.unquote(urlparts.path) )
    urlpath_parts = urlpath.strip('/').split('/')

    if len(urlpath_parts) != 2:
        log.error("Invalid URL {}".format(url))
        return None

    if urlpath_parts[0] == 'blockstack':
        return ('dropbox', urlpath_parts[1])

    else:
        return ('http', url)


def get_chunk(url, blockchain_id, index_manifest_url=None):
    """
    Get a chunk from dropbox, given its URL and the blockchain ID that owns the target data.
    Decompress and return it.
    """
    res = None
    data = None

    urltype, urlres = get_url_type(url)
    if urltype is None and urlres is None:
        log.error("Invalid URL {}".format(url))
        return None

    if urltype == 'dropbox':
        
        # look through the index for this URL
        if blockchain_id is not None:
            # find manifest URL
            log.debug("Find index manifest URL for {}".format(blockchain_id))

            if index_manifest_url is None:
                try:
                    index_manifest_url = get_index_manifest_url(blockchain_id, "dropbox", CONFIG_PATH)
                except Exception as e:
                    if DEBUG:
                        log.exception(e)

                    log.error("Failed to get index manifest URL for {}".format(blockchain_id))
                    return None

                if index_manifest_url is None:
                    log.error("Profile for {} is not connected to '{}'".format(blockchain_id, 'dropbox'))
                    return None

            # go get the url for this data
            data_url = index_lookup(index_manifest_url, urlres)
            if data_url is None:
                log.error("No data URL from index for '{}'".format(urlres))
                return None
    
            log.debug("Fetch {} via HTTP at {}".format(urlres, data_url))
            data = get_chunk_via_http(data_url)

        else:
            # assuming we want to talk to our dropbox
            global DROPBOX_TOKEN
            assert DROPBOX_TOKEN
            dbx = dropbox.Dropbox(DROPBOX_TOKEN)

            log.debug("Fetch {} via dropbox ({})".format(url, urlres))
            data = get_chunk_via_dropbox(dbx, '/{}'.format(urlres))

    else:

        # request via HTTP
        log.debug("Fetch {} via HTTP".format(url))
        data = get_chunk_via_http(url)

    if data is None:
        return None

    # decompress 
    if DROPBOX_COMPRESS:
        try:
            res = decompress_chunk(data)
        except:
            res = data
            
    else:
        res = data

    return res


def delete_chunk(dbx, name):
    """
    Delete a chunk from dropbox
    Return True on success
    """
    
    name = name.replace( "/", r"-2f" )
    try:
        dbx.files_delete("/{}".format(name))
        return True
    except Exception, e:
        log.exception(e)
        return False
    

def storage_init(conf):
    """
    Initialize dropbox storage driver
    """
    global DROPBOX_TOKEN, CONFIG_PATH
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
                DROPBOX_COMPRESS = (parser.get('dropbox', 'compress').lower() in ['1', 'true', 'yes'])

    # need the token 
    if DROPBOX_TOKEN is None:
        log.error("Config file '%s': section 'dropbox' is missing 'token'")
        return False

    # make settings dir 
    dirp = get_driver_settings_dir(config_path, 'dropbox')
    try:
        if not os.path.exists(dirp):
            os.makedirs(dirp)
            os.chmod(dirp, 0700)
    except Exception as e:
        if DEBUG:
            log.exception(e)

        log.error("Failed to create settings dir {}".format(dirp))
        return False

    CONFIG_PATH = config_path
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
    return urlparts.netlock.endswith(".dropbox.com")
    

def make_mutable_url( data_id ):
    """
    The URL here is a misnomer, since only Dropbox.com
    can create public URLs.

    This URL here will instruct get_chunk() to go and search through
    the index for the target data.
    """
    data_id = urllib.quote( data_id.replace('/', '-2f') )
    url = "https://www.dropbox.com/blockstack/{}".format(data_id)
    return url


def get_immutable_handler( key, **kw ):
    """
    Get data by hash
    """
    name = 'immutable-{}'.format(key)
    name = name.replace('/', r'-2f')
    return get_chunk('https://www.dropbox.com/blockstack/{}'.format(name), kw.get('fqu'), index_manifest_url=kw.get('index_manifest_url'))


def get_mutable_handler( url, **kw ):
    """
    Get data by URL
    """
    return get_chunk(url, kw.get('fqu'), index_manifest_url=kw.get('index_manifest_url'))


def put_immutable_handler( key, data, txid, **kw ):
    """
    Put data by hash and txid
    """
    global DROPBOX_TOKEN
    assert DROPBOX_TOKEN
    dbx = dropbox.Dropbox(DROPBOX_TOKEN)

    name = 'immutable-{}'.format(key)
    name = name.replace('/', r'-2f')

    path = '/{}'.format(name)
    return put_chunk(dbx, path, data)


def put_mutable_handler( data_id, data_bin, **kw ):
    """
    Put data by file ID
    """
    global DROPBOX_TOKEN
    assert DROPBOX_TOKEN
    dbx = dropbox.Dropbox(DROPBOX_TOKEN)
    
    data_id = data_id.replace('/', r'-2f')
    path = '/{}'.format(data_id)

    return put_chunk(dbx, path, data_bin)


def delete_immutable_handler( key, txid, sig_key_txid, **kw ):
    """
    Delete by hash
    """
    global DROPBOX_TOKEN
    assert DROPBOX_TOKEN
    dbx = dropbox.Dropbox(DROPBOX_TOKEN)
    return delete_chunk(dbx, "immutable-{}".format(key))


def delete_mutable_handler( data_id, signature, **kw ):
    """
    Delete by data ID
    """
    global DROPBOX_TOKEN
    assert DROPBOX_TOKEN
    dbx = dropbox.Dropbox(DROPBOX_TOKEN)
    return delete_chunk(dbx, data_id.format(data_id))
    

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
  
   index_manifest_url = index_setup()
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
         raise Exception("get_mutable_handler('%s'): '%s' != '%s'" % (hash_data(d), d, rd))
      
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
