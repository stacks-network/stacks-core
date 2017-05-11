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

from ConfigParser import SafeConfigParser
from common import get_logger, DEBUG, compress_chunk, decompress_chunk

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

BLOCKSTACK_DEBUG = (os.environ.get("BLOCKSTACK_DEBUG") == "1")


def put_chunk( dbx, name, chunk_buf ):
    """
    Put a chunk into dropbox.
    Compress it first.
    Return the URL
    """
    if DROPBOX_COMPRESS:
        compressed_chunk = compress_chunk(chunk_buf)
    else:
        compressed_chunk = chunk_buf

    name = name.replace( "/", r"-2f" )

    try:
        file_info = dbx.files_upload(compressed_chunk, '/{}'.format(name), mode=dropbox.files.WriteMode('overwrite'))
        link_info = dbx.sharing_create_shared_link("/{}".format(name), short_url=False)
        return link_info.url

    except Exception, e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to save {} to Dropbox".format(name))
        return None
        

def get_chunk_via_http(url):
    """
    Get a shared Dropbox URL's data
    Return the data on success
    Return None on failure

    Do not try to decompress.
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


def get_chunk_via_dropbox(dbx, data_id):
    """
    Get a mutable datum by data ID, using a Dropbox handle
    Return the data on success
    Return None on failure
    """
    try:
        metadata, req = dbx.files_download('/{}'.format(data_id))
        if req.status_code != 200:
            log.debug("Dropbox files_download /{} status code {}".format(data_id, req.status_code))
            return None

        return req.text
    except Exception, e:
        log.exception(e)
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


def get_chunk(url):
    """
    Get a chunk from dropbox, given its URL.
    Decompress and return it.
    """
    res = None
    data = None

    urltype, urlres = get_url_type(url)
    if urltype is None and urlres is None:
        log.error("Invalid URL {}".format(url))
        return None

    if urltype == 'dropbox':

        # request via Dropbox
        global DROPBOX_TOKEN
        assert DROPBOX_TOKEN
        dbx = dropbox.Dropbox(DROPBOX_TOKEN)

        log.debug("Fetch {} via dropbox ({})".format(url, urlres))
        data = get_chunk_via_dropbox(dbx, urlres) 

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
    global DROPBOX_TOKEN
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
    """
    data_id = urllib.quote( data_id.replace('/', '-2f') )
    url = "https://www.dropbox.com/blockstack/{}".format(data_id)
    return url


def get_immutable_handler( key, **kw ):
    """
    Get data by hash
    """
    global DROPBOX_TOKEN
    assert DROPBOX_TOKEN
    dbx = dropbox.Dropbox(DROPBOX_TOKEN)
    return get_chunk_via_dropbox(dbx, 'immutable-{}'.format(key))


def get_mutable_handler( url, **kw ):
    """
    Get data by URL
    """
    return get_chunk(url)


def put_immutable_handler( key, data, txid, **kw ):
    """
    Put data by hash and txid
    """
    global DROPBOX_TOKEN
    assert DROPBOX_TOKEN
    dbx = dropbox.Dropbox(DROPBOX_TOKEN)
    return put_chunk(dbx, "immutable-{}".format(key), data)


def put_mutable_handler( data_id, data_bin, **kw ):
    """
    Put data by file ID
    """
    global DROPBOX_TOKEN
    assert DROPBOX_TOKEN
    dbx = dropbox.Dropbox(DROPBOX_TOKEN)
    return put_chunk(dbx, data_id, data_bin)


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
