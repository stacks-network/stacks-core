#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016-2017 by Blockstack.org

    This file is part of Blockstack.

    Blockstack is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
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

from common import get_driver_settings_dir, DEBUG, get_logger, compress_chunk, decompress_chunk, setup_scratch_space, make_scratch_file

from ConfigParser import SafeConfigParser

log = get_logger('blockstack-client-onedrive')

import easywebdav

WEBDAV_DIR = None
SCRATCH_DIR = None

def connect_webdav(url, username, password, directory, cert=None):
    """
    Connect to the WebDav server and return a client
    """
    urlparts = urlparse.urlparse(url)
    client = easywebdav.connect(urlparts.netloc, username=username, password=password, protocol=urlparts.scheme, cert=cert)
    client.cd('/')
    return client


def get_chunk(client, data_id):
    """
    Get a chunk.
    Return the chunk on success
    Return None on error
    """
    assert WEBDAV_DIR
    assert SCRATCH_DIR

    sanitized_data_id = urllib.quote( data_id.replace('/', '-2f') )

    path = os.path.join( WEBDAV_DIR, sanitized_data_id )
    local_path = make_scratch_file(SCRATCH_DIR)
    data = None

    try:
        easywebdav.download(path, local_path)
        with open(local_path, 'r') as f:
            data = f.read()

        return data
    except Exception as e:
        if DEBUG:
            log.exception(e)

        log.error("Failed to load {}".format(data_id))
        return None


def put_chunk(client, data_id):
    """
    Put a chunk
    Return True on success
    Return False on error
    """
    pass


def handles_url( url ):
    """
    Do we handle this URL?
    Must point to a onedrive link
    """
    urlparts = urlparse.urlparse(url)
    return urlparts.scheme == 'webdav'


def make_mutable_url( data_id ):
    """
    Make a mutable data URL.
    It's not guaranteed to resolve to data via HTTP; it may instead
    encode information used by the driver.
    """
    data_id = urllib.quote( data_id.replace('/', '\\x2f') )
    url = 'https://onedrive.live.com/blockstack/{}'.format(data_id)
    return url


def get_immutable_handler( key, **kw ):
    """
    Get data by hash
    """
    drive = get_onedrive_handle()
    key = urllib.quote( key.replace('/', '\\x2f') )
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
