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
    along with Blockstack-client. If not, see <http://www.gnu.org/licenses/>.
"""

# test disk driver, meant to be used alongside the disk driver to test multi-storage-system support

import os
import sys
import json
import traceback
import logging
import time
from common import *
from ConfigParser import SafeConfigParser

log = get_logger("blockstack-storage-driver-test")

DEFAULT_DISK_ROOT = "/tmp/blockstack-integration-test-storage"
DEFAULT_INDEX_DIRNAME = '/index'

DISK_ROOT = None
INDEX_DIRNAME = '/index'

INDEXED_STORAGE = False
DVCONF = None

log.setLevel( logging.DEBUG if DEBUG else logging.INFO )

def env_setup():
   """
   Set globals based on environment
   """
   global DISK_ROOT, INDEX_DIRNAME, INDEXED_STORAGE, DVCONF, CONFIG_PATH
   
   INDEXED_STORAGE = (os.environ.get("TEST_BLOCKSTACK_TEST_INDEXED_STORAGE") == "1")
   DISK_ROOT = os.environ.get("TEST_BLOCKSTACK_TEST_DISK_ROOT", DEFAULT_DISK_ROOT)

   DVCONF = driver_config("test", CONFIG_PATH, test_get_chunk, test_put_chunk, test_delete_chunk, driver_info={}, index_stem=INDEX_DIRNAME, compress=True)


def storage_init(conf, index=False, force_index=False):
   """
   Local disk implementation of the storage_init API call.
   Do one-time global setup--i.e. make directories.
   Return True on success
   Return False on error 
   """
   global DISK_ROOT, INDEXED_STORAGE, CONFIG_PATH, DVCONF

   config_path = conf['path']
   if os.path.exists( config_path ):

       parser = SafeConfigParser()
        
       try:
           parser.read(config_path)
       except Exception, e:
           log.exception(e)
           return False

       if parser.has_section('test-storage'):
           
           if parser.has_option('test-storage', 'root'):
               DISK_ROOT = parser.get('disk', 'root')

   if DISK_ROOT is None:
       DISK_ROOT = DEFAULT_DISK_ROOT

   if not os.path.isdir( DISK_ROOT ):
       os.makedirs( DISK_ROOT )
   
   CONFIG_PATH = config_path
   DVCONF = driver_config("test", config_path, test_get_chunk, test_put_chunk, test_delete_chunk, driver_info={}, index_stem=INDEX_DIRNAME, compress=True)

   if index:
       url = index_setup(DVCONF, force=force_index)
       if url is None:
           log.error("Failed to set up index")
           return False

   return True 


def test_put_chunk( dvconf, chunk_buf, path ):
    """
    Driver-level call to put data.

    Returns the URL to the data stored on success.
    Returns None on error
    """
    env_setup()
    
    diskpath = os.path.join(DISK_ROOT, path.strip('/'))
    dirname = os.path.dirname(diskpath)

    if not os.path.exists(dirname):
        try:
            os.makedirs(dirname, 0700)
        except Exception, e:
            if DEBUG:
                log.exception(e)
            return None

    try:
        with open( diskpath, "w" ) as f:
           f.write( chunk_buf )

        if DEBUG:
           log.debug("Stored to '%s'" % diskpath)

    except Exception, e:
        if DEBUG:
           log.exception(e)

        return None
   
    return 'test://{}?diskroot={}'.format(path, DISK_ROOT)


def test_delete_chunk(dvconf, path):
    """
    Delete a chunk from storage
    Return True on success
    Return False on error
    """
   
    env_setup()
    
    path = os.path.join(DISK_ROOT, path.strip('/'))

    try:
       os.unlink( path )
    except Exception, e:
       pass 

    return True


def test_get_chunk(dvconf, path):
    """
    Get a chunk via storage
    Return the data on success
    Return None on error
    """

    env_setup()

    parts = path.split('?')
    disk_root = None

    if len(parts) == 2:
        disk_root = parts[1].split('=')[1]
        path = parts[0]

    else:
        disk_root = DISK_ROOT

    log.debug("Get chunk {} from {}".format(path, disk_root))
    path = os.path.join(disk_root, path.strip('/'))
     
    data = None 
    if not os.path.exists(path):
        log.debug("No such file or directory: '%s'" % path)
        return None
   
    try:
       with open( path, "r" ) as f:
           data = f.read() 
         
       return data
   
    except Exception, e:
       if DEBUG:
          traceback.print_exc()

       return None


def handles_url( url ):
    """
    Does this storage driver handle this kind of URL?
    """
    return url.startswith("test://")


def make_mutable_url( data_id ):
    """
    Local disk implementation of the make_mutable_url API call.
    Given the ID of the data, generate a URL that 
    can be used to route reads and writes to the data.
   
    Return a string.
    """
   
    env_setup()
   
    # replace all /'s with -2f
    data_id_noslash = data_id.replace( "/", "-2f" )
   
    return "test:///mutable/{}".format(data_id_noslash)


def get_immutable_handler( key, **kw ):
    """
    Local disk implementation of the get_immutable_handler API call.
    Given the hash of the data, return the data.
    Return None if not found.
    """
   
    env_setup()

    index_manifest_url = kw.get('index_manifest_url')
    blockchain_id = kw.get('fqu')
  
    if os.environ.get('BLOCKSTACK_INTEGRATION_TEST_STORAGE_FAILURE') == '1':
        return False

    key = key.replace('/', '-2f')
    path = '/immutable/{}'.format(key)

    if INDEXED_STORAGE:
        return get_indexed_data(DVCONF, blockchain_id, path, index_manifest_url=index_manifest_url)

    else:
        return test_get_chunk(DVCONF, path)


def get_mutable_handler( url, **kw ):
    """
    Local disk implementation of the get_mutable_handler API call.
    Given a route URL to data, return the data itself.
    Return the data if found.
    Return None if not.
    """
    
    env_setup()

    index_manifest_url = kw.get('index_manifest_url')
    blockchain_id = kw.get('fqu')
  
    if os.environ.get('BLOCKSTACK_INTEGRATION_TEST_STORAGE_FAILURE') == '1':
        return None

    if not url.startswith("test://"):
        # invalid
        return None

    path = url[len("test://"):]

    if INDEXED_STORAGE:
        return get_indexed_data(DVCONF, blockchain_id, path, index_manifest_url=index_manifest_url)

    else:
        return test_get_chunk(DVCONF, path)


def put_immutable_handler( key, data, txid, **kw ):
    """
    Local disk implmentation of the put_immutable_handler API call.
    Given the hash of the data (key), the serialized data itself,
    and the transaction ID in the blockchain that contains the data's hash,
    put the data into the storage system.
    Return True on success; False on failure.
    """
   
    env_setup()

    if os.environ.get('BLOCKSTACK_INTEGRATION_TEST_STORAGE_FAILURE') == '1':
        return False
    
    key = key.replace('/', '-2f')
    path = '/immutable/{}'.format(key)

    if INDEXED_STORAGE:
        return put_indexed_data(DVCONF, path, data)
    else:
        return test_put_chunk(DVCONF, data, path)


def put_mutable_handler( data_id, data_bin, **kw ):
    """
    Local disk implementation of the put_mutable_handler API call.
    Return True on success; False on failure.
    """
  
    env_setup()

    if os.environ.get('BLOCKSTACK_INTEGRATION_TEST_STORAGE_FAILURE') == '1':
        return False
    
    data_id = data_id.replace('/', '-2f')
    path = '/mutable/{}'.format(data_id)

    if INDEXED_STORAGE:
        return put_indexed_data(DVCONF, path, data_bin)
    else:
        return test_put_chunk(DVCONF, data_bin, path)


def delete_immutable_handler( key, txid, sig_key_txid, **kw ):
    """
    Local disk implementation of the delete_immutable_handler API call.
    Given the hash of the data and transaction ID of the update
    that deleted the data, remove data from storage.
    Return True on success; False if not.
    """
    
    env_setup()

    if os.environ.get('BLOCKSTACK_INTEGRATION_TEST_STORAGE_FAILURE') == '1':
        return False

    key = key.replace('/', '-2f')
    path = '/immutable/{}'.format(key)

    if INDEXED_STORAGE:
        return delete_indexed_data(DVCONF, path)
    else:
        return test_delete_chunk(DVCONF, path)


def delete_mutable_handler( data_id, signature, **kw ):
    """
    Local disk implementation of the delete_mutable_handler API call.
    Given the unchanging data ID for the data and the writer's
    signature over the hash of the data_id, remove data from storage.
    Return True on success; False if not.
    """
   
    env_setup()

    if os.environ.get('BLOCKSTACK_INTEGRATION_TEST_STORAGE_FAILURE') == '1':
        return False

    data_id = data_id.replace('/', '-2f')
    path = '/mutable/{}'.format(data_id)

    if INDEXED_STORAGE:
        return delete_indexed_data(DVCONF, path)
    else:
        return test_delete_chunk(DVCONF, path)


def get_classes():
    return ['read_public', 'write_private', 'read_local', 'write_local']
   
   
if __name__ == "__main__":
   """
   Unit tests.
   """
   
   import virtualchain
   from virtualchain.lib.hashing import *

   # hack around absolute paths
   current_dir =  os.path.abspath(os.path.join( os.path.dirname(__file__), "..") )
   sys.path.insert(0, current_dir)
   
   from blockstack_client.storage import serialize_mutable_data, parse_mutable_data
   from blockstack_client.config import log, get_config
   
   CONFIG_PATH = os.environ.get('BLOCKSTACK_CONFIG_PATH', None)
   assert CONFIG_PATH, "Missing BLOCKSTACK_CONFIG_PATH from environment"

   conf = get_config(CONFIG_PATH)
   print json.dumps(conf, indent=4, sort_keys=True)

   import keylib

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
   
   # put_immutable_handler
   print "put_immutable_handler"
   for i in xrange(0, len(test_data)):
      
      d_id, d, n, s, url = test_data[i]
      
      rc = put_immutable_handler( hash_data( d ), d, "unused" )
      if not rc:
         raise Exception("put_immutable_handler('%s') failed" % d)
      
      
   # put_mutable_handler
   print "put_mutable_handler"
   for i in xrange(0, len(test_data)):
      
      d_id, d, n, s, url = test_data[i]
      
      data_url = make_mutable_url( d_id )
      
      data_json = serialize_mutable_data( json.dumps({"id": d_id, "nonce": n, "data": d}, sort_keys=True), data_privkey )

      rc = put_mutable_handler( d_id, data_json )
      if not rc:
         raise Exception("put_mutable_handler('%s', '%s') failed" % (d_id, d))
     
      test_data[i][4] = data_url
      
      
   # get_immutable_handler
   print "get_immutable_handler"
   for i in xrange(0, len(test_data)):
      
      d_id, d, n, s, url = test_data[i]
      
      rd = get_immutable_handler( hash_data( d ), fqu='foo.id', index_manifest_url=index_manifest_url)
      if rd is None:
          raise Exception("Failed to get {}".format(hash_data(d)))

      if rd != d:
         raise Exception("get_mutable_handler('%s'): '%s' != '%s'" % (hash_data(d), d, rd))
      
   # get_mutable_handler
   print "get_mutable_handler"
   for i in xrange(0, len(test_data)):
      
      d_id, d, n, s, url = test_data[i]
     
      log.debug("Get {}".format(url))

      rd_json = get_mutable_handler( url, fqu='foo.id', index_manifest_url=index_manifest_url )
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
      
      rc = delete_immutable_handler( hash_data(d), "unused", "unused" )
      if not rc:
         raise Exception("delete_immutable_handler('%s' (%s)) failed" % (hash_data(d), d))
      
   # delete_mutable_handler
   print "delete_mutable_handler"
   for i in xrange(0, len(test_data)):
      
      d_id, d, n, s, url = test_data[i]
      
      rc = delete_mutable_handler( d_id, "unused" )
      if not rc:
         raise Exception("delete_mutable_handler('%s') failed" % d_id)
      
   
   
