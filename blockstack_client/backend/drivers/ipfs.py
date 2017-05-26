#!/usr/bin/env python
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

import sys
import os
import re
import zlib
import json
import logging
import ipfsapi
from common import get_logger, DEBUG, compress_chunk, decompress_chunk
from ConfigParser import SafeConfigParser

log = get_logger("blockstack-storage-skel")
log.setLevel( logging.DEBUG if DEBUG else logging.INFO )

IPFS_SERVER   = 'localhost'
IPFS_PORT     = '5001'
IPFS_COMPRESS = True

ipfs_api = None

def ipfs_key_gen(key):
    """ 
    We need a custom wraper for this API endpoint, because the ipfsapi does not provide it, yet
    Instead of checking whether a key exists before creating it,
    We create it, and ignore the error that throws if it exists already.
    """

    try:
      r = ipfs_api._client.request('/key/gen', (key,), decoder='json', opts={'type':'rsa','size':'2048'})
    except ipfsapi.exceptions.ErrorResponse:
      # An exception is thrown when the key already exists, we ignore it
      pass

def write_chunk( chunk_path, chunk_buf, is_mutable ):
    """
    Write a chunk of data to IPFS.
    
    Return True on success 
    Return False on error, and log an exception
    """

    rc = True

    if IPFS_COMPRESS:            
      compressed_data = compress_chunk( chunk_buf )
    else:
      compressed_data = chunk_buf

    try:
      h = ipfs_api.add_str( compressed_data, decoder='json' )        
    except Exception, e:
      log.error("Failed to write '%s'" % chunk_path)
      log.exception(e)
      rc = False

    if is_mutable:
      if os.environ.get("BLOCKSTACK_TEST") == "1":
        log.debug("[DEBUG] ipfs.publish_name %s: %s" % (chunk_path, chunk_buf))
      try:
        r = ipfs_api.name_publish( h, opts = {'key': 'mutable-{}'.format(chunk_path.replace( "/", r"\x2f" ))})
      except Exception, e:
        log.error("Failed to publish '%s'" % chunk_path)
        log.exception(e)
        rc = False
      if os.environ.get("BLOCKSTACK_TEST") == "1":
        log.debug("[DEBUG] ipfs.publish_name returned " % (r))

    return rc

#-------------------------
def read_chunk( chunk_path, is_mutable ):
    """
    Get a chunk of data from IPFS.
    
    Return the data on success
    Return None on error, and log an exception.
    """
    
    data = None

    url = chunk_path

    if is_mutable:
      try:
        r = ipfs_api.name_resolve( chunk_path )
        url = r['Path']
      except Exception, e:
        log.error("Failed to resolve '%s'" % chunk_path)
        log.exception(e)

    try:
      compressed_data = ipfs_api.cat(url)
      try:
        data = decompress_chunk( compressed_data )
      except:
        data = compressed_data
        
    except Exception, e:
        log.error("Failed to read '%s'" % chunk_path)
        log.exception(e)
        
    return data

#-------------------------
def delete_chunk( chunk_path, is_mutable ):
    """
    Delete a chunk of data from IPFS.
    
    Return True on success 
    Return False on error.
    """
    
    rc = True

    url = chunk_path
    if is_mutable:
      try:
        r = ipfs_api.name_resolve( chunk_path )
        url = r['Path']
      except Exception, e:
        log.error("Failed to resolve '%s'" % chunk_path)
        log.exception(e)

    try:
        ipfs_api.pin_rm( url )
    except Exception, e:
        log.error("Failed to delete '%s'" % chunk_path)
        log.exception(e)
        rc = False

    return rc


def storage_init(conf, **kwargs):
   """
   Initialize IPFS storage driver
   """
   global IPFS_SERVER, IPFS_PORT, IPFS_COMPRESS, ipfs_api

   # path to the CLI's configuration file (where you can stash driver-specific configuration)
   config_path = conf['path']
   if os.path.exists( config_path ):

       parser = SafeConfigParser()
        
       try:
           parser.read(config_path)
       except Exception, e:
           log.exception(e)
           return False

       if parser.has_section('ipfs'):
            
            if parser.has_option('ipfs', 'server'):
                IPFS_SERVER = parser.get('ipfs', 'server')
                
            if parser.has_option('ipfs', 'port'):
                IPFS_PORT = parser.get('ipfs', 'port')
            
            if parser.has_option('ipfs', 'compress'):
                IPFS_COMPRESS = (parser.get('ipfs', 'compress', 'false').lower() in ['true', '1'])

   ipfs_api = ipfsapi.connect( IPFS_SERVER, IPFS_PORT )

   return True 


def handles_url( url ):
    """
    Does this storage driver handle this kind of URL?

    It is okay if other drivers say that they can handle it.
    This is used by the storage system to quickly filter out
    drivers that don't handle this type of URL.

    A common strategy is simply to check if the scheme
    matches what your driver does.  Another common strategy
    is to check if the URL matches a particular regex.
    """
    if url.startswith("/ipfs/") or url.startswith("/ipns/"):
      return True
    else:
      # if it starts with a valid CID: https://github.com/ipld/cid
      #   return True
      # else
      return False


def make_mutable_url( data_id ):
    """
    Get data by URL
    """
    key = 'mutable-{}'.format(data_id.replace( "/", r"\x2f" ))

    ipfs_key_gen( key )
   
    url = None

    try:
      r = ipfs_api.name_publish( hash_data(''), opts = {'key':key})
      url = r['Name']
    except Exception, e:
      log.error("Failed to publish '%s'" % chunk_path)
      log.exception(e)
    
    return url
   

def get_immutable_handler( data_hash, **kw ):
    """
    Get data by hash
    """
    return read_chunk( data_hash, False )


def get_mutable_handler( url, **kw ):
    """
    Get data by dynamic hash
    """
    return read_chunk( url, True )

def put_immutable_handler( data_hash, data, txid, **kw ):
    """
    Put data by hash
    """
    return write_chunk( data_hash, data, False )

def put_mutable_handler( data_id, data_txt, **kw ):
    """
    Put data by dynamic hash
    """
    return write_chunk( data_id, data_txt, True )
   

def delete_immutable_handler( data_hash, txid, tombstone, **kw ):
    """
    Delete by hash
    """
    return delete_chunk( data_hash, False )


def delete_mutable_handler( data_id, tombstone, **kw ):
    """
    Delete by dynamic hash
    """
    return delete_chunk( data_id, True )

def hash_data( d ):

  h = None

  if IPFS_COMPRESS:
    try:            
      h = ipfs_api.add_str(compress_chunk(d), opts={'only-hash':True})
    except:
      log.error("Failed to get hash for '%s'" % chunk_path)
      log.exception(e)
  else:
    try:
      h = ipfs_api.add_str(d, opts={'only-hash':True})
    except:
      log.error("Failed to get hash for '%s'" % chunk_path)
      log.exception(e)
        
  return h
   
if __name__ == "__main__":
   """
   Unit tests.
   """

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
      ["user\"_profile",        '{"name":{"formatted":"judecn"},"v":"2"}',  3, "unused", None],
      ["empty_string",          "",                                         4, "unused", None],
   ]
   
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
      
      rc = put_immutable_handler( hash_data( d ), d, "unused" )
      if not rc:
         raise Exception("put_immutable_handler('%s') failed" % d)
      
      
   # put_mutable_handler
   print "put_mutable_handler"
   for i in xrange(0, len(test_data)):

      d_id, d, n, s, url = test_data[i]
      
      data_url = make_mutable_url( d_id )
       
      data_json = serialize_mutable_data( json.dumps({"id": d_id, "nonce": n, "data": d}), data_privkey )
      
      rc = put_mutable_handler( d_id, data_json )
      if not rc:
         raise Exception("put_mutable_handler('%s', '%s') failed" % (d_id, d))
     
      test_data[i][4] = data_url

   # get_immutable_handler
   print "get_immutable_handler"
   for i in xrange(0, len(test_data)):
      
      d_id, d, n, s, url = test_data[i]
      
      rd = get_immutable_handler( hash_data( d ) )
      if rd != d:
         raise Exception("get_immutable_handler('%s'): '%s' != '%s'" % (hash_data(d), d, rd))
      
   # get_mutable_handler
   print "get_mutable_handler"
   for i in xrange(0, len(test_data)):

      d_id, d, n, s, url = test_data[i]

      rd_json = get_mutable_handler( url )

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
      
      rc = delete_mutable_handler( url, "unused" )
      if not rc:
         raise Exception("delete_mutable_handler('%s') failed" % d_id)

