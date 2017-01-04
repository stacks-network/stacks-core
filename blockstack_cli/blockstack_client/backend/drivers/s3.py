#!/usr/bin/env python
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
 
# This module lets the blockstack client use Amazon S3 as a storage provider.

import sys
import os
import boto
import errno
import zlib
import time
from ConfigParser import SafeConfigParser

from boto.s3.key import Key

import logging
logging.getLogger('boto').setLevel(logging.CRITICAL)

from common import get_logger, DEBUG

log = get_logger("blockstack-storage-driver-s3")

log.setLevel( logging.DEBUG if DEBUG else logging.INFO )

AWS_BUCKET = None
AWS_ACCESS_KEY_ID = None 
AWS_SECRET_ACCESS_KEY = None

#-------------------------
def compress_chunk( chunk_buf ):
    """
    compress a chunk of data
    """
    data = zlib.compress(chunk_buf, 9)
    return data

#-------------------------
def decompress_chunk( chunk_buf ):
    """
    decompress a chunk of data
    """
    data = zlib.decompress(chunk_buf)
    return data

#-------------------------
def get_bucket( bucket_name ):
    """
    Get or create a reference to the given bucket.
    
    Return the bucket on success
    Return None on error, and log an exception 
    """
    
    global AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
    
    aws_id = AWS_ACCESS_KEY_ID
    aws_key = AWS_SECRET_ACCESS_KEY
    
    try:
        conn = boto.connect_s3(aws_id, aws_key)
    except Exception, e:
        log.error("Connection to S3 failed")
        log.exception(e)
        return None
        
    bucket = None
    try:
        bucket = conn.create_bucket(bucket_name)
    except Exception, e:
        log.error("Could not create/fetch bucket " + bucket_name)
        log.exception(e)
        
    return bucket

#-------------------------
def write_chunk( chunk_path, chunk_buf ):
    """
    Write a chunk of data to S3.
    
    Return True on success 
    Return False on error, and log an exception
    """

    global AWS_BUCKET
    
    bucket = get_bucket( AWS_BUCKET )
    if bucket == None:
        log.error("Failed to get bucket '%s'" % AWS_BUCKET )
        return False

    # replace / with \x2f 
    chunk_path = chunk_path.replace( "/", r"\x2f" )
    
    k = Key(bucket)
    k.key = chunk_path

    rc = True
    begin = None
    end = None
    size = None
    try:
        compressed_data = compress_chunk( chunk_buf )
        size = len(compressed_data)

        begin = time.time()
        k.set_contents_from_string( compressed_data )
        end = time.time()
        
    except Exception, e:
        log.error("Failed to write '%s'" % chunk_path)
        log.exception(e)
        rc = False
    
    if os.environ.get("BLOCKSTACK_TEST") == "1" and rc:
        log.debug("[BENCHMARK] s3.write_chunk %s: %s" % (size, end - begin))

    return rc

#-------------------------
def read_chunk( chunk_path ):
    """
    Get a chunk of data from S3.
    
    Return the data on success
    Return None on error, and log an exception.
    """

    global AWS_BUCKET
    
    bucket = get_bucket( AWS_BUCKET )
    if bucket == None:
        log.error("Failed to get bucket '%s'" % AWS_BUCKET)
        return None

    # replace / with \x2f 
    chunk_path = chunk_path.replace( "/", r"\x2f" )
    
    k = Key(bucket)
    k.key = chunk_path

    data = None
    begin = None
    end = None
    size = None
    try:
        begin = time.time()
        compressed_data = k.get_contents_as_string()
        end = time.time()
        size = len(compressed_data)

        data = decompress_chunk( compressed_data )
        
    except Exception, e:
        log.error("Failed to read '%s'" % chunk_path)
        log.exception(e)
        
    if os.environ.get("BLOCKSTACK_TEST") == "1":
        log.debug("[BENCHMARK] s3.read_chunk %s: %s" % (size, end - begin))

    return data
    
    
#-------------------------
def delete_chunk( chunk_path ):
    """
    Delete a chunk of data from S3.
    
    Return True on success 
    Return False on error.
    """
    
    global AWS_BUCKET
    
    bucket = get_bucket( AWS_BUCKET )
    if bucket == None:
        log.error("Failed to get bucket '%s'" % AWS_BUCKET)
        return False

    # replace / with \x2f 
    chunk_path = chunk_path.replace( "/", r"\x2f" )
    
    k = Key(bucket)
    k.key = chunk_path

    rc = True
    try:
        k.delete()
    except Exception, e:
        log.error("Failed to delete '%s'" % chunk_path)
        log.exception(e)
        rc = False

    return rc


# ---------------------------------------------------------
# Begin plugin implementation 
# ---------------------------------------------------------


def storage_init(conf):
    """
    S3 implementation of the storage_init API call.
    Do one-time global setup: read our S3 API tokens and bucket name.
    Return True on success
    Return False on error 
    """
    global AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_BUCKET

    config_path = conf['path']
    if os.path.exists( config_path ):

        parser = SafeConfigParser()
        
        try:
            parser.read(config_path)
        except Exception, e:
            log.exception(e)
            return False

        if parser.has_section('s3'):
            
            if parser.has_option('s3', 'bucket'):
                AWS_BUCKET = parser.get('s3', 'bucket')
                
            if parser.has_option('s3', 'api_key_id'):
                AWS_ACCESS_KEY_ID = parser.get('s3', 'api_key_id')
            
            if parser.has_option('s3', 'api_key_secret'):
                AWS_SECRET_ACCESS_KEY = parser.get('s3', 'api_key_secret')
            
            
    # we can't proceed unless we have all three.
    if AWS_ACCESS_KEY_ID is None or AWS_SECRET_ACCESS_KEY is None or AWS_BUCKET is None:
        log.error("Config file '%s': section 's3' is missing 'bucket', 'api_key_id', and/or 'api_key_secret'" % config_path )
        return False 
    
    return True


def handles_url( url ):
    """
    Does this storage driver handle this kind of URL?
    """
    return ".s3.amazonaws.com" in url


def make_mutable_url( data_id ):
    """
    S3 implementation of the make_mutable_url API call.
    Given the ID of the data, generate a URL that 
    can be used to route reads and writes to the data.

    Return a string.
    """

    global AWS_BUCKET
    
    # remove /'s
    data_id = data_id.replace( "/", r"\x2f" )

    return "https://%s.s3.amazonaws.com/mutable-%s" % (AWS_BUCKET, data_id)


def get_immutable_handler( key, **kw ):
    """
    S3 implementation of the get_immutable_handler API call.
    Given the hash of the data, return the data.
    Return None if not found.
    """

    immutable_data_id = "immutable-%s" % key 
    return read_chunk( immutable_data_id )


def get_mutable_handler( url, **kw ):
    """
    S3 implementation of the get_mutable_handler API call.
    Given a route URL to data, return the data itself.
    Return the data if found.
    Return None if not.
    """

    # extract data ID 
    mutable_data_id = None 
    try:
        parts = url.split('/')
        mutable_data_id = parts[-1]
    except Exception, e:
        log.exception(e)
        return None 

    return read_chunk( mutable_data_id )


def put_immutable_handler( key, data, txid, **kw ):
    """
    S3 implmentation of the put_immutable_handler API call.
    Given the hash of the data (key), the serialized data itself,
    and the transaction ID in the blockchain that contains the data's hash,
    put the data into the storage system.
    Return True on success; False on failure.
    """

    immutable_data_id = "immutable-%s" % key 
    return write_chunk( immutable_data_id, data )


def put_mutable_handler( data_id, data_json, **kw ):
    """
    S3 implementation of the put_mutable_handler API call.
    Return True on success; False on failure.
    """

    mutable_data_id = "mutable-%s" % data_id 
    return write_chunk( mutable_data_id, data_json )


def delete_immutable_handler( key, txid, sig_key_txid, **kw ):
    """
    S3 implementation of the delete_immutable_handler API call.
    Given the hash of the data and transaction ID of the update
    that deleted the data, remove data from storage.
    Return True on success; False if not.
    """

    immutable_data_id = "immutable-%s" % key 
    return delete_chunk( immutable_data_id )


def delete_mutable_handler( data_id, signature, **kw ):
    """
    S3 implementation of the delete_mutable_handler API call.
    Given the unchanging data ID for the data and the writer's
    signature over the hash of the data_id, remove data from storage.
    Return True on success; False if not.
    """

    mutable_data_id = "mutable-%s" % data_id 
    return delete_chunk( mutable_data_id )



if __name__ == "__main__":
   """
   Unit tests.
   """
   
   import pybitcoin 
   import json 
   import blockstack_client
   
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

   pk = pybitcoin.BitcoinPrivateKey()
   data_privkey = pk.to_hex()
   data_pubkey = pk.public_key().to_hex()

   test_data = [
      ["my_first_datum",        "hello world",                              1, "unused", None],
      ["/my/second/datum",      "hello world 2",                            2, "unused", None],
      ["user_profile",          '{"name":{"formatted":"judecn"},"v":"2"}',  3, "unused", None],
      ["empty_string",          "",                                         4, "unused", None],
   ]
   
   def hash_data( d ):
      return pybitcoin.hash.hex_hash160( d )
   
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
       
      data_json = serialize_mutable_data( {"id": d_id, "nonce": n, "data": d}, data_privkey )
      
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
         raise Exception("get_mutable_handler('%s'): '%s' != '%s'" % (hash_data(d), d, rd))
      
   # get_mutable_handler
   print "get_mutable_handler"
   for i in xrange(0, len(test_data)):
      
      d_id, d, n, s, url = test_data[i]
      
      rd_json = get_mutable_handler( url )
      rd = parse_mutable_data( rd_json, data_pubkey )
      if rd is None:
         raise Exception("Failed to parse mutable data '%s'" % rd_json)
      
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
