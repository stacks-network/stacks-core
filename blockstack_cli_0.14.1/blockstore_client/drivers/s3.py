#!/usr/bin/env python

"""
   Copyright: (c) 2013 The Trustees of Princeton University
   Copyright: (c) 2015 by Halfmoon Labs, Inc.
   Copyright: (c) 2016 by Blockstack.org


   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""
 
# This module lets the blockstore client use Amazon S3 as a storage provider.

import sys
import os
import boto
import logging 
import errno
from ConfigParser import SafeConfigParser

try:
    from ..config import log, CONFIG_PATH
except:
    if __name__ == "__main__":
        # doing tests 
        pass
    else:
        raise

from boto.s3.key import Key

import logging
logging.getLogger('boto').setLevel(logging.CRITICAL)

AWS_BUCKET = None
AWS_ACCESS_KEY_ID = None 
AWS_SECRET_ACCESS_KEY = None

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
    try:
        k.set_contents_from_string( chunk_buf )
        
    except Exception, e:
        log.error("Failed to write '%s'" % chunk_path)
        log.exception(e)
        rc = False
    
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
    try:
        data = k.get_contents_as_string()
        
    except Exception, e:
        log.error("Failed to read '%s'" % chunk_path)
        log.exception(e)
        
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


def storage_init():
    """
    S3 implementation of the storage_init API call.
    Do one-time global setup: read our S3 API tokens and bucket name.
    Return True on success
    Return False on error 
    """
    global AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_BUCKET

    if os.path.exists( CONFIG_PATH ):

        parser = SafeConfigParser()
        
        try:
            parser.read(CONFIG_PATH)
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
        log.error("Config file '%s': section 's3' is missing 'bucket', 'api_key_id', and/or 'api_key_secret'" % CONFIG_PATH )
        return False 
    
    return True



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


def get_immutable_handler( key ):
    """
    S3 implementation of the get_immutable_handler API call.
    Given the hash of the data, return the data.
    Return None if not found.
    """

    immutable_data_id = "immutable-%s" % key 
    return read_chunk( immutable_data_id )


def get_mutable_handler( url ):
    """
    S3 implementation of the get_mutable_handler API call.
    Given a route URL to data, return the data itself.
    If we can't handle this URL, raise UnhandledURLException.
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


def put_immutable_handler( key, data, txid ):
    """
    S3 implmentation of the put_immutable_handler API call.
    Given the hash of the data (key), the serialized data itself,
    and the transaction ID in the blockchain that contains the data's hash,
    put the data into the storage system.
    Return True on success; False on failure.
    """

    immutable_data_id = "immutable-%s" % key 
    return write_chunk( immutable_data_id, data )


def put_mutable_handler( data_id, nonce, signature, data_json ):
    """
    S3 implementation of the put_mutable_handler API call.
    Given the the unchanging ID for the data, a nonce representing
    this version of the data, the writer's signature over hash(data_id + data + nonce),
    and the serialized JSON representing all of the above plus the data, put 
    the serialized JSON into storage.
    Return True on success; False on failure.
    """

    mutable_data_id = "mutable-%s" % data_id 
    return write_chunk( mutable_data_id, data_json )


def delete_immutable_handler( key, txid ):
    """
    S3 implementation of the delete_immutable_handler API call.
    Given the hash of the data and transaction ID of the update
    that deleted the data, remove data from storage.
    Return True on success; False if not.
    """

    immutable_data_id = "immutable-%s" % key 
    return delete_chunk( immutable_data_id )


def delete_mutable_handler( data_id, signature ):
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
   
   # hack around absolute paths
   current_dir =  os.path.abspath(os.path.dirname(__file__))
   sys.path.insert(0, current_dir)
   
   current_dir =  os.path.abspath(os.path.join( os.path.dirname(__file__), "..") )
   sys.path.insert(0, current_dir)
   
   from parsing import json_stable_serialize
   from storage import mutable_data_parse, mutable_data
   from config import log, CONFIG_PATH
   
   test_data = [
      ["my_first_datum",        "hello world",                              1, "unused", None],
      ["/my/second/datum",      "hello world 2",                            2, "unused", None],
      ["user_profile",          '{"name":{"formatted":"judecn"},"v":"2"}',  3, "unused", None],
      ["empty_string",          "",                                         4, "unused", None],
   ]
   
   def hash_data( d ):
      return pybitcoin.hash.hex_hash160( d )
   
   rc = storage_init()
   if not rc:
      raise Exception("Failed to initialize")
   
   
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
      
      data = mutable_data( d_id, d, n, sig=s )
      
      data_json = json_stable_serialize( data )
      
      rc = put_mutable_handler( d_id, n, "unused", data_json )
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
      rd = mutable_data_parse( rd_json )
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
      
      rc = delete_immutable_handler( hash_data(d), "unused" )
      if not rc:
         raise Exception("delete_immutable_handler('%s' (%s)) failed" % (hash_data(d), d))
      
   # delete_mutable_handler
   print "delete_mutable_handler"
   for i in xrange(0, len(test_data)):
      
      d_id, d, n, s, url = test_data[i]
      
      rc = delete_mutable_handler( d_id, "unused" )
      if not rc:
         raise Exception("delete_mutable_handler('%s') failed" % d_id)
