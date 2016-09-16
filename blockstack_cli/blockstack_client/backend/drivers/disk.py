#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    The MIT License (MIT)
    Copyright (c) 2014-2015 by Halfmoon Labs, Inc.
    Copyright (c) 2016 by Blocktatck.org

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included
    in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
"""

# This module lets the blockstack client treat local disk as a storage provider.
# This is useful for doing local testing.

import os
import sys 
import traceback
import logging
from common import get_logger, DEBUG

log = get_logger("blockstack-storage-driver-disk")

if os.environ.get("BLOCKSTACK_TEST", None) is not None:
    DISK_ROOT = "/tmp/blockstack-disk"
else:
    DISK_ROOT = os.path.expanduser("~/.blockstack/storage-disk")

IMMUTABLE_STORAGE_ROOT = DISK_ROOT + "/immutable"
MUTABLE_STORAGE_ROOT = DISK_ROOT + "/mutable"

log.setLevel( logging.DEBUG if DEBUG else logging.INFO )

def storage_init(conf):
   """
   Local disk implementation of the storage_init API call.
   Do one-time global setup--i.e. make directories.
   Return True on success
   Return False on error 
   """
   global DISK_ROOT, MUTABLE_STORAGE_ROOT, IMMUTABLE_STORAGE_ROOT
   
   if not os.path.isdir( DISK_ROOT ):
      os.makedirs( DISK_ROOT )
   
   if not os.path.isdir( MUTABLE_STORAGE_ROOT ):
      os.makedirs( MUTABLE_STORAGE_ROOT )
    
   if not os.path.isdir( IMMUTABLE_STORAGE_ROOT ):
      os.makedirs( IMMUTABLE_STORAGE_ROOT )
   
   return True 


def handles_url( url ):
    """
    Does this storage driver handle this kind of URL?
    """
    return url.startswith("file://")


def make_mutable_url( data_id ):
   """
   Local disk implementation of the make_mutable_url API call.
   Given the ID of the data, generate a URL that 
   can be used to route reads and writes to the data.
   
   Return a string.
   """
   
   global MUTABLE_STORAGE_ROOT
   
   # replace all /'s with \x2f's 
   data_id_noslash = data_id.replace( "/", r"\x2f" )
   
   return "file://%s/%s" % (MUTABLE_STORAGE_ROOT, data_id_noslash)


def get_immutable_handler( key, **kw ):
   """
   Local disk implementation of the get_immutable_handler API call.
   Given the hash of the data, return the data.
   Return None if not found.
   """
   
   global IMMUTABLE_STORAGE_ROOT
   
   data = None 
   path = os.path.join( IMMUTABLE_STORAGE_ROOT, key )

   if not os.path.exists(path):
       if DEBUG:
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


def get_mutable_handler( url, **kw ):
   """
   Local disk implementation of the get_mutable_handler API call.
   Given a route URL to data, return the data itself.
   Return the data if found.
   Return None if not.
   """
   
   if not url.startswith( "file://" ):
      # invalid
      return None 
   
   # get path from URL 
   path = url[ len("file://"): ]
   
   if not os.path.exists(path):
       if DEBUG:
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


def put_immutable_handler( key, data, txid, **kw ):
   """
   Local disk implmentation of the put_immutable_handler API call.
   Given the hash of the data (key), the serialized data itself,
   and the transaction ID in the blockchain that contains the data's hash,
   put the data into the storage system.
   Return True on success; False on failure.
   """
   
   global IMMUTABLE_STORAGE_ROOT, DEBUG
   
   path = os.path.join( IMMUTABLE_STORAGE_ROOT, key )
   pathdir = os.path.dirname(path)

   if not os.path.exists(pathdir):
       try:
           os.makedirs(path_dir, 0700)
       except Exception, e:
           if DEBUG:
               log.exception(e)
           return False
   
   try:
      with open( path, "w") as f:
         f.write( data )
         f.flush()

      if DEBUG:
         log.debug("Stored to '%s'" % path)
   except Exception, e:
      if DEBUG:
         traceback.print_exc()
      return False 
   
   return True 


def put_mutable_handler( data_id, data_bin, **kw ):
   """
   Local disk implementation of the put_mutable_handler API call.
   Return True on success; False on failure.
   """
   
   global MUTABLE_STORAGE_ROOT, DEBUG
   
   # replace all /'s with \x2f's
   data_id_noslash = data_id.replace( "/", r"\x2f" )
   path = os.path.join( MUTABLE_STORAGE_ROOT, data_id_noslash )
   pathdir = os.path.dirname(path)

   if not os.path.exists(pathdir):
       try:
           os.makedirs(path_dir, 0700)
       except Exception, e:
           if DEBUG:
               log.exception(e)
           return False

   try:
      with open( path, "w" ) as f:
         f.write( data_bin )
         f.flush()

      if DEBUG:
         log.debug("Stored to '%s'" % path)

   except Exception, e:
       if DEBUG:
           log.exception(e)
       return False
   
   return True 


def delete_immutable_handler( key, txid, sig_key_txid, **kw ):
   """
   Local disk implementation of the delete_immutable_handler API call.
   Given the hash of the data and transaction ID of the update
   that deleted the data, remove data from storage.
   Return True on success; False if not.
   """
   
   global IMMUTABLE_STORAGE_ROOT
   
   path = os.path.join( IMMUTABLE_STORAGE_ROOT, key )
   
   try:
      os.unlink( path )
   except Exception, e:
      pass
   
   return True 


def delete_mutable_handler( data_id, signature, **kw ):
   """
   Local disk implementation of the delete_mutable_handler API call.
   Given the unchanging data ID for the data and the writer's
   signature over the hash of the data_id, remove data from storage.
   Return True on success; False if not.
   """
   
   global MUTABLE_STORAGE_ROOT
   
   data_id_noslash = data_id.replace( "/", r"\x2f" )
   path = os.path.join( MUTABLE_STORAGE_ROOT, data_id_noslash )
   
   try:
      os.unlink( path )
   except Exception, e:
      pass 
   
   return True
   
   
if __name__ == "__main__":
   """
   Unit tests.
   """
   
   import pybitcoin 
   import json 
   
   # hack around absolute paths
   current_dir =  os.path.abspath(os.path.join( os.path.dirname(__file__), "..") )
   sys.path.insert(0, current_dir)
   
   from storage import serialize_mutable_data, parse_mutable_data
   from user import make_mutable_data_zonefile

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
      
      data_zonefile = make_mutable_data_zonefile( d_id, n, [data_url] )
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
      
   
   
