#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore-client
    ~~~~~
    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org
    
    This file is part of Blockstore-client.
    
    Blockstore-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    Blockstore-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore-client.  If not, see <http://www.gnu.org/licenses/>.
"""

# This module lets the blockstore client treat local disk as a storage provider.
# This is useful for doing local testing.

import os
import sys 
import traceback

DISK_ROOT="/tmp/blockstore-disk"
IMMUTABLE_STORAGE_ROOT = DISK_ROOT + "/immutable"
MUTABLE_STORAGE_ROOT = DISK_ROOT + "/mutable"

DEBUG = False

def storage_init():
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


def get_immutable_handler( key ):
   """
   Local disk implementation of the get_immutable_handler API call.
   Given the hash of the data, return the data.
   Return None if not found.
   """
   
   global IMMUTABLE_STORAGE_ROOT
   
   data = None 
   path = os.path.join( IMMUTABLE_STORAGE_ROOT, key )
   
   try:
      with open( path, "r" ) as f:
         data = f.read() 
         
      return data
   
   except Exception, e:
      if DEBUG:
         traceback.print_exc()
      return None


def get_mutable_handler( url ):
   """
   Local disk implementation of the get_mutable_handler API call.
   Given a route URL to data, return the data itself.
   If we can't handle this URL, raise UnhandledURLException.
   Return the data if found.
   Return None if not.
   """
   
   global MUTABLE_STORAGE_ROOT
   
   if not url.startswith( "file://" ):
      # invalid
      return None 
   
   # get path from URL 
   path = url[ len("file://"): ]
   
   try:
      with open( path, "r" ) as f:
         data = f.read()
      
      return data 
   
   except Exception, e:
      if DEBUG:
         traceback.print_exc()
      return None 


def put_immutable_handler( key, data, txid ):
   """
   Local disk implmentation of the put_immutable_handler API call.
   Given the hash of the data (key), the serialized data itself,
   and the transaction ID in the blockchain that contains the data's hash,
   put the data into the storage system.
   Return True on success; False on failure.
   """
   
   global IMMUTABLE_STORAGE_ROOT
   
   path = os.path.join( IMMUTABLE_STORAGE_ROOT, key )
   
   try:
      with open( path, "w+") as f:
         f.write( data )
   except Exception, e:
      if DEBUG:
         traceback.print_exc()
      return False 
   
   return True 


def put_mutable_handler( data_id, nonce, signature, data_json ):
   """
   Local disk implementation of the put_mutable_handler API call.
   Given the the unchanging ID for the data, a nonce representing
   this version of the data, the writer's signature over hash(data_id + data + nonce),
   and the serialized JSON representing all of the above plus the data, put 
   the serialized JSON into storage.
   Return True on success; False on failure.
   """
   
   global MUTABLE_STORAGE_ROOT
   
   # replace all /'s with \x2f's
   data_id_noslash = data_id.replace( "/", r"\x2f" )
   path = os.path.join( MUTABLE_STORAGE_ROOT, data_id_noslash )
   
   with open( path, "w+" ) as f:
      f.write( data_json )
   
   return True 


def delete_immutable_handler( key, txid ):
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


def delete_mutable_handler( data_id, signature ):
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
   current_dir =  os.path.abspath(os.path.dirname(__file__))
   sys.path.insert(0, current_dir)
   
   current_dir =  os.path.abspath(os.path.join( os.path.dirname(__file__), "..") )
   sys.path.insert(0, current_dir)
   
   from parsing import json_stable_serialize
   from storage import mutable_data_parse, mutable_data
   
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
      
   
   