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

DISK_ROOT="/tmp/blockstore-disk"
IMMUTABLE_STORAGE_ROOT = DISK_ROOT + "/immutable"
MUTABLE_STORAGE_ROOT = DISK_ROOT + "/mutable"

def storage_init():
   """
   Local disk implementation of the storage_init API call.
   Given the blockstore API proxy, set up any persistent state.
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
   
   with open( path, "r" ) as f:
      data = f.read() 
      
   return data


def get_mutable_handler( data_id ):
   """
   Local disk implementation of the get_mutable_handler API call.
   Given a route URL to data, return the data itself.
   If we can't handle this URL, raise UnhandledURLException.
   Return the data if found.
   Return None if not.
   """
   
   global MUTABLE_STORAGE_ROOT
   
   # replace all /'s with \x2f's
   data_id_noslash = data_id.replace( "/", r"\x2f" )
   path = os.path.join( MUTABLE_STORAGE_ROOT, data_id_noslash )
   
   with open( path, "r" ) as f:
      data = f.read()
      
   return data


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
   
   with open( path, "w+") as f:
      f.write( data )
   
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
   
   
   