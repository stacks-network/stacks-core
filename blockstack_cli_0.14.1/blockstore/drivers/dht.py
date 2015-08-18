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

# this module contains the plugin to blockstack that makes the DHT useful as ancillary storage

import os
import sys
import traceback 

from kademlia.network import Server

from twisted.internet import reactor
from twisted.application import service, internet

import types 
import re 
import pybitcoin


DHT_SERVER_PORT = 6265  # blockstored default to port 6264

DEFAULT_DHT_SERVERS = [('dht.openname.org', DHT_SERVER_PORT),
                       ('dht.onename.com', DHT_SERVER_PORT),
                       ('dht.halfmoonlabs.com', DHT_SERVER_PORT),
                       ('127.0.0.1', DHT_SERVER_PORT)]

# 3 years
STORAGE_TTL = 3 * 60 * 60 * 24 * 365

NONE_VALUE = "(null)"


# client to the DHT 
dht_server = None 

def dht_data_hash( data ):
   """
   Calculate a key from the data.
   """
   return pybitcoin.hash.hex_hash160( data )


def dht_init():
   """
   Establish our connection to the DHT, and give 
   it the requisite state it needs (i.e. an API 
   proxy to blockstore)
   """
   
   global dht_server
   
   dht_server = Server(storage=BlockStorage())
   dht_server.listen( DHT_SERVER_PORT )
   bootstrap_servers = hostname_to_ip(DEFAULT_DHT_SERVERS)
   dht_server.bootstrap(bootstrap_servers)
   
   return True 


def dht_get_key( data_key ):
   """
   Given a key (a hash of data), go fetch the data.
   """
   
   global dht_server 
   if dht_server is None:
      raise Exception("DHT is not initialized")
   
   value = dht_server.get( data_key )
   if value == NONE_VALUE:
      return None 
   else:
      return value


def dht_put_data( data_key, data_value ):
   """
   Given a key and value, put it into the DHT.
   """
   global dht_server 
   if dht_server is None:
      raise Exceptoin("DHT is not initialized")
   
   if data_value is None:
      data_value = NONE_VALUE
      
   return dht_server.set( data_key, data_value )


# ---------------------------------------------------------
# Begin plugin implementation 
# ---------------------------------------------------------

def storage_init():
   """
   DHT implementation of the storage_init API call.
   Given the blockstore API proxy, set up any persistent state.
   Return True on success
   Return False on error 
   """
   return dht_init()


def make_mutable_url( data_id ):
   """
   DHT implementation of the make_mutable_url API call.
   Given the ID of the data, generate a URL that 
   can be used to route reads and writes to the data.
   
   Return a string.
   """
   return "dht:" + pybitcoin.hash.hex_hash160( data_id )


def get_immutable_handler( key ):
   """
   DHT implementation of the get_immutable_handler API call.
   Given the hash of the data, return the data.
   Return None if not found.
   """
   return dht_get_key( key )


def get_mutable_handler( data_id ):
   """
   DHT implementation of the get_mutable_handler API call.
   Given a route URL to data, return the data itself.
   If we can't handle this URL, raise UnhandledURLException.
   Return the data if found.
   Return None if not.
   """
   return dht_get_key( dht_data_hash( data_id ) )


def put_immutable_handler( key, data, txid ):
   """
   DHT implmentation of the put_immutable_handler API call.
   Given the hash of the data (key), the serialized data itself,
   and the transaction ID in the blockchain that contains the data's hash,
   put the data into the storage system.
   Return True on success; False on failure.
   """
   
   # TODO: the DHT in use at Onename should check to see that the user exists, and can write this data.
   
   return dht_put_data( key, data )


def put_mutable_handler( data_id, nonce, signature, data_json ):
   """
   DHT implementation of the put_mutable_handler API call.
   Given the the unchanging ID for the data, a nonce representing
   this version of the data, the writer's signature over hash(data_id + data + nonce),
   and the serialized JSON representing all of the above plus the data, put 
   the serialized JSON into storage.
   Return True on success; False on failure.
   """
   
   # TODO: the DHT in use at Onename should check to see that the user exists, and can write this data.
   
   try:
      rc = dht_put_data( dht_data_hash( data_id ), data_json )
   except Exception, e:
      traceback.print_exc()
      return False 
   
   return True 


def delete_immutable_handler( key, txid ):
   """
   DHT implementation of the delete_immutable_handler API call.
   Given the hash of the data and transaction ID of the update
   that deleted the data, remove data from the DHT.
   Return True on success; False if not.
   """
   
   # TODO: the DHT in use at Onename should check to see that the user exists, and can delete the data.
   
   return dht_put_data( key, None )


def delete_mutable_handler( data_id, signature ):
   """
   DHT implementation of the delete_mutable_handler API call.
   Given the unchanging data ID for the data and the writer's
   signature over the hash of the data_id, remove data from the DHT.
   Return True on success; False if not.
   """
   
   # TODO: the DHT in use at Onename should check to see that the user exists, and can delete the data.
   
   # put a null route to the data.
   try:
      rc = dht_put_data( dht_data_hash( data_id ), None )
      if not rc:
         return False 

   except Exception, e:
      traceback.print_exc()
      return False 
   
   return True 
   