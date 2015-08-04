"""
    Blockstore
    ~~~~~
    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

# this module contains the high-level methods for talking to ancillary storage.

import os
import sys
# current_dir =  os.path.abspath(os.path.dirname(__file__))
# sys.path.insert(0, current_dir)

from kademlia.network import Server

from twisted.python import log
from twisted.internet.error import ConnectionRefusedError
from twisted.internet import reactor
from txjsonrpc.netstring.jsonrpc import Proxy

from .dht.storage import BlockStorage
from ..client import mutable_data_route, mutable_data_route_parse, mutable_data_parse

from txjsonrpc.netstring import jsonrpc
from twisted.application import service, internet

from kademlia.network import Server

from .parsing import json_stable_serialize 

import pybitcoin
import types
import re


class UnhandledURLException( Exception ):
   def __init__(self, url):
      super( UnhandledURLException, self ).__init__()
      self.unhandled_url = url 

# mutable storage route
ROUTE_SCHEMA = {
   
   "id": schemas.STRING,
   "urls": schemas.STRING_ARRAY,
   schemas.OPTIONAL( "pubkey" ): schemas.STRING
}


# mutable data schema 
MUTABLE_DATA_SCHEMA = {
   
   "id": schemas.STRING,
   "data": schemas.B64STRING,
   "nonce": schemas.INTEGER,
   "sig": schemas.B64STRING
}


def mutable_data_route( data_id, data_urls, writer_pubkey=None ):
   """
   Construct a mutable data route as a dict.  This can be serialized to JSON.
   """
   
   # sanity check 
   if type(data_id) not in [types.StringType, types.UnicodeType]:
      raise Exception("Data ID must be a string (got '%s')" % str(data_id))
   
   if type(data_urls) != types.ListType:
      raise Exception("Data URLs must be an array of strings")
   
   for url in data_urls:
      if type(url) not in [types.StringType, types.UnicodeType]:
         raise Exception("Data URL must be a string (got '%s')" % str(url))
   
   if writer_pubkey is not None:
      if writer_pubkey not in [types.StringType, types.UnicodeType]:
         raise Exception("Writer public key must be encoded as a string (got '%s')" % str(writer_pubkey))
      
   route = {
      "id": data_id,
      "urls": data_urls
   }
   
   if write_pubkey is not None:
      route['pubkey'] = writer_pubkey
   
   return route


def mutable_data_route_parse( route_json_text ):
   """
   Given the serialized JSON for a mutable data route, 
   parse it into a JSON document.
   """
   
   # sanity check 
   if type(route_json_text) not in [types.StringType, types.UnicodeType]:
      raise Exception("JSON is not a valid string")
   
   try:
      route_object = json.loads( route_json_text )
   except Exception, e:
      log.error("Not a JSON string: '%s'" % str(route_json_text))
      raise e
   
   # validate against our route schema 
   if not schemas.schema_match( route_object, ROUTE_SCHEMA ):
      raise Exception("Not a valid route: '%s'" % str(route_json_text))
      
   return route_object 


def mutable_data_parse( mutable_data_json_text ):
   """
   Given the serialized JSON for a piece of mutable data,
   parse it into a JSON document.
   """
   
   # sanity check 
   if type(mutable_data_json_text) not in [types.StringType, types.UnicodeType]:
      raise Exception("JSON is not a valid string")
   
   try:
      data_object = json.loads( mutable_data_json_text )
   except Exception, e:
      log.error("Not a JSON string: '%s'" % str(mutable_data_json_text))
   
   # validate against data schema 
   if not schemas.schema_match( data_object, MUTABLE_DATA_SCHEMA ):
      raise Exception("Not a valid mutable data object: '%s'" % str(mutable_data_json_text))
   
   return data_object 


def dht_get_mutable( data_url ):
   """
   Given a DHT URL (i.e. "dht:<hash>"), go fetch the data.
   Return None if not found.
   """
   global dht_server 
   if dht_server is None:
      raise Exception("DHT is not initialized")
   
   data_id_hash = dht_url_parse( data_url )
   data_route_json = dht_get_route( data_id_hash )
   
   if data_route_json is None:
      return None 
   
   data_route = None
   try:
      data_route = mutable_data_route_parse( data_route_json )
   except Exception, e:
      return None 
   
   # 