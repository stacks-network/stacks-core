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

from .parsing import json_stable_serialize 
from . import schemas

import pybitcoin
import pybitcointools
import types
import re
import base64

from .config import log

class UnhandledURLException( Exception ):
   def __init__(self, url):
      super( UnhandledURLException, self ).__init__()
      self.unhandled_url = url 

# mutable storage route
ROUTE_SCHEMA = {
   
   "id": schemas.STRING,
   "urls": [ schemas.STRING ],
   schemas.OPTIONAL( "pubkey" ): schemas.STRING
}


# mutable data schema 
MUTABLE_DATA_SCHEMA = {
   
   "id": schemas.STRING,
   "data": schemas.B64STRING,
   "nonce": schemas.INTEGER,
   "sig": schemas.B64STRING
}

# data replication strategies
REPLICATE_ALL = "replicate_all"         # replicate to each data storage provider 
REPLICATE_ANY = "replicate_any"         # replicate to at least one storage provider 

# global list of registered data handlers 
storage_handlers = []


def get_data_hash( data_text ):
   """
   Generate a hash over data for immutable storage.
   Return the hex string.
   """
   return pybitcoin.hash.hex_hash160( data_text )

def make_mutable_urls( data_id ):
   """
   Given a data ID for mutable data, get a list of URLs to it 
   by asking the storage handlers.
   """
   global storage_handlers
   
   urls = []
   
   for handler in storage_handlers:
      
      if not hasattr(handler, "make_mutable_url"):
         continue 
      
      new_url = None 
      
      try:
         new_url = handler.make_mutable_url( data_id )
      except Exception, e:
         log.exception(e)
         continue 
      
      urls.append( new_url )
      
   return new_urls 


def mutable_data_route( data_id, data_urls, writer_pubkey=None ):
   """
   Construct a mutable data route as a dict.  This can be serialized to JSON.
   Return the parsed JSON dict on success.
   Return None on error
   """
   
   # sanity check 
   if type(data_id) not in [types.StringType, types.UnicodeType]:
      log.error("Data ID must be a string (got '%s')" % str(data_id))
      return None
   
   if type(data_urls) != types.ListType:
      log.error("Data URLs must be an array of strings")
      return None
   
   for url in data_urls:
      if type(url) not in [types.StringType, types.UnicodeType]:
         log.error("Data URL must be a string (got '%s')" % str(url))
         return None
   
   if writer_pubkey is not None:
      if writer_pubkey not in [types.StringType, types.UnicodeType]:
         log.error("Writer public key must be encoded as a string (got '%s')" % str(writer_pubkey))
         return None
      
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
   Return the dict with the JSON information on success 
   Return None on parse error
   """
   
   # sanity check 
   if type(route_json_text) not in [types.StringType, types.UnicodeType]:
      log.error("JSON is not a valid string")
      return None
   
   try:
      route_object = json.loads( route_json_text )
   except Exception, e:
      log.error("Not a JSON string: '%s'" % str(route_json_text))
      return None
   
   # validate against our route schema 
   if not schemas.schema_match( route_object, ROUTE_SCHEMA ):
      log.error("Not a valid route: '%s'" % str(route_json_text))
      return None
      
   return route_object 


def mutable_data( data_id, data_text, nonce, privkey=None, sig=None ):
   """
   Generate a mutable data dict from the given information.
   If sig is given, use sig
   If privkey is given and sig is not, then sign the data with privkey.
   otherwise, return None (this is an error)
   """
   data = {
      "id": str(data_id),
      "data": str(data_text),
      "nonce": int(nonce)
   }
   
   if sig is not None:
      data['sig'] = sig 
      
   elif sig is None and privkey is not None:
      data['sig'] = sign_mutable_data( data, privkey )
   
   else:
      return None
   
   return data 

   

def mutable_data_parse( mutable_data_json_text ):
   """
   Given the serialized JSON for a piece of mutable data,
   parse it into a JSON document.
   Return the parsed JSON dict on success
   Return None on error
   """
   
   # sanity check 
   if type(mutable_data_json_text) not in [types.StringType, types.UnicodeType]:
      log.error("JSON is not a valid string")
      return None
   
   try:
      data_object = json.loads( mutable_data_json_text )
   except Exception, e:
      log.error("Not a JSON string: '%s'" % str(mutable_data_json_text))
      return None
   
   # validate against data schema 
   if not schemas.schema_match( data_object, MUTABLE_DATA_SCHEMA ):
      log.error("Not a valid mutable data object: '%s'" % str(mutable_data_json_text))
      return None
   
   return data_object 



def register_storage( storage_impl ):
   """
   Given a class, module, etc. with the methods,
   register the mutable and immutable data handlers.
   
   The given argument--storage_impl--must persist for 
   as long as the application will be using its methods.
   
   Return True on success 
   Return False on error 
   """
   
   global storage_handlers
   storage_handlers.append( storage_impl )
   
   # sanity check 
   for expected_method in ["make_mutable_url", "get_immutable_handler", "get_mutable_handler", \
                           "put_immutable_handler", "put_mutable_handler", \
                           "delete_immutable_handler", "delete_mutable_handler" ]:
      
      if not hasattr( storage_impl, expected_method ):
         log.warning("Storage implementation is missing a '%s' method" % expected_method )
   
   return True
   

def get_immutable_data( data_key ):
   """
   Given the hash of the data, go through the list of
   immutable data handlers and look it up.
   
   Return the data on success 
   
   """
   global storage_handlers
   
   for handler in storage_handlers:
      
      if not hasattr( handler, "get_immutable_handler" ):
         continue 
      
      data = None 
      
      try:
         
         data = handler.get_immutable_handler( data_key )
      except Exception, e:
         log.exception( e ) 
         continue 
      
      # validate 
      data_hash = get_data_hash( data )
      if data_hash != data_key:
         # nope 
         log.error("Invalid data hash")
         continue 
      
      return data 
   
   return None 


def get_mutable_data_route_hash( route ):
   """
   Given an unserialized route, get its hash.
   Return the hash on success
   Return None on error
   """
   route_json = parsing.json_stable_serialize( route )
   if route_json is None:
      return None 
   
   return get_data_hash( route_json )
   

def get_mutable_data_route( data_id, route_hash ):
   """
   Given a data ID, go fetch its route.  Verify that it matches the given hash
   Return a dict with the route information on success.
   Return None on error.
   """
   global storage_handlers
   
   for handler in storage_handlers:
      
      if not hasattr( handler, "get_immutable_handler" ):
         continue 
      
      route_json = None 
      route = None
      
      try:
         
         route_json = handler.get_immutable_handler( route_hash )
      except Exception, e:
         
         log.exception(e)
         continue 
      
      if get_data_hash( route_json ) != route_hash:
         log.error("Invalid route: hash mismatch")
         continue 
      
      # it had better be a JSON doc we can use 
      try:
         route = mutable_data_route_parse( route_json )
      except Exception, e:
         
         log.exception(e)
         continue 
   
      if route['id'] != data_id:
         log.error("Invalid route: id mismatch")
         continue 
      
      return route 
   
   return None 


def verify_mutable_data( data, pubkey ):
   """
   Given the data (as a dict) and the base64-encoded signature,
   as well as the public key from the data route,
   verify that the signature matches.
   """
   
   sigb64 = data['sig']
   data['sig'] = ""
   
   data_text = parsing.json_stable_serialize( data )
   data_hash = get_data_hash( data )
   
   rc = pybitcointools.ecdsa_raw_verify( data_hash, pybitcointools.decode_sig( sigb64 ), pubkey )
   return rc


def get_mutable_data( data_route, min_nonce=None, max_nonce=None, nonce_check=None ):
   """
   Given a data's route, go fetch the data.
   
   Optionally verify that the nonce in the data returned is within [min_nonce, max_nonce],
   or no less than min_nonce, or no greater than max_nonce.
   
   Optionally evaluate nonce with nonce_check, which takes the data structure and returns true if the nonce is valid.
   
   Return a mutable data dict on success 
   Return None on error
   """
   
   global storage_handlers
   
   data_id = data_route['id']
   data_urls = data_route['urls']
   data_pubkey = data_route.get('pubkey', None)
   
   for storage_handler in storage_handlers:
      
      if not hasattr(storage_handler, "get_mutable_handler"):
         continue
      
      for url in data_urls:
         
         data_json = None 
         data = None 
         
         try:
            
            data_json = storage_handler.get_mutable_handler( url )
            
         except UnhandledURLException, uue:
            
            # handler doesn't handle this URL 
            continue 
         
         except Exception, e:
            
            log.exception( e )
            continue 
         
         if data_json is None:
            # no data
            continue 
         
         # parse it
         data = mutable_data_parse( data_json )
         if data is None:
            log.error("Unparseable data")
            continue
         
         # if the route includes a private key, verify it 
         if pubkey is not None:
            
            rc = verify_mutable_data( data, pubkey )
            if not rc:
               
               log.error("Invalid signature")
               continue 
         
         
         # verify nonce, if need be
         if min_nonce is not None:
            if data['nonce'] < min_nonce:
               continue 
         
         if max_nonce is not None:
            if data['nonce'] > max_nonce:
               continue 
            
         if nonce_check is not None:
            rc = nonce_check( data )
            if not rc:
               continue 
         
         return data 
      
   return None 


def put_immutable_data( data_text, txid, replication_strategy=REPLICATE_ALL ):
   """
   Given a string of data (which can either be data or a route), store it into our immutable data stores.
   If replication_strategy is REPLICATE_ALL, then we succeed only when we replicate to each data store.
   IF it is REPLICATE_ANY, we succeed as soon as we replicate successfully once.
   
   Return the hash of the data on success
   Return None on error
   """
   
   global storage_handlers
   
   data_hash = get_data_hash( data_text )
   
   for handler in storage_handlers:
      
      if not getattr(handler, "put_immutable_handler"):
         continue 
      
      rc = False 
      
      try:
         
         rc = handler.put_immutable_handler( data_hash, data_text, txid )
      except Exception, e:
         
         log.exception(e)
         
         if replication_strategy == REPLICATE_ALL:
            # one failed
            return None 
         
         else:
            continue 
      
      if not rc:
         
         if replication_strategy == REPLICATE_ALL:
            # one failed 
            return None 
         
         else:
            continue 
         
      # succeeded
      return data_hash 
         
   return None 


def sign_mutable_data( data, privatekey ):
   """
   Given a mutable data dict and a ECDSA private key,
   generate and return a base64-encoded signature over the fields that matter (i.e. the data_id, nonce, and data).
   Return the signature.
   """
   
   data_str = str(data['id']) + str(data['nonce']) + str(data['data'])
   data_hash = get_data_hash( data_str )
   
   data_sig_bin = pybitcointools.ecdsa_raw_sign( data_hash, privatekey )
   return pybitcointools.encode_sig( data_sig_bin )


def put_mutable_data( data, privatekey, replication_strategy=REPLICATE_ALL ):
   """
   Given the unserialized data, store it into our mutable data stores.
   If replication_strategy is REPLICATE_ALL, then we succeed only when we replicate to each data store.
   IF it is REPLICATE_ANY, we succeed as soon as we replicate successfully once.
   
   If the data is not signed, then it will be signed with the given private key.
   
   Return True on success 
   Return False on error 
   """ 
   
   data_id = data['id']
   data_text = data['data']
   nonce = data['nonce']
   sig = data.get('sig', None)
   
   if sig is None:
      sig = sign_mutable_data( data, privatekey )
      data['sig'] = sig
      
   data_json = parsing.json_stable_serialize( data )
   
   for handler in storage_handlers:
      
      if not hasattr( handler, "put_mutable_handler" ):
         continue 
      
      rc = False 
      
      try:
         
         handler.put_mutable_handler( data_id, nonce, sig, data_json )
      except Exception, e:
         
         log.exception( e )
         
         if replication_strategy == REPLICATE_ALL:
            # one failed 
            return False 
         else:
            continue 
         
      if not rc:
         
         if replication_strategy == REPLICATE_ALL:
            # one failed 
            return False 
         else:
            continue 
         
      return True 
   
   return False


def delete_immutable_data( data_hash, txid ):
   """
   Given the hash of the data, the private key of the user,
   and the txid that deleted the data's hash from the blockchain,
   delete the data from all immutable data stores.
   """
   
   global storage_handlers
   
   for handler in storage_handlers:
      
      if not hasattr( handler, "delete_immutable_handler" ):
         continue 
      
      try:
         
         handler.delete_immutable_handler( data_hash, txid )
      except Exception, e:
         
         log.exception( e )
         continue 

   return True 


def delete_mutable_data( data_id, privatekey ):
   """
   Given the data ID, route hash, user private key, and transaction ID 
   of the blockchain transaction that deleted the data route, go delete 
   both the data route and the mutable data it points to.
   """
   
   global storage_handlers
   
   # sign the data_id to prove authenticity to the storage system 
   signature = sign_mutable_data( data_id, privatekey )
   
   # remove data 
   for handler in storage_handlers:
      
      if not hasattr( handler, "delete_mutable_handler" ):
         continue 
      
      try:
         
         handler.delete_mutable_handler( data_id, signature )
      except Exception, e:
         
         log.exception( e )
         continue
      
   return True 

   
      