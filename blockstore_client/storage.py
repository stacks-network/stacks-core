#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

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
    along with Blockstore-client. If not, see <http://www.gnu.org/licenses/>.
"""

# this module contains the high-level methods for talking to ancillary storage.

import os
import sys

# hack around absolute paths
current_dir =  os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, current_dir)

from parsing import json_stable_serialize
import schemas

import pybitcoin
import bitcoin as pybitcointools
import types
import re
import base64
import json

from config import log

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
   "ver": schemas.INTEGER,
   "sig": schemas.B64STRING
}

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

   return urls


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
      if type(writer_pubkey) not in [types.StringType, types.UnicodeType]:
         log.error("Writer public key must be encoded as a string (got '%s')" % str(writer_pubkey))
         return None

   route = {
      "id": data_id,
      "urls": data_urls
   }

   if writer_pubkey is not None:
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
   if not schemas.schema_match( ROUTE_SCHEMA, route_object ):
      log.error("Not a valid route: '%s'" % str(route_json_text))
      return None

   return route_object


def mutable_data_encode( data ):
   """
   Encode the 'data' field of a mutable data dict, making
   it suitable for storing and printing to a console.
   Call this method after mutable_data( encode=False )
   to encode the data.
   """

   data['data'] = base64.b64encode( data['data'] )


def mutable_data_decode( data ):
   """
   Decode the 'data' field of a mutable data dict.
   Call this method after mutable_data_parse( decode=False )
   to recover the data.
   """

   data['data'] = base64.b64decode( data['data'] )


def mutable_data( data_id, data_text, ver, privkey=None, sig=None, encode=True ):
   """
   Generate a mutable data dict from the given information.
   If sig is given, use sig
   If privkey is given and sig is not, then sign the data with privkey.
   otherwise, return None (this is an error)
   """
   data = {
      "id": str(data_id),
      "data": data_text,
      "ver": int(ver)
   }

   if encode:
      mutable_data_encode( data )

   if sig is not None:
      data['sig'] = sig

   elif sig is None and privkey is not None:
      data['sig'] = sign_mutable_data( data, privkey )

   else:
      # need a sig or a private key!
      return None

   return data


def mutable_data_parse( mutable_data_json_text, decode=True ):
   """
   Given the serialized JSON for a piece of mutable data,
   parse it into a JSON document.

   If decode is True, then decode the data string as well.

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

   # TODO: use the schema to check for possible type conversions,
   # and to carry out type conversions en masse.
   if not data_object.has_key('ver'):
      log.error("Not a valid mutable data object: missing 'ver'")
      return None

   try:
      data_object['ver'] = int( data_object['ver'] )
   except Exception, e:
      log.error("Not a valid mutable data object: '%s'" % str(mutable_data_json_text))
      return None

   # validate against data schema
   if not schemas.schema_match( MUTABLE_DATA_SCHEMA, data_object ):
      log.error("Not a valid mutable data object: '%s'" % str(mutable_data_json_text))
      return None

   # decode data
   if decode:
      mutable_data_decode( data_object )

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

      if data is None:
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
   route_json = json_stable_serialize( route )
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

      if route_json is None:
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


def sign_raw_data( raw_data, privatekey ):
   """
   Sign a string of data.
   Return a base64-encoded signature.
   """
   data_hash = get_data_hash( raw_data )

   data_sig_bin = pybitcointools.ecdsa_raw_sign( data_hash, privatekey )
   return pybitcointools.encode_sig( data_sig_bin[0], data_sig_bin[1], data_sig_bin[2] )


def verify_raw_data( raw_data, pubkey, sigb64 ):
   """
   Verify the signature over a string, given the public key
   and base64-encode signature.
   Return True on success.
   Return False on error.
   """

   data_hash = get_data_hash( raw_data )

   return pybitcointools.ecdsa_raw_verify( data_hash, pybitcointools.decode_sig( sigb64 ), pubkey )


def sign_mutable_data( data, privatekey ):
   """
   Given a mutable data dict and a ECDSA private key,
   generate and return a base64-encoded signature over the fields that matter (i.e. the data_id, ver, and data).
   Return the signature (baes64-encoded)
   """

   data_str = str(data['id']) + str(data['ver']) + str(data['data'])
   return sign_raw_data( data_str, privatekey )


def verify_mutable_data( data, pubkey ):
   """
   Given the data (as a dict) and the base64-encoded signature,
   as well as the public key from the data route,
   verify that the signature matches.
   """

   sigb64 = data['sig']

   data_str = str(data['id']) + str(data['ver']) + str(data['data'])

   return verify_raw_data( data_str, pubkey, sigb64 )


def get_mutable_data( data_route, ver_min=None, ver_max=None, ver_check=None ):
   """
   Given a data's route, go fetch the data.

   Optionally verify that the version ('ver') in the data returned is within [ver_min, ver_max],
   or no less than ver_min, or no greater than ver_max.

   Optionally evaluate version with ver_check, which takes the data structure and returns true if the version is valid.

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

         # parse it, but don't decode it yet
         data = mutable_data_parse( data_json, decode=False )
         if data is None:
            log.error("Unparseable data")
            continue

         # if the route includes a private key, verify it
         if data_pubkey is not None:

            rc = verify_mutable_data( data, data_pubkey )
            if not rc:

               log.error("Invalid signature")
               continue

         # can decode the data now, since we've checked the sig
         mutable_data_decode( data )

         # verify ver, if need be
         if ver_min is not None:
            if data['ver'] < ver_min:
               continue

         if ver_max is not None:
            if data['ver'] > ver_max:
               continue

         if ver_check is not None:
            rc = ver_check( data )
            if not rc:
               continue

         return data

   return None


def put_immutable_data( data_text, txid ):
   """
   Given a string of data (which can either be data or a route), store it into our immutable data stores.
   Do so in a best-effort manner--this method only fails if *all* storage providers fail.

   Return the hash of the data on success
   Return None on error
   """

   global storage_handlers

   data_hash = get_data_hash( data_text )
   successes = 0

   for handler in storage_handlers:

      if not getattr(handler, "put_immutable_handler"):
         continue

      rc = False

      try:

         rc = handler.put_immutable_handler( data_hash, data_text, txid )
      except Exception, e:

         log.exception(e)
         continue

      if not rc:
         log.error("Failed to replicate with '%s'" % handler.__name__)

      else:
         successes += 1

   if successes == 0:
       # failed everywhere
       return None

   else:
       # succeeded somewhere
       return data_hash


def put_mutable_data( data, privatekey ):
   """
   Given the unserialized data, store it into our mutable data stores.
   Do so in a best-effor way.  This method only fails if all storage providers fail.

   If the data is not signed, then it will be signed with the given private key.

   Return True on success
   Return False on error
   """

   data_id = data['id']
   data_text = data['data']
   ver = data['ver']
   sig = data.get('sig', None)

   if sig is None:
      sig = sign_mutable_data( data, privatekey )
      data['sig'] = sig

   data_json = json_stable_serialize( data )

   successes = 0

   for handler in storage_handlers:

      if not hasattr( handler, "put_mutable_handler" ):
         continue

      rc = False

      try:

         rc = handler.put_mutable_handler( data_id, ver, sig, data_json )
      except Exception, e:

         log.exception( e )
         continue

      if not rc:
         log.error("Failed to replicate with '%s'" % handler.__name__)

      else:
         successes += 1

   if successes == 0:
       # failed everywhere
       return False

   else:
       # succeeded somewhere
       return True


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

   sigb64 = sign_raw_data( data_id, privatekey )

   # remove data
   for handler in storage_handlers:

      if not hasattr( handler, "delete_mutable_handler" ):
         continue

      try:

         handler.delete_mutable_handler( data_id, sigb64 )
      except Exception, e:

         log.exception( e )
         continue

   return True
