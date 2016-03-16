#!/usr/bin/env python
# -*- coding: utf-8 -*-
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

# this module contains the high-level methods for talking to ancillary storage.

import os
import sys

# hack around absolute paths
current_dir =  os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, current_dir)

import pybitcoin
import bitcoin as pybitcointools
import types
import re
import base64
import json
import hashlib

import blockstack_profiles 

from config import MAX_NAME_LENGTH, get_logger

log = get_logger()

class UnhandledURLException( Exception ):
   def __init__(self, url):
      super( UnhandledURLException, self ).__init__()
      self.unhandled_url = url


def is_valid_hash( value ):
    """
    Is this string a valid 32-byte hash?
    """
    if type(value) not in [str, unicode]:
        return False 
  
    strvalue = str(value)
  
    if re.match(r"^[a-fA-F0-9]+$", strvalue ) is None:
        return False 
  
    if len(strvalue) != 64: 
        return False 

    return True


# global list of registered data handlers
storage_handlers = []


def get_data_hash( data_txt ):
   """
   Generate a hash over data for immutable storage.
   Return the hex string.
   """
   h = hashlib.sha256()
   h.update(data_txt)
   return h.hexdigest()


def get_user_zonefile_hash( data_txt ):
   """
   Generate a hash over a user's zonefile.
   Return the hex string.
   """
   return pybitcoin.hex_hash160( data_txt )


def make_mutable_data_urls( data_id ):
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


def serialize_mutable_data( data_json, privatekey ):
   """
   Generate a serialized mutable data record from the given information.
   Sign it with privatekey.

   Return the serialized data (as a string) on success
   """

   tokenized_data = blockstack_profiles.sign_token_records( [data_json], privatekey )
   serialized_data = json.dumps( tokenized_data, sort_keys=True )
   return serialized_data


def parse_mutable_data( mutable_data_json_txt, public_key ):
   """
   Given the serialized JSON for a piece of mutable data,
   parse it into a JSON document.  Verify that it was 
   signed by public_key's private key.

   Return the parsed JSON dict on success
   Return None on error
   """

   mutable_data_jwt = json.loads(mutable_data_json_txt)
   mutable_data_json = blockstack_profiles.get_profile_from_tokens( mutable_data_jwt, public_key )
   return mutable_data_json


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
   if storage_impl in storage_handlers:
       log.debug("WARN: already registered '%s'" % storage_impl)
       return True 

   storage_handlers.append( storage_impl )

   # sanity check
   for expected_method in ["make_mutable_url", "get_immutable_handler", "get_mutable_handler", \
                           "put_immutable_handler", "put_mutable_handler", \
                           "delete_immutable_handler", "delete_mutable_handler" ]:

      if not hasattr( storage_impl, expected_method ):
         log.warning("Storage implementation is missing a '%s' method" % expected_method )

   return True


def get_immutable_data( data_key, hash_func=get_data_hash ):
   """
   Given the hash of the data, go through the list of
   immutable data handlers and look it up.

   Return the data on success

   """
   global storage_handlers
   if len(storage_handlers) == 0:
       log.debug("No storage handlers registered")
       return None

   for handler in storage_handlers:

      if not hasattr( handler, "get_immutable_handler" ):
         log.debug("No method: %s.get_immutable_handler(%s)" % (handler, data_key))
         continue

      data = None

      try:

         data = handler.get_immutable_handler( data_key )
      except Exception, e:
         log.exception( e )
         continue

      if data is None:
         log.debug("No data: %s.get_immutable_handler(%s)" % (handler, data_key))
         continue

      # validate
      data_hash = hash_func(data)
      if data_hash != data_key:
         # nope
         log.error("Invalid data hash")
         continue

      return data

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


def get_mutable_data( fq_data_id, data_pubkey, urls=None ):
   """
   Given a mutable data's zonefile, go fetch the data.

   Return a mutable data dict on success
   Return None on error
   """

   global storage_handlers
   assert is_fq_data_id( fq_data_id ) or is_valid_name( fq_data_id ), "Need either a fully-qualified data ID or a Blockstack DNS name"

   if urls is None:
       # generate them 
       urls = make_mutable_data_urls( fq_data_id )

   for storage_handler in storage_handlers:

      if not hasattr(storage_handler, "get_mutable_handler"):
         continue

      for url in urls:

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
         data = parse_mutable_data( data_json, data_pubkey )
         if data is None:
            log.error("Unparseable data from '%s'" % url)
            continue

         return data

   return None


def put_immutable_data( data_text, txid, data_hash=None ):
   """
   Given a string of data (which can either be data or a zonefile), store it into our immutable data stores.
   Do so in a best-effort manner--this method only fails if *all* storage providers fail.

   Return the hash of the data on success
   Return None on error
   """

   global storage_handlers

   if data_hash is None:
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


def put_mutable_data( fq_data_id, data_json, privatekey ):
   """
   Given the unserialized data, store it into our mutable data stores.
   Do so in a best-effort way.  This method only fails if all storage providers fail.

   @fq_data_id is the fully-qualified data id.  It must be prefixed with the username,
   to avoid collisions in shared mutable storage.

   Return True on success
   Return False on error
   """

   assert is_fq_data_id( fq_data_id ) or is_valid_name(fq_data_id), "Data ID must be fully qualified or must be a valid Blockstack DNS name"

   serialized_data = serialize_mutable_data( data_json, privatekey )
   successes = 0

   for handler in storage_handlers:

      if not hasattr( handler, "put_mutable_handler" ):
         continue

      rc = False

      try:

         rc = handler.put_mutable_handler( fq_data_id, serialized_data )
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


def delete_immutable_data( data_hash, txid, privkey ):
   """
   Given the hash of the data, the private key of the user,
   and the txid that deleted the data's hash from the blockchain,
   delete the data from all immutable data stores.
   """

   global storage_handlers

   sigb64 = sign_raw_data( data_hash + txid, privkey )

   for handler in storage_handlers:

      if not hasattr( handler, "delete_immutable_handler" ):
         continue

      try:

         handler.delete_immutable_handler( data_hash, txid, sigb64 )
      except Exception, e:

         log.exception( e )
         continue

   return True


def delete_mutable_data( data_id, privatekey ):
   """
   Given the data ID and private key of a user,
   go and delete the associated mutable data.
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


def make_fq_data_id( name, data_id ):
    """
    Make a fully-qualified data ID, prefixed by the name.
    """
    return "%s:%s" % (name, data_id)


import string
B40_CHARS = string.digits + string.lowercase + '-_.+'
B40_REGEX = '^[a-z0-9\-_.+]*$'

def is_b40(s):
    return (isinstance(s, str) and (re.match(B40_REGEX, s) is not None))


def is_fq_data_id( fq_data_id ):
    """
    Is a data ID is fully qualified?
    """
    if len(fq_data_id.split(":")) < 2:
        return False 

    # name must be valid
    name = fq_data_id.split(":")[0]
    if not is_valid_name(name):
        return False

    return True


def is_valid_name( name ):
    """
    Is a name well-formed for blockstack DNS?
    """
    
    # name must be base-40, and there must be a namespace ID
    if not is_b40(name) or name.count(".") != 1:
        return False 

    if len(name) > MAX_NAME_LENGTH:
        return False

    return True


if __name__ == "__main__":
    # unit tests
    import user
    import config
    import pybitcoin

    pk = pybitcoin.BitcoinPrivateKey()
    data_privkey = pk.to_hex()
    data_pubkey = pk.public_key().to_hex()
    
    conf = config.make_default_config()
    
    user_profile = user.make_empty_user_zonefile( "judecn.id", data_pubkey )
    
