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
import urllib
import urllib2
import blockstack_zones
from collections import defaultdict

import blockstack_profiles 

from config import MAX_NAME_LENGTH, get_logger, CONFIG_PATH

log = get_logger()

import string

B40_CHARS = string.digits + string.lowercase + '-_.+'
B40_CLASS = '[a-z0-9\-_.+]'
B40_NO_PERIOD_CLASS = '[a-z0-9\-_+]'
B40_REGEX = '^%s*$' % B40_CLASS
URLENCODED_CLASS = '[a-zA-Z0-9\-_.~%]'

# global list of registered data handlers
storage_handlers = []


def is_b40(s):
    return (isinstance(s, str) and (re.match(B40_REGEX, s) is not None))


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


def get_data_hash( data_txt ):
   """
   Generate a hash over data for immutable storage.
   Return the hex string.
   """
   h = hashlib.sha256()
   h.update(data_txt)
   return h.hexdigest()


def get_zonefile_data_hash( data_txt ):
   """
   Generate a hash over a user's zonefile.
   Return the hex string.
   """
   return pybitcoin.hex_hash160( data_txt )


def get_blockchain_compat_hash( data_txt ):
   """
   Generate a hash suitable for embedding into 
   the blockchain (e.g. for user zonefiles and
   announcements).
   """
   return pybitcoin.hex_hash160( data_txt )


def hash_zonefile( zonefile_json ):
    """
    Given a JSON-ized zonefile, calculate its hash
    """
    assert "$origin" in zonefile_json.keys(), "Missing $origin"
    assert "$ttl" in zonefile_json.keys(), "Missing $ttl"

    user_zonefile_txt = blockstack_zones.make_zone_file( zonefile_json )
    data_hash = get_zonefile_data_hash( user_zonefile_txt )
    return data_hash


def get_storage_handlers():
   """
   Get the list of loaded storage handler instances
   """
   global storage_handlers
   return storage_handlers


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

      if new_url is not None:
          urls.append( new_url )

   return urls


def serialize_mutable_data( data_json, privatekey ):
   """
   Generate a serialized mutable data record from the given information.
   Sign it with privatekey.

   Return the serialized data (as a string) on success
   """

   tokenized_data = blockstack_profiles.sign_token_records( [data_json], privatekey )
   del tokenized_data[0]['decodedToken']

   serialized_data = json.dumps( tokenized_data, sort_keys=True )
   return serialized_data


def parse_mutable_data( mutable_data_json_txt, public_key, public_key_hash=None ):
   """
   Given the serialized JSON for a piece of mutable data,
   parse it into a JSON document.  Verify that it was 
   signed by public_key's or public_key_hash's private key.

   Try to verify with both keys, if given.

   Return the parsed JSON dict on success
   Return None on error
   """

   assert public_key is not None or public_key_hash is not None, "need a public key or public key hash"

   mutable_data_jwt = None
   try:
       mutable_data_jwt = json.loads(mutable_data_json_txt)
       assert type(mutable_data_jwt) in [dict, list]
   except:
       log.error("Invalid JSON")
       return None 

   mutable_data_json = None 

   # try pubkey, if given 
   if public_key is not None:
       mutable_data_json = blockstack_profiles.get_profile_from_tokens( mutable_data_jwt, public_key )
       if len(mutable_data_json) > 0:
           return mutable_data_json
       else:
           log.warn("Failed to verify with public key '%s'" % public_key)

   # try pubkey address 
   if public_key_hash is not None:
       mutable_data_json = blockstack_profiles.get_profile_from_tokens( mutable_data_jwt, public_key_hash )
       if len(mutable_data_json) > 0:
           return mutable_data_json
       else:
           log.warn("Failed to verify with public key hash '%s'" % public_key_hash)

   return None


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
       return True 

   storage_handlers.append( storage_impl )

   # sanity check
   for expected_method in ["make_mutable_url", "get_immutable_handler", "get_mutable_handler", \
                           "put_immutable_handler", "put_mutable_handler", \
                           "delete_immutable_handler", "delete_mutable_handler" ]:

      if not hasattr( storage_impl, expected_method ):
         log.warning("Storage implementation is missing a '%s' method" % expected_method )

   return True


def get_immutable_data( data_hash, data_url=None, hash_func=get_data_hash, fqu=None, data_id=None, zonefile=False, deserialize=True, drivers=None ):
   """
   Given the hash of the data, go through the list of
   immutable data handlers and look it up.

   Optionally pass the fully-qualified name (@fqu) and human-readable data ID.

   Return the data (as a dict) on success.
   Return None on failure
   """

   global storage_handlers
   if len(storage_handlers) == 0:
       log.debug("No storage handlers registered")
       return None

   handlers_to_use = []
   if drivers is not None:
       # whitelist of drivers to try 
       for d in drivers:
           for h in storage_handlers:
               if h.__name__ == d:
                   handlers_to_use.append(h)

   else:
       handlers_to_use = storage_handlers

   log.debug("get_immutable %s" % data_hash)

   for handler in [data_url] + handlers_to_use:

      if handler is None:
         continue

      data = None
      if handler == data_url:
         # url hint
         try: 
            # assume it's something we can urlopen 
            urlh = urllib2.urlopen( data_url )
            data = urlh.read()
            urlh.close()
         except Exception, e:
            log.exception(e)
            log.error("Failed to load profile from '%s'" % data_url)
            continue

      else:
         # handler
         if not hasattr( handler, "get_immutable_handler" ):
            log.debug("No method: %s.get_immutable_handler(%s)" % (handler, data_hash))
            continue

         log.debug("Try %s (%s)" % (handler.__name__, data_hash))
         try:
            data = handler.get_immutable_handler( data_hash, data_id=data_id, zonefile=zonefile, fqu=fqu )
         except Exception, e:
            log.exception( e )
            log.debug("Method failed: %s.get_immutable_handler(%s)" % (handler, data_hash))
            continue

      if data is None:
         log.debug("No data: %s.get_immutable_handler(%s)" % (handler.__name__, data_hash))
         continue

      # validate
      dh = hash_func(data)
      if dh != data_hash:
         # nope
         if handler == data_url:
             log.error("Invalid data hash from '%s'" % data_url)
         else:
             log.error("Invalid data hash from %s.get_immutable_handler" % (handler.__name__))

         continue

      # deserialize 
      if deserialize:
          try:
              data_dict = json.loads(data)
          except ValueError:
              log.error("Invalid JSON for %s" % data_hash)
              continue

      else:
          data_dict = data

      log.debug("loaded %s with %s" % (data_hash, handler.__name__))
      return data_dict

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


def get_mutable_data( fq_data_id, data_pubkey, urls=None, data_address=None, owner_address=None, drivers=None, decode=True ):
   """
   Given a mutable data's zonefile, go fetch the data.

   Return a mutable data dict on success
   Return None on error
   """

   global storage_handlers

   fq_data_id = str(fq_data_id)
   assert is_fq_data_id( fq_data_id ) or is_valid_name( fq_data_id ), "Need either a fully-qualified data ID or a blockchain ID: '%s'" % fq_data_id

   fqu = None
   if is_fq_data_id(fq_data_id):
       fqu = fq_data_id.split(":")[0]
   else:
       fqu = fq_data_id

   handlers_to_use = []
   if drivers is not None:
       # whitelist of drivers to try 
       for d in drivers:
           for h in storage_handlers:
               if h.__name__ == d:
                   handlers_to_use.append(h)

   else:
       handlers_to_use = storage_handlers

   log.debug("get_mutable %s" % fq_data_id)
   for storage_handler in handlers_to_use:

      if not hasattr(storage_handler, "get_mutable_handler"):
         continue

      # which URLs to attempt?
      try_urls = []
      if urls is None:
        
          # make one on-the-fly
          if not hasattr(storage_handler, "make_mutable_url"):
             log.warning("Storage handler %s does not support `make_mutable_url`" % storage_handler.__name__)
             continue

          new_url = None

          try:
              new_url = storage_handler.make_mutable_url( fq_data_id )
          except Exception, e:
              log.exception(e)
              continue
          
          try_urls = [new_url]

      else:
          # find the set that this handler can manage 
          for url in urls:
              if not hasattr(storage_handler, "handles_url"):
                  log.warning("Storage handler %s does not support `handles_url`" % storage_handler.__name__)
                  continue

              if storage_handler.handles_url( url ):
                  try_urls.append(url)

      for url in try_urls:

         data_json = None
         data = None

         log.debug("Try %s (%s)" % (storage_handler.__name__, url))
         try:

            data_json = storage_handler.get_mutable_handler( url, fqu=fqu )
         except UnhandledURLException, uue:
            # handler doesn't handle this URL
            log.debug("Storage handler %s does not handle URLs like %s" % (storage_handler.__name__, url ))
            continue

         except Exception, e:
            log.exception( e )
            continue

         if data_json is None:
            # no data
            log.debug("No data from %s (%s)" % (storage_handler.__name__, url))
            continue

         # parse it, if desired
         if decode:
             data = parse_mutable_data( data_json, data_pubkey, public_key_hash=data_address )
             if data is None:
                # maybe try owner address?
                if owner_address is not None:
                    data = parse_mutable_data( data_json, data_pubkey, public_key_hash=owner_address )

                if data is None:
                    log.error("Unparseable data from '%s'" % url)
                    continue

             log.debug("loaded '%s' with %s" % (url, storage_handler.__name__))
         else:
             data = data_json
             log.debug("fetched (but did not decode) '%s' with '%s'" % (url, storage_handler.__name__))

         return data

   return None


def serialize_immutable_data( data_json ):
    """
    Serialize a piece of immutable data
    """
    assert type(data_json) in [dict,list,defaultdict], "Invalid immutable data: must be a dict or list(got type %s)" % type(data_json)
    return json.dumps(data_json, sort_keys=True)


def put_immutable_data( data_json, txid, data_hash=None, data_text=None, required=[] ):
   """
   Given a string of data (which can either be data or a zonefile), store it into our immutable data stores.
   Do so in a best-effort manner--this method only fails if *all* storage providers fail.

   Return the hash of the data on success
   Return None on error
   """

   global storage_handlers

   assert (data_hash is None and data_text is None and data_json is not None) or \
          (data_hash is not None and data_text is not None), "Need data hash and text, or just JSON"

   if data_text is None:
      data_text = serialize_immutable_data( data_json )

   if data_hash is None:
      data_hash = get_data_hash( data_text )
   else:
      data_hash = str(data_hash)

   successes = 0
   log.debug("put_immutable_data(%s), required=%s" % (data_hash, ",".join(required)))

   for handler in storage_handlers:

      if not getattr(handler, "put_immutable_handler"):
         # this one failed 
         if handler.__name__ in required:
             # fatal
             log.debug("Failed to replicate to required storage provider '%s'" % handler.__name__)
             return None
         else:
             continue

      rc = False

      try:
         log.debug("Try '%s'" % handler.__name__)
         rc = handler.put_immutable_handler( data_hash, data_text, txid )
      except Exception, e:

         log.exception(e)
         if handler.__name__ in required:
             # fatal
             log.debug("Failed to replicate to required storage provider '%s'" % handler.__name__)
             return None
         else:
             continue

      if not rc:
         log.debug("Failed to replicate with '%s'" % handler.__name__)

      else:
         log.debug("Replication succeeded with '%s'" % handler.__name__)
         successes += 1

   if successes == 0:
       # failed everywhere
       return None

   else:
       # succeeded somewhere
       return data_hash


def put_mutable_data( fq_data_id, data_json, privatekey, required=[] ):
   """
   Given the unserialized data, store it into our mutable data stores.
   Do so in a best-effort way.  This method only fails if all storage providers fail.

   @fq_data_id is the fully-qualified data id.  It must be prefixed with the username,
   to avoid collisions in shared mutable storage.

   Return True on success
   Return False on error
   """

   global storage_handlers 

   fq_data_id = str(fq_data_id)
   assert is_fq_data_id( fq_data_id ) or is_valid_name(fq_data_id), "Data ID must be fully qualified or must be a valid blockchain ID (got %s)" % fq_data_id
   assert privatekey is not None

   fqu = None
   if is_fq_data_id(fq_data_id):
       fqu = fq_data_id.split(":")[0]
   else:
       fqu = fq_data_id

   serialized_data = serialize_mutable_data( data_json, privatekey )
   successes = 0

   log.debug("put_mutable_data(%s), required=%s" % (fq_data_id, ",".join(required)))

   for handler in storage_handlers:

      if not hasattr( handler, "put_mutable_handler" ):
          if handler.__name__ in required:
              log.debug("Failed to replicate with required storage provider '%s'" % handler.__name__)
              return None
          else:
              continue

      rc = False

      try:
         log.debug("Try '%s'" % handler.__name__)
         rc = handler.put_mutable_handler( fq_data_id, serialized_data, fqu=fqu )
      except Exception, e:
         log.exception( e )
         if handler.__name__ in required:
             log.debug("Failed to replicate with required storage provider '%s'" % handler.__name__)
             return None 
         else:
             continue

      if not rc:
         if handler.__name__ in required:
             log.debug("Failed to replicate with required storage provider '%s'" % handler.__name__)
             return None 
         else:
             log.debug("Failed to replicate with '%s'" % handler.__name__)
             continue

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

   data_hash = str(data_hash)
   txid = str(txid)
   sigb64 = sign_raw_data( data_hash + txid, privkey )

   for handler in storage_handlers:

      if not hasattr( handler, "delete_immutable_handler" ):
         continue

      try:

         handler.delete_immutable_handler( data_hash, txid, sigb64 )
      except Exception, e:

         log.exception( e )
         return False

   return True


def delete_mutable_data( fq_data_id, privatekey ):
   """
   Given the data ID and private key of a user,
   go and delete the associated mutable data.
   """

   global storage_handlers

   fq_data_id = str(fq_data_id)
   assert is_fq_data_id( fq_data_id ) or is_valid_name(fq_data_id), "Data ID must be fully qualified or must be a valid blockchain ID (got %s)" % fq_data_id

   sigb64 = sign_raw_data( fq_data_id, privatekey )

   # remove data
   for handler in storage_handlers:

      if not hasattr( handler, "delete_mutable_handler" ):
         continue

      try:

         handler.delete_mutable_handler( fq_data_id, sigb64 )
      except Exception, e:

         log.exception( e )
         return False

   return True


def get_announcement( announcement_hash ):
    """
    Go get an announcement's text, given its hash.
    Use the blockstack client library, so we can get at
    the storage drivers for the storage systems the sender used
    to host it.

    Return the data on success
    """

    data = get_immutable_data( announcement_hash, hash_func=get_blockchain_compat_hash, deserialize=False )
    if data is None:
        log.error("Failed to get announcement '%s'" % (announcement_hash))
        return None

    return data



def put_announcement( announcement_text, txid ):
    """
    Go put an announcement into back-end storage.
    Use the blockstack client library, so we can get at
    the storage drivers for the storage systems this host
    is configured to use.

    Return the data's hash
    """

    data_hash = get_blockchain_compat_hash(announcement_text)
    res = put_immutable_data( None, txid, data_hash=data_hash, data_text=announcement_text )
    if res is None:
        log.error("Failed to put announcement '%s'" % (data_hash))
        return None

    return data_hash


def make_fq_data_id( name, data_id ):
    """
    Make a fully-qualified data ID, prefixed by the name.
    """
    return str("%s:%s" % (name, data_id))


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


def blockstack_mutable_data_url( blockchain_id, data_id, version ):
    """
    Make a blockstack:// URL for mutable data
    """
    if version is not None:
        if type(version) not in [int, long]:
            raise ValueError("Verison must be an int or long")

        return "blockstack://%s/%s#%s" % (urllib.quote(blockchain_id), urllib.quote(data_id), str(version))
    else:
        return "blockstack://%s/%s" % (urllib.quote(blockchain_id), urllib.quote(data_id))


def blockstack_immutable_data_url( blockchain_id, data_id, data_hash ):
    """
    Make a blockstack:// URL for immutable data
    """
    if data_hash is not None and not is_valid_hash( data_hash ):
        raise ValueError("Invalid hash: %s" % data_hash)

    if data_hash is not None:
        return "blockstack://%s.%s/#%s" % (urllib.quote(data_id), urllib.quote(blockchain_id), data_hash)
    else:
        return "blockstack://%s.%s" % (urllib.quote(data_id), urllib.quote(blockchain_id))


def blockstack_mutable_data_url_parse( url ):
    """
    Parse a blockstack:// URL for mutable data
    Return (blockchain ID, data ID, data version)
    * The version may be None if not given (in which case, the latest value is requested).
    * The data ID may be None, in which case, a listing of mutable data is requested.

    Raise on bad data
    """

    url = str(url)
    mutable_url_data_regex = r"blockstack://(%s+)[/]+(%s+)(#[0-9]+)?" % (B40_CLASS, URLENCODED_CLASS)
    mutable_url_listing_regex = r"blockstack://(%s+)[/]+#mutable" % (B40_CLASS)

    blockchain_id = None
    data_id = None
    version = None

    m = re.match( mutable_url_data_regex, url )
    if m:

        blockchain_id, data_id, version = m.groups()
        if not is_valid_name( blockchain_id ):
            raise ValueError("Invalid blockchain ID '%s'" % blockchain_id)

        # version?
        if version is not None:
            version = version.strip("#")
            version = int(version)

        return urllib.unquote(blockchain_id), urllib.unquote(data_id), version

    else:
        # maybe a listing?
        m = re.match( mutable_url_listing_regex, url )
        if not m:
            raise ValueError("Invalid URL: %s" % url)

        blockchain_id = m.groups()[0]
        return urllib.unquote(blockchain_id), None, None


def blockstack_immutable_data_url_parse( url ):
    """
    Parse a blockstack:// URL for immutable data
    Return (blockchain ID, data ID, data hash)
    * The hash may be None if not given, in which case, the hash should be looked up from the blockchain ID's profile.
    * The data ID may be None, in which case, the list of immutable data is requested.

    Raise on bad data
    """
    
    url = str(url)
    immutable_data_regex = r"blockstack://(%s+)\.(%s+)\.(%s+)([/]+#[a-fA-F0-9]+)?" % (URLENCODED_CLASS, B40_NO_PERIOD_CLASS, B40_NO_PERIOD_CLASS)
    immutable_listing_regex = r"blockstack://(%s+)[/]+#immutable" % (B40_CLASS)

    m = re.match( immutable_data_regex, url )
    if m:

        data_id, blockchain_name, namespace_id, data_hash = m.groups()
        blockchain_id = "%s.%s" % (blockchain_name, namespace_id)

        if not is_valid_name( blockchain_id ):
            raise ValueError( "Invalid blockchain ID '%s'" % blockchain_id)

        if data_hash is not None:
            data_hash = data_hash.lower().strip("#/")
            if not is_valid_hash( data_hash ):
                raise ValueError("Invalid data hash: %s" % data_hash)
    
        return urllib.unquote(blockchain_id), urllib.unquote(data_id), data_hash

    else:
        # maybe a listing?
        m = re.match( immutable_listing_regex, url )
        if not m:
            raise ValueError("Invalid URL: %s" % url)

        blockchain_id = m.groups()[0]
        return urllib.unquote(blockchain_id), None, None 


def blockstack_data_url_parse( url ):
    """
    Parse a blockstack:// URL
    Return {
        'type': immutable|mutable
        'blockchain_id': blockchain ID
        'data_id': data_id
        'fields': { fields }
    } on success
    Fields will be either {'data_hash'} on immutable 
    or {'version'} on mutable

    Return None on error
    """

    blockchain_id = None
    data_id = None
    url_type = None
    fields = {}
    try:
        blockchain_id, data_id, data_hash = blockstack_immutable_data_url_parse( url )
        url_type = 'immutable'
        fields.update( {
            'data_hash': data_hash
        } )
    except Exception, e1:
        try:
            blockchain_id, data_id, version = blockstack_mutable_data_url_parse( url )
            url_type = 'mutable'
            fields.update( {
                'version': version
            } )
        except Exception, e2:
            return None

    ret = {
        'type': url_type,
        'blockchain_id': blockchain_id,
        'data_id': data_id,
        'fields': fields
    }
    return ret


def blockstack_data_url( field_dict ):
    """
    Make a blockstack:// URL from constituent fields.
    Takes the output of blockstack_data_url_parse
    Return the URL on success
    Raise on error
    """
    assert 'blockchain_id' in field_dict
    assert 'type' in field_dict
    assert field_dict['type'] in ['mutable', 'immutable']
    assert 'data_id' in field_dict
    assert 'fields' in field_dict
    assert 'data_hash' in field_dict['fields'] or 'version' in field_dict['fields']

    if field_dict['type'] == 'immutable':
        return blockstack_immutable_data_url( field_dict['blockchain_id'], field_dict['data_id'], field_dict['fields']['data_hash'] )

    else:
        return blockstack_mutable_data_url( field_dict['blockchain_id'], field_dict['data_id'], field_dict['fields']['version'] )
    


class BlockstackURLHandle( object ):
    """
    A file-like object that handles reads on blockstack URLs
    """

    def __init__(self, url, data=None, full_response=False, config_path=CONFIG_PATH, wallet_keys=None ):
        self.name = url
        self.data = data
        self.full_response = full_response
        self.fetched = False
        self.config_path = config_path
        self.wallet_keys = wallet_keys

        if data is not None:
            self.data_len = len(data)
            self.fetched = True
            self.newlines = make_newlines(data)

        else:
            self.newlines = None

        self.offset = 0
        self.closed = False
        self.softspace = 0


    def make_newlines(self, data):
        """
        Set up newlines
        """
        
        newline_list = []
        for newline_str in ['\n', '\r', '\r\n']:
            if newline_str in data:
                newline_list.append( newline_str )

        return tuple(newline_list)


    def fetch(self):
        """
        Lazily fetch the data on read
        """
        if not self.fetched:
            import data as data_mod
            from .proxy import get_default_proxy

            proxy = get_default_proxy( config_path=self.config_path )
            data = data_mod.blockstack_url_fetch( self.name, proxy=proxy, wallet_keys=self.wallet_keys )
            if data is None:
                raise urllib2.URLError("Failed to fetch '%s'" % self.name)

            if 'error' in data:
                raise urllib2.URLError("Failed to fetch '%s': %s" % (self.name, data['error']))

            if self.full_response:
                self.data = json.dumps(data)
            else:
                self.data = data['data']
                if type(self.data) not in [str,unicode]:
                    self.data = json.dumps(data['data'])

            self.newlines = self.make_newlines(data)
            self.data_len = len(self.data)
            self.fetched = True


    def close(self):
        self.data = None
        self.closed = True


    def flush(self):
        pass


    def __iter__(self):
        return self


    def next(self):
        line = self.readline()
        if len(line) == 0:
            raise StopIteration()
        else:
            return line


    def read(self, numbytes=None):

        self.fetch()
        if self.offset >= self.data_len:
            return ""

        if numbytes is not None:
            ret = self.data[self.offset:min(self.data_len, self.offset+numbytes)]
            self.offset += numbytes
            if self.offset > self.data_len:
                self.offset = self.data_len

            return ret 

        else:
            ret = self.data[self.offset:]
            self.offset = self.data_len
            self.data = None
            return ret


    def readline(self, numbytes=None):
        if self.data is None:
            return ""

        next_newline_offset = self.data[self.offset:].find("\n")
        if next_newline_offset < 0:
            # no more newlines 
            return self.read()

        else:
            line_data = self.read( next_newline_offset+1 )
            return line_data


    def readlines(self, sizehint=None):
        lines = []
        if sizehint is None:
            sizehint = self.data_len

        total_len = 0
        while total_len < sizehint:
            line = self.readline()
            lines.append(line)
            total_len += len(line)

        return lines


class BlockstackHandler( urllib2.BaseHandler ):
    """
    URL opener for blockstack:// URLs.
    Usable with urllib2.
    """

    def __init__(self, full_response=False, config_path=CONFIG_PATH):
        self.full_response = full_response
        self.config_path = config_path

    def blockstack_open( self, req ):
        """
        Open a blockstack URL
        """
        bh = BlockstackURLHandle( req.get_full_url(), full_response=self.full_response, config_path=self.config_path )
        return bh

