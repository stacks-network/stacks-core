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
    along with Blockstack-client.  If not, see <http://www.gnu.org/licenses/>.
"""

import traceback
import json
import socket
import base64

from binascii import hexlify, unhexlify
from utilitybelt import is_hex, hex_to_charset, charset_to_hex
import storage
import config
import blockstack_profiles

log = config.get_logger()

def url_to_uri_record( url ):
    """
    Convert a URL into a DNS URI record
    """
    try:
       scheme, _ = url.split("://")
    except:
       raise Exception("BUG: invalid storage driver implementation: no scheme given in '%s'" % url)

    scheme = scheme.lower()
    proto = None 

    # tcp or udp?
    try:
       port = socket.getservbyname( scheme, "tcp" )
       proto = "tcp"
    except:
       try:
           port = socket.getservbyname( scheme, "udp" )
           proto = "udp"
       except:
           # this is weird--maybe it's embedded in the scheme?
           try:
               assert len(scheme.split("+")) == 2
               scheme, proto = scheme.split("+")
           except:
               log.debug("WARN: Scheme '%s' has no known transport protocol" % scheme)

    name = None 
    if proto is not None:
       name = "_%s._%s" % (scheme, proto)
    else:
       name = "_%s" % scheme

    ret = {
       "name": name,
       "priority": 10,
       "weight": 1,
       "target": url
    }
    return ret


def make_empty_user_zonefile( username, data_pubkey, urls=None ):
   """
   Create an empty user record from a name record.
   """
   
   # make a URI record for every mutable storage provider 
   if urls is None:
       urls = storage.make_mutable_data_urls( username )

   assert len(urls) > 0, "No profile URLs"

   user = {
      "TXT": [
          {
            "name": "@",
            "txt": "pubkey:data:%s" % str(data_pubkey)
          }
      ],
      "URI": []
   }
    
   for url in urls:
       urirec = url_to_uri_record( url )
       user["URI"].append( urirec )

   return user


def user_zonefile_set_profile_urls( user_zonefile, user_profile_urls ):
    """
    Add URI records to a user's zonefile that point to the profile.
    """
    uris = []
    for url in urls:
        urirec = url_to_uri_record( url )
        uris.append( urirec )

    user_zonefile['URI'] = uris
    return


def is_user_zonefile( d ):
    """
    Is the given dict a user zonefile?
    """
    if 'TXT' not in d.keys():
        return False 

    if 'URI' not in d.keys():
        return False 

    for txt in d['TXT']:
        if 'name' not in txt.keys():
            return False 

        if 'txt' not in txt.keys():
            return False 

    for uri in d['URI']:
        if 'name' not in uri.keys():
            return False 

        if 'priority' not in uri.keys():
            return False 
        
        if 'weight' not in uri.keys():
            return False 

        if 'target' not in uri.keys():
            return False 

    return True


def user_zonefile_data_pubkey( user_zonefile ):
    """
    Get a user's data public key from their zonefile.
    Return None if not defined
    """
    if not user_zonefile.has_key('TXT'):
        return None 
    
    data_pubkey = None
    # check that there is only one of these
    for txtrec in user_zonefile['TXT']:
        if txtrec['txt'].startswith("pubkey:data:"):
            if data_pubkey is not None:
                log.error("BUG: Multiple data pubkeys")
                return None  

            data_pubkey = txtrec['txt'][len("pubkey:data:"):]

    return data_pubkey


def user_zonefile_urls( user_zonefile ):
    """
    Given a user's zonefile, get the profile URLs
    """
    if not user_zonefile.has_key('URI'):
        return None 

    ret = []
    for urirec in user_zonefile['URI']:
        if urirec.has_key('target'):
            ret.append( urirec['target'].strip('"') )

    return ret


def make_empty_user_profile():
    """
    Given a user's name, create an empty profile (as a modern zonefile)
    """
    ret = {
        "@type": "Person",
        "accounts": []
    }
    return ret
    

def pack_immutable_data_txt( data_id, data_hash ):
    """
    Pack an immutable datum into a txt record
    """
    return "immutable:%s:%s" % (base64.b64encode(data_id), data_hash)


def unpack_immutable_data_txt( rec ):
    """
    Unpack an immutable datum
    """
    parts = rec.split(":")
    assert len(parts) == 3
    assert parts[0] == "immutable"

    data_id = base64.b64decode(parts[1])

    return data_id, parts[2]


def put_immutable_data_zonefile( user_zonefile, data_id, data_hash ):
   """
   Add a data hash to a user's zonefile.  Make sure it's a valid hash as well.
   Return True on success
   Return False otherwise.
   """
 
   assert storage.is_valid_hash( data_hash )

   k = get_immutable_data_hash( user_zonefile, data_id )
   if k is not None and k == data_hash:
       # already there 
       return True 
   elif k is not None:
       # name collision 
       return False 

   user_zonefile["TXT"].append( {
       "name": "@",
       "txt": pack_immutable_data_txt( data_id, data_hash )
   })

   return True


def remove_immutable_data_zonefile( user_zonefile, data_hash ):
   """
   Remove a data hash from a user's zonefile.
   Return True if removed
   Return False if not present
   """

   assert storage.is_valid_hash( data_hash )

   for txtrec in user_zonefile['TXT']:
       h = None
       try:
           _, h = unpack_immutable_data_txt( txtrec['txt'] )
           assert storage.is_valid_hash(h)
       except:
           continue 

       if h == data_hash:
           user_zonefile['TXT'].remove(txtrec)
           return True

   return False


def has_immutable_data( user_zonefile, data_hash ):
   """
   Does the given user have the given immutable data?
   Return True if so
   Return False if not
   """

   assert storage.is_valid_hash( data_hash )

   for txtrec in user_zonefile['TXT']:
       h = None 
       try:
           _, h = unpack_immutable_data_txt( txtrec['txt'] )
           assert storage.is_valid_hash(h)
       except:
           continue 

       if h == data_hash:
           return True 

   return False


def get_immutable_data_hash( user_zonefile, data_id ):
   """
   Get the hash of an immutable datum by name.
   Return None if not found
   """

   for txtrec in user_zonefile['TXT']:
       d_id = None 
       h = None
       try:
           d_id, h = unpack_immutable_data_txt( txtrec['txt'] )
           assert storage.is_valid_hash(h)
       except:
           continue 

       if d_id == data_id:
           return h

   return None


def has_mutable_data( user_profile, data_id ):
   """
   Does the given user profile have the named mutable data defined?
   Return True if so
   Return False if not
   """
   if not user_profile.has_key('data'):
      return False

   else:
      for packed_data_txt in user_profile['data'].keys():
          unpacked_data_id, version = unpack_mutable_data_key( packed_data_txt )
          if unpacked_data_id == data_id:
              return True

      return False


def get_mutable_data_zonefile( user_profile, data_id ):
   """
   Get the zonefile for a piece of mutable data, given
   the user's profile and data_id.
   Return the route (as a dict) on success
   Return None if not found
   """

   if not user_profile.has_key('data'):
      return None

   for packed_data_txt in user_profile['data'].keys():
       if not is_mutable_data_key( packed_data_txt ):
           continue 

       unpacked_data_id, version = unpack_mutable_data_key( packed_data_txt )
       if data_id == unpacked_data_id:
           return user_profile['data'][packed_data_txt]

   return None


def get_mutable_data_zonefile_key( user_profile, data_id ):
   """
   Get the serialized zonefile key for a piece of mutable data, given
   the user's profile and data_id.
   Return the route (as a dict) on success
   Return None if not found
   """

   if not user_profile.has_key('data'):
      return None

   for packed_data_txt in user_profile['data'].keys():
       if not is_mutable_data_key( packed_data_txt ):
           continue 

       unpacked_data_id, version = unpack_mutable_data_key( packed_data_txt )
       if data_id == unpacked_data_id:
           return packed_data_txt

   return None


def put_mutable_data_zonefile( user_profile, data_id, version, zonefile ):
   """
   Put a zonefile to mutable data to a user's profile.
   Only works if the zonefile has a later version field, or doesn't exist.
   Return True on success
   Return False if this is a duplicate
   Raise an Exception if the route is invalid, or if this is a duplicate zonefile.
   """

   if not user_profile.has_key('data'):
       user_profile['data'] = {}
       user_profile['data'].update( zonefile )
       return True
  
   existing_version = mutable_data_version( user_profile, data_id )
   existing_zonefile = get_mutable_data_zonefile( user_profile, data_id )
   
   if existing_zonefile is None:
       # first case of this mutable datum
       user_profile['data'].update( zonefile )
       return True 

   else:
       # must be a newer version
       if existing_version >= version:
           log.debug("Will not put mutable data zonefile; existing version %s >= %s" % (existing_version, version))
           return False

       else:
           packed_data_txt = get_mutable_data_zonefile_key( user_profile, data_id )
           del user_profile['data'][packed_data_txt]
           user_profile['data'].update( zonefile )
           return True


def remove_mutable_data_zonefile( user_profile, data_id ):
   """
   Remove a zonefile for mutable data from a user.
   Return True if removed
   Return False if the user had no such data.
   """

   if not user_profile.has_key('data'):
      return False

   else:

      # check for it
      for packed_data_txt in user_profile['data']:
          if not is_mutable_data_key( packed_data_txt ):
              continue 

          unpacked_data_id, version = unpack_mutable_data_key( packed_data_txt )
          if unpacked_data_id == data_id:
              del user_profile['data'][packed_data_txt]
              return True
        
      # already gone
      return False


def pack_mutable_data_key( data_id, version ):
    """
    Pack an mutable datum's metadata into a key
    """
    return "mutable:%s:%s" % (base64.b64encode(data_id), version)


def unpack_mutable_data_key( rec ):
    """
    Unpack an mutable datum's key into its metadata
    """
    parts = rec.split(":")
    assert len(parts) == 3, "parts = %s" % parts
    assert parts[0] == "mutable", "parts = %s" % parts

    data_id = base64.b64decode(parts[1])
    version = int(parts[2])

    return data_id, version


def is_mutable_data_key( rec ):
    """
    Is this a mutable datum's key?
    """
    parts = rec.split(":")
    if len(parts) != 3:
        return False

    if parts[0] != "mutable":
        return False 

    return True


def make_mutable_data_zonefile( data_id, version, urls ):
    """
    Make a zonefile for mutable data.
    """
    uris = []
    for url in urls:
        urirec = url_to_uri_record( url )
        uris.append( urirec )

    data_name = pack_mutable_data_key( data_id, version )

    rec = {
        data_name: {
            "URI": uris
        }
    }

    return rec


def mutable_data_version( user_profile, data_id ):
    """
    Get the data version for a piece of mutable data.
    Return 0 if it doesn't exist
    """
    
    key = get_mutable_data_zonefile_key( user_profile, data_id )
    if key is None:
        log.debug("No mutable data zonefiles installed for '%s'\n%s" % (data_id, json.dumps(user_profile, indent=4, sort_keys=True)))
        return 0

    data_id, version = unpack_mutable_data_key( key )
    return version


def mutable_data_zonefile_urls( mutable_zonefile ):
    """
    Get the URLs from a mutable data zonefile
    """
    uri_records = mutable_zonefile.get('URI')
    if uri_records is None:
        return None 

    urls = [u['target'].strip('"') for u in uri_records]
    return urls

