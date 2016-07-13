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

def url_to_uri_record( url, datum_name=None ):
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

    if datum_name is not None:
       name = name + "." + str(datum_name)

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
      "txt": [],
      "uri": [],
      "$origin": username,
      "$ttl": config.USER_ZONEFILE_TTL 
   }

   if data_pubkey is not None:
       if not user.has_key('txt'):
           user['txt'] = []

       user['txt'].append( {
            "name": "pubkey",
            "txt": "pubkey:data:%s" % str(data_pubkey)
          }
       )
   
   for url in urls:
       urirec = url_to_uri_record( url )
       user["uri"].append( urirec )

   return user


def is_user_zonefile( d ):
    """
    Is the given dict (or dict-like object) a user zonefile?
    * the zonefile must have a URI record
    """

    if not hasattr(d, "keys") or not callable(d.keys):
        log.error("Not a dict-like object")
        return False

    if not hasattr(d, "has_key") or not callable(d.has_key):
        log.error("Not a dict-like object")
        return False

    if not hasattr(d, "__getitem__") or not callable(d.__getitem__):
        log.error("Not a dict-like object")
        return False

    if 'uri' not in d.keys():
        return False 

    if d.has_key('txt'):
        if not hasattr(d['txt'], "__iter__") or not callable(d['txt'].__iter__):
            log.error("txt is not a list-like object")
            return False

        for txt in d['txt']:
            if not hasattr(txt, "keys") or not callable(txt.keys):
                log.error("txt item is not a dict-like object")
                return False

            if 'name' not in txt.keys():
                return False 

            if 'txt' not in txt.keys():
                return False 

    if not hasattr(d['uri'], '__iter__') or not callable(d['uri'].__iter__):
        lo.error("uri is not a list-like object")
        return False

    for uri in d['uri']:
        if not hasattr(uri, "keys") and not callable(uri.keys):
            log.error("uri item is not a dict-like object")
            return False

        if 'name' not in uri.keys():
            return False 

        if 'priority' not in uri.keys():
            return False 
        
        if 'weight' not in uri.keys():
            return False 

        if 'target' not in uri.keys():
            return False 

    return True


def user_zonefile_data_pubkey( user_zonefile, key_prefix='pubkey:data:' ):
    """
    Get a user's data public key from their zonefile.
    Return None if not defined
    Raise if there are multiple ones.
    """
    if not user_zonefile.has_key('txt'):
        return None 
    
    data_pubkey = None
    # check that there is only one of these
    for txtrec in user_zonefile['txt']:
        if txtrec['txt'].startswith(key_prefix):
            if data_pubkey is not None:
                log.error("BUG: Multiple data pubkeys")
                raise ValueError("Multiple data pubkeys starting with '%s'" % key_prefix)

            data_pubkey = txtrec['txt'][len(key_prefix):]

    return data_pubkey


def user_zonefile_set_data_pubkey( user_zonefile, pubkey_hex, key_prefix='pubkey:data:' ):
    """
    Set the data public key in the zonefile.
    NOTE: you will need to re-sign all your data!
    """
    if not user_zonefile.has_key('txt'):
        user_zonefile['txt'] = []

    for i in xrange(0, len(user_zonefile['txt'])):
        if user_zonefile['txt'][i]['txt'].startswith(key_prefix):
            # overwrite
            user_zonefile['txt'][i]['txt'] = {
                "name": "pubkey",
                "txt": "%s%s" % (key_prefix, str(data_pubkey))
            }
            return True

    # not present.  add.
    user_zonefile['txt'].append({
        "name": "pubkey",
        "txt": "%s%s" % (key_prefix, str(pubkey_hex))
    })
    
    return True


def user_zonefile_urls( user_zonefile ):
    """
    Given a user's zonefile, get the profile URLs
    """
    if not user_zonefile.has_key('uri'):
        return None 

    ret = []
    for urirec in user_zonefile['uri']:
        if urirec.has_key('target'):
            ret.append( urirec['target'].strip('"') )

    return ret


def make_empty_user_profile():
    """
    Given a user's name, create an empty profile.
    """
    ret = {
        "@type": "Person",
        "accounts": []
    }
    return ret
    

def put_immutable_data_zonefile( user_zonefile, data_id, data_hash, data_url=None ):
   """
   Add a data hash to a user's zonefile.  Make sure it's a valid hash as well.
   Return True on success
   Return False otherwise.
   """
 
   data_hash = str(data_hash)
   assert storage.is_valid_hash( data_hash )

   k = get_immutable_data_hash( user_zonefile, data_id )
   if k is not None and k == data_hash:
       # already there 
       return True

   elif k is not None:
       # name collision 
       return False 

   txtrec = None 
   if data_url is not None:
       txtrec = "%s#%s" % (data_url, data_hash)
   else: 
       txtrec = "#%s" % data_hash

   if not user_zonefile.has_key('txt'):
       user_zonefile['txt'] = []

   user_zonefile["txt"].append({
       "name": data_id,
       "txt": txtrec
   })

   return True


def get_immutable_hash_from_txt( txtrec ):
    """
    Given an immutable data txt record,
    get the hash.
    The hash is the suffix that begins with #.
    Return None if invalid or not present
    """
    if '#' not in txtrec:
        return None

    h = txtrec.split('#')[-1]
    if not storage.is_valid_hash( h ):
        return None

    return h


def get_immutable_url_from_txt( txtrec ):
    """
    Given an immutable data txt record,
    get the URL hint.
    This is everything that starts before the last #.
    Return None if there is no URL, or we can't parse the txt record
    """
    if '#' not in txtrec:
        return None

    url = "#".join( txtrec.split("#")[:-1] )
    if len(url) == 0:
        return None 

    return url


def remove_immutable_data_zonefile( user_zonefile, data_hash ):
   """
   Remove a data hash from a user's zonefile.
   Return True if removed
   Return False if not present
   """

   data_hash = str(data_hash)
   assert storage.is_valid_hash( data_hash ), "Invalid data hash '%s'" % data_hash

   if not user_zonefile.has_key('txt'):
       return False 

   for txtrec in user_zonefile['txt']:
       h = None
       try:
           h = get_immutable_hash_from_txt( txtrec['txt'] )
           assert storage.is_valid_hash(h)
       except:
           continue 

       if h == data_hash:
           user_zonefile['txt'].remove(txtrec)
           return True

   return False


def has_immutable_data( user_zonefile, data_hash ):
   """
   Does the given user have the given immutable data?
   Return True if so
   Return False if not
   """

   data_hash = str(data_hash)
   assert storage.is_valid_hash( data_hash ), "Invalid data hash '%s'" % data_hash

   if not user_zonefile.has_key('txt'):
       return False 

   for txtrec in user_zonefile['txt']:
       h = None
       try:
           h = get_immutable_hash_from_txt( txtrec['txt'] )
           assert storage.is_valid_hash(h)
       except:
           continue 

       if h == data_hash:
           return True 

   return False


def has_immutable_data_id( user_zonefile, data_id ):
   """
   Does the given user have the given immutable data?
   Return True if so
   Return False if not
   """
   if not user_zonefile.has_key('txt'):
       return False 

   for txtrec in user_zonefile['txt']:
       d_id = None 
       try:
           d_id = txtrec['name']
           h = get_immutable_hash_from_txt( txtrec['txt'] )
           assert storage.is_valid_hash(h)
       except AssertionError:
           continue 

       if d_id == data_id:
           return True 

   return False


def get_immutable_data_hash( user_zonefile, data_id ):
   """
   Get the hash of an immutable datum by name.
   Return None if there is no match.
   Return the hash if there is one match.
   Return the list of hashes if there are multiple matches.
   """

   if not user_zonefile.has_key('txt'):
       return None 

   ret = None
   for txtrec in user_zonefile['txt']:
       d_id = None 
       h = None
       try:
           d_id = txtrec['name']
           h = get_immutable_hash_from_txt( txtrec['txt'] )
           assert storage.is_valid_hash(h)
       except:
           continue 

       if d_id == data_id:
           if ret is None:
               ret = h
           elif type(ret) != list:
               ret = [ret]
               ret.append(h)

   return ret


def get_immutable_data_url( user_zonefile, data_hash ):
    """
    Given the hash of an immutable datum, find the associated
    URL hint (if given)
    Return None if not given, or not found.
    """

    ret = None
    if not user_zonefile.has_key('txt'):
        return None 

    for txtrec in user_zonefile['txt']:
        h = None 
        try:
            h = get_immutable_hash_from_txt( txtrec['txt'] )
            if h != data_hash:
                continue 

            url = get_immutable_url_from_txt( txtrec['txt'] )
        except:
            continue

        return url

    return None


def list_immutable_data( user_zonefile ):
    """
    Get the IDs and hashes of all immutable data
    Return [(data ID, hash)]
    """
    ret = []
    if not user_zonefile.has_key('txt'):
        return ret 

    for txtrec in user_zonefile['txt']:
        try:
            d_id = txtrec['name']
            h = get_immutable_hash_from_txt( txtrec['txt'] )
            assert storage.is_valid_hash(h)
            ret.append( (d_id, h) )
        except:
            continue

    return ret


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
          unpacked_data_id, version = unpack_mutable_data_md( packed_data_txt )
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

   packed_prefix = pack_mutable_data_md_prefix( data_id )
   for packed_data_txt in user_profile['data'].keys():
       if not packed_data_txt.startswith(packed_prefix):
           continue 

       unpacked_data_id, version = unpack_mutable_data_md( packed_data_txt )
       if data_id == unpacked_data_id:
           return user_profile['data'][packed_data_txt]

   return None


def get_mutable_data_zonefile_ex( user_profile, data_id ):
   """
   Get the zonefile and associated metadata for a piece of mutable data, given
   the user's profile and data_id.
   Return the (route (as a dict), version, metadata key) on success
   Return (None, None, None) if not found
   """

   if not user_profile.has_key('data'):
      return (None, None, None)

   for packed_data_txt in user_profile['data'].keys():
       if not is_mutable_data_md( packed_data_txt ):
           continue 

       unpacked_data_id, version = unpack_mutable_data_md( packed_data_txt )
       if data_id == unpacked_data_id:
           return (user_profile['data'][packed_data_txt], version, packed_data_txt)

   return (None, None, None)


def get_mutable_data_zonefile_md( user_profile, data_id ):
   """
   Get the serialized zonefile key for a piece of mutable data, given
   the user's profile and data_id.
   Return the mutable data key on success (an opaque but unique string)
   Return None if not found
   """

   if not user_profile.has_key('data'):
      return None

   for packed_data_txt in user_profile['data'].keys():
       if not is_mutable_data_md( packed_data_txt ):
           continue 

       unpacked_data_id = None
       version = None
       try:
           unpacked_data_id, version = unpack_mutable_data_md( packed_data_txt )
       except:
           continue

       if data_id == unpacked_data_id:
           return packed_data_txt

   return None


def list_mutable_data( user_profile ):
    """
    Get a list of all mutable data information.
    Return [(data_id, version)]
    """
    if not user_profile.has_key('data'):
        return []

    ret = []
    for packed_data_txt in user_profile['data'].keys():
        if not is_mutable_data_md( packed_data_txt ):
            continue

        unpacked_data_id = None
        version = None
        try:
            unpacked_data_id, version = unpack_mutable_data_md( packed_data_txt )
        except:
            continue
    
        ret.append( (unpacked_data_id, version) )

    return ret


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
  
   existing_zonefile, existing_version, existing_md = get_mutable_data_zonefile_ex( user_profile, data_id )
   
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
           # replace
           del user_profile['data'][existing_md]
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
          if not is_mutable_data_md( packed_data_txt ):
              continue 

          unpacked_data_id, version = unpack_mutable_data_md( packed_data_txt )
          if unpacked_data_id == data_id:
              del user_profile['data'][packed_data_txt]
              return True
        
      # already gone
      return False


def pack_mutable_data_md( data_id, version ):
    """
    Pack an mutable datum's metadata into a string
    """
    return "mutable:%s:%s" % (base64.b64encode(data_id.encode('utf-8')), version)


def pack_mutable_data_md_prefix( data_id ):
    """
    Pack an mutable datum's metadata prefix into a string (i.e. skip the version)
    """
    return "mutable:%s:" % (base64.b64encode(data_id.encode('utf-8')))


def unpack_mutable_data_md( rec ):
    """
    Unpack an mutable datum's key into its metadata
    """
    parts = rec.split(":")
    assert len(parts) == 3, "parts = %s" % parts
    assert parts[0] == "mutable", "parts = %s" % parts

    data_id = base64.b64decode(parts[1])
    version = int(parts[2])

    return data_id, version


def is_mutable_data_md( rec ):
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
        urirec = url_to_uri_record( url, data_id )
        uris.append( urirec )

    data_name = pack_mutable_data_md( data_id, version )

    rec = {
        data_name: {
            "uri": uris
        }
    }

    return rec


def mutable_data_version( user_profile, data_id ):
    """
    Get the data version for a piece of mutable data.
    Return 0 if it doesn't exist
    """
    
    key = get_mutable_data_zonefile_md( user_profile, data_id )
    if key is None:
        log.debug("No mutable data zonefiles installed for '%s'" % (data_id))
        return 0

    data_id, version = unpack_mutable_data_md( key )
    return version


def mutable_data_zonefile_urls( mutable_zonefile ):
    """
    Get the URLs from a mutable data zonefile
    """
    uri_records = mutable_zonefile.get('uri')
    if uri_records is None:
        return None 

    urls = [u['target'].strip('"') for u in uri_records]
    return urls


