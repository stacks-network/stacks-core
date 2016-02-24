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

from binascii import hexlify, unhexlify
from utilitybelt import is_hex, hex_to_charset, charset_to_hex

from .schemas import *
from .parsing import json_stable_serialize
from .storage import ROUTE_SCHEMA

USER_SCHEMA = {

   "name": {
      "formatted": STRING
   },

   OPTIONAL( "immutable_data" ): [ HASH160_TYPE ],

   OPTIONAL( "mutable_data" ): [ ROUTE_SCHEMA ],

   "v": STRING
}

RESERVED_USER_SCHEMA = {

   "message": STRING,
   "status": STRING
}

def make_empty_user( name, name_record ):
   """
   Create an empty user from a name record.
   """
   user = {}

   user['name'] = {'formatted': name}
   user['v'] = '2'

   return user


def parse_user( user_json ):
   """
   Parse a user into JSON.  Ensure that it matches a supported schema.
   Return a deserialized object (i.e. a dict) with the JSON data on success.
   Return None if it could not be parsed.
   """

   user = None

   try:
      user = json.loads( user_json.strip() )
   except Exception, e:
      # not valid json
      traceback.print_exc()
      print >> sys.stderr, "Can't load '%s'" % user_json
      return None

   return user


def serialize_user( user ):
   """
   Serialize a user into JSON.  Prefer this to json.dumps,
   since we do so in a stable way (i.e. the same user data
   will serialize, byte-for-byte, to the same JSON).
   """
   return json_stable_serialize( user )


def add_immutable_data( user, data_hash ):
   """
   Add a data hash to user data.  Make sure it's a valid hash as well.
   Return True on success
   Return False otherwise.
   """

   if not HASH160_TYPE.valid( data_hash ):
      return False

   if not user.has_key('immutable_data'):
      user['immutable_data'] = [data_hash]

   elif data_hash not in user['immutable_data']:
      user['immutable_data'].append( data_hash )

   return True


def remove_immutable_data( user, data_hash ):
   """
   Remove a data hash from user data.
   Return True if removed
   Return False if not present
   """
   if not HASH160_TYPE.valid( data_hash ):
      return False

   if user.has_key('immutable_data'):
      if data_hash in user['immutable_data']:
         user['immutable_data'].remove( data_hash )
         return True
      else:
         return False


def has_immutable_data( user, data_hash ):
   """
   Does the given user have the given immutable data?
   Return True if so
   Return False if not
   """
   if not HASH160_TYPE.valid( data_hash ):
      return False

   return user.has_key('immutable_data') and data_hash in user['immutable_data']


def has_mutable_data_route( user, data_id ):
   """
   Does the given user have the named mutable data route?
   Return True if so
   Return False if not
   """
   if not user.has_key('mutable_data'):
      return False

   else:

      for route in user['mutable_data']:
         if route['id'] == data_id:
            return True

      return False


def get_mutable_data_route( user, data_id ):
   """
   Get the data route for a piece of mutable data.
   Return the route (as a dict) on success
   Return None if not found
   """

   if not user.has_key('mutable_data'):
      return None

   for route in user['mutable_data']:
      if route['id'] == data_id:
         return route

   return None


def add_mutable_data_route( user, data_route ):
   """
   Add a route to mutable data to a user.
   Ensure uniqueness for the data_id.
   Return True on success
   Return False if this is a duplicate
   Raise an Exception if the route is invalid
   """

   if not schema_match( ROUTE_SCHEMA, data_route, allow_extra=True ):
      # invalid route
      raise Exception("Invalid route")

   if not user.has_key('mutable_data'):

      user['mutable_data'] = [ data_route ]

   else:

      # check for duplicates
      for route in user['mutable_data']:

         if route['id'] == data_route['id']:
            return False

      user['mutable_data'].append( data_route )

   return True


def remove_mutable_data_route( user, data_id ):
   """
   Remove a route from mutable data in a user.
   Return True if removed
   Return False if the user had no such data.
   """

   if not user.has_key('mutable_data'):
      return False

   else:

      # check for it
      for route in user['mutable_data']:

         if route['id'] == data_id:

            # yup
            user['mutable_data'].remove( route )
            return True

      # already gone
      return False


def name( user ):
   """
   Get a user's name
   """
   return user["name"]["formatted"]
