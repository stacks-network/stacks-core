from binascii import hexlify, unhexlify
from utilitybelt import is_hex, hex_to_charset, charset_to_hex

from .config import *
from .schemas import *
from .parsing import json_stable_serialize

ID_SCHEMA = {

   "name": {
      "formatted": STRING
   },
   
   "bio": STRING,
   
   OPTIONAL( "location" ): {
      "formatted": STRING 
   },
   
   "website": URL,
   
   "bitcoin": {
      "address": BITCOIN_ADDRESS
   },
   
   "avatar": { 
      "url": URL,
   },
   
   "cover": {
      "url": URL,
   },
   
   OPTIONAL( "pgp" ): {
      "url": URL,
      "fingerprint": PGP_FINGERPRINT,
   },
   
   OPTIONAL( "email" ): EMAIL,
   
   "twitter": {
      "username": STRING,
      "proof": {
         "url": URL
       }
   },
   
   "facebook": {
      "username": STRING,
      "proof": {
         "url": URL
       }
   },
   
   "github": {
      "username": STRING,
      "proof": {
         "url": URL
       }
   },
   
   OPTIONAL( "immutable_data" ): HASH160_ARRAY,
   
   "v": STRING
}


def parse_user_profile( user_json ):
   """
   Parse a user's profile into JSON.  Ensure that it matches a supported schema.
   Return a deserialized object (i.e. a dict) with the JSON data on success.
   Return None if it could not be parsed.
   """

   user_profile = None 
   
   try:
      user_profile = json.loads( user_profile_json )
   except Exception, e:
      # not valid json 
      return None 
   
   # verify that this is a valid profile 
   valid = schemas.schema_match( config.ID_SCHEMA, user_profile )
   if not valid:
      return None 
   
   return user_profile 


def serialize_user_profile( user_profile ):
   """
   Serialize a profile into JSON.  Prefer this to json.dumps,
   since we do so in a stable way (i.e. the same profile data 
   will serialize, byte-for-byte, to the same JSON).
   """
   return json_stable_serialize( user_profile )
   

def add_immutable_data( user_profile, data_hash ):
   """
   Add a data hash to profile data.  Make sure it's a valid hash as well.
   Return True on success 
   Return False otherwise.
   """
   
   if not HASH160_TYPE.valid( data_hash ):
      return False 
   
   if not user_profile.has_key('immutable_data'):
      user_profile['immutable_data'] = [data_hash]
   else:
      user_profile['immutable_data'].append( data_hash )
   
   return True


def remove_immutable_data( user_profile, data_hash ):
   """
   Remove a data hash from profile data.
   Always succeeds; idempotent.
   """
   
   if user_profile.has_key('immutable_data'):
      if data_hash in user_profile['immutable_data']:
         user_profile['immutable_data'].remove( data_hash )

