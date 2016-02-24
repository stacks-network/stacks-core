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

import types
import re
from pybitcoin.formatcheck import is_b58check_address

class SchemaField( object ):
   
   def __init__(self, name):
      self.name = name

   def __repr__(self):
      return self.name 

   def __eq__(self, value):
      return self.name == value
   

class SchemaType( object ):
   
   def __init__(self, *args):
      self.types = args
   
   def get_types(self):
      return self.types 
   
   def valid( self, value ):
      # children override this
      return type(value) in self.get_types()
   
   def __repr__(self):
      return "SchemaType(%s)" % (",".join( [str(t) for t in self.get_types()] ) )
   
      
class Base64StringType( SchemaType ):
   
   def __init__(self):
      super( Base64StringType, self ).__init__( types.StringType, types.UnicodeType )
   
   def valid( self, value ):
      
      if type(value) != types.StringType and type(value) != types.UnicodeType:
         return False 
      
      if len(value) > 0 and re.match(r"^[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=]+$", value) is None:
         return False
      
      return True 
   

class BitcoinAddressType( SchemaType ):
   
   def __init__(self):
      super( BitcoinAddressType, self ).__init__( types.StringType, types.UnicodeType )
      
   def valid( self, value ):
      
      if type(value) != types.StringType and type(value) != types.UnicodeType:
         return False 
      
      strvalue = str(value)
      
      return is_b58check_address( strvalue )


class HashType( SchemaType ):
   
   def __init__(self, length=None ):
      super( HashType, self ).__init__( types.StringType, types.UnicodeType )
      self.length = length
   
   def valid( self, value ):
      
      if type(value) != types.StringType and type(value) != types.UnicodeType:
         return False 
      
      strvalue = str(value)
      
      if re.match(r"^[a-fA-F0-9]+$", strvalue ) is None:
         return False 
      
      if self.length is not None and len(strvalue) != self.length * 2:
         return False 
      
      return True


class PGPFingerprintType( SchemaType ):
   
   def __init__(self):
      super( PGPFingerprintType, self ).__init__( types.StringType, types.UnicodeType )
      
   def valid( self, value ):
      
      if type(value) != types.StringType and type(value) != types.UnicodeType:
         return False 
      
      strvalue = str(value)
      
      if re.match(r"^[a-fA-F0-9 :]+$", strvalue) is None:
         return False 
      
      return True


class EmailType( SchemaType ):
   
   # RFC-822 compliant, as long as there aren't any comments in the address.
   # taken from http://chrisbailey.blogs.ilrt.org/2013/08/19/validating-email-addresses-in-python/
   email_regex_str = r"^(?=^.{1,256}$)(?=.{1,64}@)(?:[^\x00-\x20\x22\x28\x29\x2c\x2e\x3a-\x3c\x3e\x40\x5b-\x5d\x7f-\xff]+|\x22(?:[^\x0d\x22\x5c\x80-\xff]|\x5c[\x00-\x7f])*\x22)(?:\x2e(?:[^\x00-\x20\x22\x28\x29\x2c\x2e\x3a-\x3c\x3e\x40\x5b-\x5d\x7f-\xff]+|\x22(?:[^\x0d\x22\x5c\x80-\xff]|\x5c[\x00-\x7f])*\x22))*\x40(?:[^\x00-\x20\x22\x28\x29\x2c\x2e\x3a-\x3c\x3e\x40\x5b-\x5d\x7f-\xff]+|[\x5b](?:[^\x0d\x5b-\x5d\x80-\xff]|\x5c[\x00-\x7f])*[\x5d])(?:\x2e(?:[^\x00-\x20\x22\x28\x29\x2c\x2e\x3a-\x3c\x3e\x40\x5b-\x5d\x7f-\xff]+|[\x5b](?:[^\x0d\x5b-\x5d\x80-\xff]|\x5c[\x00-\x7f])*[\x5d]))*$"
   
   def __init__(self):
      super( EmailType, self ).__init__( types.StringType, types.UnicodeType )
      
   def valid( self, value ):
      
      if type(value) != types.StringType and type(value) != types.UnicodeType:
         return False 
      
      strvalue = str(value)
      
      if re.match( self.email_regex_str, strvalue ) is None:
         return False 
      
      return True


class OptionalField( SchemaField ):
   pass


INTEGER = SchemaType( types.IntType, types.LongType )
FLOAT = SchemaType( types.FloatType )
STRING = SchemaType( types.StringType, types.UnicodeType )
B64STRING = Base64StringType()
HASH160_TYPE = HashType(20) 
URL = STRING
PGP_FINGERPRINT = PGPFingerprintType()
BITCOIN_ADDRESS = BitcoinAddressType()
EMAIL = EmailType()
OPTIONAL = OptionalField

def schema_match( schema, obj, allow_extra=True, verbose=False ):
   
   """
   Recursively verify that the given object has the given schema.
   Optionally allow extra unmatched fields in the object that are not present in the schema.
   Return True if so
   Return False if not 
   """
   
   def debug( msg ):
      if verbose:
         print msg
   
   # object is literal?
   if type(obj) != types.DictType:
      if not schema.valid( obj ):
         debug( "Literal '%s' does not match '%s'" % (obj, schema) )
         return False 
      
      else:
         return True
      
   # all object keys must be acceptable to the schema, unless we're allowing extras
   for literal in obj.keys():
      
      if literal not in schema.keys() and not allow_extra:
         
         debug("Unmatched object literal '%s'" % literal)
         return False
   
   # all non-optional schema keys must be present in the object
   for field in schema.keys():
      
      optional = False 
      literal = field
      if isinstance( field, OptionalField ):
         literal = str(field)
         optional = True 
         
      if literal not in obj.keys():
         
         if not optional:
            
            debug( "Literal '%s' not found in object" % literal )
            return False
   
         else:
            continue
      
      sub_object = obj[literal]
      sub_schema = schema[field]
      is_match = False
      
      debug("%s =~ %s" % (sub_object, sub_schema))
      
      if type(sub_schema) != types.DictType:
         
         if isinstance( sub_schema, SchemaType ):
            
            # check custom validation
            is_match = sub_schema.valid( sub_object )
            if is_match is False:
               debug( "%s (%s): schema not valid: '%s'" % (sub_schema, field, sub_object) )
         
         elif isinstance( sub_schema, types.ListType ) and len(sub_schema) == 1:
            
            # array of objects with a given schema
            sub_schema = sub_schema[0]
            
            if not isinstance( sub_object, types.ListType ):
               is_match = False
               debug("%s != [%s]" % (sub_object, sub_schema))
               
            else:
               
               is_match = True  # for empty lists
               for so in sub_object:
                  
                  # match each object in the list to this schema
                  is_match = schema_match( sub_schema, so, verbose=verbose )
                  if not is_match:
                     debug("[%s] is not [%s]" % (so, sub_schema))
                     break
            
         else:
            # invalid schema 
            raise Exception("Invalid schema: '%s' ('%s') is neither a SchemaType nor a list of SchemaType instances" % (sub_schema, field))
            
      else:
         
         # recursively verify match 
         is_match = schema_match( sub_schema, sub_object, verbose=verbose )
         if not is_match:
             debug( "%s is not %s" % (sub_object, sub_schema) )
         
      if not is_match:
         debug( "Mismatch on key '%s'" % literal)
         return False 

   # all checks pass
   return True 


# tests 
"""
if __name__ == "__main__":
      
   PASSCARD_SCHEMA_V2 = {

      "name": {
         "formatted": STRING
      },
      
      "bio": STRING,
      
      "location": {
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
      
      OPTIONAL("pgp"): {
         "url": URL,
         "fingerprint": PGP_FINGERPRINT,
      },
      
      OPTIONAL("email"): EMAIL,
      
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
      
      OPTIONAL("immutable_data"): [ STRING ]
      
      "v": STRING
   }

   testcases = [
      # valid 
      {
         "website": "http://www.cs.princeton.edu/~jcnelson", 
         "location": {
            "formatted": "Princeton University"
         }, 
         "github": {
            "proof": {
               "url": "https://gist.github.com/jcnelson/70c02f80f8d4b0b8fc15"
            }, 
            "username": "jcnelson"
         }, 
         "bio": "PhD student", 
         "bitcoin": {
            "address": "17zf596xPvV8Z8ThbWHZHYQZEURSwebsKE"
         }, 
         "twitter": {
            "proof": {
               "url": "https://twitter.com/judecnelson/status/507374756291555328"
            }, 
            "username": "judecnelson"
         }, 
         "email": "judecn@gmail.com",
         "avatar": {
            "url": "https://s3.amazonaws.com/kd4/judecn"
         }, 
         "name": {
            "formatted": "Jude Nelson"
         }, 
         "facebook": {
            "proof": {
               "url": "https://facebook.com/sunspider/posts/674912239245011"
            }, 
            "username": "sunspider"
         }, 
         "cover": {
            "url": "https://s3.amazonaws.com/97p/gQZ.jpg"
         }, 
         "v": "0.2"
      },
         
      # valid (missing email)
      {
         "website": "http://www.cs.princeton.edu/~jcnelson", 
         "location": {
            "formatted": "Princeton University"
         }, 
         "github": {
            "proof": {
               "url": "https://gist.github.com/jcnelson/70c02f80f8d4b0b8fc15"
            }, 
            "username": "jcnelson"
         }, 
         "bio": "PhD student", 
         "bitcoin": {
            "address": "17zf596xPvV8Z8ThbWHZHYQZEURSwebsKE"
         }, 
         "twitter": {
            "proof": {
               "url": "https://twitter.com/judecnelson/status/507374756291555328"
            }, 
            "username": "judecnelson"
         }, 
         "avatar": {
            "url": "https://s3.amazonaws.com/kd4/judecn"
         }, 
         "name": {
            "formatted": "Jude Nelson"
         }, 
         "facebook": {
            "proof": {
               "url": "https://facebook.com/sunspider/posts/674912239245011"
            }, 
            "username": "sunspider"
         }, 
         "cover": {
            "url": "https://s3.amazonaws.com/97p/gQZ.jpg"
         }, 
         "v": "0.2"
      },
      
      # invalid: missing name 
      {
         "website": "http://www.cs.princeton.edu/~jcnelson", 
         "location": {
            "formatted": "Princeton University"
         }, 
         "github": {
            "proof": {
               "url": "https://gist.github.com/jcnelson/70c02f80f8d4b0b8fc15"
            }, 
            "username": "jcnelson"
         }, 
         "bio": "PhD student", 
         "bitcoin": {
            "address": "17zf596xPvV8Z8ThbWHZHYQZEURSwebsKE"
         }, 
         "twitter": {
            "proof": {
               "url": "https://twitter.com/judecnelson/status/507374756291555328"
            }, 
            "username": "judecnelson"
         }, 
         "avatar": {
            "url": "https://s3.amazonaws.com/kd4/judecn"
         },
         "facebook": {
            "proof": {
               "url": "https://facebook.com/sunspider/posts/674912239245011"
            }, 
            "username": "sunspider"
         }, 
         "cover": {
            "url": "https://s3.amazonaws.com/97p/gQZ.jpg"
         }, 
         "v": "0.2"
      },
         
      # invalid: invalid website type
      {
         "website": 1,
         "location": {
            "formatted": "Princeton University"
         }, 
         "github": {
            "proof": {
               "url": "https://gist.github.com/jcnelson/70c02f80f8d4b0b8fc15"
            }, 
            "username": "jcnelson"
         }, 
         "bio": "PhD student", 
         "bitcoin": {
            "address": "17zf596xPvV8Z8ThbWHZHYQZEURSwebsKE"
         }, 
         "twitter": {
            "proof": {
               "url": "https://twitter.com/judecnelson/status/507374756291555328"
            }, 
            "username": "judecnelson"
         }, 
         "avatar": {
            "url": "https://s3.amazonaws.com/kd4/judecn"
         }, 
         "name": {
            "formatted": "Jude Nelson"
         }, 
         "facebook": {
            "proof": {
               "url": "https://facebook.com/sunspider/posts/674912239245011"
            }, 
            "username": "sunspider"
         }, 
         "cover": {
            "url": "https://s3.amazonaws.com/97p/gQZ.jpg"
         }, 
         "v": "0.2"
      },
      
      # invalid: extra field
      {
         "extra_field": "foo",
         "website": "http://www.cs.princeton.edu/~jcnelson", 
         "location": {
            "formatted": "Princeton University"
         }, 
         "github": {
            "proof": {
               "url": "https://gist.github.com/jcnelson/70c02f80f8d4b0b8fc15"
            }, 
            "username": "jcnelson"
         }, 
         "bio": "PhD student", 
         "bitcoin": {
            "address": "17zf596xPvV8Z8ThbWHZHYQZEURSwebsKE"
         }, 
         "twitter": {
            "proof": {
               "url": "https://twitter.com/judecnelson/status/507374756291555328"
            }, 
            "username": "judecnelson"
         }, 
         "avatar": {
            "url": "https://s3.amazonaws.com/kd4/judecn"
         }, 
         "name": {
            "formatted": "Jude Nelson"
         }, 
         "facebook": {
            "proof": {
               "url": "https://facebook.com/sunspider/posts/674912239245011"
            }, 
            "username": "sunspider"
         }, 
         "cover": {
            "url": "https://s3.amazonaws.com/97p/gQZ.jpg"
         }, 
         "v": "0.2"
      },
         
      # invalid: extra field in cover
      {
         "website": "http://www.cs.princeton.edu/~jcnelson", 
         "location": {
            "formatted": "Princeton University"
         }, 
         "github": {
            "proof": {
               "url": "https://gist.github.com/jcnelson/70c02f80f8d4b0b8fc15"
            }, 
            "username": "jcnelson"
         }, 
         "bio": "PhD student", 
         "bitcoin": {
            "address": "17zf596xPvV8Z8ThbWHZHYQZEURSwebsKE"
         }, 
         "twitter": {
            "proof": {
               "url": "https://twitter.com/judecnelson/status/507374756291555328"
            }, 
            "username": "judecnelson"
         }, 
         "avatar": {
            "url": "https://s3.amazonaws.com/kd4/judecn"
         }, 
         "name": {
            "formatted": "Jude Nelson"
         }, 
         "facebook": {
            "proof": {
               "url": "https://facebook.com/sunspider/posts/674912239245011"
            }, 
            "username": "sunspider"
         }, 
         "cover": {
            "url": "https://s3.amazonaws.com/97p/gQZ.jpg",
            "extra_field": "foo",
         }, 
         "v": "0.2"
      },
         
      # invalid: missing subobject "url" in "github"
      {
         "website": "http://www.cs.princeton.edu/~jcnelson", 
         "location": {
            "formatted": "Princeton University"
         }, 
         "github": {
             
            "username": "jcnelson"
         }, 
         "bio": "PhD student", 
         "bitcoin": {
            "address": "17zf596xPvV8Z8ThbWHZHYQZEURSwebsKE"
         }, 
         "twitter": {
            "proof": {
               "url": "https://twitter.com/judecnelson/status/507374756291555328"
            }, 
            "username": "judecnelson"
         }, 
         "avatar": {
            "url": "https://s3.amazonaws.com/kd4/judecn"
         }, 
         "name": {
            "formatted": "Jude Nelson"
         }, 
         "facebook": {
            "proof": {
               "url": "https://facebook.com/sunspider/posts/674912239245011"
            }, 
            "username": "sunspider"
         }, 
         "cover": {
            "url": "https://s3.amazonaws.com/97p/gQZ.jpg"
         }, 
         "v": "0.2"
      },
      
   ]
         
         
   for i in xrange(0, len(testcases)):
      
      testcase = testcases[i]
      rc = schema_match( PASSCARD_SCHEMA_V2, testcase, verbose=True )
      print "test case %s: %s" % (i, rc)
"""