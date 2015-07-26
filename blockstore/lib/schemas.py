#!/usr/bin/python

"""
Listing of data schemas, as well as methods for validating them.
"""

import types
import re

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
   

class BitcoinAddressType( SchemaType ):
   
   def __init__(self):
      super( BitcoinAddressType, self ).__init__( types.StringType, types.UnicodeType )
      
   def valid( self, value ):
      
      if type(value) != types.StringType and type(value) != types.UnicodeType:
         print "mismatch on type (%s)" % type(value)
         return False 
      
      strvalue = str(value)
      
      if re.match(r"[a-zA-Z1-9]{27,35}$", strvalue) is None:
         print "mismatch on regex (%s)" % strvalue
         return False 
      
      return True


class PGPFingerprintType( SchemaType ):
   
   def __init__(self):
      super( PGPFingerprintType, self ).__init__( types.StringType, types.UnicodeType )
      
   def valid( self, value ):
      
      if type(value) != types.StringType and type(value) != types.UnicodeType:
         return False 
      
      strvalue = str(value)
      
      if re.match(r"[a-fA-F0-9 :]$", strvalue) is None:
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


STRING = SchemaType( types.StringType, types.UnicodeType )
URL = STRING
PGP_FINGERPRINT = PGPFingerprintType()
BITCOIN_ADDRESS = BitcoinAddressType()
EMAIL = EmailType()
OPTIONAL = OptionalField

def match( schema, obj, verbose=False ):
   
   """
   Recursively verify that the given object has the given schema.
   Return True if so
   Return False if not 
   """
   
   def debug( msg ):
      if verbose:
         print msg
   
   # object is literal?
   if type(obj) != types.DictType:
      if obj != schema:
         debug( "Literal '%s' does not match '%s'" % (literal, schema) )
         return False 
      
      else:
         return True
      
   # all object keys must be acceptable to the schema
   for literal in obj.keys():
      
      if literal not in schema.keys():
         
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
      
      if type(sub_schema) != types.DictType:
         
         if isinstance( sub_schema, SchemaType ):
            # check custom validation
            is_match = sub_schema.valid( sub_object )
            if is_match is False:
               print "schema not valid: %s" % (sub_object)
            
         else:
            # check type 
            is_match = (type(sub_schema) == type(sub_object))
            if is_match is False:
               print "%s != %s" % (type(sub_schema), type(sub_object))
            
      else:
         
         # recursively verify match 
         is_match = match( sub_schema, sub_object )
         
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
      rc = match( PASSCARD_SCHEMA_V2, testcase, verbose=True )
      print "test case %s: %s" % (i, rc)
"""