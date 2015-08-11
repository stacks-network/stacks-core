# TODO: this module will become the top-level module for:
# -- calling into the virtual blockchain's OP_RETURN parsers
# -- holding any serialization and deserialization logic that is common across this system.

import json 

def json_stable_serialize( json_data ):
   """
   Serialize a dict to JSON, but ensure that key/value pairs are serialized 
   in a predictable, stable, total order.
   """
   
   if isinstance( json_data, list ) or isinstance( json_data, tuple ):
      json_serialized_list = []
      for json_element in json_data:
         json_serialized_list.append( json_stable_serialize( json_element ) )
      
      return "[" + ", ".join( json_serialized_list ) + "]"
   
   elif isinstance( json_data, dict ):
      json_serialized_dict = {}
      for key in json_data.keys():
         json_serialized_dict[key] = json_stable_serialize( json_data[key] )
      
      key_order = [k for k in json_serialized_dict.keys()]
      key_order.sort()
      
      return "{" + ", ".join( ['"%s": %s' % (k, json_serialized_dict[k]) for k in key_order] ) + "}"
   
   elif isinstance( json_data, str ) or isinstance( json_data, unicode ):
      return '"' + json_data + '"'
   
   return '"' + str(json_data) + '"'