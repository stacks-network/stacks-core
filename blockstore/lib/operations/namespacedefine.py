from coinkit import embed_data_in_blockchain, BlockchainInfoClient, hex_hash160
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40, is_b40
from ..config import *
from ..scripts import blockstore_script_to_hex, add_magic_bytes, get_script_pubkey
from ..hashing import hash_name

def namespace_decay_to_float( namespace_decay_fixedpoint ):
   """
   Convert the raw namespace decay rate (a fixedpoint decimal)
   to a floating-point number.
   
   Upper 8 bits: integer 
   Lower 24 bits: decimal
   """
   
   ipart = namespace_decay_fixedpoint >> 24
   fpart = namespace_decay_fixedpoint & 0xff000000
   
   return ipart + (float(fpart) / 2**24)

def namespace_decay_to_fixpoint( namespace_decay_float ):
   """
   Convert a floating-point number to a namespace decay rate.
   Return None if invalid 
   """
   
   if namespace_decay_float < 0:
      return None 
   
   ipart = int(namespace_decay_float) 
   
   if( ipart > 255 ):
      return None 
   
   fpart = (namespace_decay_float - ipart)
   
   fixpoint = (ipart << 24) | int(fpart * (1 << 24))
   return fixpoint
   
   
# name lifetime (blocks): 4 bytes (0xffffffff for infinite)
# baseline price for one-letter names (satoshis): 8 bytes
# price decay rate per letter (fixed-point decimal: 2**8 integer part, 2**24 decimal part): 4 bytes
# namespace ID: up to 19 bytes

def build( namespace_id, script_pubkey, lifetime, satoshi_cost, price_decay_rate, testset=False ):
   """
   Record to mark the beginning of a namespace import in the blockchain.
   
   Takes an ASCII-encoded namespace ID and parameters and registers the beginning of a namespace definition.
   NOTE: "namespace_id" must not start with ., but can contain anything else we want
   
   We put the hash of the namespace ID instead of the namespace ID itself to avoid races with squatters (akin to pre-ordering)
   
   Format:
   
   0     2   3     7          15     19                           39
   |-----|---|-----|----------|------|----------------------------|
   magic op  life  cost       decay  hash(ns_id,script_pubkey)
   """
   
   # sanity check 
   if not is_b40( namespace_id ):
      raise Exception("Namespace identifier '%s' is not base-40" % namespace_id)
   
   if lifetime < 0 or lifetime > (2**32 - 1):
      raise Exception("Lifetime '%s' out of range (expected unsigned 32-bit integer)" % lifetime)
   
   if satoshi_cost < 0 or satoshi_cost > (2**64 - 1):
      raise Exception("Cost '%s' out of range (expected unsigned 64-bit integer)" % satoshi_cost)
   
   if price_decay_rate < 0 or price_decay_rate > (2**32 - 1):
      raise Exception("Decay rate '%s' out of range (expected unsigned 32-bit integer)" % price_decay_rate)
   
   if len(namespace_id) == 0 or len(namespace_id) > LENGTHS['blockchain_id_namespace_id']:
      raise Exception("Invalid namespace ID length '%s (expected length between 1 and %s)" % (namespace_id, LENGTHS['blockchain_id_namespace_id']))
   
   namespace_id_hash = hash_name(namespace_id, script_pubkey)
   
   readable_script = "NAMESPACE_DEFINE %i %i %i %s" % (lifetime, satoshi_cost, price_decay_rate, namespace_id_hash)
   hex_script = blockstore_script_to_hex(readable_script)
   packaged_script = add_magic_bytes(hex_script, testset=testset)
   
   return packaged_script


def broadcast( namespace_id, lifetime, satoshi_cost, price_decay_rate, private_key, blockchain_client=BlockchainInfoClient(), testset=False ):
   """
   Propagate a namespace.
   
   Arguments:
   namespace_id         human-readable (i.e. base-40) name of the namespace
   lifetime:            the number of blocks for which names will be valid (pass a negative value for "infinite")
   satoshi_cost:        the base cost (i.e. cost of a 1-character name), in satoshis 
   price_decay_rate     a positive float representing the rate at which names get cheaper.  The formula is satoshi_cost / (price_decay_rate)^(name_length - 1).
   private_key          the Bitcoin address that created this namespace, and can populate it.
   """
    
   script_pubkey = get_script_pubkey( private_key )
   price_decay_rate_fixedpoint = namespace_decay_to_fixpoint( price_decay_rate )
   
   if price_decay_rate_fixedpoint is None:
      raise Exception("Invalid price decay rate '%s'" % price_decay_rate)
   
   if lifetime < 0:
      lifetime = NAMESPACE_LIFE_INFINITE 
      
   nulldata = build( namespace_id, script_pubkey, lifetime, satoshi_cost, price_decay_rate_fixedpoint, testset=testset )
   
   # response = {'success': True }
   response = embed_data_in_blockchain( nulldata, private_key, blockchain_client, format='hex')
   response.update({'data': nulldata})
   return response
   

def parse( bin_payload ):
   """
   NOTE: the first three bytes will be missing
   """
   
   off = 0
   life = None 
   cost = None 
   decay = None 
   namespace_id_len = None 
   namespace_id = None 
   
   life = int( hexlify(bin_payload[off:off+LENGTHS['blockchain_id_namespace_life']]), 16 )
   
   off += LENGTHS['blockchain_id_namespace_life']
   
   cost = int( hexlify(bin_payload[off:off+LENGTHS['blockchain_id_namespace_cost']]), 16 )
   
   off += LENGTHS['blockchain_id_namespace_cost']
   
   decay_fixedpoint = int( hexlify(bin_payload[off:off+LENGTHS['blockchain_id_namespace_price_decay']]), 16 )
   
   off += LENGTHS['blockchain_id_namespace_price_decay']
   
   namespace_id_len = int( hexlify(bin_payload[off:off+LENGTHS['blockchain_id_namespace_id_len']]), 16 )
   
   off += LENGTHS['blockchain_id_namespace_id_len']
   
   namespace_id_hash = bin_payload[off:off+namespace_id_len]
   
   return {
      'opcode': 'NAMESPACE_DEFINE',
      'lifetime': life,
      'cost': cost,
      'price_decay': namespace_decay_to_float( decay_fixedpoint ),
      'namespace_id_hash': hexlify( namespace_id_hash )
   }

