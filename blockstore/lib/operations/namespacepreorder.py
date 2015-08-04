from pybitcoin import embed_data_in_blockchain, BlockchainInfoClient, hex_hash160
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40, is_b40
from ..config import *
from ..scripts import blockstore_script_to_hex, add_magic_bytes, get_script_pubkey
from ..hashing import hash_name

def build( namespace_id, consensus_hash, testset=False ):
   """
   Preorder a namespace with the given consensus hash.  This records that someone has begun to create 
   a namespace, while blinding all other peers to its ID.  This operation additionally records the 
   consensus hash in order to ensure that all peers will recognize that this sender has begun the creation.
   
   Takes an ASCII-encoded namespace ID.
   NOTE: "namespace_id" must not start with ., but can contain anything else we want
   
   We put the hash of the namespace ID instead of the namespace ID itself to avoid races with squatters (akin to pre-ordering)
   
   Format:
   
   0     2   3                        23               39
   |-----|---|------------------------|----------------|
   magic op  hash(ns_id,script_pubkey) consensus hash
   """
   
   # sanity check 
   if not is_b40( namespace_id ):
      raise Exception("Namespace identifier '%s' is not base-40" % namespace_id)
   
   if len(namespace_id) == 0 or len(namespace_id) > LENGTHS['blockchain_id_namespace_id']:
      raise Exception("Invalid namespace ID length '%s (expected length between 1 and %s)" % (namespace_id, LENGTHS['blockchain_id_namespace_id']))
   
   namespace_id_hash = hash_name(namespace_id, script_pubkey)
   
   readable_script = "NAMESPACE_PREORDER %s %s" % (namespace_id_hash, consensus_hash)
   hex_script = blockstore_script_to_hex(readable_script)
   packaged_script = add_magic_bytes(hex_script, testset=testset)
   
   return packaged_script


def broadcast( namespace_id, lifetime, satoshi_cost, price_decay_rate, consensus_hash, private_key, blockchain_client, testset=False ):
   """
   Propagate a namespace.
   
   Arguments:
   namespace_id         human-readable (i.e. base-40) name of the namespace
   private_key          the Bitcoin address that created this namespace, and can populate it.
   """
    
   script_pubkey = get_script_pubkey( private_key )
   nulldata = build( namespace_id, script_pubkey, consensus_hash, testset=testset )
   
   # response = {'success': True }
   response = embed_data_in_blockchain( nulldata, private_key, blockchain_client, format='hex')
   response.update({'data': nulldata})
   return response
   

def parse( bin_payload ):
   """
   NOTE: the first three bytes will be missing
   """
   
   namespace_id_hash = bin_payload[ :LENGTHS['preorder_name_hash'] ]
   consensus_hash = bin_payload[ LENGTHS['preorder_name_hash']: LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash'] ]
   
   namespace_id_hash = hexlify( namespace_id_hash )
   consensus_hash = hexlify( consensus_hash )
   
   return {
      'opcode': 'NAMESPACE_PREORDER',
      'namespace_id_hash': namespace_id_hash,
      'consensus_hash': consensus_hash
   }

