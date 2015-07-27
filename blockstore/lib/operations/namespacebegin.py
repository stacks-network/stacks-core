
from coinkit import embed_data_in_blockchain, BlockchainInfoClient, hex_hash160
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40, is_b40
from ..config import *
from ..scripts import blockstore_script_to_hex, add_magic_bytes

def build( namespace_id, testset=False ):
   """
   Record to mark the end of a namespace import in the blockchain.
   
   Takes an base40-encoded namespace ID to mark the end.
   
   Format:
   
   0     2  3  4  5           24
   |-----|--|--|--|-----------|
   magic op len .   ns_id
   """
   
   # sanity check 
   if not is_b40( namespace_id ):
      raise Exception("Namespace ID '%s' is not base-40" % namespace_id)
   
   if len(namespace_id) == 0 or len(namespace_id) > LENGTHS['blockchain_id_namespace_id']:
      raise Exception("Invalid namespace ID '%s (expected length between 1 and %s)" % (namespace_id, LENGTHS['blockchain_id_namespace_id']))
   
   readable_script = "NAMESPACE_BEGIN %i %s" % (len(namespace_id), hexlify("." + namespace_id))
   hex_script = blockstore_script_to_hex(readable_script)
   packaged_script = add_magic_bytes(hex_script, testset=testset)
   
   return packaged_script


def broadcast( namespace_id, private_key, blockchain_client=BlockchainInfoClient(), testset=False ):
   
   nulldata = build( namespace_id, testset=testset )
   # response = {'success': True }
   response = embed_data_in_blockchain( nulldata, private_key, blockchain_client, format='hex')
   response.update({'data': nulldata})
   return response


def parse( bin_payload ):
   """
   NOTE: the first three bytes will be missing
   """
   
   namespace_id_len = ord( bin_payload[0:LENGTHS['blockchain_id_namespace_id_len']] )
   namespace_id = bin_payload[ LENGTHS['blockchain_id_namespace_id_len'] + 1:LENGTHS['blockchain_id_namespace_id_len'] + namespace_id_len + 1 ]	# skip the '.'

   return {
      'opcode': 'NAMESPACE_BEGIN',
      'namespace_id': namespace_id
   }
