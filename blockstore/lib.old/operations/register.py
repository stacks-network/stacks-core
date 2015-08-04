from pybitcoin import embed_data_in_blockchain, BlockchainInfoClient
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40, is_b40
from ..config import *
from ..scripts import blockstore_script_to_hex, add_magic_bytes


def build(name, testset=False):
    """
    Takes in the name that was preordered, including the namespace ID (but not the id:// scheme)
    Returns a hex string representing up to LENGTHS['blockchain_id_name'] bytes.
    
    Record format:
    
    0    2  3                             39
    |----|--|-----------------------------|
    magic op   name.ns_id (34 bytes)
    
    """
    
    if not is_b40( name ):
       raise Exception("Name '%s' is not base-40" % name)
    
    name_hex = hexlify(name)
    if len(name_hex) > LENGTHS['blockchain_id_name'] * 2:
       # too long
      raise Exception("Name '%s' too long (exceeds %d bytes)" % (fqn, LENGTHS['blockchain_id_name']))
    
    readable_script = "NAME_REGISTRATION %s" % (hexlify(name))
    hex_script = blockstore_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script, testset=testset)
    
    return packaged_script 


def broadcast(name, private_key, blockchain_client=BlockchainInfoClient(), testset=False):
    
    nulldata = build(name, testset=testset)
    # response = {'success': True }
    response = embed_data_in_blockchain( nulldata, private_key, blockchain_client, format='hex')
    response.update({'data': nulldata})
    return response


def parse(bin_payload, outputs):
    
    """
    Interpret a block's nulldata back into a name.  The first three bytes (2 magic + 1 opcode)
    will not be present in bin_payload.
    
    The name will be directly represented by the bytes given.
    """
    
    fqn = bin_payload
    
    return {
       'opcode': 'NAME_REGISTRATION',
       'name': fqn
    }
 
