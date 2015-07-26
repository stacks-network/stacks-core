from coinkit import embed_data_in_blockchain, BlockchainInfoClient, hex_hash160
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40
from ..config import *
from ..scripts import blockstore_script_to_hex, add_magic_bytes


def build(key, name, data=None, testset=False):
    """
    Delete a chunk of signed data, owned by a particular name.
    
    Record format:
    
    0     2  3                   19                      39
    |-----|--|-------------------|-----------------------|
    magic op  hash128(name)      hash160(data)
    """
    
    if name.startswith(NAME_SCHEME):
       raise Exception("Invalid name %s: must not start with %s" % (name, NAME_SCHEME))
    
    hex_name = hash256_trunc128(name)
    
    if key is None:
        if data is None:
            raise ValueError('A data hash or data string is required.')
        
        key = hex_hash160(data)
        
    elif not (is_hex(key) and len(key) == 2*LENGTHS['data_hash']):
        raise ValueError('Data hash must be a %s byte hex string.' % LENGTHS['data_hash'])

    readable_script = 'DATA_RM %s %s' % (hex_name, key)
    hex_script = blockstore_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script, testset=testset)

    return packaged_script


def broadcast(key, name, private_key, data=None, blockchain_client=BlockchainInfoClient(), testset=False):
    """
    Broadcast a 'delete data' message to the blockchain.
    """
    
    if key is None and data is None:
       raise ValueError("A key or the raw data string is required.")
    
    nulldata = build( key, name, data=data, testset=testset)
    response = embed_data_in_blockchain(nulldata, private_key, blockchain_client, format='hex')
    response.update({'data': nulldata})
    return response


def parse(bin_payload):
    """
    Parse a binary 'delete data' message, starting from the 3rd byte.
    """
    
    name_hash_bin = bin_payload[0:LENGTHS['name_hash']]
    data_hash_bin = bin_payload[LENGHTS['name_hash']:]
    
    name_hash = hexlify( name_hash )
    data_hash = hexlify( data_hash )
    
    return {
       'opcode': 'DATA_RM',
       'name_hash': name_hash,
       'data_hash': data_hash
    }
    
