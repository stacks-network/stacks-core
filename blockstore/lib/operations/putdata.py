from coinkit import embed_data_in_blockchain, BlockchainInfoClient, hex_hash160, bin_hash160, BitcoinPrivateKey
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40, is_b40
from ..config import *
from ..scripts import blockstore_script_to_hex, add_magic_bytes, get_script_pubkey
from ..hashing import hash256_trunc128


def build(name, data_hash=None, data=None, testset=False):
    """
    Write a signed storage record: takes the name of the owner and the data or the data's hash (i.e. the key to the data).
    Name must include the namespace ID, but not the protocol scheme.
    In either case, we only want the name.ns_id hash and the data hash.
    
    Format:
    
    0     2  3                    19             39
    |-----|--|--------------------|--------------|
    magic op  hash128(name)        hash160(data)
    
    WARNING: the caller must verify that the data is well-formed.
    """
    
    hex_name = hash256_trunc128(name)
    name_len = len(hex_name)/2

    if not data_hash:
        if not data:
            raise ValueError('A data hash or data string is required.')
         
        data_hash = hex_hash160(data)
        
    elif not (is_hex(data_hash) and len(data_hash) == 40):
        raise ValueError('Data hash must be a 20 byte hex string.')

    readable_script = 'DATA_PUT %s %s' % (hex_name, data_hash)
    hex_script = blockstore_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script, testset=testset)

    return packaged_script


def broadcast(name, data_hash, private_key, blockchain_client=BlockchainInfoClient(), testset=False):
    """
    Put the DATA_PUT message into the blockchain.
    This effectively signs the data's hash with the user's private key.
    """
    
    nulldata = build(name, data_hash=data_hash, testset=testset)
    response = embed_data_in_blockchain(nulldata, private_key, blockchain_client, format='hex')
    response.update({'data': nulldata})
    return response


def parse(bin_payload):
    """
    Recover the hashed name and data from a blockchain record.
    """
    name_hash_bin = bin_payload[:LENGTHS['name_hash']]
    data_hash_bin = bin_payload[LENGTHS['name_hash']:]
    
    name_hash = hexlify( name_hash_bin )
    data_hash = hexlify( data_hash_bin )
    
    return {
        'opcode': 'DATA_PUT',
        'name_hash': name_hash,
        'data_hash': data_hash
    }
