from coinkit import embed_data_in_blockchain, BlockchainInfoClient, bin_hash160
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex
from ..config import *
from ..scripts import name_script_to_hex, add_magic_bytes
from ..hashing import hash_name, calculate_consensus_hash128, gen_name_salt

def build(name, consensus_hash, salt=None, testset=False):
    """ Takes in an ascii string as a name and an optional hex salt.
    """
    if salt:
        if not is_hex(salt) and len(unhexlify(salt)) == LENGTHS['salt']:
            raise ValueError('Invalid salt')
    else:
        salt = hexlify(gen_name_salt())
    
    name_hash = hash_name(name, salt)

    consensus_hash128 = calculate_consensus_hash128(consensus_hash)

    script = 'NAME_PREORDER %s %s' % (name_hash, consensus_hash128)
    hex_script = name_script_to_hex(script)
    packaged_script = add_magic_bytes(hex_script, testset=testset)

    return packaged_script, salt

def broadcast(name, consensus_hash, private_key, salt=None,
              blockchain_client=BlockchainInfoClient(), testset=False):
    nulldata, salt = build(
        name, consensus_hash, testset=testset, salt=salt)
    response = embed_data_in_blockchain(
        nulldata, private_key, blockchain_client, format='hex')
    #response = {'success': True }
    response.update({ 'data': nulldata, 'salt': salt })
    return response

def parse(bin_payload):
    name_hash = bin_payload[0:LENGTHS['name_hash']]
    consensus_hash = bin_payload[LENGTHS['name_hash']:]
    return {
        'opcode': 'NAME_PREORDER',
        'name_hash': hexlify(name_hash),
        'consensus_hash': hexlify(consensus_hash)
    }
