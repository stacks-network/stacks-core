from coinkit import embed_data_in_blockchain, BlockchainInfoClient
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex
from ..config import *
from ..scripts import name_script_to_hex, add_magic_bytes
from ..hashing import hash_name

def build_preorder_name_script(name, salt=None, testspace=False):
    """ Takes in an ascii string as a name and an optional hex salt.
    """
    if salt:
        if not is_hex(salt) and len(unhexlify(salt)) == LENGTHS['salt']:
            raise ValueError('Invalid salt')
    else:
        salt = hexlify(gen_name_salt())
    
    name_hash = hash_name(name, salt)

    script = 'NAME_PREORDER %s' % name_hash
    hex_script = name_script_to_hex(script)
    packaged_script = add_magic_bytes(hex_script, testspace=testspace)

    return packaged_script, salt

def preorder_name(name, private_key, salt=None,
                  blockchain_client=BlockchainInfoClient(), testspace=False):
    nulldata, salt = build_preorder_name_script(name, testspace=testspace,
        salt=salt)
    response = embed_data_in_blockchain(
        nulldata, private_key, blockchain_client, format='hex')
    #response = {'success': True }
    response.update({ 'data': nulldata, 'salt': salt })
    return response

def parse_name_preorder(bin_payload):
    name_hash = bin_payload[0:LENGTHS['name_hash']]
    return {
        'opcode': 'NAME_PREORDER', 'hash': hexlify(name_hash)
    }
