from coinkit import embed_data_in_blockchain, BlockchainInfoClient
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40
from ..config import *
from ..scripts import name_script_to_hex, add_magic_bytes

def build(name, salt, testspace=False):
    """ Takes in the name that was preordered, along with the salt used.
    """
    hex_name = b40_to_hex(name)
    name_len = len(hex_name)/2
    if not is_hex(salt):
        salt = hexlify(salt)

    readable_script = 'NAME_REGISTRATION %i %s %s' % (name_len, hex_name, salt)
    hex_script = name_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script, testspace=testspace)

    return packaged_script

def broadcast(name, salt, private_key,
               blockchain_client=BlockchainInfoClient(), testspace=False):
    nulldata = build(name, salt, testspace=testspace)
    #response = {'success': True }
    response = embed_data_in_blockchain(
        nulldata, private_key, blockchain_client, format='hex')
    response.update({ 'data': nulldata })
    return response

def parse(bin_payload):
    name_len = ord(bin_payload[0:1])
    name = bin_payload[1:1+name_len]
    salt = bin_payload[1+name_len:1+name_len+LENGTHS['salt']]
    return {
        'opcode': 'NAME_REGISTRATION',
        'name': bin_to_b40(name),
        'salt': hexlify(salt)
    }
