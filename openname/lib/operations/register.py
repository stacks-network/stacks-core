from coinkit import embed_data_in_blockchain, BlockchainInfoClient
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40
from ..config import *
from ..scripts import name_script_to_hex, add_magic_bytes


def build(name, testset=False):
    """ Takes in the name that was preordered.
    """
    hex_name = b40_to_hex(name)
    name_len = len(hex_name)/2

    readable_script = 'NAME_REGISTRATION %i %s' % (name_len, hex_name)
    hex_script = name_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script, testset=testset)

    return packaged_script


def broadcast(name, private_key,
              blockchain_client=BlockchainInfoClient(), testset=False):
    nulldata = build(name, testset=testset)
    # response = {'success': True }
    response = embed_data_in_blockchain(
        nulldata, private_key, blockchain_client, format='hex')
    response.update({'data': nulldata})
    return response


def parse(bin_payload):
    name_len = ord(bin_payload[0:1])
    name = bin_payload[1:1+name_len]
    return {
        'opcode': 'NAME_REGISTRATION',
        'name': bin_to_b40(name)
    }
