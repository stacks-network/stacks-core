from coinkit import embed_data_in_blockchain, BlockchainInfoClient, hex_hash160
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from ..b40 import b40_to_hex, bin_to_b40
from ..config import *
from ..scripts import name_script_to_hex, add_magic_bytes


def build(name, data_hash=None, data=None, testset=False):
    """ Takes in the name to update the data for and the data update itself.
    """
    hex_name = b40_to_hex(name)
    name_len = len(hex_name)/2

    if not data_hash:
        if not data:
            raise ValueError('A data hash or data string is required.')
        data_hash = hex_hash160(data)
    elif not (is_hex(data_hash) and len(data_hash) == 40):
        raise ValueError('Data hash must be a 20 byte hex string.')

    readable_script = 'NAME_UPDATE %i %s %s' % (name_len, hex_name, data_hash)
    hex_script = name_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script, testset=testset)

    return packaged_script


def broadcast(name, data, private_key,
              blockchain_client=BlockchainInfoClient(), testset=False):
    nulldata = build(name, data_hash=hex_hash160(data), testset=testset)
    response = embed_data_in_blockchain(
        nulldata, private_key, blockchain_client, format='hex')
    response.update({'data': nulldata})
    return response


def parse(bin_payload):
    name_len = ord(bin_payload[0:1])
    name = bin_payload[1:1+name_len]
    update = bin_payload[1+name_len:1+name_len+LENGTHS['update_hash']]
    return {
        'opcode': 'NAME_UPDATE',
        'name': bin_to_b40(name),
        'update': hexlify(update)
    }
