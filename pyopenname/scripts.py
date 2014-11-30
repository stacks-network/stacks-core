from coinkit import bin_hash160, hex_hash160
from coinkit.transactions.utils import count_bytes
from utilitybelt import is_hex
from binascii import hexlify, unhexlify

from .utils import gen_name_preorder_salt, is_int
from .b40 import b40_to_bin
from .configs import *

def add_magic_bytes(hex_script, testnet=False):
    if testnet:
        magic_bytes = MAGIC_BYTES_TESTNET
    else:
        magic_bytes = MAGIC_BYTES_MAINNET
    return hexlify(magic_bytes) + hex_script

def name_script_to_hex(script):
    """ Parse the readable version of a name script, return the hex version.
    """
    hex_script = ''
    parts = script.split(' ')
    for part in parts:
        if part[0:5] == 'NAME_':
            try:
                hex_script += '%0.2x' % ord(eval(part))
            except:
                raise Exception('Invalid opcode: %s' % part)
        elif is_hex(part) and len(part) % 2 == 0:
            hex_script += part
        elif is_int(part):
            hex_script += '%0.2x' % int(part)
        else:
            raise Exception('Invalid script: contains invalid characters.')
    if len(hex_script) % 2 != 0:
        raise ValueError('Invalid script: must have an even number of chars.')
    return hex_script

def build_preorder_name_script(name, salt=None, testnet=False):
    """ Takes in an ascii string as a name and an optional salt.
    """
    if not salt:
        salt = gen_name_preorder_salt()
    elif not (isinstance(salt) and len(salt) == LENGTHS['salt']):
        raise ValueError('Invalid salt')
    
    encoded_name = b40_to_bin(name)
    salted_name = encoded_name + salt
    concealed_name = hex_hash160(salted_name)

    script = 'NAME_PREORDER %s' % concealed_name
    hex_script = name_script_to_hex(script)
    packaged_script = add_magic_bytes(hex_script, testnet=testnet)

    return packaged_script, salt

def encode_name(name):
    encoded_name = hexlify(b40_to_bin(name))
    name_len = str(len(encoded_name))
    return encoded_name, name_len

def build_claim_name_script(name, salt, testnet=False):
    """ Takes in the name that was preordered, along with the salt used.
    """
    encoded_name, name_len = encode_name(name)
    if not is_hex(salt):
        salt = hexlify(salt)

    readable_script = 'NAME_CLAIM %s %s %s' % (name_len, encoded_name, salt)
    hex_script = name_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script, testnet=testnet)

    return packaged_script

def build_update_name_script(name, data_hash=None, data=None, testnet=False):
    """ Takes in the name to update the data for and the data update itself.
    """
    encoded_name, name_len = encode_name(name)

    if not data_hash:
        if not data:
            raise ValueError('A data hash or data string is required.')
        data_hash = hex_hash160(data)
    elif not (is_hex(data_hash) and len(data_hash) == 40):
        raise ValueError('Data hash must be a 20 byte hex string.')

    readable_script = 'NAME_UPDATE %s %s %s' % (name_len, encoded_name, data_hash)
    hex_script = name_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script, testnet=testnet)

    return packaged_script

def build_transfer_name_script(name, testnet=False):
    """ Takes in a name to transfer.
    """
    encoded_name, name_len = encode_name(name)

    readable_script = 'NAME_TRANSFER %s %s' % (name_len, encoded_name)
    hex_script = name_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script, testnet=testnet)

    return packaged_script

