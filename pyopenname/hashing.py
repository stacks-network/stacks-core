from utilitybelt import dev_urandom_entropy, is_hex
from binascii import hexlify, unhexlify
from coinkit import hex_hash160

from .b40 import b40_to_bin
from .configs import LENGTHS

def gen_name_salt(hex_format=False):
    bin_salt = dev_urandom_entropy(LENGTHS['salt'])
    return bin_salt

def is_hex_salt(s):
    if is_hex(s) and len(unhexlify(s)) == LENGTHS['salt']:
        return True
    return False

def hash_name(name, salt, hex_format=True):
    if hex_format and not is_hex_salt(salt):
        raise ValueError('Salt must be a %i byte hex string' % LENGTHS['salt'])
    bin_name = b40_to_bin(name)
    salted_name = bin_name + unhexlify(salt)
    return hex_hash160(salted_name)
