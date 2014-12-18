from utilitybelt import dev_urandom_entropy, is_hex
from binascii import hexlify, unhexlify
from coinkit import hex_hash160, bin_hash160
from coinkit.hash import bin_sha256

from .b40 import b40_to_bin
from .config import LENGTHS

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

def double_sha256(bin_s):
    return bin_sha256(bin_sha256(bin_s))

def hex_to_bytes_reversed(s):
    return unhexlify(s.encode('utf8'))[::-1]

def bytes_to_hex_reversed(s):
    return hexlify(s[::-1])

def hex_to_bin_hashes(hex_hashes):
    bin_hashes = []
    for h in hex_hashes:
        bin_hashes.append(hex_to_bytes_reversed(h))
    return bin_hashes

def calculate_consensus_hash128(consensus_hash):
    return hexlify(bin_hash160(consensus_hash, True)[0:16])
