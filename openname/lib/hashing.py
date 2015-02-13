from utilitybelt import dev_urandom_entropy, is_hex
from binascii import hexlify, unhexlify
from coinkit import hex_hash160, bin_hash160
from coinkit.hash import bin_sha256

from .b40 import b40_to_bin
from .config import LENGTHS


def hash_name(name, script_pubkey):
    bin_name = b40_to_bin(name)
    name_and_pubkey = bin_name + unhexlify(script_pubkey)
    return hex_hash160(name_and_pubkey)


def calculate_consensus_hash128(consensus_hash):
    return hexlify(bin_hash160(consensus_hash, True)[0:16])

from coinkit import bin_double_sha256, hex_to_bin_reversed, bin_to_hex_reversed
