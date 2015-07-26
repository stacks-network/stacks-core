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
 
 
def hash256_trunc128( data ):
   """
   Hash a string of data by taking its 256-bit sha256 and truncating it to 128 bits.
   """
   return hexlify( bin_sha256( data )[0:16] )
   
   
def get_owner_hash( owner_name, owner_script_pubkey ):
   """
   Generate an owner hash for a piece of data from the owner's username and script_pubkey
   """
   return hash256_trunc128( owner_name + owner_script_pubkey )

from coinkit import bin_double_sha256, hex_to_bin_reversed, bin_to_hex_reversed
