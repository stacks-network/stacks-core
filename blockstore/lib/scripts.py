from utilitybelt import is_hex, is_valid_int
from binascii import hexlify, unhexlify
from coinkit import BitcoinPrivateKey, script_to_hex
 
from .config import *


def add_magic_bytes(hex_script, testset=False):
    if not testset:
        magic_bytes = MAGIC_BYTES_MAINSET
    else:
        magic_bytes = MAGIC_BYTES_TESTSET
    return hexlify(magic_bytes) + hex_script


def blockstore_script_to_hex(script):
    """ Parse the readable version of a script, return the hex version.
    """
    hex_script = ''
    parts = script.split(' ')
    for part in parts:
        if part.startswith("NAME_") or part.startswith("DATA_") or part.startswith("NAMESPACE_"):
            try:
                hex_script += '%0.2x' % ord(eval(part))
            except:
                raise Exception('Invalid opcode: %s' % part)
        elif is_hex(part) and len(part) % 2 == 0:
            hex_script += part
        elif is_valid_int(part):
            hex_script += '%0.2x' % int(part)
        else:
            raise ValueError('Invalid script (at %s), contains invalid characters: %s' % (part, script))
         
    if len(hex_script) % 2 != 0:
        raise ValueError('Invalid script: must have an even number of chars.')
     
    return hex_script


def name_script_to_hex(script):
    """ Parse the readable version of a name script, return the hex version.
    """
    return blockstore_script_to_hex( "NAME_", script )


def data_script_to_hex(script):
    """ Parse the readable version of a data script, return the hex version.
    """
    return blockstore_script_to_hex( "DATA_", script )

# generate a pay-to-pubkeyhash script from a private key.
def get_script_pubkey( private_key ):
   hash160 = BitcoinPrivateKey(private_key).public_key(compressed=True).hash160()
   script_pubkey = script_to_hex( 'OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG' % hash160)
   print "script_pubkey of %s is %s" % (private_key, script_pubkey)
   return  script_pubkey
