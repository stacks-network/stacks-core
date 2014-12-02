from coinkit import bin_hash160, hex_hash160
from coinkit.transactions.utils import count_bytes
from utilitybelt import is_hex, is_valid_int
from binascii import hexlify, unhexlify

from .utils import gen_name_salt, hash_name, encode_name
from .b40 import b40_to_bin, b40_to_hex
from .configs import *

def add_magic_bytes(hex_script, testspace=False):
    if not testspace:
        magic_bytes = MAGIC_BYTES_MAINSPACE
    else:
        magic_bytes = MAGIC_BYTES_TESTSPACE
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
        elif is_valid_int(part):
            hex_script += '%0.2x' % int(part)
        else:
            raise Exception('Invalid script: contains invalid characters.')
    if len(hex_script) % 2 != 0:
        raise ValueError('Invalid script: must have an even number of chars.')
    return hex_script

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

def build_claim_name_script(name, salt, testspace=False):
    """ Takes in the name that was preordered, along with the salt used.
    """
    hex_name = b40_to_hex(name)
    print hex_name
    name_len = len(hex_name)/2
    print name_len
    if not is_hex(salt):
        salt = hexlify(salt)

    readable_script = 'NAME_CLAIM %i %s %s' % (name_len, hex_name, salt)
    hex_script = name_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script, testspace=testspace)

    return packaged_script

def build_update_name_script(name, data_hash=None, data=None, testspace=False):
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
    packaged_script = add_magic_bytes(hex_script, testspace=testspace)

    return packaged_script

def build_transfer_name_script(name, testspace=False):
    """ Takes in a name to transfer.
    """
    hex_name = b40_to_hex(name)
    name_len = len(hex_name)/2

    readable_script = 'NAME_TRANSFER %i %s' % (name_len, hex_name)
    hex_script = name_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script, testspace=testspace)

    return packaged_script

