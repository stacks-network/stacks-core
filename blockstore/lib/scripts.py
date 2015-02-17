from utilitybelt import is_hex, is_valid_int
from binascii import hexlify, unhexlify

from .config import *


def add_magic_bytes(hex_script, testset=False):
    if not testset:
        magic_bytes = MAGIC_BYTES_MAINSET
    else:
        magic_bytes = MAGIC_BYTES_TESTSET
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
            raise ValueError(
                'Invalid script, contains invalid characters: %s' % script)
    if len(hex_script) % 2 != 0:
        raise ValueError('Invalid script: must have an even number of chars.')
    return hex_script
