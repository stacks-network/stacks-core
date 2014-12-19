from utilitybelt import is_hex, is_valid_int
from binascii import hexlify, unhexlify

from .config import *

def add_magic_bytes(hex_script, testspace=False):
    return hexlify(MAGIC_BYTES) + hex_script

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
