from utilitybelt import is_hex, change_charset, charset_to_hex, hex_to_charset
import re
import string
from binascii import hexlify, unhexlify

B16_CHARS = string.hexdigits[0:16]
B40_CHARS = string.digits + string.lowercase + '-_.+'
B40_REGEX = '^[a-z0-9\-_.+]*$'


def is_b40(s):
    return (isinstance(s, str) and re.match(B40_REGEX, s))


def b40_to_bin(s):
    if not is_b40(s):
        raise ValueError('s must only contain characters in the b40 char set')
    return unhexlify(charset_to_hex(s, B40_CHARS))


def bin_to_b40(s):
    if not isinstance(s, str):
        raise ValueError('s must be a string')
    return hex_to_charset(hexlify(s), B40_CHARS)


def b40_to_hex(s):
    return hexlify(b40_to_bin(s))
