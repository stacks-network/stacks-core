#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack

    Blockstack is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
"""

import re
import string
import virtualchain
from binascii import hexlify, unhexlify

B16_CHARS = string.hexdigits[0:16]
B40_CHARS = string.digits + string.lowercase + '-_.+'
B40_REGEX = '^[a-z0-9\-_.+]*$'

B16_CHARS = string.hexdigits[0:16]
B16_REGEX = '^[0-9a-f]*$'

def int_to_charset(val, charset):
    """ Turn a non-negative integer into a string.

    >>> int_to_charset(0, B40_CHARS)
    '0'
    >>> int_to_charset(658093, B40_CHARS)
    'abcd'
    >>> int_to_charset(40, B40_CHARS)
    '10'
    >>> int_to_charset(149190078205533, B40_CHARS)
    'muneeb.id'
    >>> int_to_charset(-1, B40_CHARS)
    Traceback (most recent call last):
        ...
    ValueError: "val" must be a non-negative integer.
    """
    if val < 0:
        raise ValueError('"val" must be a non-negative integer.')

    if val == 0:
        return charset[0]

    output = ""
    while val > 0:
        val, digit = divmod(val, len(charset))
        output += charset[digit]

    # reverse the characters in the output and return
    return output[::-1]


def charset_to_int(s, charset):
    """ Turn a string into a non-negative integer.

    >>> charset_to_int('0', B40_CHARS)
    0
    >>> charset_to_int('10', B40_CHARS)
    40
    >>> charset_to_int('abcd', B40_CHARS)
    658093
    >>> charset_to_int('', B40_CHARS)
    0
    >>> charset_to_int('muneeb.id', B40_CHARS)
    149190078205533
    >>> charset_to_int('A', B40_CHARS)
    Traceback (most recent call last):
        ...
    ValueError: substring not found
    """
    output = 0
    for char in s:
        output = output * len(charset) + charset.index(char)

    return output


def change_charset(s, original_charset, target_charset):
    """ Convert a string from one charset to another.
    """
    if not isinstance(s, str):
        raise ValueError('"s" must be a string.')

    intermediate_integer = charset_to_int(s, original_charset)
    output_string = int_to_charset(intermediate_integer, target_charset)
    return output_string


def hexpad(x):
    """
    >>> hexpad('123')
    '0123'
    >>> hexpad('1234')
    '1234'
    """
    return ('0' * (len(x) % 2)) + x


def charset_to_hex(s, original_charset):
    return hexpad(change_charset(s, original_charset, B16_CHARS))


def hex_to_charset(s, destination_charset):
    if not virtualchain.lib.hashing.is_hex(s):
        raise ValueError("Value must be in hex format")

    s = s.lower()
    return change_charset(s, B16_CHARS, destination_charset)


def is_b40(s):
    """
    >>> is_b40('abcd')
    True
    >>> is_b40(u'abcd')
    False
    >>> is_b40(None)
    False
    >>> is_b40(123)
    False
    >>> is_b40('1234567890')
    True
    >>> is_b40('abcd.efgh+-_')
    True
    >>> is_b40('')
    True
    """
    return (isinstance(s, str) and (re.match(B40_REGEX, s) is not None))


def b40_to_bin(s):
    if not is_b40(s):
        raise ValueError('%s must only contain characters in the b40 char set' % s)
    return unhexlify(charset_to_hex(s, B40_CHARS))


def bin_to_b40(s):
    if not isinstance(s, str):
        raise ValueError('%s must be a string' % s)
    return hex_to_charset(hexlify(s), B40_CHARS)


def b40_to_hex(s):
    return hexlify(b40_to_bin(s))


if __name__ == '__main__':
    import doctest
    doctest.testmod()

