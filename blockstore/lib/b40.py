#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstore

    Blockstore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore. If not, see <http://www.gnu.org/licenses/>.
"""

from utilitybelt import is_hex, change_charset, charset_to_hex, hex_to_charset
import re
import string
from binascii import hexlify, unhexlify

B16_CHARS = string.hexdigits[0:16]
B40_CHARS = string.digits + string.lowercase + '-_.+'
B40_REGEX = '^[a-z0-9\-_.+]*$'


def is_b40(s):
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
