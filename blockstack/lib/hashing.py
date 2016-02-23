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

from utilitybelt import dev_urandom_entropy, is_hex
from binascii import hexlify, unhexlify
from pybitcoin.hash import hex_hash160, bin_hash160, bin_sha256, bin_double_sha256, hex_to_bin_reversed, bin_to_hex_reversed

from .b40 import b40_to_bin
from .config import LENGTHS


def hash_name(name, script_pubkey, register_addr=None):
   """
   Generate the hash over a name and hex-string script pubkey
   """
   bin_name = b40_to_bin(name)
   name_and_pubkey = bin_name + unhexlify(script_pubkey)
   
   if register_addr is not None:
       name_and_pubkey += str(register_addr)
       
   return hex_hash160(name_and_pubkey)


def hash256_trunc128( data ):
   """
   Hash a string of data by taking its 256-bit sha256 and truncating it to 128 bits.
   """
   return hexlify( bin_sha256( data )[0:16] )
   