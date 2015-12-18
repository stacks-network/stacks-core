# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~

    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

This file is part of Registrar.

    Registrar is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Registrar is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Registrar. If not, see <http://www.gnu.org/licenses/>.
"""

import re
import os
import random
import struct
import hashlib
import binascii
import scrypt
from hashlib import sha256
from pybitcoin import BitcoinKeypair, b58check_encode, b58check_decode
from Crypto.Cipher import AES


def bip38_encrypt(private_key, passphrase, n=16384, r=8, p=8, compressed=False):
    # determine the flagbyte
    if compressed:
        flagbyte = '\xe0'
    else:
        flagbyte = '\xc0'
    # get the private key's address and equivalent in hex format and wif format
    k = BitcoinKeypair(private_key)
    address = k.address()
    hex_private_key = k.private_key()
    wif_private_key = k.wif_pk()
    # calculate the address's checksum
    address_checksum = sha256(sha256(address).digest()).digest()[0:4]
    # calculate the scrypt hash and split it in half
    scrypt_derived_key = scrypt.hash(passphrase, address_checksum, n, r, p)
    derived_half_1 = scrypt_derived_key[0:32]
    derived_half_2 = scrypt_derived_key[32:64]
    # combine parts of the private key and scrypt hash and AES encrypt them
    aes = AES.new(derived_half_2)
    encrypted_half_1 = aes.encrypt(
        binascii.unhexlify(
            '%0.32x' % (long(hex_private_key[0:32], 16) ^ long(binascii.hexlify(derived_half_1[0:16]), 16))
        )
    )
    encrypted_half_2 = aes.encrypt(
        binascii.unhexlify(
            '%0.32x' % (long(hex_private_key[32:64], 16) ^ long(binascii.hexlify(derived_half_1[16:32]), 16))
        )
    )
    # build the encrypted private key from the checksum and encrypted parts
    encrypted_private_key = ('\x42' + flagbyte + address_checksum + encrypted_half_1 + encrypted_half_2)
    # base 58 encode the encrypted private key
    b58check_encrypted_private_key = b58check_encode(encrypted_private_key, version_byte=1)
    # return the encrypted private key
    return b58check_encrypted_private_key


def bip38_decrypt(b58check_encrypted_private_key, passphrase, n=16384, r=8, p=8):
    # decode private key from base 58 check to binary
    encrypted_private_key = b58check_decode(b58check_encrypted_private_key)
    # parse the encrypted key different byte sections
    bip38_key_identification_byte = encrypted_private_key[0:1]
    flagbyte = encrypted_private_key[1:2]
    address_checksum = encrypted_private_key[2:6]
    encrypted_half_1 = encrypted_private_key[6:6+16]
    encrypted_half_2 = encrypted_private_key[6+16:6+32]
    # derive a unique key from the passphrase and the address checksum
    scrypt_derived_key = scrypt.hash(passphrase, address_checksum, n, r, p)
    derived_half_1 = scrypt_derived_key[0:32]
    derived_half_2 = scrypt_derived_key[32:64]
    # decrypt the encrypted halves
    aes = AES.new(derived_half_2)
    decrypted_half_1 = aes.decrypt(encrypted_half_1)
    decrypted_half_2 = aes.decrypt(encrypted_half_2)
    # get the original private key from the encrypted halves + the derived half
    decrypted_private_key = '%064x' % (long(binascii.hexlify(decrypted_half_1 + decrypted_half_2), 16) ^ long(binascii.hexlify(derived_half_1), 16))
    # get the address corresponding to the private key
    k = BitcoinKeypair(decrypted_private_key)
    address = k.address()
    # make sure the address matches the checksum in the original encrypted key
    if address_checksum != sha256(sha256(address).digest()).digest()[0:4]:
        raise ValueError('Invalid private key and password combo.')
    # return the decrypted private key
    return k.private_key()
