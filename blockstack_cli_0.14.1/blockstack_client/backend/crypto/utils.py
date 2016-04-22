# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
"""

import os
import base64

from Crypto.Cipher import AES
from pybitcoin import BitcoinPrivateKey, BitcoinPublicKey
from binascii import hexlify, unhexlify

# modified from example at https://gist.github.com/sekondus/4322469
# the block size for the cipher object; must be 16, 24, or 32 for AES
BLOCK_SIZE = 32

# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
PADDING = '{'

# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

# one-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)


def ensure_length(secret):
    if len(secret) > 32:
        secret = secret[:32]

    elif len(secret) < 24:
        length = 24 - (len(secret) % 24)
        secret += chr(length)*length
    elif len(secret) > 24 and len(secret) < 32:
        length = 32 - (len(secret) % 32)
        secret += chr(length)*length

    return hexlify(secret)


def get_new_secret():
    secret = os.urandom(BLOCK_SIZE)
    return hexlify(secret)


def aes_encrypt(payload, secret):

    secret = ensure_length(secret)

    cipher = AES.new(unhexlify(secret))
    return EncodeAES(cipher, payload)


def aes_decrypt(payload, secret):
    secret = ensure_length(secret)

    cipher = AES.new(unhexlify(secret))
    return DecodeAES(cipher, payload)


def get_addresses_from_privkey(hex_privkey):
    """ get both bitcoin and namecoin addresses
    """

    btc_privkey = BitcoinPrivateKey(hex_privkey)
    btc_pubkey = btc_privkey.public_key()
    btc_address = btc_pubkey.address()

    return btc_address


def get_address_from_pubkey(hex_pubkey):
    """ get bitcoin address from pub key
    """

    pubkey = BitcoinPublicKey(hex_pubkey)

    return pubkey.address()


def get_address_from_privkey(hex_privkey):
    """ get bitcoin address from private key
    """

    privkey = BitcoinPrivateKey(hex_privkey)

    pubkey = privkey.public_key()
    return pubkey.address()


def get_pubkey_from_privkey(hex_privkey):
    """ get bitcoin address from private key
    """

    privkey = BitcoinPrivateKey(hex_privkey)

    pubkey = privkey.public_key()
    return pubkey.to_hex()
