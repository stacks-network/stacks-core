# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack-client.

    Blockstack-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack-client. If not, see <http://www.gnu.org/licenses/>.
"""


import base64

import scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from binascii import hexlify, unhexlify

def aes_encrypt(payload, secret, **scrypt_params):
    """
    Encrypt payload with (hexlified) secret
    Return base64-encoded ciphertext
    """
    return base64.b64encode(scrypt.encrypt(payload, unhexlify(secret), **scrypt_params))


def aes_decrypt_legacy(payload, secret):
    """
    Legacy AES decryption (FROM INSECURE ENCRYPTION)!
    Return decrypted secret on success
    Return None on error
    """
    print "Falling back to legacy decryption"
    
    # DO NOT USE TO ENCRYPT
    # legacy hold-over for migrating to stronger encryption
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

    try:
        PADDING = '{'

        secret = ensure_length(secret)
        cipher = Cipher(algorithms.AES(unhexlify(secret)), modes.ECB(),
                        backend = default_backend())
        decryptor = cipher.decryptor()
        res = decryptor.update(base64.b64decode(payload)) + decryptor.finalize()
        res = res.rstrip(PADDING)
        return res
    except:
        return None


def aes_decrypt(payload, secret):
    """
    Decrypt a base64-encoded payload with a hex-encoded secret.
    Returns the plaintext on success
    Returns None on error
    """
    try:
        res = scrypt.decrypt(base64.b64decode(payload), unhexlify(secret))
        return res
    except scrypt.error:
        res = aes_decrypt_legacy(payload, secret)
        return res

