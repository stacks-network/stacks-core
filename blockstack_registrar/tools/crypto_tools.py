# modified from example at https://gist.github.com/sekondus/4322469

from Crypto.Cipher import AES
import base64
import os

from binascii import hexlify, unhexlify

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

# generate a random secret key
#secret = os.urandom(BLOCK_SIZE)

#for saving, if needed
#print hexlify(secret)


def aes_encrypt(text, secret):
    # create a cipher object using the random secret
    cipher = AES.new(unhexlify(secret))

    # encode a string
    encoded = EncodeAES(cipher, text)
    return encoded


def aes_decrypt(text, secret):
    # create a cipher object using the random secret
    cipher = AES.new(unhexlify(secret))

    # decode the encoded string
    decoded = DecodeAES(cipher, text)
    return decoded
