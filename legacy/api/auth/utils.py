from binascii import hexlify
from utilitybelt import dev_urandom_entropy


def generate_app_id():
    return hexlify(dev_urandom_entropy(16))


def generate_app_secret():
    return hexlify(dev_urandom_entropy(32))
