#!/usr/bin/env python
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

import virtualchain
from binascii import hexlify
import collections
import json
import traceback

import keylib
from keylib import ECPrivateKey, ECPublicKey
from keylib.hashing import bin_hash160
from keylib.address_formatting import bin_hash160_to_address
from keylib.key_formatting import compress, decompress
from keylib.public_key_encoding import PubkeyType

from .backend.crypto.utils import aes_encrypt, aes_decrypt

from keychain import PrivateKeychain

import fastecdsa
import fastecdsa.curve
import fastecdsa.keys
import fastecdsa.ecdsa
from fastecdsa import _ecdsa
from fastecdsa.util import RFC6979
import hmac
from struct import pack
import hashlib
import base64
import pybitcoin
import bitcoin
import binascii
import jsonschema
from jsonschema.exceptions import ValidationError
from utilitybelt import is_hex

from .config import get_logger
from .constants import CONFIG_PATH, BLOCKSTACK_DEBUG, BLOCKSTACK_TEST

log = get_logger()

# deriving hardened keys is expensive, so cache them once derived.
# maps hex_privkey:chaincode --> {key_index: child_key}
KEY_CACHE = {}
KEYCHAIN_CACHE = {}

class HDWallet(object):
    """
    Initialize a hierarchical deterministic wallet with
    hex_privkey and get child addresses and private keys
    """

    def __init__(self, hex_privkey=None, chaincode='\x00' * 32, config_path=CONFIG_PATH):
        """
        If @hex_privkey is given, use that to derive keychain
        otherwise, use a new random seed

        TODO: load chain state from config path
        """
        global KEYCHAIN_CACHE

        assert hex_privkey
        assert len(chaincode) == 32

        self.hex_privkey = hex_privkey
        self.priv_keychain = None
        self.master_address = None
        self.child_addresses = None

        self.keychain_key = str(self.hex_privkey) + ":" + str(chaincode.encode('hex'))

        if KEYCHAIN_CACHE.has_key(self.keychain_key):
            if BLOCKSTACK_TEST:
                log.debug("{} keychain is cached".format(self.keychain_key))
            
            self.priv_keychain = KEYCHAIN_CACHE[self.keychain_key]

        else:
            if BLOCKSTACK_TEST:
                log.debug("{} keychain is NOT cached".format(self.keychain_key))

            self.priv_keychain = self.get_priv_keychain(self.hex_privkey, chaincode)
            KEYCHAIN_CACHE[self.keychain_key] = self.priv_keychain

        self.master_address = self.get_master_address()


    def get_priv_keychain(self, hex_privkey, chaincode):
        if hex_privkey:
            return PrivateKeychain.from_private_key(hex_privkey, chain_path=chaincode)

        log.debug('No privatekey given, starting new wallet')
        return PrivateKeychain()


    def get_master_privkey(self):
        return self.priv_keychain.private_key()


    def get_child_privkey(self, index=0):
        """
        Get a hardened child private key
        @index is the child index

        Returns:
        child privkey for given @index
        """
        global KEY_CACHE
        if KEY_CACHE.has_key(self.keychain_key) and KEY_CACHE[self.keychain_key].has_key(index):
            if BLOCKSTACK_TEST:
                log.debug("Child {} of {} is cached".format(index, self.keychain_key))

            return KEY_CACHE[self.keychain_key][index]

        # expensive...
        child = self.priv_keychain.hardened_child(index)

        if not KEY_CACHE.has_key(self.keychain_key):
            KEY_CACHE[self.keychain_key] = {}

        KEY_CACHE[self.keychain_key][index] = child.private_key()

        return child.private_key()


    def get_master_address(self):
        if self.master_address is not None:
            return self.master_address

        hex_privkey = self.get_master_privkey()
        hex_pubkey = get_pubkey_hex(hex_privkey)
        return keylib.public_key_to_address(hex_pubkey)


    def get_child_address(self, index=0):
        """
        @index is the child index

        Returns:
        child address for given @index
        """

        if self.child_addresses is not None:
            return self.child_addresses[index]

        hex_privkey = self.get_child_privkey(index)
        hex_pubkey = get_pubkey_hex(hex_privkey)
        return keylib.public_key_to_address(hex_pubkey)


    def get_child_keypairs(self, count=1, offset=0, include_privkey=False):
        """
        Returns (privkey, address) keypairs

        Returns:
        returns child keypairs

        @include_privkey: toggles between option to return
        privkeys along with addresses or not
        """

        keypairs = []

        for index in range(offset, offset + count):
            address = self.get_child_address(index)

            if include_privkey:
                hex_privkey = self.get_child_privkey(index)
                keypairs.append((address, hex_privkey))
            else:
                keypairs.append(address)

        return keypairs


    def get_privkey_from_address(self, target_address, count=1):
        """
        Given a child address, return priv key of that address
        """

        addresses = self.get_child_keypairs(count=count)

        for i, address in enumerate(addresses):
            if address == target_address:
                return self.get_child_privkey(i)

        return None


class RFC6979_blockstack(RFC6979):
    """
    Generate RFC6979 nonces from a file
    """
    def __init__(self, x, q, hashfunc):
        RFC6979.__init__(self, '', x, q, hashfunc)


    def gen_nonce_from_digest( self, h1 ):
        """
        Make the nonce from the digest.
        @h1: bin-encoded digest
        @hash_size: size of the digest
        """
        hash_size = self.hashfunc().digest_size
        key_and_msg = self._int2octets(self.x) + self._bits2octets(h1)

        v = b''.join([b'\x01' for _ in range(hash_size)])
        k = b''.join([b'\x00' for _ in range(hash_size)])

        k = hmac.new(k, v + b'\x00' + key_and_msg, self.hashfunc).digest()
        v = hmac.new(k, v, self.hashfunc).digest()
        k = hmac.new(k, v + b'\x01' + key_and_msg, self.hashfunc).digest()
        v = hmac.new(k, v, self.hashfunc).digest()

        while True:
            t = b''

            while len(t) * 8 < self.qlen:
                v = hmac.new(k, v, self.hashfunc).digest()
                t = t + v

            nonce = self._bits2int(t)
            if nonce >= 1 and nonce < self.q:
                return nonce

            k = hmac.new(k, v + b'\x00', self.hashfunc).digest()
            v = hmac.new(k, v, self.hashfunc).digest()


    def gen_nonce_from_file(self, fd, fd_len=None):
        ''' http://tools.ietf.org/html/rfc6979#section-3.2 '''
        # based on gen_nonce()
        
        h1 = self.hashfunc()

        count = 0
        while True:
            buf = f.read(65536)
            if len(buf) == 0:
                break

            if fd_len is not None:
                if count + len(buf) > fd_len:
                    buf = buf[:fd_len - count]

            h.update(buf)
            count += len(buf)

        h1 = h1.digest()

        return self.gen_nonce_from_digest(h1)


def is_multisig(privkey_info):
    """
    Does the given private key info represent
    a multisig bundle?
    """
    from .schemas import PRIVKEY_MULTISIG_SCHEMA
    try:
        jsonschema.validate(privkey_info, PRIVKEY_MULTISIG_SCHEMA)
        return True
    except ValidationError as e:
        return False


def is_encrypted_multisig(privkey_info):
    """
    Does a given encrypted private key info
    represent an encrypted multisig bundle?
    """
    from .schemas import ENCRYPTED_PRIVKEY_MULTISIG_SCHEMA
    try:
        jsonschema.validate(privkey_info, ENCRYPTED_PRIVKEY_MULTISIG_SCHEMA)
        return True
    except ValidationError as e:
        return False


def is_singlesig(privkey_info):
    """
    Does the given private key info represent
    a single signature bundle? (i.e. one private key)?
    """
    from .schemas import PRIVKEY_SINGLESIG_SCHEMA
    try:
        jsonschema.validate(privkey_info, PRIVKEY_SINGLESIG_SCHEMA)
        return True
    except ValidationError as e:
        return False


def is_singlesig_hex(privkey_info):
    """
    Does the given private key info represent
    a single signature bundle? (i.e. one private key)?
    """
    from .schemas import PRIVKEY_SINGLESIG_SCHEMA_HEX
    try:
        jsonschema.validate(privkey_info, PRIVKEY_SINGLESIG_SCHEMA_HEX)
        return True
    except ValidationError as e:
        return False


def is_encrypted_singlesig(privkey_info):
    """
    Does the given string represent an encrypted
    single private key?
    """
    from .schemas import ENCRYPTED_PRIVKEY_SINGLESIG_SCHEMA
    try:
        jsonschema.validate(privkey_info, ENCRYPTED_PRIVKEY_SINGLESIG_SCHEMA)
        return True
    except ValidationError as e:
        return False


def singlesig_privkey_to_string(privkey_info):
    """
    Convert private key to string
    """
    return ECPrivateKey(privkey_info).to_hex()


def multisig_privkey_to_string(privkey_info):
    """
    Convert multisig keys to string
    """
    return ','.join([singlesig_privkey_to_string(pk) for pk in privkey_info['private_keys']])


def privkey_to_string(privkey_info):
    """
    Convert private key to string
    Return None on invalid
    """
    if is_singlesig(privkey_info):
        return singlesig_privkey_to_string(privkey_info)

    if is_multisig(privkey_info):
        return multisig_privkey_to_string(privkey_info)

    return None


def encrypt_multisig_info(multisig_info, password):
    """
    Given a multisig info dict,
    encrypt the sensitive fields.

    Returns {'encrypted_private_keys': ..., 'encrypted_redeem_script': ..., **other_fields}
    """
    enc_info = {
        'encrypted_private_keys': None,
        'encrypted_redeem_script': None
    }

    hex_password = hexlify(password)

    assert is_multisig(multisig_info), 'Invalid multisig keys'

    enc_info['encrypted_private_keys'] = []
    for pk in multisig_info['private_keys']:
        pk_ciphertext = aes_encrypt(pk, hex_password)
        enc_info['encrypted_private_keys'].append(pk_ciphertext)

    enc_info['encrypted_redeem_script'] = aes_encrypt(
        multisig_info['redeem_script'], hex_password
    )

    # preserve any other fields
    for k, v in multisig_info.items():
        if k not in ['private_keys', 'redeem_script']:
            enc_info[k] = v

    return enc_info


def decrypt_multisig_info(enc_multisig_info, password):
    """
    Given an encrypted multisig info dict,
    decrypt the sensitive fields.

    Returns {'private_keys': ..., 'redeem_script': ..., **other_fields}
    Return {'error': ...} on error
    """
    multisig_info = {
        'private_keys': None,
        'redeem_script': None,
    }

    hex_password = hexlify(password)

    assert is_encrypted_multisig(enc_multisig_info), 'Invalid encrypted multisig keys'

    multisig_info['private_keys'] = []
    for enc_pk in enc_multisig_info['encrypted_private_keys']:
        pk = None
        try:
            pk = aes_decrypt(enc_pk, hex_password)
            virtualchain.BitcoinPrivateKey(pk)
        except Exception as e:
            if BLOCKSTACK_TEST:
                log.exception(e)

            return {'error': 'Invalid password; failed to decrypt private key in multisig wallet'}

        multisig_info['private_keys'].append(ECPrivateKey(pk).to_hex())

    redeem_script = None
    enc_redeem_script = enc_multisig_info['encrypted_redeem_script']
    try:
        redeem_script = aes_decrypt(enc_redeem_script, hex_password)
    except Exception as e:
        if BLOCKSTACK_TEST:
            log.exception(e)

        return {'error': 'Invalid password; failed to decrypt redeem script in multisig wallet'}

    multisig_info['redeem_script'] = redeem_script

    # preserve any other information in the multisig info
    for k, v in enc_multisig_info.items():
        if k not in ['encrypted_private_keys', 'encrypted_redeem_script']:
            multisig_info[k] = v

    return multisig_info


def encrypt_private_key_info(privkey_info, password):
    """
    Encrypt private key info.
    Return {'status': True, 'encrypted_private_key_info': {'address': ..., 'private_key_info': ...}} on success
    Returns {'error': ...} on error
    """

    hex_password = hexlify(password)

    ret = {}
    if is_multisig(privkey_info):
        ret['address'] = virtualchain.make_multisig_address(
            privkey_info['redeem_script']
        )
        ret['private_key_info'] = encrypt_multisig_info(
            privkey_info, password
        )

        return {'status': True, 'encrypted_private_key_info': ret}

    if is_singlesig(privkey_info):
        ret['address'] = virtualchain.BitcoinPrivateKey(
            privkey_info).public_key().address()
        ret['private_key_info'] = aes_encrypt(privkey_info, hex_password)

        return {'status': True, 'encrypted_private_key_info': ret}

    return {'error': 'Invalid private key info'}


def decrypt_private_key_info(privkey_info, password):
    """
    Decrypt a particular private key info bundle.
    It can be either a single-signature private key, or a multisig key bundle.
    Return {'address': ..., 'private_key_info': ...} on success.
    Return {'error': ...} on error.
    """
    hex_password = hexlify(password)

    ret = {}
    if is_encrypted_multisig(privkey_info):
        ret = decrypt_multisig_info(privkey_info, password)

        if 'error' in ret:
            return {'error': 'Failed to decrypt multisig wallet: {}'.format(ret['error'])}

        # sanity check
        if 'redeem_script' not in ret:
            return {'error': 'Invalid multisig wallet: missing redeem_script'}

        if 'private_keys' not in ret:
            return {'error': 'Invalid multisig wallet: missing private_keys'}

        return {'address': virtualchain.make_p2sh_address(ret['redeem_script']), 'private_key_info': ret}

    if is_encrypted_singlesig(privkey_info):
        try:
            pk = aes_decrypt(privkey_info, hex_password)
            pk = ECPrivateKey(pk).to_hex()
        except Exception as e:
            if BLOCKSTACK_TEST:
                log.exception(e)

            return {'error': 'Invalid password'}

        return {'address': virtualchain.BitcoinPrivateKey(pk).public_key().address(), 'private_key_info': pk}

    return {'error': 'Invalid encrypted private key info'}


def make_wallet_keys(data_privkey=None, owner_privkey=None, payment_privkey=None):
    """
    For testing.  DO NOT USE
    """

    ret = {
        'owner_privkey': None,
        'data_privkey': None,
        'payment_privkey': None,
    }

    if data_privkey is not None:
        if not is_singlesig(data_privkey):
            raise ValueError('Invalid data key info')

        pk_data = virtualchain.BitcoinPrivateKey(data_privkey).to_hex()
        ret['data_privkey'] = pk_data

    if owner_privkey is not None:
        if is_multisig(owner_privkey):
            pks = [virtualchain.BitcoinPrivateKey(pk).to_hex() for pk in owner_privkey['private_keys']]
            m, pubs = virtualchain.parse_multisig_redeemscript(owner_privkey['redeem_script'])
            ret['owner_privkey'] = virtualchain.make_multisig_info(m, pks)
            ret['owner_addresses'] = [ret['owner_privkey']['address']]

        elif is_singlesig(owner_privkey):
            pk_owner = virtualchain.BitcoinPrivateKey(owner_privkey).to_hex()
            ret['owner_privkey'] = pk_owner
            ret['owner_addresses'] = [virtualchain.BitcoinPrivateKey(pk_owner).public_key().address()]

        else:
            raise ValueError('Invalid owner key info')

    if payment_privkey is None:
        return ret

    if is_multisig(payment_privkey):
        pks = [virtualchain.BitcoinPrivateKey(pk).to_hex() for pk in payment_privkey['private_keys']]
        m, pubs = virtualchain.parse_multisig_redeemscript(payment_privkey['redeem_script'])
        ret['payment_privkey'] = virtualchain.make_multisig_info(m, pks)
        ret['payment_addresses'] = [ret['payment_privkey']['address']]

    elif is_singlesig(payment_privkey):
        pk_payment = virtualchain.BitcoinPrivateKey(payment_privkey).to_hex()
        ret['payment_privkey'] = pk_payment
        ret['payment_addresses'] = [virtualchain.BitcoinPrivateKey(pk_payment).public_key().address()]

    else:
        raise ValueError('Invalid payment key info')

    ret['data_pubkey'] = ECPrivateKey(ret['data_privkey']).public_key().to_hex()
    ret['data_pubkeys'] = [ret['data_pubkey']]

    return ret


def get_data_privkey(user_zonefile, wallet_keys=None, config_path=CONFIG_PATH):
    """
    Get the data private key that matches this zonefile.
    * If the zonefile has a public key that this wallet does not have, then there is no data key.
    * If the zonefile does not have a public key, then:
      * if the data private key in the wallet matches the owner private key, then the wallet data key is the data key to use.
      (this is for legacy compatibility with onename.com, which does not create data keys for users)
      * otherwise, there is no data key

    Return the private key on success
    Return {'error': ...} if we could not find the key
    """
    from .wallet import get_wallet
    from .user import user_zonefile_data_pubkey

    zonefile_data_pubkey = None

    try:
        # NOTE: uncompressed...
        zonefile_data_pubkey = user_zonefile_data_pubkey(user_zonefile)
    except ValueError:
        log.error('Multiple pubkeys defined in zone file')
        return {'error': 'Multiple data public keys in zonefile'}

    wallet_keys = {} if wallet_keys is None else wallet_keys
    if wallet_keys.get('data_privkey', None) is None:
        log.error('No data private key set')
        return {'error': 'No data private key in wallet keys'}

    wallet = get_wallet(config_path=CONFIG_PATH) if wallet_keys is None else wallet_keys
    assert wallet, 'Failed to get wallet'

    if not wallet.has_key('data_privkey'):
        log.error("No data private key in wallet")
        return {'error': 'No data private key in wallet'}

    data_privkey = wallet['data_privkey']

    # NOTE: uncompresssed
    wallet_data_pubkey = get_pubkey_hex(str(data_privkey))

    if zonefile_data_pubkey is None and wallet_data_pubkey is not None:
        # zone file does not have a data key set.
        # the wallet data key *must* match the owner key
        owner_privkey_info = wallet['owner_privkey']
        owner_privkey = None
        if is_singlesig(owner_privkey_info):
            owner_privkey = owner_privkey_info
        elif is_multisig(owner_privkey_info):
            owner_privkey = owner_privkey_info['private_keys'][0]

        owner_pubkey = get_pubkey_hex(str(owner_privkey))
        if owner_pubkey != wallet_data_pubkey:
            # doesn't match. no data key 
            return {'error': 'No zone file key, and data key does not match owner key'}
        
    return str(data_privkey)


def get_data_privkey_info(user_zonefile, wallet_keys=None, config_path=CONFIG_PATH):
    """
    Get the user's data private key info
    """

    privkey = get_data_privkey(user_zonefile, wallet_keys=wallet_keys, config_path=config_path)
    return privkey


def get_owner_privkey_info(wallet_keys=None, config_path=CONFIG_PATH):
    """
    Get the user's owner private key info
    """
    from .wallet import get_wallet

    wallet = get_wallet(config_path=CONFIG_PATH) if wallet_keys is None else wallet_keys
    assert wallet is not None, 'Failed to get wallet'

    owner_privkey_info = wallet.get('owner_privkey', None)
    assert owner_privkey_info is not None, 'No owner private key set'

    return owner_privkey_info


def get_payment_privkey_info(wallet_keys=None, config_path=CONFIG_PATH):
    """
    Get the user's payment private key info
    """
    from .wallet import get_wallet

    wallet = get_wallet(config_path=CONFIG_PATH) if wallet_keys is None else wallet_keys
    assert wallet is not None, 'Failed to get wallet'

    payment_privkey_info = wallet.get('payment_privkey', None)
    assert payment_privkey_info is not None, 'No payment private key set'

    return payment_privkey_info


def get_privkey_info_address(privkey_info):
    """
    Get the address of private key information:
    * if it's a single private key, then calculate the address.
    * if it's a multisig info dict, then get the p2sh address
    """
    if privkey_info is None:
        return

    if is_singlesig(privkey_info):
        return virtualchain.BitcoinPrivateKey(privkey_info).public_key().address()

    if is_multisig(privkey_info):
        return virtualchain.make_multisig_address(privkey_info['redeem_script'])

    raise ValueError('Invalid private key info')


def get_privkey_info_params(privkey_info, config_path=CONFIG_PATH):
    """
    Get the parameters that characterize a private key
    info bundle:  the number of private keys, and the
    number of signatures required to make a valid
    transaction.
    * for single private keys, this is (1, 1)
    * for multisig info dicts, this is (m, n)

    Return (m, n) on success
    Return (None, None) on failure
    """

    if privkey_info is None:
        from .backend.blockchain import get_block_height

        key_config = (2, 3)
        log.warning('No private key info given, assuming {} key config'.format(key_config))
        return key_config

    if is_singlesig( privkey_info ):
        return (1, 1)
    
    elif is_multisig( privkey_info ):
        m, pubs = virtualchain.parse_multisig_redeemscript(privkey_info['redeem_script'])
        if m is None or pubs is None:
            return None, None
        return m, len(pubs)

    return None, None


def get_pubkey_addresses(pubkey):
    """
    Get the compressed and uncompressed addresses
    for a public key.  Useful for verifying
    signatures by key address.

    If we're running in testnet mode, then use
    the testnet version byte.

    Return (compressed address, uncompressed address)
    """
    version_byte = virtualchain.version_byte
    compressed_address, uncompressed_address = None, None

    pubkey = ECPublicKey(pubkey, version_byte=version_byte)
    pubkey_bin = pubkey.to_bin()

    if pubkey._type == PubkeyType.compressed:
        compressed_address = pubkey.address()
        uncompressed_address = decompress(pubkey_bin)
        hashed_address = bin_hash160(uncompressed_address)
        uncompressed_address = bin_hash160_to_address(hashed_address, version_byte=version_byte)
    elif pubkey._type == PubkeyType.uncompressed:
        uncompressed_address = pubkey.address()
        compressed_address = compress(pubkey_bin)
        hashed_address = bin_hash160(compressed_address)
        compressed_address = bin_hash160_to_address(hashed_address, version_byte=version_byte)
    else:
        raise Exception('Invalid public key')

    return compressed_address, uncompressed_address


def get_pubkey_hex( privatekey_hex ):
    """
    Get the uncompressed hex form of a private key
    """

    if len(privatekey_hex) > 64:
        assert privatekey_hex[-2:] == '01'
        privatekey_hex = privatekey_hex[:64]

    # get hex public key
    privatekey_int = int(privatekey_hex, 16)
    pubkey_parts = fastecdsa.keys.get_public_key( privatekey_int, curve=fastecdsa.curve.secp256k1 )
    pubkey_hex = "04{:064x}{:064x}".format(pubkey_parts[0], pubkey_parts[1])
    return pubkey_hex


def get_uncompressed_private_and_public_keys( privkey_str ):
    """
    Get the private and public keys from a private key string.
    Make sure the both are *uncompressed*
    """
    pk = virtualchain.BitcoinPrivateKey(str(privkey_str))
    pk_hex = pk.to_hex()

    # force uncompressed
    if len(pk_hex) > 64:
        assert pk_hex[-2:] == '01'
        pk_hex = pk_hex[:64]

    pubk_hex = virtualchain.BitcoinPrivateKey(pk_hex).public_key().to_hex()
    return pk_hex, pubk_hex


def decode_privkey_hex(privkey_hex):
    """
    Decode a private key for ecdsa signature
    """
    # force uncompressed
    priv = str(privkey_hex)
    if len(priv) > 64:
        assert priv[-2:] == '01'
        priv = priv[:64]

    pk_i = int(priv, 16)
    return pk_i


def decode_pubkey_hex(pubkey_hex):
    """
    Decode a public key for ecdsa verification
    """
    pubk = str(pubkey_hex)
    if keylib.key_formatting.get_pubkey_format(pubk) == 'hex_compressed':
        pubk = keylib.key_formatting.decompress(pubk)

    assert len(pubk) == 130

    pubk_raw = pubk[2:]
    pubk_i = (int(pubk_raw[:64], 16), int(pubk_raw[64:], 16))
    return pubk_i


def encode_signature(sig_r, sig_s):
    """
    Encode an ECDSA signature, with low-s
    """
    # enforce low-s 
    if sig_s * 2 >= fastecdsa.curve.secp256k1.q:
        log.debug("High-S to low-S")
        sig_s = fastecdsa.curve.secp256k1.q - sig_s

    sig_bin = '{:064x}{:064x}'.format(sig_r, sig_s).decode('hex')
    assert len(sig_bin) == 64

    sig_b64 = base64.b64encode(sig_bin)
    return sig_b64


def decode_signature(sigb64):
    """
    Decode a signature into r, s
    """
    sig_bin = base64.b64decode(sigb64)
    assert len(sig_bin) == 64

    sig_hex = sig_bin.encode('hex')
    sig_r = int(sig_hex[:64], 16)
    sig_s = int(sig_hex[64:], 16)
    return sig_r, sig_s


def sign_raw_data(raw_data, privatekey_hex):
    """
    Sign a string of data.
    Returns signature as a base64 string
    """
    pk_i = decode_privkey_hex(privatekey_hex)
    sig_r, sig_s = fastecdsa.ecdsa.sign(raw_data, pk_i, curve=fastecdsa.curve.secp256k1)
    sig_b64 = encode_signature(sig_r, sig_s)
    return sig_b64


def verify_raw_data(raw_data, pubkey_hex, sigb64):
    """
    Verify the signature over a string, given the public key
    and base64-encode signature.
    Return True on success.
    Return False on error.
    """
    sig_r, sig_s = decode_signature(sigb64)
    pubk_i = decode_pubkey_hex(pubkey_hex)
    res = fastecdsa.ecdsa.verify((sig_r, sig_s), raw_data, pubk_i, curve=fastecdsa.curve.secp256k1)
    return res


def sign_digest( digest_hex, privkey_hex, curve=fastecdsa.curve.secp256k1, hashfunc=hashlib.sha256 ):
    """
    Sign a digest with ECDSA
    Return base64 signature
    """
    pk_i = decode_privkey_hex(str(privkey_hex))

    # generate a deterministic nonce per RFC6979
    rfc6979 = RFC6979_blockstack(pk_i, curve.q, hashfunc)
    k = rfc6979.gen_nonce_from_digest(digest_hex.decode('hex'))

    r, s = _ecdsa.sign(digest_hex, str(pk_i), str(k), curve.name)
    return encode_signature(int(r), int(s))


def verify_digest( digest_hex, pubkey_hex, sigb64, curve=fastecdsa.curve.secp256k1, hashfunc=hashlib.sha256 ):
    """
    Verify a digest and signature with ECDSA
    Return True if it matches
    """

    Q = decode_pubkey_hex(str(pubkey_hex))
    r, s = decode_signature(sigb64)

    # validate Q, r, s
    if not curve.is_point_on_curve(Q):
        raise fastecdsa.ecdsa.EcdsaError('Invalid public key, point is not on curve {}'.format(curve.name))
    elif r > curve.q or r < 1:
        raise fastecdsa.ecdsa.EcdsaError('Invalid Signature: r is not a positive integer smaller than the curve order')
    elif s > curve.q or s < 1:
        raise fastecdsa.ecdsa.EcdsaError('Invalid Signature: s is not a positive integer smaller than the curve order')

    qx, qy = Q
    return _ecdsa.verify(str(r), str(s), digest_hex, str(qx), str(qy), curve.name)


