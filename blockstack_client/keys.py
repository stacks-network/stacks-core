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
import re

import keylib

from keychain import PrivateKeychain
import jsonschema
from jsonschema.exceptions import ValidationError

from .logger import get_logger
from .constants import CONFIG_PATH, BLOCKSTACK_DEBUG, BLOCKSTACK_TEST

import virtualchain
from virtualchain.lib.ecdsalib import *

# for compatibility
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


    def _encode_child_privkey(self, child_privkey, compressed=True):
        """
        Make sure the private key given is compressed or not compressed
        """
        return set_privkey_compressed(child_privkey, compressed=compressed)


    def get_child_privkey(self, index=0, compressed=True):
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

            return self._encode_child_privkey(KEY_CACHE[self.keychain_key][index], compressed=compressed)

        # expensive...
        child = self.priv_keychain.hardened_child(index)

        if not KEY_CACHE.has_key(self.keychain_key):
            KEY_CACHE[self.keychain_key] = {}

        child_privkey = self._encode_child_privkey(child.private_key(), compressed=compressed)
        
        KEY_CACHE[self.keychain_key][index] = child_privkey
        return child_privkey


    def get_master_address(self):
        if self.master_address is not None:
            return self.master_address

        hex_privkey = self.get_master_privkey()
        hex_pubkey = get_pubkey_hex(hex_privkey)
        return virtualchain.address_reencode(keylib.public_key_to_address(hex_pubkey))


    def get_child_address(self, index=0):
        """
        @index is the child index

        Returns:
        child address for given @index
        """

        if self.child_addresses is not None:
            return self.child_addresses[index]

        # force decompressed...
        hex_privkey = self.get_child_privkey(index)
        hex_pubkey = get_pubkey_hex(hex_privkey)
        return virtualchain.address_reencode(keylib.public_key_to_address(hex_pubkey))


    def get_child_keypairs(self, count=1, offset=0, include_privkey=False, compressed=True):
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
                hex_privkey = self.get_child_privkey(index, compressed=compressed)
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


def is_encrypted_multisig(privkey_info):
    """
    LEGACY COMPATIBILITY CODE

    Does a given encrypted private key info
    represent an encrypted multisig bundle?
    """
    from .schemas import ENCRYPTED_PRIVKEY_MULTISIG_SCHEMA
    try:
        jsonschema.validate(privkey_info, ENCRYPTED_PRIVKEY_MULTISIG_SCHEMA)
        return True
    except ValidationError as e:
        return False



def is_singlesig_hex(privkey_info):
    """
    Does the given private key info represent
    a single signature bundle? (i.e. one private key)?
    """
    return virtualchain.is_singlesig(privkey_info) and re.match(r"^[0-9a-fA-F]+$", privkey_info)


def is_encrypted_singlesig(privkey_info):
    """
    LEGACY COMPATIBILITY CODE

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
    return ecdsa_private_key(privkey_info).to_hex()


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
    if virtualchain.is_singlesig(privkey_info):
        return singlesig_privkey_to_string(privkey_info)

    if virtualchain.is_multisig(privkey_info):
        return multisig_privkey_to_string(privkey_info)

    return None


def decrypt_multisig_info(enc_multisig_info, password):
    """
    LEGACY COMPATIBILITY CODE

    Given an encrypted multisig info dict,
    decrypt the sensitive fields.

    Returns {'private_keys': ..., 'redeem_script': ..., **other_fields}
    Return {'error': ...} on error
    """
    from .backend.crypto.utils import aes_decrypt

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
            ecdsa_private_key(pk)
        except Exception as e:
            if BLOCKSTACK_TEST or BLOCKSTACK_DEBUG:
                log.exception(e)

            return {'error': 'Invalid password; failed to decrypt private key in multisig wallet'}

        multisig_info['private_keys'].append(ecdsa_private_key(pk).to_hex())

    redeem_script = None
    enc_redeem_script = enc_multisig_info['encrypted_redeem_script']
    try:
        redeem_script = aes_decrypt(enc_redeem_script, hex_password)
    except Exception as e:
        if BLOCKSTACK_TEST or BLOCKSTACK_DEBUG:
            log.exception(e)

        return {'error': 'Invalid password; failed to decrypt redeem script in multisig wallet'}

    multisig_info['redeem_script'] = redeem_script

    # preserve any other information in the multisig info
    for k, v in enc_multisig_info.items():
        if k not in ['encrypted_private_keys', 'encrypted_redeem_script']:
            multisig_info[k] = v

    assert virtualchain.is_multisig(multisig_info)
    return multisig_info


def decrypt_private_key_info(privkey_info, password):
    """
    LEGACY COMPATIBILITY CODE

    Decrypt a particular private key info bundle.
    It can be either a single-signature private key, or a multisig key bundle.
    Return {'address': ..., 'private_key_info': ...} on success.
    Return {'error': ...} on error.
    """

    from .backend.crypto.utils import aes_decrypt

    ret = {}
    if is_encrypted_multisig(privkey_info):
        ret = decrypt_multisig_info(privkey_info, password)
        if 'error' in ret:
            return {'error': 'Failed to decrypt multisig wallet: {}'.format(ret['error'])}

        address = virtualchain.get_privkey_address(ret)
        return {'address': address, 'private_key_info': ret}

    if is_encrypted_singlesig(privkey_info):
        try:
            hex_password = hexlify(password)
            pk = aes_decrypt(privkey_info, hex_password)
            pk = ecdsa_private_key(pk).to_hex()
        except Exception as e:
            if BLOCKSTACK_TEST:
                log.exception(e)

            return {'error': 'Invalid password'}

        address = virtualchain.get_privkey_address(pk)
        return {'address': address, 'private_key_info': pk}

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
        if not virtualchain.is_singlesig(data_privkey):
            raise ValueError('Invalid data key info')

        pk_data = ecdsa_private_key(data_privkey).to_hex()
        ret['data_privkey'] = pk_data

    if owner_privkey is not None:
        if virtualchain.is_multisig(owner_privkey):
            pks = owner_privkey['private_keys']
            m, _ = virtualchain.parse_multisig_redeemscript(owner_privkey['redeem_script'])
            assert m <= len(pks)

            multisig_info = virtualchain.make_multisig_info(m, pks)
            ret['owner_privkey'] = multisig_info
            ret['owner_addresses'] = [virtualchain.get_privkey_address(multisig_info)]

        elif virtualchain.is_singlesig(owner_privkey):
            pk_owner = ecdsa_private_key(owner_privkey).to_hex()
            ret['owner_privkey'] = pk_owner
            ret['owner_addresses'] = [virtualchain.get_privkey_address(pk_owner)]

        else:
            raise ValueError('Invalid owner key info')

    if payment_privkey is None:
        return ret

    if virtualchain.is_multisig(payment_privkey):
        pks = payment_privkey['private_keys']
        m, _ = virtualchain.parse_multisig_redeemscript(payment_privkey['redeem_script'])
        assert m <= len(pks)

        multisig_info = virtualchain.make_multisig_info(m, pks)
        ret['payment_privkey'] = multisig_info
        ret['payment_addresses'] = [virtualchain.get_privkey_address(multisig_info)]

    elif virtualchain.is_singlesig(payment_privkey):
        pk_payment = ecdsa_private_key(payment_privkey).to_hex()
        ret['payment_privkey'] = pk_payment
        ret['payment_addresses'] = [virtualchain.get_privkey_address(pk_payment)]

    else:
        raise ValueError('Invalid payment key info')

    ret['data_pubkey'] = ecdsa_private_key(ret['data_privkey']).public_key().to_hex()
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
    wallet_data_pubkey = keylib.key_formatting.decompress(get_pubkey_hex(str(data_privkey)))

    if zonefile_data_pubkey is None and wallet_data_pubkey is not None:
        # zone file does not have a data key set.
        # the wallet data key *must* match the owner key
        owner_privkey_info = wallet['owner_privkey']
        owner_privkey = None
        if virtualchain.is_singlesig(owner_privkey_info):
            owner_privkey = owner_privkey_info
        elif virtualchain.is_multisig(owner_privkey_info):
            owner_privkey = owner_privkey_info['private_keys'][0]

        owner_pubkey = keylib.key_formatting.decompress(get_pubkey_hex(str(owner_privkey)))
        if owner_pubkey != wallet_data_pubkey:
            # doesn't match. no data key 
            return {'error': 'No zone file key, and data key does not match owner key ({} != {})'.format(owner_pubkey, wallet_data_pubkey)}
        
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

    if virtualchain.is_singlesig( privkey_info ):
        return (1, 1)
    
    elif virtualchain.is_multisig( privkey_info ):
        m, pubs = virtualchain.parse_multisig_redeemscript(privkey_info['redeem_script'])
        if m is None or pubs is None:
            return None, None
        return m, len(pubs)

    return None, None

