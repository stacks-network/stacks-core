#!/usr/bin/env python2
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
from virtualchain.lib.ecdsalib import (
    set_privkey_compressed, get_pubkey_hex, ecdsa_private_key)

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

    elif isinstance(privkey_info, dict) and privkey_info.has_key('private_keys'):
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


def get_compressed_and_decompressed_private_key_info(privkey_info):
    """
    Get the compressed and decompressed versions of private keys and addresses
    Return {'compressed_addr': ..., 'compressed_private_key_info': ..., 'decompressed_addr': ..., 'decompressed_private_key_info': ...} on success
    """
    if virtualchain.is_multisig(privkey_info) or virtualchain.btc_is_multisig_segwit(privkey_info):

        # get both compressed and decompressed addresses 
        privkeys = privkey_info['private_keys']
        m, _ = virtualchain.parse_multisig_redeemscript(privkey_info['redeem_script'])
        privkeys_hex = [ecdsa_private_key(pk).to_hex() for pk in privkeys]

        decompressed_privkeys = map(lambda pk: pk if len(pk) == 64 else pk[:-2], privkeys_hex)
        compressed_privkeys = map(lambda pk: pk if len(pk) == 66 and pk[:-2] == '01' else pk, privkeys_hex)
        
        decompressed_multisig = virtualchain.make_multisig_info(m, decompressed_privkeys, compressed=True)
        compressed_multisig = virtualchain.make_multisig_info(m, compressed_privkeys, compressed=False)

        decompressed_addr = virtualchain.address_reencode(decompressed_multisig['address'])
        compressed_addr = virtualchain.address_reencode(compressed_multisig['address'])
        
        return {'decompressed_private_key_info': decompressed_multisig,
                'compressed_private_key_info': compressed_multisig,
                'compressed_addr': compressed_addr, 'decompressed_addr': decompressed_addr}

    elif virtualchain.is_singlesig(privkey_info) or virtualchain.btc_is_singlesig_segwit(privkey_info):
        
        pk = virtualchain.get_singlesig_privkey(privkey_info)

        # get both compressed and decompressed addresses
        compressed_pk = None
        decompressed_pk = None
        if len(pk) == 66 and pk.endswith('01'):
            compressed_pk = pk
            decompressed_pk = pk[:-2]
        else:
            compressed_pk = pk
            decompressed_pk = pk + '01'

        compressed_pubk = ecdsa_private_key(compressed_pk).public_key().to_hex()
        decompressed_pubk = ecdsa_private_key(decompressed_pk).public_key().to_hex()

        compressed_addr = virtualchain.address_reencode(keylib.public_key_to_address(compressed_pubk))
        decompressed_addr = virtualchain.address_reencode(keylib.public_key_to_address(decompressed_pubk))

        return {'decompressed_private_key_info': decompressed_pk,
                'compressed_private_key_info': compressed_pk,
                'compressed_addr': compressed_addr, 'decompressed_addr': decompressed_addr}

    else:
        raise ValueError("Invalid key bundle")


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

    def _convert_key(given_privkey, key_type):
        if virtualchain.is_multisig(given_privkey):
            pks = given_privkey['private_keys']
            m, _ = virtualchain.parse_multisig_redeemscript(given_privkey['redeem_script'])
            assert m <= len(pks)

            multisig_info = virtualchain.make_multisig_info(m, pks)
            ret['{}_privkey'.format(key_type)] = multisig_info
            ret['{}_addresses'.format(key_type)] = [virtualchain.get_privkey_address(multisig_info)]

        elif virtualchain.is_singlesig(given_privkey):
            pk = ecdsa_private_key(given_privkey).to_hex()
            ret['{}_privkey'.format(key_type)] = pk
            ret['{}_addresses'.format(key_type)] = [virtualchain.get_privkey_address(pk)]

        elif virtualchain.btc_is_singlesig_segwit(given_privkey):
            pk = virtualchain.make_segwit_info( virtualchain.get_singlesig_privkey(given_privkey) )
            ret['{}_privkey'.format(key_type)] = pk
            ret['{}_addresses'.format(key_type)] = [pk['address']]

        elif virtualchain.btc_is_multisig_segwit(given_privkey):
            pks = given_privkey['private_keys']
            m, _ = virtualchain.parse_multisig_redeemscript(given_privkey['redeem_script'])
            assert m <= len(pks)

            pk = virtualchain.make_multisig_segwit_info(m, pks)
            ret['{}_privkey'.format(key_type)] = pk
            ret['{}_addresses'.format(key_type)] = [pk['address']]

        else:
            raise ValueError('Invalid owner key info')

    if data_privkey is not None:
        if not virtualchain.is_singlesig(data_privkey):
            raise ValueError('Invalid data key info')

        pk_data = ecdsa_private_key(data_privkey).to_hex()
        ret['data_privkey'] = pk_data

    if owner_privkey is not None:
        _convert_key(owner_privkey, 'owner')

    if payment_privkey is None:
        return ret

    _convert_key(payment_privkey, 'payment')

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
        if user_zonefile is not None:
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

    if zonefile_data_pubkey is None:
        # zone file does not have a data key set.
        # use the owner key instead
        owner_privkey_info = wallet['owner_privkey']
        owner_privkey = None

        if virtualchain.is_singlesig(owner_privkey_info):
            owner_privkey = owner_privkey_info
        else:
            return {'error': 'No zone file key, and owner key is multisig'}
            # owner_privkey = owner_privkey_info['private_keys'][0]

        '''
        owner_pubkey = keylib.key_formatting.decompress(get_pubkey_hex(str(owner_privkey)))
        if owner_pubkey != keylib.key_formatting.decompress(wallet_data_pubkey):
            # doesn't match. no data key 
            log.error("No zone file data key, and data key does not match owner key ({} != {})".format(owner_pubkey, wallet_data_pubkey))
            return {'error': 'No zone file key, and data key does not match owner key ({} != {})'.format(owner_pubkey, wallet_data_pubkey)}
        '''
        data_privkey = owner_privkey

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


def find_name_index(name_address, master_privkey_hex, max_tries=25, start=0):
    """
    Given a name's device-specific address and device-specific master key,
    find index from which it was derived.

    Return the index on success
    Return None on failure.
    """
    
    hdwallet = HDWallet(master_privkey_hex)
    for i in xrange(start, max_tries):
        child_privkey = hdwallet.get_child_privkey(index=i)
        child_pubkey = get_pubkey_hex(child_privkey)

        child_addresses = [
            keylib.public_key_to_address(keylib.key_formatting.compress(child_pubkey)),
            keylib.public_key_to_address(keylib.key_formatting.decompress(child_pubkey))
        ]

        if str(name_address) in child_addresses:
            return i

    return None


def get_name_privkey(master_privkey_hex, name_index):
    """
    Make the device-specific private key that owns the name.
    @master_privkey_hex is the wallet master key, e.g. from the Browser.
    @name_index is the ith name to be created from this device.
    """
    hdwallet = HDWallet(master_privkey_hex)
    names_privkey = hdwallet.get_child_privkey(index=NAMES_PRIVKEY_NODE, compressed=False)

    hdwallet = HDWallet(names_privkey)
    names_version_privkey = hdwallet.get_child_privkey(index=NAMES_PRIVKEY_VERSION_NODE, compressed=False)

    hdwallet = HDWallet(names_version_privkey)
    name_privkey = hdwallet.get_child_privkey(index=name_index, compressed=False)

    return name_privkey


def get_app_root_privkey(name_privkey):
    """
    Make the device-specific app private key from the device-specific name owner private key
    """
    hdwallet = HDWallet(name_privkey)
    app_privkey = hdwallet.get_child_privkey(index=APP_PRIVKEY_NODE, compressed=False)
    return app_privkey


def get_app_privkey_index(full_application_name):
    """
    Get the full application private key index.
    Application name must be full. i.e. must end in '.1', or '.x'
    """
    full_application_name = str(full_application_name)
    hashcode = 0
    for i in xrange(0, len(full_application_name)):
        next_byte = ord(full_application_name[i])
        hashcode = ((hashcode << 5) - hashcode) + next_byte
    
    return hashcode & 0x7fffffff


def get_app_privkey(app_root_privkey, full_application_name):
    """
    Make the app-specific, device-specific private key from the app root private key
    """
    hdwallet = HDWallet(app_root_privkey)
    app_index = get_app_privkey_index(full_application_name)
    app_privkey = hdwallet.get_child_privkey(index=app_index, compressed=False)
    return app_privkey


def get_signing_privkey(name_privkey):
    """
    Make the device-specific signing private key from the device-specific name owner private key
    """
    hdwallet = HDWallet(name_privkey)
    signing_privkey = hdwallet.get_child_privkey(index=SIGNING_PRIVKEY_NODE, compressed=False)
    return signing_privkey


def get_encryption_privkey(name_privkey):
    """
    Make the device-specific encryption private key from the device-specific name owner private key
    """
    hdwallet = HDWallet(name_privkey)
    encryption_privkey = hdwallet.get_child_privkey(index=ENCRYPTION_PRIVKEY_NODE, compressed=False)
    return encryption_privkey

