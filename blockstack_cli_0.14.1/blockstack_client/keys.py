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

from .backend.crypto.utils import aes_encrypt, aes_decrypt
from keylib import ECPrivateKey, ECPublicKey
from keylib.hashing import bin_hash160
from keylib.address_formatting import bin_hash160_to_address
from keylib.key_formatting import compress, decompress
from keylib.public_key_encoding import PubkeyType

from .backend.crypto.utils import aes_encrypt, aes_decrypt

import pybitcoin
import bitcoin
import binascii
import jsonschema
from jsonschema.exceptions import ValidationError
from utilitybelt import is_hex

from .config import get_logger
from .constants import CONFIG_PATH, BLOCKSTACK_DEBUG, BLOCKSTACK_TEST

log = get_logger()

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
    return virtualchain.BitcoinPrivateKey(privkey_info).to_wif()


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

        multisig_info['private_keys'].append(pk)

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
            virtualchain.BitcoinPrivateKey(pk)
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
        elif is_singlesig(owner_privkey):
            pk_owner = virtualchain.BitcoinPrivateKey(owner_privkey).to_hex()
            ret['owner_privkey'] = pk_owner
        else:
            raise ValueError('Invalid owner key info')

    if payment_privkey is None:
        return ret

    if is_multisig(payment_privkey):
        pks = [virtualchain.BitcoinPrivateKey(pk).to_hex() for pk in payment_privkey['private_keys']]
        m, pubs = virtualchain.parse_multisig_redeemscript(payment_privkey['redeem_script'])
        ret['payment_privkey'] = virtualchain.make_multisig_info(m, pks)
    elif is_singlesig(payment_privkey):
        pk_payment = virtualchain.BitcoinPrivateKey(payment_privkey).to_hex()
        ret['payment_privkey'] = pk_payment
    else:
        raise ValueError('Invalid payment key info')

    return ret


def get_data_privkey(user_zonefile, wallet_keys=None, config_path=CONFIG_PATH):
    """
    Get the user's data private key.
    Use the private key that corresponds to the data public key in their zonefile.
    (If the have a designated data public key, use the data private key.  If they don't,
    use the owner private key).

    Return None if not set
    """
    from .wallet import get_wallet
    from .user import user_zonefile_data_pubkey

    try:
        data_pubkey = user_zonefile_data_pubkey(user_zonefile)
    except ValueError:
        log.error('Multiple pubkeys defined')
        return

    if data_pubkey is None:
        log.error('No data public key defined')
        return

    wallet_keys = {} if wallet_keys is None else wallet_keys
    if wallet_keys.get('data_privkey', None) is None:
        log.error('No data private key set')
        return

    wallet = get_wallet(config_path=CONFIG_PATH) if wallet_keys is None else wallet_keys
    assert wallet, 'Failed to get wallet'

    data_privkey = wallet.get('data_privkey', None)
    is_matching_keys = ECPrivateKey(data_privkey).public_key().to_hex() == data_pubkey

    if data_privkey is None or not is_matching_keys:
        # data private key doesn't match zonefile
        log.error('Data private key does not match zonefile')
        return

    # zonefile matches data privkey
    return ECPrivateKey(data_privkey).to_wif()


def get_data_or_owner_privkey(user_zonefile, owner_address, wallet_keys=None, config_path=CONFIG_PATH):
    """
    Get the data private key if it is set in the zonefile, or if not, fall back to the
    owner private key.

    Useful for signing mutable data when no explicit data key is set.
    Returns {'status': True, 'privatekey': ...} on success
    Returns {'error': ...} on error
    """

    # generate the mutable zonefile
    data_privkey = get_data_privkey(user_zonefile, wallet_keys=wallet_keys, config_path=config_path)

    if data_privkey is not None:
        return {'status': True, 'privatekey': data_privkey}

    # This is legacy code here.  The only time this should happen is
    # when the user has a single owner key, and does not have a
    # separate data key.
    log.warn('No data private key set.  Falling back to owner keypair.')
    owner_privkey_info = get_owner_privkey_info(wallet_keys=wallet_keys, config_path=config_path)
    if owner_privkey_info is None:
        raise Exception('No owner private key info')

    # sanity check: must be a single private key.
    # if it isn't, then use the *first* private key in the multisig bundle.
    if not is_singlesig(owner_privkey_info):
        if is_multisig(owner_privkey_info):
            owner_privkey_info = owner_privkey_info['private_keys'][0]

        else:
            raise Exception('Invalid owner private key info')

    # sanity check: must match profile address
    owner_pubkey = virtualchain.BitcoinPrivateKey(owner_privkey_info).public_key().to_hex()
    compressed_addr, uncompressed_addr = get_pubkey_addresses(owner_pubkey)
    if owner_address not in [compressed_addr, uncompressed_addr]:
        raise Exception('{} not in [{},{}]'.format(owner_address, compressed_addr, uncompressed_addr))

    data_privkey = virtualchain.BitcoinPrivateKey(owner_privkey_info).to_wif()
    return {'status': True, 'privatekey': data_privkey}


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
