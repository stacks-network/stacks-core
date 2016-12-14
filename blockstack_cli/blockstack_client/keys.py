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

import argparse
import sys
import json
import traceback
import types
import socket
import uuid
import os
import importlib
import pprint
import random
import time
import copy
import blockstack_profiles
import urllib
import virtualchain
from binascii import hexlify, unhexlify

from keylib import ECPrivateKey, ECPublicKey
from keylib.hashing import bin_hash160
from keylib.address_formatting import bin_hash160_to_address
from keylib.key_formatting import compress, decompress
from keylib.public_key_encoding import PubkeyType

from .backend.crypto.utils import aes_encrypt, aes_decrypt

import pybitcoin
import bitcoin
import binascii
from utilitybelt import is_hex

from config import get_logger, DEBUG, MAX_RPC_LEN, find_missing, BLOCKSTACKD_SERVER, \
    BLOCKSTACKD_PORT, BLOCKSTACK_METADATA_DIR, BLOCKSTACK_DEFAULT_STORAGE_DRIVERS, \
    FIRST_BLOCK_MAINNET, NAME_OPCODES, OPFIELDS, CONFIG_DIR, SPV_HEADERS_PATH, BLOCKCHAIN_ID_MAGIC, \
    NAME_PREORDER, NAME_REGISTRATION, NAME_UPDATE, NAME_TRANSFER, NAMESPACE_PREORDER, NAME_IMPORT, \
    USER_ZONEFILE_TTL, CONFIG_PATH, EPOCH_HEIGHT_MINIMUM

log = get_logger()

def is_multisig( privkey_info ):
    """
    Does the given private key info represent
    a multisig bundle?
    """
    if type(privkey_info) != dict:
        return False

    if 'private_keys' not in privkey_info.keys():
        return False

    if 'redeem_script' not in privkey_info.keys():
        return False

    return True


def is_encrypted_multisig( privkey_info ):
    """
    Does a given encrypted private key info
    represent an encrypted multisig bundle?
    """
    if type(privkey_info) != dict:
        return False

    if 'encrypted_private_keys' not in privkey_info.keys():
        return False

    if 'encrypted_redeem_script' not in privkey_info.keys():
        return False

    return True


def is_singlesig( privkey_info ):
    """
    Does the given private key info represent
    a single signature bundle? (i.e. one private key)?
    """
    if type(privkey_info) not in [str, unicode]:
        return False

    try:
        virtualchain.BitcoinPrivateKey(privkey_info)
        return True
    except:
        return False


def singlesig_privkey_to_string( privkey_info ):
    """
    Convert private key to string
    """
    return virtualchain.BitcoinPrivateKey(privkey_info).to_wif()


def multisig_privkey_to_string( privkey_info ):
    """
    Convert multisig keys to string
    """
    return ",".join( [virtualchain.BitcoinPrivateKey(pk).to_wif() for pk in privkey_info['private_keys']] )


def privkey_to_string( privkey_info ):
    """
    Convert private key to string
    Return None on invalid
    """
    if is_singlesig( privkey_info ):
        return singlesig_privkey_to_string( privkey_info )

    elif is_multisig( privkey_info ):
        return multisig_privkey_to_string( privkey_info )

    else:
        return None


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


def encrypt_multisig_info( multisig_info, password ):
    """
    Given a multisig info dict,
    encrypt the sensitive fields.

    Returns {'encrypted_private_keys': ..., 'encrypted_redeem_script': ..., **other_fields}
    """
    enc_info = {}
    hex_password = hexlify(password)

    if 'private_keys' in multisig_info.keys():
        enc_info['encrypted_private_keys'] = []
        for pk in multisig_info['private_keys']:
            pk_ciphertext = aes_encrypt( pk, hex_password ) 
            enc_info['encrypted_private_keys'].append( pk_ciphertext )


    if 'redeem_script' in multisig_info.keys():
        enc_info['encrypted_redeem_script'] = aes_encrypt( multisig_info['redeem_script'], hex_password )

    for (k, v) in multisig_info.items():
        if k not in ['private_keys', 'redeem_script']:
            enc_info[k] = v

    return enc_info


def decrypt_multisig_info( enc_multisig_info, password ):
    """
    Given an encrypted multisig info dict,
    decrypt the sensitive fields.

    Returns {'private_keys': ..., 'redeem_script': ..., **other_fields}
    Return {'error': ...} on error
    """
    multisig_info = {}
    hex_password = hexlify(password)

    if 'encrypted_private_keys' in enc_multisig_info.keys():
        multisig_info['private_keys'] = []
        for enc_pk in enc_multisig_info['encrypted_private_keys']:
            pk = None
            try:
                pk = aes_decrypt( enc_pk, hex_password )
                virtualchain.BitcoinPrivateKey(pk)
            except Exception, e:
                if os.environ.get("BLOCKSTACK_TEST", None) == "1":
                    log.exception(e)

                return {'error': 'Invalid password; failed to decrypt private key in multisig wallet'}
                
            multisig_info['private_keys'].append( pk )

    if 'encrypted_redeem_script' in enc_multisig_info.keys():
        redeem_script = None
        try:
            redeem_script = aes_decrypt( enc_multisig_info['encrypted_redeem_script'], hex_password )
        except:
            if os.environ.get("BLOCKSTACK_TEST", None) == "1":
                log.exception(e)

            return {'error': 'Invalid password; failed to decrypt redeem script in multisig wallet'}

        multisig_info['redeem_script'] = redeem_script

    for (k, v) in enc_multisig_info.items():
        if k not in ['encrypted_private_keys', 'encrypted_redeem_script']:
            multisig_info[k] = v

    return multisig_info


def encrypt_private_key_info( privkey_info, password ):
    """
    Encrypt private key info.
    Return {'status': True, 'encrypted_private_key_info': {'address': ..., 'private_key_info': ...}} on success
    Returns {'error': ...} on error
    """

    ret = {}
    hex_password = hexlify(password)

    if is_multisig( privkey_info ):
        ret['address'] = virtualchain.make_multisig_address( privkey_info['redeem_script'] )
        ret['private_key_info'] = encrypt_multisig_info( privkey_info, password )

        return {'status': True, 'encrypted_private_key_info': ret}

    elif is_singlesig( privkey_info ):
        ret['address'] = virtualchain.BitcoinPrivateKey(privkey_info).public_key().address()
        ret['private_key_info'] = aes_encrypt( privkey_info, hex_password )

        return {'status': True, 'encrypted_private_key_info': ret}

    else:
        return {'error': 'Invalid private key info'}


def decrypt_private_key_info( privkey_info, password ):
    """
    Decrypt a particular private key info bundle.
    It can be either a single-signature private key, or a multisig key bundle.
    Return {'address': ..., 'private_key_info': ...} on success.
    Return {'error': ...} on error.
    """
    hex_password = hexlify(password)

    if is_encrypted_multisig( privkey_info ):
        ret = decrypt_multisig_info( privkey_info, password )

        if 'error' in ret:
            return {'error': 'Failed to decrypt multisig wallet: %s' % ret['error']}

        # sanity check
        if 'redeem_script' not in ret:
            return {'error': 'Invalid multisig wallet: missing redeem_script'}

        if 'private_keys' not in ret:
            return {'error': 'Invalid multisig wallet: missing private_keys'}
        
        return {'address': virtualchain.make_p2sh_address(ret['redeem_script']), 'private_key_info': ret}

    elif type(privkey_info) in [str, unicode]:
        try:
            pk = aes_decrypt( privkey_info, hex_password )
            virtualchain.BitcoinPrivateKey(pk)
        except:
            return {'error': 'Invalid password'}

        return {'address': virtualchain.BitcoinPrivateKey(pk).public_key().address(), 'private_key_info': pk}

    else:
        return {'error': 'Invalid encrypted private key info'}


def make_wallet_keys( data_privkey=None, owner_privkey=None, payment_privkey=None ):
    """
    For testing.  DO NOT USE
    """
    
    ret = {
        'owner_privkey': None,
        'data_privkey': None,
        'payment_privkey': None
    }

    if data_privkey is not None:
        if not is_singlesig(data_privkey):
            raise ValueError("Invalid data key info")

        pk_data = virtualchain.BitcoinPrivateKey( data_privkey ).to_hex()
        ret['data_privkey'] = pk_data 

    if owner_privkey is not None:
        if is_multisig( owner_privkey ):
            pks = [virtualchain.BitcoinPrivateKey(pk).to_hex() for pk in owner_privkey['private_keys']]
            m, pubs = virtualchain.parse_multisig_redeemscript( owner_privkey['redeem_script'] )
            ret['owner_privkey'] = virtualchain.make_multisig_info( m, pks )

        elif is_singlesig( owner_privkey ):
            pk_owner = virtualchain.BitcoinPrivateKey( owner_privkey ).to_hex()
            ret['owner_privkey'] = pk_owner

        else:
            raise ValueError("Invalid owner key info")

    if payment_privkey is not None:
        if is_multisig( payment_privkey ):
            pks = [virtualchain.BitcoinPrivateKey(pk).to_hex() for pk in payment_privkey['private_keys']]
            m, pubs = virtualchain.parse_multisig_redeemscript( payment_privkey['redeem_script'] )
            ret['payment_privkey'] = virtualchain.make_multisig_info( m, pks )

        elif is_singlesig( payment_privkey ):
            pk_payment = virtualchain.BitcoinPrivateKey( payment_privkey ).to_hex()
            ret['payment_privkey'] = pk_payment

        else:
            raise ValueError("Invalid payment key info")

    return ret


def get_data_privkey( user_zonefile, wallet_keys=None, config_path=CONFIG_PATH ):
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
        data_pubkey = user_zonefile_data_pubkey( user_zonefile )
    except ValueError:
        log.error("Multiple pubkeys defined")
        return None

    if data_pubkey is None:
        log.error("No data public key defined")
        return None

    wallet = None
    if wallet_keys is not None:
        if not wallet_keys.has_key('data_privkey') or wallet_keys['data_privkey'] is None:
            log.error("No data private key set")
            return None 

        wallet = wallet_keys

    else:
        wallet = get_wallet(config_path=CONFIG_PATH)
        assert wallet is not None

    if not wallet.has_key('data_privkey') or ECPrivateKey(wallet['data_privkey']).public_key().to_hex() != data_pubkey:
        # data private key doesn't match zonefile 
        log.error("Data private key does not match zonefile")
        return None

    else:
        # zonefile matches data privkey 
        return wallet['data_privkey']


def get_data_or_owner_privkey( user_zonefile, owner_address, wallet_keys=None, config_path=CONFIG_PATH ):
    """
    Get the data private key if it is set in the zonefile, or if not, fall back to the 
    owner private key.
    
    Due to legacy compatibility

    Useful for signing mutable data when no explicit data key is set.
    Returns {'status': True, 'privatekey': ...} on success
    Returns {'error': ...} on error
    """

    # generate the mutable zonefile
    data_privkey = get_data_privkey( user_zonefile, wallet_keys=wallet_keys, config_path=config_path )
    if data_privkey is None:
        # This is legacy code here.  The only time this should happen is
        # when the user has a single owner key, and does not have a 
        # separate data key.
        log.warn("No data private key set.  Falling back to owner keypair.")
        owner_privkey_info = get_owner_privkey_info( wallet_keys=wallet_keys, config_path=config_path )
        if owner_privkey_info is None:
            raise Exception("No owner private key info")
            return {'error': 'No usable private signing key found'}

        # sanity check: must be a single private key 
        if not is_singlesig( owner_privkey_info ):
            raise Exception("Owner private key info must be a single key")
            return {'error': 'No usable private signing key found'}

        # sanity check: must match profile address
        owner_pubkey = virtualchain.BitcoinPrivateKey(owner_privkey_info).public_key().to_hex()
        compressed_addr, uncompressed_addr = get_pubkey_addresses( owner_pubkey )
        if owner_address not in [compressed_addr, uncompressed_addr]:
            raise Exception("%s not in [%s,%s]" % (owner_address, compressed_addr, uncompressed_addr))
            return {'error': 'No usable public key'}

        data_privkey = owner_privkey_info

    return {'status': True, 'privatekey': data_privkey}


def get_data_privkey_info( user_zonefile, wallet_keys=None, config_path=CONFIG_PATH ):
    """
    Get the user's data private key info
    """

    privkey = get_data_privkey( user_zonefile, wallet_keys=wallet_keys, config_path=config_path )
    if privkey is None:
        return None

    return privkey


def get_owner_privkey_info( wallet_keys=None, config_path=CONFIG_PATH ):
    """
    Get the user's owner private key info
    """
    from .wallet import get_wallet

    wallet = None
    if wallet_keys is not None:
        assert wallet_keys.has_key('owner_privkey') and wallet_keys['owner_privkey'] is not None, "No owner private key set"
        wallet = wallet_keys

    else:
        wallet = get_wallet(config_path=CONFIG_PATH)
        assert wallet is not None 

    owner_privkey_info = wallet['owner_privkey']
    return owner_privkey_info


def get_payment_privkey_info( wallet_keys=None, config_path=CONFIG_PATH ):
    """
    Get the user's payment private key info
    """
    from .wallet import get_wallet 

    wallet = None
    if wallet_keys is not None:
        assert wallet_keys.has_key('payment_privkey') and wallet_keys['payment_privkey'] is not None, "No payment private key set"
        wallet = wallet_keys

    else:
        wallet = get_wallet( config_path=CONFIG_PATH )
        assert wallet is not None

    payment_privkey_info = wallet['payment_privkey']
    return payment_privkey_info


def get_privkey_info_address( privkey_info ):
    """
    Get the address of private key information:
    * if it's a single private key, then calculate the address.
    * if it's a multisig info dict, then get the p2sh address
    """
    if privkey_info is None:
        return None

    if is_singlesig(privkey_info):
        return virtualchain.BitcoinPrivateKey(privkey_info).public_key().address()

    elif is_multisig(privkey_info):
        return virtualchain.make_multisig_address( privkey_info['redeem_script'] )

    else:
        raise ValueError("Invalid private key info")


def get_privkey_info_params( privkey_info, config_path=CONFIG_PATH ):
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

        key_config = (1, 1)
        curr_height = get_block_height( config_path=config_path )
        if curr_height >= EPOCH_HEIGHT_MINIMUM:
            # safe to use multisig
            key_config = (2, 3)

        log.warning("No private key info given, assuming {} key config".format(key_config))
        return key_config

    if is_singlesig( privkey_info ):
        return (1, 1)
    
    elif is_multisig( privkey_info ):
        m, pubs = virtualchain.parse_multisig_redeemscript(privkey_info['redeem_script'])
        if m is None or pubs is None:
            return (None, None)

        return (m, len(pubs))
    else:
        return (None, None)
    


def get_pubkey_addresses( pubkey ):
    """
    Get the compressed and uncompressed addresses
    for a public key.  Useful for verifying
    signatures by key address.

    If we're running in testnet mode, then use
    the testnet version byte.

    Return (compressed address, uncompressed address)
    """
    public_key_object = ECPublicKey(pubkey, version_byte=virtualchain.version_byte)
    compressed_address = None
    uncompressed_address = None

    if public_key_object._type == PubkeyType.compressed:
        compressed_address = public_key_object.address()
        uncompressed_address = bin_hash160_to_address(
            bin_hash160(
                decompress(public_key_object.to_bin())
            ),
            version_byte=virtualchain.version_byte
        )
    elif public_key_object._type == PubkeyType.uncompressed:
        compressed_address = bin_hash160_to_address(
            bin_hash160(
                compress(public_key_object.to_bin())
            ),
            version_byte=virtualchain.version_byte
        )
        uncompressed_address = public_key_object.address()
    else:
        raise Exception("Invalid public key")

    return (compressed_address, uncompressed_address)
