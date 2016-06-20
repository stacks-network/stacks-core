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
from keylib import ECPrivateKey, ECPublicKey
from keylib.hashing import bin_hash160
from keylib.address_formatting import bin_hash160_to_address
from keylib.key_formatting import compress, decompress
from keylib.public_key_encoding import PubkeyType

import pybitcoin
import bitcoin
import binascii
from utilitybelt import is_hex

from config import get_logger, DEBUG, MAX_RPC_LEN, find_missing, BLOCKSTACKD_SERVER, \
    BLOCKSTACKD_PORT, BLOCKSTACK_METADATA_DIR, BLOCKSTACK_DEFAULT_STORAGE_DRIVERS, \
    FIRST_BLOCK_MAINNET, NAME_OPCODES, OPFIELDS, CONFIG_DIR, SPV_HEADERS_PATH, BLOCKCHAIN_ID_MAGIC, \
    NAME_PREORDER, NAME_REGISTRATION, NAME_UPDATE, NAME_TRANSFER, NAMESPACE_PREORDER, NAME_IMPORT, \
    USER_ZONEFILE_TTL, CONFIG_PATH

log = get_logger()

def make_wallet_keys( data_privkey=None, owner_privkey=None, payment_privkey=None ):
    """
    For testing.  DO NOT USE
    """

    ret = {}
    if data_privkey is not None:
        pk_data = pybitcoin.BitcoinPrivateKey( data_privkey ).to_hex()
        ret['data_privkey'] = pk_data 

    if owner_privkey is not None:
        pk_owner = pybitcoin.BitcoinPrivateKey( owner_privkey ).to_hex()
        ret['owner_privkey'] = pk_owner

    if payment_privkey is None:
        # fall back to owner key
        payment_privkey = owner_privkey

    if payment_privkey is not None:
        pk_payment = pybitcoin.BitcoinPrivateKey( payment_privkey ).to_hex()
        ret['payment_privkey'] = pk_payment

    return ret


def get_data_privkey( user_zonefile, wallet_keys=None, config_path=CONFIG_PATH ):
    """
    Get the user's data private key.
    Use the private key that corresponds to the data public key in their zonefile.
    (If the have a designated data public key, use the data private key.  If they don't,
    use the owner private key).
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
        assert wallet_keys.has_key('data_privkey') and wallet_keys['data_privkey'] is not None, "No data private key set"
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

    Useful for signing mutable data when no explicit data key is set.
    Returns {'status': True, 'privatekey': ...} on success
    Returns {'error': ...} on error
    """

    # generate the mutable zonefile
    data_privkey = get_data_privkey( user_zonefile, wallet_keys=wallet_keys, config_path=config_path )
    if data_privkey is None:
        # no usable (distinct) data private key
        # fall back to owner keypair 
        log.warn("No data private key set.  Falling back to owner keypair.")
        owner_pubkey, owner_privkey = get_owner_keypair( wallet_keys=wallet_keys, config_path=config_path )
        if owner_privkey is None:
            raise Exception("No owner private key")
            return {'error': 'No usable private signing key found'}

        # sanity check: must match profile address
        compressed_addr, uncompressed_addr = get_pubkey_addresses( owner_pubkey )
        if owner_address not in [compressed_addr, uncompressed_addr]:
            raise Exception("%s not in [%s,%s]" % (owner_address, compressed_addr, uncompressed_addr))
            return {'error': 'No usable public key'}

        data_privkey = owner_privkey

    return {'status': True, 'privatekey': data_privkey}


def get_data_keypair( user_zonefile, wallet_keys=None, config_path=CONFIG_PATH ):
    """
    Get the user's data keypair.
    Return (pubkey, privkey) on success
    Return (None, None) on success
    """

    privkey = get_data_privkey( user_zonefile, wallet_keys=wallet_keys, config_path=config_path )
    if privkey is None:
        return (None, None)

    public_key = ECPrivateKey(privkey).public_key().to_hex()

    return public_key, privkey


def get_owner_keypair( wallet_keys=None, config_path=CONFIG_PATH ):
    """
    Get the user's owner keypair
    """
    from .wallet import get_wallet

    wallet = None
    if wallet_keys is not None:
        assert wallet_keys.has_key('owner_privkey') and wallet_keys['owner_privkey'] is not None, "No owner private key set"
        wallet = wallet_keys

    else:
        wallet = get_wallet(config_path=CONFIG_PATH)
        assert wallet is not None 

    owner_privkey = wallet['owner_privkey']
    public_key = pybitcoin.BitcoinPrivateKey(owner_privkey).public_key().to_hex()
    return public_key, owner_privkey


def get_payment_keypair( wallet_keys=None, config_path=CONFIG_PATH ):
    """
    Get the user's payment keypair
    """
    from .wallet import get_wallet 

    wallet = None
    if wallet_keys is not None:
        assert wallet_keys.has_key('payment_privkey') and wallet_keys['payment_privkey'] is not None, "No payment private key set"
        wallet = wallet_keys

    else:
        wallet = get_wallet( config_path=CONFIG_PATH )
        assert wallet is not None

    payment_privkey = wallet['payment_privkey']
    public_key = pybitcoin.BitcoinPrivateKey(payment_privkey).public_key().to_hex()
    return public_key, payment_privkey


def get_pubkey_addresses( pubkey ):
    """
    Get the compressed and uncompressed addresses
    for a public key.  Useful for verifying
    signatures by key address.

    Return (compressed address, uncompressed address)
    """
    public_key_object = ECPublicKey(pubkey)
    compressed_address = None
    uncompressed_address = None

    if public_key_object._type == PubkeyType.compressed:
        compressed_address = public_key_object.address()
        uncompressed_address = bin_hash160_to_address(
            bin_hash160(
                decompress(public_key_object.to_bin())
            )
        )
    elif public_key_object._type == PubkeyType.uncompressed:
        compressed_address = bin_hash160_to_address(
            bin_hash160(
                compress(public_key_object.to_bin())
            )
        )
        uncompressed_address = public_key_object.address()
    else:
        raise Exception("Invalid public key")

    return (compressed_address, uncompressed_address)
