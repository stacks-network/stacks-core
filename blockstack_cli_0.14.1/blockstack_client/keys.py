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
from keylib import ECPrivateKey

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

    pk_data = pybitcoin.BitcoinPrivateKey( data_privkey ).to_hex()
    pk_owner = pybitcoin.BitcoinPrivateKey( owner_privkey ).to_hex()

    if payment_privkey is None:
        payment_privkey = owner_privkey

    pk_payment = pybitcoin.BitcoinPrivateKey( payment_privkey ).to_hex()

    return {
        'data_privkey': pk_data,
        'owner_privkey': pk_owner,
        'payment_privkey': pk_payment
    }


def get_data_privkey( wallet_keys=None, config_path=CONFIG_PATH ):
    """
    Get the user's data keypair
    """
    from .wallet import get_wallet

    wallet = None
    if wallet_keys is not None:
        assert wallet_keys.has_key('data_privkey') and wallet_keys['data_privkey'] is not None, "No data private key set"
        wallet = wallet_keys

    else:
        wallet = get_wallet(config_path=CONFIG_PATH)
        assert wallet is not None

    data_privkey = wallet['data_privkey']
    return data_privkey


def get_data_keypair( wallet_keys=None, config_path=CONFIG_PATH ):
    """
    Get the user's data keypair
    """
    privkey = get_data_privkey( wallet_keys=wallet_keys, config_path=config_path )
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

