#!/usr/bin/env python
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
    along with Blockstack-client.  If not, see <http://www.gnu.org/licenses/>.
"""

import argparse
import sys
import json
import traceback
import os
import re
import errno
import pybitcoin
import subprocess
import shutil
from keylib import ECPrivateKey
from socket import error as socket_error
from time import sleep
from getpass import getpass
from binascii import hexlify, unhexlify

from xmlrpclib import ServerProxy
from defusedxml import xmlrpc

# prevent the usual XML attacks 
xmlrpc.monkey_patch()

import logging
logging.disable(logging.CRITICAL)

import requests
requests.packages.urllib3.disable_warnings()

from keychain import PrivateKeychain

from pybitcoin import make_send_to_address_tx
from pybitcoin import BlockcypherClient
from pybitcoin.rpc.bitcoind_client import BitcoindClient

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")
sys.path.insert(0, parent_dir)

from .backend.crypto.utils import get_address_from_privkey, get_pubkey_from_privkey
from .backend.crypto.utils import aes_encrypt, aes_decrypt
from .backend.blockchain import get_balance, dontuseAddress, underfundedAddress
from .utils import satoshis_to_btc, btc_to_satoshis, exit_with_error, print_result

import config
from .config import WALLET_PATH, WALLET_PASSWORD_LENGTH, CONFIG_PATH, CONFIG_DIR, CONFIG_FILENAME, WALLET_FILENAME

from .proxy import get_names_owned_by_address, get_default_proxy
from .rpc import local_rpc_connect

log = config.get_logger()


class HDWallet(object):

    """
        Initialize a hierarchical deterministic wallet with
        hex_privkey and get child addresses and private keys
    """

    def __init__(self, hex_privkey=None):

        """
            If @hex_privkey is given, use that to derive keychain
            otherwise, use a new random seed
        """

        if hex_privkey:
            self.priv_keychain = PrivateKeychain.from_private_key(hex_privkey)
        else:
            log.debug("No privatekey given, starting new wallet")
            self.priv_keychain = PrivateKeychain()

        self.master_address = self.get_master_address()
        self.child_addresses = None


    def get_master_privkey(self):

        return self.priv_keychain.private_key()


    def get_child_privkey(self, index=0):
        """
            @index is the child index

            Returns:
            child privkey for given @index
        """

        child = self.priv_keychain.hardened_child(index)
        return child.private_key()


    def get_master_address(self):

        hex_privkey = self.get_master_privkey()
        return get_address_from_privkey(hex_privkey)


    def get_child_address(self, index=0):
        """
            @index is the child index

            Returns:
            child address for given @index
        """

        if self.child_addresses is not None:
            return self.child_addresses[index]

        hex_privkey = self.get_child_privkey(index)
        return get_address_from_privkey(hex_privkey)


    def get_child_keypairs(self, count=1, offset=0, include_privkey=False):
        """
            Returns (privkey, address) keypairs

            Returns:
            returns child keypairs

            @include_privkey: toggles between option to return
                             privkeys along with addresses or not
        """

        keypairs = []

        for index in range(offset, offset+count):
            address = self.get_child_address(index)

            if include_privkey:
                hex_privkey = self.get_child_privkey(index)
                keypairs.append((address, hex_privkey))
            else:
                keypairs.append(address)

        return keypairs


    def get_next_keypair(self, count=1):
        """ Get next payment address that is ready to use

            Returns (payment_address, hex_privkey)
        """

        addresses = self.get_child_keypairs(count=count)
        index = 0

        for payment_address in addresses:

            # find an address that can be used for payment

            if dontuseAddress(payment_address):
                log.debug("Pending tx on address: %s" % payment_address)

            elif underfundedAddress(payment_address):
                log.debug("Underfunded address: %s" % payment_address)

            else:
                return payment_address, self.get_child_privkey(index)

            index += 1

        log.debug("No valid address available.")

        return None, None


    def get_privkey_from_address(self, target_address, count=1):
        """ Given a child address, return priv key of that address
        """

        addresses = self.get_child_keypairs(count=count)

        index = 0

        for address in addresses:

            if address == target_address:

                return self.get_child_privkey(index)

            index += 1

        return None


def make_wallet( hex_privkey, password ):
    """
    Make a wallet structure
    """

    hex_password = hexlify(password)

    wallet = HDWallet(hex_privkey)
    child = wallet.get_child_keypairs(count=3, include_privkey=True)

    data = {}
    encrypted_key = aes_encrypt(hex_privkey, hex_password)
    data['encrypted_master_private_key'] = encrypted_key
    data['payment_addresses'] = [child[0][0]]
    data['owner_addresses'] = [child[1][0]]
    data_keypair = child[2]

    data_pubkey = ECPrivateKey(data_keypair[1]).public_key().to_hex()
    data['data_pubkeys'] = [data_pubkey]

    return data


def write_wallet( hex_privkey, password, path=None, config_dir=CONFIG_DIR ):
    """
    Generate and save the wallet to disk.
    """
    if path is None:
        path = os.path.join(config_dir, WALLET_FILENAME )

    data = make_wallet( hex_privkey, password )
    with open(path, 'w') as f:
        f.write( json.dumps(data) )
        f.flush()

    return True


def initialize_wallet( password="", interactive=True, hex_privkey=None, config_dir=CONFIG_DIR, wallet_path=None ):
    """
    Initialize the wallet,
    interatively if need be.
    Return a dict with the wallet password and master private key.
    Return {'error': ...} on error
    """
    if wallet_path is None:
        wallet_path = os.path.join(config_dir, WALLET_FILENAME)
        
    if not interactive and len(password) == 0:
        raise Exception("Non-interactive wallet initialization requires a password of length %s or greater" % WALLET_PASSWORD_LENGTH)

    result = {}
    print "Initializing new wallet ..."

    try:
        if interactive:
            while len(password) < WALLET_PASSWORD_LENGTH:
                password = getpass("Enter new password: ")

                if len(password) < WALLET_PASSWORD_LENGTH:
                    msg = "Password is too short. Please make it at"
                    msg += " least %s characters long" % WALLET_PASSWORD_LENGTH
                    print msg

                else:
                    break

            confirm_password = getpass("Confirm new password: ")

            if password != confirm_password:
                return {'error': 'Passwords do not match'}

        if hex_privkey is None:
            temp_wallet = HDWallet()
            hex_privkey = temp_wallet.get_master_privkey()

        write_wallet( hex_privkey, password, path=wallet_path )
        print "Wallet created. Make sure to backup the following:"

        result['wallet_password'] = password
        result['master_private_key'] = hex_privkey
        print_result(result)

        if interactive:
            input_prompt = "Have you backed up the above private key? (y/n): "
            user_input = raw_input(input_prompt)
            user_input = user_input.lower()

            if user_input != 'y':
                return {'error': 'Please back up your private key first'}

    except KeyboardInterrupt:
        exit_with_error("\nExited.")

    return result


def load_wallet( password=None, config_dir=CONFIG_DIR, wallet_path=None, include_private=False ):
    """
    Get the wallet from disk, and unlock it.
    Return {'status': True, 'wallet': ...} on success
    Return {'error': ...} on error
    """
    if wallet_path is None:
        wallet_path = os.path.join( config_dir, WALLET_FILENAME )

    if password is None:
        password = getpass("Enter wallet password: ")

    hex_password = hexlify(password)

    file = open(wallet_path, 'r')
    data = file.read()
    data = json.loads(data)
    file.close()
    hex_privkey = None
    try:
        hex_privkey = aes_decrypt(data['encrypted_master_private_key'],
                                  hex_password)
    except Exception, e:
        log.exception(e)
        return {'error': 'Incorrect password'}

    else:
        wallet = HDWallet(hex_privkey)
        child = wallet.get_child_keypairs(count=3,
                                          include_privkey=True)
        payment_keypair = child[0]
        owner_keypair = child[1]
        data_keypair = child[2]
        data_pubkey = ECPrivateKey( data_keypair[1] ).public_key().to_hex()

        wallet = make_wallet( hex_privkey, password )
        if include_private:
            wallet['owner_privkey'] = owner_keypair[1]
            wallet['payment_privkey'] = payment_keypair[1]
            wallet['data_privkey'] = data_keypair[1]
            wallet['master_privkey'] = hex_privkey

        return {'status': True, 'wallet': wallet}
    

def unlock_wallet(display_enabled=False, password=None, config_dir=CONFIG_DIR, wallet_path=None ):
    """
    Unlock the wallet.
    Save the wallet to the RPC daemon on success.
    exit on error (e.g. incorrect password)
    Return {'status': True} on success
    return {'error': ...} on error
    """
    if wallet_path is None:
        wallet_path = os.path.join( config_dir, WALLET_FILENAME )

    if walletUnlocked(config_dir):
        if display_enabled:
            payment_address, owner_address, data_pubkey = get_addresses_from_file(wallet_path=wallet_path)
            display_wallet_info(payment_address, owner_address, data_pubkey)
    else:

        try:
            if password is None:
                password = getpass("Enter wallet password: ")

            hex_password = hexlify(password)

            file = open(wallet_path, 'r')
            data = file.read()
            data = json.loads(data)
            file.close()
            hex_privkey = None
            try:
                hex_privkey = aes_decrypt(data['encrypted_master_private_key'],
                                          hex_password)
            except Exception, e:
                log.exception(e)
                return {'error': 'Incorrect password'}

            else:
                wallet = HDWallet(hex_privkey)
                child = wallet.get_child_keypairs(count=3,
                                                  include_privkey=True)
                payment_keypair = child[0]
                owner_keypair = child[1]
                data_keypair = child[2]
                data_pubkey = ECPrivateKey( data_keypair[1] ).public_key().to_hex()

                res = save_keys_to_memory(payment_keypair, owner_keypair, data_keypair, config_dir=config_dir)
                if 'error' in res:
                    return res

                if display_enabled:
                    display_wallet_info(payment_keypair[0], owner_keypair[0], data_pubkey)

                # may need to migrate data_pubkey into wallet.json
                _, _, onfile_data_pubkey = get_addresses_from_file(wallet_path=wallet_path)
                if onfile_data_pubkey is None:
                    write_wallet( hex_privkey, password, path=wallet_path+".tmp" )
                    shutil.move( wallet_path+".tmp", wallet_path )

                return {'status': True}

        except KeyboardInterrupt:
            print "\nExited."
            sys.exit(1)


def walletUnlocked(config_dir=CONFIG_DIR):
    """
    Determine whether or not the wallet is unlocked.
    Do so by asking the local RPC backend daemon
    """
    config_path = os.path.join(config_dir, CONFIG_FILENAME)
    local_proxy = local_rpc_connect(config_dir=config_dir)
    conf = config.get_config(config_path)

    if local_proxy is not False:

        try:
            wallet_data = local_proxy.backend_get_wallet(conf['rpc_token'])
            if 'error' in wallet_data:
                log.error("RPC error: %s" % wallet_data['error'])
                raise Exception("RPC error: %s" % wallet_data['error'])

        except Exception, e:
            log.exception(e)
            return {'error': 'Failed to get wallet'}

        if 'error' in wallet_data:
            return False
        elif wallet_data['payment_address'] is None:
            return False
        else:
            return True
    else:
        return False


def get_wallet(config_path=CONFIG_PATH):
    """
    Get the decrypted wallet from the running RPC backend daemon.
    """
    local_proxy = local_rpc_connect(config_dir=os.path.dirname(config_path))
    conf = config.get_config(config_path)

    if local_proxy is not False:

        try:
            wallet_data = local_proxy.backend_get_wallet(conf['rpc_token'])
            if 'error' in wallet_data:
                log.error("RPC error: %s" % wallet_data['error'])
                raise Exception("RPC error: %s" % wallet_data['error'])

        except Exception, e:
            log.exception(e)
            return {'error': 'Failed to get wallet'}

        if 'error' in wallet_data:
            return None

        return wallet_data

    else:
        return None


def display_wallet_info(payment_address, owner_address, data_public_key):
    """
    Print out useful wallet information
    """
    print '-' * 60
    print "Payment address:\t%s" % payment_address
    print "Owner address:\t\t%s" % owner_address

    if data_public_key is not None:
        print "Data public key:\t%s" % data_public_key

    print '-' * 60
    print "Balance:"
    print "%s: %s" % (payment_address, get_balance(payment_address))
    print '-' * 60

    print "Names Owned:"
    names_owned = get_names_owned(owner_address)
    print "%s: %s" % (owner_address, names_owned)
    print '-' * 60


def get_names_owned(address, proxy=None):
    """
    Get names owned by address
    """

    if proxy is None:
        proxy = get_default_proxy()

    try:
        names_owned = get_names_owned_by_address(address, proxy=proxy)
    except socket_error:
        names_owned = "Error connecting to server"

    return names_owned


def save_keys_to_memory(payment_keypair, owner_keypair, data_keypair, config_dir=CONFIG_DIR):
    """
    Save keys to the running RPC backend
    """
    proxy = local_rpc_connect(config_dir=config_dir)

    log.debug("Saving keys to memory")
    try:
        data = proxy.backend_set_wallet(payment_keypair, owner_keypair, data_keypair)
        return data
    except Exception, e:
        log.exception(e)
        return {'error': "Failed to save keys"}


def get_addresses_from_file(config_dir=CONFIG_DIR, wallet_path=None):
    """
    Load up the set of addresses from the wallet
    """
    if wallet_path is None:
        wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    file = open(wallet_path, 'r')
    data = file.read()
    data = json.loads(data)
    file.close()
    
    data_pubkey = None
    payment_address = data['payment_addresses'][0]
    owner_address = data['owner_addresses'][0]
    if data.has_key('data_pubkeys'):
        data_pubkey = data['data_pubkeys'][0]

    return payment_address, owner_address, data_pubkey


def get_payment_addresses(wallet_path=WALLET_PATH):
    """
    Get payment addresses
    """
    payment_addresses = []

    # currently only using one
    payment_address, owner_address, data_pubkey = get_addresses_from_file(wallet_path=wallet_path)

    payment_addresses.append({'address': payment_address,
                              'balance': get_balance(payment_address)})

    return payment_addresses


def get_owner_addresses(wallet_path=WALLET_PATH):
    """
    Get owner addresses
    """
    owner_addresses = []

    # currently only using one
    payment_address, owner_address, data_pubkey = get_addresses_from_file(wallet_path=wallet_path)

    owner_addresses.append({'address': owner_address,
                            'names_owned': get_names_owned(owner_address)})

    return owner_addresses


def get_all_names_owned(wallet_path=WALLET_PATH):

    owner_addresses = get_owner_addresses(wallet_path)
    names_owned = []

    for entry in owner_addresses:
        additional_names = get_names_owned(entry['address'])
        for name in additional_names:
            names_owned.append(name)

    return names_owned


def get_total_balance(wallet_path=WALLET_PATH):

    payment_addresses = get_payment_addresses(wallet_path)
    total_balance = 0.0

    for entry in payment_addresses:
        total_balance += float(entry['balance'])

    return total_balance, payment_addresses


def approx_tx_fees(num_tx):
    """ Just a rough approximation on tx fees
        It slightly over estimates
        Should be replaced by checking for fee estimation from bitcoind
    """
    APPROX_FEE_PER_TX = 8000  # in satoshis
    return num_tx * APPROX_FEE_PER_TX


def hasEnoughBalance(payment_address, cost):

    total_balance = get_balance(payment_address)

    if total_balance > cost:
        return True
    else:
        return False


def get_total_fees(data):

    reply = {}

    registration_fee_satoshi = data['satoshis']
    tx_fee_satoshi = approx_tx_fees(num_tx=2)

    registration_fee = satoshis_to_btc(registration_fee_satoshi)
    tx_fee = satoshis_to_btc(tx_fee_satoshi)

    reply['name_price'] = registration_fee
    reply['transaction_fee'] = tx_fee
    reply['total_estimated_cost'] = registration_fee + tx_fee

    return reply


def dump_wallet(config_path=CONFIG_PATH):
    """
    Load the wallet private keys.
    Return {'status': True, 'wallet': wallet} on success
    Return {'error': ...} on error
    """
    from .action import start_rpc_endpoint

    config_dir = os.path.dirname(config_path)
    start_rpc_endpoint(config_dir)

    wallet_path = os.path.join(config_dir, WALLET_FILENAME)
    if not os.path.exists(wallet_path):
        res = initialize_wallet(wallet_path=wallet_path)
        if 'error' in res:
            return res

    if not walletUnlocked(config_dir=config_dir):
        res = unlock_wallet(config_dir=config_dir, password=password)
        if 'error' in res:
            return res

    wallet = get_wallet( config_path=config_path )
    if wallet is None:
        return {'error': 'Failed to load wallet'}

    return {'status': True, 'wallet': wallet}

