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
from .backend.blockchain import get_balance, is_address_usable, get_tx_fee
from .utils import satoshis_to_btc, btc_to_satoshis, exit_with_error, print_result

import config
from .config import WALLET_PATH, WALLET_PASSWORD_LENGTH, CONFIG_PATH, CONFIG_DIR, CONFIG_FILENAME, WALLET_FILENAME, MINIMUM_BALANCE

from .proxy import get_names_owned_by_address, get_default_proxy, get_name_cost
from .rpc import local_rpc_connect

log = config.get_logger()


class HDWallet(object):

    """
        Initialize a hierarchical deterministic wallet with
        hex_privkey and get child addresses and private keys
    """

    def __init__(self, hex_privkey=None, config_path=CONFIG_PATH):

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
        self.config_path = config_path


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


    def get_next_keypair(self, count=1, config_path=None):
        """ Get next payment address that is ready to use

            Returns (payment_address, hex_privkey)
        """

        if config_path is None:
            config_path = self.config_path

        addresses = self.get_child_keypairs(count=count)
        index = 0

        for payment_address in addresses:

            # find an address that can be used for payment
            if not is_address_usable(payment_address, config_path=config_path):
                log.debug("Pending tx on address: %s" % payment_address)

            balance = get_balance( payment_address, config_path=config_path )
            if balance < MINIMUM_BALANCE: 
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


def make_wallet( password, hex_privkey=None, payment_privkey=None, owner_privkey=None, data_privkey=None, config_path=CONFIG_PATH ):
    """
    Make a wallet structure
    """

    hex_password = hexlify(password)

    wallet = HDWallet(hex_privkey, config_path=config_path)
    if hex_privkey is None:
        hex_privkey = wallet.get_master_privkey()
        
    child = wallet.get_child_keypairs(count=3, include_privkey=True)

    data = {}
    encrypted_key = aes_encrypt(hex_privkey, hex_password)
    data['encrypted_master_private_key'] = encrypted_key

    if payment_privkey is None:
        data['payment_addresses'] = [child[0][0]]
    else:
        try:
            data['payment_addresses'] = [pybitcoin.BitcoinPrivateKey(payment_privkey).public_key().address()]
        except:
            return {'error': 'Invalid payment private key'}

        data['encrypted_payment_privkey'] = aes_encrypt(payment_privkey, hex_password)

    if owner_privkey is None:
        data['owner_addresses'] = [child[1][0]]
    else:
        try:
            data['owner_addresses'] = [pybitcoin.BitcoinPrivateKey(owner_privkey).public_key().address()]
        except:
            return {'error': 'Invalid payment private key'}

        data['encrypted_owner_privkey'] = aes_encrypt(owner_privkey, hex_password)

    data_keypair = child[2]
    if data_privkey is None:
        data['data_pubkeys'] = [ECPrivateKey(data_keypair[1]).public_key().to_hex()]
    else:
        try:
            data['data_pubkeys'] = [ECPrivateKey(data_privkey).public_key().to_hex()]
        except:
            return {'error': 'Invalid data private key'}

        data['encrypted_data_privkey'] = aes_encrypt(data_privkey, hex_password)

    data['data_pubkey'] = data['data_pubkeys'][0]

    return data


def decrypt_wallet( data, password, config_path=CONFIG_PATH ):
    """
    Decrypt a wallet's encrypted fields
    Return a dict with the decrypted fields on success
    Return {'error': ...} on failure
    """
    hex_password = hexlify(password)
    wallet = None

    try:
        hex_privkey = aes_decrypt(data['encrypted_master_private_key'], hex_password)
        wallet = HDWallet(hex_privkey, config_path=config_path)
    except Exception, e:
        if os.environ.get("BLOCKSTACK_DEBUG", None) is not None:
            log.exception(e)
        return {'error': 'Incorrect password'}
    
    child = wallet.get_child_keypairs(count=3, include_privkey=True)
    payment_keypair = child[0]
    owner_keypair = child[1]
    data_keypair = child[2]
    data_pubkey = ECPrivateKey( data_keypair[1] ).public_key().to_hex()

    ret = {}
    keynames = ['payment_privkey', 'owner_privkey', 'data_privkey']
    for i in xrange(0, len(keynames)):

        keyname = keynames[i]
        child_keypair = child[i]
        encrypted_keyname = "encrypted_%s" % keyname

        if data.has_key(encrypted_keyname):
            try:
                privkey = aes_decrypt(data[encrypted_keyname], hex_password)
            except Exception, e:
                log.exception(e)
                return {'error': 'Incorrect password'}

            ret[keyname] = privkey
        else:
            ret[keyname] = child_keypair[1]

    ret['hex_privkey'] = hex_privkey
    ret['payment_addresses'] = [pybitcoin.BitcoinPrivateKey(ret['payment_privkey']).public_key().address()]
    ret['owner_addresses'] = [pybitcoin.BitcoinPrivateKey(ret['owner_privkey']).public_key().address()]
    ret['data_pubkeys'] = [ECPrivateKey(ret['data_privkey']).public_key().to_hex()]
    ret['data_pubkey'] = ret['data_pubkeys'][0]

    return ret


def write_wallet( data, path=None, config_dir=CONFIG_DIR ):
    """
    Generate and save the wallet to disk.
    """
    if path is None:
        path = os.path.join(config_dir, WALLET_FILENAME )

    with open(path, 'w') as f:
        f.write( json.dumps(data) )
        f.flush()
        os.fsync(f.fileno())

    return True


def make_wallet_password( password=None ):
    """
    Make a wallet password:
    prompt for a wallet, and ensure it's the right length.
    If @password is not None, verify that it's the right length.
    Return {'status': True, 'password': ...} on success
    Return {'error': ...} on error
    """
    if password is not None and len(password) > 0:
        if len(password) < WALLET_PASSWORD_LENGTH:
            return {'error': 'Password not long enough (%s-character minimum)' % WALLET_PASSWORD_LENGTH}

        return {'status': True, 'password': password}

    else:
        p1 = getpass("Enter new password: ")
        p2 = getpass("Confirm new password: ")
        if p1 != p2:
            return {'error': 'Passwords do not match'}

        if len(p1) < WALLET_PASSWORD_LENGTH:
            return {'error': 'Password not long enough (%s-character minimum)' % WALLET_PASSWORD_LENGTH}

        else:
            return {'status': True, 'password': p1}


def initialize_wallet( password="", interactive=True, hex_privkey=None, config_dir=CONFIG_DIR, wallet_path=None ):
    """
    Initialize the wallet,
    interatively if need be.
    Return a dict with the wallet password and master private key.
    Return {'error': ...} on error
    """
    if wallet_path is None:
        wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    config_path = os.path.join(config_dir, CONFIG_FILENAME)
        
    if not interactive and len(password) == 0:
        raise Exception("Non-interactive wallet initialization requires a password of length %s or greater" % WALLET_PASSWORD_LENGTH)

    result = {}
    print "Initializing new wallet ..."

    try:
        if interactive:
            while len(password) < WALLET_PASSWORD_LENGTH:
                res = make_wallet_password(password)
                if 'error' in res:
                    print res['error']
                    continue

                else:
                    password = res['password']
                    break

        if hex_privkey is None:
            temp_wallet = HDWallet(config_path=config_path)
            hex_privkey = temp_wallet.get_master_privkey()

        wallet = make_wallet( password, hex_privkey=hex_privkey, config_path=config_path )
        write_wallet( wallet, path=wallet_path ) 

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
        return {'error': 'Interrupted'}

    return result


def wallet_exists(config_dir=CONFIG_DIR, wallet_path=None):
    """
    Does a wallet exist?
    Return True if so
    Return False if not
    """
    if wallet_path is None:
        wallet_path = os.path.join(config_dir, WALLET_FILENAME )

    return os.path.exists(wallet_path)


def load_wallet( password=None, config_dir=CONFIG_DIR, wallet_path=None, include_private=False ):
    """
    Get the wallet from disk, and unlock it.
    Return {'status': True, 'wallet': ...} on success
    Return {'error': ...} on error
    """
    if wallet_path is None:
        wallet_path = os.path.join( config_dir, WALLET_FILENAME )

    config_path = os.path.join(config_dir, CONFIG_FILENAME )

    if password is None:
        password = getpass("Enter wallet password: ")

    file = open(wallet_path, 'r')
    data = file.read()
    data = json.loads(data)
    file.close()

    wallet = decrypt_wallet( data, password, config_path=config_path )
    if 'error' in wallet:
        return wallet

    else:
        return {'status': True, 'wallet': wallet}
    

def unlock_wallet(display_enabled=False, password=None, config_dir=CONFIG_DIR, wallet_path=None ):
    """
    Unlock the wallet.
    Save the wallet to the RPC daemon on success.
    exit on error (e.g. incorrect password)
    Return {'status': True} on success
    return {'error': ...} on error
    """
    config_path = os.path.join( config_dir, CONFIG_FILENAME )
    if wallet_path is None:
        wallet_path = os.path.join( config_dir, WALLET_FILENAME )

    if walletUnlocked(config_dir):
        if display_enabled:
            payment_address, owner_address, data_pubkey = get_addresses_from_file(wallet_path=wallet_path)
            display_wallet_info(payment_address, owner_address, data_pubkey, config_path=config_path)

        return {'status': True}

    else:

        try:
            if password is None:
                password = getpass("Enter wallet password: ")

            with open(wallet_path, "r") as f:
                data = f.read()
                data = json.loads(data)

            wallet = decrypt_wallet( data, password, config_path=config_path )
            if display_enabled:
                display_wallet_info( wallet['payment_addresses'][0], wallet['owner_addresses'][0], wallet['data_pubkeys'][0], config_path=config_path )

            # may need to migrate data_pubkey into wallet.json
            _, _, onfile_data_pubkey = get_addresses_from_file(wallet_path=wallet_path)
            if onfile_data_pubkey is None:

                # make a data keypair 
                w = HDWallet(wallet['hex_privkey'], config_path=config_path)
                child = wallet.get_child_keypairs(count=3, include_privkey=True)
                data_keypair = child[2]

                wallet['data_privkey'] = data_keypair[1]
                wallet['data_pubkeys'] = [ECPrivateKey(data_keypair[1]).public_key().to_hex()]
                wallet['data_pubkey'] = wallet['data_pubkeys'][0]

                write_wallet( wallet, path=wallet_path + ".tmp" )
                shutil.move( wallet_path + ".tmp", wallet_path )

            # save!
            res = save_keys_to_memory( [wallet['payment_addresses'][0], wallet['payment_privkey']],
                                       [wallet['owner_addresses'][0], wallet['owner_privkey']],
                                       [wallet['data_pubkeys'][0], wallet['data_privkey']],
                                       config_dir=config_dir )

            if 'error' in res:
                return res

            return {'status': True}

        except KeyboardInterrupt:
            return {'error': 'Interrupted'}


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
    Returns the wallet data on success
    Returns None on error
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


def display_wallet_info(payment_address, owner_address, data_public_key, config_path=CONFIG_PATH):
    """
    Print out useful wallet information
    """
    print '-' * 60
    print "Payment address:\t%s" % payment_address
    print "Owner address:\t\t%s" % owner_address

    if data_public_key is not None:
        print "Data public key:\t%s" % data_public_key

    balance = get_balance( payment_address, config_path=config_path )
    if balance is None:
        print "Failed to look up balance"

    else:
        balance = satoshis_to_btc( balance )
        print '-' * 60
        print "Balance:"
        print "%s: %s" % (payment_address, balance)
        print '-' * 60

    names_owned = get_names_owned(owner_address)
    if 'error' in names_owned:
        print "Failed to look up names owned"

    else:
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


def get_payment_addresses_and_balances(config_path=CONFIG_PATH, wallet_path=None):
    """
    Get payment addresses
    """
    config_dir = os.path.dirname(config_path)
    if wallet_path is None:
        wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    payment_addresses = []

    # currently only using one
    payment_address, owner_address, data_pubkey = get_addresses_from_file(wallet_path=wallet_path)

    payment_addresses.append({'address': payment_address,
                              'balance': get_balance(payment_address, config_path=config_path)})

    return payment_addresses


def get_owner_addresses_and_names(wallet_path=WALLET_PATH):
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

    owner_addresses = get_owner_addresses_and_names(wallet_path)
    names_owned = []

    for entry in owner_addresses:
        additional_names = get_names_owned(entry['address'])
        for name in additional_names:
            names_owned.append(name)

    return names_owned


def get_total_balance(config_path=CONFIG_PATH, wallet_path=WALLET_PATH):

    payment_addresses = get_payment_addresses_and_balances(wallet_path=wallet_path, config_path=config_path)
    total_balance = 0.0

    for entry in payment_addresses:
        total_balance += entry['balance']

    return total_balance, payment_addresses


def dump_wallet(config_path=CONFIG_PATH, password=None):
    """
    Load the wallet private keys.
    Return {'status': True, 'wallet': wallet} on success
    Return {'error': ...} on error
    """
    from .actions import start_rpc_endpoint

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

