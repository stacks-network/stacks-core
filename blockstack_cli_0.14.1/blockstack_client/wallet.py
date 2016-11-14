#!/usr/bin/env python

from __future__ import print_function

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

import time
import json
import os
import shutil
import virtualchain

from keylib import ECPrivateKey
from socket import error as socket_error
from getpass import getpass
from binascii import hexlify
import jsonschema

from defusedxml import xmlrpc

# prevent the usual XML attacks
xmlrpc.monkey_patch()

import logging
logging.disable(logging.CRITICAL)

import requests
requests.packages.urllib3.disable_warnings()

from keychain import PrivateKeychain

from .backend.crypto.utils import get_address_from_privkey
from .backend.crypto.utils import aes_encrypt, aes_decrypt
from .backend.blockchain import get_balance, get_block_height
from .utils import satoshis_to_btc, print_result

from .keys import *

import config
from .config import (
    WALLET_PATH, WALLET_PASSWORD_LENGTH, CONFIG_PATH,
    CONFIG_DIR, CONFIG_FILENAME, WALLET_FILENAME,
    WALLET_DECRYPT_MAX_TRIES, WALLET_DECRYPT_BACKOFF_RESET,
    BLOCKSTACK_DEBUG
)

from .proxy import get_names_owned_by_address, get_default_proxy
from .rpc import local_rpc_connect, start_rpc_endpoint
from .schemas import *

log = config.get_logger()

DECRYPT_ATTEMPTS = 0
LAST_DECRYPT_ATTEMPT = 0 

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

        self.priv_keychain = self.get_priv_keychain(hex_privkey)
        self.master_address = self.get_master_address()
        self.child_addresses = None

    def get_priv_keychain(self, hex_privkey):
        if hex_privkey:
            return PrivateKeychain.from_private_key(hex_privkey)

        log.debug('No privatekey given, starting new wallet')
        return PrivateKeychain()

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


def make_wallet(password, hex_privkey=None, payment_privkey_info=None,
                owner_privkey_info=None, data_privkey_info=None, config_path=CONFIG_PATH):
    """
    Make a wallet structure.
    By default, the owner and payment keys will be key bundles set up to require 2-of-3 signatures.
    @payment_privkey_info, @owner_privkey_info, and @data_privkey_info can either be individual private keys, or
    dicts with {'redeem_script': ..., 'private_keys': ...} defined.

    Return the new wallet on success.
    Return {'error': ...} on failure
    """

    def make_privkey_info(multisig):
        if multisig:
            return virtualchain.make_multisig_wallet(2, 3)

        return virtualchain.BitcoinPrivateKey().to_wif()

    hex_password = hexlify(password)

    wallet = HDWallet(hex_privkey)
    if hex_privkey is None:
        hex_privkey = wallet.get_master_privkey()

    child = wallet.get_child_keypairs(count=3, include_privkey=True)

    data = {}
    encrypted_key = aes_encrypt(hex_privkey, hex_password)
    data['encrypted_master_private_key'] = encrypted_key

    multisig = False
    curr_height = get_block_height(config_path=config_path)
    if curr_height >= config.EPOCH_HEIGHT_MINIMUM:
        # safe to use multisig
        multisig = True

    # default to 2-of-3 multisig key info if data isn't given
    if payment_privkey_info is None:
        payment_privkey_info = make_privkey_info(multisig)

    if not is_singlesig(payment_privkey_info) and not is_multisig(payment_privkey_info):
        return {
            'error': (
                'Payment private key info must be either '
                'a single private key or a multisig bundle'
            )
        }

    if not multisig and is_multisig(payment_privkey_info):
        return {'error': 'Multisig payment private key info is not supported'}

    if owner_privkey_info is None:
        owner_privkey_info = make_privkey_info(multisig)

    if not is_singlesig(owner_privkey_info) and not is_multisig(owner_privkey_info):
        return {
            'error': (
                'Owner private key info must be either '
                'a single private key or a multisig bundle'
            )
        }

    if not multisig and is_multisig(owner_privkey_info):
        return {'error': 'Multisig owner private key info is not supported'}

    if data_privkey_info is None:
        # TODO: for now, this must be a single private key
        data_privkey_info = child[2][1]
    elif not is_singlesig(data_privkey_info):
        return {'error': 'Data private key info must be a single private key'}
    else:
        assert False

    enc_payment_info = encrypt_private_key_info(payment_privkey_info, password)
    if 'error' in enc_payment_info:
        return {'error': enc_payment_info['error']}

    enc_owner_info = encrypt_private_key_info(owner_privkey_info, password)
    if 'error' in enc_owner_info:
        return {'error': enc_owner_info['error']}

    enc_data_info = encrypt_private_key_info(data_privkey_info, password)
    if 'error' in enc_data_info:
        return {'error': enc_data_info['error']}

    payment_addr = enc_payment_info['encrypted_private_key_info']['address']
    owner_addr = enc_owner_info['encrypted_private_key_info']['address']

    enc_payment_info = enc_payment_info['encrypted_private_key_info']['private_key_info']
    enc_owner_info = enc_owner_info['encrypted_private_key_info']['private_key_info']
    enc_data_info = enc_data_info['encrypted_private_key_info']['private_key_info']

    data['encrypted_payment_privkey'] = enc_payment_info
    data['payment_addresses'] = [payment_addr]

    data['encrypted_owner_privkey'] = enc_owner_info
    data['owner_addresses'] = [owner_addr]

    data['encrypted_data_privkey'] = enc_data_info
    data['data_pubkeys'] = [virtualchain.BitcoinPrivateKey(data_privkey_info).public_key().to_hex()]
    data['data_pubkey'] = data['data_pubkeys'][0]

    return data


def log_failed_decrypt(max_tries=WALLET_DECRYPT_MAX_TRIES):
    """
    Record that we tried (and failed)
    to decrypt a wallet.  Determine
    how long we should wait before
    allowing another attempt.

    If we tried many times, then use
    exponential backoff to limit brute-forces

    Return the interval of time to sleep
    """
    global DECRYPT_ATTEMPTS
    global LAST_DECRYPT_ATTEMPT
    global NEXT_DECRYPT_ATTEMPT

    if LAST_DECRYPT_ATTEMPT + WALLET_DECRYPT_BACKOFF_RESET < time.time():
        # haven't tried in a while
        DECRYPT_ATTEMPTS = 0
        NEXT_DECRYPT_ATTEMPT = 0
        return

    DECRYPT_ATTEMPTS += 1
    LAST_DECRYPT_ATTEMPT = time.time()

    if DECRYPT_ATTEMPTS > max_tries:
        interval = 2 ** (DECRYPT_ATTEMPTS - max_tries + 1)
        NEXT_DECRYPT_ATTEMPT = time.time() + interval

    return


def can_attempt_decrypt(max_tries=WALLET_DECRYPT_MAX_TRIES):
    """
    Can we attempt a decryption?
    Has enough time passed since the last guess?
    """
    global DECRYPT_ATTEMPTS
    global LAST_DECRYPT_ATTEMPT
    global NEXT_DECRYPT_ATTEMPT

    if LAST_DECRYPT_ATTEMPT + WALLET_DECRYPT_BACKOFF_RESET < time.time():
        # haven't tried in a while
        DECRYPT_ATTEMPTS = 0
        NEXT_DECRYPT_ATTEMPT = 0
        return True

    return NEXT_DECRYPT_ATTEMPT < time.time()


def time_until_next_decrypt_attempt():
    """
    When can we try to decrypt next?
    """
    global NEXT_DECRYPT_ATTEMPT
    if NEXT_DECRYPT_ATTEMPT == 0:
        return 0

    return max(0, NEXT_DECRYPT_ATTEMPT - time.time())


def decrypt_wallet(data, password, config_path=CONFIG_PATH,
                   max_tries=WALLET_DECRYPT_MAX_TRIES):
    """
    Decrypt a wallet's encrypted fields.

    After WALLET_DECRYPT_MAX_TRIES failed attempts, start doing exponential backoff
    to prevent brute-force attacks.

    Return a dict with the decrypted fields on success
    Return {'error': ...} on failure
    """
    hex_password = hexlify(password)
    wallet = None

    if not can_attempt_decrypt(max_tries=max_tries):
        msg = 'Cannot decrypt at this time.  Try again in {} seconds'
        return {'error': msg.format(time_until_next_decrypt_attempt())}

    try:
        hex_privkey = aes_decrypt(data['encrypted_master_private_key'], hex_password)
        wallet = HDWallet(hex_privkey)
    except Exception as e:
        if BLOCKSTACK_DEBUG is not None:
            log.exception(e)

        ret = {'error': 'Incorrect password'}
        log_failed_decrypt(max_tries=max_tries)
        if not can_attempt_decrypt(max_tries=max_tries):
            log.debug('Incorrect password; using exponential backoff')
            msg = 'Incorrect password.  Try again in {} seconds'
            ret['error'] = msg.format(time_until_next_decrypt_attempt())

        return ret

    # legacy compat: use the master private key to generate child keys.
    # If the specific key they are purposed for is not defined in the wallet,
    # then they are used in its place.
    # This is because originally, the master private key was used to derive
    # the owner, payment, and data private keys; not all wallets define
    # these keys separately (and have instead relied on us being able to
    # generate them from the master private key).
    child = wallet.get_child_keypairs(count=3, include_privkey=True)

    # note: payment_keypair = child[0]; owner_keypair = child[1]
    data_keypair = child[2]

    multisig = False
    curr_height = get_block_height(config_path=config_path)
    if curr_height >= config.EPOCH_HEIGHT_MINIMUM:
        # safe to use multisig
        multisig = True

    ret = {}
    keynames = ['payment', 'owner', 'data']
    for keyname in keynames:
        keyname_privkey = '{}_privkey'.format(keyname)
        keyname_addresses = '{}_addresses'.format(keyname)
        encrypted_keyname = 'encrypted_{}_privkey'.format(keyname)

        if encrypted_keyname in data:
            # This key was explicitly defined in the wallet.
            # It is not guaranteed to be a child key of the
            # master private key.
            field = decrypt_private_key_info(data[encrypted_keyname], password)

            if 'error' in field:
                msg = 'Failed to decrypt "{}": {}'
                log.debug(msg.format(encrypted_keyname, field['error']))
                return field

            ret[keyname_privkey] = field['private_key_info']
            ret[keyname_addresses] = [field['address']]
        else:
            # Legacy: this key is not defined in the wallet.
            # Derive it from the master key.
            ret[keyname_privkey] = child_keypair[1]
            ret[keyname_addresses] = [
                    virtualchain.BitcoinPrivateKey(ret[keyname_privkey]).public_key().address()
            ]

        # this can't be multisig if it's not yet supported 
        if not is_singlesig( ret[keyname_privkey] ) and not multisig:
            log.error('Invalid wallet data for {}'.format(keyname_privkey))
            return {'error': 'Invalid wallet'}

    ret['hex_privkey'] = hex_privkey
    ret['data_pubkeys'] = [ECPrivateKey(ret['data_privkey']).public_key().to_hex()]
    ret['data_pubkey'] = ret['data_pubkeys'][0]

    return ret


def write_wallet(data, path=None, config_dir=CONFIG_DIR):
    """
    Generate and save the wallet to disk.
    """
    if path is None:
        path = os.path.join(config_dir, WALLET_FILENAME)

    data = json.dumps(data)
    with open(path, 'w') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

    return True


def make_wallet_password(prompt=None, password=None):
    """
    Make a wallet password:
    prompt for a wallet, and ensure it's the right length.
    If @password is not None, verify that it's the right length.
    Return {'status': True, 'password': ...} on success
    Return {'error': ...} on error
    """
    if password is not None and password:
        if len(password) < WALLET_PASSWORD_LENGTH:
            msg = 'Password not long enough ({}-character minimum)'
            return {'error': msg.format(WALLET_PASSWORD_LENGTH)}
        return {'status': True, 'password': password}

    if prompt:
        print(prompt)

    p1 = getpass('Enter new password: ')
    p2 = getpass('Confirm new password: ')
    if p1 != p2:
        return {'error': 'Passwords do not match'}

    if len(p1) < WALLET_PASSWORD_LENGTH:
        msg = 'Password not long enough ({}-character minimum)'
        return {'error': msg.format(WALLET_PASSWORD_LENGTH)}

    return {'status': True, 'password': p1}


def initialize_wallet(password='', interactive=True, hex_privkey=None, config_dir=CONFIG_DIR,
                      wallet_path=None, owner_privkey_info=None, payment_privkey_info=None, data_privkey_info=None):
    """
    Initialize a wallet,
    interatively if need be.
    Save it to @wallet_path
    Return a dict with the wallet password and master private key.
    Return {'error': ...} on error
    """
    if wallet_path is None:
        wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    config_path = os.path.join(config_dir, CONFIG_FILENAME)

    if not interactive and not password:
        msg = ('Non-interactive wallet initialization '
               'requires a password of length {} or greater')
        raise Exception(msg.format(WALLET_PASSWORD_LENGTH))

    result = {}

    try:
        if interactive:
            print('Initializing new wallet ...')
            while password is None or len(password) < WALLET_PASSWORD_LENGTH:
                res = make_wallet_password(password)
                if 'error' in res:
                    print(res['error'])
                    continue

                password = res['password']
                break

        if hex_privkey is None:
            temp_wallet = HDWallet()
            hex_privkey = temp_wallet.get_master_privkey()

        wallet = make_wallet(
            password, hex_privkey=hex_privkey,
            config_path=config_path, owner_privkey_info=owner_privkey_info,
            payment_privkey_info=payment_privkey_info, data_privkey_info=data_privkey_info
        )

        if 'error' in wallet:
            log.error('make_wallet failed: {}'.format(wallet['error']))
            return wallet

        write_wallet(wallet, path=wallet_path)

        result['wallet_password'] = password
        result['master_private_key'] = hex_privkey

        if not interactive:
            return result

        print('Wallet created. Make sure to backup the following:')
        print_result(result)

        input_prompt = 'Have you backed up the above private key? (y/n): '
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
        wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    return os.path.exists(wallet_path)


def load_wallet(password=None, config_dir=CONFIG_DIR, wallet_path=None, include_private=False):
    """
    Get a wallet from disk, and unlock it.
    Return {'status': True, 'wallet': ...} on success
    Return {'error': ...} on error
    """
    if wallet_path is None:
        wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    config_path = os.path.join(config_dir, CONFIG_FILENAME)

    if password is None:
        password = getpass('Enter wallet password: ')

    with open(wallet_path, 'r') as f:
        data = f.read()
        data = json.loads(data)

    wallet = decrypt_wallet(data, password, config_path=config_path)
    if 'error' in wallet:
        return wallet

    return {'status': True, 'wallet': wallet}


def unlock_wallet(password=None, config_dir=CONFIG_DIR, wallet_path=None):
    """
    Unlock the wallet.
    Save the wallet to the RPC daemon on success.

    If this wallet is in legacy format, then it will
    be migrated to the latest format and the legacy
    copy backed up.

    Return {'status': True, 'addresses': ...} on success
    return {'error': ...} on error
    """
    config_path = os.path.join(config_dir, CONFIG_FILENAME)
    if wallet_path is None:
        wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    if is_wallet_unlocked(config_dir):
        return {'status': True}

    try:
        try:
            if password is None:
                password = getpass('Enter wallet password: ')

            with open(wallet_path, "r") as f:
                data = f.read()
                data = json.loads(data)

            wallet = decrypt_wallet( data, password, config_path=config_path )
            if 'error' in wallet:
                log.error("Failed to decrypt wallet: %s" % wallet['error'])
                return wallet

            # may need to migrate data_pubkey into wallet.json
            _, _, onfile_data_pubkey = get_addresses_from_file(wallet_path=wallet_path)
            if onfile_data_pubkey is None:

                # make a data keypair (always the third child (index 2) of the HDWallet) 
                w = HDWallet(wallet['hex_privkey'])
                child = w.get_child_keypairs(count=3, include_privkey=True)
                data_keypair = child[2]

                wallet['data_privkey'] = data_keypair[1]
                wallet['data_pubkeys'] = [ECPrivateKey(data_keypair[1]).public_key().to_hex()]
                wallet['data_pubkey'] = wallet['data_pubkeys'][0]

                # set addresses 
                wallet['payment_addresses'] = [get_privkey_info_address( wallet['payment_privkey'] )]
                wallet['owner_addresses'] = [get_privkey_info_address( wallet['owner_privkey'] )]

                # save!
                encrypted_wallet = make_wallet( password, hex_privkey=wallet['hex_privkey'],
                                                          payment_privkey=wallet['payment_privkey'], 
                                                          owner_privkey=wallet['owner_privkey'],
                                                          data_privkey=wallet['data_privkey'],
                                                          config_path=config_path )

                if 'error' in encrypted_wallet:
                    log.error("Failed to make wallet: %s" % encrypted_wallet['error'])
                    return encrypted_wallet

                write_wallet( encrypted_wallet, path=wallet_path + ".tmp" )
                legacy_path = wallet_path + ".legacy"
                if os.path.exists(wallet_path):
                    if not os.path.exists( legacy_path ):
                        shutil.move( wallet_path, legacy_path )
                    else:
                        i = 1
                        while os.path.exists(legacy_path):
                            legacy_path = wallet_path + ".legacy.%s" % i
                            i += 1

                        shutil.move( wallet_path, legacy_path )

                shutil.move( wallet_path + ".tmp", wallet_path )
                log.debug("Migrated wallet %s (legacy wallet backed up to %s)" % (wallet_path, legacy_path))

        # save!
        try:
            res = save_keys_to_memory(
                (wallet['payment_addresses'][0], wallet['payment_privkey']),
                (wallet['owner_addresses'][0], wallet['owner_privkey']),
                (wallet['data_pubkeys'][0], wallet['data_privkey']),
                config_dir=config_dir
            )
        except KeyError as ke:
            if BLOCKSACK_DEBUG is not None:
                data = json.dumps(wallet, indent=4, sort_keys=True)
                log.error('data: {}\n'.format(data))
            raise

        if 'error' in res:
            return res

        addresses = {
            'payment_address': wallet['payment_addresses'][0],
            'owner_address': wallet['owner_addresses'][0],
            'data_pubkey': wallet['data_pubkeys'][0]
        }

        return {'status': True, 'addresses': addresses}
    except KeyboardInterrupt:
        return {'error': 'Interrupted'}

    return {'status': True}


def is_wallet_unlocked(config_dir=CONFIG_DIR):
    """
    Determine whether or not the wallet is unlocked.
    Do so by asking the local RPC backend daemon
    """
    config_path = os.path.join(config_dir, CONFIG_FILENAME)
    local_proxy = local_rpc_connect(config_dir=config_dir)
    conf = config.get_config(config_path)

    if not local_proxy:
        return False

    try:
        wallet_data = local_proxy.backend_get_wallet(conf['rpc_token'])
    except (IOError, OSError):
        return False
    except Exception as e:
        log.exception(e)
        return False

    if 'error' in wallet_data:
        return False

    return wallet_data['payment_address'] is not None


def get_wallet(config_path=CONFIG_PATH):
    """
    Get the decrypted wallet from the running RPC backend daemon.
    Returns the wallet data on success
    Returns None on error
    """
    local_proxy = local_rpc_connect(config_dir=os.path.dirname(config_path))
    conf = config.get_config(config_path)

    if not local_proxy:
        return None

    try:
        wallet_data = local_proxy.backend_get_wallet(conf['rpc_token'])
        if 'error' in wallet_data:
            msg = 'RPC error: {}'
            log.error(msg.format(wallet_data['error']))
            raise Exception(msg.format(wallet_data['error']))
    except Exception as e:
        log.exception(e)
        return {'error': 'Failed to get wallet'}

    if 'error' in wallet_data:
        return None

    return wallet_data


def display_wallet_info(payment_address, owner_address, data_public_key, config_path=CONFIG_PATH):
    """
    Print out useful wallet information
    """
    print('-' * 60)
    print('Payment address:\t{}'.format(payment_address))
    print('Owner address:\t\t{}'.format(owner_address))

    if data_public_key is not None:
        print('Data public key:\t{}'.format(data_public_key))

    balance = None
    if payment_address is not None:
        balance = get_balance( payment_address, config_path=config_path )

    if balance is None:
        print('Failed to look up balance')
    else:
        balance = satoshis_to_btc(balance)
        print('-' * 60)
        print('Balance:')
        print('{}: {}'.format(payment_address, balance))
        print('-' * 60)

    names_owned = None
    if owner_address is not None:
        names_owned = get_names_owned(owner_address)
        
    if names_owned is None or 'error' in names_owned:
        print('Failed to look up names owned')

    else:
        print('Names Owned:')
        names_owned = get_names_owned(owner_address)
        print('{}: {}'.format(owner_address, names_owned))
        print('-' * 60)


def get_names_owned(address, proxy=None):
    """
    Get names owned by address
    """

    proxy = get_default_proxy() if proxy is None else proxy

    try:
        names_owned = get_names_owned_by_address(address, proxy=proxy)
    except socket_error:
        names_owned = 'Error connecting to server'

    return names_owned


def save_keys_to_memory(payment_keypair, owner_keypair, data_keypair, config_dir=CONFIG_DIR):
    """
    Save keys to the running RPC backend
    Each keypair must be a list or tuple with 2 items: the address, and the private key information.
    (Note that the private key information can be a multisig info dict).

    Return {'status': True} on success
    Return {'error': ...} on error
    """
    proxy = local_rpc_connect(config_dir=config_dir)

    log.debug('Saving keys to memory')
    try:
        data = proxy.backend_set_wallet(payment_keypair, owner_keypair, data_keypair)
        return data
    except Exception as e:
        log.exception(e)
        return {'error': 'Failed to save keys'}

    return


def get_addresses_from_file(config_dir=CONFIG_DIR, wallet_path=None):
    """
    Load up the set of addresses from the wallet
    Not all fields may be set in older wallets.
    """ 

    data_pubkey = None
    payment_address = None
    owner_address = None

    if wallet_path is None:
        wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    if not os.path.exists(wallet_path):
        log.error('No such file or directory: {}'.format(wallet_path))
        return None, None, None

    with open(wallet_path, 'r') as f:
        data = f.read()

    try:
        data = json.loads(data)
    except:
        log.error('Invalid wallet data: not JSON (in {})'.format(wallet_path))
        return None, None, None 
   
    # extract addresses
    # TODO: schema
    if data.has_key('payment_addresses'):
        payment_address = data['payment_addresses'][0]
    if data.has_key('owner_addresses'):
        owner_address = data['owner_addresses'][0]
    if data.has_key('data_pubkeys'):
        data_pubkey = data['data_pubkeys'][0]

    return payment_address, owner_address, data_pubkey


def get_payment_addresses_and_balances(config_path=CONFIG_PATH, wallet_path=None):
    """
    Get payment addresses and balances.
    Each payment address will have a balance in satoshis.
    Returns [{'address', 'balance'}] on success
    If the wallet is a legacy wallet, returns [{'error': ...}]
    """
    config_dir = os.path.dirname(config_path)
    if wallet_path is None:
        wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    payment_addresses = []

    # currently only using one
    payment_address, owner_address, data_pubkey = (
        get_addresses_from_file(wallet_path=wallet_path)
    )

    if payment_address is not None:
        payment_addresses.append({'address': payment_address,
                                  'balance': get_balance(payment_address, config_path=config_path)})

    else:
        payment_addresses.append({'error': 'Legacy wallet; payment address is not visible'})

    return payment_addresses


def get_owner_addresses_and_names(wallet_path=WALLET_PATH):
    """
    Get owner addresses
    """
    owner_addresses = []

    # currently only using one
    payment_address, owner_address, data_pubkey = (
        get_addresses_from_file(wallet_path=wallet_path)
    )

    if owner_address is not None:
        owner_addresses.append({'address': owner_address,
                                'names_owned': get_names_owned(owner_address)})
    else:
        owner_addresses.append({'error': 'Legacy wallet; owner address is not visible'})

    return owner_addresses


def get_all_names_owned(wallet_path=WALLET_PATH):
    owner_addresses = get_owner_addresses_and_names(wallet_path)
    names_owned = []

    for entry in owner_addresses:
        if 'address' in entry.keys():
            additional_names = get_names_owned(entry['address'])
            for name in additional_names:
                names_owned.append(name)

        elif 'error' in entry.keys():
            # failed to get owner address
            return [entry]

    return names_owned


def get_total_balance(config_path=CONFIG_PATH, wallet_path=WALLET_PATH):
    """
    Get the total balance for the wallet's payment address.
    Units will be in satoshis.
    """
    payment_addresses = get_payment_addresses_and_balances(wallet_path=wallet_path, config_path=config_path)
    total_balance = 0.0

    for entry in payment_addresses:
        if 'balance' in entry.keys():
            total_balance += entry['balance']

    return total_balance, payment_addresses


def dump_wallet(config_path=CONFIG_PATH, wallet_path=None, password=None):
    """
    Load the wallet private keys.
    Return {'status': True, 'wallet': wallet} on success
    Return {'error': ...} on error
    """
    config_dir = os.path.dirname(config_path)
    start_rpc_endpoint(config_dir)

    if wallet_path is None:
        wallet_path = os.path.join(config_dir, WALLET_FILENAME)
        if not os.path.exists(wallet_path):
            res = initialize_wallet(wallet_path=wallet_path, password=password)
            if 'error' in res:
                return res

    if not is_wallet_unlocked(config_dir=config_dir):
        res = unlock_wallet(config_dir=config_dir, password=password)
        if 'error' in res:
            return res

    wallet = get_wallet(config_path=config_path)
    if wallet is None:
        return {'error': 'Failed to load wallet'}

    return {'status': True, 'wallet': wallet}
