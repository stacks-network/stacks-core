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
from jsonschema.exceptions import ValidationError

from defusedxml import xmlrpc

# prevent the usual XML attacks
xmlrpc.monkey_patch()

import logging
logging.disable(logging.CRITICAL)

import requests
requests.packages.urllib3.disable_warnings()

from .backend.crypto.utils import get_address_from_privkey
from .backend.crypto.utils import aes_decrypt
from .backend.blockchain import get_balance, get_block_height
from .utils import satoshis_to_btc, print_result

from .keys import *

import config
from .constants import (
    WALLET_PATH, WALLET_PASSWORD_LENGTH, CONFIG_PATH,
    CONFIG_DIR, CONFIG_FILENAME, WALLET_FILENAME,
    WALLET_DECRYPT_MAX_TRIES, WALLET_DECRYPT_BACKOFF_RESET,
    BLOCKSTACK_DEBUG, BLOCKSTACK_TEST, SERIES_VERSION
)

from .proxy import get_names_owned_by_address, get_default_proxy
from .rpc import local_api_connect 
from .schemas import *

log = config.get_logger()

DECRYPT_ATTEMPTS = 0
LAST_DECRYPT_ATTEMPT = 0 

def _make_encrypted_wallet_data(password, payment_privkey_info, owner_privkey_info, data_privkey_info, test_legacy=False):
    """
    Lowlevel method to make the encrypted wallet's data,
    given the decrypted data.
    """
   
    data = {}
    
    enc_payment_info = None
    enc_owner_info = None
    enc_data_info = None

    if not test_legacy:
        # legacy wallets (which we test for) may omit these.
        # when running in production, this is prohibited.
        assert payment_privkey_info
        assert owner_privkey_info
        assert data_privkey_info

    if payment_privkey_info is not None:
        enc_payment_info = encrypt_private_key_info(payment_privkey_info, password)
        if 'error' in enc_payment_info:
            log.error('failed to encrypt payment private key info')
            return {'error': enc_payment_info['error']}

    if owner_privkey_info is not None:
        enc_owner_info = encrypt_private_key_info(owner_privkey_info, password)
        if 'error' in enc_owner_info:
            log.error('failed to encrypt owner private key info')
            return {'error': enc_owner_info['error']}

    if data_privkey_info is not None:
        enc_data_info = encrypt_private_key_info(data_privkey_info, password)
        if 'error' in enc_data_info:
            log.error('failed to encrypt data private key info')
            return {'error': enc_data_info['error']}

    if enc_payment_info is not None:
        payment_addr = enc_payment_info['encrypted_private_key_info']['address']
        enc_payment_info = enc_payment_info['encrypted_private_key_info']['private_key_info']
       
        data['encrypted_payment_privkey'] = enc_payment_info
        data['payment_addresses'] = [payment_addr]

    if enc_owner_info is not None:
        owner_addr = enc_owner_info['encrypted_private_key_info']['address']
        enc_owner_info = enc_owner_info['encrypted_private_key_info']['private_key_info']

        data['encrypted_owner_privkey'] = enc_owner_info
        data['owner_addresses'] = [owner_addr]

    if enc_data_info is not None:
        enc_data_info = enc_data_info['encrypted_private_key_info']['private_key_info']

        data['encrypted_data_privkey'] = enc_data_info
        data['data_pubkeys'] = [ECPrivateKey(data_privkey_info).public_key().to_hex()]
        data['data_pubkey'] = data['data_pubkeys'][0]

    data['version'] = SERIES_VERSION
    return data


def encrypt_wallet(wallet, password, test_legacy=False):
    """
    Encrypt the wallet.
    Return the encrypted dict on success
    Return {'error': ...} on error
    """
    
    if test_legacy:
        assert BLOCKSTACK_TEST, 'test_legacy only works in test mode'

    # must be conformant to the current schema
    if not test_legacy:
        jsonschema.validate(wallet, WALLET_SCHEMA_CURRENT)

    payment_privkey_info = wallet.get('payment_privkey', None)
    owner_privkey_info = wallet.get('owner_privkey', None)
    data_privkey_info = wallet.get('data_privkey', None)

    if not is_singlesig(data_privkey_info):
        log.error('Invalid data private key')
        return {'error': 'Invalid data private key'}

    if not is_singlesig_hex(data_privkey_info):
        data_privkey_info = ECPrivateKey(data_privkey_info).to_hex()

    encrypted_wallet = _make_encrypted_wallet_data(password, payment_privkey_info, owner_privkey_info, data_privkey_info, test_legacy=test_legacy)

    if 'error' in encrypted_wallet:
        return encrypted_wallet

    # sanity check
    if not test_legacy:
        jsonschema.validate(encrypted_wallet, ENCRYPTED_WALLET_SCHEMA_CURRENT)

    return encrypted_wallet


def make_wallet(password, config_path=CONFIG_PATH, payment_privkey_info=None, owner_privkey_info=None, data_privkey_info=None, test_legacy=False, encrypt=True):
    """
    Make a new, encrypted wallet structure.
    The owner and payment keys will be 2-of-3 multisig key bundles.
    The data keypair will be a single-key bundle.

    Return the new wallet on success.
    Return {'error': ...} on failure
    """
    
    if test_legacy and not BLOCKSTACK_TEST:
        raise Exception("Not in testing but tried to make a legacy wallet")

    # default to 2-of-3 multisig key info if data isn't given
    payment_privkey_info = virtualchain.make_multisig_wallet(2, 3) if payment_privkey_info is None and not test_legacy else payment_privkey_info
    owner_privkey_info = virtualchain.make_multisig_wallet(2, 3) if owner_privkey_info is None and not test_legacy else owner_privkey_info
    data_privkey_info = ECPrivateKey().to_wif() if data_privkey_info is None and not test_legacy else data_privkey_info

    new_wallet = _make_encrypted_wallet_data(password, payment_privkey_info, owner_privkey_info, data_privkey_info, test_legacy=test_legacy)

    if 'error' in new_wallet:
        return new_wallet

    # sanity check
    if not test_legacy:
        jsonschema.validate(new_wallet, ENCRYPTED_WALLET_SCHEMA_CURRENT)

    if encrypt:
        return new_wallet

    # decrypt and return 
    wallet_info = decrypt_wallet(new_wallet, password, config_path=config_path)
    assert 'error' not in wallet_info, "Failed to decrypt new wallet: {}".format(wallet_info['error'])

    return wallet_info['wallet']


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


def decrypt_error(max_tries):
    """
    Generate an appropriate error response, based on 
    why we failed to decrypt data
    """
    ret = {'error': 'Incorrect password'}
    log_failed_decrypt(max_tries=max_tries)
    if not can_attempt_decrypt(max_tries=max_tries):
        log.debug('Incorrect password; using exponential backoff')
        msg = 'Incorrect password.  Try again in {} seconds'
        ret['error'] = msg.format(time_until_next_decrypt_attempt())

    return ret


def make_legacy_wallet_keys(data, password, max_tries=WALLET_DECRYPT_MAX_TRIES):
    """
    Given a legacy wallet with a "master private key",
    generate the owner, payment, and data key values
    Return {'payment': priv, 'owner': priv, 'data': priv} on success
    Return {'error': ...} on error
    """
    legacy_hdwallet = None
    hex_password = hexlify(password)
    try:
        hex_privkey = aes_decrypt(data['encrypted_master_private_key'], hex_password)
        legacy_hdwallet = HDWallet(hex_privkey)
    except Exception as e:
        if BLOCKSTACK_DEBUG is not None:
            log.exception(e)

        ret = decrypt_error(max_tries)
        log.debug('Failed to decrypt encrypted_master_private_key: {}'.format(ret['error']))
        return ret

    # legacy compat: use the master private key to generate child keys.
    # If the specific key they are purposed for is not defined in the wallet,
    # then they are used in its place.
    # This is because originally, the master private key was used to derive
    # the owner, payment, and data private keys; not all wallets define
    # these keys separately (and have instead relied on us being able to
    # generate them from the master private key).
    child_keys = legacy_hdwallet.get_child_keypairs(count=3, include_privkey=True)

    # note: payment_keypair = child[0]; owner_keypair = child[1]
    key_defaults = {
        'payment': child_keys[0][1],
        'owner': child_keys[1][1],
        'data': child_keys[2][1]
    }

    return key_defaults


def make_legacy_wallet_013_keys(data, password, max_tries=WALLET_DECRYPT_MAX_TRIES):
    """
    Given a legacy 0.13 wallet with "owner private key" and "payment private key"
    defined, generate the owner, payment, and data values.

    In these wallets, the data key is the same as the owner key.

    Return {'payment': priv, 'owner': priv, 'data': priv} on success
    Return {'error': ...} on error
    """
    payment_privkey = decrypt_private_key_info(data['encrypted_payment_privkey'], password)
    owner_privkey = decrypt_private_key_info(data['encrypted_owner_privkey'], password)

    err = None
    if 'error' in payment_privkey:
        err = payment_privkey['error']
    else:
        payment_privkey = payment_privkey.pop('private_key_info')

    if 'error' in owner_privkey:
        err = owner_privkey['error']
    else:
        owner_privkey = owner_privkey.pop('private_key_info')

    if err:
        ret = decrypt_error(max_tries)
        log.debug("Failed to decrypt owner or payment keys: {}".format(err))
        return ret
 
    data_privkey = None
    if is_singlesig(owner_privkey):
        data_privkey = owner_privkey
    else:
        data_privkey = owner_privkey['private_keys'][0]

    key_defaults = {
        'payment': payment_privkey,
        'owner': owner_privkey,
        'data': data_privkey
    }

    return key_defaults


def decrypt_wallet(data, password, config_path=CONFIG_PATH,
                   max_tries=WALLET_DECRYPT_MAX_TRIES):
    """
    Decrypt a wallet's encrypted fields.  The wallet will be migrated to the current schema.

    After WALLET_DECRYPT_MAX_TRIES failed attempts, start doing exponential backoff
    to prevent brute-force attacks.

    Migrate the wallet from a legacy format to the latest format, if needed.
    * By default, generate a new data key if there is no data key set (unless owner_key_is_data_key=True,
      in which case, the first owner private key will be set)

    Return {'status': True, 'migrated': True|False, 'wallet': wallet} on success.  
    Return {'error': ...} on failure
    """

    legacy = False
    legacy_013 = False
    is_legacy = False
    migrated = False

    # must match either current schema or legacy schema 
    try:
        jsonschema.validate(data, ENCRYPTED_WALLET_SCHEMA_CURRENT)
    except ValidationError as ve:
        # maybe legacy?
        try:
            jsonschema.validate(data, ENCRYPTED_WALLET_SCHEMA_LEGACY)
            legacy = True
        except ValidationError, ve2:
            try:
                jsonschema.validate(data, ENCRYPTED_WALLET_SCHEMA_LEGACY_013)
                legacy_013 = True
            except ValidationError, ve3:
                if not BLOCKSTACK_TEST:
                    # if in production, this is fatal
                    log.exception(ve2)
        
                log.error('Invalid wallet data')
                return {'error': 'Invalid wallet data'}

    is_legacy = (legacy or legacy_013)

    legacy_hdwallet = None
    key_defaults = {}
    new_wallet = {}
    ret = {}

    if not can_attempt_decrypt(max_tries=max_tries):
        msg = 'Cannot decrypt at this time.  Try again in {} seconds'
        return {'error': msg.format(time_until_next_decrypt_attempt())}

    if legacy:
        # legacy wallets use a hierarchical deterministic private key for owner, payment, and data keys.
        # get that key first, if needed.
        key_defaults = make_legacy_wallet_keys(data, password, max_tries=max_tries)
        if 'error' in key_defaults:
            log.error("Failed to migrate legacy wallet: {}".format(key_defaults['error']))
            return key_defaults

        migrated = True

    elif legacy_013:
        # legacy 0.13 wallets have an owner_privkey and a payment_privkey, but not a data_privkey
        key_defaults = make_legacy_wallet_013_keys(data, password, max_tries=max_tries)
        if 'error' in key_defaults:
            log.error("Failed to migrate legacy 0.13 wallet: {}".format(key_defaults['error']))
            return key_defaults

        migrated = True

    # NOTE: 'owner' must come before 'data', since we may use it to generate the data key
    keynames = ['payment', 'owner', 'data']
    for keyname in keynames:

        # get the key's private key info and address
        keyname_privkey = '{}_privkey'.format(keyname)
        keyname_addresses = '{}_addresses'.format(keyname)
        encrypted_keyname = 'encrypted_{}_privkey'.format(keyname)

        if encrypted_keyname in data:
            # This key was explicitly defined in the wallet.
            # It is not guaranteed to be a child key of the
            # master private key.
            field = decrypt_private_key_info(data[encrypted_keyname], password)

            if 'error' in field:
                ret = decrypt_error(max_tries)
                log.debug('Failed to decrypt {}: {}'.format(encrypted_keyname, ret['error']))
                return ret

            new_wallet[keyname_privkey] = field['private_key_info']
            new_wallet[keyname_addresses] = [field['address']]

        else:

            # Legacy migration: this key is not defined in the wallet
            # use the appopriate default key
            assert is_legacy
            assert keyname in key_defaults, 'BUG: no legacy private key for {}'.format(keyname)

            default_privkey = key_defaults[keyname]
            new_wallet[keyname_privkey] = default_privkey
            new_wallet[keyname_addresses] = [
                virtualchain.BitcoinPrivateKey(default_privkey).public_key().address()
            ]

            migrated = True


    # add data keys. Make sure it's *uncompressed*
    assert new_wallet.has_key('data_privkey')
    data_pubkey = ECPrivateKey(str(new_wallet['data_privkey'])).public_key().to_hex()
    if keylib.key_formatting.get_pubkey_format(data_pubkey) == 'hex_compressed':
        data_pubkey = keylib.key_formatting.decompress(data_pubkey)

    data_pubkey = str(data_pubkey)

    new_wallet['data_pubkeys'] = [data_pubkey]
    new_wallet['data_pubkey'] = data_pubkey
   
    new_wallet['version'] = SERIES_VERSION

    # sanity check--must be decrypted properly
    try:
        jsonschema.validate(new_wallet, WALLET_SCHEMA_CURRENT)
    except ValidationError as e:
        log.exception(e)
        log.error("FATAL: BUG: invalid wallet generated")
        os.abort()

    ret = {
        'status': True,
        'wallet': new_wallet,
        'migrated': migrated
    }

    return ret


def write_wallet(data, path=None, config_path=CONFIG_PATH, test_legacy=False):
    """
    Generate and save the wallet to disk.
    """
    config_dir = os.path.dirname(config_path)
    if path is None:
        path = os.path.join(config_dir, WALLET_FILENAME)

    if test_legacy:
        assert BLOCKSTACK_TEST, 'test_legacy only works in test mode'

    if not test_legacy:
        # must be a current schema
        try:
            jsonschema.validate(data, ENCRYPTED_WALLET_SCHEMA_CURRENT)
        except ValidationError as ve:
            if BLOCKSTACK_DEBUG:
                log.exception(ve)

            return {'error': 'Invalid wallet data'}

    data = json.dumps(data)
    with open(path, 'w') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

    return {'status': True}


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


def initialize_wallet(password='', wallet_path=None, interactive=True, config_dir=CONFIG_DIR):
    """
    Initialize a wallet, interatively if need be.
    Save it to @wallet_path, if successfully generated.

    Return {'status': True, 'wallet': ..., 'wallet_password': ...} on success.
    Return {'error': ...} on error
    """

    config_path = os.path.join(config_dir, CONFIG_FILENAME)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME) if wallet_path is None else wallet_path

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

        wallet = make_wallet(password, config_path=config_path)
        if 'error' in wallet:
            log.error('make_wallet failed: {}'.format(wallet['error']))
            return wallet

        try:
            write_wallet(wallet, path=wallet_path)
        except Exception as e:
            log.exception(e)
            return {'error': 'Failed to write wallet'}

        result['status'] = True
        result['wallet'] = wallet
        result['wallet_password'] = password

        if not interactive:
            return result

        if interactive:
            print('Wallet created. Make sure to backup the following:')
            output = {
                'wallet_password': password,
                'wallet': wallet
            }
            print_result(output)

        input_prompt = 'Have you backed up the above information? (y/n): '
        user_input = raw_input(input_prompt)
        user_input = user_input.lower()

        if user_input != 'y':
            return {'error': 'Please back up your private key first'}

    except KeyboardInterrupt:
        return {'error': 'Interrupted'}

    return result


def get_wallet_path(config_path=CONFIG_PATH):
    """
    Get the path to the wallet
    """
    return os.path.join( os.path.dirname(config_path), WALLET_FILENAME )


def wallet_exists(config_path=CONFIG_PATH, wallet_path=None):
    """
    Does a wallet exist?
    Return True if so
    Return False if not
    """
    config_dir = os.path.dirname(config_path)
    if wallet_path is None:
        wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    return os.path.exists(wallet_path)


def prompt_wallet_password(prompt='Enter wallet password: '):
    """
    Get the wallet password from the user
    """
    password = getpass(prompt)
    return password


def load_wallet(password=None, config_path=CONFIG_PATH, wallet_path=None, interactive=True, include_private=False):
    """
    Get a wallet from disk, and unlock it.
    Requries either a password, or interactive=True
    Return {'status': True, 'migrated': ..., 'wallet': ..., 'password': ...} on success
    Return {'error': ...} on error
    """
    config_dir = os.path.dirname(config_path)
    if wallet_path is None:
        wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    if password is None:
        password = prompt_wallet_password()

    if not os.path.exists(wallet_path):
        return {'error': 'No wallet found'}

    with open(wallet_path, 'r') as f:
        data = f.read()
        data = json.loads(data)

    res = decrypt_wallet(data, password, config_path=config_path)
    if 'error' in res:
        return res

    res['password'] = password
    return res


def backup_wallet(wallet_path):
    """
    Given the path to an on-disk wallet, back it up.
    Return the new path, or None if there is no such wallet.
    """
    if not os.path.exists(wallet_path):
        return None

    legacy_path = wallet_path + ".legacy.{}".format(int(time.time()))
    while os.path.exists(legacy_path):
        time.sleep(1.0)
        legacy_path = wallet_path + ".legacy.{}".format(int(time.time()))

    log.warning('Back up old wallet from {} to {}'.format(wallet_path, legacy_path))
    shutil.move(wallet_path, legacy_path)
    return legacy_path


def migrate_wallet(password=None, config_path=CONFIG_PATH, dry_run=False):
    """
    Migrate the wallet to the latest format.
    Back up the old wallet.
    Optionally do a dry-run to see what would happen.
    Optionally use the owner key as the data key

    Return {'status': True, 'backup_wallet': ..., 'wallet': ..., 'wallet_password': ..., 'migrated': True} on success
    Return {'status': True, 'wallet': ..., 'wallet_password': ..., 'migrated': False} if no migration was necessary.
    Return {'error': ...} on error
    """
    config_dir = os.path.dirname(config_path)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    wallet_info = load_wallet(password=password, wallet_path=wallet_path, config_path=config_path, include_private=True)
    if 'error' in wallet_info:
        return wallet_info

    wallet = wallet_info['wallet']
    password = wallet_info['password']

    if not wallet_info['migrated']:
        return {'status': True, 'migrated': False, 'wallet': wallet, 'wallet_password': password}

    encrypted_wallet = encrypt_wallet(wallet, password)
    if 'error' in encrypted_wallet:
        return encrypted_wallet

    # back up 
    old_path = None
    if not dry_run:
        old_path = backup_wallet(wallet_path)

        # store
        res = write_wallet(encrypted_wallet, path=wallet_path)
        if not res:
            # try to restore
            shutil.copy(old_path, wallet_path)
            return {'error': 'Failed to store migrated wallet.'}

    return {'status': True, 'migrated': True, 'backup_wallet': old_path, 'wallet': wallet, 'wallet_password': password}


def unlock_wallet(password=None, config_dir=CONFIG_DIR, wallet_path=None):
    """
    Unlock the wallet, and store it to the running RPC daemon.
    
    This will only work if the wallet is in the latest supported state.
    Otherwise, the caller may need to migrate the wallet first.
    
    Return {'status': True} on success
    return {'error': ...} on error
    """
    config_path = os.path.join(config_dir, CONFIG_FILENAME)
    wallet_path = os.path.join(config_dir, WALLET_FILENAME) if wallet_path is None else wallet_path

    if is_wallet_unlocked(config_dir):
        return {'status': True}

    try:
        if password is None:
            password = prompt_wallet_password()

        with open(wallet_path, "r") as f:
            data = f.read()
            data = json.loads(data)

        # decrypt...
        wallet_info = decrypt_wallet( data, password, config_path=config_path )
        if 'error' in wallet_info:
            log.error('Failed to decrypt wallet: {}'.format(wallet_info['error']))
            return wallet_info

        wallet = wallet_info['wallet']
        if wallet_info['migrated']:
            # need to have the user migrate the wallet first
            return {'error': 'Wallet is in legacy format.  Please migrate it with the `migrate_wallet` command.', 'legacy': True}

        # save to RPC daemon
        try:
            res = save_keys_to_memory( wallet, config_path=config_path )
        except KeyError as ke:
            if BLOCKSACK_DEBUG is not None:
                data = json.dumps(wallet, indent=4, sort_keys=True)
                log.error('data:\n{}\n'.format(data))
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


def is_wallet_unlocked(config_dir=CONFIG_DIR):
    """
    Determine whether or not the wallet is unlocked.
    Do so by asking the local RPC backend daemon
    """
    config_path = os.path.join(config_dir, CONFIG_FILENAME)
    local_proxy = local_api_connect(config_dir=config_dir)
    conf = config.get_config(config_path)

    if not local_proxy:
        return False

    try:
        wallet_data = local_proxy.backend_get_wallet()
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
    local_proxy = local_api_connect(config_dir=os.path.dirname(config_path))
    conf = config.get_config(config_path)

    if not local_proxy:
        return None

    try:
        wallet_data = local_proxy.backend_get_wallet()
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


def save_keys_to_memory( wallet_keys, config_path=CONFIG_PATH ):
    """
    Save keys to the running RPC backend
    Each keypair must be a list or tuple with 2 items: the address, and the private key information.
    (Note that the private key information can be a multisig info dict).

    Return {'status': True} on success
    Return {'error': ...} on error
    """
    config_dir = os.path.dirname(config_path)
    proxy = local_api_connect(config_dir=config_dir)

    log.debug('Saving keys to memory')
    try:
        data = proxy.backend_set_wallet(wallet_keys)
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
        
        # best we can do is guarantee that this is a dict
        assert isinstance(data, dict)
    except:
        log.error('Invalid wallet data: not a JSON object (in {})'.format(wallet_path))
        return None, None, None 
   
    # extract addresses
    if data.has_key('payment_addresses'):
        payment_address = str(data['payment_addresses'][0])
    if data.has_key('owner_addresses'):
        owner_address = str(data['owner_addresses'][0])
    if data.has_key('data_pubkeys'):
        data_pubkey = str(data['data_pubkeys'][0])

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
        balance = get_balance(payment_address, config_path=config_path)
        if balance is None:
            payment_addresses.append( {'error': 'Failed to get balance for {}'.format(payment_address)} )

        else:
            payment_addresses.append({'address': payment_address,
                                      'balance': balance})

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
    """
    Get back the list of all names owned by the given wallet.
    Return [names] on success
    Return [{'error': ...}] on failure
    """
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

    Returns units, addresses on success
    Returns None, {'error': ...} on error
    """
    payment_addresses = get_payment_addresses_and_balances(wallet_path=wallet_path, config_path=config_path)
    total_balance = 0.0

    for entry in payment_addresses:
        if 'balance' in entry.keys():
            total_balance += entry['balance']

        elif 'error' in entry:
            # failed to look up 
            return None, entry

    return total_balance, payment_addresses


def wallet_setup(config_path=CONFIG_PATH, interactive=True, wallet_data=None, wallet_path=None, password=None, dry_run=False, test_legacy=False):
    """
    Do one-time wallet setup.
    * make sure the wallet exists (creating it if need be)
    * migrate the wallet if it is in legacy format

    Return {'status': True, 'created': False, 'migrated': False, 'password': ..., 'wallet'; ... } on success
    Return {'status': True, 'created'; True, 'migrated': False, 'password': ..., 'wallet': ...} if we had to create the wallet
    Return {'status': True, 'created': False, 'migrated': True, 'password': ..., 'wallet': ...} if we had to migrate the wallet
    Optionally also include 'backup_wallet': ... if the wallet was migrated
    """
    
    config_dir = os.path.dirname(config_path)
    if wallet_path is None:
        wallet_path = os.path.join(config_dir, WALLET_FILENAME)

    wallet = None
    created = False
    migrated = False
    backup_path = None

    if not wallet_exists(wallet_path=wallet_path):
        # create
        if wallet_data is None:
            res = initialize_wallet(wallet_path=wallet_path, password=password, interactive=interactive)
            if 'error' in res:
                return res
        
            created = True
            password = res['wallet_password']
            wallet = res['wallet']

        else:
            # make sure up-to-date
            wallet = wallet_data
            encrypted_wallet = encrypt_wallet(wallet, password, test_legacy=test_legacy)
            if 'error' in encrypted_wallet:
                return encrypted_wallet

            res = decrypt_wallet(encrypted_wallet, password, config_path=config_path)
            if 'error' in res:
                return res

            wallet = res['wallet']
            migrated = res['migrated']

            res = write_wallet(wallet, path=wallet_path)
            if 'error' in res:
                return res

    if not created:
        # try to migrate
        res = migrate_wallet(password=password, config_path=config_path, dry_run=dry_run)
        if 'error' in res:
            return res

        if res['migrated']:
            migrated = True

        password = res['wallet_password']
        wallet = res['wallet']
        backup_path = res.get('backup_wallet', None)
    
    res = {
        'status': True,
        'migrated': migrated,
        'created': created,
        'wallet': wallet,
        'password': password,
    }

    if backup_path:
        res['backup_wallet'] = backup_path

    return res

