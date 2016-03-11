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
import pybitcoin
import subprocess
from socket import error as socket_error
from time import sleep
from getpass import getpass

import requests
requests.packages.urllib3.disable_warnings()

import logging
logging.disable(logging.CRITICAL)

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)
import xmlrpclib

from registrar.config import REGISTRAR_IP, REGISTRAR_PORT
from registrar.config import BLOCKSTACKD_IP, BLOCKSTACKD_PORT

from registrar.wallet import HDWallet
from registrar.crypto.utils import aes_encrypt, aes_decrypt
from registrar.blockchain import get_balance, dontuseAddress
from registrar.network import get_bs_client
from registrar.rpc_daemon import background_process
from registrar.utils import satoshis_to_btc
from registrar.states import nameRegistered, ownerName, profileonBlockchain
from registrar.blockchain import recipientNotReady, get_tx_confirmations

RPC_DAEMON = 'http://' + REGISTRAR_IP + ':' + str(REGISTRAR_PORT)

def initialize_wallet():

    result = {}
    print "Initializing new wallet ..."
    password = "temp"

    try:
        while len(password) < WALLET_PASSWORD_LENGTH:
            password = getpass("Enter new password: ")

            if len(password) < WALLET_PASSWORD_LENGTH:
                msg = "Password is too short. Please make it at"
                msg += " least %s characters long" % WALLET_PASSWORD_LENGTH
                print msg
            else:

                confirm_password = getpass("Confirm new password: ")

                if password != confirm_password:
                    exit_with_error("Passwords don't match.")

                temp_wallet = HDWallet()
                hex_privkey = temp_wallet.get_master_privkey()

                hex_password = hexlify(password)

                wallet = HDWallet(hex_privkey)
                child = wallet.get_child_keypairs(count=3)

                data = {}
                encrypted_key = aes_encrypt(hex_privkey, hex_password)
                data['encrypted_master_private_key'] = encrypted_key
                data['payment_addresses'] = [child[0]]
                data['owner_addresses'] = [child[1]]
                data['data_address'] = [child[2]]

                file = open(WALLET_PATH, 'w')
                file.write(json.dumps(data))
                file.close()

                print "Wallet created. Make sure to backup the following:"

                result['wallet_password'] = password
                result['master_private_key'] = hex_privkey
                print_result(result)

                input_prompt = "Have you backed up the above private key? (y/n): "
                user_input = raw_input(input_prompt)
                user_input = user_input.lower()

                if user_input != 'y':
                    exit_with_error("Please backup your private key first.")

    except KeyboardInterrupt:
        exit_with_error("\nExited.")

    return result


def unlock_wallet(display_enabled=False):

    if walletUnlocked():
        if display_enabled:
            payment_address, owner_address = get_addresses_from_file()
            display_wallet_info(payment_address, owner_address)
    else:

        try:
            password = getpass("Enter wallet password: ")
            hex_password = hexlify(password)

            file = open(WALLET_PATH, 'r')
            data = file.read()
            data = json.loads(data)
            file.close()
            hex_privkey = None
            try:
                hex_privkey = aes_decrypt(data['encrypted_master_private_key'],
                                          hex_password)
            except:
                exit_with_error("Incorrect password.")
            else:
                print "Unlocked wallet."
                wallet = HDWallet(hex_privkey)
                child = wallet.get_child_keypairs(count=3,
                                                  include_privkey=True)
                payment_keypair = child[0]
                owner_keypair = child[1]
                data_keypair = child[2]
                save_keys_to_memory(payment_keypair, owner_keypair, data_keypair)

                if display_enabled:
                    display_wallet_info(payment_keypair[0], owner_keypair[0], data_keypair[0])
        except KeyboardInterrupt:
            print "\nExited."


def walletUnlocked():

    local_proxy = get_local_proxy()
    conf = config.get_config()

    if local_proxy is not False:

        wallet_data = local_proxy.get_wallet(conf['rpc_token'])
        wallet_data = json.loads(wallet_data)

        if 'error' in wallet_data:
            return False
        elif wallet_data['payment_address'] is None:
            return False
        else:
            return True
    else:
        return False


def get_wallet():
    """
    Get the decrypted wallet from the running wallet daemon.
    """
    local_proxy = get_local_proxy()
    conf = config.get_config()

    if local_proxy is not False:

        wallet_data = local_proxy.get_wallet(conf['rpc_token'])
        wallet_data = json.loads(wallet_data)

        if 'error' in wallet_data:
            return None

        return wallet_data

    else:
        return None


def display_wallet_info(payment_address, owner_address, data_address):

    print '-' * 60
    print "Payment address:\t%s" % payment_address
    print "Owner address:\t\t%s" % owner_address
    print "Data address:\t\t%s" % data_address
    print '-' * 60
    print "Balance:"
    print "%s: %s" % (payment_address, get_balance(payment_address))
    print '-' * 60

    print "Names Owned:"
    names_owned = get_names_owned(owner_address)
    print "%s: %s" % (owner_address, names_owned)
    print '-' * 60


def get_names_owned(address):

      # hack to ensure local, until we update client
    from blockstack_client import client as bs_client
    # start session using blockstack_client
    bs_client.session(server_host=BLOCKSTACKD_IP, server_port=BLOCKSTACKD_PORT,
                      set_global=True)

    try:
        names_owned = bs_client.get_names_owned_by_address(address)
    except socket_error:
        names_owned = "Error connecting to server"

    return names_owned


def get_local_proxy():

    proxy = xmlrpclib.ServerProxy(RPC_DAEMON)

    try:
        data = proxy.ping()
    except:
        log.debug('RPC daemon is not online')
        return False

    return proxy


def start_background_daemons():
    """ Start the rpc_daemon and monitor processes
        if they're not already running
    """

    proxy = xmlrpclib.ServerProxy(RPC_DAEMON)

    try:
        data = proxy.ping()
    except:
        background_process('start_daemon')
        sleep(2)

    output = findProcess('start_monitor')

    if 'registrar.rpc_daemon' not in output:
        background_process('start_monitor')
        sleep(2)


def save_keys_to_memory(payment_keypair, owner_keypair, data_keypair):

    proxy = get_local_proxy()

    if proxy is False:
        start_background_daemons()

    try:
        data = proxy.set_wallet(payment_keypair, owner_keypair, data_keypair)
    except:
        exit_with_error('Error talking to local proxy')


def get_addresses_from_file():

    file = open(WALLET_PATH, 'r')
    data = file.read()
    data = json.loads(data)
    file.close()

    payment_address = data['payment_addresses'][0]
    owner_address = data['owner_addresses'][0]

    return payment_address, owner_address


def get_payment_addresses():

    payment_addresses = []

    # currently only using one
    payment_address, owner_address = get_addresses_from_file()

    payment_addresses.append({'address': payment_address,
                              'balance': get_balance(payment_address)})

    return payment_addresses


def get_owner_addresses():

    owner_addresses = []

    # currently only using one
    payment_address, owner_address = get_addresses_from_file()

    owner_addresses.append({'address': owner_address,
                            'names_owned': get_names_owned(owner_address)})

    return owner_addresses


def get_all_names_owned():

    owner_addresses = get_owner_addresses()

    names_owned = []

    for entry in owner_addresses:

        additional_names = get_names_owned(entry['address'])
        for name in additional_names:
            names_owned.append(name)

    return names_owned


def get_total_balance():

    payment_addresses = get_payment_addresses()

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


def findProcess(processName):
    ps = subprocess.Popen("ps -ef | grep "+processName, shell=True,
                          stdout=subprocess.PIPE)
    output = ps.stdout.read()
    ps.stdout.close()
    ps.wait()
    return output


def get_profile_public_key():

