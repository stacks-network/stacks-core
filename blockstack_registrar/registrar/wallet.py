#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~

    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

This file is part of Registrar.

    Registrar is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Registrar is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Registrar. If not, see <http://www.gnu.org/licenses/>.
"""

import os
import json
import traceback

from keychain import PrivateKeychain

from pybitcoin import make_send_to_address_tx
from pybitcoin import BlockcypherClient
from pybitcoin.rpc.bitcoind_client import BitcoindClient

from crypto.utils import get_address_from_privkey, get_pubkey_from_privkey

from .utils import pretty_print as pprint
from .utils import config_log
from .utils import btc_to_satoshis

from .config import RATE_LIMIT
from .config import LOCAL_DIR, CACHE_FILE_FULLPATH
from .config import BLOCKCYPHER_TOKEN
from .config import TARGET_BALANCE_PER_ADDRESS, TX_FEE
from .config import CHAINED_PAYMENT_AMOUNT, MINIMUM_BALANCE
from .config import DEFAULT_CHILD_ADDRESSES
from .config import HD_WALLET_PRIVKEY, DEFAULT_REFILL_AMOUNT

from .blockchain import get_balance, dontuseAddress
from .blockchain import underfundedAddress

from blockcypher import pushtx
from blockcypher import create_unsigned_tx, make_tx_signatures
from blockcypher import broadcast_signed_transaction

log = config_log(__name__)
blockcypher_client = BlockcypherClient(api_key=BLOCKCYPHER_TOKEN)


class HDWallet(object):

    """
        Initialize a hierarchical deterministic wallet with
        hex_privkey and get child addresses and private keys
    """

    def __init__(self, hex_privkey=None, enable_cache=False):

        """
            If @hex_privkey is given, use that to derive keychain
            otherwise, use a new random seed
        """

        if hex_privkey:
            self.priv_keychain = PrivateKeychain.from_private_key(hex_privkey)
        else:
            #log.debug("No privatekey given, starting new wallet")
            self.priv_keychain = PrivateKeychain()

        self.master_address = self.get_master_address()
        self.child_addresses = None

        if enable_cache:
            cache = self.get_cache()

            if cache is not None:

                if cache['master_address'] == self.master_address:
                    self.child_addresses = cache['child_addresses']
                else:
                    log.debug("Wallet already exists with master address: %s" % cache['master_address'])
            else:
                #log.debug("Creating cache of HD wallet addresses ...")
                self.create_addresses_cache()

    def create_addresses_cache(self, count=DEFAULT_CHILD_ADDRESSES):

        if self.get_cache() is not None:
            return True

        child_addresses = []

        for index in range(0, count):
            hex_privkey = self.get_child_privkey(index)
            address = self.get_child_address(index)

            child_addresses.append(address)

        if not os.path.exists(LOCAL_DIR):
            os.makedirs(LOCAL_DIR)

        with open(CACHE_FILE_FULLPATH, 'w') as cache_file:
            data = {'child_addresses': child_addresses}
            data['master_address'] = self.get_master_address()
            cache_file.write(json.dumps(data))

        return True

    def get_cache(self):

        if not os.path.isfile(CACHE_FILE_FULLPATH):
            return None

        try:
            with open(CACHE_FILE_FULLPATH, 'r') as cache_file:
                data = json.loads(cache_file.read())

            return data
        except:
            return None

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

    def get_next_keypair(self, count=DEFAULT_CHILD_ADDRESSES):
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

    def get_privkey_from_address(self, target_address,
                                 count=DEFAULT_CHILD_ADDRESSES):
        """ Given a child address, return priv key of that address
        """

        addresses = self.get_child_keypairs(count=count)

        index = 0

        for address in addresses:

            if address == target_address:

                return self.get_child_privkey(index)

            index += 1

        return None

# global default wallet
wallet = HDWallet(HD_WALLET_PRIVKEY)


def get_underfunded_addresses(list_of_addresses):
    """
        Given a list of addresses, return the underfunded ones
    """

    underfunded_addresses = []

    for address in list_of_addresses:

        balance = get_balance(address)

        if balance <= float(MINIMUM_BALANCE):
            log.debug("address %s needs refill: %s"
                      % (address, balance))

            underfunded_addresses.append(address)

    return underfunded_addresses


def send_payment(hex_privkey, to_address, btc_amount):

    payment_address = get_address_from_privkey(hex_privkey)

    if dontuseAddress(payment_address):
        log.debug("Payment address %s not ready" % payment_address)
        return None

    to_satoshis = btc_to_satoshis(btc_amount)
    fee_satoshis = btc_to_satoshis(TX_FEE)

    signed_tx = make_send_to_address_tx(to_address, to_satoshis, hex_privkey,
                                        blockchain_client=blockcypher_client,
                                        fee=fee_satoshis)

    resp = pushtx(tx_hex=signed_tx, api_key=BLOCKCYPHER_TOKEN)

    if 'tx' in resp:
        return resp['tx']['hash']
    else:
        log.debug("ERROR: broadcasting tx")
        return resp


def send_multi_payment(payment_privkey, list_of_addresses, payment_per_address):

    payment_address = get_address_from_privkey(payment_privkey)

    if dontuseAddress(payment_address):
        log.debug("Payment address %s not ready" % payment_address)
        return None

    inputs = [{'address': payment_address}]
    payment_in_satoshis = btc_to_satoshis(float(payment_per_address))
    outputs = []

    for address in list_of_addresses:
        outputs.append({'address': address, 'value': int(payment_in_satoshis)})

    unsigned_tx = create_unsigned_tx(inputs=inputs, outputs=outputs,
                                     api_key=BLOCKCYPHER_TOKEN)

    # iterate through unsigned_tx['tx']['inputs'] to find each address in order
    # need to include duplicates as many times as they may appear
    privkey_list = []
    pubkey_list = []

    for input in unsigned_tx['tx']['inputs']:
        privkey_list.append(payment_privkey)
        pubkey_list.append(get_pubkey_from_privkey(payment_privkey))

    tx_signatures = make_tx_signatures(txs_to_sign=unsigned_tx['tosign'],
                                       privkey_list=privkey_list,
                                       pubkey_list=pubkey_list)

    resp = broadcast_signed_transaction(unsigned_tx=unsigned_tx,
                                        signatures=tx_signatures,
                                        pubkeys=pubkey_list)

    if 'tx' in resp:
        return resp['tx']['hash']
    else:
        return None


def display_wallet_info(list_of_addresses):

    addresses = []
    addresses.append(wallet.get_master_address())
    addresses += list_of_addresses

    total_balance = 0

    for address in addresses:
        has_pending_tx = dontuseAddress(address)
        balance_on_address = get_balance(address)
        log.debug("(%s, balance %s,\t pending %s)" % (address,
                                                      balance_on_address,
                                                      has_pending_tx))
        if balance_on_address is not None:
            total_balance += balance_on_address

    log.debug("Total addresses: %s" % len(addresses))
    log.debug("Total balance: %s" % total_balance)


def refill_wallet(count=DEFAULT_CHILD_ADDRESSES, offset=0,
                  payment=DEFAULT_REFILL_AMOUNT,
                  live=False):

    list_of_addresses = wallet.get_child_keypairs(count=count, offset=offset)

    underfunded_addresses = get_underfunded_addresses(list_of_addresses)

    if live:

        try:
            tx_hash = send_multi_payment(str(HD_WALLET_PRIVKEY), underfunded_addresses, payment)
        except:
            log.debug(traceback.print_exc())
        else:
            log.debug("Sent: %s" % tx_hash)

    display_wallet_info(underfunded_addresses)


def display_names_wallet_owns(list_of_addresses):

    for address in list_of_addresses:

        names_owned = c.get_names_owned_by_address(address)

        if len(names_owned) is not 0:
            log.debug("Address: %s" % address)
            log.debug("Names owned: %s" % names_owned)
            log.debug('-' * 5)


def initialize_watch_only_addresses(bicoind_server, bitcoind_port,
                                    bitcoind_user, bicoind_passwd,
                                    use_https):
    """
        Add all addresses from HD Wallet as watch-only addresses
        at the given bitcoind server (UTXO provider)
    """

    child_addresses = wallet.get_child_keypairs(count=DEFAULT_CHILD_ADDRESSES)

    client = BitcoindClient(server=bitcoind_server, port=bitcoind_port,
                            user=bitcoind_user,
                            passwd=bitcoind_passwd,
                            use_https=use_https)

    for address in child_addresses:
        resp = client.importaddress(address, 'registrar', False)

        if resp == "None":
            log.debug("Added watch-only address: %s" % address)

if __name__ == '__main__':

    log.debug("wallet.py")
    #refill_wallet(count=10, offset=90, payment=DEFAULT_REFILL_AMOUNT, live=False)
