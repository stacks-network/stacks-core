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

from pybitcoin import BitcoinPrivateKey, make_send_to_address_tx
from pybitcoin import BlockcypherClient

from crypto.utils import aes_encrypt, aes_decrypt
from crypto.utils import get_address_from_privkey

from .utils import pretty_print as pprint
from .utils import config_log
from .utils import btc_to_satoshis

from .db import registrar_users, registrar_addresses

from .config import SECRET_KEY, RATE_LIMIT
from .config import BLOCKCYPHER_TOKEN
from .config import TARGET_BALANCE_PER_ADDRESS, TX_FEE
from .config import CHAINED_PAYMENT_AMOUNT, MINIMUM_BALANCE
from .config import MAX_LENGTH_CHAINED_PAYMENT

from .network import bs_client as c
from .blockchain import get_balance, dontuseAddress

#from blockcypher import simple_spend_tx
from blockcypher import pushtx

log = config_log(__name__)
blockcypher_client = BlockcypherClient(api_key=BLOCKCYPHER_TOKEN)


def get_registrar_users():
    """ Display users where registrar currently has the private key
    """

    counter = 0

    for entry in registrar_users.find():

        fqu = entry['username'] + ".id"

        data = c.get_name_blockchain_record(fqu)

        if 'error' in data:
            log.debug("Error while processing: (%s, %s)" % (fqu, data))
            continue

        if entry['btc_address'] != data['address']:
            log.debug("registrar doesn't own: %s" % fqu)
            continue

        log.debug(pprint(entry))
        log.debug('-' * 5)

        counter += 1

    log.debug("Total names: %s" % counter)


def test_registrar_users():
    """ Test if registrar has access to correct private keys
    """

    for entry in registrar_users.find():

        fqu = entry['username'] + ".id"

        data = c.get_name_blockchain_record(fqu)

        if 'error' in data:
            log.debug("Error while processing: (%s, %s)" % (fqu, data))
            continue

        if entry['btc_address'] != data['address']:
            log.debug("registrar doesn't own: %s" % fqu)
            continue

        privkey = aes_decrypt(entry['encrypted_privkey'], SECRET_KEY)

        if get_address_from_privkey(privkey) == entry['btc_address']:
            log.debug("Correct pvtkey: %s" % fqu)
        else:
            log.debug("ERROR: wrong pvtkey: %s")


def get_privkey(address):
    """ given an address, get decrypted hex private key from DB
    """

    entry = registrar_addresses.find_one({"address": address})

    if entry is None:
        log.debug("Address not found in DB, can't fetch privkey")
        return None

    encrypted_privkey = entry['encrypted_privkey']
    hex_privkey = aes_decrypt(encrypted_privkey, SECRET_KEY)

    return hex_privkey


def get_addresses(count=50, offset=0):
    """ return all bitcoin addresses registrar is using
    """

    addresses = []

    ignore_counter = 0
    counter = 0

    for entry in registrar_addresses.find():

        if ignore_counter < offset:
            ignore_counter += 1
            continue

        addresses.append(entry['address'])

        counter += 1

        if counter == count:
            break

    return addresses


def get_underfunded_addresses(length_chain=MAX_LENGTH_CHAINED_PAYMENT):

    addresses = []

    counter = 0

    for entry in registrar_addresses.find():

        address = entry['address']
        balance = get_balance(address)

        if balance <= float(MINIMUM_BALANCE):
            log.debug("address %s needs refill: %s"
                      % (address, balance))

            if dontuseAddress(address):
                log.debug("address %s has pending tx" % address)
            else:
                addresses.append(entry['address'])

        counter += 1

        # can't use more addresses from wallet than rate limit
        if counter == RATE_LIMIT:
            break

        # can't be more than intended length of chained payment
        if len(addresses) == length_chain:
            break

    return addresses


def generate_bitcoin_keypairs(number_of_addresses=50):
    """ This function:
        1) generates new bitcoin keypairs
        2) saves encrypted private keys
        private keys are encrypted with SECRET_KEY
    """

    if registrar_addresses.find().count() >= number_of_addresses:
        log.debug("Already have enough addresses")
        return

    no_of_new_addresses = number_of_addresses - registrar_addresses.find().count()

    for count in range(1, no_of_new_addresses + 1):

        privkey = BitcoinPrivateKey()
        hex_privkey = privkey.to_hex()
        encrypted_privkey = aes_encrypt(hex_privkey, SECRET_KEY)

        address = get_address_from_privkey(hex_privkey)
        log.debug("Creating new address (count, address): (%s, %s):" % (count, address))

        new_entry = {}
        new_entry['encrypted_privkey'] = encrypted_privkey
        new_entry['address'] = address

        registrar_addresses.save(new_entry)


def send_payment(hex_privkey, to_address, btc_amount):

    to_satoshis = btc_to_satoshis(btc_amount)
    fee_satoshis = btc_to_satoshis(TX_FEE)

    signed_tx = make_send_to_address_tx(to_address, to_satoshis, hex_privkey,
                                        blockchain_client=blockcypher_client,
                                        fee=fee_satoshis)

    resp = pushtx(tx_hex=signed_tx)

    if 'tx' in resp:
        return resp['tx']['hash']
    else:
        log.debug("ERROR: broadcasting tx")
        return resp


def send_chained_payment(btc_per_address, list_of_addresses, list_of_privkeys,
                         live=False):
    """ Sends BTC from head of chain to rest of address list

    @btc_per_address: btc to send per address in list
    @list_of_addresses: list of addresses in the chain
                        first address is used to start chained payment
    @list_of_privkeys: the corresponding priv keys

    Return True/False.
    """

    no_of_addresses = len(list_of_addresses) - 1
    index = 0

    starting_amount = no_of_addresses * btc_per_address

    btc_amount = starting_amount

    while(index < no_of_addresses):

        from_address = list_of_addresses[index]
        hex_privkey = list_of_privkeys[index]
        to_address = list_of_addresses[index + 1]

        log.debug("sending %s BTC from %s to %s: "
                  % (btc_amount, from_address, to_address))

        if live:
            send_payment(hex_privkey, to_address, btc_amount)

        btc_amount -= btc_per_address
        index += 1


def construct_payment_chain(source_address, no_of_addresses, offset=None):
    """ Makes properly formatted lists for making chained payments

        @source_address: goes at the head of chain
                         used to fund the entire chained payment
        @no_of_addresses: no of additional addresses to add to chained payment
        @offset: the offset for which addresses to pick from DB

        Returns:
        @list_of_addresses: the chained payment addresses as a list
        @list_of_privkeys: associated private keys
    """

    list_of_addresses = []
    list_of_privkeys = []

    list_of_addresses.append(source_address)

    #send_to_addresses = get_addresses(no_of_addresses, offset)
    send_to_addresses = get_underfunded_addresses(no_of_addresses)

    for address in send_to_addresses:
        list_of_addresses.append(str(address))

    for address in list_of_addresses:
        list_of_privkeys.append(get_privkey(address))

    return list_of_addresses, list_of_privkeys


def display_wallet_info(number_of_addresses=RATE_LIMIT):

    addresses = get_addresses(count=number_of_addresses)
    total_balance = 0

    for address in addresses:
        has_pending_tx = dontuseAddress(address)
        balance_on_address = get_balance(address)
        log.debug("(%s, balance %s,\t pending %s)" % (address,
                                                      balance_on_address,
                                                      has_pending_tx))
        total_balance += balance_on_address

    log.debug("Total addresses: %s" % len(addresses))
    log.debug("Total balance: %s" % total_balance)


def refill_wallet(source_address, live=False):

    list_of_addresses, list_of_privkeys = construct_payment_chain(source_address,
                                                                  MAX_LENGTH_CHAINED_PAYMENT)
    send_chained_payment(CHAINED_PAYMENT_AMOUNT, list_of_addresses,
                         list_of_privkeys, live=live)
