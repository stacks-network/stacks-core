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

import sys

from time import sleep

from .nameops import preorder, register, update, transfer

from .states import nameRegistered
from .states import profileonBlockchain, profileonDHT
from .states import ownerName, registrationComplete

from .network import write_dht_profile

from .config import RATE_LIMIT, DHT_IGNORE
from .config import SLEEP_INTERVAL

from .utils import config_log

from .db import preorder_queue

from .queue import alreadyinQueue

from .wallet import get_addresses
from .blockchain import dontuseAddress, underfundedAddress

log = config_log(__name__)

index = 0
payment_addresses = []
owner_addresses = []

"""
    Registrar/server handles loadbalancing and is the entry
    point for sending nameops
"""


def init_addresses_in_use():
    """ Initialize registrar addresses

        @payment_addresses: used for funding transactions
        @owner_addresses: intermediate owner for names registered
    """

    global payment_addresses
    global owner_addresses

    payment_addresses = get_addresses(count=RATE_LIMIT)

    # change the positions by 1, so that different payment and owner addresses
    # are at a given index for the two lists
    owner_addresses = [payment_addresses[-1]] + payment_addresses[:-1]


# initialize the list of addresses
init_addresses_in_use()


def get_next_addresses():
    """ Get next set of addresses that are ready to use

        Returns (payment_address, owner_address)
    """

    global index
    global payment_addresses
    global owner_addresses

    payment_address = payment_addresses[index]

    def increment_index():

        global index

        if index == RATE_LIMIT - 1:
            index = 0
        else:
            index += 1

    log.debug("Getting new payment address")
    counter = 0

    while(1):
        # find an address that can be used for payment

        if dontuseAddress(payment_address):
            increment_index()

            payment_address = payment_addresses[index]

        elif underfundedAddress(payment_address):
            print "underfunded %s: " % payment_address
            increment_index()
            payment_address = payment_addresses[index]

        else:
            break

        counter += 1

        if counter == RATE_LIMIT:
            log.debug("All addresses were recently used. Sleeping")
            sleep(SLEEP_INTERVAL)
            counter = 0

    owner_address = owner_addresses[index]

    return payment_address, owner_address


def process_nameop(fqu, profile, transfer_address, nameop=None):
    """ Given the state of the name, process new nameop

        @fqu: the fully qualified name
        @profile: json profile associated with fqu
        @transfer_address: address that should own fqu after transfer

        Optional parameter:
        @nameop: process all nameop types or only a specific type
                 values can be 'preorder', 'register', 'update', 'transfer'

        Returns True, if sent a tx on blockchain (for tracking rate limiting)
    """

    if not nameRegistered(fqu):
        log.debug("Not registered: %s" % fqu)

        if alreadyinQueue(preorder_queue, fqu):
            if nameop is None or nameop is 'register':
                return register(fqu, auto_preorder=False)
        else:
            if nameop is None or nameop is 'preorder':
                # loadbalancing happens in get_next_addresses()
                payment_address, owner_address = get_next_addresses()
                return preorder(fqu, payment_address, owner_address)

    elif not profileonBlockchain(fqu, profile):

        if nameop is None or nameop is 'update':
            log.debug("Updating profile on blockchain: %s" % fqu)
            return update(fqu, profile)

    elif not profileonDHT(fqu, profile):

        if fqu not in DHT_IGNORE:
            log.debug("Writing profile to DHT: %s" % fqu)
            write_dht_profile(profile)

        return False  # because not a blockchain operation

    elif not ownerName(fqu, transfer_address):

        if nameop is None or nameop is 'transfer':
            log.debug("Transferring name: %s" % fqu)
            return transfer(fqu, transfer_address)

    log.debug("Nameop didn't meet any conditions")
    return False  # no blockchain tx was sent
