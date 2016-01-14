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

from .nameops import preorder, register, update, transfer
from .subsidized_nameops import subsidized_update

from .states import nameRegistered
from .states import profileonBlockchain, profileonDHT
from .states import ownerName, registrationComplete

from .network import write_dht_profile

from .config import RATE_LIMIT, DHT_IGNORE
from .config import SLEEP_INTERVAL

from .utils import config_log

from .db import preorder_queue

from .queue import alreadyinQueue

from .wallet import wallet
from .blockchain import dontuseAddress, underfundedAddress

log = config_log(__name__)


class RegistrarServer(object):
    """
        Registrar/server handles loadbalancing and is the entry
        point for sending nameops
    """

    def __init__(self):
        """ Initialize registrar addresses

            @payment_addresses: used for funding transactions
            @owner_addresses: intermediate owner for names registered
        """

        self.index = 0
        self.all_addresses_in_use = False
        self.payment_addresses = wallet.get_child_keypairs(count=RATE_LIMIT)

        # change the positions by 1, so that different payment and
        # owner addresses are at a given index for the two lists
        self.owner_addresses = [self.payment_addresses[-1]] + self.payment_addresses[:-1]

    def increment_index(self):

        if self.index == RATE_LIMIT - 1:
            self.index = 0
        else:
            self.index += 1

    def get_next_addresses(self):
        """ Get next set of addresses that are ready to use

            Returns (payment_address, owner_address)
        """

        if(self.all_addresses_in_use):
            return None, None

        payment_address = self.payment_addresses[self.index]

        #log.debug("Getting new payment address")
        counter = 0

        while(1):
            # find an address that can be used for payment

            if dontuseAddress(payment_address):
                self.increment_index()
                payment_address = self.payment_addresses[self.index]

            elif underfundedAddress(payment_address):
                log.debug("Underfunded address: %s" % payment_address)
                self.increment_index()
                payment_address = self.payment_addresses[self.index]

            else:
                break

            counter += 1

            if counter == RATE_LIMIT:
                log.debug("All addresses were recently used.")
                self.all_addresses_in_use = True
                return None, None

        owner_address = self.owner_addresses[self.index]

        return payment_address, owner_address

    def reset_flag(self):
        self.all_addresses_in_use = False

    def process_nameop(self, fqu, profile, transfer_address, nameop=None):
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
            #log.debug("Not registered: %s" % fqu)

            if alreadyinQueue(preorder_queue, fqu):
                if nameop is None or nameop == 'register':
                    log.debug("Registering: %s" % fqu)
                    return register(fqu, auto_preorder=False)
            else:
                if nameop is None or nameop is 'preorder':
                    #log.debug("Preordering: %s" % fqu)
                    # loadbalancing happens in get_next_addresses()
                    payment_address, owner_address = self.get_next_addresses()

                    if payment_address is None:
                        return False
                    else:
                        return preorder(fqu, payment_address, owner_address)

        elif not profileonBlockchain(fqu, profile):
            #log.debug("Not updated: %s" % fqu)

            if nameop is None or nameop == 'update':
                if fqu not in DHT_IGNORE:
                    log.debug("Updating profile on blockchain: %s" % fqu)
                    return update(fqu, profile)
                else:
                    log.debug("In DHT IGNORE list: %s" % fqu)

        elif not profileonDHT(fqu, profile):
            #log.debug("Not on DHT: %s" % fqu)

            if fqu not in DHT_IGNORE:
                #log.debug("Writing profile to DHT: %s" % fqu)
                write_dht_profile(profile)

            return False  # because not a blockchain operation

        elif not ownerName(fqu, transfer_address):
            #log.debug("Not transferred: %s" % fqu)

            if nameop is None or nameop == 'transfer':
                log.debug("Transferring name: %s" % fqu)
                return transfer(fqu, transfer_address)

        #log.debug("Nameop didn't meet any conditions")
        return False  # no blockchain tx was sent

    def subsidized_nameop(self, fqu, profile, hex_privkey, nameop=None):

        if not profileonBlockchain(fqu, profile):

            if nameop is None or nameop is 'update':
                if fqu not in DHT_IGNORE:
                    log.debug("Updating profile on blockchain: %s" % fqu)

                    payment_address, other_address = self.get_next_addresses()

                    if payment_address is None:
                        return False

                    return subsidized_update(fqu, profile, hex_privkey,
                                             payment_address)
                else:
                    log.debug("In DHT IGNORE list: %s" % fqu)

        elif not profileonDHT(fqu, profile):
            #log.debug("Not on DHT: %s" % fqu)

            if fqu not in DHT_IGNORE:
                #log.debug("Writing profile to DHT: %s" % fqu)
                write_dht_profile(profile)

            return False  # because not a blockchain operation