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

from .nameops import get_blockchain_record
from .nameops import usernameRegistered, ownerUsername, registrationComplete
from .nameops import preorder, register, update, transfer

from .config import DEFAULT_NAMESPACE
from .config import BTC_PRIV_KEY
from .config import RATE_LIMIT

from .utils import get_hash, check_banned_email, nmc_to_btc_address
from .utils import config_log

from .network import bs_client
from .db import users, registrations, updates
from .db import get_db_user_from_id
from .db import preorder_queue, register_queue, update_queue, transfer_queue

from .queue import display_queue, add_to_queue, alreadyinQueue
from .queue import cleanup_rejected_tx

from .wallet import get_addresses, get_privkey
from .blockchain import get_tx_confirmations, dontuseAddress

from .utils import pretty_print as pprint

log = config_log(__name__)

index = 0
payment_addresses = []
owner_addresses = []


def init_addresses_in_use():

    global payment_addresses
    global owner_addresses

    payment_addresses = get_addresses(count=RATE_LIMIT)

    # change the positions by 1, so that different payment and owner addresses
    # are at a given index for the two lists
    owner_addresses = [payment_addresses[-1]] + payment_addresses[:-1]


# initialize the list of addresses
init_addresses_in_use()


def get_next_addresses():

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
    num_of_tries = RATE_LIMIT
    counter = 0

    while(1):
        # find an address that can be used for payment

        if dontuseAddress(payment_address):
            increment_index()

            payment_address = payment_addresses[index]
        else:
            break

        counter += 1

        if counter == RATE_LIMIT:
            log.debug("All addresses were recently used. Sleeping")
            sleep(10)
            counter = 0

    owner_address = owner_addresses[index]

    return payment_address, owner_address


def register_load_balancer(fqu):

    if usernameRegistered(fqu):
        log.debug("Already registered: %s" % fqu)
        return

    payment_address, owner_address = get_next_addresses()
    payment_privkey = get_privkey(payment_address)

    register(fqu, payment_address, payment_privkey, owner_address)


def register_webapp_users(spam_protection=False):

    counter = 0

    for new_user in registrations.find(no_cursor_timeout=True):

        user = get_db_user_from_id(new_user)

        if user is None:
            log.debug("No such user, need to remove: %s" % new_user['_id'])
            #registrations.remove({'_id': new_user['_id']})
            continue

        # for spam protection
        if check_banned_email(user['email']):
            if spam_protection:
                #users.remove({"email": user['email']})
                log.debug("Deleting spam %s, %s" % (user['email'], user['username']))
                continue
            else:
                log.debug("Need to delete %s, %s" % (user['email'], user['username']))
                continue

        fqu = user['username'] + "." + DEFAULT_NAMESPACE
        btc_address = nmc_to_btc_address(user['namecoin_address'])
        profile = user['profile']

        log.debug("-" * 5)
        log.debug("Processing: %s" % fqu)

        if not usernameRegistered(fqu):
            log.debug("Not registered: %s" % fqu)
            register_load_balancer(fqu)

        elif registrationComplete(fqu, profile, btc_address):
            registrations.remove({"user_id": new_user['user_id']})
            log.debug("Removing registration")


def update_users_bulk():

    counter = 0

    for new_user in updates.find(no_cursor_timeout=True):

        user = get_db_user_from_id(new_user)

        if user is None:
            continue

        fqu = user['username'] + "." + DEFAULT_NAMESPACE
        btc_address = nmc_to_btc_address(user['namecoin_address'])
        profile = user['profile']

        if usernameRegistered(fqu):

            resp = get_blockchain_record(fqu)

            if 'error' in resp:
                log.debug("ERROR: %s, %s" % (fqu, resp))
                continue

            if resp['value_hash'] == get_hash(user['profile']):
                log.debug("profile match, removing: %s" % fqu)
                updates.remove({"user_id": new_user['user_id']})
            else:
                if ownerUsername(fqu, btc_address):
                    update(fqu, profile, btc_address)

                    counter += 1

                    if counter == RATE_LIMIT:
                        log.debug("Reached limit. Breaking.")
                        break
                else:
                    log.debug("Cannot update (wrong owner): %s " % fqu)
                    updates.remove({"user_id": new_user['user_id']})
        else:

            log.debug("Not registered: %s" % fqu)


def cleanup_register_queue():

    for entry in preorder_queue.find():

        if usernameRegistered(entry['fqu']):
            log.debug("%s registered. Removing preorder: " % entry['fqu'])
            preorder_queue.remove({"fqu": entry['fqu']})

    for entry in register_queue.find():

        if usernameRegistered(entry['fqu']):
            log.debug("%s registered. Removing register: " % entry['fqu'])
            register_queue.remove({"fqu": entry['fqu']})

    cleanup_rejected_tx(preorder_queue)
    cleanup_rejected_tx(register_queue)


def reprocess_user(username):

    user = users.find_one({"username": username})
    fqu = user['username'] + "." + DEFAULT_NAMESPACE
    btc_address = nmc_to_btc_address(user['namecoin_address'])
    profile = user['profile']

    log.debug("Reprocessing update: %s" % fqu)
    update(fqu, profile, btc_address)


def display_stats():

    log.debug("Pending registrations: %s" % registrations.find().count())
    log.debug("Pending updates: %s" % updates.find().count())

if __name__ == '__main__':

    try:
        command = sys.argv[1]
    except:
        log.info("Options are register, update, clean, stats, reprocess")
        exit(0)

    if command == "register":
        register_webapp_users()

    elif command == "update":
        update_users_bulk()

    elif command == "clean":
        cleanup_register_queue()
        #cleanup_queue(register_queue)

    elif command == "getinfo":
        display_queue(preorder_queue)
        display_queue(register_queue)

    elif command == "stats":
        display_stats()

    elif command == "reprocess":

        try:
            username = sys.argv[2]
        except:
            log.info("Usage error: reprocess <username>")
            exit(0)

        reprocess_user(username)
