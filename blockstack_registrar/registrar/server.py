#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~

    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

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

from .config import DEFAULT_NAMESPACE
from .config import BTC_PRIV_KEY
from .config import RATE_LIMIT, PREORDER_CONFIRMATIONS

from .utils import get_hash, check_banned_email, nmc_to_btc_address
from .utils import config_log

from .network import bs_client
from .db import users, registrations, updates
from .db import get_db_user_from_id
from .db import register_queue, update_queue

from .queue import cleanup_queue, add_to_queue, alreadyinQueue

from .wallet import get_addresses, get_privkey
from .blockchain import get_tx_confirmations

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


def get_next_index():

    global index

    index += 1

    if index >= RATE_LIMIT:

        index = 0

    return index


def preorder_user(fqu, payment_privkey, owner_address):

    if alreadyinQueue(register_queue, fqu, 'preorder'):
        log.debug("Already in queue: %s" % fqu)
        return

    log.debug("Preordering (%s, %s)" % (fqu, owner_address))

    try:
        resp = bs_client.preorder(fqu, payment_privkey, owner_address)
    except Exception as e:
        log.debug(e)

    if 'tx_hash' in resp:
        add_to_queue(register_queue, fqu, owner_address,
                     "preorder", resp['tx_hash'])
    else:
        log.debug("Error preordering: %s" % fqu)
        log.debug(pprint(resp))


def register_user(fqu, payment_privkey, owner_address):

    if not alreadyinQueue(register_queue, fqu, 'preorder'):
        preorder_user(fqu, payment_privkey, owner_address)
        return

    if alreadyinQueue(register_queue, fqu, 'register'):
        log.debug("Already in queue: %s" % fqu)
        return

    if usernameRegistered(fqu):
        log.debug("Already registered %s" % fqu)
        return

    preorder_entry = register_queue.find_one({"fqu": fqu, "state": "preorder"})
    preorder_tx = preorder_entry['tx_hash']

    tx_confirmations = get_tx_confirmations(preorder_tx)

    if tx_confirmations < PREORDER_CONFIRMATIONS:
        log.debug("Waiting on preorder confirmations: (%s, %s)"
                  % (preorder_tx, tx_confirmations))
        return

    log.debug("Registering (%s, %s)" % (fqu, owner_address))

    try:
        resp = bs_client.register(fqu, payment_privkey, owner_address)
    except Exception as e:
        log.debug(e)

    if 'tx_hash' in resp:
        add_to_queue(register_queue, fqu, owner_address,
                     "register", resp['transaction_hash'])
    else:
        log.debug("Error registering: %s" % fqu)
        log.debug(pprint(resp))


def update_user(fqu, profile, btc_address):

    if alreadyinQueue(update_queue, fqu):
        log.debug("Already in queue: %s" % fqu)
        return

    if not ownerUsername(fqu, btc_address):
        log.debug("Don't own this name")
        return

    profile_hash = get_hash(profile)

    log.debug("Updating (%s, %s, %s)" % (fqu, btc_address, profile_hash))

    try:
        resp = bs_client.name_import(fqu, btc_address, profile_hash, BTC_PRIV_KEY)
        resp = resp[0]
    except Exception as e:
        log.debug(e)
        return

    if 'tx_hash' in resp:
        add_to_queue(update_queue, fqu, profile, profile_hash, btc_address,
                     resp['transaction_hash'])
    else:
        log.debug("Error updating: %s" % fqu)
        log.debug(resp)


def register_new_users(spam_protection=False):

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

            global index

            payment_address = payment_addresses[index]
            owner_address = owner_addresses[index]
            payment_privkey = get_privkey(payment_address)

            register_user(fqu, payment_privkey, owner_address)
            
            index = get_next_index()

            if index == 0:
                log.debug("Reached rate limit. Breaking.")
                break

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
                    update_user(fqu, profile, btc_address)

                    counter += 1

                    if counter == RATE_LIMIT:
                        log.debug("Reached limit. Breaking.")
                        break
                else:
                    log.debug("Cannot update (wrong owner): %s " % fqu)
                    updates.remove({"user_id": new_user['user_id']})
        else:

            log.debug("Not registered: %s" % fqu)


def reprocess_user(username):

    user = users.find_one({"username": username})
    fqu = user['username'] + "." + DEFAULT_NAMESPACE
    btc_address = nmc_to_btc_address(user['namecoin_address'])
    profile = user['profile']

    log.debug("Reprocessing update: %s" % fqu)
    update_user(fqu, profile, btc_address)


def display_stats():

    log.debug("Pending registrations: %s" % registrations.find().count())
    log.debug("Pending updates: %s" % updates.find().count())

if __name__ == '__main__':

    init_addresses_in_use()

    try:
        command = sys.argv[1]
    except:
        log.info("Options are register, update, clean, stats, reprocess")
        exit(0)

    if command == "register":
        register_new_users()
    elif command == "update":
        update_users_bulk()
    elif command == "clean":
        cleanup_queue(update_queue)
        cleanup_queue(register_queue)

    elif command == "stats":
        display_stats()

    elif command == "reprocess":

        try:
            username = sys.argv[2]
        except:
            log.info("Usage error: reprocess <username>")
            exit(0)

        reprocess_user(username)
