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
from .nameops import usernameRegistered, ownerUsername

from .config import DEFAULT_NAMESPACE
from .config import BTC_PRIV_KEY
from .config import RATE_LIMIT_TX

from .utils import get_hash, check_banned_email, nmc_to_btc_address
from .utils import config_log

from .network import get_bs_client
from .db import users, registrations, updates
from .db import get_db_user_from_id
from .db import register_queue, update_queue

from .queue import cleanup_queue, add_to_queue, alreadyinQueue

log = config_log(__name__)


def register_user(fqu, profile, btc_address):

    bs_client = get_bs_client()

    if alreadyinQueue(register_queue, fqu):
        log.debug("Already in queue: %s" % fqu)
        return

    if usernameRegistered(fqu):
        log.debug("Already registered %s" % fqu)
        return

    profile_hash = get_hash(profile)

    log.debug("Registering (%s, %s, %s)" % (fqu, btc_address, profile_hash))

    try:
        resp = bs_client.name_import(fqu, btc_address, profile_hash,
                                     BTC_PRIV_KEY)
        resp = resp[0]
    except Exception as e:
        log.debug(e)
        return

    if 'transaction_hash' in resp:
        add_to_queue(register_queue, fqu, profile, profile_hash, btc_address,
                     resp['transaction_hash'])
    else:
        log.debug("Error registering: %s" % fqu)
        log.debug(resp)


def update_user(fqu, profile, btc_address):

    bs_client = get_bs_client()

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

    if 'transaction_hash' in resp:
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

        bs_client = get_bs_client()

        fqu = user['username'] + "." + DEFAULT_NAMESPACE
        btc_address = nmc_to_btc_address(user['namecoin_address'])
        profile = user['profile']

        log.debug("-" * 5)
        log.debug("Processing: %s" % fqu)

        if usernameRegistered(fqu):
            log.debug("Already registered %s" % fqu)

            resp = get_blockchain_record(fqu)

            if 'value_hash' not in resp:
                log.debug("ERROR in resp")
                log.debug(resp)
                break

            if resp['value_hash'] == get_hash(user['profile']):
                registrations.remove({"user_id": new_user['user_id']})
                log.debug("Removing registration")
            else:
                log.debug("Latest profile not on blockchain, need to update")
                update_user(fqu, profile, btc_address)

        else:

            log.debug("Not registered: %s" % fqu)
            register_user(fqu, profile, btc_address)

            counter += 1

            if counter == RATE_LIMIT_TX:
                log.debug("Reached limit. Breaking.")
                break


def update_users_bulk():

    counter = 0

    for new_user in updates.find(no_cursor_timeout=True):

        user = get_db_user_from_id(new_user)

        if user is None:
            continue

        bs_client = get_bs_client()

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

                    if counter == RATE_LIMIT_TX:
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

if __name__ == '__main__':

    try:
        command = sys.argv[1]
    except:
        log.info("Options are register, update, clean")
        exit(0)

    if command == "register":
        register_new_users()
    elif command == "update":
        update_users_bulk()
    elif command == "clean":
        cleanup_queue(update_queue)
        cleanup_queue(register_queue)
    elif command == "reprocess":

        try:
            username = sys.argv[2]
        except:
            log.info("Usage error: reprocess <username>")
            exit(0)

        reprocess_user(username)
