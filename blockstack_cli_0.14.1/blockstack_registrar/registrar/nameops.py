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

import json

from .utils import get_hash, pretty_print
from .network import bs_client
from .network import get_dht_client

from .queue import alreadyinQueue, add_to_queue
from .db import register_queue, preorder_queue

from .blockchain import get_tx_confirmations

from .utils import config_log
from .utils import pretty_print as pprint

from .config import PREORDER_CONFIRMATIONS

log = config_log(__name__)


"""
    There are 4 main nameops (preorder, register, update, transfer)
"""


def preorder(fqu, payment_address, payment_privkey, owner_address):
    """
        Preorder a fqu (step #1)

        @fqu: fully qualified name e.g., muneeb.id
        @payment_address: used for making the payment
        @payment_privkey: privkey for paying address
        @owner_address: will own the fqu

        Returns True/False and stores tx_hash in queue
    """

    if alreadyinQueue(preorder_queue, fqu):
        log.debug("Already in preorder queue: %s" % fqu)
        return False

    log.debug("Preordering (%s, %s, %s)" % (fqu, payment_address, owner_address))

    try:
        resp = bs_client.preorder(fqu, payment_privkey, owner_address)
    except Exception as e:
        log.debug(e)

    if 'tx_hash' in resp:
        add_to_queue(preorder_queue, fqu, payment_address, resp['tx_hash'],
                     owner_address)
    else:
        log.debug("Error preordering: %s" % fqu)
        log.debug(pprint(resp))
        return False

    return True


def register(fqu, payment_address, payment_privkey, owner_address=None):
    """
        Register a previously preordered fqu (step #2)

        @fqu: fully qualified name e.g., muneeb.id
        @payment_address: used for making the payment
        @payment_privkey: privkey for paying address
        @owner_address: will own the fqu (must be same as preorder owner_address)

        Returns True/False and stores tx_hash in queue
    """

    if not alreadyinQueue(preorder_queue, fqu):
        return preorder(fqu, payment_address, payment_privkey, owner_address)

    if alreadyinQueue(register_queue, fqu):
        log.debug("Already in register queue: %s" % fqu)
        return False

    if usernameRegistered(fqu):
        log.debug("Already registered %s" % fqu)
        return False

    preorder_entry = preorder_queue.find_one({"fqu": fqu})
    preorder_tx = preorder_entry['tx_hash']

    tx_confirmations = get_tx_confirmations(preorder_tx)

    if tx_confirmations < PREORDER_CONFIRMATIONS:
        log.debug("Waiting on preorder confirmations: (%s, %s)"
                  % (preorder_tx, tx_confirmations))

        return False

    # use the correct owner_address from preorder operation
    try:
        owner_address = preorder_entry['owner_address']

    except:
        log.debug("Error getting preorder owner_address")
        return False

    log.debug("Registering (%s, %s, %s)" % (fqu, payment_address, owner_address))

    try:
        resp = bs_client.register(fqu, payment_privkey, owner_address)
    except Exception as e:
        log.debug(e)

    if 'tx_hash' in resp:
        add_to_queue(register_queue, fqu, payment_address, resp['tx_hash'],
                     owner_address)
    else:
        log.debug("Error registering: %s" % fqu)
        log.debug(pprint(resp))
        return False

    return True


def update(fqu, profile, btc_address):

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
                     resp['tx_hash'])
    else:
        log.debug("Error updating: %s" % fqu)
        log.debug(resp)


def transfer(fqu, profile, btc_address):

    return None

"""
    These are helper functions to the 4 main nameops
"""


def get_blockchain_record(fqu):

    data = {}

    try:
        resp = bs_client.get_name_blockchain_record(fqu)
    except Exception as e:
        data['error'] = e
        return data

    return resp


def get_dht_profile(fqu):

    resp = get_blockchain_record(fqu)

    if resp is None:
        return None

    profile_hash = resp['value_hash']

    profile = None

    dht_client = get_dht_client()

    try:
        resp = dht_client.get(profile_hash)
        profile = resp[0]['value']
    except Exception as e:
        print "Error DHT get: (%s, %s)" % (fqu, profile_hash)

    return profile


def write_dht_profile(profile):

    resp = None
    dht_client = get_dht_client()

    key = get_hash(profile)
    value = json.dumps(profile, sort_keys=True)

    print "DHT write (%s, %s)" % (key, value)

    try:
        resp = dht_client.set(key, value)
        pretty_print(resp)
    except Exception as e:
        print e

    return resp


def usernameRegistered(fqu):

    data = get_blockchain_record(fqu)

    if "first_registered" in data:
        return True
    else:
        return False


def ownerUsername(fqu, btc_address):
    """ return True if btc_address owns the username
    """

    record = get_blockchain_record(fqu)

    if record['address'] == btc_address:
        return True
    else:
        return False


def registrationComplete(fqu, profile, btc_address):
    """ return True if properly registered
    """

    record = get_blockchain_record(fqu)

    if 'address' not in record or 'value_hash' not in record:
        log.debug("ERROR in resp")
        log.debug(record)
        return False

    if record['address'] != btc_address:
        # if incorrect owner address
        return False

    if record['value_hash'] != get_hash(profile):
        # if hash of profile is in correct
        return False

    return True
