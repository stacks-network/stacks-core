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
from .db import preorder_queue, register_queue
from .db import update_queue, transfer_queue

from .blockchain import get_tx_confirmations
from .blockchain import dontuseAddress, underfundedAddress

from .wallet import get_privkey

from .utils import config_log
from .utils import pretty_print as pprint

from .config import PREORDER_CONFIRMATIONS

log = config_log(__name__)


"""
    There are 4 main nameops (preorder, register, update, transfer)
"""


def preorder(fqu, payment_address, owner_address):
    """
        Preorder a fqu (step #1)

        @fqu: fully qualified name e.g., muneeb.id
        @payment_address: used for making the payment
        @owner_address: will own the fqu

        Returns True/False and stores tx_hash in queue
    """

    # stale preorder will get removed from preorder_queue
    if alreadyinQueue(register_queue, fqu):
        log.debug("Already in register queue: %s" % fqu)
        return False

    if alreadyinQueue(preorder_queue, fqu):
        log.debug("Already in preorder queue: %s" % fqu)
        return False

    log.debug("Preordering (%s, %s, %s)" % (fqu, payment_address, owner_address))

    payment_privkey = get_privkey(payment_address)

    try:
        resp = bs_client.preorder(fqu, payment_privkey, owner_address)
    except Exception as e:
        log.debug(e)

    if 'tx_hash' in resp:
        add_to_queue(preorder_queue, fqu, payment_address=payment_address,
                     tx_hash=resp['tx_hash'],
                     owner_address=owner_address)
    else:
        log.debug("Error preordering: %s" % fqu)
        log.debug(pprint(resp))
        return False

    return True


def register(fqu, payment_address=None, owner_address=None,
             auto_preorder=True):
    """
        Register a previously preordered fqu (step #2)

        @fqu: fully qualified name e.g., muneeb.id
        @auto_preorder: automatically preorder, if true

        Uses from preorder queue:
        @payment_address: used for making the payment
        @owner_address: will own the fqu (must be same as preorder owner_address)

        Returns True/False and stores tx_hash in queue
    """

    # check register_queue first
    # stale preorder will get removed from preorder_queue
    if alreadyinQueue(register_queue, fqu):
        log.debug("Already in register queue: %s" % fqu)
        return False

    if not alreadyinQueue(preorder_queue, fqu):
        if auto_preorder:
            return preorder(fqu, payment_address, owner_address)
        else:
            log.debug("No preorder sent yet: %s" % fqu)
            return False

    if nameRegistered(fqu):
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
        payment_address = preorder_entry['payment_address']

    except:
        log.debug("Error getting preorder addresses")
        return False

    if dontuseAddress(payment_address):
        log.debug("Payment address not ready")
        return False

    elif underfundedAddress(payment_address):
        log.debug("Payment address under funded")
        return False

    payment_privkey = get_privkey(payment_address)

    log.debug("Registering (%s, %s, %s)" % (fqu, payment_address, owner_address))

    try:
        resp = bs_client.register(fqu, payment_privkey, owner_address)
    except Exception as e:
        log.debug(e)

    if 'tx_hash' in resp:
        add_to_queue(register_queue, fqu, payment_address=payment_address,
                     tx_hash=resp['tx_hash'],
                     owner_address=owner_address)
    else:
        log.debug("Error registering: %s" % fqu)
        log.debug(pprint(resp))
        return False

    return True


def update(fqu, profile):
    """
        Update a previously registered fqu (step #3)

        @fqu: fully qualified name e.g., muneeb.id
        @profile: new profile json, hash(profile) goes to blockchain

        Internal use:
        @owner_address: fetches the owner_address that can update

        Returns True/False and stores tx_hash in queue
    """

    if alreadyinQueue(update_queue, fqu):
        log.debug("Already in update queue: %s" % fqu)
        return False

    if not nameRegistered(fqu):
        log.debug("Not yet registered %s" % fqu)
        return False

    data = get_blockchain_record(fqu)

    owner_address = data['address']
    profile_hash = get_hash(profile)
    owner_privkey = get_privkey(owner_address)

    if owner_privkey is None:
        log.debug("Registrar doens't own this name.")
        return False

    log.debug("Updating (%s, %s)" % (fqu, profile_hash))

    if dontuseAddress(owner_address):
        log.debug("Owner address not ready")
        return False

    elif underfundedAddress(owner_address):
        log.debug("Owner address under funded")
        return False

    try:
        resp = bs_client.update(fqu, profile_hash, owner_privkey)
    except Exception as e:
        log.debug(e)

    if 'tx_hash' in resp:
        add_to_queue(update_queue, fqu, profile=profile,
                     profile_hash=profile_hash, owner_address=owner_address,
                     tx_hash=resp['tx_hash'])
    else:
        log.debug("Error updating: %s" % fqu)
        log.debug(resp)
        return False

    return True


def transfer(fqu, transfer_address):
    """
        Transfer a previously registered fqu (step #4)

        @fqu: fully qualified name e.g., muneeb.id
        @transfer_address: new owner address of @fqu

        Internal use:
        @owner_address: fetches the owner_address that can transfer

        Returns True/False and stores tx_hash in queue
    """

    if alreadyinQueue(transfer_queue, fqu):
        log.debug("Already in transfer queue: %s" % fqu)
        return False

    if ownerName(fqu, transfer_address):
        log.debug("Already transferred %s" % fqu)
        return True

    data = get_blockchain_record(fqu)

    owner_address = data['address']
    owner_privkey = get_privkey(owner_address)

    log.debug("Transferring (%s, %s)" % (fqu, transfer_address))

    if dontuseAddress(owner_address):
        log.debug("Owner address not ready")
        return False

    elif underfundedAddress(owner_address):
        log.debug("Owner address under funded")
        return False

    try:
        # format for transfer RPC call is (name, address, keepdata, privatekey)
        resp = bs_client.transfer(fqu, transfer_address, True, owner_privkey)
    except Exception as e:
        log.debug(e)

    if 'tx_hash' in resp:
        add_to_queue(transfer_queue, fqu,
                     owner_address=owner_address,
                     tx_hash=resp['tx_hash'])
    else:
        log.debug("Error transferring: %s" % fqu)
        log.debug(resp)
        return False

    return True

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


def nameRegistered(fqu):
    """ return True if @fqu registered on blockchain
    """

    data = get_blockchain_record(fqu)

    if "first_registered" in data:
        return True
    else:
        return False


def profileonBlockchain(fqu, profile):
    """ return True if hash(@profile) published on blockchain
    """

    record = get_blockchain_record(fqu)

    profile_hash = get_hash(profile)

    if 'value_hash' in record and record['value_hash'] != profile_hash:
        # if hash of profile is in correct
        return False

    return True


def profileonDHT(fqu, profile):
    """ return True if hash(@profile) published on DHT
    """

    profile_hash = get_hash(profile)

    dht_profile = get_dht_profile(fqu)

    if dht_profile is None:
        return False
    else:
        if get_hash(dht_profile) == profile_hash:
            return True
        else:
            return False


def profilePublished(fqu, profile):
    """ return True if:
        1) hash(@profile) published on blockchain, and
        2) @profile published on DHT
    """

    if profileonBlockchain(fqu, profile) and profileonDHT(fqu, profile):
        return True
    else:
        return False


def ownerName(fqu, address):
    """ return True if @btc_address owns @fqu
    """

    record = get_blockchain_record(fqu)

    if 'address' in record and record['address'] == address:
        return True
    else:
        return False


def registrationComplete(fqu, profile, transfer_address):
    """ return True if properly registered

        Three conditions that need to be met:
        1) @fqu is registered on blockchain
        2) correct hash(@profile) is published
        3) @owner_address owns the fqu
    """

    if not nameRegistered(fqu):
        return False

    if not profilePublished(fqu, profile):
        return False

    if not ownerName(fqu, transfer_address):
        return False

    return True
