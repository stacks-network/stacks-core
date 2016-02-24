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

from .utils import get_hash, pretty_print
from .network import get_blockchain_record

from .states import ownerName, nameRegistered

from .queue import alreadyinQueue, add_to_queue
from .db import preorder_queue, register_queue
from .db import update_queue, transfer_queue

from .blockchain import get_tx_confirmations
from .blockchain import dontuseAddress, underfundedAddress
from .blockchain import recipientNotReady

from crypto.utils import get_address_from_privkey

from .wallet import wallet

from .utils import config_log
from .utils import pretty_print as pprint

from .config import PREORDER_CONFIRMATIONS
from .config import BLOCKSTORED_IP, BLOCKSTORED_PORT

log = config_log(__name__)


"""
    There are 4 main nameops (preorder, register, update, transfer)
"""


def preorder(fqu, payment_address, owner_address, payment_privkey=None):
    """
        Preorder a fqu (step #1)

        @fqu: fully qualified name e.g., muneeb.id
        @payment_address: used for making the payment
        @owner_address: will own the fqu

        Returns True/False and stores tx_hash in queue
    """

    # hack to ensure local, until we update client
    from blockstore_client import client as bs_client
    # start session using blockstore_client
    bs_client.session(server_host=BLOCKSTORED_IP, server_port=BLOCKSTORED_PORT,
                      set_global=True)

    # stale preorder will get removed from preorder_queue
    if alreadyinQueue(register_queue, fqu):
        log.debug("Already in register queue: %s" % fqu)
        return False

    if alreadyinQueue(preorder_queue, fqu):
        log.debug("Already in preorder queue: %s" % fqu)
        return False

    if recipientNotReady(owner_address):
        log.debug("Address %s owns too many names already." % owner_address)
        return False

    if payment_privkey is None:
        payment_privkey = wallet.get_privkey_from_address(payment_address)
    else:
        payment_address = get_address_from_privkey(payment_privkey)

    if dontuseAddress(payment_address):
        log.debug("Payment address not ready: %s" % payment_address)
        return False

    elif underfundedAddress(payment_address):
        log.debug("Payment address under funded: %s" % payment_address)
        return False

    log.debug("Preordering (%s, %s, %s)" % (fqu, payment_address, owner_address))

    resp = {}

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
        raise ValueError('Error preordering')
        return False

    return True


def register(fqu, payment_address=None, owner_address=None,
             payment_privkey=None, auto_preorder=True):
    """
        Register a previously preordered fqu (step #2)

        @fqu: fully qualified name e.g., muneeb.id
        @auto_preorder: automatically preorder, if true

        Uses from preorder queue:
        @payment_address: used for making the payment
        @owner_address: will own the fqu (must be same as preorder owner_address)

        Returns True/False and stores tx_hash in queue
    """

    # hack to ensure local, until we update client
    from blockstore_client import client as bs_client
    # start session using blockstore_client
    bs_client.session(server_host=BLOCKSTORED_IP, server_port=BLOCKSTORED_PORT,
                      set_global=True)

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

    if payment_privkey is None:
        # use the correct owner_address from preorder operation
        try:
            owner_address = preorder_entry['owner_address']
            payment_address = preorder_entry['payment_address']

        except:
            log.debug("Error getting preorder addresses")
            return False

        payment_privkey = wallet.get_privkey_from_address(payment_address)
    else:
        payment_address = get_address_from_privkey(payment_privkey)

    if dontuseAddress(payment_address):
        log.debug("Payment address not ready: %s" % payment_address)
        return False

    elif underfundedAddress(payment_address):
        log.debug("Payment address under funded: %s" % payment_address)
        return False

    log.debug("Registering (%s, %s, %s)" % (fqu, payment_address, owner_address))

    resp = {}

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

    # hack to ensure local, until we update client
    from blockstore_client import client as bs_client
    # start session using blockstore_client
    bs_client.session(server_host=BLOCKSTORED_IP, server_port=BLOCKSTORED_PORT,
                      set_global=True)

    if alreadyinQueue(update_queue, fqu):
        log.debug("Already in update queue: %s" % fqu)
        return False

    if not nameRegistered(fqu):
        log.debug("Not yet registered %s" % fqu)
        return False

    data = get_blockchain_record(fqu)

    owner_address = data['address']
    profile_hash = get_hash(profile)
    owner_privkey = wallet.get_privkey_from_address(owner_address)

    if owner_privkey is None:
        log.debug("Registrar doens't own this name.")
        return False

    if dontuseAddress(owner_address):
        log.debug("Owner address not ready: %s" % owner_address)
        return False

    elif underfundedAddress(owner_address):
        log.debug("Owner address under funded: %s" % owner_address)
        return False

    log.debug("Updating (%s, %s)" % (fqu, profile_hash))

    resp = {}

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

    # hack to ensure local, until we update client
    from blockstore_client import client as bs_client
    # start session using blockstore_client
    bs_client.session(server_host=BLOCKSTORED_IP, server_port=BLOCKSTORED_PORT,
                      set_global=True)

    if alreadyinQueue(transfer_queue, fqu):
        log.debug("Already in transfer queue: %s" % fqu)
        return False

    if ownerName(fqu, transfer_address):
        log.debug("Already transferred %s" % fqu)
        return True

    if recipientNotReady(transfer_address):
        log.debug("Address %s owns too many names already." % transfer_address)
        return False

    data = get_blockchain_record(fqu)
    owner_address = data['address']
    owner_privkey = wallet.get_privkey_from_address(owner_address)

    if dontuseAddress(owner_address):
        log.debug("Owner address not ready: %s" % owner_address)
        return False

    elif underfundedAddress(owner_address):
        log.debug("Owner address under funded: %s" % owner_address)
        return False

    log.debug("Transferring (%s, %s)" % (fqu, transfer_address))

    resp = {}

    try:
        # format for transfer RPC call is (name, address, keepdata, privatekey)
        resp = bs_client.transfer(fqu, transfer_address, True, owner_privkey)
    except Exception as e:
        log.debug(e)

    if 'tx_hash' in resp:
        add_to_queue(transfer_queue, fqu,
                     owner_address=owner_address,
                     transfer_address=transfer_address,
                     tx_hash=resp['tx_hash'])
    else:
        log.debug("Error transferring: %s" % fqu)
        log.debug(resp)
        return False

    return True
