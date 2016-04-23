# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
"""

import os
import sys
import json
import pybitcoin

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

from .queue import in_queue, queue_append, queue_findone

from .blockchain import get_tx_confirmations, get_utxos, get_utxo_client
from .blockchain import dontuseAddress, underfundedAddress
from .blockchain import recipientNotReady

from crypto.utils import get_address_from_privkey, get_pubkey_from_privkey

from ..utils import pretty_print as pprint
from ..utils import pretty_dump

from ..config import PREORDER_CONFIRMATIONS, DEFAULT_QUEUE_PATH
from ..config import get_logger

from ..profile import hash_zonefile
from ..proxy import get_default_proxy
from ..proxy import preorder as blockstack_preorder 
from ..proxy import register as blockstack_register
from ..proxy import update_subsidized as blockstack_update_subsidized
from ..proxy import transfer_subsidized as blockstack_transfer_subsidized
from ..proxy import get_name_blockchain_record as blockstack_get_name_blockchain_record
from ..proxy import is_name_registered, is_name_owner

log = get_logger()


def send_subsidized(hex_privkey, unsigned_tx_hex):
    """
    Send a given transaction, but pay for it with the given key.
    """
    reply = {}

    # sign all unsigned inputs
    signed_tx = pybitcoin.sign_all_unsigned_inputs(hex_privkey, unsigned_tx_hex)
    utxo_client = get_utxo_client()
    resp = pybitcoin.broadcast_transaction( signed_tx, utxo_client )

    if 'transaction_hash' not in resp:
        reply['error'] = "ERROR: broadcasting tx"
        log.debug(pprint(resp))
        return reply

    return resp


def async_preorder(fqu, paymetn_address, owner_address, payment_privkey=None, proxy=None, queue_path=DEFAULT_QUEUE_PATH):
    """
        Preorder a fqu (step #1)

        @fqu: fully qualified name e.g., muneeb.id
        @owner_address: will own the fqu
        @payment privkey: private key that will pay

        Returns True/False and stores tx_hash in queue
    """

    if proxy is None:
        proxy = get_default_proxy

    # stale preorder will get removed from preorder_queue
    if in_queue("register", fqu):
        log.debug("Already in register queue: %s" % fqu)
        return {'error': 'Already in register queue'}

    if in_queue("preorder", fqu):
        log.debug("Already in preorder queue: %s" % fqu)
        return {'error': 'Already in preorder queue'}

    if recipientNotReady(owner_address, proxy=proxy):
        log.debug("Address %s owns too many names already." % owner_address)
        return {'error': 'Address owns too many names'}

    payment_address = get_address_from_privkey(payment_privkey)
    if dontuseAddress(payment_address):
        log.debug("Payment address not ready: %s" % payment_address)
        return {'error': 'Payment address is not ready'}

    elif underfundedAddress(payment_address):
        log.debug("Payment address under funded: %s" % payment_address)
        return {'error': 'Payment address is underfunded'}

    log.debug("Preordering (%s, %s, %s)" % (fqu, payment_address, owner_address))

    resp = {}

    try:
        resp = blockstack_preorder(fqu, payment_privkey, owner_address, proxy=proxy )
    except Exception as e:
        log.exception(e)
        return {'error': 'Failed to issue preorder'}

    if 'transaction_hash' in resp:
        # watch this preorder, and register it when it gets queued
        queue_append("preorder", fqu, resp['transaction_hash'],
                     payment_address=payment_address,
                     owner_address=owner_address,
                     path=queue_path)
    else:
        log.debug("Error preordering: %s with %s for %s" % (fqu, payment_address, owner_address))
        log.debug("Error below\n%s" % json.dumps(resp, indent=4, sort_keys=True))
        return {'error': 'Failed to preorder'}

    return resp


def async_register(fqu, payment_address=None, owner_address=None, payment_privkey=None, auto_preorder=True, proxy=None, queue_path=DEFAULT_QUEUE_PATH):
    """
        Register a previously preordered fqu (step #2)

        @fqu: fully qualified name e.g., muneeb.id
        @auto_preorder: automatically preorder, if true

        Uses from preorder queue:
        @payment_address: used for making the payment
        @owner_address: will own the fqu (must be same as preorder owner_address)

        Return {'status': True, ...} on success
        Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy()

    # check register_queue first
    # stale preorder will get removed from preorder_queue
    if in_queue("register", fqu):
        log.debug("Already in register queue: %s" % fqu)
        return {'error': 'Already in register queue'}

    if not in_queue("preorder", fqu):
        if auto_preorder:
            return blockstack_preorder(fqu, payment_address, owner_address, proxy=proxy)
        else:
            log.debug("No preorder sent yet: %s" % fqu)
            return {'error': 'No preorder sent yet'}

    if is_name_registered(fqu, proxy=proxy):
        log.debug("Already registered %s" % fqu)
        return {'error': 'Already registered'}

    preorder_entry = queue_findone( "preorder", fqu, path=queue_path )
    if len(preorder_entry) == 0:
        log.error("No preorder for '%s'" % fqu)
        return {'error': 'No preorder found'}

    preorder_tx = preorder_entry[0]['tx_hash']
    tx_confirmations = get_tx_confirmations(preorder_tx)

    if tx_confirmations < PREORDER_CONFIRMATIONS:
        log.debug("Waiting on preorder confirmations: (%s, %s)"
                  % (preorder_tx, tx_confirmations))

        return {'error': 'Waiting on preorder confirmations'}

    if payment_privkey is None:
        # use the correct owner_address from preorder operation
        try:
            owner_address = preorder_entry['owner_address']
            payment_address = preorder_entry['payment_address']

        except:
            log.debug("Error getting preorder addresses")
            return {'error': 'Could not get preorder addresses'}

        payment_privkey = get_privkey_from_address(payment_address)
    else:
        payment_address = get_address_from_privkey(payment_privkey)

    if dontuseAddress(payment_address):
        log.debug("Payment address not ready: %s" % payment_address)
        return {'error': 'Payment address not ready'}

    elif underfundedAddress(payment_address):
        log.debug("Payment address under funded: %s" % payment_address)
        return {'error': 'Payment address underfunded'}

    log.debug("Registering (%s, %s, %s)" % (fqu, payment_address, owner_address))
    resp = {}

    try:
        resp = blockstack_register(fqu, payment_privkey, owner_address, proxy=proxy)
    except Exception as e:
        log.exception(e)
        return {'error': 'Failed to register name'}

    if 'transaction_hash' in resp:
        queue_append("register", fqu, resp['transaction_hash'],
                     payment_address=payment_address,
                     owner_address=owner_address,
                     path=queue_path)

        return resp

    else:
        log.debug("Error registering: %s" % fqu)
        log.debug(pprint(resp))
        return {'error': 'Failed to send registration'}


def async_update(fqu, zonefile, owner_privkey, payment_address,
                      payment_privkey=None, proxy=None, wallet_keys=None, queue_path=DEFAULT_QUEUE_PATH):
    """
        Update a previously registered fqu, using a different payment address

        @fqu: fully qualified name e.g., muneeb.id
        @zonefile: new zonefile json, hash(zonefile) goes to blockchain
        @owner_privkey: privkey of owner address, to sign update
        @payment_address: the address which is paying for the cost

        Returns True/False and stores tx_hash in queue
    """

    if proxy is None:
        proxy = get_default_proxy()

    if in_queue("update", fqu):
        log.debug("Already in update queue: %s" % fqu)
        return {'error': 'Already in update queue'}

    if not is_name_registered(fqu, proxy=proxy):
        log.debug("Not yet registered %s" % fqu)
        return {'error': 'Not yet registered'}

    zonefile_hash = hash_zonefile( zonefile )

    blockchain_record = blockstack_get_name_blockchain_record( fqu, proxy=proxy )
    if 'error' in blockchain_record:
        log.debug("Failed to read blockchain record for %s" % fqu)
        return {'error': 'Failed to look up name'}

    owner_address = blockchain_record['address']

    check_address = get_address_from_privkey(owner_privkey)

    if check_address != owner_address:
        log.debug("Given privkey/address doesn't own this name.")
        return {'error': 'Name is not owned'}

    if dontuseAddress(payment_address):
        log.debug("Payment address not ready: %s" % payment_address)
        return {'error': 'Payment address is not ready'}

    elif underfundedAddress(payment_address):
        log.debug("Payment address under funded: %s" % payment_address)
        return {'error': 'Payment address is underfunded'}

    owner_public_key = get_pubkey_from_privkey(owner_privkey)

    if payment_privkey is None:
        payment_privkey = get_privkey_from_address(payment_address)

    log.debug("Updating (%s, %s)" % (fqu, zonefile_hash))
    log.debug("<owner, payment> (%s, %s)" % (owner_address, payment_address))

    resp = {}

    try:
        resp = blockstack_update_subsidized(fqu, zonefile_hash,
                                            public_key=owner_public_key,
                                            subsidy_key=payment_privkey)
    except Exception as e:
        log.exception(e)
        return {'error': 'Failed to make update'}

    if 'subsidized_tx' in resp:
        unsigned_tx = resp['subsidized_tx']
    else:
        log.debug("Error updating: %s" % fqu)
        log.debug(resp)
        return {'error': 'Failed to make update'}

    broadcast_resp = send_subsidized(owner_privkey, unsigned_tx)

    if 'transaction_hash' in broadcast_resp:
        queue_append("update", fqu, broadcast_resp['transaction_hash'],
                     zonefile=zonefile,
                     owner_address=owner_address,
                     path=queue_path)

        broadcast_resp['zonefile_hash'] = zonefile_hash
        return broadcast_resp

    else:
        log.debug("Error updating: %s" % fqu)
        log.debug(broadcast_resp)
        return {'error': 'Failed to broadcast update'}


def async_transfer(fqu, transfer_address, owner_privkey, payment_address, payment_privkey=None, proxy=None, queue_path=DEFAULT_QUEUE_PATH):
    """
        Transfer a previously registered fqu, using a different payment address

        @fqu: fully qualified name e.g., muneeb.id
        @transfer_address: new owner address
        @owner_privkey: privkey of current owner address, to sign tx
        @payment_address: the address which is paying for the cost

        Return {'status': True, 'transaction_hash': ...} on success
        Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy()

    if in_queue("transfer", fqu):
        log.debug("Already in transfer queue: %s" % fqu)
        return {'error': 'Already in transfer queue'}

    if not is_name_registered(fqu, proxy=proxy):
        log.debug("Not yet registered %s" % fqu)
        return {'error': 'Not yet registered'}

    if is_name_owner(fqu, transfer_address, proxy=proxy):
        log.debug("Already transferred %s" % fqu)
        return {'error': 'Already transfered'}

    if recipientNotReady(transfer_address, proxy=proxy):
        log.debug("Address %s owns too many names already." % transfer_address)
        return {'error': 'Recipient owns too many names'}

    blockchain_record = blockstack_get_name_blockchain_record( fqu, proxy=proxy )
    if 'error' in blockchain_record:
        log.debug("Failed to read blockchain record for %s" % fqu)
        return {'error': 'Failed to read blockchain record for name'}

    owner_address = blockchain_record['address']
    check_address = get_address_from_privkey(owner_privkey)

    if check_address != owner_address:
        log.debug("Given privkey/address doesn't own this name.")
        return {'error': 'Given keypair does not own this name'}

    if dontuseAddress(payment_address):
        log.debug("Payment address not ready: %s" % payment_address)
        return {'error': 'Payment address is not ready'}

    elif underfundedAddress(payment_address):
        log.debug("Payment address under funded: %s" % payment_address)
        return {'error': 'Payment address is underfunded'}

    owner_public_key = get_pubkey_from_privkey(owner_privkey)
    if payment_privkey is None:
        payment_privkey = wallet.get_privkey_from_address(payment_address)

    log.debug("Transferring (%s, %s)" % (fqu, transfer_address))
    log.debug("<owner, payment> (%s, %s)" % (owner_address, payment_address))

    resp = {}

    try:
        # format for transfer RPC call is:
        # (name, address, keep_data, public_key, subsidy_key)
        resp = blockstack_transfer_subsidized(fqu, transfer_address, True,
                                              public_key=owner_public_key,
                                              subsidy_key=payment_privkey,
                                              proxy=proxy )
    except Exception as e:
        log.exception(e)

    if 'subsidized_tx' in resp:
        unsigned_tx = resp['subsidized_tx']
    else:
        log.debug("Error transferring: %s" % fqu)
        log.debug(pprint(resp))
        return resp

    broadcast_resp = send_subsidized(owner_privkey, unsigned_tx)

    if 'transaction_hash' in broadcast_resp:
        queue_append("transfer", fqu, broadcast_resp['transaction_hash'],
                     owner_address=owner_address,
                     transfer_address=transfer_address,
                     path=queue_path)
    else:
        log.debug("Error transferring: %s" % fqu)
        log.debug(broadcast_resp)
        return {'error': 'Failed to send transfer'}

    return broadcast_resp
