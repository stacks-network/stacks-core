# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
"""

from pybitcoin import sign_all_unsigned_inputs
from blockcypher import pushtx

from crypto.utils import get_address_from_privkey
from crypto.utils import get_pubkey_from_privkey

from .utils import get_hash, pretty_print
from .network import get_blockchain_record

from .states import ownerName, nameRegistered

from .queue import alreadyinQueue, add_to_queue
from .db import preorder_queue, register_queue
from .db import update_queue, transfer_queue

from .blockchain import get_tx_confirmations
from .blockchain import dontuseAddress, underfundedAddress
from .blockchain import recipientNotReady
from .blockchain import get_bitcoind_client

from .wallet import wallet

from .utils import config_log
from .utils import pretty_print as pprint

from .config import PREORDER_CONFIRMATIONS
from .config import BLOCKCYPHER_TOKEN
from .config import BLOCKSTACKD_IP, BLOCKSTACKD_PORT

from blockstack_client.backend import do_preorder, do_register
from blockstack_client.backend import do_update, do_transfer
from blockstack_client.config import get_utxo_provider_client
from blockstack_client.config import get_tx_broadcaster
from blockstack_client.proxy import get_name_cost

log = config_log(__name__)

utxo_client = get_utxo_provider_client()
tx_broadcaster = get_tx_broadcaster()


def subsidized_update(fqu, profile, owner_privkey, payment_address,
                      payment_privkey=None):
    """
        Update a previously registered fqu, using a different payment address

        @fqu: fully qualified name e.g., muneeb.id
        @profile: new profile json, hash(profile) goes to blockchain
        @owner_privkey: privkey of owner address, to sign update
        @payment_address: the address which is paying for the cost

        Returns True/False and stores tx_hash in queue
    """

    if alreadyinQueue(update_queue, fqu):
        log.debug("Already in update queue: %s" % fqu)
        return False

    if not nameRegistered(fqu):
        log.debug("Not yet registered %s" % fqu)
        return False

    profile_hash = get_hash(profile)

    blockchain_record = get_blockchain_record(fqu)
    owner_address = blockchain_record['address']

    check_address = get_address_from_privkey(owner_privkey)

    if check_address != owner_address:
        log.debug("Given privkey/address doesn't own this name.")
        return False

    if dontuseAddress(payment_address):
        log.debug("Payment address not ready: %s" % payment_address)
        return False

    elif underfundedAddress(payment_address):
        log.debug("Payment address under funded: %s" % payment_address)
        return False

    owner_public_key = get_pubkey_from_privkey(owner_privkey)

    if payment_privkey is None:
        payment_privkey = wallet.get_privkey_from_address(payment_address)

    log.debug("Updating (%s, %s)" % (fqu, profile_hash))
    log.debug("<owner, payment> (%s, %s)" % (owner_address, payment_address))

    resp = {}

    try:
        # do_update( fqu, zonefile_hash, owner_privkey, payment_privkey, utxo_client, tx_broadcaster
        resp = do_update(fqu, profile_hash,
                                     owner_privkey, payment_privkey,
                                     utxo_client, tx_broadcaster)
    except Exception as e:
        log.debug(e)

    if 'transaction_hash' in resp:
        add_to_queue(update_queue, fqu, profile=profile,
                     profile_hash=profile_hash, owner_address=owner_address,
                     tx_hash=resp['transaction_hash'])
    else:
        log.debug("Error updating: %s" % fqu)
        log.debug(resp)
        return False

    return True


def subsidized_transfer(fqu, transfer_address, owner_privkey, payment_address,
                        payment_privkey=None):
    """
        Transfer a previously registered fqu, using a different payment address

        @fqu: fully qualified name e.g., muneeb.id
        @transfer_address: new owner address
        @owner_privkey: privkey of current owner address, to sign tx
        @payment_address: the address which is paying for the cost

        Returns True/False and stores tx_hash in queue
    """

    if alreadyinQueue(transfer_queue, fqu):
        log.debug("Already in transfer queue: %s" % fqu)
        return False

    if not nameRegistered(fqu):
        log.debug("Not yet registered %s" % fqu)
        return False

    if ownerName(fqu, transfer_address):
        log.debug("Already transferred %s" % fqu)
        return True

    if recipientNotReady(transfer_address):
        log.debug("Address %s owns too many names already." % transfer_address)
        return False

    blockchain_record = get_blockchain_record(fqu)
    owner_address = blockchain_record['address']

    check_address = get_address_from_privkey(owner_privkey)

    if check_address != owner_address:
        log.debug("Given privkey/address doesn't own this name.")
        return False

    if dontuseAddress(payment_address):
        log.debug("Payment address not ready: %s" % payment_address)
        return False

    elif underfundedAddress(payment_address):
        log.debug("Payment address under funded: %s" % payment_address)
        return False

    owner_public_key = get_pubkey_from_privkey(owner_privkey)

    if payment_privkey is None:
        payment_privkey = wallet.get_privkey_from_address(payment_address)

    log.debug("Transferring (%s, %s)" % (fqu, transfer_address))
    log.debug("<owner, payment> (%s, %s)" % (owner_address, payment_address))

    resp = {}

    try:
        # do_transfer( fqu, transfer_address, keep_data, owner_privkey, payment_privkey, utxo_client, tx_broadcaster
        resp = do_transfer(fqu, transfer_address, True,
                                      owner_privkey, payment_privkey,
                                      utxo_client, tx_broadcaster)
    except Exception as e:
        log.debug(e)

    if 'transaction_hash' in resp:
        add_to_queue(transfer_queue, fqu, owner_address=owner_address,
                     transfer_address=transfer_address,
                     tx_hash=resp['transaction_hash'])
    else:
        log.debug("Error transferring: %s" % fqu)
        log.debug(resp)
        return False

    return True
