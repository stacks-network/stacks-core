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

from blockcypher import push_tx

from tools.crypto_tools import get_address_from_privkey

from .utils import get_hash, pretty_print
from .network import bs_client
from .network import get_blockchain_record

from .states import ownerName, nameRegistered

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


def tx_deserialize(tx_hex):
    """
        Given a serialized transaction, return its inputs, outputs,
        locktime, and version

        This func is also defined in blockstore package.
        Included here for completeness.

        Each input will have:
        * transaction_hash: string
        * output_index: int
        * [optional] sequence: int
        * [optional] script_sig: string

        Each output will have:
        * value: int
        * script_hex: string
    """

    tx = bitcoin.deserialize(tx_hex)

    inputs = tx["ins"]
    outputs = tx["outs"]

    ret_inputs = []
    ret_outputs = []

    for inp in inputs:
        ret_inp = {
            "transaction_hash": inp["outpoint"]["hash"],
            "output_index": int(inp["outpoint"]["index"]),
        }

        if "sequence" in inp:
            ret_inp["sequence"] = int(inp["sequence"])

        if "script" in inp:
            ret_inp["script_sig"] = inp["script"]

        ret_inputs.append(ret_inp)

    for out in outputs:
        ret_out = {
            "value": out["value"],
            "script_hex": out["script"]
        }

        ret_outputs.append(ret_out)

    return ret_inputs, ret_outputs, tx["locktime"], tx["version"]


def tx_sign_all_unsigned_inputs(tx_hex, hex_privkey):
    """
        Sign a serialized transaction's unsigned inputs
    """
    inputs, outputs, locktime, version = tx_deserialize(tx_hex)

    for i in xrange(0, len(inputs)):
        if len(inputs[i]['script_sig']) == 0:
            tx_hex = bitcoin.sign(tx_hex, i, hex_privkey)

    return tx_hex


def send_subsidized(hex_privkey, unsigned_tx):

    reply = {}

    # sign all unsigned inputs
    signed_tx = tx_sign_all_unsigned_inputs(unsigned_tx, hex_privkey)

    resp = pushtx(tx_hex=signed_tx)

    if 'tx' in resp:
        reply['tx_hash'] = resp['tx']['hash']
    else:
        reply['error'] = "ERROR: broadcasting tx"

    return reply


def subsidized_update(fqu, profile, owner_privkey, payment_address):
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
        log.debug("Given privkey/address doens't own this name.")
        return False

    log.debug("Updating (%s, %s)" % (fqu, profile_hash))

    if dontuseAddress(payment_address):
        log.debug("Payment address not ready")
        return False

    elif underfundedAddress(payment_address):
        log.debug("Payment address under funded")
        return False

    payment_privkey = get_privkey(payment_address)

    try:
        resp = bs_client.update(fqu, profile_hash, owner_privkey,
                                subsidy_key=payment_privkey)
    except Exception as e:
        log.debug(e)

    if 'subsidized_tx' in resp:
        unsigned_tx = resp['subsidized_tx']
    else:
        log.debug("Error updating: %s" % fqu)
        log.debug(resp)
        return False

    broadcast_resp = send_subsidized(owner_privkey, unsigned_tx)

    if 'tx_hash' in broadcast_resp:
        add_to_queue(update_queue, fqu, profile=profile,
                     profile_hash=profile_hash, payment_address=payment_address,
                     tx_hash=broadcast_resp['tx_hash'])
    else:
        log.debug("Error updating: %s" % fqu)
        log.debug(broadcast_resp)
        return False

    return True
