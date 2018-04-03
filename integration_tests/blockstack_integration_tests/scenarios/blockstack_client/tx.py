#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack-client.

    Blockstack-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack-client. If not, see <http://www.gnu.org/licenses/>.
"""

import virtualchain

from .operations import (
    tx_preorder, tx_register, tx_update, tx_transfer, tx_revoke,
    tx_namespace_preorder, tx_namespace_reveal, tx_namespace_ready,
    tx_name_import, tx_announce
)

from .constants import CONFIG_PATH, BLOCKSTACK_TEST, BLOCKSTACK_DRY_RUN
from .config import get_tx_broadcaster
from .logger import get_logger

from .backend.blockchain import broadcast_tx

log = get_logger('blockstack-client')


def serialize_tx(inputs, outputs):
    """
    Given the inputs and outputs to a transaction, serialize them
    to the appropriate blockchain format.

    Return the hex-string containing the transaction
    """

    # TODO: expand beyond bitcoin
    txobj = {
        'ins': inputs,
        'outs': outputs,
        'locktime': 0,
        'version': 1
    }

    # log.debug("serialize tx: {}".format(json.dumps(txobj, indent=4, sort_keys=True)))
    txstr = virtualchain.btc_tx_serialize(txobj)
    return txstr


def deserialize_tx(txstr):
    """
    Given a tx string, deserialize it into the inputs and outputs
    """
    # TODO: expand beyond bitcoin
    txobj = virtualchain.btc_tx_deserialize(txstr)
    return txobj['ins'], txobj['outs']


## Aaron: preorder, register, update, and transfer accept
##        a `dust_included` parameter, which allows the caller
##        to tell the serializer that they already included the
##        dust fee in the given tx_fee. this prevents double counting
##        dust fees.

def preorder_tx(*args, **kw):
    """
    Make an unsigned preorder transaction
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_preorder(*args, **kw)
    return serialize_tx(inputs, outputs)


def register_tx(*args, **kw):
    """
    Make an unsigned register transaction
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_register(*args, **kw)
    return serialize_tx(inputs, outputs)


def update_tx(*args, **kw):
    """
    Make an unsigned update transaction
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_update(*args, **kw)
    return serialize_tx(inputs, outputs)


def transfer_tx(*args, **kw):
    """
    Make an unsigned transfer transaction
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_transfer(*args, **kw)
    return serialize_tx(inputs, outputs)


def revoke_tx(*args, **kw):
    """
    Make an unsigned revoke transaction
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_revoke(*args, **kw)
    return serialize_tx(inputs, outputs)


def namespace_preorder_tx(*args, **kw):
    """
    Make an unsigned namespace preorder transaction
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_namespace_preorder(*args, **kw)
    return serialize_tx(inputs, outputs)


def namespace_reveal_tx(*args, **kw):
    """
    Make an unsigned namespace reveal transaction
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_namespace_reveal(*args, **kw)
    return serialize_tx(inputs, outputs)


def namespace_ready_tx(*args, **kw):
    """
    Make an unsigned namespace ready transaction
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_namespace_ready(*args, **kw)
    return serialize_tx(inputs, outputs)


def name_import_tx(*args, **kw):
    """
    Make an unsigned name import transaction
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_name_import(*args, **kw)
    return serialize_tx(inputs, outputs)


def announce_tx(*args, **kw):
    """
    Make an unsigned announce transaction
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_announce(*args, **kw)
    return serialize_tx(inputs, outputs)


def sign_tx(tx_hex, prev_outputs, private_key_info):
    """
    Sign a transaction
    @param tx_hex (string) the hex-encoded unsigned transaction
    @param prev_outputs (list) a list of [{'out_script': xxx, 'value': xxx}] dicts
    @param private_key_info (string or dict) the private key info bundle
    """
    return virtualchain.tx_sign_all_unsigned_inputs(private_key_info, prev_outputs, tx_hex)


def sign_and_broadcast_tx(tx_hex, prev_outputs, private_key_info, config_path=CONFIG_PATH, tx_broadcaster=None):
    """
    Sign and send a transaction
    """
    signed_tx = sign_tx(tx_hex, prev_outputs, private_key_info)
    resp = {}
    try:
        resp = broadcast_tx(signed_tx, config_path=config_path, tx_broadcaster=tx_broadcaster)
    except Exception as e:
        log.exception(e)
        log.error('Failed to broadcast transaction: {}'.format(signed_tx))
        return {'error': 'Failed to broadcast transaction (caught exception)'}

    if 'error' in resp:
        log.error('Failed to broadcast transaction: {}'.format(resp['error']))

    return resp
