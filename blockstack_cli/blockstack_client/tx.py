#!/usr/bin/env python
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

import pybitcoin
from .operations import *
from .config import CONFIG_PATH, get_utxo_provider_client, get_tx_broadcaster, get_logger
from pybitcoin import serialize_transaction, sign_all_unsigned_inputs, broadcast_transaction

log = get_logger("blockstack-client")

def preorder_tx( *args, **kw ):
    """
    Make an unsigned preorder transaction
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_preorder( *args, **kw )
    return pybitcoin.serialize_transaction( inputs, outputs )


def register_tx( *args, **kw ):
    """
    Make an unsigned register transaction
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_register( *args, **kw )
    return pybitcoin.serialize_transaction( inputs, outputs )


def update_tx( *args, **kw ):
    """
    Make an unsigned update transaction
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_update( *args, **kw )
    return pybitcoin.serialize_transaction( inputs, outputs )


def transfer_tx( *args, **kw ):
    """
    Make an unsigned transfer transaction
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_transfer( *args, **kw ) 
    return pybitcoin.serialize_transaction( inputs, outputs )


def revoke_tx( *args, **kw ):
    """
    Make an unsigned revoke transaction
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_revoke( *args, **kw )
    return pybitcoin.serialize_transaction( inputs, outputs )


def namespace_preorder_tx( *args, **kw ):
    """
    Make an unsigned namespace preorder transaction
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_namespace_preorder( *args, **kw )
    return pybitcoin.serialize_transaction( inputs, outputs )


def namespace_reveal_tx( *args, **kw ):
    """
    Make an unsigned namespace reveal transaction 
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_namespace_reveal( *args, **kw )
    return pybitcoin.serialize_transaction( inputs, outputs )


def namespace_ready_tx( *args, **kw ):
    """
    Make an unsigned namespace ready transaction 
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_namespace_ready( *args, **kw )
    return pybitcoin.serialize_transaction( inputs, outputs )


def name_import_tx( *args, **kw ):
    """
    Make an unsigned name import transaction
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_name_import( *args, **kw )
    return pybitcoin.serialize_transaction( inputs, outputs )


def announce_tx( *args, **kw ):
    """
    Make an unsigned announce transaction
    Raise ValueError if there are not enough inputs to make the transaction
    """
    inputs, outputs = tx_announce( *args, **kw )
    return pybitcoin.serialize_transaction( inputs, outputs )


def sign_tx( tx_hex, private_key_hex ):
    """
    Sign a transaction
    """
    return sign_all_unsigned_inputs( private_key_hex, tx_hex )


def broadcast_tx( tx_hex, config_path=CONFIG_PATH, tx_broadcaster=None ):
    """
    Send a signed transaction to the blockchain
    """
    if tx_broadcaster is None:
        tx_broadcaster = get_tx_broadcaster( config_path=config_path )

    resp = broadcast_transaction( tx_hex, tx_broadcaster )
    if 'tx_hash' not in resp:
        resp['error'] = 'Failed to broadcast transaction: %s' % tx_hex

    # for compatibility
    resp['transaction_hash'] = resp['tx_hash']
    del resp['tx_hash']
    return resp


def sign_and_broadcast_tx( tx_hex, private_key_hex, config_path=CONFIG_PATH, tx_broadcaster=None ):
    """
    Sign and send a transaction
    """
    signed_tx = sign_tx( tx_hex, private_key_hex )
    resp = broadcast_tx( signed_tx, config_path=config_path, tx_broadcaster=tx_broadcaster )
    return resp

