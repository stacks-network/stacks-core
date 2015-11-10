#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org
    
    This file is part of Blockstore
    
    Blockstore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    Blockstore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore.  If not, see <http://www.gnu.org/licenses/>.
"""

# all fields common to a name record
# NOTE: this order must be preserved for all eternity
NAMEREC_FIELDS = [
    'name',                 # the name itself
    'value_hash',           # the hash of the name's associated profile
    'sender',               # the scriptPubKey hex that owns this name (identifies ownership)
    'sender_pubkey',        # (OPTIONAL) the public key 
    'address',              # the address of the sender
    
    'block_number',         # the block number when this name record was created (preordered for the first time)
    'preorder_block_number', # the block number when this name was last preordered
    'first_registered',     # the block number when this name was registered by the current owner
    'last_renewed',         # the block number when this name was renewed by the current owner
    'revoked',              # whether or not the name is revoked

    'op',                   # byte sequence describing the last operation to affect this name
    'txid',                 # the ID of the last transaction to affect this name
    'vtxindex',             # the index in the block of the transaction.
    'op_fee',               # the value of the last Blockstore-specific burn fee paid for this name (i.e. from preorder or renew)

    'importer',             # (OPTIONAL) if this name was imported, this is the importer's scriptPubKey hex
    'importer_address',     # (OPTIONAL) if this name was imported, this is the importer's address
]

import namedb 
import virtualchain_hooks

from .namedb import BlockstoreDB, get_namespace_from_name, price_name, \
    get_name_from_fq_name, price_namespace
from .virtualchain_hooks import get_virtual_chain_name, get_virtual_chain_version, get_first_block_id, get_opcodes, \
    get_op_processing_order, get_magic_bytes, get_db_state, db_parse, db_check, db_commit, db_save, db_serialize
