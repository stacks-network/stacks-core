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

import namedb 
import virtualchain_hooks

from .namedb import BlockstoreDB, BlockstoreDBIterator, get_namespace_from_name, price_name, is_name_mining_fee_sufficient, \
    is_namespace_mining_fee_sufficient
from .virtualchain_hooks import get_virtual_chain_name, get_virtual_chain_version, get_first_block_id, get_opcodes, \
    get_op_processing_order, get_magic_bytes, get_db_state, db_parse, db_check, db_commit, db_save, db_iterable