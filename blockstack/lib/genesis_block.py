#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016-2018 by Blockstack.org

    This file is part of Blockstack.

    Blockstack is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
"""

# for the sake of interpreting a JSON string as Python
true = True
false = False

# TODO: fill in 
GENESIS_BLOCK_STAGES = [
    {
        'history': [],
        'rows': [],
    }
]

# TODO: fill in -- map key ID to ASCII armored public key
GENESIS_BLOCK_SIGNING_KEYS = {}

# genesis block is the final stage of the genesis block's evolution
GENESIS_BLOCK = GENESIS_BLOCK_STAGES[-1]

