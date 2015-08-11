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

import re
import math 

from .config import DEFAULT_OP_RETURN_FEE, SATOSHIS_PER_BTC


def is_alphabetic(s):
    return len(re.findall('[^a-z]', s)) == 0


def has_numerics(s):
    return len(re.findall('[0-9]', s)) > 0


def has_underscores_or_dashes(s):
    return len(re.findall('[-_]', s)) > 0


def calculate_basic_name_tx_fee():
    return DEFAULT_OP_RETURN_FEE

def calculate_name_price(name, namespace_base_price, namespace_decay):
    
    # establish the base price (in satoshis)
    price = float(namespace_base_price)
    
    # adjust the price by a factor X for every character beyond the first
    price = ceil( price / (namespace_decay**(len(name)-1)) )
    
    # price cannot be lower than 1 satoshi
    if price < 1:
       price = 1
    
    return price
 

def is_mining_fee_sufficient(name, mining_fee, namespace_base_price, namespace_decay):
    name_price = 0
    # TODO: use namespace pricing
    # name_price = calculate_name_price(name, namespace_base_price, namespace_decay)
    return (mining_fee >= name_price)
