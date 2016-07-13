#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack

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

import os
import sys
import json
import blockstack_zones

import blockstack_client

import virtualchain
from ..nameset import get_db_state
from blockstack_client import hash_zonefile, get_zonefile_data_hash

log = virtualchain.get_logger("blockstack-server")

def is_current_zonefile_hash( value_hash ):
    """
    Is this, in fact, a valid value hash?
    """
    db = get_db_state()
    names = db.get_names_with_value_hash( value_hash )
    if names is None:
        return False 

    else:
        log.debug("Value hash '%s' belongs to '%s'" % (value_hash, ",".join(names)))
        return True


def serialize_zonefile( zonefile_data ):
    """
    Serialize a zonefile to string
    """
    
    zonefile_txt = blockstack_zones.make_zone_file( zonefile_data )
    return zonefile_txt


def verify_zonefile( zonefile_str, value_hash ):
    """
    Verify that a zonefile hashes to the given value hash
    @zonefile_str must be the zonefile as a serialized string
    """
    zonefile_hash = get_zonefile_data_hash( zonefile_str )
    if zonefile_hash != value_hash:
        log.debug("Zonefile hash mismatch: expected %s, got %s" % (value_hash, zonefile_hash))
        return False 

    return True


def is_valid_zonefile( zonefile_str, value_hash ):
    """
    Is the given zonefile valid:
    * does it hash to the given value_hash?
    * is the value_hash current?

    zonefile_str should be the serialized zonefile
    """
    if not verify_zonefile( zonefile_str, value_hash ):
        return False

    if not is_current_zonefile_hash( value_hash ):
        return False 

    return True
