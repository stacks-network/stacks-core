#!/usr/bin/env python2
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

import virtualchain
import hashlib

from virtualchain.lib.hashing import hex_hash160

log = virtualchain.get_logger("blockstack-server")


def get_data_hash(data_txt):
    """
    Generate a hash over data for immutable storage.
    Return the hex string.
    """
    h = hashlib.sha256()
    h.update(data_txt)
    return h.hexdigest()


def get_zonefile_data_hash(data_txt):
    """
    Generate a hash over a user's zonefile.
    Return the hex string.
    """
    return hex_hash160(data_txt)


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

