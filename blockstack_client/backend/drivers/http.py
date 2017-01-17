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

import os
import sys
import requests
from common import get_logger

log = get_logger("blockstack-storage-drivers-http")

def storage_init(conf):
    return True

def handles_url( url ):
    return url.lower().startswith("https://") or url.lower().startswith("http://")

def make_mutable_url( data_id ):
    return None

def get_immutable_handler( key, **kw ):
    return None


def get_mutable_handler( url, **kw ):
    try:
        req = requests.get(url)
        if req.status_code != 200:
            log.debug("GET %s status code %s" % (url, req.status_code))
            return None

        return req.content 
    except Exception, e:
        log.exception(e)
        return None


def put_immutable_handler( key, data, txid, **kw ):
    # read only
    return False

def put_mutable_handler( data_id, data_bin, **kw ):
    # read only
    return False

def delete_immutable_handler( key, txid, sig_key_txid, **kw ):
    return True

def delete_mutable_handler( data_id, signature, **kw ):
    return True
