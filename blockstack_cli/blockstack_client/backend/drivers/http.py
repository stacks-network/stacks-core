#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    The MIT License (MIT)
    Copyright (c) 2014-2015 by Halfmoon Labs, Inc.
    Copyright (c) 2016 by Blocktatck.org

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included
    in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
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
