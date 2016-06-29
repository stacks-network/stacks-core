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

# use Blockstack Labs as a read-only reader for zonefile/profile data

import os
import sys 
import traceback
import logging
import json
import requests
import pybitcoin
from ConfigParser import SafeConfigParser

import blockstack_zones

from common import get_logger, DEBUG

log = get_logger("blockstack-storage-driver-blockstack-s3-readonly")

if os.environ.get("BLOCKSTACK_TEST") is None:
    RESOLVER_URL = "https://onename.com"
    STORAGE_URL = "https://blockstack.s3.amazonaws.com"
else:
    RESOLVER_URL = "http://localhost:8081"
    STORAGE_URL = "http://localhost:8081"


def get_zonefile( fqu, zonefile_hash ):
    """
    Try to get a zonefile, from onename.com
    Return the zonefile (serialized as a string) on success
    Return None on error
    """
    fqu_json = fqu.split(".")[0] + ".json"
    url = "%s/%s" % (RESOLVER_URL, fqu_json)
    req = requests.get(url)
    if req.status_code != 200:
        log.debug("GET %s status code %s" % (url, req.status_code))
        return None

    try:
        res = json.loads(req.content)
    except Exception, e:
        log.exception(e)
        log.debug("Failed to parse request to %s" % url)
        return None 

    if 'zone_file' not in res.keys():
        log.debug("No zonefile in request to %s" % url)
        return None
    
    zone_file_str = str(res['zone_file'])
    if pybitcoin.hex_hash160( zone_file_str ) != zonefile_hash:
        log.debug("Hash mismatch: expected %s, got %s" % (pybitcoin.hex_hash160(zone_file_str), zonefile_hash))
        return None

    return zone_file_str


def get_profile( fqu ):
    """
    Try to get a profile, from S3
    """
    url = "%s/%s" % (STORAGE_URL, fqu)
    req = requests.get(url)
    if req.status_code != 200:
        log.debug("GET %s status code %s" % (url, req.status_code))
        return None

    try:
        res = json.loads(req.content)
    except Exception, e:
        log.exception(e)
        log.debug("Failed to parse request to %s" % url)
        return None

    try:
        res = res[0]
    except:
        log.debug("JWT is not a list")
        return None 

    for k in ['token', 'parentPublicKey']:
        if k not in res.keys():
            log.debug("Missing required key '%s' in request to %s" % (k, url))
            return None

    ret = {}
    ret['token'] = res['token']
    ret['parentPublicKey'] = res['parentPublicKey']
    return ret


def storage_init(conf):
    # read config options from the config file, if given 
    global STORAGE_URL, RESOLVER_URL

    config_path = conf['path']
    if os.path.exists( config_path ):

        parser = SafeConfigParser()
        
        try:
            parser.read(config_path)
        except Exception, e:
            log.exception(e)
            return False

        if parser.has_section('blockstack-resolver-storage'):
            
            if parser.has_option('blockstack-resolver-storage', 'storage_url'):
                SERVER_NAME = parser.get('blockstack-resolver-storage', 'storage_url')
                
            if parser.has_option('blockstack-resolver-storage', 'resolver_url'):
                SERVER_PORT = int(parser.get('blockstack-resolver-storage', 'resolver_url'))
            
            
    # we can't proceed unless we have them.
    if STORAGE_URL is None or RESOLVER_URL is None:
        log.error("Config file '%s': section 'blockstack_resolver_storage' is missing 'resolver_url' and/or 'storage_url'")
        return False

    return True


def handles_url( url ):
    if RESOLVER_URL in url or STORAGE_URL in url:
        return True
    else:
        return False

def make_mutable_url( data_id ):
    # only deal with names 
    if ':' in data_id:
        return None 
    else:
        return "%s/%s" % (STORAGE_URL, data_id)
    

def get_immutable_handler( key, **kw ):
    # only works for zonefiles, and we need the name
    if 'zonefile' in kw and not kw['zonefile']:
        return None
    
    fqu = kw.get('fqu', None)
    if fqu is None:
        return None

    return get_zonefile( fqu, key )


def get_mutable_handler( url, **kw ):
    # only works for profiles
    fqu = kw.get('fqu', None)
    if fqu is None:
        return None

    return get_profile( fqu )


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
