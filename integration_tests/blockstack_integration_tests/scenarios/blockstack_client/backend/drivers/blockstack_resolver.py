#!/usr/bin/env python2
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

# use Blockstack Labs as a read-only reader for zonefile/profile data

import os
import json
import requests
from ConfigParser import SafeConfigParser

import virtualchain
from virtualchain.lib.hashing import *

from common import get_logger

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
    import blockstack_client

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
    if hex_hash160( zone_file_str ) != zonefile_hash:
        log.debug("Hash mismatch for %s: expected %s, got %s" % (fqu, zonefile_hash, hex_hash160(zone_file_str)))
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
    return json.dumps([ret])


def storage_init(conf, **kw):
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

def get_classes():
    return ['read_public']

