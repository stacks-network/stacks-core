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

# use Blockstack Labs as a storage proxy

import os
import sys 
import traceback
import logging
import xmlrpclib
import json
import re
from ConfigParser import SafeConfigParser

import blockstack_zones

# stop common XML attacks 
from defusedxml import xmlrpc
xmlrpc.monkey_patch()

from common import get_logger, DEBUG

SERVER_NAME = None
SERVER_PORT = None 

if os.environ.get("BLOCKSTACK_TEST", None) == "1":
    SERVER_NAME = "localhost"
    SERVER_PORT = 16264

else:
    SERVER_NAME = "node.blockstack.org"
    SERVER_PORT = 6264

log = get_logger("blockstack-storage-driver-blockstack-server")
log.setLevel(logging.DEBUG)


def is_zonefile_hash( data_id ):
    """
    Is the given ID a zonefile hash?
    """
    return (re.match("^[0-9a-fA-F]{40}$", data_id) is not None)


def get_data( data_id, zonefile=False ):
    """
    Get data or a zonefile from the server.
    """

    if os.environ.get("BLOCKSTACK_RPC_PID", None) == str(os.getpid()):
        # don't talk to ourselves 
        log.debug("Do not get_data from ourselves")
        return None

    url = "http://%s:%s/RPC2" % (SERVER_NAME, SERVER_PORT)
    ses = xmlrpclib.ServerProxy( url, allow_none=True )
    
    if zonefile:
        log.debug("Get zonefile for %s" % data_id)

        res = None
        if is_zonefile_hash(data_id):
            res = ses.get_zonefiles([data_id])
        else:
            res = ses.get_zonefiles_by_names( [data_id] )

        try:
            data = json.loads(res)
        except:
            log.error("Failed to parse zonefile from %s" % data_id)
            return None

        if 'error' in data:
            log.error("Get zonefile %s: %s" % (data_id, data['error']))
            return None
        else:
            try:
                return data['zonefiles'][data_id]
            except:
                log.error("Failed to parse zonefile")
                print data
                return None

    else:
        log.debug("Get profile for %s" % data_id)
        res = ses.get_profile( data_id )
        try:
            data = json.loads(res)
        except:
            log.error("Failed to parse profile from %s" % data_id)
            return None

        if 'error' in data:
            log.error("Get profile %s: %s" % (data_id, data['error']))
            return None 
        else:
            try:
                return data['profile']
            except:
                log.error("Failed to parse profile")
                return None


def put_data( data_id, data_txt, zonefile=False ):
    """
    Put data or a zoneflie to the server.
    """
    
    if os.environ.get("BLOCKSTACK_RPC_PID", None) == str(os.getpid()):
        # don't talk to ourselves 
        log.debug("Do not put_data to ourselves")
        return False

    url = "http://%s:%s/RPC2" % (SERVER_NAME, SERVER_PORT)
    ses = xmlrpclib.ServerProxy( url, allow_none=True )

    if zonefile:
        # must be a zonefile 
        try:
            zf = blockstack_zones.parse_zone_file( data_txt )
        except:
            log.error("Failed to parse zone file for %s" % data_id)
            return False
 
        log.debug("Replicate zonefile for %s" % data_id)
        res_json = ses.put_zonefiles( [data_txt] )
        try:
            res = json.loads(res_json)
        except:
            log.error("Invalid non-JSON response")
            return False

        if 'error' in res:
            log.error("Failed to put %s: %s" % (data_id, data_txt))
            return False
        elif len(res['saved']) != 1 or res['saved'][0] != 1:
            log.error("Server %s:%s failed to save %s" % (SERVER_NAME, SERVER_PORT, data_id))
            return False 

        else:
            return True

    else:
        log.debug("Replicate profile for %s" % data_id)
        res = ses.put_profile( data_id, data_txt )
        if 'error' in res:
            log.error("Failed to put %s: %s" % (data_id, res))
            return False
        else:
            return True


def storage_init(conf):
    # read config options from the config file, if given 
    global SERVER_NAME, SERVER_PORT

    config_path = conf['path']
    if os.path.exists( config_path ):

        parser = SafeConfigParser()
        
        try:
            parser.read(config_path)
        except Exception, e:
            log.exception(e)
            return False

        if parser.has_section('blockstack-server-storage'):
            
            if parser.has_option('blockstack-server-storage', 'server'):
                SERVER_NAME = parser.get('blockstack-server-storage', 'server')
                
            if parser.has_option('blockstack-server-storage', 'port'):
                SERVER_PORT = int(parser.get('blockstack-server-storage', 'port'))
           
    else:
        raise Exception("No such file or directory: %s" % config_path)
            
    # we can't proceed unless we have them.
    if SERVER_NAME is None or SERVER_PORT is None:
        log.error("Config file '%s': section 'blockstack_server_storage' is missing 'host' and/or 'port'")
        return False

    return True


def handles_url( url ):
    if (url.startswith("http://") or url.startswith("https://")) and len(url.split("#")) == 2 and url.split("#")[0].endswith("/RPC2"):
        return True
    else:
        return False

def make_mutable_url( data_id ):
    # xmlrpc endpoint
    return "http://%s:%s/RPC2#%s" % (SERVER_NAME, SERVER_PORT, data_id)

def get_immutable_handler( key, **kw ):
    """
    Only works on user zonefiles, and only works on names
    """
    fqu = kw.get("fqu", None)
    zonefile = kw.get("zonefile", False)
    if fqu is None:
        # fall back to whatever the key is
        fqu = key

    return get_data( fqu, zonefile=zonefile )


def get_mutable_handler( url, **kw ):
    parts = url.split("#")
    if len(parts) != 2:
        log.error("Invalid url '%s'" % url)
        return None

    data_id = parts[1]
    return get_data( data_id, zonefile=False )


def put_immutable_handler( key, data, txid, **kw ):
    return put_data( key, data, zonefile=True )

def put_mutable_handler( data_id, data_bin, **kw ):
    return put_data( data_id, data_bin, zonefile=False )

def delete_immutable_handler( key, txid, sig_key_txid, **kw ):
    return True

def delete_mutable_handler( data_id, signature, **kw ):
    return True

if __name__ == "__main__":
    config_path = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    assert config_path is not None, "You must set BLOCKSTACK_CLIENT_CONFIG"

    import blockstack_client
    config = blockstack_client.get_config(config_path)
    assert config is not None

    print json.dumps(config, indent=4, sort_keys=True)
    storage_init(config)

    assert len(sys.argv) > 1, "You must specify one or more names"
    for name in sys.argv[1:]:
        zonefile = get_data(name, zonefile=True)
        assert zonefile is not None and 'error' not in zonefile, "Bad zonefile: %s" % zonefile
        profile = get_data( name, zonefile=False )
        assert profile is not None and 'error' not in profile, "Bad profile: %s" % profile

        print "zonefile:\n%s" % zonefile
        print "profile:\n%s" % json.dumps(profile, indent=4, sort_keys=True)
        print ""

