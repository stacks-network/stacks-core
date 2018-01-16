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

# use Blockstack Labs as a storage proxy

import os
import sys 
import logging
import xmlrpclib
import json
import re
import base64
from ConfigParser import SafeConfigParser

# stop common XML attacks 
from defusedxml import xmlrpc
xmlrpc.monkey_patch()

from common import get_logger

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


def get_data( data_id, zonefile=False, fqu=None ):
    """
    Get data or a zonefile from the server.
    """

    if os.environ.get("BLOCKSTACK_RPC_PID", None) == str(os.getpid()):
        # don't talk to ourselves 
        log.warn("Calling get_data to ourselves in the same process")

    url = "http://%s:%s/RPC2" % (SERVER_NAME, SERVER_PORT)
    ses = xmlrpclib.ServerProxy( url, allow_none=True )
   
    import blockstack_client

    if zonefile:
        log.debug("Get zonefile for %s" % data_id)
        
        zonefile_hash = None
        if not is_zonefile_hash(data_id):

            if not blockstack_client.is_name_valid(data_id):
                log.error("Not a valid name or zone file hash: {}".format(data_id))
                return None

            # find zonefile hash
            res = blockstack_client.proxy.get_name_blockchain_record(data_id, proxy=ses)
            if 'error' in res:
                log.error("Failed to look up {}: {}".format(data_id), res['error'])
                return None

            zonefile_hash = res.get('value_hash', None)
            if zonefile_hash is None:
                log.error("No zonefile hash for {}".format(data_id))
                return None

        res = blockstack_client.proxy.get_zonefiles([zonefile_hash], proxy=ses)
        if 'error' in res:
            log.error("Failed to look up {}: {}".format(zonefile_hash), res['error'])
            return None
        
        try:
            return base64.b64decode(data['zonefiles'][zonefile_hash])
        except:
            log.error("Failed to decode zonefile")
            return None

    elif blockstack_client.is_name_valid(data_id):
        log.debug("Get profile for %s" % data_id)
        res = ses.get_profile( data_id )
        try:
            data = json.loads(res)
        except:
            log.error("Failed to parse profile from %s" % data_id)
            return None

        if type(data) != dict:
            log.error("Invalid profile data for %s" % data_id)
            return None

        if 'error' in data:
            log.error("Get profile %s: %s" % (data_id, data['error']))
            return None 

        try:
            return data['profile']
        except:
            log.error("Failed to parse profile")
            return None
    
    elif fqu is not None:
        log.debug("Get mutable data for %s (%s)" % (data_id, fqu))
        res = ses.get_mutable_data( fqu, data_id )

        try:
            res = json.loads(res)
        except: 
            log.error("Failed to parse data for %s" % data_id)
            return None

        if blockstack_client.proxy.json_is_error(res):
            log.error("Failed to get mutable data: {}".format(res['error']))
            return None

        if not isinstance(res, dict):
            log.error("Response is not a dict")
            return None

        if not res.has_key('data'):
            log.error("Response has not data")
            return None

        if type(res['data']) not in [str, unicode]:
            log.error("Response is not data string")
            return None

        return res['data']

    else:
        log.error("No blockchain ID given; cannot load data")
        return None


def put_data( data_id, data_txt, zonefile=False, fqu=None, profile=False ):
    """
    Put data or a zonefile to the server.
    """
    
    import blockstack_client
    import blockstack

    if os.environ.get("BLOCKSTACK_RPC_PID", None) == str(os.getpid()):
        # don't talk to ourselves 
        log.warn("Calling put_data to ourselves in the same process")

    url = "http://%s:%s/RPC2" % (SERVER_NAME, SERVER_PORT)
    ses = xmlrpclib.ServerProxy( url, allow_none=True )

    if zonefile:
        # don't duplicate effort
        log.error("Driver does not support putting a zonefile")
        return False
        
    elif profile:
        log.debug("Replicate profile for %s" % data_id)

        # data_txt must be a sufficiently small JSON blob
        if len(data_txt) >= blockstack.RPC_MAX_PROFILE_LEN:
            log.error("Data is too big")
            return False
       
        # NOTE: last two arguments are legacy compat
        res = ses.put_profile( data_id, data_txt, '', '')
        if 'error' in res:
            log.error("Failed to put %s: %s" % (data_id, res))
            return False
        else:
            return True

    elif fqu is not None:
        log.debug("Replicate mutable datum {}".format(data_id))

        # data_txt must be a sufficiently small JSON blob
        if len(data_txt) >= blockstack.RPC_MAX_DATA_LEN:
            log.error("Data is too big")
            return False
       
        res = ses.put_mutable_data( fqu, data_txt )
        if 'error' in res:
            log.error("Failed to put %s: %s" % (data_id, res))
            return False
        else:
            return True

    else:
        log.debug("No name given; cannot store data")
        return False


def storage_init(conf, **kw):
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

    fqu = kw.get('fqu', None)
    data_id = parts[1]
    return get_data( data_id, zonefile=False, fqu=fqu )


def put_immutable_handler( key, data, txid, **kw ):
    return put_data( key, data, zonefile=True )

def put_mutable_handler( data_id, data_bin, **kw ):
    return put_data( data_id, data_bin, zonefile=False, fqu=kw.get('fqu', None), profile=kw.get('profile', False) )

def delete_immutable_handler( key, txid, sig_key_txid, **kw ):
    return True

def delete_mutable_handler( data_id, signature, **kw ):
    return True

def get_classes():
    return ['read_public', 'write_private']

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

