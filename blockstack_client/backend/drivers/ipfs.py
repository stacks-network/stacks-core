#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016-2017 by Blockstack.org
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

import os
import sys 
import traceback
import logging
from common import get_logger, DEBUG
from ConfigParser import SafeConfigParser

import ipfsapi


EMPTY_STRING_HASH = 'QmaRwA91m9Rdfaq9u3FH1fdMVxw1wFPjKL38czkWMxh3KB'

log = get_logger("blockstack-storage-skel")
log.setLevel( logging.DEBUG if DEBUG else logging.INFO )

ipfs = None


def url_to_uri(url):
    if (ipfs.startwith('ipfs://')):
        url = url.replace(('ipfs://'), "/ipfs/")
    elif (ipfs.startwith('ipns://')):
        url = url.replace(('ipns://'), "/ipns/")

    return url


def storage_init(conf, **kwargs):
    """
    Initialize IPFS storage driver
    """
    global ipfs

    SERVER = 'localhost'
    PORT = '5001'

    # path to the CLI's configuration file (where you can stash driver-specific configuration)
    config_path = conf['path']
    if os.path.exists( config_path ):

        parser = SafeConfigParser()
        
        try:
           parser.read(config_path)
        except Exception, e:
           log.exception(e)
           return False

        if parser.has_section('ipfs'):
            SERVER = parser.get('ipfs', 'server') if parser.has_option('ipfs', 'server') else SERVER
            PORT = parser.get('ipfs', 'port') if parser.has_option('ipfs', 'port') else PORT

    try:
        ipfs = ipfsapi.connect(SERVER, PORT)
    except:
        ipfs = None
        SERVER = None
        PORT = None


    existingKeys = ipfs._client.request('/key/list', decoder='json')['Keys']
    if "blockstack" not in [key['Name'] for key in existingKeys]:
        ipfs._client.request('/key/gen', ("blockstack",), decoder='json', opts={'type':'rsa','size':'2048'})

    try:
        ipfs.files_mkdir("/blockstack")
    except:
        pass

    return True 


def handles_url( url ):
    """
    Checks to see if its in the proper URI or URL format for IPFS or IPNS objects
    """

    return True if url.startwith('/ipfs/') or url.startswith('ipfs://') or url.startswith('/ipns/') or url.startswith('ipns://') else False


def make_mutable_url( data_id ):
    """
    Returns IPNS URL for a file in a file system pointed to by an IPNS object.
    """
    try:
        existingKeys = ipfs.files_ls("/blockstack")['Entries']
        
        if data_id not in [key['Name'] for key in existingKeys]:
            ipfs.files_cp('/ipfs/' + EMPTY_STRING_HASH, '/blockstack/' + data_id)
        
        h = ipfs.files_stat('/blockstack')

        ipns_object = ipfs.name_publish(h, {opts:{'key':'blockstack'}})

        return ('/ipns/' + ipns_object['Name'])
    except:
        return None


def get_immutable_handler( data_hash, **kw ):
    """
    Get data from IPFS
    """
    try:
        return ipfs.cat(data_hash)
    except:
        return None

def get_mutable_handler( url, **kw ):
    """
    Get data from IPFS Object pointed to by IPNS Object
    """
    url = url_to_uri(url)

    try:
        data_hash = ipfs.name_resolve(url)['Path']
    except:
        return None

    return get_immutable_handler(data_hash)


def put_immutable_handler( data_hash, data_txt, txid, **kw ):
    """
    Add String to IPFS
    """
    try:
        ipfs.add_str( data_txt, decoder='json' )      
        return True  
    except:
        return False

def put_mutable_handler( data_id, data_txt, **kw ):
    """
    Put Data in IPFS Object and link to IPNS name
    """
    try:
        ipfs_hash = ipfs.add_str(data_txt)
        ipfs.files_cp('/ipfs/' + ipfs_hash, '/blockstack/' + data_id)
        return True
    except:
        return False


def delete_immutable_handler( data_hash, txid, tombstone, **kw ):
    """
    Deletes IPFS object from Local Storage.
    NOTE:  It is impossible to remove object from IPFS once published.
    """
    try:
        ipfs.pin_rm(data_hash)
        return True
    except:
        return False


def delete_mutable_handler( data_id, tombstone, **kw ):
    """
    Delete IPFS Object from Local Storage then remove pointer from IPNS Object
    """

    ipfs_hash = ipns.name_resolve(url)['Path']
    delete_immutable_handler(ipfs_hash)
    
    ipfs.files_rm('/blockstack/' + data_id)
    h = ipfs.files_stat('/blockstack')
    ipns_object = ipfs.name_publish(h, {opts:{'key':'blockstack'}})



if __name__ == "__main__":
   """
   Removed unit tests.
   """
   pass