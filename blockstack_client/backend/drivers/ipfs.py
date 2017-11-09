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

import sys
import os
import io
import re
import zlib
import json
import logging

import requests
import ipfsapi

from common import get_logger, driver_config, DEBUG, \
    index_setup, decompress_chunk, index_make_mutable_url, \
    index_put_mutable_handler, index_put_immutable_handler, \
    index_get_mutable_handler, index_get_immutable_handler, \
    index_delete_mutable_handler, index_delete_immutable_handler
from ConfigParser import SafeConfigParser

log = get_logger("blockstack-storage-driver-ipfs")
log.setLevel( logging.DEBUG if DEBUG else logging.INFO )

IPFS_DEFAULT_COMPRESS = False

IPFS_DEFAULT_GATEWAY = 'https://gateway.ipfs.io'

INDEX_DIRNAME = 'index'
DVCONF        = None


def ipfs_default_gw( hash_ ):
    """
    Return the default gateway url for a given hash
    """
    return '{}/ipfs/{}'.format(IPFS_DEFAULT_GATEWAY, hash_)


def ipfs_put_chunk( dvconf, chunk_buf, chunk_path ):
    """
    Write a chunk of data to IPFS.
    
    Return True on success 
    Return False on error, and log an exception
    """
    try:
        dvconf['driver_info']['api'].files_mkdir(os.path.dirname(chunk_path), 
                                                 parents = True)
    except Exception, e:
        log.error('Failed to create {}'.format(chunk_path))
        log.exception(e)
        rc = False
    else:
        """ 
        There is a bug with the ipfsapi implementation in which
        the 'truncate' option in files_write() has no effect, as reported
        here: https://github.com/ipfs/py-ipfs-api/issues/112
        Until that is fixed, we try to delete the file first, to account  
        for those cases in which len(chunk_buf) is shorter than the 
        contents of the file. When the bug is fixed, we can safely 
        remove the call to ipfs_delete_chunk()
        """
        try:
            dvconf['driver_info']['api'].files_rm(chunk_path)
        except:
            try:
                dvconf['driver_info']['api'].pin_rm(chunk_path)
            except:
                pass

        try:
            r = dvconf['driver_info']['api'].files_write( chunk_path, 
                                      io.BytesIO(str(chunk_buf)), 
                                      create = True,
                                      truncate = True )
            h = dvconf['driver_info']['api'].files_stat (chunk_path)['Hash']
            rc = 'ipfs://{}'.format(h)
            log.debug("{} available at {}".format(chunk_path, rc))
        except Exception, e:
            log.error("Failed to write '{}'".format(chunk_path))
            log.exception(e)
            rc = False

    return rc


def ipfs_get_chunk(dvconf, chunk_path):
    """
    Get a chunk of data from IPFS.
  
    Return the data on success
    Return None on error, and log an exception.
    """
    data = None
    compressed_data = None

    log.debug('Getting chunk at {}'.format(chunk_path))

    if (dvconf is None) or (dvconf is not None and not dvconf['driver_info'].get('api', None)):
        url = ipfs_default_gw(chunk_path)
        log.debug('Fetching {}'.format(url))
        r = requests.get(url)
        if r.status_code != 200:
            log.error("Failed to fetch {url}, error code: {error}".format(
                        url=url,
                        error=r.status_code
                        )
                     )
        else:
            compressed_data = r.text
    else:
        try:
            compressed_data = dvconf['driver_info']['api'].files_read(chunk_path)
        except:
            try:
                compressed_data = dvconf['driver_info']['api'].cat(chunk_path)
            except Exception, e:
                log.error("Failed to read file '{}'".format(chunk_path))
                log.exception(e)

    try:
        data = decompress_chunk( compressed_data )
    except:
        data = compressed_data
      
    return data


def ipfs_delete_chunk(dvconf, chunk_path):
    """
      Delete a chunk of data from IPFS.
    """
    try:
        dvconf['driver_info']['api'].files_rm(chunk_path)
    except Exception, e:
        try:
            dvconf['driver_info']['api'].pin_rm(chunk_path)
        except Exception, e:
            log.error('Failed to delete {}'.format(chunk_path) )
            log.exception(e)
            return False 
    return True


def storage_init(conf, index=False, force_index=False, **kwargs):
    """
    Initialize IPFS storage driver
    """
    global DVCONF

    ipfs_server = None
    ipfs_port = None
    ipfs_compress = IPFS_DEFAULT_COMPRESS

    # path to the CLI's configuration file (where you can stash 
    # driver-specific configuration)
    config_path = conf['path']
    if os.path.exists( config_path ):

        parser = SafeConfigParser()
        
        try:
            parser.read(config_path)
        except Exception, e:
            log.exception(e)
            return False

        if parser.has_section('ipfs'):
            
            if parser.has_option('ipfs', 'server'):
                ipfs_server = parser.get('ipfs', 'server')
                
            if parser.has_option('ipfs', 'port'):
                ipfs_port = parser.get('ipfs', 'port')
            
            if parser.has_option('ipfs', 'compress'):
                ipfs_compress = (parser.get(
                                    'ipfs', 
                                    'compress', 
                                    'false'
                                    ).lower() in ['true', '1', 'yes'])

    if ipfs_server is None:
        log.error("IPFS driver is READ-ONLY: no IPFS server "
                  "configuration found in {}".format(config_path))
        ipfs_api = None
    else:
        ipfs_api = ipfsapi.connect(ipfs_server, ipfs_port)

    DVCONF = driver_config(
                driver_name = 'ipfs',
                config_path = config_path, 
                get_chunk = ipfs_get_chunk,
                put_chunk = ipfs_put_chunk,
                delete_chunk = ipfs_delete_chunk,
                driver_info={
                    'api': ipfs_api,
                    'dynamic_index': True,
                    },
                index_stem=INDEX_DIRNAME,
                compress=ipfs_compress,
                )

    if index:
        url = index_setup(DVCONF,force_index)
        if not url:
            log.error("Failed to set up index")
            return False

    return True 


def handles_url( url ):
    """
    Does this storage driver handle this kind of URL?

    It is okay if other drivers say that they can handle it.
    This is used by the storage system to quickly filter out
    drivers that don't handle this type of URL.

    A common strategy is simply to check if the scheme
    matches what your driver does.  Another common strategy
    is to check if the URL matches a particular regex.
    """
    if url.startswith("ipfs://"):
        return True
    return False


def make_mutable_url( data_id, **kw ):
    """
    Get data by URL
    """
    return index_make_mutable_url( 'ipfs', data_id, scheme='ipfs' )


def get_immutable_handler( key, **kw ):
    """
    Get data by hash
    """
    return index_get_immutable_handler(DVCONF, key, **kw)


def get_mutable_handler( url, **kw ):
    """
    Get data by dynamic hash
    """
    return index_get_mutable_handler(DVCONF, url, **kw)


def put_immutable_handler( key, data, txid, **kw ):
    """
    Put data by hash
    """
    return index_put_immutable_handler(DVCONF, key, data, txid, **kw)


def put_mutable_handler( data_id, data_txt, **kw ):
    """
    Put data by dynamic hash
    """
    return index_put_mutable_handler(DVCONF, data_id, data_txt, **kw)

   
def delete_immutable_handler( key, txid, sig_key_txid, **kw ):
    """
    Delete by hash
    """
    return index_delete_immutable_handler(DVCONF, key, txid, sig_key_txid, **kw)

    
def delete_mutable_handler( data_id, signature, **kw ):
    """
    Delete by dynamic hash
    """
    return index_delete_mutable_handler(DVCONF, data_id, signature, **kw)

   
if __name__ == "__main__":
    """
    Unit tests.
    """
    import keylib
    import json 
    import virtualchain
    from virtualchain.lib.hashing import hex_hash160

    from blockstack_client.storage import parse_mutable_data, \
        serialize_mutable_data
    from blockstack_client.config import get_config
    from blockstack_client.constants import CONFIG_PATH

    # hack around absolute paths
    current_dir =  os.path.abspath(os.path.dirname(__file__))
    sys.path.insert(0, current_dir)

    current_dir =  os.path.abspath(os.path.join( os.path.dirname(__file__), "..") )
    sys.path.insert(0, current_dir)

    conf = get_config(CONFIG_PATH)
    #print json.dumps(conf, indent=4, sort_keys=True)

    pk = keylib.ECPrivateKey()
    data_privkey = pk.to_hex()
    data_pubkey = pk.public_key().to_hex()

    test_data = [
      ["my_first_datum",   "hello world",                             1, "unused", None],
      ["/my/second/datum", "hello world 2",                           2, "unused", None],
      ["user\"_profile",   '{"name":{"formatted":"judecn"},"v":"2"}', 3, "unused", None],
      ["empty_string",     "",                                        4, "unused", None],
    ]

    def hash_data( d ):
        return hex_hash160( d )

    rc = storage_init(conf, fqu = 'test.id')
    if not rc:
        raise Exception("Failed to initialize")

    index_manifest_url = index_setup(DVCONF)
    assert index_manifest_url

    if len(sys.argv) > 1:
        # try to get these profiles 
        for name in sys.argv[1:]:
            prof = get_mutable_handler( 
                        url = make_mutable_url( name ), 
                        index_manifest_url=index_manifest_url, 
                        blockchain_id='test.id' 
                        )
            if prof is None:
                raise Exception("Failed to get {}".format(name))

            print json.dumps(prof, indent=4, sort_keys=True)

        sys.exit(0)

    # put_immutable_handler
    print "put_immutable_handler"
    for i in xrange(0, len(test_data)):
      
        d_id, d, n, s, url = test_data[i]

        rc = put_immutable_handler( hash_data( d ), d, "unused" )
        if not rc:
            raise Exception("put_immutable_handler('{}') failed".format(d))
           
    # put_mutable_handler
    print "put_mutable_handler"
    for i in xrange(0, len(test_data)):

        d_id, d, n, s, url = test_data[i]

        data_url = make_mutable_url( d_id, fqu = 'test.id' )

        data_json = serialize_mutable_data( 
                        json.dumps({
                            "id": d_id, 
                            "nonce": n, 
                            "data": d
                            }), data_privkey )

        rc = put_mutable_handler( d_id, data_json, fqu = 'test.id' )
        if not rc:
            raise Exception("put_mutable_handler('{}', '{}') failed".format(d_id, d))

        test_data[i][4] = data_url

    # get_immutable_handler
    print "get_immutable_handler"
    for i in xrange(0, len(test_data)):
      
        d_id, d, n, s, url = test_data[i]

        rd = get_immutable_handler( hash_data( d ) )
        if rd != d:
            raise Exception("get_immutable_handler('{}'): '{}' != '{}'".format(hash_data(d), d, rd))
        
    # get_mutable_handler
    print "get_mutable_handler"
    for i in xrange(0, len(test_data)):

        d_id, d, n, s, url = test_data[i]

        rd_json = get_mutable_handler( url )

        rd = parse_mutable_data( rd_json, data_pubkey )
        if rd is None:
            raise Exception("Failed to parse mutable data '{}'".format(rd_json_))

        rd = json.loads(rd)

        if rd['id'] != d_id:
            raise Exception("Data ID mismatch: '{}' != '{}'".format(rd['id'], d_id))

        if rd['nonce'] != n:
            raise Exception("Nonce mismatch: '{}' != '{}'".format(rd['nonce'], n))

        if rd['data'] != d:
            raise Exception("Data mismatch: '{}' != '{}'".format(rd['data'], d))

    # delete_immutable_handler
    print "delete_immutable_handler"
    for i in xrange(0, len(test_data)):
      
        d_id, d, n, s, url = test_data[i]

        rc = delete_immutable_handler( hash_data(d), "unused", "unused" )

        if not rc:
            raise Exception("delete_immutable_handler('{}' ({})) failed".format(hash_data(d), d))
      
    # delete_mutable_handler
    print "delete_mutable_handler"
    for i in xrange(0, len(test_data)):
      
        d_id, d, n, s, url = test_data[i]

        rc = delete_mutable_handler( d_id, "unused" )
        if not rc:
            raise Exception("delete_mutable_handler('{}') failed".format(d_id))

