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
import ipfsapi
from common import get_logger, driver_config, DEBUG, \
    index_setup, compress_chunk, decompress_chunk, \
    index_get_manifest_page_path, index_insert, put_indexed_data, \
    get_indexed_data, index_put_mutable_handler, \
    index_get_immutable_handler, index_get_mutable_handler
from ConfigParser import SafeConfigParser

log = get_logger("blockstack-storage-driver-ipfs")
log.setLevel( logging.DEBUG if DEBUG else logging.INFO )

IPFS_DEFAULT_SERVER = 'localhost'
IPFS_DEFAULT_PORT = '5001'
IPFS_DEFAULT_COMPRESS = False

INDEX_DIRNAME = 'index'
DVCONF        = None

ipfs_api = None


def ipfs_key_gen(key):
    """ 
    We need a custom wraper for this API endpoint, because the ipfsapi 
    does not provide it, yet. Instead of checking whether a key exists 
    before creating it, we create it, and ignore the error that throws 
    if it exists already.
    """

    try:
      r = ipfs_api._client.request('/key/gen', (key,), decoder='json', 
                                   opts={'type':'rsa','size':'2048'})
    except ipfsapi.exceptions.ErrorResponse:
      # An exception is thrown when the key already exists, we ignore it
      pass


def ipfs_put_chunk( dvconf, chunk_buf, chunk_path ):
    """
    Write a chunk of data to IPFS.
    
    Return True on success 
    Return False on error, and log an exception
    """

    chunk_buf = str(chunk_buf)
    base_path = '/blockstack/{}{}'.format(
                      dvconf['driver_info']['blockstack_id'],
                      os.path.dirname(chunk_path),
                      )
    chunk_path = os.path.join(base_path, os.path.basename(chunk_path))

    try:
        ipfs_api.files_mkdir(base_path, parents = True)
    except Exception, e:
        log.error('Failed to create {}'.format(base_path))
        log.exception(e)
        rc = False
    else:
        try:
            r = ipfs_api.files_write( chunk_path, 
                                      io.BytesIO(str(chunk_buf)), 
                                      create = True )
            h = ipfs_api.files_stat (chunk_path)['Hash']
            rc = 'ipfs://{}'.format(h)
            #rc = 'ipfs:/{}'.format(chunk_path)
        except Exception, e:
            log.error("Failed to write mutable '%s'" % chunk_path)
            log.exception(e)
            rc = False

    return rc

def ipfs_put_chunk_immutable( dvconf, chunk_buf, chunk_path):
    """
    Write a chunk of data to IPFS.
    
    Return True on success 
    Return False on error, and log an exception
    """

    chunk_buf = str(chunk_buf)

    try:
        if chunk_buf: 
            h = ipfs_api.add_str( chunk_buf )
            h = 'ipfs://{}'.format(h) 
        else:
            h = False       
    except Exception, e:
        log.error("Failed to write '%s'" % chunk_path)
        log.exception(e)
        h = False

    return h


def ipfs_put_indexed_data_immutable( dvconf, name, chunk_buf, raw=False, index=True, **kw ):
    """
    Put data into the storage system.
    Compress it (if configured to do so), save it, and then update the index.

    If @raw is True, then do not compress
    If @index is False, then do not update the index

    Return True on success
    Return False on error
    """
    if dvconf['compress'] and not raw:
        compressed_chunk = compress_chunk(chunk_buf)
    else:
        compressed_chunk = chunk_buf

    put_chunk = dvconf['put_chunk']
    log.debug("Store {} bytes to {}".format(len(chunk_buf), name))

    # store data
    new_url = ipfs_put_chunk_immutable(dvconf, compressed_chunk, name)
    if new_url is None:
        log.error("Failed to save {}".format(name))
        return False

    # update index
    if index:
        log.debug("Insert ({}, {}) into index".format(name, new_url))
        rc = index_insert( dvconf, name, new_url )
        if not rc:
            log.error("Failed to insert ({}, {}) into index".format(name, new_url))
            return False

    return True

def ipfs_get_chunk(dvconf, chunk_path):
    """
    Get a chunk of data from IPFS.
    
    Return the data on success
    Return None on error, and log an exception.
    """
    
    data = None
    compressed_data = None

    try:
      compressed_data = ipfs_api.files_read( chunk_path )
    except Exception, e:
      log.error("Failed to read file '%s'" % chunk_path)
      log.exception(e)

    try:
      data = decompress_chunk( compressed_data )
    except:
      data = compressed_data
        
    return data

def ipfs_get_chunk_immutable(dvconf, chunk_path):
    """
    Get a chunk of data from IPFS.
    
    Return the data on success
    Return None on error, and log an exception.
    """
    
    data = None
    compressed_data = None

    try:
      compressed_data = ipfs_api.cat( chunk_path )
    except Exception, e:
      log.error("Failed to read '%s'" % chunk_path)
      log.exception(e)

    try:
      data = decompress_chunk( compressed_data )
    except:
      data = compressed_data
        
    return data


def ipfs_delete_chunk( chunk_path, is_mutable ):
    """
      Delete a chunk of data from IPFS.
    """

    if is_mutable:
      try:
        ipfs_api.files_rm( chunk_path )
      except Exception, e:
        log.error("Failed to delete file '%s'" % data_id )
        log.exception(e)
        return False
    else:
      try:
          ipfs_api.pin_rm( chunk_path )
      except Exception, e:
          log.error("Failed to delete '%s'" % data_hash )
          log.exception(e)
          return False 
    return True


def ipfs_index_get_immutable_handler( dvconf, key, **kw ):
    """
    Default method to get data by hash using the index.
    Meant for HTTP-based cloud providers.

    Return the data on success
    Return None on error
    """
    #blockchain_id = kw.get('fqu', None)
    index_manifest_url = kw.get('index_manifest_url', None)

    name = 'immutable-{}'.format(key)
    name = name.replace('/', r'-2f')
   
    path = '/{}'.format(name)

    return get_indexed_data(dvconf, None, path, index_manifest_url=index_manifest_url)


def storage_init(conf, index=False, force_index=False, **kwargs):
    """
    Initialize IPFS storage driver
    """
    global DVCONF, ipfs_api

    ipfs_server = IPFS_DEFAULT_SERVER
    ipfs_port = IPFS_DEFAULT_PORT
    ipfs_compress = IPFS_DEFAULT_COMPRESS
    blockstack_id = None

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

    blockstack_id = kwargs.get('fqu', None)

    if blockstack_id is None:
        log.error("Blockstack.id is missing to initalize IPFS storage driver")
        return False

    DVCONF = driver_config(
                driver_name = 'ipfs',
                config_path = config_path, 
                get_chunk = ipfs_get_chunk,
                put_chunk = ipfs_put_chunk,
                delete_chunk = ipfs_delete_chunk,
                driver_info={
                    'blockstack_id': blockstack_id,
                    },
                #index_stem='/blockstack/{}/{}'.format(blockstack_id, INDEX_DIRNAME),
                index_stem=INDEX_DIRNAME,
                compress=ipfs_compress,
                )

    ipfs_api = ipfsapi.connect( ipfs_server, ipfs_port )

    d = '/blockstack/'+blockstack_id

    try:
        ipfs_api.files_mkdir( d, parents = True)
    except Exception, e:
        log.error("Failed to create directory '%s' within the MFS" % d)
        log.exception(e)

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
    if url.startswith("/ipfs/") or url.startswith("/ipns/") or url.startswith("ipfs://"):
        return True
    else:
        # if it starts with a valid CID: https://github.com/ipld/cid
        #   return True
        # else
        return False


def make_mutable_url( data_id, **kw ):
    """
    Get data by URL
    """
    blockstack_id = kw.get('fqu', None)
    if blockstack_id is None:
        return 'ipfs://blockstack/' + data_id.replace( "/", r"\x2f" )
    else:
        return ('ipfs://blockstack/' + blockstack_id + '/'
               + data_id.replace('/', r"\x2f"))


def get_immutable_handler( key, **kw ):
    """
    Get data by hash
    """
    #return ipfs_get_chunk_immutable(DVCONF, key)
    kw.pop('fqu')
    return index_get_immutable_handler(DVCONF, key, **kw)

    #return ipfs_index_get_immutable_handler(DVCONF, key, **kw)


def get_mutable_handler( url, **kw ):
    """
    Get data by dynamic hash
    """
    #url = url.replace('/', r'-2f')
    return index_get_mutable_handler(DVCONF, url, **kw)
    #return ipfs_get_chunk(DVCONF, url)


def put_immutable_handler( key, data, txid, **kw ):
    """
    Put data by hash
    """
    name = 'immutable-{}'.format(key)
    name = name.replace('/', r'-2f')

    path = '/{}'.format(name)

    return ipfs_put_indexed_data_immutable(DVCONF, path, data, txid, **kw)

#def put_immutable_handler( key, data, txid, **kw ):
    """
    Put data by hash and txid
    """
#    return index_put_immutable_handler(DVCONF, key, data, txid, **kw)


def put_mutable_handler( data_id, data_txt, **kw ):
    """
    Put data by dynamic hash
    """
    # blockchain_id = DVCONF['driver_info']['blockstack_id']
    # mutable_data_id = ('/blockstack/' + blockchain_id + '/' 
    #                   + data_id.replace('/', r"\x2f"))


    # data_id = data_id.replace('/', r'-2f')
    # path = '/blockstack/{}/{}'.format(
    #           DVCONF['driver_info']['blockstack_id'],
    #           data_id
    #           )

    #return put_indexed_data(DVCONF, path, data_txt)
    return index_put_mutable_handler(DVCONF, data_id, data_txt, **kw)
    #return put_indexed_data(DVCONF, mutable_data_id, data_txt)
    #return ipfs_put_chunk(DVCONF, data_txt, mutable_data_id)

   
def delete_immutable_handler( data_hash, txid, tombstone, **kw ):
    """
    Delete by hash
    """
    return ipfs_delete_chunk( data_hash, False )

    
def delete_mutable_handler( data_id, tombstone, **kw ):
    """
    Delete by dynamic hash
    """
    return ipfs_delete_chunk( data_id, True )


def hash_data( d ):

    h = None

    if DVCONF['compress']:
      try:            
        h = ipfs_api.add_str(compress_chunk(d), opts={'only-hash':True})
      except Exception, e:
        log.error("Failed to get hash for '%s'" % d )
        log.exception(e)
    else:
      try:
        h = ipfs_api.add_str(d, opts={'only-hash':True})
      except Exception, e:
        log.error("Failed to get hash for '%s'" % d )
        log.exception(e)
          
    return h

   
if __name__ == "__main__":
    """
    Unit tests.
    """
    import keylib
    import json 
    import virtualchain
    #from virtualchain.lib.hashing import hex_hash160

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

    rc = storage_init(conf, fqu = 'test.id')
    if not rc:
      raise Exception("Failed to initialize")

    index_manifest_url = index_setup(DVCONF)
    assert index_manifest_url

    if len(sys.argv) > 1:
       # try to get these profiles 
       for name in sys.argv[1:]:
           prof = get_mutable_handler( make_mutable_url( name ) )
           if prof is None:
               raise Exception("Failed to get %s" % name)

           print json.dumps(prof, indent=4, sort_keys=True)

       sys.exit(0)

    # put_immutable_handler
    print "put_immutable_handler"
    for i in xrange(0, len(test_data)):
      
      d_id, d, n, s, url = test_data[i]
      
      rc = put_immutable_handler( hash_data( d ), d, "unused" )
      if not rc:
         raise Exception("put_immutable_handler('%s') failed" % d)
           
    # put_mutable_handler
    print "put_mutable_handler"
    for i in xrange(0, len(test_data)):

      d_id, d, n, s, url = test_data[i]
      
      data_url = make_mutable_url( d_id, fqu = 'test.id' )
       
      data_json = serialize_mutable_data( json.dumps({"id": d_id, "nonce": n, "data": d}), data_privkey )
      
      rc = put_mutable_handler( d_id, data_json, fqu = 'test.id' )
      if not rc:
         raise Exception("put_mutable_handler('%s', '%s') failed" % (d_id, d))
     
      test_data[i][4] = data_url

    # get_immutable_handler
    print "get_immutable_handler"
    for i in xrange(0, len(test_data)):
      
      d_id, d, n, s, url = test_data[i]

      rd = get_immutable_handler( hash_data( d ) )
      if rd != d:
         raise Exception("get_immutable_handler('%s'): '%s' != '%s'" % (hash_data(d), d, rd))
      
    # get_mutable_handler
    print "get_mutable_handler"
    for i in xrange(0, len(test_data)):

      d_id, d, n, s, url = test_data[i]

      rd_json = get_mutable_handler( url )

      rd = parse_mutable_data( rd_json, data_pubkey )
      if rd is None:
         raise Exception("Failed to parse mutable data '%s'" % rd_json)
      
      rd = json.loads(rd)
      
      if rd['id'] != d_id:
         raise Exception("Data ID mismatch: '%s' != '%s'" % (rd['id'], d_id))
      
      if rd['nonce'] != n:
         raise Exception("Nonce mismatch: '%s' != '%s'" % (rd['nonce'], n))
      
      if rd['data'] != d:
         raise Exception("Data mismatch: '%s' != '%s'" % (rd['data'], d))

    # delete_immutable_handler
    print "delete_immutable_handler"
    for i in xrange(0, len(test_data)):
      
      d_id, d, n, s, url = test_data[i]
      
      rc = delete_immutable_handler( hash_data(d), "unused", "unused" )
      if not rc:
         raise Exception("delete_immutable_handler('%s' (%s)) failed" % (hash_data(d), d))
      
    # delete_mutable_handler
    print "delete_mutable_handler"
    for i in xrange(0, len(test_data)):
      
      d_id, d, n, s, url = test_data[i]
      
      rc = delete_mutable_handler( url, "unused" )
      if not rc:
         raise Exception("delete_mutable_handler('%s') failed" % d_id)

