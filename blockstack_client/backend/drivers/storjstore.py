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
import json
import traceback
import logging
from common import *
from ConfigParser import SafeConfigParser

from storj.uploader import Uploader
from storj.downloader import Downloader
from storj import http
from common import get_driver_settings_dir
from common import rip160sha256

log = get_logger("blockstack-storage-driver-storj")

log.setLevel( logging.DEBUG if DEBUG else logging.INFO )

STORJ_USER = None
STORJ_PASSWD = None
STORJ_BUCKET = None
STORJ_CONN = None
TMP_DIR = None

class StorjAPI:
    def __init__(self, user, passwd, bucket_id, tmp_dir):
        self.user = user
        self.passwd = passwd
        self.bucket_id = bucket_id
        self.tmp_dir = tmp_dir

        self.init()

    def write(self, name, data):
        file_id = storj_get_file_id(self.user, self.passwd, self.bucket_id, name)
        try:
            meta = self.deleter.file_metadata(self.bucket_id,file_id)
            if meta.filename == name:
                self.deleter.file_remove(self.bucket_id, file_id)
        except:
            pass

        log.debug("Storing file %s at id %s", name, file_id)
        file_path, file_dir = dump2file(name, data, self.tmp_dir)
        self.uploader.file_upload(self.bucket_id, file_path, self.tmp_dir)
        os.unlink(file_path)
        return file_id

    def read(self, name):
        data = None
        file_id = storj_get_file_id(self.user, self.passwd, self.bucket_id, name)
        log.debug("Downloading file %s with id %s", name, file_id)
        self.downloader.download_begin(self.bucket_id, file_id)
        path = os.path.join(self.downloader.destination_file_path, name)
        with open(path) as f:
            data = f.read()
        os.unlink(path)
        return data

    def remove(self, name):
        file_id = storj_get_file_id(self.user, self.passwd, self.bucket_id, name)
        log.debug("Deleting file %s at id %s", name, file_id)
        self.deleter.file_remove(self.bucket_id, file_id)

    def init(self):
        self.uploader = Uploader(self.user, self.passwd)
        self.downloader = Downloader(self.user, self.passwd)
        self.deleter = http.Client(self.user, self.passwd)

    def reset(self):
        try:
            self.init()
        except Exception, e:
            log.exception(e)


def dump2file(name, data, tmp_dir):
    tmp_file = os.path.join(tmp_dir, name)
    with open(tmp_file, 'w') as f:
        f.write(data)
    return tmp_file, tmp_dir


def storj_encode_name(name):
    return name.replace( "/", r"-2f" )


def storj_get_bucket_id(user, passwd, name):
    """
    Ref: https://storj.github.io/core/lib_utils.js.html
    """
    return rip160sha256(user+name)[:24]

def storj_get_file_id(user, passwd, bucket_id, name):
    """
    Ref: https://storj.github.io/core/lib_utils.js.html
    """
    return rip160sha256(bucket_id+name)[:24]

def storage_init(conf, index=False, force_index=False):
    """
    Initialize storage driver for storj
    """
    global TMP_DIR, STORJ_USER, STORJ_PASSWD, STORJ_BUCKET, STORJ_CONN
    config_path = conf['path']

    if os.path.exists( config_path ):

        parser = SafeConfigParser()

        try:
            parser.read(config_path)
        except Exception, e:
            log.exception(e)
            return False

        bucket_name = None
        if parser.has_section('storj'):
            if parser.has_option('storj', 'user') and parser.has_option('storj', 'passwd'):
                STORJ_USER = parser.get('storj', 'user')
                STORJ_PASSWD = parser.get('storj', 'passwd')

            if parser.has_option("storj", "bucket"):
                bucket_name = parser.get("storj", "bucket")

    # Auth
    if STORJ_USER is None or STORJ_PASSWD is None:
        log.error("Config file: 'storj.user' or 'storj.passwd' is missing")
        return False

    if bucket_name is None:
        log.error("Config file: 'storj.bucket' is missing")
        return False


    STORJ_BUCKET = storj_get_bucket_id(STORJ_USER, STORJ_PASSWD, bucket_name)
    log.debug("Bucket id is %s", STORJ_BUCKET)
    if STORJ_BUCKET is None:
        log.error("Invalid storj bucket %s", bucket_name)

    config_path = conf['path']
    TMP_DIR = get_driver_settings_dir(config_path, ".tmp")
    if not os.path.exists(TMP_DIR):
        try:
            os.makedirs(TMP_DIR)
            os.chmod(TMP_DIR, 0700)
        except Exception as e:
            if DEBUG:
                log.exception(e)

    try:
        STORJ_CONN = StorjAPI(STORJ_USER, STORJ_PASSWD, STORJ_BUCKET, TMP_DIR)
    except Exception as e:
        if DEBUG:
            log.exception(e)
        return False

    return True


def storj_put_chunk(chunk_buf, name):
    """
    Store a chunk to storj
    Return URL on success
    Return None on error
    """


    try:
        name = storj_encode_name(name)
        file_id = STORJ_CONN.write(name, chunk_buf)
        return "storj:///blockstack/{}".format(file_id)
    except Exception as e:
        STORJ_CONN.reset()
        if DEBUG:
            log.exception(e)

        log.error("Failed to save {} bytes to {} in Storj".format(len(chunk_buf), name))
        return None


def storj_delete_chunk(name):
    """
    Delete a chunk from storj
    Return True on success
    Return False on error
    """

    try:
        STORJ_CONN.remove(name)
        return True
    except Exception, e:
        STORJ_CONN.reset()
        log.exception(e)
        return False


def storj_get_chunk(name):
    """
    Get a chunk via storj
    Return the data on success
    Return None on error
    """

    try:
        return STORJ_CONN.read(name)
    except Exception, e:
        STORJ_CONN.reset()
        log.error("Failed to load {}".format(name))
        return None


def handles_url( url ):
    """
    Does this storage driver handle this kind of URL?
    """
    return url.startswith("storj:///")


def make_mutable_url( data_id ):
    """
    Make a mutable data URL
    """

    data_id = '/mutable/{}'.format(data_id)
    data_id = storj_encode_name(data_id)
    return "storj:///blockstack/{}".format(data_id)


def get_immutable_handler( key, **kw ):
    """
    Given the hash of the data, return the data.
    Return None if not found.
    """

    path = '/immutable/{}'.format(key)
    path = storj_encode_name(path)

    return storj_get_chunk(path)


def get_mutable_handler( url, **kw ):
    """
    Given a route URL to data, return the data itself.
    Return the data if found.
    Return None if not.
    """

    urltype, urlres = get_url_type(url)
    if urltype is None and urlres is None:
        log.error("Invalid URL {}".format(url))
        return None

    return storj_get_chunk(urlres)


def put_immutable_handler( key, data, txid, **kw ):
    """
    Put data by hash and txid
    Return True on success; False on failure.
    """

    path = '/immutable/{}'.format(key)
    path = storj_encode_name(path)

    return storj_put_chunk(data, path)


def put_mutable_handler( data_id, data_bin, **kw ):
    """
    Put data by data_id
    Return True on success; False on failure.
    """

    path = '/mutable/{}'.format(data_id)
    path = storj_encode_name(path)

    return storj_put_chunk(data_bin, path)


def delete_immutable_handler( key, txid, sig_key_txid, **kw ):
    """
    Delete by hash
    Return True on success; False if not.
    """

    path = '/immutable/{}'.format(key)
    path = storj_encode_name(path)

    return storj_delete_chunk(path)


def delete_mutable_handler( data_id, signature, **kw ):
    """
    Delete by hash
    Return True on success; False if not.
    """

    path = '/mutable/{}'.format(data_id)
    path = storj_encode_name(path)

    return storj_delete_chunk(path)


if __name__ == "__main__":

   import keylib
   import json
   import virtualchain
   from virtualchain.lib.hashing import hex_hash160

   # hack around absolute paths
   current_dir =  os.path.abspath(os.path.dirname(__file__))
   sys.path.insert(0, current_dir)

   current_dir =  os.path.abspath(os.path.join( os.path.dirname(__file__), "..") )
   sys.path.insert(0, current_dir)

   from blockstack_client.storage import parse_mutable_data, serialize_mutable_data
   from blockstack_client.config import log, get_config

   CONFIG_PATH = os.environ.get('BLOCKSTACK_CONFIG_PATH', None)
   assert CONFIG_PATH, "Missing BLOCKSTACK_CONFIG_PATH from environment"

   conf = get_config(CONFIG_PATH)
   print json.dumps(conf, indent=4, sort_keys=True)

   pk = keylib.ECPrivateKey()
   data_privkey = pk.to_hex()
   data_pubkey = pk.public_key().to_hex()

   test_data = [
      ["my_first_datum",        "hello world",                              1, "unused", None],
      ["/my/second/datum",      "hello world 2",                            2, "unused", None],
      ["user\"_profile",          '{"name":{"formatted":"judecn"},"v":"2"}',  3, "unused", None],
      ["empty_string",          "",                                         4, "unused", None],
   ]

   def hash_data( d ):
      return hex_hash160( d )

   rc = storage_init(conf)
   if not rc:
      raise Exception("Failed to initialize")

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

      print "store {} ({})".format(d_id, hash_data(d))

      rc = put_immutable_handler( hash_data( d ), d, "unused" )
      if not rc:
         raise Exception("put_immutable_handler('%s') failed" % d)


   # put_mutable_handler
   print "put_mutable_handler"
   for i in xrange(0, len(test_data)):

      d_id, d, n, s, url = test_data[i]

      data_url = make_mutable_url( d_id )

      print 'store {} with {}'.format(d_id, data_privkey)
      data_json = serialize_mutable_data( json.dumps({"id": d_id, "nonce": n, "data": d}), data_privkey)

      rc = put_mutable_handler( d_id, data_json )
      if not rc:
         raise Exception("put_mutable_handler('%s', '%s') failed" % (d_id, d))

      test_data[i][4] = data_url


   # get_immutable_handler
   print "get_immutable_handler"
   for i in xrange(0, len(test_data)):

      d_id, d, n, s, url = test_data[i]

      print "get {}".format(hash_data(d))
      rd = get_immutable_handler( hash_data( d ) )
      if rd != d:
         raise Exception("get_mutable_handler('%s'): '%s' != '%s'" % (hash_data(d), d, rd))

   # get_mutable_handler
   print "get_mutable_handler"
   for i in xrange(0, len(test_data)):

      d_id, d, n, s, url = test_data[i]

      print "get {}".format(d_id)
      rd_json = get_mutable_handler( url )
      if rd_json is None:
          raise Exception("Failed to get data {}".format(d_id))

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

      print "delete {}".format(hash_data(d))
      rc = delete_immutable_handler( hash_data(d), "unused", "unused" )
      if not rc:
         raise Exception("delete_immutable_handler('%s' (%s)) failed" % (hash_data(d), d))

   # delete_mutable_handler
   print "delete_mutable_handler"
   for i in xrange(0, len(test_data)):

      d_id, d, n, s, url = test_data[i]

      print "delete {}".format(d_id)
      rc = delete_mutable_handler( d_id, "unused" )
      if not rc:
         raise Exception("delete_mutable_handler('%s') failed" % d_id)
