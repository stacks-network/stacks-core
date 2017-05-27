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

import logging
import os
import zlib
import hashlib
import requests
import blockstack_zones
import json
import jsonschema
import urlparse
import posixpath
import urllib
from Crypto.Hash import RIPEMD
import hashlib

if os.environ.get("BLOCKSTACK_DEBUG", None) is not None:
    DEBUG = True
else:
    DEBUG = False

INDEX_VERSION_STRING = '1'

INDEX_PAGE_SCHEMA = {
    'type': 'object',
    'properties': {
        'version': {
            'type': 'string',
            'pattern': '^{}$'.format(INDEX_VERSION_STRING),
        },
        'data': {
            'type': 'object',            
            'patternProperties': {
                r'^([a-zA-Z0-9\-_.~%/]+)$': {
                    'type': 'string',
                    'pattern': r'^([a-z0-9+]+://[a-zA-Z0-9\-_.~%/?&=]+)$'
                },
            },
        },
    },
}

# map blockchain_id --> {index_page_url: index_data}
INDEX_CACHE = {}
INDEX_MANIFEST_URL_CACHE = {}

def get_logger(name=None):
    """
    Get logger
    """

    level = logging.CRITICAL
    if DEBUG:
        logging.disable(logging.NOTSET)
        level = logging.DEBUG

    if name is None:
        name = "<unknown>"
        level = logging.CRITICAL

    log = logging.getLogger(name=name)
    log.setLevel( level )
    console = logging.StreamHandler()
    console.setLevel( level )
    log_format = ('[%(asctime)s] [%(levelname)s] [%(module)s:%(lineno)d] (' + str(os.getpid()) + ') %(message)s' if DEBUG else '%(message)s')
    formatter = logging.Formatter( log_format )
    console.setFormatter(formatter)
    log.propagate = False

    if len(log.handlers) > 0:
        for i in xrange(0, len(log.handlers)):
            log.handlers.pop(0)
    
    log.addHandler(console)
    return log

log = get_logger('blockstack-backend-drivers-common')

def compress_chunk( chunk_buf ):
    """
    compress a chunk of data
    """
    data = zlib.compress(chunk_buf, 9)
    return data


def decompress_chunk( chunk_buf ):
    """
    decompress a chunk of data
    """
    data = zlib.decompress(chunk_buf)
    return data


def get_driver_settings_dir(config_path, driver_name):
    """
    driver-specific state
    """
    return os.path.join( os.path.dirname(config_path), "drivers/{}".format(driver_name))


def setup_scratch_space(scratch_dir):
    """
    Set up download scratch space
    Return True on success
    Return False on error
    """
    if not os.path.exists(scratch_dir):
        try:
            os.makedirs(scratch_dir)
            os.chmod(scratch_dir, 0700)
        except Exception as e:
            if DEBUG:
                log.exception(e)

            log.error("Failed to create scratch directory")
            return False

    else:
        # make sure we have the right mode 
        sb = os.stat(scratch_dir)
        if sb.st_mode != 0700:
            os.chmod(scratch_dir, 0700)

        # clear it out
        for name in os.listdir(scratch_dir):
            fp = os.path.join(scratch_dir, name)
            try:
                os.unlink(fp)
            except:
                pass

    return True


def make_scratch_file(dirp):
    """
    Make a scratch file at a given path.
    Return the path
    """
    scratch_fd, scratch_path = tempfile.mkstemp(dir=dirp)
    os.close(scratch_fd)
    return scratch_path


def normpath(path):
    """
    Normalize a path
    """
    path = posixpath.normpath(path)
    path = '/' + '/'.join( filter(lambda p: len(p) > 0, path.split('/')))
    return path


def index_get_page_path(name, index_dir):
    """
    Get the path to an index page
    """
    h = hashlib.sha256(name).hexdigest()
    bucket_1 = h[0:1]

    path = normpath('/{}/{}'.format(index_dir, bucket_1))
    log.debug("Index page for {} is {}".format(name, path))
    return path


def index_get_manifest_page_path(index_stem='index'):
    """
    Get the path to the index manifest
    """
    index_path = None
    if index_stem is not None:
        index_path = normpath('/' + os.path.join(index_stem.strip('/'), 'index.manifest'))
    else:
        index_path = '/index.manifest'

    return index_path


def parse_index_page(index_page_data):
    """
    Parse a serialized index page into a dict
    Return the dict on success
    Return None on error
    """
    try:
        page_data = json.loads(str(index_page_data))
        jsonschema.validate(page_data, INDEX_PAGE_SCHEMA)
        return page_data['data']

    except Exception as e:
        if DEBUG:
            log.exception(e)

        log.error("Failed to parse index page ({} bytes)".format(len(index_page_data)))
        return None


def serialize_index_page(index_page_data):
    """
    Serialize an index page
    Return the serialized byte buffer
    """
    index_page = {
        'version': INDEX_VERSION_STRING,
        'data': index_page_data
    }

    return str(json.dumps(index_page, sort_keys=True))


def get_index_bucket_names():
    """
    Get the list of index bucket names
    """
    return ['{:1x}'.format(i) for i in xrange(0, 16)]


def driver_config(driver_name, config_path, get_chunk, put_chunk, delete_chunk, driver_info=None, index_stem='index', compress=False):
    """
    Set up the driver.
    @get_chunk is a callable that takes (dvconf, path) as an argument and returns data
    @put_chunk is a callable that takes (dvconf, data, path) as arguments and returns a URL
    @delete_chunk is a callable that takes (dvconf, path) as an argument and returns True/False

    Neither callable should call any of the indexing methods.

    Return an object that will be passed to other index routines.
    """
    return {
        'driver_name': driver_name,
        'config_path': config_path,
        'get_chunk': get_chunk,
        'put_chunk': put_chunk,
        'delete_chunk': delete_chunk,
        'index_stem': index_stem,
        'driver_info': driver_info,
        'compress': compress
    }


def driver_config_set_info(dvconf, driver_info):
    """
    Set driver-specific information
    """
    dvconf['driver_info'] = driver_invo


def get_url_type(url):
    """
    How do we handle this URL?
    Return ('http', url) if we use http to get this data
    Return ('blockstack', data_id) if we use the index to get this data
    Return None, None on invalid URL
    """

    # is this a direct URL to a resource,
    # or is this a URL generated with get_mutable_url()?
    urlparts = urlparse.urlparse(url)
    urlpath = posixpath.normpath( urllib.unquote(urlparts.path) )
    urlpath_parts = urlpath.strip('/').split('/')

    if len(urlpath_parts) != 2:
        log.error("Invalid URL {}".format(url))
        return None

    if urlpath_parts[0] == 'blockstack':
        return ('blockstack', urlpath_parts[1])

    else:
        return ('http', url)


def index_make_bucket(dvconf, bucket):
    """
    Make an index bucket.
    @dvconf is the structure returned by driver_config

    Return the URL
    """
    try:
        log.debug("Make index bucket {}".format(bucket))

        index_page = {}
        index_page_data = serialize_index_page(index_page)

        url = dvconf['put_chunk'](dvconf, index_page_data, bucket)
        assert url
        return url
    except Exception as e:
        if DEBUG:
            log.exception(e)

        log.error("Failed to make bucket {}".format(bucket))
        return None


def index_settings_get_index_manifest_url(driver_name, config_path):
    """
    Get the locally-written index manifest URL
    Return the URL if present
    Return None if not present.
    """
    settings_dir = get_driver_settings_dir(config_path, driver_name)
    if not os.path.exists(settings_dir):
        return None

    # find URL to the index manifest
    index_manifest_url_path = os.path.join(settings_dir, 'index_manifest_url')
    if os.path.exists(index_manifest_url_path):
        url = None
        with open(index_manifest_url_path, 'r') as f:
            url = f.read().strip()

        return url

    else:
        return None


def index_settings_set_index_manifest_url(driver_name, config_path, url):
    """
    Set the index manifest URL in our settings,
    so we can load it again in the future.

    Return True if stored.
    Return False if not stores.

    Has the side-effect of creating the settings directory for this driver,
    if it does not exist.
    """
    settings_dir = get_driver_settings_dir(config_path, driver_name)
    if not os.path.exists(settings_dir):
        os.makedirs(settings_dir)
        os.chmod(settings_dir, 0700)
    
    index_manifest_url_path = os.path.join(settings_dir, 'index_manifest_url')

    try:
        # flag it on disk
        log.debug("Save index manifest URL {} to {}".format(url, index_manifest_url_path))
        with open(index_manifest_url_path, 'w') as f:
            f.write(url)
        
        return True
    except:
        return False


def index_setup(dvconf, force=False):
    """
    Set up our index if we haven't already.
    Return the index manifest URL on success
    Return the index manifest URL if already setup
    Return False on error
    """
    
    # TODO: need to force this to happen for both foo.test and bar.test

    config_path = dvconf['config_path']
    put_chunk = dvconf['put_chunk']
    driver_name = dvconf['driver_name']
    index_stem = dvconf['index_stem']

    index_manifest_url = index_settings_get_index_manifest_url(driver_name, config_path)
    if index_manifest_url is not None and not force:
        # already set up
        return index_manifest_url

    index_bucket_names = get_index_bucket_names()

    if index_stem is not None:
        fq_index_bucket_names = [normpath('/' + os.path.join(index_stem.strip('/'), p)) for p in index_bucket_names]
    else:
        fq_index_bucket_names = index_bucket_names

    index_manifest = {}
    for b in fq_index_bucket_names:
        bucket_url = index_make_bucket(dvconf, b)
        if bucket_url is None:
            log.error("Failed to create bucket {}".format(b))
            return False

        index_manifest[b] = bucket_url

    # save index manifest 
    index_manifest_data = serialize_index_page(index_manifest)
    index_manifest_url = None
    try:
        index_path = index_get_manifest_page_path(index_stem)
        index_manifest_url = put_chunk(dvconf, index_manifest_data, index_path)
        assert index_manifest_url
    except Exception as e:
        if DEBUG:
            log.exception(e)

        log.error("Failed to create index manifest")
        return False

    rc = index_settings_set_index_manifest_url(driver_name, config_path, index_manifest_url)
    if not rc:
        # failed 
        return False

    return index_manifest_url


def index_get_cached_page(blockchain_id, url):
    """
    Get cached index page data
    Return the cached page on success
    Return None on error
    """
    global INDEX_CACHE
    if not INDEX_CACHE.has_key(blockchain_id):
        return None

    if not INDEX_CACHE[blockchain_id].has_key(url):
        return None

    return INDEX_CACHE[blockchain_id][url]


def index_get_cached_manifest_url(blockchain_id, driver_name):
    """
    Get the cached index manifest URL
    Return None if not cached
    """
    global INDEX_MANIFEST_URL_CACHE
    key = '{}-{}'.format(blockchain_id, driver_name)

    if not INDEX_MANIFEST_URL_CACHE.has_key(key):
        return None

    return INDEX_MANIFEST_URL_CACHE[key]


def index_set_cached_page(blockchain_id, url, data):
    """
    Insert a page's data into the index page cache
    """
    global INDEX_CACHE
    if not INDEX_CACHE.has_key(blockchain_id):
        INDEX_CACHE[blockchain_id] = {}

    log.debug("Cache {} bytes for ({}, {})".format(len(data), blockchain_id, url))
    INDEX_CACHE[blockchain_id][url] = data
    return True


def index_set_cached_manifest_url(blockchain_id, driver_name, url):
    """
    Cache the index manifest URL
    """
    global INDEX_MANIFEST_URL_CACHE
    key = '{}-{}'.format(blockchain_id, driver_name)

    log.debug("Cache {}-byte manifest URL for driver {} from {}".format(len(url), driver_name, blockchain_id))
    INDEX_MANIFEST_URL_CACHE[key] = url


def index_remove_cached_page(blockchain_id, url):
    """
    Remove a cached page
    """
    global INDEX_CACHE
    if not INDEX_CACHE.has_key(blockchain_id):
        return True

    if not INDEX_CACHE[blockchain_id].has_key(url):
        return True

    del INDEX_CACHE[blockchain_id][url]
    return True


def index_remove_cached_manifest_url(blockchain_id, driver_name):
    """
    Remove cached manifest URL
    """
    global INDEX_MANIFEST_URL_CACHE
    key = '{}-{}'.format(blockchain_id, driver_name)

    if key in INDEX_MANIFEST_URL_CACHE:
        del INDEX_MANIFEST_URL_CACHE[key]


def index_get_page(dvconf, blockchain_id=None, path=None, url=None):
    """
    Get an index page from the storage provider
    either @path or @url must be given.
    if @url is given, then @dvconf can be None (but blockchain_id is required)

    Return the dict on success
    Return None on error
    """
    assert url or path 
    if url and not path:
        assert blockchain_id

    serialized_index_page = None
    if url and blockchain_id:
        log.debug("Fetch index page {} via HTTP".format(url))
        serialized_index_page = get_chunk_via_http(url, blockchain_id=blockchain_id)
    else:
        assert path
        log.debug("Fetch index page {} via driver".format(path))
        assert dvconf
        get_chunk = dvconf['get_chunk']
        serialized_index_page = get_chunk(dvconf, path)

    if serialized_index_page is None:
        # failed to get index
        log.error("Failed to get index page {}".format(path))
        return None
    
    log.debug("Fetched {} bytes".format(len(serialized_index_page)))
    index_page = parse_index_page(serialized_index_page)
    if index_page is None:
        # invalid
        log.error("Invalid index page {}".format(path))
        return None

    return index_page


def index_set_page(dvconf, path, index_page):
    """
    Store an index page to the storage provider

    Return True on success
    Return False on error
    """
    assert index_setup(dvconf)
    
    put_chunk = dvconf['put_chunk']
    
    log.debug("Set index page {}".format(path))

    new_serialized_index_page = serialize_index_page(index_page)
    rc = put_chunk(dvconf, new_serialized_index_page, path)
    if not rc:
        # failed 
        log.error("Failed to store index page {}".format(path))
        return False

    return True  


def index_insert(dvconf, name, url):
    """
    Insert a url into the index.

    Return True on success
    Return False if not.
    """
    assert index_setup(dvconf)

    index_stem = dvconf['index_stem']

    path = index_get_page_path(name, index_stem)
    index_page = index_get_page( dvconf, path=path )
    if index_page is None:
        index_page = {}

    index_page[name] = url
    return index_set_page(dvconf, path, index_page)
    

def index_remove( dvconf, name ):
    """
    Remove a url from the index.
    Return True on success
    Return False if not.
    """
    assert index_setup(dvconf)

    index_stem = dvconf['index_stem']

    path = index_get_page_path(name, index_stem)
    index_page = index_get_page(dvconf, path=path)
    if index_page is None:
        log.error("Failed to get index page {}".format(path))
        return False

    if name not in index_page:
        # already gone
        return True

    del index_page[name]
    return index_set_page(dvconf, path, index_page)


def index_cached_lookup( index_manifest_url, blockchain_id, name, index_stem ):
    """
    Do a lookup in our cache for a url to a named datum
    Return the URL on success
    Return None if not cached
    """
    log.debug("Index cached lookup on {} from {} via {}".format(name, blockchain_id, index_manifest_url))

    # if this is cached, then use the cache 
    path = index_get_page_path(name, index_stem)
    manifest_page = index_get_cached_page(blockchain_id, index_manifest_url)
    if manifest_page is not None:
        # cached...
        log.debug("Cache HIT on {}".format(index_manifest_url))
        if path in manifest_page.keys():

            bucket_url = manifest_page[path]
            index_page = index_get_cached_page(blockchain_id, bucket_url)
            if index_page is not None:

                # also cached 
                log.debug("Cache HIT on {}".format(bucket_url))
                url = index_page.get(name, None)
                if url is not None:
                    return url

                else:
                    log.debug("Missing name on cached page ({}, {} ({}))".format(blockchain_id, path, bucket_url))

            else:
                log.debug("Cache MISS on ({}, {} ({}))".format(blockchain_id, path, bucket_url))

        else:
            log.debug("Missing {} on manifest ({}, {}))".format(path, blockchain_id, index_manifest_url))

    else:
        log.debug("Cache MISS on manifest ({}, {}))".format(blockchain_id, index_manifest_url))

    return None


def index_lookup( dvconf, index_manifest_url, blockchain_id, name, index_stem='index' ):
    """
    Given the name, find the URL
    Return the (URL, {url: page}) on success
    Return (None, {url: page}) on error
    """
   
    log.debug("Index lookup on {} from {} via {}".format(name, blockchain_id, index_manifest_url))

    index_manifest_path = index_get_manifest_page_path(index_stem)
    path = index_get_page_path(name, index_stem)

    fetched = {}

    log.debug("Get index manifest page ({}, {})".format(index_manifest_url, index_manifest_path))
    manifest_page = index_get_page(dvconf, blockchain_id=blockchain_id, url=index_manifest_url, path=index_manifest_path)
    if manifest_page is None:
        log.error("Failed to get manifest page {}".format(index_manifest_url))
        return None, fetched
    
    fetched[index_manifest_url] = manifest_page

    if path not in manifest_page.keys():
        log.error("Bucket {} not in manifest".format(path))
        if os.environ.get("BLOCKSTACK_TEST") == '1':
            log.debug("Index manifest:\n{}".format(json.dumps(manifest_page, indent=4, sort_keys=True)))

        return None, fetched

    bucket_url = manifest_page[path]
    index_page = index_get_page(dvconf, blockchain_id=blockchain_id, url=bucket_url, path=path)
    if index_page is None:
        log.error("Failed to get index page {}".format(path))
        return None, fetched

    url = index_page.get(name, None)
    fetched[bucket_url] = index_page
    return url, fetched


def put_indexed_data( dvconf, name, chunk_buf, raw=False, index=True ):
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
    new_url = put_chunk(dvconf, compressed_chunk, name)
    if new_url is None:
        log.error("Failed to save {}".format(name))
        return False

    # update index
    if index:
        log.debug("Insert ({}, {}) into index".format(name, new_url))
        rc = index_insert( dvconf, name, new_url )
        if not rc:
            log.error("Failed to insert ({}, {}) into index".foramt(name, new_url))
            return False

    return True


def _get_indexed_data_impl( dvconf, blockchain_id, name, raw=False, index_manifest_url=None, data_url=None ):
    """
    Get data from the storage system via the index.
    Load it from the index, and decompress it if needed.

    If @raw is True, then do not decompress even if we're configured to do so

    Return (data, None) on success
    Return (None, None) if we couldn't get data.
    Return (False, index pages) if we couldn't get index data.
    """
    log.debug("get indexed data {} from {}".format(name, blockchain_id))

    driver_name = dvconf['driver_name']
    config_path = dvconf['config_path']
    index_stem = dvconf['index_stem']
    index_pages = {}
    cache_hit = False

    if index_manifest_url is None:
        # try cache
        index_manifest_url = index_get_cached_manifest_url(blockchain_id, driver_name)
        if index_manifest_url is not None:
            cache_hit = True

    if index_manifest_url is None:
        # not cached, or didn't check
        # go look it up.
        index_manifest_url = None
        try:
            index_manifest_url = lookup_index_manifest_url(blockchain_id, driver_name, config_path)
        except Exception as e:
            if DEBUG:
                log.exception(e)

            log.error("Failed to get index manifest URL for {}".format(blockchain_id))
            return False, {}

        if index_manifest_url is None:
            log.error("Profile for {} is not connected to '{}'".format(blockchain_id, driver_name))
            return False, {}

    if data_url is None:
        # try the cache first... 
        data_url = index_cached_lookup(index_manifest_url, blockchain_id, name, index_stem)
        if data_url is not None:
            cache_hit = True

    if data_url is None:
        # cache miss
        # go get the url for this data
        data_url, index_pages = index_lookup(dvconf, index_manifest_url, blockchain_id, name, index_stem=index_stem)
        if data_url is None:
            log.error("No data URL from index for '{}'".format(name))
            return False, {}

    log.debug("Fetch {} via HTTP at {} (cached url: {})".format(name, data_url, cache_hit))
    data = get_chunk_via_http(data_url, blockchain_id=blockchain_id)
    if data is None:
        log.error("Failed to load {} from {}".format(name, data_url))

        if cache_hit:
            # might be due to stale cached index data
            return False, index_pages

        else:
            return None, None
        
    if dvconf['compress'] and not raw:
        data = decompress_chunk(data)
        if data is None:
            # corrupt
            return None, None

    # success! cache any index information
    if blockchain_id is not None:
        for (url, page) in index_pages.items():
            index_set_cached_page(blockchain_id, url, page)

        index_set_cached_manifest_url(blockchain_id, driver_name, index_manifest_url)

    return data, None


def get_indexed_data(dvconf, blockchain_id, name, raw=False, index_manifest_url=None ):
    """
    Get indexed data.
    Load it from the index, and decompress it if needed.

    Return the data on success.
    Return None on error
    """
    driver_name = dvconf['driver_name']

    # try cache path first
    data, pages = _get_indexed_data_impl(dvconf, blockchain_id, name, raw=raw, index_manifest_url=index_manifest_url)
    if data == False:
        if blockchain_id:
            # reading someone else's datastore
            log.warning("Failed to load fresh cached data when fetching {} from {}".format(name, blockchain_id))

            # clear index caches for this data and try again
            for (url, _) in pages.items():
                index_remove_cached_page(blockchain_id, url)

            index_remove_cached_manifest_url(blockchain_id, driver_name)

            # try again
            data, pages = _get_indexed_data_impl(dvconf, blockchain_id, name, raw=raw, index_manifest_url=index_manifest_url)
            if data is None or data == False:
                log.error("Failed to load data for {} from {} when forcing cache misses".format(name, blockchain_id))
                data = None

            else:
                log.debug("Loaded {} bytes for {} from {} when forcing cache misses".format(len(data), name, blockchain_id))

        else:
            # reading our own datastore, and failed.
            data = None

    if data is None:
        log.error("Failed to load data for {} from {}".format(name, blockchain_id))

    return data


def delete_indexed_data( dvconf, name ):
    """
    Delete data from the storage driver,
    and then delete it from the index.

    Return True on success
    Return False on error
    """
    driver_name = dvconf['driver_name']
    config_path = dvconf['config_path']
    delete_chunk = dvconf['delete_chunk']

    log.debug("Delete {}".format(name))
    res = delete_chunk(dvconf, name)
    if not res:
        log.error("Failed to delete {}".format(name))
        return False

    res = index_remove(dvconf, name)
    if not res:
        log.error("Failed to delete {} from index".format(name))
        return False

    return True
    

def get_chunk_via_http(url, blockchain_id=None):
    """
    Get a URL's data.
    Do not do any pre or post processing.

    Return the data on success
    Return None on failure
    """
    try:
        req = requests.get(url)
        if req.status_code != 200:
            log.debug("GET %s status code %s" % (url, req.status_code))
            return None

        return req.content
    except Exception, e:
        # this may be a test protocol...
        if url.startswith("test://"):
            import blockstack_client.backend.drivers.test
            return blockstack_client.backend.drivers.test.test_get_chunk(blockstack_client.backend.drivers.test.DVCONF, url[len('test://'):])

        if DEBUG:
            log.exception(e)

        return None


def http_get_data(dvconf, url, raw=False):
    """
    Get data via HTTP.  Follow directives in dvconf
    as to whether or not to decompress it.

    Return the data on success
    Return None on error
    """

    log.debug("Get {} via HTTP".format(url))
    data = get_chunk_via_http(url)
    if data is None:
        log.error("Failed to get {} via HTTP".format(url))
        return None

    if raw or not dvconf['compress']:
        return data

    else:
        try:
            data = decompress_chunk(data)
            return data
        except:
            # not compressed
            return data


def get_zonefile_from_atlas(blockchain_id, config_path, name_record=None):
    """
    Get the zone file from the atlas network
    Return the raw zone file on success
    Raise on eror
    """
    import blockstack_client
    import blockstack_client.proxy as proxy
    
    conf = blockstack_client.get_config(config_path)
    if not conf:
        raise Exception("Failed to load config file from {}".format(config_path))

    if 'server' not in conf or 'port' not in conf:
        raise Exception("Config file is missing 'server' and/or 'port")

    if name_record is not None:
        name_record = proxy.get_name_blockchain_record(blockchain_id)
        if 'error' in name_record:
            raise Exception("Failed to load name record for {}".format(blockchain_id))

    name_zonefile_hash = name_record['value_hash']

    atlas_host = conf['server']
    atlas_port = conf['port']
    hostport = '{}:{}'.format( atlas_host, atlas_port )

    zonefile_txt = None
    expected_zonefile_hash = str(name_zonefile_hash)

    # load from atlas
    res = proxy.get_zonefiles( hostport, [expected_zonefile_hash] )
    if 'error' in res:
        raise Exception("Failed to load {} from Atlas network: {}".format(expected_zonefile_hash, res['error']))

    zonefile_txt = res['zonefiles'][expected_zonefile_hash]
    return zonefile_txt


def lookup_index_manifest_url( blockchain_id, driver_name, config_path ):
    """
    Given a blockchain ID, go and get the index manifest url.

    This is only applicable for certain drivers--i.e. the ones that 
    need a name-to-URL index since the storage system generates URLs
    to data on-the-fly.  This includes Dropbox, Google Drive, Onedrive,
    etc.

    The storage index URL will be located as an 'account', where
    * 'service' will be set to the driver name
    * 'identifier' will be set to 'storage'
    * 'contentUrl' will be set to the index url

    Return the index manifest URL on success.
    Return None if there is no URL
    Raise on error
    """
    import blockstack_client
    import blockstack_client.proxy as proxy
    import blockstack_client.user
    import blockstack_client.storage

    if blockchain_id is None:
        # try getting it directly (we should have it)
        return index_settings_get_index_manifest_url(driver_name, config_path)        

    name_record = proxy.get_name_blockchain_record(blockchain_id)
    if 'error' in name_record:
        raise Exception("Failed to load name record for {}".format(blockchain_id))

    zonefile_txt = get_zonefile_from_atlas(blockchain_id, config_path, name_record=name_record)
    zonefile_pubkey = None

    try:
        zonefile = blockstack_zones.parse_zone_file(zonefile_txt) 
        zonefile = dict(zonefile)
        zonefile_pubkey = blockstack_client.user.user_zonefile_data_pubkey(zonefile)
    except:
        raise Exception("Non-standard zonefile for {}".format(blockchain_id))

    # get the profile... 
    profile_txt = None
    urls = blockstack_client.user.user_zonefile_urls(zonefile)
    for url in urls:
        profile_txt = None
        try:
            profile_txt = get_chunk_via_http(url, blockchain_id=blockchain_id)
        except Exception as e:
            if DEBUG:
                log.exception(e)

            log.debug("Failed to load profile from {}".format(url))
            continue

        if profile_txt is None:
            log.debug("Failed to load profile from {}".format(url))
            continue
        
        profile = blockstack_client.storage.parse_mutable_data(profile_txt, zonefile_pubkey, public_key_hash=name_record['address'])
        if not profile:
            log.debug("Failed to load profile from {}".format(url))
            continue
        
        # got profile! the storage information will be listed as an account, where the 'service' is the driver name and the 'identifier' is the manifest url 
        if 'account' not in profile:
            log.error("No 'account' key in profile for {}".format(blockchain_id))
            return None

        accounts = profile['account']
        if not isinstance(accounts, list):
            log.error("Invalid 'account' key in profile for {}".format(blockchain_id))
            return None

        for account in accounts:
            if not isinstance(account, dict):
                log.debug("Invalid account")
                continue

            if not account.has_key('service'):
                log.debug("No 'service' key in account")
                continue

            if not account.has_key('identifier'):
                log.debug("No 'identifier' key in account")
                continue

            if not account.has_key('contentUrl'):
                log.debug("No 'contentUrl' key in account")
                continue

            if account['service'] != driver_name:
                log.debug("Skipping account for '{}'".format(account['service']))
                continue

            if account['identifier'] != 'storage':
                log.debug("Skipping non-storage account for '{}'".format(account['service']))
                continue

            url = account['contentUrl']
            parsed_url = urlparse.urlparse(url)
            
            # must be valid http(s) URL, or a test:// URL
            if (not parsed_url.scheme or not parsed_url.netloc) and not url.startswith('test://'):
                log.warning("Skip invalid '{}' driver URL".format(driver_name))
                continue

            log.debug("Index manifest URL for {} is {}".format(blockchain_id, url))
            return url

    return None

def rip160sha256(data):
    h1 = hashlib.sha256()
    h2 = RIPEMD.new()

    h1.update(data)
    h2.update(h1.digest())
    return h2.hexdigest()
