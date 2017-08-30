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
import threading
import time
import tempfile

from functools import wraps

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

# map driver_name --> {index_page_url: index_data}
INDEX_CACHE = {}

# map driver_name --> {bucket ID: lock}
INDEX_CACHE_LOCK = threading.Lock()
INDEX_CACHE_LOCKS = {}

# map blockchain_id --> manifest URL
INDEX_MANIFEST_URL_CACHE = {}

# operations in progress
IN_PROGRESS = {}
IN_PROGRESS_LOCK = threading.Lock()

class ConcurrencyViolationException(Exception):
    """
    Exception thrown when we try to run a non-parallelizable
    operation (like index initialization) in parallel with
    another instance of that operation.
    """
    pass


def nonconcurrent(operation_name):
    """
    Decorator to ensure that at most one instance of this function is executing.
    Throws ConcurrencyVioaltionException if not.
    """
    assert(operation_name)

    def decorator(function):
        @wraps(function)
        def inner(*args, **kw):
            global IN_PROGRESS_LOCK, IN_PROGRESS
            with IN_PROGRESS_LOCK:
                if IN_PROGRESS.get(operation_name) is not None:
                    # in progress
                    log.debug("Non-concurrent operation already in progress: '{}'".format(operation_name))
                    raise ConcurrencyViolationException()

                log.debug("Non-concurrent operation in progress: '{}'".format(operation_name))
                IN_PROGRESS[operation_name] = True

            res = function(*args, **kw)

            with IN_PROGRESS_LOCK:
                log.debug("Finished non-concurrent operation: '{}'".format(operation_name))
                del IN_PROGRESS[operation_name]

            return res

        return inner
    return decorator


def get_logger(name=None):
    """
    Get logger
    """

    level = logging.INFO
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


def index_get_page_bucket_id(name):
    """
    Which index bucket is this in?
    """
    h = hashlib.sha256(name).hexdigest()
    bucket_id = h[0:1]
    return bucket_id


def index_get_page_path(name, index_dir):
    """
    Get the path to an index page
    """
    bucket_id = index_get_page_bucket_id(name)

    path = normpath('/{}/{}'.format(index_dir, bucket_id))
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
        return None, None

    if urlpath_parts[0] == 'blockstack':
        return ('blockstack', urlpath_parts[1])

    else:
        return ('http', url)


def index_make_mutable_url(host, data_id, scheme='https'):
    """
    Make a faux-mutable URL that will be identified
    by the indexer as referring to indexed data.
    """
    data_id = urllib.quote( data_id.replace('/', '-2f') )
    url = "{}://{}/blockstack/{}".format(scheme, host, data_id)
    return url


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
        log.debug("Serialized index bucket {}".format(bucket))

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


def index_check_setup(dvconf, blockchain_id=None):
    """
    Is the index set up?
    Return True if so
    Return False if not
    """

    config_path = dvconf['config_path']
    get_chunk = dvconf['get_chunk']
    driver_name = dvconf['driver_name']
    index_stem = dvconf['index_stem']

    index_manifest_url = index_settings_get_index_manifest_url(driver_name, config_path)
    if index_manifest_url is not None :
        # already set up
        return True
 
    index_manifest_path = index_get_manifest_page_path(index_stem)

    log.debug("Get index manifest page ({}, {})".format(index_manifest_url, index_manifest_path))
    manifest_page = index_get_page(dvconf, blockchain_id=blockchain_id, url=index_manifest_url, path=index_manifest_path)
    if manifest_page is None:
        log.error("Failed to get manifest page {}".format(index_manifest_url))
        return False
  
    log.warning("Index appears to be set up for {} (index {}); will cache index URL".format(driver_name, index_stem))

    # it's set up 
    rc = index_settings_set_index_manifest_url(driver_name, config_path, index_manifest_url)
    if not rc:
        # failed 
        return False

    return True


@nonconcurrent("index_setup")
def index_setup(dvconf, force=False):
    """
    Set up our index if we haven't already.
    Return the index manifest URL on success
    Return the index manifest URL if already setup
    Return False on error
    """

    config_path = dvconf['config_path']
    put_chunk = dvconf['put_chunk']
    driver_name = dvconf['driver_name']
    index_stem = dvconf['index_stem']

    # test long-running index setup...
    if os.environ.get("TEST_BLOCKSTACK_TEST_INDEX_SETUP_DELAY") is not None:
        delay = int(os.environ["TEST_BLOCKSTACK_TEST_INDEX_SETUP_DELAY"])
        log.debug("Waiting {} seconds for index to complete".format(delay))
        time.sleep(delay)

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


def index_get_cached_page(driver_name, bucket_id):
    """
    Get cached index page data
    Return the cached page on success
    Return None on error
    """
    global INDEX_CACHE
    if not INDEX_CACHE.has_key(driver_name):
        return None

    if not INDEX_CACHE[driver_name].has_key(bucket_id):
        return None

    return INDEX_CACHE[driver_name][bucket_id]


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


def index_set_cached_page(driver_name, bucket_id, data, locked=False):
    """
    Insert a page's data into the index page cache
    """
    global INDEX_CACHE
    if not INDEX_CACHE.has_key(driver_name):
        INDEX_CACHE[driver_name] = {}

    log.debug("Cache {} bytes for {}".format(len(data), bucket_id))

    def _do_insert():
        if not INDEX_CACHE[driver_name].has_key(bucket_id):
            INDEX_CACHE[driver_name][bucket_id] = {}

        INDEX_CACHE[driver_name][bucket_id].update(data)

    if locked:
        _do_insert()

    else:
        with index_page_get_lock(driver_name, bucket_id):
            _do_insert()

    return True


def index_set_cached_manifest_url(blockchain_id, driver_name, url):
    """
    Cache the index manifest URL
    """
    global INDEX_MANIFEST_URL_CACHE
    key = '{}-{}'.format(blockchain_id, driver_name)

    log.debug("Cache {}-byte manifest URL for driver {} from {}".format(len(url), driver_name, blockchain_id))
    INDEX_MANIFEST_URL_CACHE[key] = url


def index_remove_cached_page(driver_name, bucket_id, url):
    """
    Remove a cached page
    """
    global INDEX_CACHE
    if not INDEX_CACHE.has_key(driver_name):
        return True

    if not INDEX_CACHE[driver_name].has_key(bucket_id):
        return True

    if not INDEX_CACHE[driver_name][bucket_id].has_key(url):
        return True

    del INDEX_CACHE[driver_name][bucket_id][url]
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
    
    Does NOT load from the cache 

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


def index_set_page(dvconf, bucket_id, path, index_page):
    """
    Store an index page to the storage provider

    Return True on success
    Return False on error
    """
    assert index_check_setup(dvconf)
    
    put_chunk = dvconf['put_chunk']
    driver_name = dvconf['driver_name']

    log.debug("Set index page {}".format(path))

    new_serialized_index_page = serialize_index_page(index_page)
    rc = put_chunk(dvconf, new_serialized_index_page, path)
    if not rc:
        # failed 
        log.error("Failed to store index page {}".format(path))
        return False

    return True  


def index_locks_setup(driver_name):
    """
    Initialize the global index cache locks.
    For a driver, there is one lock per bucket
    """
    global INDEX_CACHE_LOCKS
    if not INDEX_CACHE_LOCKS.has_key(driver_name):
        # add lock set for this driver
        with INDEX_CACHE_LOCK:
            if not INDEX_CACHE_LOCKS.has_key(driver_name):
                INDEX_CACHE_LOCKS[driver_name] = {}
                bucket_ids = get_index_bucket_names() + ['manifest']
                for bid in bucket_ids:
                    INDEX_CACHE_LOCKS[driver_name][bid] = threading.Lock()

    return True


def index_page_get_lock(driver_name, bucket_id):
    """
    Return a lock for a page
    """
    global INDEX_CACHE_LOCKS
    index_locks_setup(driver_name)
    return INDEX_CACHE_LOCKS[driver_name][bucket_id]


def index_insert(dvconf, name, url):
    """
    Insert a url into the index.

    Return True on success
    Return False if not.
    """
    assert index_check_setup(dvconf)

    driver_name = dvconf['driver_name']
    index_stem = dvconf['index_stem']
    
    bucket_id = index_get_page_bucket_id(name)
    path = index_get_page_path(name, index_stem) 

    with index_page_get_lock(driver_name, bucket_id):
        index_page = index_get_cached_page(driver_name, bucket_id)
        if index_page is None: 
            index_page = index_get_page( dvconf, path=path )
            if index_page is None:
                index_page = {}

        index_page[name] = url
        index_set_cached_page(driver_name, bucket_id, index_page, locked=True)
        return index_set_page(dvconf, bucket_id, path, index_page)
    

def index_remove( dvconf, name ):
    """
    Remove a url from the index.
    Return True on success
    Return False if not.
    """
    assert index_check_setup(dvconf)

    index_stem = dvconf['index_stem']
    driver_name = dvconf['driver_name']

    bucket_id = index_get_page_bucket_id(name)
    path = index_get_page_path(name, index_stem)

    with index_page_get_lock(driver_name, bucket_id):
        index_page = index_get_cached_page(driver_name, bucket_id)
        if index_page is None: 
            index_page = index_get_page( dvconf, path=path )
            if index_page is None:
                log.error("Failed to get index page {}".format(path))
                return False

        if name not in index_page:
            # already gone
            return True

        del index_page[name]
        index_set_cached_page(driver_name, bucket_id, index_page, locked=True)
        return index_set_page(dvconf, bucket_id, path, index_page)


def index_cached_lookup( driver_name, name, index_stem ):
    """
    Do a lookup in our cache for a url to a named datum
    Return the {'url': URL, 'manifest': manifest page} on success
    Return {'manifest': manifest_page} if not cached
    """
    log.debug("Index cached lookup on {} from {}".format(name, driver_name))

    # if this is cached, then use the cache 
    path = index_get_page_path(name, index_stem)
    bucket_id = index_get_page_bucket_id(name)
    manifest_page = index_get_cached_page(driver_name, 'manifest')

    if manifest_page is not None:
        # cached...
        log.debug("Cache HIT on manifest")
        if path in manifest_page.keys():

            index_page = index_get_cached_page(driver_name, bucket_id)
            if index_page is not None:

                # also cached 
                log.debug("Cache HIT on bucket {}".format(bucket_id))
                url = index_page.get(name, None)
                if url is not None:
                    return {'url': url, 'manifest': manifest_page}

                else:
                    log.debug("Missing name {} on cached page ({}, {} (bucket {}))".format(name, driver_name, path, bucket_id))

            else:
                log.debug("Cache MISS on ({}, {} (bucket {}))".format(driver_name, path, bucket_id))

        else:
            log.debug("Missing {} on manifest (from {})".format(path, driver_name))

    else:
        log.debug("Cache MISS on manifest (from {})".format(driver_name))

    if manifest_page is not None:
        return {'manifest': manifest_page}

    return None


def index_lookup( dvconf, index_manifest_url, blockchain_id, name, index_stem='index', manifest_page=None ):
    """
    Given the name, find the URL
    Return the (URL, {'manifest': page, 'page': page) on success
    Return (None, {'manifest': page, 'page': page}) on error
    """
   
    log.debug("Index lookup on {} from {} via {}".format(name, blockchain_id, index_manifest_url))

    index_manifest_path = index_get_manifest_page_path(index_stem)
    path = index_get_page_path(name, index_stem)

    fetched = {}
    
    if manifest_page is not None and path not in manifest_page.keys():
        log.warning("Bucket {} not in manifest".format(path))
        manifest_page = None

    if manifest_page is None:
        log.debug("Get index manifest page ({}, {})".format(index_manifest_url, index_manifest_path))
        manifest_page = index_get_page(dvconf, blockchain_id=blockchain_id, url=index_manifest_url, path=index_manifest_path)
        if manifest_page is None:
            log.error("Failed to get manifest page {}".format(index_manifest_url))
            return None, fetched
    
    fetched['manifest'] = manifest_page
    
    if path not in manifest_page.keys():
        # not present
        log.error("Bucket {} not in fresh manifest".format(path))
        if os.environ.get("BLOCKSTACK_TEST") == '1':
            log.debug("Index manifest:\n{}".format(json.dumps(manifest_page, indent=4, sort_keys=True)))

        return None, fetched

    bucket_url = manifest_page[path]
    index_page = index_get_page(dvconf, blockchain_id=blockchain_id, url=bucket_url, path=path)
    if index_page is None:
        log.error("Failed to get index page {}".format(path))
        return None, fetched

    url = index_page.get(name, None)
    fetched['page'] = index_page
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
            log.error("Failed to insert ({}, {}) into index".format(name, new_url))
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
    manifest_page = None
    given_manifest_url = False

    if index_manifest_url is None:
        # try cache
        index_manifest_url = index_get_cached_manifest_url(blockchain_id, driver_name)
        if index_manifest_url is not None:
            cache_hit = True

    else:
        given_manifest_url = True

    if index_manifest_url is None:
        # not cached, or didn't check
        # go look it up.
        index_manifest_url = None
        try:
            index_manifest_url = lookup_index_manifest_url(blockchain_id, driver_name, index_stem, config_path)
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
        cached_lookup = index_cached_lookup(driver_name, name, index_stem)
        if cached_lookup is not None:
            if cached_lookup.has_key('url'):
                cache_hit = True
                data_url = cached_lookup['url']

            if cached_lookup.has_key('manifest'):
                manifest_page = cached_lookup['manifest']

    if data_url is None:
        # cache miss
        # go get the url for this data
        manifest_page = None
        data_url, index_pages = index_lookup(dvconf, index_manifest_url, blockchain_id, name, index_stem=index_stem, manifest_page=manifest_page)
        if data_url is None:
            log.error("No data URL from index for '{}'".format(name))

            if os.environ.get('BLOCKSTACK_TEST') == '1':
                log.debug("Index page: {}".format(json.dumps(index_pages['page'], indent=4, sort_keys=True)))

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
        if not given_manifest_url:
            index_set_cached_manifest_url(blockchain_id, driver_name, index_manifest_url)

    if index_pages.has_key('manifest'):
        index_set_cached_page(driver_name, 'manifest', index_pages['manifest'])

    if index_pages.has_key('page'):
        bucket_id = index_get_page_bucket_id(name)
        index_set_cached_page(driver_name, bucket_id, index_pages['page'])

    return data, None


def get_indexed_data(dvconf, blockchain_id, name, raw=False, index_manifest_url=None ):
    """
    Get indexed data.
    Load it from the index, and decompress it if needed.

    Return the data on success.
    Return None on error
    """
    driver_name = dvconf['driver_name']
    bucket_id = index_get_page_bucket_id(name)

    # try cache path first
    data, pages = _get_indexed_data_impl(dvconf, blockchain_id, name, raw=raw, index_manifest_url=index_manifest_url)
    if data == False:
        if blockchain_id:
            # reading someone else's datastore
            log.warning("Failed to load fresh cached data when fetching {} from {}".format(name, blockchain_id))

            # clear index caches for this data and try again
            for (url, _) in pages.items():
                index_remove_cached_page(driver_name, bucket_id, url)

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


def index_get_immutable_handler( dvconf, key, **kw ):
    """
    Default method to get data by hash using the index.
    Meant for HTTP-based cloud providers.

    Return the data on success
    Return None on error
    """
    blockchain_id = kw.get('fqu', None)
    index_manifest_url = kw.get('index_manifest_url', None)
    
    name = 'immutable-{}'.format(key)
    name = name.replace('/', r'-2f')
   
    path = '/{}'.format(name)
    return get_indexed_data(dvconf, blockchain_id, path, index_manifest_url=index_manifest_url)


def index_get_mutable_handler( dvconf, url, default_get_data=http_get_data, **kw ):
    """
    Default method to get data by URL using the index.
    Falls back to HTTP GET on failure, unless default_get_data() is given

    Return the data on success
    Return None on error
    """
    blockchain_id = kw.get('fqu', None)
    index_manifest_url = kw.get('index_manifest_url', None)

    urltype, urlres = get_url_type(url)
    if urltype is None and urlres is None:
        log.error("Invalid URL {}".format(url))
        return None

    if urltype == 'blockstack':
        # get via index
        data_id = '/' + urlres.replace('/', r'-2f')
        return get_indexed_data(dvconf, blockchain_id, data_id, index_manifest_url=index_manifest_url)

    else:
        # raw url 
        return http_get_data(dvconf, url)


def index_put_immutable_handler( dvconf, key, data, txid, **kw ):
    """
    Put data by hash and txid, using the index.
    Meant for HTTP-based cloud providers.

    Return the URL on success
    Return None on error
    """
    name = 'immutable-{}'.format(key)
    name = name.replace('/', r'-2f')

    path = '/{}'.format(name)
    return put_indexed_data(dvconf, path, data)


def index_put_mutable_handler( dvconf, data_id, data_bin, **kw ):
    """
    Put data by data ID, using the index.
    Meant for HTTP-based cloud providers.

    Return the URL on success
    Return None on error
    """
    data_id = data_id.replace('/', r'-2f')
    path = '/{}'.format(data_id)

    return put_indexed_data(dvconf, path, data_bin)


def index_delete_immutable_handler( dvconf, key, txid, sig_key_txid, **kw ):
    """
    Delete by hash, using the index.
    Meant for HTTP-based cloud providers.

    Return the URL on success
    Return None on error
    """
    name = 'immutable-{}'.format(key)
    name = name.replace('/', r'-2f')
    path = '/{}'.format(name)

    return delete_indexed_data(dvconf, path)


def index_delete_mutable_handler( dvconf, data_id, signature, **kw ):
    """
    Delete by data ID
    """
    data_id = data_id.replace('/', r'-2f')
    path = '/{}'.format(data_id)

    return delete_indexed_data(dvconf, path)


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


def lookup_index_manifest_url( blockchain_id, driver_name, index_stem, config_path ):
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

    TODO: this method needs to be rewritten to use the token file format,
    and to use the proper public key to verify it.
    """
    import blockstack_client
    import blockstack_client.proxy as proxy
    import blockstack_client.user
    import blockstack_client.storage
    import blockstack_client.schemas

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
    # we're assuming here that some of the profile URLs are at least HTTP-accessible
    # (i.e. we can get them without having to go through the indexing system)
    # TODO: let drivers report their 'safety'
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
       
        # TODO: load this from the tokens file
        # got profile! the storage information will be listed as an account, where the 'service' is the driver name and the 'identifier' is the manifest url 
        if 'account' not in profile:
            log.error("No 'account' key in profile for {}".format(blockchain_id))
            return None

        accounts = profile['account']
        if not isinstance(accounts, list):
            log.error("Invalid 'account' key in profile for {}".format(blockchain_id))
            return None

        for account in accounts:
            try:
                jsonschema.validate(account, blockstack_client.schemas.PROFILE_ACCOUNT_SCHEMA)
            except jsonschema.ValidationError:
                continue

            if account['service'] != driver_name:
                log.debug("Skipping account for '{}'".format(account['service']))
                continue

            if account['identifier'] != 'storage':
                log.debug("Skipping non-storage account for '{}'".format(account['service']))
                continue
            
            if not account.has_key('contentUrl'):
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
