import json
import os

from blockstack_client.backend.drivers.common import index_setup, index_get_page_path, index_get_cached_manifest_url, \
    log, DEBUG, lookup_index_manifest_url, index_get_manifest_page_path, compress_chunk, \
    serialize_index_page, index_remove_cached_page, index_remove_cached_manifest_url, index_cached_lookup, \
    get_chunk_via_http, decompress_chunk, index_set_cached_page, index_set_cached_manifest_url, parse_index_page, \
    index_settings_get_index_manifest_url, get_index_bucket_names, normpath, index_make_bucket

"""
Wrapper file for the index implementation in common.py
IPFS needs some small changes in the index handling, since every write/delete results in 
new content addresses for the index. 
"""


def ipfs_index_setup(dvconf, force=False):
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
    manifest_manipulator = dvconf['driver_info']['manifest_manipulator']

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
    manifest_manipulator.cur_manifest_index = index_manifest
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
    return True


def ipfs_index_page_find(dvconf, index_stem, name, index_manifest_url=None):
    manifest_manipulator = dvconf['driver_info']['manifest_manipulator']

    fetched = {}
    index_manifest_path = index_get_manifest_page_path(index_stem)
    path = index_get_page_path(name, index_stem)

    log.debug("Get index manifest page ({}, {})".format(index_manifest_url, index_manifest_path))
    if manifest_manipulator.cur_manifest_index is None:
        manifest_page = ipfs_index_get_page(dvconf, url=index_manifest_url, path=index_manifest_path)
        manifest_manipulator.cur_manifest_index = manifest_page
        if manifest_page is None:
            log.error("Failed to get manifest page {}".format(index_manifest_url))
            return None, fetched
    manifest_page = manifest_manipulator.cur_manifest_index
    fetched[index_manifest_url] = manifest_page

    if path not in manifest_manipulator.cur_manifest_index.keys():
        log.error("Bucket {} not in manifest".format(path))
        if os.environ.get("BLOCKSTACK_TEST") == '1':
            log.debug("Index manifest:\n{}".format(json.dumps(manifest_page, indent=4, sort_keys=True)))

        return None, fetched

    bucket_url = manifest_page[path]
    index_page = ipfs_index_get_page(dvconf, url=bucket_url, path=path)
    if index_page is None:
        log.error("Failed to get index page {}".format(path))
        return None, fetched

    return index_page, manifest_page, fetched


def ipfs_index_insert(dvconf, name, url, index_manifest_url=None):
    """
    Insert a url into the index.
    and updates the index in the storage

    Return True on success
    Return False if not.
    """
    assert index_setup(dvconf)

    manifest_manipulator = dvconf['driver_info']['manifest_manipulator']
    index_stem = dvconf['index_stem']

    path = index_get_page_path(name, index_stem)
    index_page, manifest_page, fetched = ipfs_index_page_find(dvconf, index_stem, name, index_manifest_url=index_manifest_url)
    if index_page is None:
        index_page = {}
    if manifest_page is None:
        manifest_page = {}

    index_page[name] = url

    put_chunk = dvconf['put_chunk']
    log.debug("Set index page {}".format(path))
    new_serialized_index_page = serialize_index_page(index_page)

    rc = put_chunk(dvconf, new_serialized_index_page, path)

    manifest_page[path] = rc
    new_serialized_manifest_page = serialize_index_page(manifest_page)
    manifest_manipulator.cur_manifest_index = manifest_page
    return put_chunk(dvconf, new_serialized_manifest_page, path, use_index_put=True)


def ipfs_index_remove(dvconf, name, index_manifest_url=None):
    """
    Remove a url from the index.
    Return True on success
    Return False if not.
    """
    assert index_setup(dvconf)

    manifest_manipulator = dvconf['driver_info']['manifest_manipulator']
    index_stem = dvconf['index_stem']

    path = index_get_page_path(name, index_stem)
    index_page, manifest_page, fetched = ipfs_index_page_find(dvconf, index_stem, name,
                                                              index_manifest_url=index_manifest_url)
    if index_page is None:
        log.error("Failed to get index page {}".format(path))
        return False

    if name not in index_page:
        # already gone
        return True

    del index_page[name]
    put_chunk = dvconf['put_chunk']
    log.debug("Set index page {}".format(path))
    new_serialized_index_page = serialize_index_page(index_page)

    rc = put_chunk(dvconf, new_serialized_index_page, path)

    manifest_page[path] = rc
    new_serialized_manifest_page = serialize_index_page(manifest_page)
    manifest_manipulator.cur_manifest_index = manifest_page
    return put_chunk(dvconf, new_serialized_manifest_page, path, use_index_put=True)


def ipfs_delete_indexed_data( dvconf, name ):
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

    res = ipfs_index_remove(dvconf, name)
    if not res:
        log.error("Failed to delete {} from index".format(name))
        return False

    return True


def ipfs_put_indexed_data( dvconf, name, chunk_buf, raw=False, index=True, index_manifest_url=None):
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
        rc = ipfs_index_insert( dvconf, name, new_url, index_manifest_url=index_manifest_url)
        if not rc:
            log.error("Failed to insert ({}, {}) into index".foramt(name, new_url))
            return False

    return True


def ipfs_index_get_page(dvconf, blockchain_id=None, path=None, url=None):
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
        serialized_index_page = get_chunk(dvconf, url)

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


def ipfs_index_lookup(dvconf, index_manifest_url, blockchain_id, name, index_stem='index'):
    """
    Given the name, find the URL
    Return the (URL, {url: page}) on success
    Return (None, {url: page}) on error
    """
    manifest_manipulator = dvconf['driver_info']['manifest_manipulator']

    log.debug("Index lookup on {} from {} via {}".format(name, blockchain_id, index_manifest_url))

    index_manifest_path = index_get_manifest_page_path(index_stem)
    path = index_get_page_path(name, index_stem)

    fetched = {}

    log.debug("Get index manifest page ({}, {})".format(index_manifest_url, index_manifest_path))
    #blockchain_id_tmp = blockchain_id if blockchain_id is not None else "dummy"
    if blockchain_id is not None or manifest_manipulator.cur_manifest_index is None:
        manifest_page = ipfs_index_get_page(dvconf, blockchain_id=blockchain_id, url=index_manifest_url,
                                       path=index_manifest_path)
        if blockchain_id is None:
            manifest_manipulator.cur_manifest_index = manifest_page
    else:
        manifest_page = manifest_manipulator.cur_manifest_index

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
    index_page = ipfs_index_get_page(dvconf, blockchain_id=blockchain_id, url=bucket_url, path=path)
    if index_page is None:
        log.error("Failed to get index page {}".format(path))
        return None, fetched

    url = index_page.get(name, None)
    fetched[bucket_url] = index_page
    return url, fetched


def _ipfs_get_indexed_data_impl(dvconf, blockchain_id, name, raw=False, index_manifest_url=None, data_url=None):
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
    manifest_manipulator = dvconf['driver_info']['manifest_manipulator']
    index_pages = {}
    cache_hit = False
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
        data_url, index_pages = ipfs_index_lookup(dvconf, index_manifest_url, blockchain_id, name, index_stem=index_stem)
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

        if not given_manifest_url:
            index_set_cached_manifest_url(blockchain_id, driver_name, index_manifest_url)

    return data, None


def ipfs_get_indexed_data(dvconf, blockchain_id, name, raw=False, index_manifest_url=None ):
    """
    Get indexed data.
    Load it from the index, and decompress it if needed.

    Return the data on success.
    Return None on error
    """
    driver_name = dvconf['driver_name']

    # try cache path first
    data, pages = _ipfs_get_indexed_data_impl(dvconf, blockchain_id, name, raw=raw, index_manifest_url=index_manifest_url)
    if data == False:
        if blockchain_id:
            # reading someone else's datastore
            log.warning("Failed to load fresh cached data when fetching {} from {}".format(name, blockchain_id))

            # clear index caches for this data and try again
            for (url, _) in pages.items():
                index_remove_cached_page(blockchain_id, url)

            index_remove_cached_manifest_url(blockchain_id, driver_name)

            # try again
            data, pages = _ipfs_get_indexed_data_impl(dvconf, blockchain_id, name, raw=raw, index_manifest_url=index_manifest_url)
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