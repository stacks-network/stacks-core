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

if os.environ.get("BLOCKSTACK_DEBUG", None) is not None:
    DEBUG = True
else:
    DEBUG = False


INDEX_PAGE_SCHEMA = {
    'type': 'object',
    'patternProperties': {
        r'^([a-zA-Z0-9\-_.~%/]+)$': {
            'type': 'string',
            'pattern': r'^(http[s]{0,1}://[a-zA-Z0-9\-_.~%/?&=]+)$'
        },
    },
}
 
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


def get_index_page_path(name, index_dir):
    """
    Get the path to an index page
    """
    h = hashlib.sha256(name).hexdigest()
    bucket_1 = h[0:1]

    path = '/{}/{}'.format(index_dir, bucket_1)
    return path


def parse_index_page(index_page_data):
    """
    Parse a serialized index page into a dict
    Return the dict on success
    Return None on error
    """
    try:
        page_data = json.loads(str(index_page_data))
        jsonschema.validate(page_data, INDEX_PAGE_SCHEMA)
        return page_data

    except Exception as e:
        if DEBUG:
            log.exception(e)

        log.error("Failed to parse index page ({} bytes)".format(len(index_page_data)))
        return None


def serialize_index_page(index_page):
    """
    Serialize an index page
    Return the serialized byte buffer
    """
    return str(json.dumps(index_page, sort_keys=True))


def get_index_bucket_names():
    """
    Get the list of index bucket names
    """
    return ['{:1x}'.format(i) for i in xrange(0, 16)]


def get_chunk_via_http(url):
    """
    Get a URL's data
    Return the data on success
    Return None on failure

    Do not try to decompress.
    """
    try:
        req = requests.get(url)
        if req.status_code != 200:
            log.debug("GET %s status code %s" % (url, req.status_code))
            return None

        return req.content
    except Exception, e:
        log.exception(e)
        return None


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


def get_index_manifest_url( blockchain_id, driver_name, config_path ):
    """
    Given a blockchain ID, go and get the index manifest url.
    This will be a special field under the profile, called 'storage'
    Return the URL on success.

    This is only applicable for certain drivers--i.e. the ones that 
    need a name-to-URL index since the storage system generates URLs
    to data on-the-fly.  This includes Dropbox, Google Drive, Onedrive,
    etc.

    Return the index manifest URL on success.
    Return None if there is no URL
    Raise on error
    """
    import blockstack_client
    import blockstack_client.proxy as proxy
    import blockstack_client.user
    import blockstack_client.storage

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
        if url.lower().startswith("http://") or url.lower().startswith("https://"):
            try:
                profile_txt = get_chunk_via_http(url)
            except:
                continue
            
            profile = blockstack_client.storage.parse_mutable_data(profile_txt, zonefile_pubkey, public_key_hash=name_record['address'])
            if not profile:
                continue

            # got profile!
            if 'storage' not in profile:
                log.error("No 'storage' key in profile for {}".format(blockstack_id))
                return None

            if driver_name not in profile['storage']:
                log.error("No '{}' key in profile['storage'] for {}".format(driver_name, blockstack_id))
                return None

            return profile['storage'][driver_name]

    return None
