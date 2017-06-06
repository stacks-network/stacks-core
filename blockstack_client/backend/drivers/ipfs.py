#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Implements an IPFS driver for blockstack.
    An index is used for translating names to content addressing names used in IPFS.
    Assumptions:
    - Writing user runs it's IPFS node with a pub/priv key pair tagged with it's blockstack id
      (used for the IPNS entry to have a fixed url for the index)
"""

import re
import threading
from ConfigParser import SafeConfigParser

import ipfsapi

from blockstack_client.backend.drivers.ipfsindex import ipfs_put_indexed_data, ipfs_get_indexed_data, ipfs_index_setup
from common import *

log = get_logger("blockstack-storage-drivers-ipfs")
log.setLevel(logging.DEBUG if DEBUG else logging.INFO)

IPFS_API = None
INDEX_DIRNAME = ""
DVCONF = None

BLOCKSTACK_DEBUG = (os.environ.get("BLOCKSTACK_DEBUG") == "1")

DEFAULT_GATEAWAY = "https://gateway.ipfs.io"
IPFS_HASH_PATTERN = re.compile(".*/(ipfs|ipns)/(.*)")
IPNS_ADDR_PATTERN = re.compile(".*(/ipns/.*)/?")
IPFS_ADDR_PATTERN = re.compile(".*(/ipfs/.*)/?")


class NameUpdateThread(threading.Thread):
    """
    Since IPNS name publish takes ages, the task is outsourced to a thread.
    """
    def __init__(self, ipfs_api, data_address, blockstack_id, previous_thread=None, driver_name=None, config_path=None):
        threading.Thread.__init__(self)
        self.no_newer = threading.Event()
        self.previous_thread = previous_thread
        self.ipfs_api = ipfs_api
        self.data_address = data_address
        self.blockstack_id = blockstack_id
        self.driver_name = driver_name
        self.config_path = config_path

    def run(self):
        if not self.previous_thread is None:
            # wait until older publish is done
            self.previous_thread.join()
        if self.no_newer.is_set():
            return
        name = ipfs_publish_name(self.ipfs_api, "/ipfs/%s" % self.data_address, self.blockstack_id)
        if not (self.driver_name is None or
                        self.config_path is None or
                        name is None):
            index_settings_set_index_manifest_url(self.driver_name, self.config_path, name)


class LocalIndexManifestManipulator(object):
    """
    A helper class which preserves the index manifest state.
    After each insert/update operation the content changes and hence it's ipfs address.
    Therefore, the IPNS entry has to be republished for the new index manifest address.
    """
    def __init__(self, start_manifest_index=None):
        self.cur_manifest_index = start_manifest_index
        self.cur_thread = None

    def publish_name(self, ipfs_api, data_address, blockstack_id,
                     driver_name=None, config_path=None):
        """
        Publish the new index manifest address
        :param ipfs_api: ifps api object
        :param data_address: the new address
        :param blockstack_id: the blockstack id for identifying the key
        :param driver_name: (optional)
        :param config_path: (optional)
        :return:
        """
        if self.cur_thread is not None:
            self.cur_thread.no_newer.set()
        self.cur_thread = NameUpdateThread(ipfs_api, data_address, blockstack_id, previous_thread=self.cur_thread,
                                           driver_name=driver_name, config_path=config_path)
        self.cur_thread.daemon = True
        self.cur_thread.start()


def ipfs_url_reformat(data_hash):
    """
    Given a IPFS data hash, outputs the default gataway url of the content
    :param data_hash:
    :return: the default Gateaway url.
    """
    return "%s/ipfs/%s" % (DEFAULT_GATEAWAY, data_hash)


def ipns_url_reformat(data_hash):
    """
    Given a IPNS pub hash, outputs the default gateway url of the content
    :param data_hash:
    :return: the default gateway url.
    """
    return "%s/ipns/%s" % (DEFAULT_GATEAWAY, data_hash)


def is_ipns_url(url):
    return "ipns" in url


def extract_hash_from_url(ipfs_url):
    """
    Extracts the resource path of a IPFS/IPNS URL
    ex: https://gateway.ipfs.io/ipfs/QmeZfdngL9Lw9489vjfaom5FRV4hbazoP8UuJtQQcjDeZa
    output: /ipfs/QmeZfdngL9Lw9489vjfaom5FRV4hbazoP8UuJtQQcjDeZa
    :param ipfs_url:
    :return: the IPFS/IPNS address
    """
    res = IPFS_HASH_PATTERN.match(ipfs_url)
    if res:
        return res.group(2)
    return None


def extract_addr_from_ipfs_url(ipfs_url):
    """
    Extracts the data hash from a IPFS Url
    ex: https://gateway.ipfs.io/ipfs/QmeZfdngL9Lw9489vjfaom5FRV4hbazoP8UuJtQQcjDeZa
    output: QmeZfdngL9Lw9489vjfaom5FRV4hbazoP8UuJtQQcjDeZa
    :param ipfs_url:
    :return: the content address
    """
    res = IPFS_ADDR_PATTERN.match(ipfs_url)
    if res:
        return res.group(1)
    return None


def extract_addr_from_ipns_url(ipns_url):
    """
    Extracts the data hash from a IPNS Url
    ex: https://gateway.ipfs.io/ipns/QmeZfdngL9Lw9489vjfaom5FRV4hbazoP8UuJtQQcjDeZa
    output: QmeZfdngL9Lw9489vjfaom5FRV4hbazoP8UuJtQQcjDeZa
    :param ipfs_url:
    :return: the content address
    """
    res = IPNS_ADDR_PATTERN.match(ipns_url)
    if res:
        return res.group(1)
    return None


def ipfs_check_key_exists(ipfs_api, key_name):
    """
    Check if the ipfs node has the key pair with the given name.
    :param ipfs_api: the api object
    :param key_name: the name of the key ex. "defaultkey"
    :return: true if key exists else false
    """
    if key_name is None:
        return False

    keys = ipfs_api._client.request('/key/list', decoder='json')['Keys']
    for key in keys:
        if key['Name'] == key_name:
            return True
    return False


def ipfs_publish_name(ipfs_api, ipfs_path, key, resolve=False, lifetime="175200h", ttl=None, **kwargs):
    """
    Publishes a new IPFS name for a IPNS address
    :param ipfs_api: the api object
    :param ipfs_path: the new IPFS path to publish (ex. /ipfs/QmeZfdngL9Lw9489vjfaom5FRV4hbazoP8UuJtQQcjDeZa)
    :param key: the name of the key IPNS key-pair to use (ex.  "defaultkey")
    :param resolve: -
    :param lifetime: -
    :param ttl: -
    :param kwargs:
    :return: dictionary with the resulting IPNS entry
    """
    opts = {"lifetime": lifetime, "resolve": resolve, "key": key}
    if ttl:
        opts["ttl"] = ttl
    kwargs.setdefault("opts", opts)
    args = (ipfs_path,)
    result = ipfs_api._client.request('/name/publish', decoder='json', args=args, **kwargs)
    return result


def ipfs_put_chunk(dvconf, chunk_buf, name, use_index_put=False):
    """
    Driver-level call to put data to ipfs.
    Returns the URL to the data stored on success. If not an Index Store request -> "/none"
    Returns None on error
    """
    driver_info = dvconf['driver_info']
    ipfs_server = driver_info['ipfs_server']
    ipfs_port = driver_info['ipfs_port']
    blockstack_id = driver_info['blockstack_id']
    manifest_manipulator = driver_info['manifest_manipulator']

    if ipfs_server is None or ipfs_port is None:
        log.warn("IPFS server not set, cannot write")
        return None

    ipfs_api = ipfsapi.connect(ipfs_server, ipfs_port)
    chunk_buf = str(chunk_buf)
    try:
        data_address = ipfs_api.add_str(chunk_buf)

        # check if index specific store request
        index_name = index_get_manifest_page_path(INDEX_DIRNAME)
        if index_name == name or use_index_put:
            # index store, add ipns entry!
            # (https://github.com/ipfs/examples/tree/master/examples/ipns,
            # https://groups.google.com/forum/#!topic/ipfs-users/rUK89pYway4)
            if not ipfs_check_key_exists(ipfs_api, blockstack_id):
                log.warn("IPFS node does not contain a key pair for the blockstack id {}".format(blockstack_id))
                return None
            # IPNS publish, Very slow at the moment :( -> outsource to thread + local caching of the index manifest
            if use_index_put:
                manifest_manipulator.publish_name(ipfs_api, data_address, blockstack_id)
            else:
                manifest_manipulator.publish_name(ipfs_api, data_address, blockstack_id,
                                                  driver_name=dvconf['driver_name'], config_path=dvconf['config_path'])
            return "/none"

        url = ipfs_url_reformat(data_address)
        log.debug("{} available at {}".format(name, url))
        return url
    except Exception as e:
        if DEBUG:
            log.exception(e)

        log.error("Failed to save {} bytes to {} in IPFS".format(len(chunk_buf), name))
        return None


def ipfs_delete_chunk(dvconf, name):
    """
    Unpin a chunk from ipfs
    Return True on success
    Return False on error
    """

    driver_info = dvconf['driver_info']
    ipfs_server = driver_info['ipfs_server']
    ipfs_port = driver_info['ipfs_port']

    if ipfs_server is None or ipfs_port is None:
        log.warn("IPFS server not set, cannot delete")
        return None

    ipfs_api = ipfsapi.connect(ipfs_server, ipfs_port)
    try:
        ipfs_api.pin_rm(extract_hash_from_url(name))
        return True
    except Exception, e:
        log.exception(e)
        return False


def ipfs_get_chunk(dvconf, name):
    """
    Get a chunk form IPFS
    Return the data on success
    Return None on error
    """

    driver_info = dvconf['driver_info']
    ipfs_server = driver_info['ipfs_server']
    ipfs_port = driver_info['ipfs_port']

    ipfs_api = None

    if not ipfs_server is None and not ipfs_port is None:
        ipfs_api = ipfsapi.connect(ipfs_server, ipfs_port)

    try:
        if ipfs_api is None:
            # use default gateway
            req = requests.get(name)
            if req.status_code != 200:
                log.debug("Failed retrieving {} status code {}".format(name, req.status_code))
                return None
            return req.text
        else:
            # use ipfs node
            path = name
            if is_ipns_url(path):
                path = ipfs_api.resolve(extract_addr_from_ipns_url(path))['Path']
            else:
                path = extract_addr_from_ipfs_url(path)
            return ipfs_api.cat(path.split("/")[2])
    except Exception, e:
        log.error("Failed to load {}".format(name))
        return None


def storage_init(conf, index=False, force_index=False, **kwargs):
    """
    Initialize ipfs storage driver
    """
    global DVCONF, IPFS_API
    compress = False
    ipfs_server = None
    ipfs_port = None
    config_path = conf['path']

    if os.path.exists(config_path):

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
                ipfs_port = int(parser.get('ipfs', 'port'))

            if parser.has_option('ipfs', 'compress'):
                compress = (parser.get('ipfs', 'compress').lower() in ['1', 'true', 'yes'])

    # blockstack id for identifying the ipfs key used for the IPNS url
    blockstack_id = kwargs.get('fqu', None)

    # set up driver
    DVCONF = driver_config("ipfs", config_path, ipfs_get_chunk, ipfs_put_chunk, ipfs_delete_chunk,
                           driver_info={'blockstack_id': blockstack_id, 'ipfs_server': ipfs_server,
                                        'ipfs_port': ipfs_port,
                                        'manifest_manipulator': LocalIndexManifestManipulator()},
                           index_stem=INDEX_DIRNAME, compress=compress)
    if index:
        # instantiate the index
        url = ipfs_index_setup(DVCONF, force=force_index)
        if not url:
            log.error("Failed to set up index")
            return False

    return True


def handles_url(url):
    """
    Do we handle this URL?
    Must point to a ipfs link
    """

    return DEFAULT_GATEAWAY in url \
           and ("ipfs" in url or "ipns" in url)


def make_mutable_url(data_id):
    """
    TODO:rewrite
    The URL here is a misnomer, since ipfs has content hash addressing.

    This URL here will instruct get_chunk() to go and search through
    the index for the target data.
    """
    data_id = urllib.quote(data_id.replace('/', '-2f'))
    url = "https://ipfs.io/blockstack/{}".format(data_id)
    return url


def get_immutable_handler(key, **kw):
    """
    Get data by hash
    """
    blockchain_id = kw.get('fqu', None)
    index_manifest_url = kw.get('index_manifest_url', None)

    name = 'immutable-{}'.format(key)
    name = name.replace('/', r'-2f')

    path = '/{}'.format(name)
    return ipfs_get_indexed_data(DVCONF, blockchain_id, path, index_manifest_url=index_manifest_url)


def get_mutable_handler(url, **kw):
    """
    Get data by URL
    """
    blockchain_id = kw.get('fqu', None)
    index_manifest_url = kw.get('index_manifest_url', None)

    urltype, urlres = get_url_type(url)
    if urltype is None and urlres is None:
        log.error("Invalid URL {}".format(url))
        return None

    if urltype == 'blockstack':
        # get via index
        urlres = urlres.replace('/', r'-2f')
        path = '/{}'.format(urlres)
        return ipfs_get_indexed_data(DVCONF, blockchain_id, path, index_manifest_url=index_manifest_url)

    else:
        # raw ipfs gateaway url
        return http_get_data(DVCONF, url)


def put_immutable_handler(key, data, txid, **kw):
    """
    Put data by hash and txid
    """
    global DVCONF
    index_manifest_url = index_settings_get_index_manifest_url(DVCONF['driver_name'], DVCONF['config_path'])

    name = 'immutable-{}'.format(key)
    name = name.replace('/', r'-2f')

    path = '/{}'.format(name)
    return ipfs_put_indexed_data(DVCONF, path, data, index_manifest_url=index_manifest_url)


def put_mutable_handler(data_id, data_bin, **kw):
    """
    Put data by file ID
    """
    global DVCONF
    index_manifest_url = index_settings_get_index_manifest_url(DVCONF['driver_name'], DVCONF['config_path'])
    data_id = data_id.replace('/', r'-2f')
    path = '/{}'.format(data_id)

    return ipfs_put_indexed_data(DVCONF, path, data_bin, index_manifest_url=index_manifest_url)


def delete_immutable_handler(key, txid, sig_key_txid, **kw):
    """
    Delete by hash (only index is updated) (IPFS does not support delete)
    """
    global DVCONF

    name = 'immutable-{}'.format(key)
    name = name.replace('/', r'-2f')
    path = '/{}'.format(name)

    return delete_indexed_data(DVCONF, path)


def delete_mutable_handler(data_id, signature, **kw):
    """
    Delete by data ID (only index is updated)  (IPFS does not support delete)
    """
    global DVCONF

    data_id = data_id.replace('/', r'-2f')
    path = '/{}'.format(data_id)

    return delete_indexed_data(DVCONF, path)


if __name__ == "__main__":
    """
    Simple test
    Demo Hash corresponds to the hash of the public key in the ipfs node for the TAG demo.io
    (the address for IPNS)
    """

    demo_hash = "QmfYEYcX9KY9PUuwr1a4VgNgtAxJ81ZEsNF4Tid6GTp87z"
    import ConfigParser, os, shutil

    config = ConfigParser.SafeConfigParser()
    config.add_section('ipfs')
    config.set('ipfs', 'server', 'localhost')
    config.set('ipfs', 'port', '5001')
    config.set('ipfs', 'compress', '1')
    with open("temp.config", 'w') as config_file:
        config.write(config_file)
    os.mkdir("drivers")
    os.mkdir("drivers/ipfs")
    with open("drivers/ipfs/index_manifest_url", 'w') as config_file:
        config_file.write(DEFAULT_GATEAWAY + "/ipns/%s" % demo_hash)
    try:
        storage_init(conf={'path': 'temp.config'}, index=True, force_index=True, fqu='demo.io')
        data = "ipfs with blockstack is great"
        print "Put data: %s" % data
        url = put_immutable_handler("test", data, "txid1")
        print "Fetch data"
        out = get_immutable_handler("test")
        print "Result: %s" % out

        if out == data:
            print "Success :D"
        else:
            print "Failed :("
    finally:
        shutil.rmtree("drivers")
