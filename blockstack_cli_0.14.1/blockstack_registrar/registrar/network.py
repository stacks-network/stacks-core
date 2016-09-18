# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
"""

import json
import requests

from basicrpc import Proxy
from pybitcoin import hex_hash160
from blockstack_profiles import is_profile_in_legacy_format

from .config import BLOCKSTACKD_IP, BLOCKSTACKD_PORT
from .config import DHT_MIRROR_IP, DHT_MIRROR_PORT
from .config import RESOLVER_URL, RESOLVER_USERS_ENDPOINT
from .config import MAX_DHT_WRITE

from .utils import get_hash, config_log
from .utils import pretty_dump as pprint

log = config_log(__name__)

from blockstack_client.proxy import get_name_blockchain_record

# direct client, using Proxy
dht_client = Proxy(DHT_MIRROR_IP, DHT_MIRROR_PORT)


def get_bs_client():

    #return Proxy(BLOCKSTACKD_IP, BLOCKSTACKD_PORT)
    return bs_client


def get_dht_client():

    return Proxy(DHT_MIRROR_IP, DHT_MIRROR_PORT)


def get_blockchain_record(fqu):

    data = {}

    try:
        resp = get_name_blockchain_record(fqu)

    except Exception as e:
        data['error'] = e
        return data

    return resp


def get_dht_profile(fqu):

    resp = get_blockchain_record(fqu)

    if resp is None:
        return None

    try:
        profile_hash = resp['value_hash']
    except Exception as e:
        log.debug(e)
        return None

    profile = None

    dht_client = get_dht_client()

    try:
        resp = dht_client.get(profile_hash)
        profile = resp[0]['value']
    except Exception as e:
        log.debug("<key, value> not in DHT: (%s, %s)" % (fqu, profile_hash))

    return profile


def write_dht_profile(profile):

    resp = None
    dht_client = get_dht_client()

    if is_profile_in_legacy_format(profile):
        key = get_hash(profile)
        value = json.dumps(profile, sort_keys=True)
    else:
        key = hex_hash160(profile)
        value = profile

    if len(value) > MAX_DHT_WRITE:
        log.debug("DHT value too large: %s, %s" % (key, len(value)))
        return resp

    log.debug("DHT write (%s, %s)" % (key, value))

    try:
        resp = dht_client.set(key, value)
        log.debug(pprint(resp))
    except Exception as e:
        log.debug(e)

    return resp


def refresh_resolver(name):
    """ Given a @name force refresh the resolver entry

        This is meant to force update resolver cache,
        after updating an entry

        Should use fqu here instead of name.
        Resolver doesn't support that yet.
    """

    url = RESOLVER_URL + RESOLVER_USERS_ENDPOINT + name + '?refresh=True'

    try:
        resp = requests.get(url, verify=False)
    except:
        log.debug("Error refreshing resolver: %s")
        return False

    return True


def dontUseServer(blockstackd_server):
    """
        Return false if server fails any tests
    """

    from registrar.config import CONSENSUS_SERVERS
    from blockstack_client.proxy import BlockstackRPCClient as Proxy

    servers_to_check = CONSENSUS_SERVERS
    servers_to_check.append(blockstackd_server)

    consensus_hashes = []
    # initialize to a very large number
    last_block_everyone = 2000000000

    for server in servers_to_check:

        bs_client = Proxy(server, BLOCKSTACKD_PORT)

        last_block_seen = bs_client.getinfo()[0]['bitcoind_blocks']
        try:
            last_block_processed = bs_client.getinfo()[0]['last_block']
        except:
            last_block_processed = bs_client.getinfo()[0]['blocks']

        if (last_block_seen - last_block_processed) > 10:
            log.debug("Server %s, seems to be lagging: (%s, %s)"
                      % (server, last_block_seen, last_block_processed))

            return True

        if last_block_processed < last_block_everyone:
            last_block_everyone = last_block_processed

    for server in servers_to_check:

        bs_client = Proxy(server, BLOCKSTACKD_PORT)
        consensus_hash = bs_client.get_consensus_at(last_block_everyone)[0]
        print consensus_hash
        consensus_hashes.append(consensus_hash)

    check_hash = consensus_hashes[0]

    for stored_hash in consensus_hashes:

        if check_hash != stored_hash:
            log.debug('Mismatch in consensus hashes from %s' % servers_to_check)
            return True

    # can use server, if all tests pass
    return False
