"""
    Registrar
    ~~~~~

    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

This file is part of Registrar.

    Registrar is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Registrar is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Registrar. If not, see <http://www.gnu.org/licenses/>.
"""

import json
import requests

from basicrpc import Proxy
from blockstore_client.client import BlockstoreRPCClient

from .config import BLOCKSTORED_IP, BLOCKSTORED_PORT
from .config import DHT_MIRROR_IP, DHT_MIRROR_PORT
from .config import RESOLVER_URL, RESOLVER_USERS_ENDPOINT
from .config import MAX_DHT_WRITE

from .utils import get_hash, config_log
from .utils import pretty_dump as pprint

log = config_log(__name__)

# direct client, using Proxy
#bs_client = Proxy(BLOCKSTORED_IP, BLOCKSTORED_PORT)
dht_client = Proxy(DHT_MIRROR_IP, DHT_MIRROR_PORT)


def get_bs_client():

    #return Proxy(BLOCKSTORED_IP, BLOCKSTORED_PORT)
    return bs_client


def get_dht_client():

    return Proxy(DHT_MIRROR_IP, DHT_MIRROR_PORT)


def get_blockchain_record(fqu):

    # hack to ensure local, until we update client
    from blockstore_client import client as bs_client
    # start session using blockstore_client
    bs_client.session(server_host=BLOCKSTORED_IP, server_port=BLOCKSTORED_PORT,
                      set_global=True)

    data = {}

    try:
        resp = bs_client.get_name_blockchain_record(fqu)
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

    key = get_hash(profile)
    value = json.dumps(profile, sort_keys=True)

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


def dontUseServer(blockstored_server):
    """
        Return false if server fails any tests
    """

    from registrar.config import CONSENSUS_SERVERS
    from basicrpc import Proxy

    servers_to_check = CONSENSUS_SERVERS
    servers_to_check.append(blockstored_server)

    consensus_hashes = []
    # initialize to a very large number
    last_block_everyone = 2000000000

    for server in servers_to_check:

        bs_client = Proxy(server, BLOCKSTORED_PORT)

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

        bs_client = Proxy(server, BLOCKSTORED_PORT)
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
