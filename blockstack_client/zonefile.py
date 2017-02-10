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

import json
import time
import copy
import blockstack_profiles
import blockstack_zones
import base64
import socket
import virtualchain
from keylib import ECPrivateKey
import jsonschema
from jsonschema import ValidationError

from .proxy import *
import storage
import user as user_db

from .config import get_logger, get_config
from .constants import USER_ZONEFILE_TTL, CONFIG_PATH, BLOCKSTACK_TEST, BLOCKSTACK_DEBUG

log = get_logger()


def url_to_uri_record(url, datum_name=None):
    """
    Convert a URL into a DNS URI record
    """
    try:
        scheme, _ = url.split('://')
    except ValueError:
        msg = 'BUG: invalid storage driver implementation: no scheme given in "{}"'
        raise Exception(msg.format(url))

    scheme = scheme.lower()
    proto = None

    # tcp or udp?
    try:
        port = socket.getservbyname(scheme, 'tcp')
        proto = 'tcp'
    except socket.error:
        try:
            port = socket.getservbyname(scheme, 'udp')
            proto = 'udp'
        except socket.error:
            # this is weird--maybe it's embedded in the scheme?
            try:
                assert len(scheme.split('+')) == 2
                scheme, proto = scheme.split('+')
            except (AssertionError, ValueError):
                msg = 'WARN: Scheme "{}" has no known transport protocol'
                log.debug(msg.format(scheme))

    name = None
    if proto is not None:
        name = '_{}._{}'.format(scheme, proto)
    else:
        name = '_{}'.format(scheme)

    if datum_name is not None:
        name = '{}.{}'.format(name, str(datum_name))

    ret = {
        'name': name,
        'priority': 10,
        'weight': 1,
        'target': url,
    }

    return ret


def make_empty_zonefile(username, data_pubkey, urls=None):
    """
    Create an empty user record from a name record.
    """

    # make a URI record for every mutable storage provider
    urls = storage.make_mutable_data_urls(username) if urls is None else urls

    assert urls, 'No profile URLs'

    user = {
        'txt': [],
        'uri': [],
        '$origin': username,
        '$ttl': config.USER_ZONEFILE_TTL,
    }

    if data_pubkey is not None:
        user.setdefault('txt', [])

        pubkey = str(data_pubkey)
        name_txt = {'name': 'pubkey', 'txt': 'pubkey:data:{}'.format(pubkey)}

        user['txt'].append(name_txt)

    for url in urls:
        urirec = url_to_uri_record(url)
        user['uri'].append(urirec)

    return user


def decode_name_zonefile(name, zonefile_txt, allow_legacy=False):
    """
    Decode a serialized zonefile into a JSON dict.
    If allow_legacy is True, then support legacy zone file formats (including Onename profiles)
    Otherwise, the data must actually be a Blockstack zone file.
        * If the zonefile does not have $ORIGIN, or if $ORIGIN does not match the name,
          then this fails.
    Return None on error
    """

    user_zonefile = None
    try:
        # by default, it's a zonefile-formatted text file
        user_zonefile_defaultdict = blockstack_zones.parse_zone_file(zonefile_txt)
        assert user_db.is_user_zonefile(user_zonefile_defaultdict), 'Not a user zonefile'

        # force dict
        user_zonefile = dict(user_zonefile_defaultdict)

    except (IndexError, ValueError, blockstack_zones.InvalidLineException):
        if not allow_legacy:
            return {'error': 'Legacy zone file'}

        # might be legacy profile
        log.debug('WARN: failed to parse user zonefile; trying to import as legacy')
        try:
            user_zonefile = json.loads(zonefile_txt)
            if not isinstance(user_zonefile, dict):
                log.debug('Not a legacy user zonefile')
                return None

        except Exception as e:
            if BLOCKSTACK_DEBUG is not None:
                log.exception(e)
            log.error('Failed to parse non-standard zonefile')
            return None

    except Exception as e:
        log.exception(e)
        log.error('Failed to parse zonefile')
        return None

    if user_zonefile is None:
        return None 

    if not allow_legacy:
        # additional checks
        if not user_zonefile.has_key('$origin'):
            log.debug("Zonefile has no $ORIGIN")
            return None

        if user_zonefile['$origin'] != name:
            log.debug("Name/zonefile mismatch: $ORIGIN = {}, name = {}".format(user_zonefile['$origin'], name))
            return None

    return user_zonefile


def load_name_zonefile(name, expected_zonefile_hash, storage_drivers=None, raw_zonefile=False, allow_legacy=False, proxy=None ):
    """
    Fetch and load a user zonefile from the storage implementation with the given hex string hash,
    The user zonefile hash should have been loaded from the blockchain, and thereby be the
    authentic hash.

    If raw_zonefile is True, then return the raw zonefile data.  Don't parse it.
    If however, raw_zonefile is False, the zonefile will be parsed.  If name is given, the $ORIGIN will be checked.

    Return the user zonefile (as a dict) on success
    Return None on error
    """

    proxy = get_default_proxy() if proxy is None else proxy
    conf = proxy.conf
    
    assert 'server' in conf, json.dumps(conf, indent=4, sort_keys=True)
    assert 'port' in conf, json.dumps(conf, indent=4, sort_keys=True)

    atlas_host = conf['server']
    atlas_port = conf['port']
    hostport = '{}:{}'.format( atlas_host, atlas_port )

    zonefile_txt = None
    expected_zonefile_hash = str(expected_zonefile_hash)

    # try atlas node first 
    res = get_zonefiles( hostport, [expected_zonefile_hash], proxy=proxy )
    if 'error' in res or expected_zonefile_hash not in res['zonefiles'].keys():
        # fall back to storage drivers if atlas node didn't have it
        zonefile_txt = storage.get_immutable_data(
                expected_zonefile_hash, hash_func=storage.get_zonefile_data_hash, 
                fqu=name, zonefile=True, drivers=storage_drivers
        )

        if zonefile_txt is None:
            log.error('Failed to load user zonefile "{}"'.format(expected_zonefile_hash))
            return None

    else:
        # extract 
        log.debug('Fetched {} from Atlas peer {}'.format(expected_zonefile_hash, hostport))
        zonefile_txt = res['zonefiles'][expected_zonefile_hash]

    if raw_zonefile:
        msg = 'Driver did not return a serialized zonefile'
        try:
            assert isinstance(zonefile_txt, (str, unicode)), msg
        except AssertionError as ae:
            if BLOCKSTACK_TEST is not None:
                log.exception(ae)

            log.error(msg)
            return None

        return zonefile_txt

    parsed_zonefile = decode_name_zonefile(name, zonefile_txt, allow_legacy=allow_legacy)
    return parsed_zonefile


def load_data_pubkey_for_new_zonefile(wallet_keys={}, config_path=CONFIG_PATH):
    """
    Find the right public key to use for data when creating a new zonefile.
    If the wallet has a data keypair defined, use that.
    Otherwise, fall back to the owner public key
    """
    data_pubkey = None

    data_privkey = wallet_keys.get('data_privkey', None)
    if data_privkey is not None:
        data_pubkey = ECPrivateKey(data_privkey).public_key().to_hex()
        return data_pubkey

    data_pubkey = wallet_keys.get('data_pubkey', None)
    return data_pubkey


def get_name_zonefile(name, storage_drivers=None, proxy=None,
                      name_record=None, include_name_record=False,
                      raw_zonefile=False, include_raw_zonefile=False, allow_legacy=False):
    """
    Given a name, go fetch its zonefile.
    Verifies that the hash on the blockchain matches the zonefile.

    Returns {'status': True, 'zonefile': zonefile dict} on success.
    Returns a dict with "error" defined and a message on failure to load.
    Return None if there is no zonefile (i.e. the hash is null)

    if 'include_name_record' is true, then zonefile will contain
    an extra key called 'name_record' that includes the blockchain name record.

    If 'raw_zonefile' is true, no attempt to parse the zonefile will be made.
    The raw zonefile will be returned in 'zonefile'.  allow_legacy is ignored.
    
    If 'allow_legacy' is true, then support returning older supported versions of the zone file
    (including old Onename profiles).  Otherwise, this method fails.
    """

    proxy = get_default_proxy() if proxy is None else proxy

    # find name record first
    if name_record is None:
        name_record = get_name_blockchain_record(name, proxy=proxy)

    if name_record is None or not name_record:
        # failed to look up or zero-length name
        return {'error': 'No such name'}

    # sanity check
    if 'value_hash' not in name_record:
        return {'error': 'Name has no user record hash defined'}

    value_hash = name_record['value_hash']

    # is there a user record loaded?
    if value_hash in [None, 'null', '']:
        log.error("Failed to load zone file: no value hash")
        return {'error': 'No zone file hash for name'}

    user_zonefile_hash = value_hash
    raw_zonefile_data = None
    user_zonefile_data = None

    if raw_zonefile or include_raw_zonefile:
        raw_zonefile_data = load_name_zonefile(
            name, user_zonefile_hash, storage_drivers=storage_drivers,
            raw_zonefile=True, proxy=proxy, allow_legacy=allow_legacy
        )

        if raw_zonefile_data is None:
            return {'error': 'Failed to load raw name zonefile'}

        if raw_zonefile:
            user_zonefile_data = raw_zonefile_data

        else:
            # further decode
            user_zonefile_data = decode_name_zonefile(name, raw_zonefile_data, allow_legacy=allow_legacy)
            if user_zonefile_data is None:
                return {'error': 'Failed to decode name zonefile'}

    else:
        user_zonefile_data = load_name_zonefile(
            name, user_zonefile_hash, storage_drivers=storage_drivers, proxy=proxy, allow_legacy=allow_legacy
        )
        if user_zonefile_data is None:
            return {'error': 'Failed to load or decode name zonefile'}

    ret = {
        'zonefile': user_zonefile_data
    }

    if include_name_record:
        ret['name_record'] = name_record

    if include_raw_zonefile:
        ret['raw_zonefile'] = raw_zonefile_data

    return ret


def store_name_zonefile_data(name, user_zonefile_txt, txid, storage_drivers=None):
    """
    Store a serialized zonefile to immutable storage providers, synchronously.
    This is only necessary if we've added/changed/removed immutable data.

    Return (True, hash(user zonefile)) on success
    Return (False, None) on failure.
    """

    storage_drivers = [] if storage_drivers is None else storage_drivers

    data_hash = storage.get_zonefile_data_hash(user_zonefile_txt)

    result = storage.put_immutable_data(
        None, txid, data_hash=data_hash,
        data_text=user_zonefile_txt, required=storage_drivers
    )

    rc = bool(result)

    return rc, data_hash


def store_name_zonefile(name, user_zonefile, txid, storage_drivers=None):
    """
    Store JSON user zonefile data to the immutable storage providers, synchronously.
    This is only necessary if we've added/changed/removed immutable data.

    Return (True, hash(user zonefile)) on success
    Return (False, None) on failure
    """

    storage_drivers = [] if storage_drivers is None else storage_drivers

    assert not blockstack_profiles.is_profile_in_legacy_format(user_zonefile), 'User zonefile is a legacy profile'
    assert user_db.is_user_zonefile(user_zonefile), 'Not a user zonefile (maybe a custom legacy profile?)'

    # serialize and send off
    user_zonefile_txt = blockstack_zones.make_zone_file(user_zonefile, origin=name, ttl=USER_ZONEFILE_TTL)

    return store_name_zonefile_data(name, user_zonefile_txt, txid, storage_drivers=storage_drivers)


def remove_name_zonefile(user, txid):
    """
    Delete JSON user zonefile data from immutable storage providers, synchronously.

    Return (True, hash(user)) on success
    Return (False, hash(user)) on error
    """

    # serialize
    user_json = json.dumps(user, sort_keys=True)
    data_hash = storage.get_data_hash(user_json)
    result = storage.delete_immutable_data(data_hash, txid)

    rc = bool(result)

    return rc, data_hash


def zonefile_data_publish(fqu, zonefile_txt, server_list, wallet_keys=None):
    """
    Replicate a zonefile to as many blockstack servers as possible.
    @server_list is a list of (host, port) tuple
    Return {'status': True, 'servers': ...} on success, if we succeeded to replicate at least once.
        'servers' will be a list of (host, port) tuples
    Return {'error': ...} if we failed on all accounts.
    """
    successful_servers = []
    for server_host, server_port in server_list:
        try:
            log.debug('Replicate zonefile to {}:{}'.format(server_host, server_port))
            hostport = '{}:{}'.format(server_host, server_port)

            res = put_zonefiles(hostport, [base64.b64encode(zonefile_txt)])
            if 'error' in res or len(res['saved']) == 0 or res['saved'][0] != 1:
                if not res.has_key('error'):
                    res['error'] = 'server did not save'
                
                log.debug("server returned {}".format(res))
                msg = 'Failed to publish zonefile to {}:{}: {}'
                log.error(msg.format(server_host, server_port, res['error']))
                continue

            log.debug('Replicated zonefile to {}:{}'.format(server_host, server_port))
            successful_servers.append((server_host, server_port))
        except Exception as e:
            log.exception(e)
            log.error('Failed to publish zonefile to {}:{}'.format(server_host, server_port))
            continue

    if successful_servers:
        return {'status': True, 'servers': successful_servers}

    return {'error': 'Failed to publish zonefile to all backend providers'}


def zonefile_data_replicate(fqu, zonefile_data, tx_hash, server_list, config_path=CONFIG_PATH, storage_drivers=None):
    """
    Replicate zonefile data both to a list of blockstack servers,
    as well as to the user's storage drivers.

    Return {'status': True, 'servers': successful server list} on success
    Return {'error': ...}
    """

    conf = get_config(config_path)

    # find required storage drivers
    required_storage_drivers = None
    if storage_drivers is not None:
        required_storage_drivers = storage_drivers
    else:
        required_storage_drivers = conf.get('storage_drivers_required_write', None)
        if required_storage_drivers is not None:
            required_storage_drivers = required_storage_drivers.split(',')
        else:
            required_storage_drivers = conf.get('storage_drivers', '').split(',')

    assert required_storage_drivers, 'No zonefile storage drivers specified'

    # replicate to our own storage providers
    rc = store_name_zonefile_data(
        fqu, zonefile_data, tx_hash, storage_drivers=required_storage_drivers
    )

    if not rc:
        log.info('Failed to replicate zonefile for {} to {}'.format(fqu))
        return {'error': 'Failed to store user zonefile'}

    # replicate to blockstack servers
    res = zonefile_data_publish(fqu, zonefile_data, server_list)
    if 'error' in res:
        return res

    return {'status': True, 'servers': res['servers']}
