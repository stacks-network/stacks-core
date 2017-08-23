#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016-2017 by Blockstack.org

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
import os
import sys
import time
import jsontokens
import urllib
import virtualchain
import posixpath
import uuid
import errno
import hashlib
import jsontokens
import collections
import threading
import functools
import traceback
import sqlite3

from keylib import *

import virtualchain
from virtualchain.lib.ecdsalib import *

from ..logger import get_logger
from ..proxy import get_default_proxy
from ..config import get_config, get_local_device_id
from ..constants import BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, DEFAULT_DEVICE_ID, CONFIG_PATH
from ..schemas import *
from ..storage import sign_data_payload, make_data_tombstone, make_fq_data_id, sign_data_tombstone, parse_data_tombstone, verify_data_tombstone, parse_fq_data_id, \
        hash_data_payload, sign_data_payload, serialize_mutable_data, get_storage_handlers, verify_data_payload, get_mutable_data, get_immutable_data, get_data_hash, \
        put_immutable_data, hash_zonefile

from ..user import is_user_zonefile, get_immutable_data_hashes, has_immutable_data, get_immutable_data_url, user_zonefile_set_data_pubkey, list_immutable_data_zonefile, \
        has_immutable_data_id, remove_immutable_data_zonefile, put_immutable_data_zonefile, has_immutable_data

log = get_logger('gaia-immutable')


def is_obsolete_zonefile(user_zonefile):
    return (
        blockstack_profiles.is_profile_in_legacy_format(user_zonefile) or
        not is_user_zonefile(user_zonefile)
    )


def get_immutable(name, data_hash, data_id=None, config_path=CONFIG_PATH, proxy=None):
    """
    get_immutable

    Fetch a piece of immutable data.  Use @data_hash to look it up
    in the user's zonefile, and then fetch and verify the data itself
    from the configured storage providers.

    Return {'data': the data, 'hash': hash} on success
    Return {'error': ...} on failure
    """

    proxy = get_default_proxy(config_path) if proxy is None else proxy

    user_zonefile = get_name_zonefile(name, proxy=proxy)
    if 'error' in user_zonefile:
        log.debug("Unable to load zone file for '{}': {}".format(name, user_zonefile['error']))
        return user_zonefile

    user_zonefile = user_zonefile['zonefile']

    if is_obsolete_zonefile(user_zonefile):
        # zonefile is really a legacy profile
        msg = 'Zone file is in a legacy format that does not support immutable data.'
        return {'error': msg}

    if data_id is not None:
        # look up hash by name
        hs = get_immutable_data_hashes(user_zonefile, data_id)
        if hs is None:
            return {'error': 'No such immutable datum'}

        if len(hs) > 1:
            # this tool doesn't allow this to happen (one ID matches
            # one hash), but that doesn't preclude the user from doing
            # this with other tools.
            if data_hash is not None and data_hash not in hs:
                return {'error': 'Data ID/hash mismatch: {} not in {} (possibly due to invalid zonefile)'.format(data_hash, hs)}
            else:
                msg = 'Multiple matches for "{}": {}'
                return {'error': msg.format(data_id, ','.join(h))}

        h = hs[0]
        if data_hash is not None:
            if h != data_hash:
                return {'error': 'Data ID/hash mismatch: {} != {}'.format(data_hash, h)}
        else:
            data_hash = h

    elif not has_immutable_data(user_zonefile, data_hash):
        return {'error': 'No such immutable datum'}

    data_url_hint = get_immutable_data_url(user_zonefile, data_hash)

    data = get_immutable_data(
        data_hash, blockchain_id=name, data_id=data_id, data_url=data_url_hint
    )

    if data is None:
        return {'error': 'No immutable data returned'}

    return {'data': data, 'hash': data_hash}


def get_immutable_by_name(name, data_id, proxy=None):
    """
    get_immutable_by_name

    Fetch a piece of immutable data, using a human-meaningful name.
    Look up the hash in the user's zonefile, and use it to fetch
    and verify the immutable data from the configured storage providers.

    Return {'data': the data, 'hash': hash} on success
    Return {'error': ...} on failure
    """
    return get_immutable(name, None, data_id=data_id, proxy=proxy)


def list_update_history(name, current_block=None, config_path=CONFIG_PATH, proxy=None):
    """
    list_update_history

    List all zonefile hashes of a name, in historic order.
    Return a list of hashes on success.
    Return {'error': ...} on failure
    """

    proxy = get_default_proxy(config_path) if proxy is None else proxy

    if current_block is None:
        try:
            info = getinfo(proxy=proxy)
            if 'last_block_processed' in info:
                current_block = int(info['last_block_processed']) + 1
            elif 'last_block' in info:
                current_block = int(info['last_block']) + 1
            else:
                raise Exception('Invalid getinfo reply')
        except Exception as e:
            log.error('Invalid getinfo reply')
            return {'error': 'Failed to contact Blockstack server'}

    name_history = get_name_blockchain_history( name, 0, current_block )
    if 'error' in name_history:
        log.error('Failed to get name history for {}: {}'.format(name, name_history['error']))
        return name_history

    all_update_hashes = []
    block_ids = name_history.keys()
    block_ids.sort()
    for block_id in block_ids:
        history_items = name_history[block_id]
        for history_item in history_items:
            value_hash = history_item.get('value_hash', None)
            if value_hash is None:
                continue

            if len(all_update_hashes) > 0 and all_update_hashes[-1] == value_hash:
                continue

            # changed
            all_update_hashes.append(value_hash)

    return all_update_hashes


def list_zonefile_history(name, current_block=None, proxy=None):
    """
    list_zonefile_history

    List all prior zonefiles of a name, in historic order.
    Return the list of zonefiles.  Each zonefile will be a dict with either the zonefile data,
    or a dict with only the key 'error' defined.  This method can successfully return
    some but not all zonefiles.
    """
    zonefile_hashes = list_update_history(
        name, current_block=current_block, proxy=proxy
    )

    zonefiles = []
    for zh in zonefile_hashes:
        zonefile = load_name_zonefile(name, zh, raw_zonefile=True)
        if zonefile is None:
            zonefile = {'error': 'Failed to load zonefile {}'.format(zh)}
        else:
            msg = 'Invalid zonefile type {}'.format(type(zonefile))
            assert isinstance(zonefile, (str, unicode)), msg

        zonefiles.append(zonefile)

    return zonefiles


def list_immutable_data_history(name, data_id, current_block=None, proxy=None):
    """
    list_immutable_data_history

    List all prior hashes of an immutable datum, given its unchanging ID.
    If the zonefile at a particular update is missing, the string "missing zonefile" will be
    appended in its place.  If the zonefile did not define data_id at that time,
    the string "data not defined" will be placed in the hash's place.

    Returns the list of hashes.
    If there are multiple matches for the data ID in a zonefile, then return the list of hashes for that zonefile.
    """
    zonefiles = list_zonefile_history(name, current_block=current_block, proxy=proxy)
    hashes = []
    for zf in zonefiles:
        if zf is None:
            # not found
            hashes.append('missing zonefile')
            continue

        if isinstance(zf, dict):
            # only happens on error
            if 'error' in zf and len(zf.keys()) == 1:
                # couldn't get it
                hashes.append('missing zonefile')
                continue

        # try to parse
        try:
            zf = blockstack_zones.parse_zone_file(zf)
            zf = dict(zf)  # force dict
        except Exception as e:
            if BLOCKSTACK_TEST is not None:
                log.exception(e)

            # not a standard zonefile
            log.debug('Skip non-standard zonefile')
            hashes.append('non-standard zonefile')
            continue

        if not is_user_zonefile(zf):
            # legacy profile
            hashes.append('missing zonefile')
            continue

        data_hashes = get_immutable_data_hashes(zf, data_id)
        if data_hashes is not None:
            hashes += data_hashes
            continue

        hashes.append('data not defined')

    return hashes


def put_immutable(blockchain_id, data_id, data_text, data_url=None, txid=None, proxy=None, wallet_keys=None, config_path=CONFIG_PATH):
    """
    put_immutable

    Given a blockchain ID, the data ID, and a JSON-ified chunk of data,
    put it into the user's zonefile.

    If the user's zonefile corresponds to a legacy profile, then automatically
    convert it into a mutable profile and a modern zonefile, and then proceed
    to add the data record.

    If @txid is given, then don't re-send the NAME_UPDATE.  Just try to store
    the data to the immutable storage providers (again).  This is to allow
    for retries in the case where the NAME_UPDATE went through but the
    storage providers did not receive data.

    On success, the new zonefile will be returned.  THE CALLER SHOULD PUSH THIS NEW ZONEFILE
    TO BLOCKSTACK SERVERS ONCE THE TRANSACTION CONFIRMS.  By default, it will be enqueued
    for replication.

    Return {'status': True, 'transaction_hash': txid, 'immutable_data_hash': data_hash, 'zonefile_hash': ..., 'zonefile': {...} } on success
    Return {'error': ...} on error
    """

    from backend.nameops import async_update

    proxy = get_default_proxy(config_path) if proxy is None else proxy

    # NOTE: only accept non-legacy zone files
    user_zonefile = get_name_zonefile(blockchain_id, proxy=proxy)
    if 'error' in user_zonefile:
        log.debug("Unable to load zone file for '{}': {}".format(blockchain_id, user_zonefile['error']))
        return user_zonefile

    user_zonefile = user_zonefile['zonefile']
    data_hash = get_data_hash(data_text)

    # insert into user zonefile, overwriting if need be
    if has_immutable_data_id(user_zonefile, data_id):
        log.debug('WARN: overwriting old "{}" with {}'.format(data_id, data_hash))
        old_hashes = get_immutable_data_hashes(user_zonefile, data_id)

        # NOTE: can be a list, if the name matches multiple hashes.
        # this tool doesn't do this, but it's still possible for the
        # user to use other tools to do this.
        for oh in old_hashes:
            rc = remove_immutable_data_zonefile(user_zonefile, oh)
            if not rc:
                return {'error': 'Failed to overwrite old immutable data'}

    rc = put_immutable_data_zonefile(
        user_zonefile, data_id, data_hash, data_url=data_url
    )

    if not rc:
        return {'error': 'Failed to insert immutable data into user zonefile'}

    zonefile_hash = hash_zonefile(user_zonefile)

    # update zonefile, if we haven't already
    if txid is None:
        payment_privkey_info = get_payment_privkey_info(
            wallet_keys=wallet_keys, config_path=proxy.conf['path']
        )

        owner_privkey_info = get_owner_privkey_info(
            wallet_keys=wallet_keys, config_path=proxy.conf['path']
        )

        user_zonefile_txt = blockstack_zones.make_zone_file(user_zonefile)

        update_result = async_update(
            blockchain_id, user_zonefile_txt, None, owner_privkey_info,
            payment_privkey_info, config_path=proxy.conf['path'],
            proxy=proxy, queue_path=proxy.conf['queue_path']
        )

        if 'error' in update_result:
            # failed to replicate user zonefile hash the caller should
            # simply try again, with the 'transaction_hash' given in
            # the result.
            return update_result

        txid = update_result['transaction_hash']

    result = {
        'immutable_data_hash': data_hash,
        'transaction_hash': txid,
        'zonefile_hash': zonefile_hash
    }

    # replicate immutable data
    rc = put_immutable_data(data_text, txid)
    if not rc:
        result['error'] = 'Failed to store immutable data'
        return result

    rc = store_name_zonefile(blockchain_id, user_zonefile, txid)
    if not rc:
        result['error'] = 'Failed to store zonefile'
        return result

    # success!
    result['status'] = True
    result['zonefile'] = user_zonefile

    return result


def delete_immutable(blockchain_id, data_key, data_id=None, proxy=None, txid=None, wallet_keys=None, config_path=CONFIG_PATH):
    """
    delete_immutable

    Remove an immutable datum from a blockchain ID's zonefile, given by @data_key.
    Return a dict with {'status': True, 'zonefile_hash': ..., 'zonefile': ...} on success
    Return a dict with {'error': ...} on failure
    """

    from backend.nameops import async_update

    proxy = get_default_proxy(config_path) if proxy is None else proxy

    user_zonefile = get_name_zonefile(blockchain_id, proxy=proxy, include_name_record=True)
    if 'error' in user_zonefile:
        log.debug("Unable to load zone file for '{}': {}".format(blockchain_id, user_zonefile['error']))
        return user_zonefile

    name_record = user_zonefile['name_record']
    del user_zonefile['name_record']
    user_zonefile = user_zonefile['zonefile']

    if is_obsolete_zonefile(user_zonefile):
        # zonefile is a legacy profile.  There is no immutable data
        log.info('Profile is in legacy format.  No immutable data.')
        return {'error': 'Non-standard or legacy zonefile'}

    if data_key is None:
        if data_id is None:
            return {'error': 'No data hash or data ID given'}

        # look up the key (or list of keys) shouldn't be a
        # list--this tool prevents that--but deal with it
        # nevertheless
        data_keys = get_immutable_data_hashes(user_zonefile, data_id)
        if data_keys is not None and len(data_keys) > 1:
            msg = 'Multiple hashes for "{}": {}'
            return {'error': msg.format(data_id, ','.join(data_key))}

        data_key = data_keys[0]
        if data_key is None:
            return {'error': 'No hash for "{}"'.format(data_id)}

    # already deleted?
    if not has_immutable_data(user_zonefile, data_key):
        return {'status': True}

    # remove
    remove_immutable_data_zonefile(user_zonefile, data_key)

    zonefile_hash = hash_zonefile(user_zonefile)

    if txid is None:
        # actually send the transaction
        payment_privkey_info = get_payment_privkey_info(
            wallet_keys=wallet_keys, config_path=proxy.conf['path']
        )

        owner_privkey_info = get_owner_privkey_info(
            wallet_keys=wallet_keys, config_path=proxy.conf['path']
        )

        user_zonefile_txt = blockstack_zones.make_zone_file(user_zonefile)

        update_result = async_update(
            blockchain_id, user_zonefile_txt, None, owner_privkey_info,
            payment_privkey_info, config_path=proxy.conf['path'],
            proxy=proxy, queue_path=proxy.conf['queue_path']
        )

        if 'error' in update_result:
            # failed to remove from zonefile
            return update_result

        txid = update_result['transaction_hash']

    result = {
        'zonefile_hash': zonefile_hash,
        'zonefile': user_zonefile,
        'transaction_hash': txid
    }

    # put new zonefile
    rc = store_name_zonefile(blockchain_id, user_zonefile, txid)
    if not rc:
        result['error'] = 'Failed to put new zonefile'
        return result

    # delete immutable data
    data_privkey = get_data_privkey_info(user_zonefile, wallet_keys=wallet_keys, config_path=config_path)
    if json_is_error(data_privkey):
        return {'error': data_privkey['error']}
    else:
        assert data_privkey is not None
        assert type(data_privkey) in [str, unicode]

    rc = delete_immutable_data(data_key, txid, data_privkey)
    if not rc:
        result['error'] = 'Failed to delete immutable data'
    else:
        result['status'] = True

    return result


def list_immutable_data(blockchain_id, proxy=None, config_path=CONFIG_PATH):
    """
    List the names and hashes of all immutable data in a user's zonefile.
    Returns {'data': [{'data_id': data_id, 'hash': hash}]} on success
    Returns {'error': ...} on error
    """
    proxy = get_default_proxy(config_path) if proxy is None else proxy

    user_zonefile = get_name_zonefile(blockchain_id, proxy=proxy)
    if 'error' in user_zonefile:
        log.debug("Unable to load zone file for '{}': {}".format(blockchain_id, user_zonefile['error']))
        return user_zonefile

    user_zonefile = user_zonefile['zonefile']

    if is_obsolete_zonefile(user_zonefile):
        # zonefile is really a legacy profile
        return {'data': []}

    names_and_hashes = list_immutable_data_zonefile(user_zonefile)
    listing = [{'data_id': nh[0], 'hash': nh[1]} for nh in names_and_hashes]

    return {'data': listing}


def set_data_pubkey(blockchain_id, data_pubkey, proxy=None, wallet_keys=None, txid=None, config_path=CONFIG_PATH):
    """
    Set the data public key for a blockchain ID
    Overwrites the public key that is present (if given at all).

    WARN: you will need to re-sign your profile after you do this; otherwise
    no one will be able to use your current zonefile contents (with your new
    key) to verify their authenticity.

    Return {'status': True, 'transaction_hash': ..., 'zonefile_hash': ...} on success
    Return {'error': ...} on error
    """

    from backend.nameops import async_update

    legacy = False
    proxy = get_default_proxy(config_path) if proxy is None else proxy

    # NOTE: only accept non-legacy zone files
    user_zonefile = get_name_zonefile(blockchain_id, proxy=proxy)
    if 'error' in user_zonefile:
        log.debug("Unable to load zone file for '{}': {}".format(blockchain_id, user_zonefile['error']))
        return user_zonefile

    user_zonefile = user_zonefile['zonefile']

    user_zonefile = user_zonefile_set_data_pubkey(user_zonefile, data_pubkey)
    zonefile_hash = hash_zonefile(user_zonefile)

    # update zonefile, if we haven't already
    if txid is None:
        payment_privkey_info = get_payment_privkey_info(
            wallet_keys=wallet_keys, config_path=proxy.conf['path']
        )

        owner_privkey_info = get_owner_privkey_info(
            wallet_keys=wallet_keys, config_path=proxy.conf['path']
        )

        user_zonefile_txt = blockstack_zones.make_zone_file(user_zonefile)

        update_result = async_update(
            blockchain_id, user_zonefile_txt, None, owner_privkey_info,
            payment_privkey_info, config_path=proxy.conf['path'],
            proxy=proxy, queue_path=proxy.conf['queue_path']
        )

        if 'error' in update_result:
            # failed to replicate user zonefile hash the caller should
            # simply try again, with the 'transaction_hash' given in
            # the result.
            return update_result

        txid = update_result['transaction_hash']

    result = {
        'transaction_hash': txid,
        'zonefile_hash': zonefile_hash,
        'zonefile': user_zonefile
    }

    # replicate zonefile
    rc = store_name_zonefile(blockchain_id, user_zonefile, txid)
    if not rc:
        result['error'] = 'Failed to store zonefile'
        return result

    # success!
    result['status'] = True
    return result

