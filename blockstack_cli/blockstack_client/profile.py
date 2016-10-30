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

import argparse
import sys
import json
import traceback
import types
import socket
import uuid
import os
import importlib
import pprint
import random
import time
import copy
import blockstack_profiles
import blockstack_zones 
import urllib
import base64
import virtualchain
from keylib import ECPrivateKey

from .proxy import *
from .keys import get_data_or_owner_privkey
from blockstack_client import storage
from blockstack_client import user as user_db

from storage import hash_zonefile
import pybitcoin
import bitcoin
import binascii
from utilitybelt import is_hex

from config import get_logger, DEBUG, MAX_RPC_LEN, find_missing, BLOCKSTACKD_SERVER, \
    BLOCKSTACKD_PORT, BLOCKSTACK_METADATA_DIR, BLOCKSTACK_DEFAULT_STORAGE_DRIVERS, \
    FIRST_BLOCK_MAINNET, NAME_OPCODES, OPFIELDS, CONFIG_DIR, SPV_HEADERS_PATH, BLOCKCHAIN_ID_MAGIC, \
    NAME_PREORDER, NAME_REGISTRATION, NAME_UPDATE, NAME_TRANSFER, NAMESPACE_PREORDER, NAME_IMPORT, \
    USER_ZONEFILE_TTL, CONFIG_PATH, get_config

log = get_logger()


def set_profile_timestamp( profile, now=None ):
    """
    Set the profile's timestamp to now
    """
    if now is None:
        now = time.time()

    profile['timestamp'] = now 
    return profile


def get_profile_timestamp( profile ):
    """
    Get profile timestamp
    """
    return profile['timestamp']


def decode_name_zonefile(zonefile_txt):
    """
    Decode a serialized zonefile into a JSON dict
    Return None on error
    """
    
    user_zonefile = None
    try:
        # by default, it's a zonefile-formatted text file
        user_zonefile_defaultdict = blockstack_zones.parse_zone_file( zonefile_txt )
        assert user_db.is_user_zonefile( user_zonefile_defaultdict ), "Not a user zonefile"

        # force dict
        user_zonefile = dict(user_zonefile_defaultdict)

    except (IndexError, ValueError, blockstack_zones.InvalidLineException):
        # might be legacy profile
        log.debug("WARN: failed to parse user zonefile; trying to import as legacy")
        try:
            user_zonefile = json.loads(zonefile_txt)
            if type(user_zonefile) != dict:
                log.debug("Not a legacy user zonefile")
                return None

        except Exception, e:
            if os.environ.get("BLOCKSTACK_DEBUG", None) == "1":
                log.exception(e)

            log.error("Failed to parse non-standard zonefile")
            return None
        
    except Exception, e:
        log.exception(e)
        log.error("Failed to parse zonefile %s")
        return None 

    return user_zonefile


def load_name_zonefile(name, expected_zonefile_hash, storage_drivers=None, raw_zonefile=False, proxy=None ):
    """
    Fetch and load a user zonefile from the storage implementation with the given hex string hash,
    The user zonefile hash should have been loaded from the blockchain, and thereby be the
    authentic hash.

    If raw_zonefile is True, then return the raw zonefile data.  Don't parse it.

    Return the user zonefile (as a dict) on success
    Return None on error
    """

    if proxy is None:
        proxy = get_default_proxy()

    conf = proxy.conf 
    atlas_host = conf['server']
    atlas_port = conf['port']
    hostport = '{}:{}'.format( atlas_host, atlas_port )

    zonefile_txt = None

    # try atlas node first 
    res = get_zonefiles( hostport, [expected_zonefile_hash], proxy=proxy )
    if 'error' in res:
        # fall back to storage drivers if atlas node didn't have it
        zonefile_txt = storage.get_immutable_data(expected_zonefile_hash, hash_func=storage.get_zonefile_data_hash, fqu=name, zonefile=True, deserialize=False, drivers=storage_drivers)
        if zonefile_txt is None:
            log.error("Failed to load user zonefile '%s'" % expected_zonefile_hash)
            return None

    else:
        # extract 
        log.debug('Fetched {} from Atlas peer {}'.format(expected_zonefile_hash, hostport))
        zonefile_txt = res['zonefiles'][expected_zonefile_hash]

    if raw_zonefile:
        try:
            assert type(zonefile_txt) in [str, unicode], "Driver did not return a serialized zonefile"
        except AssertionError as ae:
            if os.environ.get("BLOCKSTACK_TEST", None) == "1":
                log.exception(ae)

            log.error("Driver did not return a serialized zonefile")
            return None

        return zonefile_txt

    return decode_name_zonefile( zonefile_txt )


def load_legacy_user_profile( name, expected_hash ):
    """
    Load a legacy user profile, and convert it into
    the new zonefile-esque profile format that can 
    be serialized into a JWT.

    Verify that the profile hashses to the above expected hash
    """

    # fetch... 
    storage_host = "onename.com"
    assert name.endswith(".id")

    name_without_namespace = ".".join( name.split(".")[:-1] )
    storage_path = "/%s.json" % name_without_namespace 

    try:
        req = httplib.HTTPConnection( storage_host )
        resp = req.request( "GET", storage_path )
        data = resp.read()
    except Exception, e:
        log.error("Failed to fetch http://%s/%s: %s" % (storage_host, storage_path, e))
        return None 

    try:
        data_json = json.loads(data)
    except Exception, e:
        log.error("Unparseable profile data")
        return None

    data_hash = storage.get_blockchain_compat_hash( data_json )
    if expected_hash != data_hash:
        log.error("Hash mismatch: expected %s, got %s" % (expected_hash, data_hash))
        return None

    assert blockstack_profiles.is_profile_in_legacy_format( data_json )
    new_profile = blockstack_profiles.get_person_from_legacy_format( data_json )
    return new_profile


def load_name_profile(name, user_zonefile, data_address, owner_address, use_zonefile_urls=True, storage_drivers=None, decode=True):
    """
    Fetch and load a user profile, given the user zonefile.
    Try to verify using the public key in the zonefile (if one
    is present), and fall back to the user-address if need be
    (it should be the hash of the profile JWT's public key).

    Return the user profile on success (either as a dict, or as a string if decode=False)
    Return None on error
    """
    # get user's data public key
    try:
        user_data_pubkey = user_db.user_zonefile_data_pubkey( user_zonefile )
    except ValueError, v:
        # user decided to put multiple keys under the same name into the zonefile.
        # so don't use them.
        log.exception(v)
        user_data_pubkey = None 

    if user_data_pubkey is None and data_address is None and owner_address is None:
        raise Exception("Missing user data public key and address; cannot verify profile")

    if user_data_pubkey is None:
        log.warn("No data public key set; falling back to hash of data and/or owner public key for profile authentication")

    # get user's data public key from the zonefile
    urls = None
    if use_zonefile_urls:
        urls = user_db.user_zonefile_urls( user_zonefile )

    user_profile = storage.get_mutable_data( name, user_data_pubkey, data_address=data_address, owner_address=owner_address, urls=urls, drivers=storage_drivers, decode=decode )
    return user_profile


def load_data_pubkey_for_new_zonefile( wallet_keys={}, config_path=CONFIG_PATH ):
    """
    Find the right public key to use for data when creating a new zonefile.
    If the wallet has a data keypair defined, use that.
    Otherwise, fall back to the owner public key
    """
    data_pubkey = None
    if 'data_privkey' in wallet_keys and wallet_keys['data_privkey'] is not None:
        data_pubkey = ECPrivateKey(wallet_keys['data_privkey']).public_key().to_hex()
    elif 'data_pubkey' in wallet_keys:
        data_pubkey = wallet_keys['data_pubkey']

    return data_pubkey


def profile_update( name, user_zonefile, new_profile, owner_address, proxy=None, wallet_keys=None, required_drivers=None ):
    """
    Set the new profile data.  CLIENTS SHOULD NOT CALL THIS METHOD DIRECTLY.
    Return {'status: True} on success, as well as {'transaction_hash': hash} if we updated on the blockchain.
    Return {'error': ...} on failure.
    """
    
    ret = {}
    if proxy is None:
        proxy = get_default_proxy()

    config = proxy.conf

    required_storage_drivers = None
    if required_drivers is None:
        required_storage_drivers = config.get('storage_drivers_required_write', None)
        if required_storage_drivers is None:
            required_storage_drivers = config.get("storage_drivers", "").split(",")
        else:
            required_storage_drivers = required_storage_drivers.split(",")
    else:
        required_storage_drivers = required_drivers

    # update the profile with the new zonefile
    data_privkey_res = get_data_or_owner_privkey( user_zonefile, owner_address, wallet_keys=wallet_keys, config_path=proxy.conf['path'] )
    if 'error' in data_privkey_res:
        return {'error': data_privkey_res['error']}
    else:
        data_privkey = data_privkey_res['privatekey']
        assert data_privkey is not None

    profile_payload = copy.deepcopy(new_profile)
    profile_payload = set_profile_timestamp( profile_payload )

    log.debug("Save updated profile for '%s' to %s at %s" % (name, ",".join(required_storage_drivers), get_profile_timestamp(profile_payload)))
    rc = storage.put_mutable_data( name, profile_payload, data_privkey, required=required_storage_drivers )
    if not rc:
        ret['error'] = 'Failed to update profile'
        return ret

    else:
        ret['status'] = True

    return ret


def get_name_zonefile( name, storage_drivers=None, create_if_absent=False, proxy=None, wallet_keys=None, name_record=None, include_name_record=False, raw_zonefile=False, include_raw_zonefile=False ):
    """
    Given the name of the user, go fetch its zonefile.
    Verifies that the hash on the blockchain matches the zonefile.

    Returns {'status': True, 'zonefile': zonefile dict} on success.
    Returns a dict with "error" defined and a message on failure to load.
    Return None if there is no zonefile (i.e. the hash is null)

    if 'include_name_record' is true, then zonefile will contain
    an extra key called 'name_record' that includes the blockchain name record.

    If 'raw_zonefile' is true, no attempt to parse the zonefile will be made.
    The raw zonefile will be returned in 'zonefile'.

    @wallet_keys does not need to be given, unles you're creating a new zonefile (with create_if_absent).
    Even then, only the *public* data key needs to be set.
    """

    if proxy is None:
        proxy = get_default_proxy()

    # find name record first
    if name_record is None:
        name_record = get_name_blockchain_record(name, proxy=proxy)

    if name_record is None:
        # failed to look up
        return {'error': "No such name"}

    if len(name_record) == 0:
        return {"error": "No such name"}

    # sanity check
    if 'value_hash' not in name_record:
        return {"error": "Name has no user record hash defined"}

    value_hash = name_record['value_hash']

    # is there a user record loaded?
    if value_hash in [None, "null", ""]:

        # no user data
        if not create_if_absent:
            return None

        else:
            # make an empty zonefile and return that
            # get user's data public key
            public_key = load_data_pubkey_for_new_zonefile( wallet_keys=wallet_keys, config_path=proxy.conf['path'] )
            user_resp = user_db.make_empty_user_zonefile(name, public_key)

            if include_name_record:
                user_resp['name_record'] = name_record

            return user_resp

    user_zonefile_hash = value_hash
    raw_zonefile_data = None
    user_zonefile_data = None

    if raw_zonefile or include_raw_zonefile:
        raw_zonefile_data = load_name_zonefile(name, user_zonefile_hash, storage_drivers=storage_drivers, raw_zonefile=True, proxy=proxy )
        if raw_zonefile_data is None:
            return {'error': 'Failed to load raw user zonefile'}

        if raw_zonefile:
            user_zonefile_data = raw_zonefile_data

        else:
            # further decode
            user_zonefile_data = decode_name_zonefile(raw_zonefile_data)
            if user_zonefile_data is None:
                return {"error": "Failed to decode user zonefile"}

    else:
        user_zonefile_data = load_name_zonefile(name, user_zonefile_hash, storage_drivers=storage_drivers, proxy=proxy )
        if user_zonefile_data is None:
            return {'error': 'Failed to load or decode user zonefile'}

    ret = {
        "zonefile": user_zonefile_data
    }

    if include_name_record:
        ret['name_record'] = name_record

    if include_raw_zonefile:
        ret['raw_zonefile'] = raw_zonefile_data

    return ret
    

def get_name_profile(name, zonefile_storage_drivers=None,
                           profile_storage_drivers=None,
                           create_if_absent=False,
                           proxy=None,
                           user_zonefile=None,
                           name_record=None,
                           include_name_record=False,
                           include_raw_zonefile=False,
                           use_zonefile_urls=True,
                           decode_profile=True ):

    """
    Given the name of the user, look up the user's record hash,
    and then get the record itself from storage.

    If the user's zonefile is really a legacy profile, then 
    the profile will be the converted legacy profile.  The
    returned zonefile will still be a legacy profile, however.
    The caller can check this and perform the conversion automatically.

    Returns (profile, zonefile) on success.  If include_name_record is True, then zonefile['name_record'] will be defined and will contain the user's blockchain information
    Returns (None, {'error': ...}) on failure
    """

    if proxy is None:
        proxy = get_default_proxy()
 
    raw_zonefile = None

    if user_zonefile is None:
        user_zonefile = get_name_zonefile( name, create_if_absent=create_if_absent, proxy=proxy, name_record=name_record, include_name_record=True, storage_drivers=zonefile_storage_drivers, include_raw_zonefile=include_raw_zonefile )
        if user_zonefile is None:
            return (None, {'error': 'No user zonefile'})

        if 'error' in user_zonefile:
            return (None, user_zonefile)

        name_record = user_zonefile['name_record']
        del user_zonefile['name_record']

        raw_zonefile = None
        if include_raw_zonefile:
            raw_zonefile = user_zonefile['raw_zonefile']
            del user_zonefile['raw_zonefile']

        user_zonefile = user_zonefile['zonefile']

    # is this really a legacy profile?
    if blockstack_profiles.is_profile_in_legacy_format( user_zonefile ):
        # convert it
        log.debug("Converting legacy profile to modern profile")
        user_profile = blockstack_profiles.get_person_from_legacy_format( user_zonefile )
     
    elif not user_db.is_user_zonefile( user_zonefile ):
        # not a legacy profile, but a custom profile
        log.debug("Using custom legacy profile")
        user_profile = copy.deepcopy(user_zonefile)

    else:
        # get user's data public key
        user_address = None
        old_address = None

        try:
            user_data_pubkey = user_db.user_zonefile_data_pubkey( user_zonefile )
            if user_data_pubkey is not None:
                user_data_pubkey = str(user_data_pubkey)
                user_address = virtualchain.BitcoinPublicKey(user_data_pubkey).address()

        except ValueError:
            # user decided to put multiple keys under the same name into the zonefile.
            # so don't use them.
            user_data_pubkey = None 

        # convert to address
        if name_record is None:
            name_record = proxy.get_name_blockchain_record( name )
            if name_record is None or 'error' in name_record:
                log.error("Failed to look up name record for '%s'" % name)
                return (None, {'error': 'Failed to look up name record'})

        old_address = name_record['address']
        if user_address is None:
            # cut to the chase
            user_address = old_address

        user_profile = load_name_profile( name, user_zonefile, user_address, old_address, use_zonefile_urls=use_zonefile_urls, storage_drivers=profile_storage_drivers, decode=decode_profile )
        if user_profile is None or (type(user_profile) not in [str, unicode] and 'error' in user_profile):

            if user_profile is None:
                log.debug("WARN: no user profile for %s" % name)
            else:
                log.debug("WARN: failed to load profile for %s: %s" % (name, user_profile['error']))

            if create_if_absent:
                user_profile = user_db.make_empty_user_profile()
            else:
                return (None, {'error': 'Failed to load user profile'})

    # finally, if the caller asked for the name record, and we didn't get a chance to look it up,
    # then go get it.
    if include_name_record:
        if name_record is None:
            name_record = proxy.get_name_blockchain_record( name )
            if name_record is None or 'error' in name_record:
                log.error("Failed to look up name record for '%s'" % name)
                return (None, {'error': 'Failed to look up name record'})

        user_zonefile['name_record'] = name_record

    if include_raw_zonefile:
        if raw_zonefile is not None:
            user_zonefile['raw_zonefile'] = raw_zonefile

    return (user_profile, user_zonefile)


def store_name_zonefile_data( name, user_zonefile_txt, txid, storage_drivers=None ):
    """
    Store a serialized zonefile to immutable storage providers, synchronously.
    This is only necessary if we've added/changed/removed immutable data.

    Return (True, hash(user zonefile)) on success
    Return (False, None) on failure.
    """

    storage_drivers = [] if storage_drivers is None else storage_drivers

    data_hash = storage.get_zonefile_data_hash( user_zonefile_txt )
    result = storage.put_immutable_data(None, txid, data_hash=data_hash, data_text=user_zonefile_txt, required=storage_drivers )

    rc = None
    if result is None:
        rc = False
    else:
        rc = True

    return (rc, data_hash)


def store_name_zonefile( name, user_zonefile, txid, storage_drivers=None ):
    """
    Store JSON user zonefile data to the immutable storage providers, synchronously.
    This is only necessary if we've added/changed/removed immutable data.

    Return (True, hash(user zonefile)) on success
    Return (False, None) on failure
    """

    storage_drivers = [] if storage_drivers is None else storage_drivers

    assert not blockstack_profiles.is_profile_in_legacy_format(user_zonefile), "User zonefile is a legacy profile"
    assert user_db.is_user_zonefile(user_zonefile), "Not a user zonefile (maybe a custom legacy profile?)"

    # serialize and send off
    user_zonefile_txt = blockstack_zones.make_zone_file( user_zonefile, origin=name, ttl=USER_ZONEFILE_TTL )
    return store_name_zonefile_data( name, user_zonefile_txt, txid, storage_drivers=storage_drivers )


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

    rc = None
    if result is None:
        rc = False
    else:
        rc = True

    return (rc, data_hash)


def get_and_migrate_profile( name, zonefile_storage_drivers=None, profile_storage_drivers=None, proxy=None, create_if_absent=False, wallet_keys=None, include_name_record=False ):
    """
    Get a name's profile and zonefile, optionally creating a new one along the way.  Migrate the profile to a new zonefile,
    if the profile is in legacy format.

    Only pass 'create_if_absent=True' for names we own

    If @include_name_record is set, then the resulting zonefile will have a key called 'name_record' that includes the name record.

    @wallet_keys, if given, only needs the data public key set.

    Return ({'profile': user_profile}, {'zonefile': user_zonefile}, migrated:bool) on success
    Return ({'error': ...}, None, False) on error
    """

    if proxy is None:
        proxy = get_default_proxy()

    created_new_zonefile = False
    created_new_profile = False

    name_record = None
    user_zonefile = get_name_zonefile( name, storage_drivers=zonefile_storage_drivers, proxy=proxy, wallet_keys=wallet_keys, include_name_record=True )
    if user_zonefile is None or 'error' in user_zonefile: 
        if not create_if_absent:
            return ({'error': 'No such zonefile'}, None, False)

        # creating. we'd better have a data public key
        log.debug("Creating new profile and zonefile for name '%s'" % name)
            
        data_pubkey = load_data_pubkey_for_new_zonefile( wallet_keys=wallet_keys, config_path=proxy.conf['path'] )
        if data_pubkey is None:
            log.warn("No data keypair set; will fall back to owner private key for data signing")

        user_profile = user_db.make_empty_user_profile()
        user_zonefile = user_db.make_empty_user_zonefile( name, data_pubkey )

        # look up name too 
        name_record = proxy.get_name_blockchain_record(name)
        if name_record is None:
            return ({'error': 'No such name'}, None, False)

        if 'error' in name_record:
            return ({'error': 'Failed to look up name: %s' % name_record['error']}, None, False)

        created_new_zonefile = True
        created_new_profile = True

    else:
        name_record = user_zonefile['name_record']
        del user_zonefile['name_record']
        user_zonefile = user_zonefile['zonefile']

    if blockstack_profiles.is_profile_in_legacy_format( user_zonefile ) or not user_db.is_user_zonefile( user_zonefile ):

        log.debug("Migrating legacy profile to modern zonefile for name '%s'" % name)
        
        data_pubkey = load_data_pubkey_for_new_zonefile( wallet_keys=wallet_keys, config_path=proxy.conf['path'] )
        if data_pubkey is None:
            log.warn("No data keypair set; will fall back to owner private key for data signing")

        user_profile = {}
        if blockstack_profiles.is_profile_in_legacy_format( user_zonefile ):
            # traditional profile
            user_profile = blockstack_profiles.get_person_from_legacy_format( user_zonefile )
        else:
            # custom profile 
            user_profile = copy.deepcopy( user_zonefile )

        user_zonefile = user_db.make_empty_user_zonefile( name, data_pubkey )

        created_new_zonefile = True
        created_new_profile = True

    else:
        if not created_new_profile:
            user_profile, error_msg = get_name_profile( name, zonefile_storage_drivers=zonefile_storage_drivers, profile_storage_drivers=profile_storage_drivers,
                                                        proxy=proxy, user_zonefile=user_zonefile, name_record=name_record )
            if user_profile is None:
                return (error_msg, None, False)

        elif create_if_absent:
            log.debug("Creating new profile for existing zonefile for name '%s'" % name)
            user_profile = user_db.make_empty_user_profile()
            created_new_profile = True

        else:
            raise Exception("Should be unreachable")

    ret_user_profile = {
        "profile": user_profile
    }

    ret_user_zonefile = {
        "zonefile": user_zonefile
    }

    if include_name_record:
        # put it back
        ret_user_zonefile['name_record'] = name_record 

    return (ret_user_profile, ret_user_zonefile, created_new_zonefile)


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

            log.debug("Replicate zonefile to %s:%s" % (server_host, server_port))
            hostport = '{}:{}'.format(server_host, server_port)

            res = put_zonefiles( hostport, [base64.b64encode(zonefile_txt)] )
            if 'error' in res or res['saved'][0] != 1:
                log.error("Failed to publish zonefile to %s:%s: %s" % (server_host, server_port, res['error']))
                continue

            log.debug("Replicated zonefile to %s:%s" % (server_host, server_port))
            successful_servers.append( (server_host, server_port) )

        except Exception, e:
            log.exception(e)
            log.error("Failed to publish zonefile to %s:%s" % (server_host, server_port))
            continue

    if len(successful_servers) > 0:
        return {'status': True, 'servers': successful_servers}

    else:
        return {'error': 'Failed to publish zonefile to all backend providers'}


def zonefile_data_replicate( fqu, zonefile_data, tx_hash, server_list, config_path=CONFIG_PATH, storage_drivers=None ):
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
        if required_storage_drivers is None:
            required_storage_drivers = conf.get("storage_drivers", "").split(",")
        else:
            required_storage_drivers = required_storage_drivers.split(",")

    assert len(required_storage_drivers) > 0, "No zonefile storage drivers specified"

    # replicate to our own storage providers
    rc = store_name_zonefile_data( fqu, zonefile_data, tx_hash, storage_drivers=required_storage_drivers )
    if not rc:
        log.info("Failed to replicate zonefile for %s to %s" % (fqu))
        return {'error': 'Failed to store user zonefile'}

    # replicate to blockstack servers
    res = zonefile_data_publish( fqu, zonefile_data, server_list ) 
    if 'error' in res:
        return res

    return {'status': True, 'servers': res['servers']}


