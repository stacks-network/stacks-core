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
import urllib

import user as user_db
import storage

from keys import *
from profile import *
from proxy import *
from storage import hash_zonefile

import pybitcoin
import bitcoin
import binascii
from utilitybelt import is_hex

from config import get_logger, DEBUG, MAX_RPC_LEN, find_missing, BLOCKSTACKD_SERVER, \
    BLOCKSTACKD_PORT, BLOCKSTACK_METADATA_DIR, BLOCKSTACK_DEFAULT_STORAGE_DRIVERS, \
    FIRST_BLOCK_MAINNET, NAME_OPCODES, OPFIELDS, CONFIG_DIR, SPV_HEADERS_PATH, BLOCKCHAIN_ID_MAGIC, \
    NAME_PREORDER, NAME_REGISTRATION, NAME_UPDATE, NAME_TRANSFER, NAMESPACE_PREORDER, NAME_IMPORT, \
    USER_ZONEFILE_TTL, CONFIG_PATH, get_utxo_provider_client, get_tx_broadcaster

log = get_logger()

import virtualchain


def serialize_mutable_data_id( data_id ):
    """
    Turn a data ID into a suitable filesystem name
    """
    return urllib.quote(data_id.replace("\0", "\\0")).replace("/", r"\x2f")


def load_mutable_data_version(conf, name, fq_data_id):
    """
    Get the version field of a piece of mutable data from local cache.
    """

    # try to get the current, locally-cached version
    if conf is None:
        conf = config.get_config()

    metadata_dir = None
    if conf is not None:

        metadata_dir = conf.get('metadata', None)
        if metadata_dir is not None and os.path.isdir(metadata_dir):

            # find the version file for this data
            serialized_data_id = serialize_mutable_data_id( fq_data_id )
            version_file_path = os.path.join(metadata_dir, serialized_data_id + ".ver")

            if os.path.exists(version_file_path):

                ver = None
                try:
                    with open(version_file_path, "r") as f:
                        ver_txt = f.read()
                        ver = int(ver_txt.strip())

                    # success!
                    return ver

                except ValueError, ve:
                    # not an int
                    log.warn("Not an integer: '%s'" % version_file_path)
                    return None

                except Exception, e:
                    # can't read
                    log.warn("Failed to read '%s': %s" % (version_file_path))
                    return None

            else:
                log.debug("No version path found")
                return None

    else:
        log.debug("No config found; cannot load version for '%s'" % fq_data_id)
        return None



def store_mutable_data_version(conf, fq_data_id, ver):
    """
    Locally store the version of a piece of mutable data,
    so we can ensure that its version is incremented on
    subsequent puts.

    Return True if stored
    Return False if not
    """

    assert storage.is_fq_data_id( fq_data_id ) or storage.is_valid_name( fq_data_id ), "data ID must be a Blockstack DNS name or a fully-qualified data ID"

    if conf is None:
        conf = config.get_config()

    if conf is None:
        log.warning("No config found; cannot store version for '%s'" % fq_data_id)
        return False

    assert 'metadata' in conf, "Missing metadata directory"
    metadata_dir = conf['metadata']
    if not os.path.isdir(metadata_dir):
        log.warning("No metadata directory found; cannot store version of '%s'" % fq_data_id)
        return False

    serialized_data_id = serialize_mutable_data_id( fq_data_id )
    version_file_path = os.path.join(metadata_dir, serialized_data_id + ".ver")

    try:
        with open(version_file_path, "w+") as f:
            f.write("%s" % ver)
            f.flush()
            os.fsync(f.fileno())

        return True

    except Exception, e:
        # failed for whatever reason
        log.exception(e)
        log.warn("Failed to store version of '%s' to '%s'" % (fq_data_id, version_file_path))
        return False


def delete_mutable_data_version(conf, data_id):
    """
    Locally delete the version of a piece of mutable data.

    Return True if deleted.
    Return False if not
    """

    if conf is None:
        conf = config.get_config()

    if conf is None:
        log.warning("No config found; cannot store version for '%s'" % data_id)
        return False

    metadata_dir = conf['metadata']
    if not os.path.isdir(metadata_dir):
        log.warning("No metadata directory found; cannot store version of '%s'" % data_id)
        return False

    serialized_data_id = data_id.replace("/", "\x2f").replace('\0', "\\0")
    version_file_path = os.path.join(metadata_dir, serialized_data_id + ".ver")

    try:
        os.unlink(version_file_path)
        return True

    except Exception, e:
        # failed for whatever reason
        log.warn("Failed to remove version file '%s'" % (version_file_path))
        return False


def get_immutable(name, data_hash, data_id=None, proxy=None):
    """
    get_immutable

    Fetch a piece of immutable data.  Use @data_hash to look it up
    in the user's zonefile, and then fetch and verify the data itself
    from the configured storage providers.

    Return {'data': the data, 'hash': hash} on success
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy()

    user_zonefile = get_name_zonefile(name, proxy=proxy)
    if user_zonefile is None:
        return {'error': 'No user zonefile defined'}

    if 'error' in user_zonefile:
        return user_zonefile 

    if blockstack_profiles.is_profile_in_legacy_format( user_zonefile ):
        # zonefile is really a legacy profile 
        return {'error': 'Profile is in a legacy format that does not support immutable data.'}

    if data_id is not None:
        # look up hash by name 
        h = user_db.get_immutable_data_hash( user_zonefile, data_id )
        if h is None:
            return {'error': 'No such immutable datum'}
         
        if type(h) == list:
            # this tool doesn't allow this to happen (one ID matches one hash),
            # but that doesn't preclude the user from doing this with other tools.
            if data_hash is not None and data_hash not in h:
                return {'error': 'Data ID/hash mismatch'}

            else:
                return {'error': "Multiple matches for '%s': %s" % (data_id, ",".join(h))}

        if data_hash is not None:
            if h != data_hash:
                return {'error': 'Data ID/hash mismatch'}

        else:
            data_hash = h

    elif not user_db.has_immutable_data( user_zonefile, data_hash ):
        return {'error': 'No such immutable datum'}

    data_url_hint = user_db.get_immutable_data_url( user_zonefile, data_hash )
    data = storage.get_immutable_data( data_hash, fqu=name, data_id=data_id, data_url=data_url_hint )
    if data is None:
        return {'error': 'No immutable data returned'}

    return {'data': data, 'hash': data_hash}


def get_immutable_by_name( name, data_id, proxy=None ):
    """
    get_immutable_by_name

    Fetch a piece of immutable data, using a human-meaningful name.
    Look up the hash in the user's zonefile, and use it to fetch
    and verify the immutable data from the configured storage providers.

    Return {'data': the data, 'hash': hash} on success
    Return {'error': ...} on failure
    """
    return get_immutable( name, None, data_id=data_id, proxy=proxy )


def list_update_history( name, current_block=None, proxy=None ):
    """
    list_update_history

    List all prior zonefile hashes of a name, in historic order.
    Return a list of hashes on success.
    Return None on error
    """

    if proxy is None:
        proxy = get_default_proxy()

    if current_block is None:
        info = proxy.getinfo()
        current_block = info['last_block']+1

    name_history = proxy.get_name_blockchain_history( name, 0, current_block )
    all_update_hashes = []

    for state in name_history:
        if state.has_key('value_hash') and state['value_hash'] is not None:
            if len(all_update_hashes) == 0 or all_update_hashes[-1] != state['value_hash']:
                # changed
                all_update_hashes.append( state['value_hash'] )

    return all_update_hashes


def list_zonefile_history( name, current_block=None, proxy=None ):
    """
    list_zonefile_history

    List all prior zonefiles of a name, in historic order.
    Return the list of zonefiles.  Each zonefile will be a dict with either the zonefile data,
    or a dict with only the key 'error' defined.  This method can successfully return
    some but not all zonefiles.
    """
    zonefile_hashes = list_update_history( name, current_block=current_block, proxy=proxy )
    zonefiles = []
    for zh in zonefile_hashes:
        zonefile = load_name_zonefile( name, zh )
        if zonefile is None:
            zonefile = {'error': 'Failed to load zonefile %s' % zh}

        zonefiles.append( zonefile )

    return zonefiles
       

def list_immutable_data_history( name, data_id, current_block=None, proxy=None ):
    """
    list_immutable_data_history

    List all prior hashes of an immutable datum, given its unchanging ID.
    If the zonefile at a particular update is missing, the string "missing zonefile" will be
    appended in its place.  If the zonefile did not define data_id at that time,
    the string "data not defined" will be placed in the hash's place.

    Returns the list of hashes.
    If there are multiple matches for the data ID in a zonefile, then return the list of hashes for that zonefile.
    """
    zonefiles = list_zonefile_history( name, current_block=current_block, proxy=proxy )
    hashes = []
    for zf in zonefiles:
        if 'error' in zf and len(zf.keys()) == 1:
            # invalid
            hashes.append("missing zonefile")
            continue
       
        if not user_db.is_user_zonefile(zf):
            # legacy profile 
            hashes.append("missing zonefile")
            continue 

        data_hash_or_hashes = user_db.get_immutable_data_hash( zf, data_id )
        if data_hash_or_hashes is None:
            hashes.append("data not defined")
            continue
       
        else:
            hashes.append(data_hash_or_hashes)

    return hashes


def get_mutable(name, data_id, proxy=None, ver_min=None, ver_max=None, ver_check=None, conf=None, wallet_keys=None):
    """
    get_mutable

    Fetch a piece of mutable data.  Use @data_id to look it up in the user's
    profile, and then fetch and erify the data itself from the configured 
    storage providers.

    If @ver_min is given, ensure the data's version is greater or equal to it.
    If @ver_max is given, ensure the data's version is less than it.
    If @ver_check is given, it must be a callable that takes the name, data and version and returns True/False

    Return {'data': the data, 'version': the version} on success
    Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy()

    if conf is None:
        conf = proxy.conf

    fq_data_id = storage.make_fq_data_id( name, data_id )
    user_profile, user_zonefile = get_name_profile( name, proxy=proxy, wallet_keys=wallet_keys, include_name_record=True )
    if user_profile is None:
        return user_zonefile    # will be an error message
   
    # recover name record 
    name_record = user_zonefile['name_record']
    del user_zonefile['name_record']

    if blockstack_profiles.is_profile_in_legacy_format( user_zonefile ):
        # profile has not been converted to the new zonefile format yet.
        return {'error': 'Profile is in a legacy format that does not support mutable data.'}

    # get the mutable data zonefile
    if not user_db.has_mutable_data( user_profile, data_id ):
        return {'error': "No such mutable datum"}

    mutable_data_zonefile = user_db.get_mutable_data_zonefile( user_profile, data_id )
    assert mutable_data_zonefile is not None, "BUG: could not look up mutable datum '%s'.'%s'" % (name, data_id)

    # get user's data public key and owner address
    data_pubkey = user_db.user_zonefile_data_pubkey( user_zonefile )
    data_address = name_record['address']
    if data_pubkey is None:
        log.warn("Falling back to owner address for authentication")

    # get the mutable data itself
    urls = user_db.mutable_data_zonefile_urls( mutable_data_zonefile )
    mutable_data = storage.get_mutable_data(fq_data_id, data_pubkey, urls=urls, data_address=data_address )
    if mutable_data is None:
        return {'error': "Failed to look up mutable datum"}

    expected_version = load_mutable_data_version( conf, name, data_id )
    if expected_version is None:
        expected_version = 0

    # check consistency
    version = user_db.mutable_data_version( user_profile, data_id )
    if ver_min is not None and ver_min > version:
        return {'error': 'Mutable data is stale'}

    if ver_max is not None and ver_max <= version:
        return {'error': 'Mutable data is in the future'}

    if ver_check is not None:
        rc = ver_check( name, mutable_data, version )
        if not rc:
            return {'error': 'Mutable data consistency check failed'}

    elif expected_version > version:
        return {'error': 'Mutable data is stale; a later version was previously fetched'}

    rc = store_mutable_data_version( conf, fq_data_id, version )
    if not rc:
        return {'error': 'Failed to store consistency information'}

    return {'data': mutable_data, 'version': version}


def put_immutable(name, data_id, data_json, data_url=None, txid=None, proxy=None, utxo_client=None, wallet_keys=None ):
    """
    put_immutable

    Given a user's name, the data ID, and a JSON-ified chunk of data,
    put it into the user's zonefile.

    If the user's zonefile corresponds to a legacy profile, then automatically
    convert it into a mutable profile and a modern zonefile, and then proceed
    to add the data record.

    If @txid is given, then don't re-send the NAME_UPDATE.  Just try to store
    the data to the immutable storage providers (again).  This is to allow
    for retries in the case where the NAME_UPDATE went through but the
    storage providers did not receive data.
    
    Return {'status': True, 'transaction_hash': txid, 'immutable_data_hash': data_hash, ...} on success
    Return {'error': ...} on error
    """

    from backend.nameops import do_update

    if type(data_json) not in [dict]:
        raise ValueError("Immutable data must be a dict")

    legacy = False
    if proxy is None:
        proxy = get_default_proxy()

    user_profile, user_zonefile, legacy = get_and_migrate_profile( name, create_if_absent=True, proxy=proxy, wallet_keys=wallet_keys )
    if 'error' in user_profile:
        log.debug("Unable to load user zonefile for '%s'" % name)
        return user_profile
   
    if legacy:
        log.debug("User profile is legacy")
        return {'error': "User profile is in legacy format, which does not support this operation.  You must first migrate it with the 'migrate' command."}

    data_text = storage.serialize_immutable_data( data_json )
    data_hash = storage.get_data_hash( data_text )

    # insert into user zonefile, overwriting if need be
    if user_db.has_immutable_data_id( user_zonefile, data_id ):
        log.debug("WARN: overwriting old '%s'" % data_id)
        old_hash = user_db.get_immutable_data_hash( user_zonefile, data_id )

        # NOTE: can be a list, if the name matches multiple hashes.
        # this tool doesn't do this, but it's still possible for the user to use other tools to do this.
        if type(old_hash) != list:
            old_hash = [old_hash]

        for oh in old_hash:
            rc = user_db.remove_immutable_data_zonefile( user_zonefile, oh )
            if not rc:
                return {'error': 'Failed to overwrite old immutable data'}

    rc = user_db.put_immutable_data_zonefile( user_zonefile, data_id, data_hash, data_url=data_url )
    if not rc:
        return {'error': 'Failed to insert immutable data into user zonefile'}

    zonefile_hash = hash_zonefile( user_zonefile )

    # update zonefile, if we haven't already
    if txid is None:
        _, payment_privkey = get_payment_keypair(wallet_keys=wallet_keys, config_path=proxy.conf['path'])
        _, owner_privkey = get_owner_keypair(wallet_keys=wallet_keys, config_path=proxy.conf['path'])
        utxo_client = get_utxo_provider_client( config_path=proxy.conf['path'] )
        broadcaster_client = get_tx_broadcaster( config_path=proxy.conf['path'] )

        update_result = do_update( name, zonefile_hash, owner_privkey, payment_privkey, utxo_client, broadcaster_client, config_path=proxy.conf['path'], proxy=proxy )
        if 'error' in update_result:
            # failed to replicate user zonefile hash 
            # the caller should simply try again, with the 'transaction_hash' given in the result.
            return update_result

        txid = update_result['transaction_hash']

    result = {
        'immutable_data_hash': data_hash,
        'transaction_hash': txid,
        'zonefile_hash': zonefile_hash
    }

    # replicate immutable data 
    rc = storage.put_immutable_data( data_json, txid )
    if not rc:
        result['error'] = 'Failed to store immutable data'
        return result

    rc = store_name_zonefile( name, user_zonefile, txid )
    if not rc:
        result['error'] = 'Failed to store zonefile'
        return result

    # success!
    result['status'] = True
    return result


def put_mutable_get_version( user_profile, data_id, data_json, make_version=None ):
    """
    Given the user profile, data_id, desired version, and callback to create a version,
    find out what the next version of the mutable datum should be.
    """
    version = None
    mutable_version = user_db.mutable_data_version( user_profile, data_id )
    if make_version is not None:
        version = make_version( data_id, data_json, mutable_version )

    else:
        if mutable_version is not None:
            version = mutable_version + 1
        else:
            version = 1

    return version


def put_mutable(name, data_id, data_json, proxy=None, create_only=False, update_only=False, 
                txid=None, version=None, make_version=None, wallet_keys=None):
    """
    put_mutable

    Given a name, an ID for the data, and the data itself, sign and upload the data to the
    configured storage providers.  Add an entry for it into the user's profile as well.

    ** Consistency **

    @version, if given, is the version to include in the data.
    @make_version, if given, is a callback that takes the data_id, data_json, and current version as arguments, and generates the version to be included in the data record uploaded.
    If ver is not given, but make_ver is, then make_ver will be used to generate the version.
    If neither ver nor make_ver are given, the mutable data (if it already exists) is fetched, and the version is calculated as the larget known version + 1.

    ** Durability **

    Replication is best-effort.  If one storage provider driver succeeds, the put_mutable succeeds.  If they all fail, then put_mutable fails.
    More complex behavior can be had by creating a "meta-driver" that calls existing drivers' methods in the desired manner.

    Returns a dict with {'status': True, 'version': version, ...} on success
    Returns a dict with 'error' set on failure
    """

    if type(data_json) not in [dict]:
        raise ValueError("Mutable data must be a dict")

    if proxy is None:
        proxy = get_default_proxy()

    fq_data_id = storage.make_fq_data_id( name, data_id )

    name_record = None
    user_profile, user_zonefile, created_new_zonefile = get_and_migrate_profile( name, create_if_absent=True, proxy=proxy, wallet_keys=wallet_keys, include_name_record=True )
    if 'error' in user_profile:
        return user_profile 

    if created_new_zonefile:
        log.debug("User profile is legacy")
        return {'error': "User profile is in legacy format, which does not support this operation.  You must first migrate it with the 'migrate' command."}

    name_record = user_zonefile['name_record']
    del user_zonefile['name_record']

    log.debug("Profile for %s is currently:\n%s" % (name, json.dumps(user_profile, indent=4, sort_keys=True)))

    exists = user_db.has_mutable_data( user_profile, data_id )
    if not exists and update_only:
        return {'error': 'Mutable datum does not exist'}

    if exists and create_only:
        return {'error': 'Mutable datum already exists'}
    
    # get the version to use
    if version is None:
        version = put_mutable_get_version( user_profile, data_id, data_json, make_version=make_version )

    # generate the mutable zonefile
    data_privkey = get_data_or_owner_privkey( user_zonefile, name_record['address'], wallet_keys=wallet_keys, config_path=proxy.conf['path'] )
    if 'error' in data_privkey:
        # error text
        return {'error': data_privkey['error']}

    else:
        data_privkey = data_privkey['privatekey']
        assert data_privkey is not None

    urls = storage.make_mutable_data_urls( fq_data_id )
    mutable_zonefile = user_db.make_mutable_data_zonefile( data_id, version, urls )

    # add the mutable zonefile to the profile
    rc = user_db.put_mutable_data_zonefile( user_profile, data_id, version, mutable_zonefile )
    assert rc, "Failed to put mutable data zonefile"

    # for legacy migration...
    txid = None 
    zonefile_hash = None
    result = {}
 
    # update the profile with the new zonefile
    rc = storage.put_mutable_data( name, user_profile, data_privkey )
    if not rc:
        result['error'] = 'Failed to store mutable data zonefile to profile'
        return result

    # put the mutable data record itself
    rc = storage.put_mutable_data( fq_data_id, data_json, data_privkey )
    if not rc:
        result['error'] = "Failed to store mutable data"
        return result

    # remember which version this was 
    rc = store_mutable_data_version(proxy.conf, fq_data_id, version)
    if not rc:
        result['error'] = "Failed to store mutable data version"
        return result

    result['status'] = True
    result['version'] = version
    log.debug("Put '%s' to %s mutable data (version %s)\nProfile is now:\n%s" % (data_id, name, version, json.dumps(user_profile, indent=4, sort_keys=True)))
    return result


def delete_immutable(name, data_key, data_id=None, proxy=None, txid=None, wallet_keys=None):
    """
    delete_immutable

    Remove an immutable datum from a name's profile, given by @data_key.
    Return a dict with {'status': True} on success
    Return a dict with {'error': ...} on failure
    """

    from backend.nameops import do_update

    if proxy is None:
        proxy = get_default_proxy()

    legacy = False
    user_zonefile = get_name_zonefile( name, proxy=proxy, include_name_record=True )
    if user_zonefile is None or 'error' in user_zonefile:
        if user_zonefile is None:
            return {'error': 'No user zonefile'}
        else:
            return user_zonefile

    name_record = user_zonefile['name_record']
    del user_zonefile['name_record']

    if blockstack_profiles.is_profile_in_legacy_format( user_zonefile ):
        # zonefile is a legacy profile.  There is no immutable data 
        log.info("Profile is in legacy format.  No immutable data.")
        return {'status': True}

    if data_key is None:
        if data_id is not None:
            # look up the key (or list of keys)
            # shouldn't be a list--this tool prevents that--but deal with it nevertheless
            data_key = user_db.get_immutable_data_hash( user_zonefile, data_id )
            if type(data_key) == list:
                return {'error': "Multiple hashes for '%s': %s" % (data_id, ",".join(data_key)) }

            if data_key is None:
                return {'error': "No hash for '%s'" % data_id}

        else:
            return {'error': 'No data hash or data ID given'}

    # already deleted?
    if not user_db.has_immutable_data( user_zonefile, data_key ):
        return {'status': True}

    # remove 
    user_db.remove_immutable_data_zonefile( user_zonefile, data_key )

    zonefile_hash = hash_zonefile( user_zonefile )
    
    if txid is None:
        # actually send the transaction
        _, payment_privkey = get_payment_keypair(wallet_keys=wallet_keys, config_path=proxy.conf['path'])
        _, owner_privkey = get_owner_keypair(wallet_keys=wallet_keys, config_path=proxy.conf['path'])
        utxo_client = get_utxo_provider_client( config_path=proxy.conf['path'] )
        broadcaster_client = get_tx_broadcaster( config_path=proxy.conf['path'] )

        update_result = do_update( name, zonefile_hash, owner_privkey, payment_privkey, utxo_client, broadcaster_client, config_path=proxy.conf['path'], proxy=proxy )
        if 'error' in update_result:
            # failed to remove from zonefile 
            return update_result 

        txid = update_result['transaction_hash']

    result = {
        'zonefile_hash': zonefile_hash,
        'transaction_hash': txid
    }
    
    # put new zonefile 
    rc = store_name_zonefile( name, user_zonefile, txid )
    if not rc:
        result['error'] = 'Failed to put new zonefile'
        return result

    # delete immutable data 
    data_privkey = get_data_or_owner_privkey( user_zonefile, name_record['address'], wallet_keys=wallet_keys, config_path=proxy.conf['path'] )
    if 'error' in data_privkey:
        return {'error': data_privkey['error']}
    else:
        data_privkey = data_privkey['privatekey']
        assert data_privkey is not None

    rc = storage.delete_immutable_data( data_key, txid, data_privkey )
    if not rc:
        result['error'] = 'Failed to delete immutable data'
        return result

    else:
        result['status'] = True
        return result


def delete_mutable(name, data_id, proxy=None, wallet_keys=None):
    """
    delete_mutable

    Remove a piece of mutable data from the user's profile. Delete it from
    the storage providers as well.

    Returns a dict with {'status': True} on success
    Returns a dict with {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy()
 
    fq_data_id = storage.make_fq_data_id( name, data_id )
    legacy = False
    user_profile, user_zonefile = get_name_profile( name, proxy=proxy, wallet_keys=wallet_keys, include_name_record=True )
    if user_profile is None:
        return user_zonefile    # will be an error message 

    name_record = user_zonefile['name_record']
    del user_zonefile['name_record']

    if blockstack_profiles.is_profile_in_legacy_format( user_zonefile ):
        # zonefile is a legacy profile.  There is no immutable data 
        log.info("Profile is in legacy format.  No immutable data.")
        return {'status': True}

    # already deleted?
    if not user_db.has_mutable_data( user_profile, data_id ):
        return {'status': True}

    # unlink
    user_db.remove_mutable_data_zonefile( user_profile, data_id )

    # put new profile 
    data_privkey = get_data_or_owner_privkey( user_zonefile, name_record['address'], wallet_keys=wallet_keys, config_path=proxy.conf['path'] )
    if 'error' in data_privkey:
        return {'error': data_privkey['error']}
    else:
        data_privkey = data_privkey['privatekey']
        assert data_privkey is not None

    rc = storage.put_mutable_data( name, user_profile, data_privkey )
    if not rc:
        return {'error': 'Failed to unlink mutable data from profile'}

    # remove the data itself 
    rc = storage.delete_mutable_data( fq_data_id, data_privkey )
    if not rc:
        return {'error': 'Failed to delete mutable data from storage providers'}

    return {'status': True}


def list_immutable_data( name, proxy=None ):
    """
    List the names and hashes of all immutable data in a user's zonefile.
    Returns {"data": [{"data_id": data_id, "hash": hash}]} on success
    """
    if proxy is None:
        proxy = get_default_proxy()

    user_zonefile = get_name_zonefile(name, proxy=proxy)
    if user_zonefile is None:
        return {'error': 'No user zonefile defined'}

    if 'error' in user_zonefile:
        return user_zonefile 

    if blockstack_profiles.is_profile_in_legacy_format( user_zonefile ):
        # zonefile is really a legacy profile
        return {"data": []}

    names_and_hashes = user_db.list_immutable_data( user_zonefile )
    listing = [ {"data_id": nh[0], "hash": nh[1]} for nh in names_and_hashes ]
    return {"data": listing}


def list_mutable_data( name, proxy=None, wallet_keys=None ):
    """
    List the names and versions of all mutable data in a user's zonefile
    Returns {"data": [{"data_id": data ID, "version": version}]}
    """
    if proxy is None:
        proxy = get_default_proxy()

    user_profile, user_zonefile = get_name_profile( name, proxy=proxy, wallet_keys=wallet_keys )
    if user_zonefile is None:
        # user_profile will contain an error message
        return user_profile 

    if blockstack_profiles.is_profile_in_legacy_format( user_zonefile ):
        # zonefile is really a legacy profile
        return {"data": []}

    names_and_versions = user_db.list_mutable_data( user_profile )
    listing = [ {"data_id": nv[0], "version": nv[1]} for nv in names_and_versions ]
    return {"data": listing}


def blockstack_url_fetch( url, proxy=None, wallet_keys=None ):
    """
    Given a blockstack:// url, fetch its data.
    If the data is an immutable data url, and the hash is not given, then look up the hash first.
    If the data is a mutable data url, and the version is not given, then look up the version as well.

    Return {"data": data} on success
    Return {"error": error message} on error
    """
    mutable = False
    immutable = False
    blockchain_id = None
    data_id = None
    version = None
    data_hash = None

    try:
        blockchain_id, data_id, version = storage.blockstack_mutable_data_url_parse( url )
        mutable = True
    except ValueError:
        blockchain_id, data_id, data_hash = storage.blockstack_immutable_data_url_parse( url )
        immutable = True

    if mutable:
        if data_id is not None:
            # get single data
            if version is not None:
                return get_mutable( blockchain_id, data_id, proxy=proxy, wallet_keys=wallet_keys, ver_min=version, ver_max=version+1 )
            else:
                return get_mutable( blockchain_id, data_id, proxy=proxy, wallet_keys=wallet_keys )

        else:
            # list data 
            return list_mutable_data( blockchain_id, proxy=proxy, wallet_keys=wallet_keys )

    else:
        if data_id is not None:
            # get single data
            if data_hash is not None:
                return get_immutable( blockchain_id, data_hash, data_id=data_id, proxy=proxy )

            else:
                return get_immutable_by_name( blockchain_id, data_id, proxy=proxy )

        else:
            # list data
            return list_immutable_data( blockchain_id, proxy=proxy )


def data_get( blockstack_url, proxy=None, wallet_keys=None, **kw ):
    """
    Resolve a blockstack URL to data (be it mutable or immutable).
    """
    begin = None
    end = None

    begin = time.time()
    ret = blockstack_url_fetch( blockstack_url, proxy=proxy, wallet_keys=wallet_keys )
    end = time.time()

    if os.environ.get("BLOCKSTACK_TEST") == "1":
        log.debug("[BENCHMARK] data_get %s" % (end - begin))

    return ret


def data_put( blockstack_url, data, proxy=None, wallet_keys=None, **kw ):
    """
    Put data to a blockstack URL (be it mutable or immutable).
    """
    parts = storage.blockstack_data_url_parse( blockstack_url )
    assert parts is not None, "invalid url '%s'" % blockstack_url

    end = None
    begin = None

    if parts['type'] == 'immutable':
        begin = time.time()
        ret = put_immutable( parts['blockchain_id'], parts['data_id'], data, proxy=proxy, wallet_keys=wallet_keys, **kw ) 
        end = time.time()

    else:
        begin = time.time()
        ret = put_mutable( parts['blockchain_id'], parts['data_id'], data, proxy=proxy, wallet_keys=wallet_keys, **kw ) 
        end = time.time()

    if os.environ.get("BLOCKSTACK_TEST") == "1":
        log.debug("[BENCHMARK] data_put %s" % (end - begin))

    return ret


def data_delete( blockstack_url, proxy=None, wallet_keys=None, **kw ):
    """
    Delete data from a blockstack URL (be it mutable or immutable).
    """
    parts = storage.blockstack_data_url_parse( blockstack_url )
    assert parts is not None, "invalid url '%s'" % blockstack_url

    if parts['type'] == 'immutable':
        return delete_immutable( parts['blockchain_id'], parts['fields']['data_hash'], data_id=parts['data_id'], proxy=proxy, wallet_keys=wallet_keys, **kw )
    else:
        return delete_mutable( parts['blockchain_id'], parts['data_id'], proxy=proxy, wallet_keys=wallet_keys )


def data_list( name, proxy=None, wallet_keys=None ):
    """
    List all data for a blockchain ID
    Return {'status': True, 'listing': [...]} on success
    Return {'error': ...} on failure
    """
    immutable_listing = list_immutable_data( name, proxy=proxy )
    mutable_listing = list_mutable_data( name, proxy=proxy, wallet_keys=wallet_keys )
    
    if 'error' in immutable_listing:
        return immutable_listing

    if 'error' in mutable_listing:
        return mutable_listing

    return {'status': True, 'listing': immutable_listing['data'] + mutable_listing['data']}


def set_data_pubkey( name, data_pubkey, proxy=None, wallet_keys=None, txid=None ):
    """
    Set the data public key for a name.
    Overwrites the public key that is present (if given at all).

    WARN: you will need to re-sign all your data after you do this; otherwise
    no one will be able to use your current zonefile contents (with your new 
    key) to verify their authenticity.

    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on error
    """

    from backend.nameops import do_update

    legacy = False
    if proxy is None:
        proxy = get_default_proxy()

    user_profile, user_zonefile, legacy = get_and_migrate_profile( name, create_if_absent=True, proxy=proxy, wallet_keys=wallet_keys )
    if 'error' in user_profile:
        log.debug("Unable to load user zonefile for '%s'" % name)
        return user_profile
   
    if legacy:
        log.debug("User profile is legacy")
        return {'error': "User profile is in legacy format, which does not support this operation.  You must first migrate it with the 'migrate' command."}

    
    user_db.user_zonefile_set_data_pubkey( user_zonefile, data_pubkey )
    zonefile_hash = hash_zonefile( user_zonefile )

    # update zonefile, if we haven't already
    if txid is None:
        _, payment_privkey = get_payment_keypair(wallet_keys=wallet_keys, config_path=proxy.conf['path'])
        _, owner_privkey = get_owner_keypair(wallet_keys=wallet_keys, config_path=proxy.conf['path'])
        utxo_client = get_utxo_provider_client( config_path=proxy.conf['path'] )
        broadcaster_client = get_tx_broadcaster( config_path=proxy.conf['path'] )

        update_result = do_update( name, zonefile_hash, owner_privkey, payment_privkey, utxo_client, broadcaster_client, config_path=proxy.conf['path'], proxy=proxy )
        if 'error' in update_result:
            # failed to replicate user zonefile hash 
            # the caller should simply try again, with the 'transaction_hash' given in the result.
            return update_result

        txid = update_result['transaction_hash']

    result = {
        'transaction_hash': txid,
        'zonefile_hash': zonefile_hash
    }

    # replicate zonefile
    rc = store_name_zonefile( name, user_zonefile, txid )
    if not rc:
        result['error'] = 'Failed to store zonefile'
        return result

    # success!
    result['status'] = True
    return result

