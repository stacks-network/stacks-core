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

# This module contains the code needed to generate and authenticate key-delegation JWTs.
# This is NOT the Blockstack Token code.
import os
import schemas
import storage
import user as user_db

from constants import BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, CONFIG_PATH, DEFAULT_DEVICE_ID
from config import get_config
from proxy import get_default_proxy, get_name_blockchain_record
from zonefile import get_name_zonefile

import keychain
import virtualchain
from virtualchain.lib import ecdsalib
import blockstack_profiles

from keys import HDWallet, get_app_root_privkey, get_signing_privkey, get_encryption_privkey, get_pubkey_hex

import copy
import time
import json
import jsontokens
import jsonschema 
from jsonschema import ValidationError
import urlparse

import keylib

from logger import get_logger
from config import get_local_device_id, make_unassigned_device_id

log = get_logger()


def key_file_get_name_public_keys(key_file, name_addr):
    """
    Given the parsed (but not yet verified) key file and an address, get the public keys
    from the key file if they match the address.

    Return {'status': True, 'public_keys': [...]} on success
    Return {'error': ...} if the public keys in the key file do not match the address
    """

    name_addr = virtualchain.address_reencode(str(name_addr))
    name_owner_pubkeys = []

    if virtualchain.is_multisig_address(name_addr):

        public_keys = key_file['keys']['name']
        if name_addr != virtualchain.make_multisig_address(public_keys, len(public_keys)):
            return {'error': 'Multisig address {} does not match public keys {}'.format(name_addr, ','.join(public_keys))}

        # match!
        name_owner_pubkeys = [str(pubk) for pubk in public_keys]

    elif virtualchain.is_singlesig_address(name_addr):

        public_keys = key_file['keys']['name']
        for public_key in public_keys:
            if virtualchain.address_reencode(keylib.public_key_to_address(str(public_key))) == name_addr:
                name_owner_pubkeys = [str(public_key)]
                break

        if len(name_owner_pubkeys) == 0:
            # no match 
            return {'error': 'Address {} does not match any public key {}'.format(name_addr, ','.join(public_keys))}

    else:
        # invalid 
        return {'error': 'Invalid address {}'.format(name_addr)}

    return {'status': True, 'public_keys': name_owner_pubkeys}


def key_file_make_datastore_index(apps):
    """
    Given the .keys.apps section of the key file, generate an index
    that maps datastore IDs onto application names.

    The existence of a datastore ID does not imply that the datastore ever existed.
    All this index does is map the datastore ID *that this device would have calculated if it created the datastore*
    to the name of the application.

    Return {'status': True, 'index': {'$datastore_id': '$app_name'}} on success
    """
    from gaia import datastore_get_id
    index = {}
    for dev_id in apps.keys():
        dev_apps = apps[dev_id]['apps']
        for app_name in dev_apps.keys():
            datastore_id = datastore_get_id(dev_apps[app_name]['public_key'])
            index[datastore_id] = app_name 
        
    return {'status': True, 'index': index}


def key_file_get_app_name(key_file, datastore_id):
    """
    Given a parsed key file and a datastore ID, find the application domain.
    Return {'status': True, 'full_application_name': ...} on success
    Return {'error': ...} on failure
    """
    if 'datastore_index' not in key_file:
        raise ValueError("key file does not have a datastore index")

    full_application_name = key_file['datastore_index'].get(datastore_id)
    if full_application_name is None:
        return {'error': 'No application name for "{}"'.format(datastore_id)}

    return {'status': True, 'full_application_name': full_application_name}


def key_file_parse(profile_txt, name_owner_pubkeys_or_addr):
    """
    Given a compact-format JWT encoding a key file, this device's name-owner private key, and the list of name-owner public keys,
    go verify that the key file is well-formed and authentic.
    Return {'status': True, 'key_file': the parsed, decoded key file} on success
    Return {'error': ...} on error
    """
    unverified_key_file = None
    unverified_profile = None
    unverified_apps = None

    signing_public_keys = {}
    app_public_keys = {}

    key_file = None
    delegation_jwt_txt = None
    delegation_jwt = None
    delegation_file = None
    profile = None
    apps = {}
    apps_jwts_txt = {}

    name_owner_pubkeys = []

    # get the key file out of the profile
    try:
        # possibly JSON profile tokens
        try:
            log.debug("Try parsing profile as JSON")
            unverified_profile = json.loads(profile_txt)
            assert isinstance(unverified_profile, (dict, list))

            if isinstance(unverified_profile, list):
                unverified_profile = unverified_profile[0]
                assert isinstance(unverified_profile, dict)

            unverified_profile = unverified_profile['claim']
        except Exception as e1:
            try:
                # possibly a JWT
                log.debug("Try parsing profile as JWT")
                unverified_profile = jsontokens.decode_token(profile_txt)['payload']['claim']
            except Exception as e2:
                if BLOCKSTACK_DEBUG:
                    log.error("Tried parsing profile as JSON:")
                    log.exception(e1)
                    log.error("Tried parsing profile as a JWT:")
                    log.exception(e2)
                    log.debug("Invalid profile: {}".format(profile_txt))

                return {'error': 'Invalid profile: Profile text is not JSON or a JWT'}

    except jsontokens.utils.DecodeError:
        return {'error': 'Invalid profile: not a JWT'}

    # confirm that it's a profile 
    try:
        jsonschema.validate(unverified_profile, blockstack_profiles.person.PERSON_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)
            log.error(json.dumps(unverified_profile, indent=4, sort_keys=True))

        return {'error': 'Invalid profile: does not conform to a Person schema'}

    if not unverified_profile.has_key('keyfile'):
        if BLOCKSTACK_TEST:
            log.debug(json.dumps(unverified_profile, indent=4, sort_keys=True))

        return {'error': 'No key file in profile'}
    
    key_txt = unverified_profile['keyfile']

    # get the delegation file out of the key file
    try:
        unverified_key_file = jsontokens.decode_token(key_txt)['payload']
    except jsontokens.utils.DecodeError:
        return {'error': 'Invalid key file: not a JWT'}

    try:
        jsonschema.validate(unverified_key_file, schemas.BLOCKSTACK_KEY_FILE_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_TEST:
            log.exception(ve)

        return {'error': 'Invalid key file: does not match key file schema'}

    except Exception as e:
        log.exception(e)
        return {'error': 'Invalid key file: failed to parse'}

    try:
        delegation_jwt_txt = unverified_key_file['keys']['delegation']
        try:
            delegation_jwt = json.loads(delegation_jwt_txt)
        except ValueError:
            delegation_jwt = delegation_jwt_txt

    except ValueError as ve:
        if BLOCKSTACK_TEST:
            log.exception(ve)
        
        return {'error': 'Invalid delegation file'}

    # if we're given an address (b58check-encoded hash of a public key or list of pbulic keys),
    # see if we can authenticate based on the keys given
    if isinstance(name_owner_pubkeys_or_addr, (str, unicode)):
        res = key_file_get_name_public_keys(unverified_key_file, str(name_owner_pubkeys_or_addr))
        if 'error' in res:
            return res

        name_owner_pubkeys = res['public_keys']

    else:
        if not isinstance(name_owner_pubkeys_or_addr, list):
            return {'error': 'Not a valid address or list: {}'.format(name_owner_pubkeys_or_addr)}

        name_owner_pubkeys = [str(pubk) for pubk in name_owner_pubkeys_or_addr]

    # authenticate the delegation file with the name owner public keys
    try:
        delegation_verifier = jsontokens.TokenVerifier()

        if len(name_owner_pubkeys) > 1:
            assert delegation_verifier.verify(delegation_jwt, name_owner_pubkeys)
        else:
            assert delegation_verifier.verify(delegation_jwt, name_owner_pubkeys[0])

    except AssertionError as ae:
        if BLOCKSTACK_TEST:
            log.exception(ae)

        return {'error': 'Delegation file verification failed'}

    # decode the delegation file
    try:
        delegation_file = jsontokens.decode_token(delegation_jwt)['payload']
    except Exception as e:
        if BLOCKSTACK_TEST:
            log.exception(e)

        return {'error': 'Invalid delegation file: failed to parse'}

    # have verified, well-formed delegation file
    # extract signing public keys and app public keys
    for device_id in delegation_file['devices'].keys():
        try:
            signing_public_keys[device_id] = keylib.ECPublicKey(str(delegation_file['devices'][device_id]['sign'])).to_hex()
        except Exception as e:
            log.exception(e)
            return {'error': 'Invalid signing public key for device "{}"'.format(device_id)}

        # validate the rest of the public keys
        for key_type in ['app', 'enc']:
            try:
                keylib.ECPublicKey(str(delegation_file['devices'][device_id][key_type]))
            except Exception as e:
                log.exception(e)
                return {'error': 'Invalid public key "{}" for device "{}"'.format(key_type, device_id)}

    # verify the keyfile and profile, using any of the signing keys
    for (device_id, signing_public_key) in signing_public_keys.items():
        try:
            profile_verifier = jsontokens.TokenVerifier()
            profile_valid = profile_verifier.verify(profile_txt, signing_public_key)
            assert profile_valid

            # success!
            profile = unverified_profile

        except AssertionError as ae:
            pass

        try:
            key_file_verifier = jsontokens.TokenVerifier()
            key_file_valid = key_file_verifier.verify(key_txt, signing_public_key)
            assert key_file_valid

            # success!
            key_file = unverified_key_file

        except AssertionError as ae:
            pass

        if key_file and profile:
            break

    if not key_file:
        # unverifiable 
        return {'error': 'Failed to verify key file with name owner public keys'}

    if not profile:
        # unverifiable 
        return {'error': 'Failed to verify profile with name owner public keys'}

    # the device IDs in the delegation file must include all of the device IDs in the app key bundles
    for device_id in key_file['keys']['apps'].keys():
        if device_id not in delegation_file['devices'].keys():
            return {'error': 'Application key bundle contains a non-delegated device ID "{}"'.format(device_id)}

    # verify app key bundles, using each device's respective public key
    for (device_id, signing_public_key) in signing_public_keys.items():
        if not key_file['keys']['apps'].has_key(device_id):
            continue

        apps_jwt_txt = key_file['keys']['apps'][device_id]
        try:
            apps_verifier = jsontokens.TokenVerifier()
            apps_is_valid = apps_verifier.verify(apps_jwt_txt, signing_public_key)
            assert apps_is_valid

            # valid! but well-formed?
            app_payload = jsontokens.decode_token(apps_jwt_txt)['payload']
            jsonschema.validate(app_payload, schemas.APP_KEY_BUNDLE_SCHEMA)

            # valid and well-formed!
            apps[device_id] = app_payload
            apps_jwts_txt[device_id] = apps_jwt_txt

        except AssertionError as ae:
            return {'error': 'Application key bundle for "{}" has an invalid signature'.format(device_id)}

        except ValidationError as ve:
            if BLOCKSTACK_TEST:
                log.exception(ve)

            return {'error': 'Application key bundle for "{}" is not well-formed'.format(device_id)}
    
    # map datastore_id to names
    res = key_file_make_datastore_index(apps)
    if 'error' in res:
        return {'error': 'Failed to build datastore index: {}'.format(res['error'])}
    
    datastore_index = res['index']

    # success!
    key_file_data = {
        'profile': profile,
        'keys': {
            'name': key_file['keys']['name'],
            'delegation': delegation_file,
            'apps': apps,
        },
        'timestamp': key_file['timestamp'],
        'jwts': {
            'version': key_file['version'],
            'keys': {
                'name': key_file['keys']['name'],
                'delegation': delegation_jwt_txt,
                'apps': apps_jwts_txt,
            },
            'keyfile': key_txt,
            'timestamp': key_file['timestamp'],
        },
        'datastore_index': datastore_index
    }

    return {'status': True, 'key_file': key_file_data}
    

def key_file_make_delegation_entry(name_owner_privkey, device_id, key_index):
    """
    Make a delegation file entry for a specific device.
    Returns {'status': True, 'delegation': delegation entry, 'private_keys': delegation private keys}
    """
    signing_privkey = get_signing_privkey(name_owner_privkey)
    encryption_privkey = get_encryption_privkey(name_owner_privkey)
    app_privkey = get_app_root_privkey(name_owner_privkey)

    delg = {
        'app': ecdsalib.get_pubkey_hex(app_privkey),
        'enc': ecdsalib.get_pubkey_hex(encryption_privkey),
        'sign': ecdsalib.get_pubkey_hex(signing_privkey),
        'index': key_index
    }

    privkeys = {
        'app': app_privkey,
        'enc': encryption_privkey,
        'sign': signing_privkey
    }

    return {'status': True, 'delegation': delg, 'private_keys': privkeys}


def key_file_get_key_order(name_owner_privkeys, pubkeys):
    """
    Given the device -> privkey owner mapping, and a list of public keys
    (e.g. from an on-chain multisig redeem script), calculate the key-signing order
    (e.g. to be fed into key_file_create())

    Return {'status': True, 'key_order': [...]} on success
    Return {'error': ...} on failure
    """
    key_order = [None] * len(name_owner_pubkeys)
    for (dev_id, privkey) in name_owner_privkeys.items():
        compressed_form = keylib.key_formatting.compress(keylib.ECPrivateKey(privkey).public_key().to_hex())
        uncompressed_form = keylib.key_formatting.decompress(keylib.ECPrivateKey(privkey).public_key().to_hex())

        index = None
        if compressed_form in pubkeys:
            index = pubkeys.index(compressed_form)

        elif uncompressed_form in pubkeys:
            index = pubkeys.index(uncompressed_form)

        else:
            return {'error': 'Public key {} is not present in name owner keys'.format(compressed_form)}

        key_order[index] = dev_id

    return {'status': True, 'key_order': key_order}


def key_file_create(name, name_owner_privkeys, device_id, key_order=None, apps=None, profile=None, delegations=None, config_path=CONFIG_PATH):
    """
    Make a new key file, possibly from an existing profile.  Sign and serialize the delegations file,
    and sign and serialize each of the app bundles.

    @name_owner_privkeys is a dict of {'$device_id': '$private_key'}
    @apps is a dict of {'$device_id': {'$app_name': '$app_public_key'}}

    Return {'status': True, 'key_file': compact-serialized JWT} on success, signed with this device's signing key.
    Return {'error': ...} on error
    """
    if apps is None:
        # default
        apps = {}
        for dev_id in name_owner_privkeys.keys():
            apps[dev_id] = {'version': '1.0', 'apps': {}, 'timestamp': int(time.time())}

    if profile is None:
        # default
        profile = user_db.make_empty_user_profile(config_path=config_path)
        
    if delegations is None:
        # default
        delegations = {
            'version': '1.0',
            'name': name,
            'devices': {},
            'timestamp': int(time.time()),
        }

        for dev_id in name_owner_privkeys.keys():
            delg = key_file_make_delegation_entry(name_owner_privkeys[dev_id], dev_id, 0)['delegation']
            delegations['devices'][dev_id] = delg

    # sanity check: apps must be per-device app key bundles
    for dev_id in apps.keys():
        try:
            jsonschema.validate(apps[dev_id], schemas.APP_KEY_BUNDLE_SCHEMA)
        except ValidationError as e:
            if BLOCKSTACK_TEST:
                log.exception(e)

            return {'error': 'Invalid app bundle'}

    # sanity check: delegations must be well-formed
    try:
        jsonschema.validate(delegations, schemas.KEY_DELEGATION_SCHEMA)
    except ValidationError as e:
        if BLOCKSTACK_TEST:
            log.exception(e)

        return {'error': 'Invalid key delegations object'}

    try:
        jsonschema.validate(profile, blockstack_profiles.person.PERSON_SCHEMA)
        if 'timestamp' not in profile.keys():
            profile['timestamp'] = int(time.time())

    except ValidationError as e:
        if BLOCKSTACK_TEST:
            log.exception(e)

        return {'error': 'Invalid profile'}

    device_specific_name_owner_privkey = name_owner_privkeys[device_id]
    
    # derive the appropriate signing keys 
    signing_keys = dict([(dev_id, get_signing_privkey(name_owner_privkeys[dev_id])) for dev_id in name_owner_privkeys.keys()])
    signing_public_keys = dict([(dev_id, ecdsalib.get_pubkey_hex(signing_keys[dev_id])) for dev_id in signing_keys.keys()])

    # make delegation jwt (to be signed by each name owner key)
    signer = jsontokens.TokenSigner()

    # store compact-form delegation JWT if there is one signature
    delegation_jwt_txt = None
    if len(name_owner_privkeys) == 1:
        delegation_jwt = signer.sign(delegations, name_owner_privkeys.values()[0])
        delegation_jwt_txt = delegation_jwt
    else:
        delegation_jwt = signer.sign(delegations, name_owner_privkeys.values())
        delegation_jwt_txt = json.dumps(delegation_jwt)

    # make the app jwt 
    apps_jwt_txt = {}
    for dev_id in apps.keys():
        signing_privkey = signing_keys.get(dev_id)
        if signing_privkey is None:
            raise ValueError("No key for {}".format(dev_id))

        signer = jsontokens.TokenSigner()
        app_jwt_txt = signer.sign(apps[dev_id], signing_privkey)

        # only want the token 
        apps_jwt_txt[dev_id] = app_jwt_txt

    # name public keys are alphabetically sorted on device ID upon creation by default.
    # otherwise, follow a key order 
    name_owner_pubkeys = []
    if key_order is None:
        for dev_id in sorted(name_owner_privkeys.keys()):
            name_owner_pubkeys.append( keylib.key_formatting.compress(ecdsalib.get_pubkey_hex(name_owner_privkeys[dev_id])) )

    else:
        if len(key_order) != len(name_owner_privkeys.keys()):
            return {'error': 'Invalid key order: length mismatch'}

        for dev_id in key_order:
            if dev_id not in name_owner_privkeys.keys():
                return {'error': 'Invalid key order: device "{}" not present in private key set'.format(dev_id)}

            name_owner_pubkeys.append( keylib.key_formatting.compress(ecdsalib.get_pubkey_hex(name_owner_privkeys[dev_id])) )

    # make the key file
    key_file = {
        'version': '3.0',
        'keys': {
            'name': name_owner_pubkeys,
            'delegation': delegation_jwt_txt,
            'apps': apps_jwt_txt,
        },
        'timestamp': int(time.time()),
    }
    
    # sign it 
    key_file_txt = key_file_sign(key_file, signing_keys[device_id])

    # make the profile 
    profile['keyfile'] = key_file_txt
    
    # make profile jwt
    profile_jwt_txt = key_file_profile_serialize(profile, signing_keys[device_id])

    return {'status': True, 'key_file': profile_jwt_txt}


def key_file_sign(parsed_key_file, signing_private_key):
    """
    Given a parsed key file, sign it with the private key
    and return the serialized JWT (in compact serialization)

    Return the jwt text
    """
    signer = jsontokens.TokenSigner()
    jwt = signer.sign(parsed_key_file, signing_private_key)
    return jwt


def key_file_profile_serialize(data_text_or_json, data_privkey):
    """
    Serialize a profile to a string
    """
    # profiles must conform to a particular standard format
    tokenized_data = blockstack_profiles.sign_token_records([data_text_or_json], data_privkey)
    token = tokenized_data[0]['token']
    return token


def key_file_update_profile(parsed_key_file, new_profile, signing_private_key):
    """
    Given a parsed key file, a new profile, and the signing key for this device,
    generate a new (serialized) key file with the new profile.

    Return {'status': True, 'key_file': serialized key file}
    Return {'error': ...} on failure
    """

    keys_jwts = parsed_key_file.get('jwts', {}).get('keys', None)
    if keys_jwts is None:
        return {'error': 'Invalid parsed key file: missing jwts or keys'}
    
    key_txt = parsed_key_file.get('jwts', {}).get('keyfile', None)
    if key_txt is None:
        return {'error': 'Invalid parsed key file: missing jwts or keyfile'}

    new_profile['timestamp'] = int(time.time())
    new_profile['keyfile'] = key_txt

    profile_jwt_txt = key_file_profile_serialize(new_profile, signing_private_key)
    return {'status': True, 'key_file': profile_jwt_txt}


def key_file_update_apps(parsed_key_file, device_id, app_name, app_pubkey, fq_datastore_id, datastore_urls, signing_private_key):
    """
    Given a parsed key file, a device ID, an application name, its public key, and the device's signing private key,
    insert a new entry for the application for this device

    Return {'status': True, 'key_file': serialized key file} on success
    Return {'error': ...} on failure
    """

    key_jwts = parsed_key_file.get('jwts', {}).get('keys', None)
    if key_jwts is None:
        return {'error': 'Invalid parsed key file: missing jwts'}

    profile = parsed_key_file.get('profile', None)
    if profile is None:
        return {'error': 'Invalid parsed key file: missing profile'}

    delegation_jwt = key_jwts.get('delegation', None)
    if delegation_jwt is None:
        return {'error': 'Invalid parsed key file: missing delegations JWT'}

    if device_id not in parsed_key_file['keys']['delegation']['devices'].keys():
        return {'error': 'Device "{}" not present in delegation file'.format(device_id)}

    cur_apps = parsed_key_file['keys']['apps']
    if not cur_apps.has_key(device_id):
        cur_apps[device_id] = {'version': '1.0', 'apps': {}}

    cur_apps[device_id]['apps'][app_name] = {
        'public_key': app_pubkey,
        'fq_datastore_id': fq_datastore_id,
        'datastore_urls': datastore_urls,
    }

    cur_apps[device_id]['timestamp'] = int(time.time())
    
    apps_signer = jsontokens.TokenSigner()
    apps_jwt = apps_signer.sign(cur_apps[device_id], signing_private_key)

    apps_jwts = key_jwts['apps']
    apps_jwts[device_id] = apps_jwt

    keyfile = {
        'version': '3.0',
        'keys': {
            'name': parsed_key_file['keys']['name'], 
            'delegation': delegation_jwt,
            'apps': apps_jwts,
        },
        'timestamp': max(int(time.time()), parsed_key_file['timestamp'] + 1)
    }

    keyfile_txt = key_file_sign(keyfile, signing_private_key)

    profile['timestamp'] = int(time.time())
    profile['keyfile'] = keyfile_txt

    profile_jwt_txt = key_file_profile_serialize(profile, signing_private_key)
    return {'status': True, 'key_file': profile_jwt_txt}


def key_file_update_delegation(parsed_key_file, device_delegation, name_owner_privkeys, signing_private_key):
    """
    Given a parsed key file, a device delegation object, and a list of name owner private keys,
    insert a new entry for the key file's delegation records.

    Return {'status': True, 'key_file': serialized key file} on success
    Return {'error': ...} on failure
    """

    keys_jwts = parsed_key_file.get('jwts', {}).get('keys', None)
    if keys_jwts is None:
        return {'error': 'Invalid parsed key file: missing jwts'}
    
    profile = parsed_key_file.get('profile', None)
    if profile is None:
        return {'error': 'Invalid parsed key file: missing profile'}

    apps_jwt = keys_jwts.get('apps', None)
    if apps_jwt is None:
        return {'error': 'Invalid parsed key file: missing apps JWT'}

    try:
        jsonschema.validate(device_delegation, schemas.KEY_DELEGATION_SCHEMA['properties']['devices'])
    except ValidationError as ve:
        if BLOCKSTACK_TEST:
            log.exception(ve)

        return {'error': 'Invalid device delegation'}

    new_delegation = copy.deepcopy(parsed_key_file['keys']['delegation'])
    new_delegation['devices'].update(device_delegation)
    new_delegation['timestamp'] = int(time.time())

    signer = jsontokens.TokenSigner()
    new_delegation_jwt = signer.sign(new_delegation, name_owner_privkeys)
    new_delegation_jwt_txt = json.dumps(new_delegation_jwt)
    
    keyfile = {
        'version': '3.0',
        'keys': {
            'name': parsed_key_file['keys']['name'],
            'delegation': new_delegation_jwt_txt,
            'apps': apps_jwt,
        },
        'timestamp': max(int(time.time()), parsed_key_file['timestamp'] + 1),
    }

    keyfile_txt = key_file_sign(keyfile, signing_private_key)

    profile['timestamp'] = int(time.time())
    profile['keyfile'] = keyfile_txt

    profile_jwt_txt = key_file_profile_serialize(profile, signing_private_key)
    return {'status': True, 'key_file': profile_jwt_txt}


def key_file_get_delegated_device_pubkeys(parsed_key_file, device_id):
    """
    Get the public keys for a delegated device.
    Returns {'status': true, 'version': ..., 'pubkeys': {'app': ..., 'sign': ..., 'enc': ...}} on success
    Returns {'error': ...} on error
    """
    delegation = parsed_key_file.get('keys', {}).get('delegation', None)
    if not delegation:
        raise ValueError('key file does not have a "delegation" entry')

    device_info = delegation['devices'].get(device_id, None)
    if device_info is None:
        return {'error': 'No device entry in delegation file for "{}"'.format(device_id)}

    res = {
        'status': True,
        'version': delegation['version'],
        'app': device_info['app'],
        'enc': device_info['enc'],
        'sign': device_info['sign'],
    }

    return res


def key_file_get_app_device_ids(parsed_key_file):
    """
    Get the list of app-specific device IDs

    Returns {'status': True, 'device_ids': [...]} on success
    Return {'error': ...} on error
    """
    apps = parsed_key_file.get('keys', {}).get('apps', None)
    if not apps:
        raise ValueError('key file does not have a "apps" entry')

    return {'status': True, 'device_ids': apps.keys()}


def key_file_get_app_device_info(parsed_key_file, device_id):
    """
    Get the public keys and other information for apps available from a particular device
    Returns {'status': True, 'version': ..., 'app_info': {...}} on success
    Returns {'error': ...} on error
    """
    apps = parsed_key_file.get('keys', {}).get('apps', None)
    if not apps:
        raise ValueError('key file does not have an "apps" entry')

    apps_info = apps.get(device_id, None)
    if apps_info is None:
        return {'error': 'No device entry in apps file for {}'.format(device_id)}

    res = {
        'status': True,
        'version': apps_info['version'],
        'app_info': apps_info['apps'],
    }
    return res


def key_file_get_delegated_device_ids(parsed_key_file):
    """
    Get the list of delegated device IDs

    Returns {'status': True, 'device_ids': [...]} on success
    Return {'error': ...} on error
    """
    delegation = parsed_key_file.get('keys', {}).get('delegation', None)
    if not delegation:
        raise ValueError('key file does not have a "delegation" entry')

    return {'status': True, 'device_ids': delegation['devices'].keys()}


def deduce_name_privkey(parsed_key_file, owner_privkey_info):
    """
    Given owner private key info, and the key file and device ID,
    determine the name-owning private key to use for this device.

    Return {'status': True, 'name_privkey': privkey} on success
    Return {'error': ...} on failure
    """
    privkey_candidates = []
    if virtualchain.is_singlesig(owner_privkey_info):
        # one owner key, and this is it.
        privkey_candidates = [owner_privkey_info]

    else:
        # multisig bundle
        privkey_candidates = owner_privkey_info['privkeys']
   
    # map signing public keys back to the name private key that generated it
    signing_pubkey_candidates = dict([(ecdsalib.get_pubkey_hex(get_signing_privkey(pk)), pk) for pk in privkey_candidates])

    all_device_ids = key_file_get_delegated_device_ids(parsed_key_file)
    for device_id in all_device_ids['device_ids']:
        pubkeys = key_file_get_delegated_device_pubkeys(parsed_key_file, device_id)
        assert 'error' not in pubkeys, pubkeys['error']
        
        signing_pubkey = pubkeys['sign']
        compressed_form = keylib.key_formatting.compress(signing_pubkey)
        uncompressed_form = keylib.key_formatting.decompress(signing_pubkey)

        if compressed_form in signing_pubkey_candidates.keys():
            # found!
            return {'status': True, 'name_privkey': signing_pubkey_candidates[compressed_form]}
            
        if uncompressed_form in signing_pubkey_candidates.keys():
            # found!
            return {'status': True, 'name_privkey': signing_pubkey_candidates[uncompressed_form]}

    # absent
    return {'error': 'key file is missing name public keys'}


def lookup_name_privkey(name, owner_privkey_info, cache=None, cache_max_age=600, config_path=CONFIG_PATH, proxy=None, parsed_key_file=None):
    """
    Given a name and wallet keys, get the name private key
    Return {'status': True, 'name_privkey': ...} on success
    Return {'error': ...} on error
    """
    proxy = get_default_proxy() if proxy is None else proxy

    if parsed_key_file is None:
        res = key_file_get(name, cache=cache, cache_max_age=cache_max_age, proxy=proxy, config_path=config_path)
        if 'error' in res:
            log.error("Failed to get key file for {}: {}".format(name, res['error']))
            return {'error': 'Failed to get key file for {}: {}'.format(name, res['error'])}

        parsed_key_file = res['key_file']
        if parsed_key_file is None:
            log.error("No key file for {}".format(name))
            return {'error': 'No key file available for {}'.format(name)}

    return deduce_name_privkey(parsed_key_file, owner_privkey_info)


def lookup_signing_privkey(name, owner_privkey_info, cache=None, cache_max_age=600, proxy=None, parsed_key_file=None):
    """
    Given a name and wallet keys, get the signing private key
    Return {"status': True, 'signing_privkey': ...} on success
    Return {'error': ...} on error
    """
    res = lookup_name_privkey(name, owner_privkey_info, cache=cache, cache_max_age=cache_max_age, proxy=proxy, parsed_key_file=parsed_key_file)
    if 'error' in res:
        return res

    name_privkey = res['name_privkey']
    signing_privkey = get_signing_privkey(name_privkey)
    return {'status': True, 'signing_privkey': signing_privkey}


def lookup_delegated_device_pubkeys(name, cache=None, cache_max_age=600, proxy=None, config_path=CONFIG_PATH, parsed_key_file=None):
    """
    Given a blockchain ID (name), get all of its delegated devices' public keys
    Return {'status': True, 'pubkeys': {'$device-id': {...}}} on success
    Return {'error': ...} on error
    """
    if parsed_key_file is None:
        res = key_file_get(name, cache=cache, cache_max_age=cache_max_age, proxy=proxy, config_path=config_path)
        if 'error' in res:
            log.error("Failed to get key file for {}".format(name))
            return {'error': 'Failed to get key file for {}: {}'.format(name, res['error'])}

        parsed_key_file = res['key_file']
        if parsed_key_file is None:
            log.error("No key file for {}".format(name))
            return {'error': 'No key file available for {}'.format(name)}

    all_device_ids = key_file_get_delegated_device_ids(parsed_key_file)
    all_pubkeys = {}
    for dev_id in all_device_ids['device_ids']:
        pubkey_info = key_file_get_delegated_device_pubkeys(parsed_key_file, dev_id)
        assert 'error' not in pubkey_info, pubkey_info['error']

        all_pubkeys[dev_id] = pubkey_info
    
    return {'status': True, 'pubkeys': all_pubkeys, 'key_file': parsed_key_file}
    

def lookup_signing_pubkeys(name, cache=None, cache_max_age=600, proxy=None):
    """
    Given a blockchain ID (name), get its signing public keys.
    Return {'status': True, 'key_file': ..., 'pubkeys': {'$device_id': ...}} on success
    Return {'error': ...} on error
    """
    res = lookup_delegated_device_pubkeys(name, cache=cache, cache_max_age=cache_max_age, proxy=proxy)
    if 'error' in res:
        return res
    
    key_file = res['key_file']
    all_pubkeys = res['pubkeys']
    signing_keys = {}
    for dev_id in all_pubkeys.keys():
        signing_keys[dev_id] = all_pubkeys[dev_id].get('sign')

    return {'status': True, 'pubkeys': signing_keys, 'key_file': key_file}


def lookup_app_listing(name, full_application_name, cache=None, cache_max_age=600, proxy=None, config_path=CONFIG_PATH, parsed_key_file=None):
    """
    Given a blockchain ID (name), and the full application name (i.e. ending in .1 or .x),
    go and get all of the public keys for it in the app keys file
    Return {'status': True, 'key_file': ..., 'app_info': {'$device_id': ...}} on success
    Return {'error': ...} on error
    """
    assert name
    assert full_application_name

    if parsed_key_file is None:
        res = key_file_get(name, cache=cache, cache_max_age=cache_max_age, proxy=proxy, config_path=config_path)
        if 'error' in res:
            log.error("Failed to get key file for {}".format(name))
            return {'error': 'Failed to get key file for {}: {}'.format(name, res['error'])}
        
        parsed_key_file = res['key_file']
        if parsed_key_file is None:
            log.error("No key file for {}".format(name))
            return {'error': 'No key file available for {}'.format(name)}

    all_device_ids = key_file_get_app_device_ids(parsed_key_file)
    app_info = {}
    for dev_id in all_device_ids['device_ids']:
        dev_app_pubkey_info = key_file_get_app_device_info(parsed_key_file, dev_id)
        assert 'error' not in dev_app_pubkey_info, dev_app_pubkey_info['error']

        dev_app_info = dev_app_pubkey_info['app_info']
        if full_application_name not in dev_app_info.keys():
            # this device may not access this app
            log.debug("Device '{}' does not have access to application '{}'".format(dev_id, full_application_name))
            continue

        app_info[dev_id] = dev_app_info

    return {'status': True, 'app_info': app_info, 'key_file': parsed_key_file}


def lookup_app_pubkeys(name, full_application_name, cache=None, cache_max_age=600, proxy=None, config_path=CONFIG_PATH, parsed_key_file=None):
    """
    Given a blockchain ID (name), and the full application name (i.e. ending in .1 or .x),
    go and get all of the public keys for it in the app keys file
    Return {'status': True, 'key_file': ..., 'pubkeys': {'$device_id': ...}} on success
    Return {'error': ...} on error
    """
    res = lookup_app_listing(name, full_application_name, cache=cache, cache_max_age=cache_max_age, proxy=proxy, config_path=config_path, parsed_key_file=parsed_key_file)
    if 'error' in res:
        return res

    return {'status': True, 'key_file': res['key_file'], 'pubkeys': dict([(dev_id, res['app_info'][dev_id][full_application_name]['public_key']) for dev_id in res['app_info'].keys()])}


def make_initial_key_file(name, user_profile, owner_privkey_info, config_path=CONFIG_PATH):
    """
    Given a profile, set it up as an "initial" key file (given the owner private key bundle)
    Return {'status': True, 'key_file': serialized key file} on success
    Return {'error': ...} on error
    """
    this_device_id = get_local_device_id(config_dir=os.path.dirname(config_path))
    name_owner_privkeys = {}
    pubkey_order = []

    if virtualchain.is_multisig(owner_privkey_info):
        # create default device IDs, with this device receiving the first public key.
        all_device_ids = [this_device_id] + [make_unassigned_device_id(i) for i in range(1, len(owner_privkey_info['private_keys']))]
        name_owner_privkeys = dict(zip(all_device_ids, owner_privkey_info['private_keys']))

        m, pubkeys = virtualchain.parse_multisig_redeemscript(owner_privkey_info['redeem_script'])
        res = key_file_get_key_order(name_owner_privkeys, pubkeys)
        if 'error' in res:
            return res
        
        pubkey_order = res['key_order']

    else:
        name_owner_privkeys = {
            this_device_id: owner_privkey_info
        }

        pubkey_order = [this_device_id]

    res = key_file_create(name, name_owner_privkeys, this_device_id, key_order=pubkey_order, profile=user_profile, config_path=config_path)
    if 'error' in res:
        return {'error': 'Failed to generate key file for {}: {}'.format(name, res['error'])}

    user_key_file = res['key_file']
    return {'status': True, 'key_file': user_key_file}


def key_file_add_app( blockchain_id, datastore_id, parsed_key_file, this_device_id, app_domain, app_privkey, signing_privkey,
                      cache=None, datastore_urls=[], config_path=CONFIG_PATH ):
    """
    Add application information to a key file, and save the key file.
    Return {'status': True} on success
    Return {'error': ...} on failure
    """
    fq_datastore_id = storage.make_fq_data_id(this_device_id, '{}.datastore'.format(datastore_id))

    log.debug("Allowing device {} to access {} (public key is {})".format(this_device_id, app_domain, get_pubkey_hex(app_privkey)))
    
    # sanitize
    app_domain_scheme = urlparse.urlparse(app_domain).scheme
    app_domain_noscheme = app_domain
    if app_domain_scheme:
        app_domain_noscheme = app_domain[len(app_domain_scheme) + len('://'):]

    # add this app's public key (but we don't have URLs for its datastore yet) 
    res = key_file_update_apps(parsed_key_file, this_device_id, app_domain_noscheme, get_pubkey_hex(app_privkey), fq_datastore_id, datastore_urls, signing_privkey)
    if 'error' in res:
        msg = 'Failed to add key file entry for {} for logging in with {} with device {}'.format(app_domain, blockchain_id, this_device_id)
        log.error(msg)
        return {'error': msg}

    key_file_str = res['key_file']
   
    log.debug("Storing updated key file for {}".format(blockchain_id))

    # store new key file
    # TODO: do via API call?
    res = key_file_put(blockchain_id, key_file_str, cache=cache, config_path=config_path)
    if 'error' in res:
        msg = 'Failed to store new key file to allow signins to {} from {} on device {}'.format(app_domain, blockchain_id, this_device_id)
        log.error(msg)
        return {'error': msg}

    return {'status': True}


def key_file_get_versions(name, device_ids, config_path=CONFIG_PATH):
    """
    Get the version vector for a key file.
    Return {'status': True, 'versions': ...} on success
    Return {'error': ...} on error
    """
    from gaia import get_mutable_data_version

    versions = {}

    # look up key file version from metadata 
    res = get_mutable_data_version(name, [DEFAULT_DEVICE_ID], config_path=config_path)
    if 'error' in res:
        log.error("Failed to load version for key file for {}".format(name))
        return res

    versions['key_file'] = res['version']

    versions['apps'] = {}

    # look up key file app bundle version from metadata
    for device_id in device_ids:
        res = get_mutable_data_version('{}.{}'.format(name, 'apps'), [device_id], config_path=config_path)
        if 'error' in res:
            log.error("Failed to load version for key file for {}".format(name))
            return res
    
        versions['apps'][device_id] = res['version']

    # look up key file delegation bundle version from metadata 
    res = get_mutable_data_version('{}.{}'.format(name, 'delegation'), [DEFAULT_DEVICE_ID], config_path=config_path)
    if 'error' in res:
        log.error("Failed to load version for key file for {}".format(name))
        return res

    versions['delegation'] = res['version']

    # look up key file delegation bundle version from metadata 
    res = get_mutable_data_version('{}.{}'.format(name, 'profile'), [DEFAULT_DEVICE_ID], config_path=config_path)
    if 'error' in res:
        log.error("Failed to load version for key file for {}".format(name))
        return res

    versions['profile'] = res['version']

    return {'status': True, 'versions': versions}


def key_file_check_versions(key_file, versions=None, min_timestamp=None):
    """
    Verify that a key file is fresh
    Return True if so
    Return False if not
    """
    if versions is None and min_timestamp is None:
        raise ValueError("Need either versions dict or min_timestamp")

    if versions is None:
        versions = {
            'key_file': min_timestamp,
            'apps': min_timestamp,
            'delegation': min_timestamp,
            'profile': min_timestamp
        }

    if key_file['timestamp'] < versions['key_file']:
        return {'error': 'Key file is stale ({} < {})'.format(key_file['timestamp'], versions['key_file'])}
    
    for device_id in key_file['keys']['apps']:
        ts = key_file['keys']['apps'][device_id]['timestamp']

        ver = None
        if versions['apps'] == min_timestamp:
            ver = min_timestamp
        else:
            ver = versions['apps'][device_id]

        if ts < ver:
            return {'error': 'Key file app bundle is stale for device {} ({} < {})'.format(device_id, ts, ver)}

    if key_file['keys']['delegation']['timestamp'] < versions['delegation']:
        return {'error': 'Key file delegation file is stale ({} < {})'.format(key_file['keys']['delegation']['timestamp'], versions['delegation'])}

    if key_file['profile']['timestamp'] < versions['profile']:
        return {'error': 'Key file profile is stale ({} < {})'.format(key_file['profile']['timestamp'], versions['profile'])}

    return {'status': True}


def key_file_put_versions(name, key_file_jwt, config_path=CONFIG_PATH):
    """
    Store version vector for key file fields.
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    from gaia import put_mutable_data_version
    
    key_file = jsontokens.decode_token(key_file_jwt)['payload']

    # store key file version 
    res = put_mutable_data_version(name, key_file['timestamp'], [DEFAULT_DEVICE_ID], config_path=config_path)
    if 'error' in res:
        log.error("Failed to store data version for key file for {}".format(name))
        return {'error': 'Failed to store data version for key file for {}: {}'.format(name, res['error'])}

    # store key app bundle version for each device
    for device_id in key_file['keys']['apps']:
        app_keys = jsontokens.decode_token(key_file['keys']['apps'][device_id])['payload']
        ts = app_keys['timestamp']
        res = put_mutable_data_version('{}.{}'.format(name, 'apps'), ts, [device_id], config_path=config_path)
        if 'error' in res:
            log.error("Failed to store data version for app key bundle for key file for {}".format(name))
            return {'error': 'Failed to store data version for app key bundle for key file for {}: {}'.format(name, res['error'])}

    # store delegate version
    delegation_bundle = jsontokens.decode_token(key_file['keys']['delegation'])['payload']
    res = put_mutable_data_version('{}.{}'.format(name, 'delegation'), delegation_bundle['timestamp'], [DEFAULT_DEVICE_ID], config_path=config_path)
    if 'error' in res:
        log.error("Failed to store data version for delegation bundle for key file for {}".format(name))
        return {'error': 'Failed to store data version for delegation bundle for key file for {}: {}'.format(name, res['error'])}

    # store profile version 
    profile_bundle = jsontokens.decode_token(key_file['profile'])['payload']['claim']
    res = put_mutable_data_version('{}.{}'.format(name, 'profile'), profile_bundle['timestamp'], [DEFAULT_DEVICE_ID], config_path=config_path)
    if 'error' in res:
        log.error("Failed to store data version for profile bundle for key file for {}".format(name))
        return {'error': 'Failed to store data version for profile bundle for key file for {}: {}'.format(name, res['error'])}

    return {'status': True}


def key_file_get(name, cache=None, cache_max_age=600, zonefile_storage_drivers=None, profile_storage_drivers=None,
                 proxy=None, user_zonefile=None, name_record=None, min_timestamp=None,
                 use_zonefile_urls=True, decode=True, config_path=CONFIG_PATH):
    """
    Given a name, look up an associated key key file.
    Do so by first looking up the zonefile the name points to,
    and then loading the key file from that zonefile's public key.

    Returns {
    'status': True,
    'key_file': key_file (if present),
    'profile': profile,
    'zonefile': zonefile
    'raw_zonefile': unparesed zone file,
    'nonstandard_zonefile': bool whether or not this is a non-standard zonefile
    'legacy_profile': legacy parsed profile
    'name_record': name record (if needed)
    } on success.

    'key_file' may be None, if this name still points to an off-zonefile profile
    'legacy_profile' will be set if this name does not even have an off-zonefile profile (but instead a zone file that parses to a profile)
    
    Returns {'error': ...} on error
    """

    proxy = get_default_proxy() if proxy is None else proxy

    ret = {
        'status': True,
        'key_file': None,
        'profile': None,
        'legacy_profile': None,
        'raw_zonefile': None,
        'nonstandard_zonefile': False,
        'zonefile': user_zonefile,
        'name_record': name_record,
    }

    if cache:
        # do we have a cached response?
        res = cache.get_key_file(name, cache_max_age)
        if res is not None:
            return res

    key_file = None

    if user_zonefile is None:
        user_zonefile = get_name_zonefile(name, include_raw_zonefile=True, proxy=proxy, name_record=name_record, storage_drivers=zonefile_storage_drivers, allow_legacy=True)
        if 'error' in user_zonefile:
            return user_zonefile

        ret['raw_zonefile'] = user_zonefile['raw_zonefile']
        ret['user_zonefile'] = user_zonefile['zonefile']
        
        user_zonefile = user_zonefile['zonefile']

    # is this really a legacy profile?
    if blockstack_profiles.is_profile_in_legacy_format(user_zonefile):
        # convert it
        log.warning('Converting legacy profile to modern profile')
        legacy_profile = blockstack_profiles.get_person_from_legacy_format(user_zonefile)

        # nothing more to do 
        ret['legacy_profile'] = legacy_profile
        return ret

    elif not user_db.is_user_zonefile(user_zonefile):
        # not a legacy profile, but a custom profile
        log.warning('Non-standard zone file; treating as legacy profile')
        ret['legacy_profile'] = copy.deepcopy(user_zonefile)
        ret['nonstandard_zonefile'] = True
        return ret

    # get user's data public key from their zone file, if it is set.
    # this is only needed for legacy lookups in off-zonefile profiles 
    # (i.e. pre-key file)
    data_address, owner_address = None, None

    try:
        user_data_pubkey = user_db.user_zonefile_data_pubkey(user_zonefile)
        if user_data_pubkey is not None:
            user_data_pubkey = str(user_data_pubkey)
            data_address = keylib.ECPublicKey(user_data_pubkey).address()

    except ValueError:
        # multiple keys defined; we don't know which one to use
        user_data_pubkey = None

    # find owner address
    if name_record is None:
        name_record = get_name_blockchain_record(name, proxy=proxy)
        if name_record is None or 'error' in name_record:
            log.error('Failed to look up name record for "{}"'.format(name))
            return {'error': 'Failed to look up name record'}

    ret['name_record'] = name_record

    assert 'address' in name_record.keys(), json.dumps(name_record, indent=4, sort_keys=True)
    owner_address = name_record['address']

    # find the set of URLs, if none are given
    urls = None
    if use_zonefile_urls and user_zonefile is not None:
        urls = user_db.user_zonefile_urls(user_zonefile)

    # actually go and load the profile or key file (but do not decode it yet)
    profile_or_key_file_txt = storage.get_mutable_data(name, None, urls=urls, drivers=profile_storage_drivers, decode=False, blockchain_id=name)
    if profile_or_key_file_txt is None:
        log.error('no key file or profile for {}'.format(name))
        return {'error': 'Failed to load profile or key file from zone file for {}'.format(name)}

    # try to parse as a key file...
    key_file = None
    profile = None
    key_file_data = key_file_parse(profile_or_key_file_txt, owner_address)
    if 'error' in key_file_data: 
        log.warning("Failed to parse key file: {}".format(key_file_data['error']))

        # try to parse as a legacy profile 
        profile = storage.parse_mutable_data(profile_or_key_file_txt, user_data_pubkey, public_key_hash=owner_address)
        if profile is None:
            log.error("Failed to parse data as a key file or a profile")
            return {'error': 'Failed to load profile or key file'}
        
    else:
        # got a key file!
        key_file = key_file_data['key_file']

        # check that it's fresh
        key_file_versions = None
        if min_timestamp is None:
            # look up from metadata
            device_ids = key_file['keys']['apps'].keys()
            res = key_file_get_versions(name, device_ids, config_path=config_path)
            if 'error' in res:
                log.error("Failed to load versions for key file for {}".format(name))
                return res

            key_file_versions = res['versions']

        if not key_file_check_versions(key_file, min_timestamp=min_timestamp, versions=key_file_versions):
            return {'error': 'Key file is stale'}

        # store versions
        res = key_file_put_versions(name, profile_or_key_file_txt, config_path=config_path)
        if 'error' in res:
            return res

        profile = key_file['profile']

    ret['key_file'] = key_file
    ret['profile'] = profile

    if cache:
        # store response 
        cache.put_key_file(name, ret, cache_max_age)

    return ret


def key_file_put(name, new_key_file, cache=None, proxy=None, required_drivers=None, config_path=CONFIG_PATH):
    """
    Set the new key file data.  CLIENTS SHOULD NOT CALL THIS METHOD DIRECTLY.
    Takes a serialized key file (as a string).
    Takes the 

    Return {'status: True} on success
    Return {'error': ...} on failure.
    """
    if not isinstance(new_key_file, (str, unicode)):
        raise ValueError("Invalid key file: string or unicode compact-form JWT required")

    ret = {}

    proxy = get_default_proxy() if proxy is None else proxy
    config = proxy.conf
    
    # deduce storage drivers
    required_storage_drivers = None
    if required_drivers is not None:
        required_storage_drivers = required_drivers
    else:
        required_storage_drivers = config.get('storage_drivers_required_write', None)
        if required_storage_drivers is not None:
            required_storage_drivers = required_storage_drivers.split(',')
        else:
            required_storage_drivers = config.get('storage_drivers', '').split(',')

    log.debug('Save updated key file for "{}" to {}'.format(name, ','.join(required_storage_drivers)))
    
    storage_res = storage.put_mutable_data(name, new_key_file, sign=False, raw=True, required=required_storage_drivers, key_file=True, blockchain_id=name)
    if 'error' in storage_res:
        log.error("Failed to store updated key file: {}".format(storage_res['error']))
        return {'error': 'Failed to store key file for {}'.format(name)}

    # cache evict
    if cache:
        cache.evict_key_file(name)

    # store new version
    res = key_file_put_versions(name, new_key_file, config_path=config_path)
    if 'error' in res:
        log.error("Failed to store data version vector for key file for {}".format(name))
        return {'error': 'Failed to store data version vector for key file for {}: {}'.format(name, res['error'])}
    
    return storage_res


def key_file_delete(blockchain_id, signing_private_key, cache=None, proxy=None):
    """
    Delete key file data.  CLIENTS SHOULD NOT CALL THIS DIRECTLY
    Return {'status: True} on success
    Return {'error': ...} on failure.
    """

    proxy = get_default_proxy() if proxy is None else proxy

    rc = storage.delete_mutable_data(blockchain_id, signing_private_key)
    if not rc:
        return {'error': 'Failed to delete key file'}
    
    # clear cache
    if cache:
        cache.evict_key_file(name)

    return {'status': True}



if __name__ == "__main__":
    
    name_owner_privkeys = {
        'test_device_1': '2acbababb77e2d52845fd5c9f710ff83595c01b0f4a431927c74afc88dd4c2d501',
        'test_device_2': 'b261db1ae6e0dfeb947b3e1eb67e8426157c6b0abea9de863ce01e76499b231501',
        'test_device_3': '7150f2b6275c1e29f3cf27fb2442ccb17a15ef0de50bc633e14a80175207066b01',
    }

    name_owner_pubkeys = dict([(dev_id, ecdsalib.get_pubkey_hex(nopk)) for (dev_id, nopk) in name_owner_privkeys.items()])
    name_owner_address = virtualchain.make_multisig_address( [keylib.key_formatting.compress(name_owner_pubkeys[dev_id]) for dev_id in sorted(name_owner_pubkeys.keys())], len(name_owner_pubkeys) )

    name = 'test.id'
    device_id = 'test_device_1'
    profile = {
        '@type': 'Person',
        'accounts': []
    }
    apps = {
        'test_device_1': {
            'version': '1.0',
            'apps': {},
            'timestamp': 1,
        },
    }
    delegations = {
        'version': '1.0',
        'name': name,
        'devices': {
            'test_device_1': key_file_make_delegation_entry(name_owner_privkeys['test_device_1'], 'test_device_1', 0)['delegation'],
        },
        'timestamp': 2,
    }

    # make key file
    key_info = key_file_create("test.id", name_owner_privkeys, device_id, profile=profile, delegations=delegations, apps=apps)
    assert 'error' not in key_info, key_info

    key_file_txt = key_info['key_file']
    key_file = key_file_parse(key_file_txt, name_owner_pubkeys.values())
    assert 'error' not in key_file, key_file

    key_file = key_file_parse(key_file_txt, name_owner_address)
    assert 'error' not in key_file, key_file

    key_file = key_file['key_file']

    print 'initial key file is \n{}'.format(json.dumps(key_file, indent=4, sort_keys=True))

    assert key_file['profile'] == profile
    assert key_file['keys']['delegation'] == delegations
    assert key_file['keys']['apps'] == apps, 'key_file[keys][apps] = {}, apps = {}'.format(key_file['keys']['apps'], apps)

    # update the key file's profile
    new_profile = {
        '@type': 'Person',
        'accounts': [],
        'name': '{}.updated'.format(name)
    }

    print 'update profile'
    res = key_file_update_profile(key_file, new_profile, get_signing_privkey(name_owner_privkeys['test_device_1']))
    assert 'error' not in res

    # re-extract
    key_file_txt = res['key_file']
    key_file = key_file_parse(key_file_txt, name_owner_pubkeys.values())
    assert 'error' not in key_file, key_file

    key_file = key_file_parse(key_file_txt, name_owner_address)
    assert 'error' not in key_file, key_file

    key_file = key_file['key_file']
    
    print 'key file with new profile is \n{}'.format(json.dumps(key_file, indent=4, sort_keys=True))
    
    for k in ['@type', 'accounts', 'name']:
        assert key_file['profile'][k] == new_profile[k], new_profile

    assert key_file['keys']['delegation'] == delegations
    assert key_file['keys']['apps'] == apps

    # update the key file's delegations 
    new_delegations = {
        'test_device_1': delegations['devices']['test_device_1'],
        'test_device_2': key_file_make_delegation_entry(name_owner_privkeys['test_device_2'], 'test_device_2', 0)['delegation'],
    }

    print 'update delegation'
    res = key_file_update_delegation(key_file, new_delegations, name_owner_privkeys.values(), get_signing_privkey(name_owner_privkeys['test_device_1']))
    assert 'error' not in res, res['error']

    # re-extract
    key_file_txt = res['key_file']
    key_file = key_file_parse(key_file_txt, name_owner_pubkeys.values())
    assert 'error' not in key_file, key_file['error']

    key_file = key_file_parse(key_file_txt, name_owner_address)
    assert 'error' not in key_file, key_file

    key_file = key_file['key_file']

    print 'key file with new profile and new delegation is \n{}'.format(json.dumps(key_file, indent=4, sort_keys=True))

    for k in ['@type', 'accounts', 'name']:
        assert key_file['profile'][k] == new_profile[k], new_profile

    expected_delegation = {'version': '1.0', 'name': name, 'devices': new_delegations}
    for k in ['version', 'name', 'devices']:
        assert key_file['keys']['delegation'][k] == expected_delegation[k]

    assert key_file['keys']['apps'] == apps

    # update the key file's apps
    helloblockstack_com_pubkey = keylib.ECPrivateKey().public_key().to_hex()
    res = key_file_update_apps(key_file, 'test_device_1', "helloblockstack.com.1", helloblockstack_com_pubkey, 'test:test.datastore', ['file:///test'], get_signing_privkey(name_owner_privkeys['test_device_1']))
    assert 'error' not in res, res['error']

    # re-extract 
    key_file_txt = res['key_file']
    key_file = key_file_parse(key_file_txt, name_owner_pubkeys.values())
    assert 'error' not in key_file

    key_file = key_file_parse(key_file_txt, name_owner_address)
    assert 'error' not in key_file, key_file

    key_file = key_file['key_file']
    
    print 'key file with new profile and new delegation and new app is \n{}'.format(json.dumps(key_file, indent=4, sort_keys=True))

    for k in ['@type', 'accounts', 'name']:
        assert key_file['profile'][k] == new_profile[k], new_profile

    expected_delegation = {'version': '1.0', 'name': name, 'devices': new_delegations}
    for k in ['version', 'name', 'devices']:
        assert key_file['keys']['delegation'][k] == expected_delegation[k]

    assert key_file['keys']['apps'].has_key('test_device_1')
    assert key_file['keys']['apps']['test_device_1']['apps'].has_key('helloblockstack.com.1')
    assert key_file['keys']['apps']['test_device_1']['apps']['helloblockstack.com.1']['public_key'] == helloblockstack_com_pubkey
    assert key_file['keys']['apps']['test_device_1']['apps']['helloblockstack.com.1']['datastore_urls'] == ['file:///test']
    assert key_file['keys']['apps']['test_device_1']['apps']['helloblockstack.com.1']['fq_datastore_id'] == 'test:test.datastore'

    


    # def key_file_parse(key_txt, name_owner_pubkeys_or_addrs, min_writes=None):
    # def key_file_create(profile, delegations, apps, name_owner_privkeys, device_id):
    # def key_file_update_profile(parsed_key_file, new_profile, signing_private_key):
    # def key_file_update_delegation(parsed_key_file, device_delegation, name_owner_privkeys):
    # def key_file_update_apps(parsed_key_file, device_id, app_name, app_pubkey, signing_private_key):
