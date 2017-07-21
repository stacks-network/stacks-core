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

import schemas
import storage
import user as user_db

from constants import BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, CONFIG_PATH
from proxy import get_default_proxy, get_name_blockchain_record
from zonefile import get_name_zonefile

import keychain
import virtualchain
from virtualchain.lib import ecdsalib
import blockstack_profiles

from keys import HDWallet, get_app_root_privkey, get_signing_privkey, get_encryption_privkey

import copy
import time
import json
import jsontokens
import jsonschema 
from jsonschema import ValidationError

import keylib

from logger import get_logger
log = get_logger()


def token_file_get_name_public_keys(token_file, name_addr):
    """
    Given the parsed (but not yet verified) token file and an address, get the public keys
    from the token file if they match the address.

    Return {'status': True, 'public_keys': [...]} on success
    Return {'error': ...} if the public keys in the token file do not match the address
    """

    name_addr = virtualchain.address_reencode(str(name_addr))
    name_owner_pubkeys = []

    if virtualchain.is_multisig_address(name_addr):

        public_keys = token_file['keys']['name']
        if name_addr != virtualchain.make_multisig_address(public_keys, len(public_keys)):
            return {'error': 'Multisig address {} does not match public keys {}'.format(name_addr, ','.join(public_keys))}

        # match!
        name_owner_pubkeys = [str(pubk) for pubk in public_keys]

    elif virtualchain.is_singlesig_address(name_addr):

        public_keys = token_file['keys']['name']
        for public_key in public_keys:
            if virtualchain.address_reencode(keylib.public_key_to_address(str(public_key))) == name_addr:
                name_owner_pubkeys = [str(public_key)]
                break

        if len(name_owner_pubkeys) == 0:
            # no match 
            return {'error': 'Address {} does not match any public key {}'.format(name_addr, ','.join(public_keys))}

    else:
        # invalid 
        return {'error': 'Invalid address {}'.format(name_owner_pubkeys_or_addr)}

    return {'status': True, 'public_keys': name_owner_pubkeys}


def token_file_make_datastore_index(apps):
    """
    Given the .keys.apps section of the token file, generate an index
    that maps datastore IDs onto application names.

    The existence of a datastore ID does not imply that the datastore ever existed.
    All this index does is map the datastore ID *that this device would have calculated if it created the datastore*
    to the name of the application.

    Return {'status': True, 'index': {'$datastore_id': '$app_name'}} on success
    """
    from data import datastore_get_id
    index = {}
    for dev_id in apps.keys():
        dev_apps = apps[dev_id]['apps']
        for app_name in dev_apps.keys():
            datastore_id = datastore_get_id(dev_apps[app_name])
            index[datastore_id] = app_name 
        
    return {'status': True, 'index': index}


def token_file_get_app_name(token_file, datastore_id):
    """
    Given a parsed token file and a datastore ID, find the application domain.
    Return {'status': True, 'full_application_name': ...} on success
    Return {'error': ...} on failure
    """
    if 'datastore_index' not in token_file:
        raise ValueError("Token file does not have a datastore index")

    full_application_name = token_file['datastore_index'].get(datastore_id)
    if full_application_name is None:
        return {'error': 'No application name for "{}"'.format(datastore_id)}

    return {'status': True, 'full_application_name': full_application_name}


def token_file_parse(token_txt, name_owner_pubkeys_or_addr, min_writes=None):
    """
    Given a compact-format JWT encoding a token file, this device's name-owner private key, and the list of name-owner public keys,
    go verify that the token file is well-formed and authentic.
    Return {'status': True, 'token_file': the parsed, decoded token file} on success
    Return {'error': ...} on error
    """
    unverified_token_file = None
    unverified_profile = None
    unverified_apps = None

    signing_public_keys = {}
    app_public_keys = {}

    token_file = None
    profile_jwt_txt = None
    delegation_jwt_txt = None
    delegation_jwt = None
    delegation_file = None
    profile = None
    apps = {}
    apps_jwts_txt = {}

    name_owner_pubkeys = []

    # get the delegation file out of the token file
    try:
        unverified_token_file = jsontokens.decode_token(token_txt)['payload']
    except jsontokens.utils.DecodeError:
        return {'error': 'Invalid token file: not a JWT'}

    try:
        jsonschema.validate(unverified_token_file, schemas.BLOCKSTACK_TOKEN_FILE_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_TEST:
            log.exception(ve)

        return {'error': 'Invalid token file: does not match token file schema'}

    except Exception as e:
        log.exception(e)
        return {'error': 'Invalid token file: failed to parse'}

    try:
        delegation_jwt_txt = unverified_token_file['keys']['delegation']
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
        res = token_file_get_name_public_keys(unverified_token_file, str(name_owner_pubkeys_or_addr))
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

    # verify the token file, using any of the signing keys
    for (device_id, signing_public_key) in signing_public_keys.items():
        try:
            token_file_verifier = jsontokens.TokenVerifier()
            token_file_valid = token_file_verifier.verify(token_txt, signing_public_key)
            assert token_file_valid

            # success!
            token_file = unverified_token_file
            break

        except AssertionError as ae:
            continue

    if not token_file:
        # unverifiable 
        return {'error': 'Failed to verify token file with name owner public keys'}

    # the device IDs in the delegation file must include all of the device IDs in the app key bundles
    for device_id in token_file['keys']['apps'].keys():
        if device_id not in delegation_file['devices'].keys():
            return {'error': 'Application key bundle contains a non-delegated device ID "{}"'.format(device_id)}

    # now go verify the profile, using any of the signing public keys
    for (device_id, signing_public_key) in signing_public_keys.items():
        try:
            profile_jwt_txt = token_file['profile']
            profile = storage.parse_mutable_data(profile_jwt_txt, signing_public_key)
            assert profile

            # success
            break
        except AssertionError as ae:
            continue

    if profile is None:
        return {'error': 'Failed to verify profile using signing keys in delegation file'}

    # verify app key bundles, using each device's respective public key
    for (device_id, signing_public_key) in signing_public_keys.items():
        if not token_file['keys']['apps'].has_key(device_id):
            continue

        apps_jwt_txt = token_file['keys']['apps'][device_id]
        try:
            apps_verifier = jsontokens.TokenVerifier()
            apps_is_valid = apps_verifier.verify(apps_jwt_txt, signing_public_key)
            assert apps_is_valid

            # valid! but well-formed?
            app_token = jsontokens.decode_token(apps_jwt_txt)['payload']
            jsonschema.validate(app_token, schemas.APP_KEY_BUNDLE_SCHEMA)

            # valid and well-formed!
            apps[device_id] = app_token
            apps_jwts_txt[device_id] = apps_jwt_txt

        except AssertionError as ae:
            return {'error': 'Application key bundle for "{}" has an invalid signature'.format(device_id)}

        except ValidationError as ve:
            if BLOCKSTACK_TEST:
                log.exception(ve)

            return {'error': 'Application key bundle for "{}" is not well-formed'.format(device_id)}

    # verify fresh 
    if min_writes is not None:
        if token_file['writes'] < min_writes:
            return {'error': 'Stale token file with only {} writes'.format(token_file['writes'])}
    
    # map datastore_id to names
    res = token_file_make_datastore_index(apps)
    if 'error' in res:
        return {'error': 'Failed to build datastore index: {}'.format(res['error'])}
    
    datastore_index = res['index']

    # success!
    token_file_data = {
        'profile': profile,
        'keys': {
            'name': token_file['keys']['name'],
            'delegation': delegation_file,
            'apps': apps,
        },
        'writes': token_file['writes'],
        'timestamp': token_file['timestamp'],
        'jwts': {
            'profile': profile_jwt_txt,
            'keys': {
                'name': token_file['keys']['name'],
                'delegation': delegation_jwt_txt,
                'apps': apps_jwts_txt,
            },
        },
        'datastore_index': datastore_index
    }

    return {'status': True, 'token_file': token_file_data}
    

def token_file_make_delegation_entry(name_owner_privkey, device_id, key_index):
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


def token_file_get_key_order(name_owner_privkeys, pubkeys):
    """
    Given the device -> privkey owner mapping, and a list of public keys
    (e.g. from an on-chain multisig redeem script), calculate the key-signing order
    (e.g. to be fed into token_file_create())

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


def token_file_create(name, name_owner_privkeys, device_id, key_order=None, write_version=1, apps=None, profile=None, delegations=None, config_path=CONFIG_PATH):
    """
    Make a new token file from a profile.  Sign and serialize the delegations file,
    and sign and serialize each of the app bundles.

    @name_owner_privkeys is a dict of {'$device_id': '$private_key'}
    @apps is a dict of {'$device_id': {'$app_name': '$app_public_key'}}

    Return {'status': True, 'token_file': compact-serialized JWT} on success, signed with this device's signing key.
    Return {'error': ...} on error
    """
    if apps is None:
        # default
        apps = {}
        for dev_id in name_owner_privkeys.keys():
            apps[dev_id] = {'version': '1.0', 'apps': {}}

    if profile is None:
        # default
        profile = user_db.make_empty_user_profile(config_path=config_path)
        
    if delegations is None:
        # default
        delegations = {
            'version': '1.0',
            'name': name,
            'devices': {},
        }

        for dev_id in name_owner_privkeys.keys():
            delg = token_file_make_delegation_entry(name_owner_privkeys[dev_id], dev_id, 0)['delegation']
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
    except ValidationError as e:
        if BLOCKSTACK_TEST:
            log.exception(e)

        return {'error': 'Invalid profile'}

    device_specific_name_owner_privkey = name_owner_privkeys[device_id]
    
    # derive the appropriate signing keys 
    signing_keys = dict([(dev_id, get_signing_privkey(name_owner_privkeys[dev_id])) for dev_id in name_owner_privkeys.keys()])
    signing_public_keys = dict([(dev_id, ecdsalib.get_pubkey_hex(signing_keys[dev_id])) for dev_id in signing_keys.keys()])

    # make profile jwt
    profile_jwt_txt = token_file_profile_serialize(profile, signing_keys[device_id])

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

    # make the token file
    token_file = {
        'version': '3.0',
        'profile': profile_jwt_txt,
        'keys': {
            'name': name_owner_pubkeys,
            'delegation': delegation_jwt_txt,
            'apps': apps_jwt_txt,
        },
        'writes': write_version,
        'timestamp': int(time.time()),
    }

    return {'status': True, 'token_file': token_file_sign(token_file, signing_keys[device_id])}


def token_file_sign(parsed_token_file, signing_private_key):
    """
    Given a parsed token file, sign it with the private key
    and return the serialized JWT (in compact serialization)

    Return {'status': True, 'token_file': token file text}
    """
    signer = jsontokens.TokenSigner()
    jwt = signer.sign(parsed_token_file, signing_private_key)
    return jwt


def token_file_profile_serialize(data_text_or_json, data_privkey):
    """
    Serialize a profile to a string
    """
    # profiles must conform to a particular standard format
    tokenized_data = blockstack_profiles.sign_token_records([data_text_or_json], data_privkey)

    del tokenized_data[0]['decodedToken']

    serialized_data = json.dumps(tokenized_data, sort_keys=True)
    return serialized_data


def token_file_update_profile(parsed_token_file, new_profile, signing_private_key):
    """
    Given a parsed token file, a new profile, and the signing key for this device,
    generate a new (serialized) token file with the new profile.

    Return {'status': True, 'token_file': serialized token file}
    Return {'error': ...} on failure
    """

    keys_jwts = parsed_token_file.get('jwts', {}).get('keys', None)
    if keys_jwts is None:
        return {'error': 'Invalid parsed token file: missing jwts'}

    profile_jwt_txt = token_file_profile_serialize(new_profile, signing_private_key)
    tok = {
        'version': '3.0',
        'profile': profile_jwt_txt,
        'keys': keys_jwts,
        'writes': parsed_token_file['writes'] + 1,
        'timestamp': int(time.time()),
    }

    return {'status': True, 'token_file': token_file_sign(tok, signing_private_key)}


def token_file_update_apps(parsed_token_file, device_id, app_name, app_pubkey, signing_private_key):
    """
    Given a parsed token file, a device ID, an application name, its public key, and the device's signing private key,
    insert a new entry for the application for this device

    Return {'status': True, 'token_file': serialized token file} on success
    Return {'error': ...} on failure
    """

    key_jwts = parsed_token_file.get('jwts', {}).get('keys', None)
    if key_jwts is None:
        return {'error': 'Invalid parsed token file: missing jwts'}

    profile_jwt = parsed_token_file.get('jwts', {}).get('profile', None)
    if profile_jwt is None:
        return {'error': 'Invalid parsed token file: missing profile JWT'}

    delegation_jwt = key_jwts.get('delegation', None)
    if delegation_jwt is None:
        return {'error': 'Invalid parsed token file: missing delegations JWT'}

    if device_id not in parsed_token_file['keys']['delegation']['devices'].keys():
        return {'error': 'Device "{}" not present in delegation file'.format(device_id)}

    cur_apps = parsed_token_file['keys']['apps']
    if not cur_apps.has_key(device_id):
        cur_apps[device_id] = {'version': '1.0', 'apps': {}}

    cur_apps[device_id]['apps'][app_name] = app_pubkey

    apps_signer = jsontokens.TokenSigner()
    apps_jwt = apps_signer.sign(cur_apps[device_id], signing_private_key)

    apps_jwts = key_jwts['apps']
    apps_jwts[device_id] = apps_jwt

    tok = {
        'version': '3.0',
        'profile': profile_jwt,
        'keys': {
            'name': parsed_token_file['keys']['name'], 
            'delegation': delegation_jwt,
            'apps': apps_jwts,
        },
        'writes': parsed_token_file['writes'] + 1,
        'timestamp': int(time.time()),
    }

    return {'status': True, 'token_file': token_file_sign(tok, signing_private_key)}


def token_file_update_delegation(parsed_token_file, device_delegation, name_owner_privkeys, signing_private_key):
    """
    Given a parsed token file, a device delegation object, and a list of name owner private keys,
    insert a new entry for the token file's delegation records.

    Return {'status': True, 'token_file': serialized token file} on success
    Return {'error': ...} on failure
    """

    keys_jwts = parsed_token_file.get('jwts', {}).get('keys', None)
    if keys_jwts is None:
        return {'error': 'Invalid parsed token file: missing jwts'}

    profile_jwt = parsed_token_file.get('jwts', {}).get('profile', None)
    if profile_jwt is None:
        return {'error': 'Invalid parsed token file: missing profile JWT'}

    apps_jwt = keys_jwts.get('apps', None)
    if apps_jwt is None:
        return {'error': 'Invalid parsed token file: missing apps JWT'}

    try:
        jsonschema.validate(device_delegation, schemas.KEY_DELEGATION_DEVICES_SCHEMA)
    except ValidationError as ve:
        if BLOCKSTACK_TEST:
            log.exception(ve)

        return {'error': 'Invalid device delegation'}

    new_delegation = copy.deepcopy(parsed_token_file['keys']['delegation'])
    new_delegation['devices'].update(device_delegation)

    signer = jsontokens.TokenSigner()
    new_delegation_jwt = signer.sign(new_delegation, name_owner_privkeys)
    new_delegation_jwt_txt = json.dumps(new_delegation_jwt)

    tok = {
        'version': '3.0',
        'profile': profile_jwt,
        'keys': {
            'name': parsed_token_file['keys']['name'],
            'delegation': new_delegation_jwt_txt,
            'apps': apps_jwt,
        },
        'writes': parsed_token_file['writes'] + 1,
        'timestamp': int(time.time()),
    }

    return {'status': True, 'token_file': token_file_sign(tok, signing_private_key)}


def token_file_get_delegated_device_pubkeys(parsed_token_file, device_id):
    """
    Get the public keys for a delegated device.
    Returns {'status': true, 'version': ..., 'pubkeys': {'app': ..., 'sign': ..., 'enc': ...}} on success
    Returns {'error': ...} on error
    """
    delegation = parsed_token_file.get('keys', {}).get('delegation', None)
    if not delegation:
        raise ValueError('Token file does not have a "delegation" entry')

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


def token_file_get_app_device_ids(parsed_token_file):
    """
    Get the list of app-specific device IDs

    Returns {'status': True, 'device_ids': [...]} on success
    Return {'error': ...} on error
    """
    apps = parsed_token_file.get('keys', {}).get('apps', None)
    if not apps:
        raise ValueError('Token file does not have a "apps" entry')

    return {'status': True, 'device_ids': apps.keys()}


def token_file_get_app_device_pubkeys(parsed_token_file, device_id):
    """
    Get the public keys for apps available from a particular device
    Returns {'status': True, 'version': ..., 'pubkeys': {...}} on success
    Returns {'error': ...} on error
    """
    apps = parsed_token_file.get('keys', {}).get('apps', None)
    if not apps:
        raise ValueError('Token file does not have an "apps" entry')

    apps_info = apps.get(device_id, None)
    if apps_info is None:
        return {'error': 'No device entry in apps file for {}'.format(device_id)}

    res = {
        'status': True,
        'version': apps_info['version'],
        'app_pubkeys': apps_info['apps'],
    }
    return res


def token_file_get_delegated_device_ids(parsed_token_file):
    """
    Get the list of delegated device IDs

    Returns {'status': True, 'device_ids': [...]} on success
    Return {'error': ...} on error
    """
    delegation = parsed_token_file.get('keys', {}).get('delegation', None)
    if not delegation:
        raise ValueError('Token file does not have a "delegation" entry')

    return {'status': True, 'device_ids': delegation['devices'].keys()}


def deduce_name_privkey(parsed_token_file, owner_privkey_info):
    """
    Given owner private key info, and the token file and device ID,
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

    all_device_ids = token_file_get_delegated_device_ids(parsed_token_file)
    for device_id in all_device_ids['device_ids']:
        pubkeys = token_file_get_delegated_device_pubkeys(parsed_token_file, device_id)
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
    return {'error': 'Token file is missing name public keys'}


def lookup_name_privkey(name, owner_privkey_info, proxy=None, parsed_token_file=None):
    """
    Given a name and wallet keys, get the name private key
    Return {'status': True, 'name_privkey': ...} on success
    Return {'error': ...} on error
    """
    proxy = get_default_proxy() if proxy is None else proxy

    if parsed_token_file is None:
        res = token_file_get(name, proxy=proxy)
        if 'error' in res:
            log.error("Failed to get token file for {}: {}".format(name, res['error']))
            return {'error': 'Failed to get token file for {}: {}'.format(name, res['error'])}

        parsed_token_file = res['token_file']
        if parsed_token_file is None:
            log.error("No token file for {}".format(name))
            return {'error': 'No token file available for {}'.format(name)}

    return deduce_name_privkey(parsed_token_file, owner_privkey_info)


def lookup_signing_privkey(name, owner_privkey_info, proxy=None, parsed_token_file=None):
    """
    Given a name and wallet keys, get the signing private key
    Return {"status': True, 'signing_privkey': ...} on success
    Return {'error': ...} on error
    """
    res = lookup_name_privkey(name, owner_privkey_info, proxy=proxy, parsed_token_file=parsed_token_file)
    if 'error' in res:
        return res

    name_privkey = res['name_privkey']
    signing_privkey = get_signing_privkey(name_privkey)
    return {'status': True, 'signing_privkey': signing_privkey}


def lookup_delegated_device_pubkeys(name, proxy=None):
    """
    Given a blockchain ID (name), get all of its delegated devices' public keys
    Return {'status': True, 'pubkeys': {'$device-id': {...}}} on success
    Return {'error': ...} on error
    """
    res = token_file_get(name, proxy=proxy)
    if 'error' in res:
        log.error("Failed to get token file for {}".format(name))
        return {'error': 'Failed to get token file for {}: {}'.format(name, res['error'])}

    parsed_token_file = res['token_file']
    if parsed_token_file is None:
        log.error("No token file for {}".format(name))
        return {'error': 'No token file available for {}'.format(name)}

    all_device_ids = token_file_get_delegated_device_ids(parsed_token_file)
    all_pubkeys = {}
    for dev_id in all_device_ids['device_ids']:
        pubkey_info = token_file_get_delegated_device_pubkeys(parsed_token_file, dev_id)
        assert 'error' not in pubkey_info, pubkey_info['error']

        all_pubkeys[dev_id] = pubkey_info
    
    return {'status': True, 'pubkeys': all_pubkeys, 'token_file': parsed_token_file}
    

def lookup_signing_pubkeys(name, proxy=None):
    """
    Given a blockchain ID (name), get its signing public keys.
    Return {'status': True, 'token_file': ..., 'pubkeys': {'$device_id': ...}} on success
    Return {'error': ...} on error
    """
    res = lookup_delegated_device_pubkeys(name, proxy=proxy)
    if 'error' in res:
        return res
    
    token_file = res['token_file']
    all_pubkeys = res['pubkeys']
    signing_keys = {}
    for dev_id in all_pubkeys.keys():
        signing_keys[dev_id] = all_pubkeys[dev_id].get('sign')

    return {'status': True, 'pubkeys': signing_keys, 'token_file': token_file}


def lookup_app_pubkeys(name, full_application_name, proxy=None, parsed_token_file=None):
    """
    Given a blockchain ID (name), and the full application name (i.e. ending in .1 or .x),
    go and get all of the public keys for it in the app keys file
    Return {'status': True, 'token_file': ..., 'pubkeys': {'$device_id': ...}} on success
    Return {'error': ...} on error
    """
    assert name
    assert full_application_name

    if parsed_token_file is None:
        res = token_file_get(name, proxy=proxy)
        if 'error' in res:
            log.error("Failed to get token file for {}".format(name))
            return {'error': 'Failed to get token file for {}: {}'.format(name, res['error'])}
        
        parsed_token_file = res['token_file']
        if parsed_token_file is None:
            log.error("No token file for {}".format(name))
            return {'error': 'No token file available for {}'.format(name)}

    all_device_ids = token_file_get_app_device_ids(parsed_token_file)
    app_pubkeys = {}
    for dev_id in all_device_ids['device_ids']:
        dev_app_pubkey_info = token_file_get_app_device_pubkeys(parsed_token_file, dev_id)
        assert 'error' not in dev_app_pubkey_info, dev_app_pubkey_info['error']

        dev_app_pubkeys = dev_app_pubkey_info['app_pubkeys']
        if full_application_name not in dev_app_pubkeys.keys():
            # this device may not access this app
            log.debug("Device '{}' does not have access to application '{}'".format(dev_id, full_application_name))
            continue

        app_pubkeys[dev_id] = dev_app_pubkeys[full_application_name]

    return {'status': True, 'pubkeys': app_pubkeys, 'token_file': parsed_token_file}


def token_file_get(name, zonefile_storage_drivers=None, profile_storage_drivers=None,
                   proxy=None, user_zonefile=None, name_record=None,
                   use_zonefile_urls=True, decode=True):
    """
    Given a name, look up an associated key token file.
    Do so by first looking up the zonefile the name points to,
    and then loading the token file from that zonefile's public key.

    Returns {
    'status': True,
    'token_file': token_file (if present),
    'profile': profile,
    'zonefile': zonefile
    'raw_zonefile': unparesed zone file,
    'nonstandard_zonefile': bool whether or not this is a non-standard zonefile
    'legacy_profile': legacy parsed profile
    'name_record': name record (if needed)
    } on success.

    'token_file' may be None, if this name still points to an off-zonefile profile
    'legacy_profile' will be set if this name does not even have an off-zonefile profile (but instead a zone file that parses to a profile)
    
    Returns {'error': ...} on error
    """

    proxy = get_default_proxy() if proxy is None else proxy
    
    ret = {
        'status': True,
        'token_file': None,
        'profile': None,
        'legacy_profile': None,
        'raw_zonefile': None,
        'nonstandard_zonefile': False,
        'zonefile': user_zonefile,
        'name_record': name_record,
    }

    token_file = None

    if user_zonefile is None:
        user_zonefile = get_name_zonefile(name, proxy=proxy, name_record=name_record, storage_drivers=zonefile_storage_drivers, allow_legacy=True)
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
    # (i.e. pre-token file)
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

    # actually go and load the profile or token file (but do not decode it yet)
    profile_or_token_file_txt = storage.get_mutable_data(name, None, urls=urls, drivers=profile_storage_drivers, decode=False, fqu=name)
    if profile_or_token_file_txt is None:
        log.error('no token file or profile for {}'.format(name))
        return {'error': 'Failed to load profile or token file from zone file for {}'.format(name)}

    # try to parse as a token file...
    token_file = None
    profile = None
    token_file_data = token_file_parse(profile_or_token_file_txt, owner_address)
    if 'error' in token_file_data: 
        log.warning("Failed to parse token file: {}".format(token_file_data['error']))

        # try to parse as a legacy profile 
        profile = storage.parse_mutable_data(profile_or_token_file_txt, user_data_pubkey, public_key_hash=owner_address)
        if profile is None:
            log.error("Failed to parse data as a token file or a profile")
            return {'error': 'Failed to load profile or token file'}

    else:
        # got a token file!
        token_file = token_file_data['token_file']
        profile = token_file['profile']

    ret['token_file'] = token_file
    ret['profile'] = profile
    return ret


def token_file_put(name, new_token_file, signing_privkey, proxy=None, required_drivers=None, config_path=CONFIG_PATH):
    """
    Set the new token file data.  CLIENTS SHOULD NOT CALL THIS METHOD DIRECTLY.
    Takes a serialized token file (as a string)

    Return {'status: True} on success
    Return {'error': ...} on failure.
    """
    if not isinstance(new_token_file, (str, unicode)):
        raise ValueError("Invalid token file: string or unicode compact-form JWT required")

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

    log.debug('Save updated token file for "{}" to {}'.format(name, ','.join(required_storage_drivers)))

    rc = storage.put_mutable_data(name, new_token_file, raw=True, required=required_storage_drivers, token_file=True, fqu=name)
    if not rc:
        return {'error': 'Failed to store token file for {}'.format(name)}

    return {'status': True}


def token_file_delete(blockchain_id, signing_private_key, proxy=None):
    """
    Delete token file data.  CLIENTS SHOULD NOT CALL THIS DIRECTLY
    Return {'status: True} on success
    Return {'error': ...} on failure.
    """

    proxy = get_default_proxy() if proxy is None else proxy
    rc = storage.delete_mutable_data(blockchain_id, signing_private_key)
    if not rc:
        return {'error': 'Failed to delete token file'}

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
            'apps': {}
        },
    }
    delegations = {
        'version': '1.0',
        'name': name,
        'devices': {
            'test_device_1': token_file_make_delegation_entry(name_owner_privkeys['test_device_1'], 'test_device_1', 0)['delegation'],
        },
    }

    # make token file
    token_info = token_file_create("test.id", name_owner_privkeys, device_id, profile=profile, delegations=delegations, apps=apps)
    assert 'error' not in token_info, token_info

    token_file_txt = token_info['token_file']
    token_file = token_file_parse(token_file_txt, name_owner_pubkeys.values())
    assert 'error' not in token_file, token_file

    token_file = token_file_parse(token_file_txt, name_owner_address)
    assert 'error' not in token_file, token_file

    token_file = token_file['token_file']

    print 'initial token file is \n{}'.format(json.dumps(token_file, indent=4, sort_keys=True))

    assert token_file['profile'] == profile
    assert token_file['keys']['delegation'] == delegations
    assert token_file['keys']['apps'] == apps, 'token_file[keys][apps] = {}, apps = {}'.format(token_file['keys']['apps'], apps)

    # update the token file's profile
    new_profile = {
        '@type': 'Person',
        'accounts': [],
        'name': {
            'formatted': 'Hello World',
        },
    }

    print 'update profile'
    res = token_file_update_profile(token_file, new_profile, get_signing_privkey(name_owner_privkeys['test_device_1']))
    assert 'error' not in res

    # re-extract
    token_file_txt = res['token_file']
    token_file = token_file_parse(token_file_txt, name_owner_pubkeys.values())
    assert 'error' not in token_file

    token_file = token_file_parse(token_file_txt, name_owner_address)
    assert 'error' not in token_file, token_file

    token_file = token_file['token_file']
    
    print 'token file with new profile is \n{}'.format(json.dumps(token_file, indent=4, sort_keys=True))

    assert token_file['profile'] == new_profile
    assert token_file['keys']['delegation'] == delegations
    assert token_file['keys']['apps'] == apps

    # update the token file's delegations 
    new_delegations = {
        'test_device_1': delegations['devices']['test_device_1'],
        'test_device_2': token_file_make_delegation_entry(name_owner_privkeys['test_device_2'], 'test_device_2', 0)['delegation'],
    }

    print 'update delegation'
    res = token_file_update_delegation(token_file, new_delegations, name_owner_privkeys.values(), get_signing_privkey(name_owner_privkeys['test_device_1']))
    assert 'error' not in res, res['error']

    # re-extract
    token_file_txt = res['token_file']
    token_file = token_file_parse(token_file_txt, name_owner_pubkeys.values())
    assert 'error' not in token_file, token_file['error']

    token_file = token_file_parse(token_file_txt, name_owner_address)
    assert 'error' not in token_file, token_file

    token_file = token_file['token_file']

    print 'token file with new profile and new delegation is \n{}'.format(json.dumps(token_file, indent=4, sort_keys=True))

    assert token_file['profile'] == new_profile
    assert token_file['keys']['delegation'] == {'version': '1.0', 'name': name, 'devices': new_delegations}
    assert token_file['keys']['apps'] == apps

    # update the token file's apps
    helloblockstack_com_pubkey = keylib.ECPrivateKey().public_key().to_hex()
    res = token_file_update_apps(token_file, 'test_device_1', "helloblockstack.com.1", helloblockstack_com_pubkey, get_signing_privkey(name_owner_privkeys['test_device_1']))
    assert 'error' not in res, res['error']

    # re-extract 
    token_file_txt = res['token_file']
    token_file = token_file_parse(token_file_txt, name_owner_pubkeys.values())
    assert 'error' not in token_file

    token_file = token_file_parse(token_file_txt, name_owner_address)
    assert 'error' not in token_file, token_file

    token_file = token_file['token_file']
    
    print 'token file with new profile and new delegation and new app is \n{}'.format(json.dumps(token_file, indent=4, sort_keys=True))

    assert token_file['profile'] == new_profile
    assert token_file['keys']['delegation'] == {'version': '1.0', 'name': name, 'devices': new_delegations}
    assert token_file['keys']['apps'].has_key('test_device_1')
    assert token_file['keys']['apps']['test_device_1']['apps'].has_key('helloblockstack.com.1')
    assert token_file['keys']['apps']['test_device_1']['apps']['helloblockstack.com.1'] == helloblockstack_com_pubkey

    


    # def token_file_parse(token_txt, name_owner_pubkeys_or_addrs, min_writes=None):
    # def token_file_create(profile, delegations, apps, name_owner_privkeys, device_id, write_version=1):
    # def token_file_update_profile(parsed_token_file, new_profile, signing_private_key):
    # def token_file_update_delegation(parsed_token_file, device_delegation, name_owner_privkeys):
    # def token_file_update_apps(parsed_token_file, device_id, app_name, app_pubkey, signing_private_key):
