#!/usr/bin/env python2
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

# this module contains the high-level methods for talking to ancillary storage.

import keylib
import re
import json
import hashlib
import urllib
import urllib2
import base64
import time
import jsontokens

import blockstack_zones
import blockstack_profiles

from .logger import get_logger
from constants import BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, BLOCKSTACK_STORAGE_CLASSES
from config import get_config, CONFIG_PATH
from scripts import hex_hash160
import schemas
from keys import is_singlesig_hex

import virtualchain
from virtualchain.lib.ecdsalib import (
    sign_raw_data,
    verify_raw_data,
    get_pubkey_hex)

log = get_logger()

# global list of registered data handlers
storage_handlers = []


class UnhandledURLException(Exception):
    def __init__(self, url):
        super(UnhandledURLException, self).__init__()
        self.unhandled_url = url


def get_data_hash(data_txt):
    """
    Generate a hash over data for immutable storage.
    Return the hex string.
    """
    h = hashlib.sha256()
    h.update(data_txt)

    return h.hexdigest()


def get_zonefile_data_hash(data_txt):
    """
    Generate a hash over a user's zonefile.
    Return the hex string.
    """
    return hex_hash160(data_txt)


def get_blockchain_compat_hash(data_txt):
    """
    Generate a hash suitable for embedding into
    the blockchain (e.g. for user zonefiles and
    announcements).
    """
    return hex_hash160(data_txt)


def hash_zonefile(zonefile_json):
    """
    Given a JSON-ized zonefile, calculate its hash
    """
    assert '$origin' in zonefile_json.keys(), 'Missing $origin'
    assert '$ttl' in zonefile_json.keys(), 'Missing $ttl'

    user_zonefile_txt = blockstack_zones.make_zone_file(zonefile_json)
    data_hash = get_zonefile_data_hash(user_zonefile_txt)

    return data_hash


def verify_zonefile(zonefile_str, value_hash):
    """
    Verify that a zonefile hashes to the given value hash
    @zonefile_str must be the zonefile as a serialized string
    """
    zonefile_hash = get_zonefile_data_hash(zonefile_str)

    msg = 'Comparing zonefile hashes: expected {}, got {} ({})'
    log.debug(msg.format(value_hash, zonefile_hash, zonefile_hash == value_hash))

    return zonefile_hash == value_hash


def get_storage_handlers():
    """
    Get the list of loaded storage handler instances
    """
    global storage_handlers
    return storage_handlers


def lookup_storage_handler(handler_name):
    """
    Get a storage handler by name
    """
    global storage_handlers
    for handler in storage_handlers:
        if handler.__name__ == handler_name:
            return handler

    return None


def make_mutable_data_urls(data_id, use_only=None):
    """
    Given a data ID for mutable data, get a list of URLs to it
    by asking the storage handlers.
    """
    global storage_handlers

    use_only = [] if use_only is None else use_only

    urls = []
    for handler in storage_handlers:
        if not getattr(handler, 'make_mutable_url', None):
            continue

        if use_only and handler.__name__ not in use_only:
            # not requested
            continue

        new_url = None
        try:
            new_url = handler.make_mutable_url(data_id)
        except Exception as e:
            log.exception(e)
            continue

        if new_url is not None:
            urls.append(new_url)

    return urls


def serialize_data_payload( data_payload ):
    """
    Make a data payload (i.e. a netstring)
    """
    data_txt = str(data_payload)
    return '{}:{},'.format(len(data_txt), data_txt)


def parse_data_payload( data_txt ):
    """
    Parse a data payload into the string it contains.
    The txt is a netstring
    """
    parts = data_txt.split(":", 1)
    if len(parts) != 2:
        log.debug("Invalid netstring: no ':'")
        return None

    try:
        payload_len = int(parts[0])
        data_txt = parts[1]
    except ValueError:
        # invalid
        log.debug("Invalid netstring: not a number")
        return None

    if data_txt[-1] != ',':
        # not a netstring
        log.debug("Invalid netstring: no ',' delimiter")
        return None

    data_txt = data_txt[:-1]
    if len(data_txt) != payload_len:
        # not a valid netstring
        log.debug("Invalid netstring: {} != {}".format(len(data_txt), payload_len))
        return None

    return data_txt


def sign_data_payload( data_payload, data_privkey ):
    """
    Sign a netstring representation of the data payload.
    Return the signature (base64-encoded)
    """
    data_txt = serialize_data_payload(data_payload)
    data_sigb64 = sign_raw_data(data_txt, data_privkey)
    return data_sigb64


def verify_data_payload( data_payload, data_pubkey, sigb64 ):
    """
    Given a payload, verify that the signature covers
    its netstring representation (i.e. 'len(data_payload):data_payload,')
    """
    data_txt = serialize_data_payload(data_payload)
    res = verify_raw_data( data_txt, data_pubkey, sigb64 )
    return res
   

def hash_data_payload( data_payload ):
    """
    Given a payload, verify that the hash covers
    its netstring representation (i.e. hash(len(data_payload):data_payload,))
    """
    data_txt = serialize_data_payload(data_payload)
    dh = hashlib.sha256(data_txt)
    return dh.hexdigest()


def sign_data_tombstone( tombstone_data, data_privkey ):
    """
    Make a data tombstone, and return the tombstone with
    an appended signature (base64)
    """
    sigb64 = sign_raw_data(tombstone_data, data_privkey)
    return '{}:{}'.format(tombstone_data, sigb64)


def parse_data_tombstone( signed_tombstone ):
    """
    Parse a signed data tombstone
    """
    parts = signed_tombstone.rsplit(":", 1)
    if len(parts) != 2:
        return {'error': 'Missing signature'}

    tombstone_data, sigb64 = parts[0], parts[1]
    if not tombstone_data.startswith('delete-'):
        return {'error': 'Missing `delete` crib'}

    # strip `delete-${timestamp}:`
    tombstone_payload_parts = tombstone_data.split(':', 1)
    if len(tombstone_payload_parts) != 2:
        return {'error': 'Invalid `delete` crib'}

    tombstone_payload = tombstone_payload_parts[1]
    return {'tombstone_payload': tombstone_payload, 'sigb64': sigb64}


def verify_data_tombstone( signed_tombstone, data_pubkey ):
    """
    Verify the authenticity of a data tombstone
    """
    parts = signed_tombstone.rsplit(":", 1)
    if len(parts) != 2:
        return False

    tombstone_data, sigb64 = parts[0], parts[1]
    return verify_raw_data( tombstone_data, data_pubkey, sigb64 )


def make_data_tombstone( tombstone_data ):
    """
    Make a serialized tombstone.
    Format is `delete-${millis since epoch date}:${tombstone data}`
    """
    return 'delete-{}:{}'.format(int(time.time() * 1000), tombstone_data)


def parse_signed_data_tombstone( tombstone_data ):
    """
    extract the data ID and signature from a signed tombstone
    return {'id': data ID, 'signature': sig, 'timestamp': ts} on success
       `ts` will be the number of milliseconds since the epoch date
    Return None on error
    """
    parts1 = tombstone_data.split(":", 1)
    if len(parts1) != 2:
        return None

    if not parts1[0].startswith('delete'):
        return None
    
    if parts1[0].count('-') != 1:
        return None

    header_parts = parts1[0].split('-')
    if len(header_parts) != 2:
        return None

    if header_parts[0] != 'delete':
        return None

    ts = None
    try:
        ts = int(header_parts[1])
    except ValueError:
        return None

    parts2 = parts1[1].rsplit(":", 1)
    if len(parts2) != 2:
        return None 

    return {'id': parts2[0], 'signature': parts2[1], 'timestamp': ts}


def serialize_mutable_data(data_text_or_json, data_privkey=None, data_pubkey=None, data_signature=None, profile=False):
    """
    Generate a serialized mutable data record from the given information.
    Sign it with privatekey.

    The signature will be generated over the netstring "len(payload):payload,".
    If given, the signature must be signed this way (i.e. via sign_data_payload)

    Return the serialized data (as a string) on success
    """
  
    if profile:
        # private key required to generate signature
        assert data_privkey is not None

        # profiles must conform to a particular standard format
        tokenized_data = blockstack_profiles.sign_token_records(
            [data_text_or_json], data_privkey
        )

        del tokenized_data[0]['decodedToken']

        serialized_data = json.dumps(tokenized_data, sort_keys=True)
        return serialized_data
    
    else:
        # version 2 format for mutable data
        assert data_privkey or (data_pubkey and data_signature)

        if data_signature is None:
            assert isinstance(data_text_or_json, (str, unicode)), "data must be a string"
            data_str = str(data_text_or_json)
            data_signature = sign_data_payload( data_str, data_privkey )

        # make sure it's compressed
        if data_pubkey is None:
            data_pubkey = get_pubkey_hex(data_privkey)

        pubkey_hex_compressed = keylib.key_formatting.compress(data_pubkey)
        data_payload = serialize_data_payload( data_text_or_json )
        res = "bsk2.{}.{}.{}".format(pubkey_hex_compressed, data_signature, data_payload)

        return res


def parse_mutable_data_v2(mutable_data_json_txt, public_key_hex, public_key_hash=None, data_hash=None, raw=False, return_public_key=False):
    """
    Version 2 parser
    Parse a piece of mutable data back into the serialized payload.
    Verify that it was signed by the given public key, or the public key hash.
    If neither are given, then verify that it has the given hash.
    Return the data on success.  If return_public_key is True, then return {'data': ..., 'public_key': ...}
    Return None on error
    """

    pubk_hex = None
    sig_b64 = None
    data_txt = None
    original_data_txt = None

    if not raw:
        # format: bsk2.pubkey.sigb64.data_len:data,
        parts = mutable_data_json_txt.split(".", 3)
        if len(parts) != 4:
            log.debug("Malformed data: {}".format(mutable_data_json_txt))
            return None 
        
        if parts[0] != 'bsk2':
            log.debug("Not v2 data")
            return None

        pubk_hex = str(parts[1])
        sig_b64 = str(parts[2])
        data_txt = str(parts[3])

        # basic sanity checks
        if not re.match('^[0-9a-fA-F]+$', pubk_hex):
            log.debug("Not a v2 mutable datum: Invalid public key")
            return None 

        if not re.match(schemas.OP_BASE64_PATTERN_SECTION, sig_b64):
            log.debug("Not a v2 mutable datum: Invalid signature data")
            return None

        try:
            sig_bin = base64.b64decode(sig_b64)
        except:
            log.error("Incorrect base64-encoding")
            return None

        # data_txt must be a netstring (format: 'len(payload):payload,')
        serialized_len = len(data_txt)
        original_data_txt = data_txt[:]
        data_txt = parse_data_payload(data_txt)
        if data_txt is None:
            log.debug("Invalid data payload of {} bytes".format(serialized_len))
            return None

    else:
        data_txt = mutable_data_json_txt
        original_data_txt = mutable_data_json_txt

    # shortcut: if hash is given, we're done 
    if data_hash is not None:
        dh = hash_data_payload( str(data_txt) )
        if dh == data_hash:
            # done!
            log.debug("Verified with hash {}".format(data_hash))

            if return_public_key:
                return {'data': data_txt, 'public_key': None}
            else:
                return data_txt

        else:
            log.debug("Hash mismatch: expected {}, got {}\noriginal_data_text ({}): '{}'\nlen(original_data_text): {}\nparsed payload: '{}'\nhash_data_payload: {}".format(
                data_hash, dh, type(original_data_txt), original_data_txt, len(original_data_txt), parse_data_payload(original_data_txt), hash_data_payload(data_txt)))
    
    # validate 
    if pubk_hex is not None:
        if keylib.key_formatting.get_pubkey_format(pubk_hex) == 'hex_compressed':
            pubk_hex = keylib.key_formatting.decompress(pubk_hex)

    if public_key_hex is not None:
        # make sure uncompressed
        given_pubkey_hex = str(public_key_hex)
        if keylib.key_formatting.get_pubkey_format(given_pubkey_hex) == 'hex_compressed':
            given_pubkey_hex = keylib.key_formatting.decompress(given_pubkey_hex)

        log.debug("Try verify with {}".format(given_pubkey_hex))

        if pubk_hex is not None and given_pubkey_hex == pubk_hex:
            if verify_data_payload( data_txt, pubk_hex, sig_b64 ):
                log.debug("Verified payload with public key {}".format(pubk_hex))

                if return_public_key:
                    return {'data': data_txt, 'public_key': pubk_hex}
                else:
                    return data_txt
            else:
                log.debug("Signature failed")

        else:
            log.debug("Public key mismatch: {} != {}".format(given_pubkey_hex, pubk_hex))

    if public_key_hash is not None and pubk_hex is not None:
        pubkey_hash = keylib.address_formatting.bin_hash160_to_address(
                keylib.address_formatting.address_to_bin_hash160(
                    str(public_key_hash),
                ),
                version_byte=0
        )

        log.debug("Try verify with {}".format(pubkey_hash))

        pubk_compressed = keylib.key_formatting.compress(pubk_hex)
        pubk_uncompressed = keylib.key_formatting.decompress(pubk_hex)

        if keylib.public_key_to_address(pubk_compressed) == pubkey_hash or keylib.public_key_to_address(pubk_uncompressed) == pubkey_hash:
            if verify_data_payload( data_txt, pubk_hex, sig_b64 ):
                log.debug("Verified payload with public key hash {} ({})".format(pubk_hex, pubkey_hash))

                if return_public_key:
                    return {'data': data_txt, 'public_key': pubk_hex}

                else:
                    return data_txt
            else:
                log.debug("Signature failed with pubkey hash")

        else:
            log.debug("Public key hash mismatch")

    log.debug("Failed to verify v2 mutable datum")
    return None


def parse_mutable_data(mutable_data_json_txt, public_key, public_key_hash=None, data_hash=None, bsk_version=None, return_public_key=False):
    """
    Given the serialized JSON for a piece of mutable data,
    parse it into a JSON document.  Verify that it was
    signed by public_key's or public_key_hash's private key.

    Try to verify with both keys, if given.

    Returns:
    * the parsed JSON dict on success (if a profile)
    * the raw data (otherwise)
    * the dict {'data': ..., 'public_key': ...} (if return_public_key is True)

    Return None on error
    """
    
    # newer version?
    if mutable_data_json_txt.startswith("bsk2.") or bsk_version == 2:
        raw = False
        if not mutable_data_json_txt.startswith("bsk2."):
            # raw data; will authenticate with data hash
            raw = True
            if data_hash is None:
                log.error("Corrupt data: data text does not start with 'bsk2.', and no data hash given")
                return None

        return parse_mutable_data_v2(mutable_data_json_txt, public_key, public_key_hash=public_key_hash, data_hash=data_hash, raw=raw, return_public_key=return_public_key)
        
    # legacy parser
    assert public_key is not None or public_key_hash is not None, 'Need a public key or public key hash'

    mutable_data_jwt = None
    try:
        mutable_data_jwt = json.loads(mutable_data_json_txt)
        assert isinstance(mutable_data_jwt, (dict, list))
    except:
        # TODO: Check use of catchall exception handler
        log.error('Invalid JSON')
        return None

    mutable_data_json = None

    # try pubkey, if given
    if public_key is not None:
        mutable_data_json = blockstack_profiles.get_profile_from_tokens(
            mutable_data_jwt, str(public_key)
        )

        if len(mutable_data_json) > 0:
            if return_public_key:
                return {'data': mutable_data_json, 'public_key': str(public_key)}
            else:
                return mutable_data_json

        msg = 'Failed to verify with public key "{}"'
        log.warn(msg.format(public_key))

    # try pubkey address
    if public_key_hash is not None:
        # NOTE: these should always have version byte 0
        # TODO: use jsontokens directly
        public_key_hash_0 = keylib.address_formatting.bin_hash160_to_address(
            keylib.address_formatting.address_to_bin_hash160(
                str(public_key_hash)
            ),
            version_byte=0
        )

        mutable_data_json = blockstack_profiles.get_profile_from_tokens(
            mutable_data_jwt, public_key_hash_0
        )

        if len(mutable_data_json) > 0:
            log.debug('Verified with {}'.format(public_key_hash))
            if return_public_key:
                profile_token = jsontokens.decode_token(mutable_data_jwt[0]['token'])
                issuer_public_key = profile_token['payload']['issuer']['publicKey']

                # use the one that corresponds to the address 
                ret_pubkey = None
                if virtualchain.address_reencode(keylib.public_key_to_address(keylib.key_formatting.compress(str(issuer_public_key)))) == virtualchain.address_reencode(str(public_key_hash)):
                    ret_pubkey = keylib.key_formatting.compress(issuer_public_key)
                elif virtualchain.address_reencode(keylib.public_key_to_address(keylib.key_formatting.decompress(str(issuer_public_key)))) == virtualchain.address_reencode(str(public_key_hash)):
                    ret_pubkey = keylib.key_formatting.decompress(issuer_public_key)
                else:
                    raise Exception("BUG: public key {} does not match {}".format(issuer_public_key, public_key_hash))

                return {'data': mutable_data_json, 'public_key': ret_pubkey}

            else:
                return mutable_data_json

        msg = 'Failed to verify with public key hash "{}" ("{}")'
        log.warn(msg.format(public_key_hash, public_key_hash_0))

    # try sha256 hash 
    if data_hash is not None:
        log.error("Verifying profiles by hash it not supported")

    return None


def register_storage(storage_impl):
    """
    Given a class, module, etc. with the methods,
    register the mutable and immutable data handlers.

    The given argument--storage_impl--must persist for
    as long as the application will be using its methods.

    Return True on success
    Return False on error
    """

    global storage_handlers
    if storage_impl in storage_handlers:
        return True

    storage_handlers.append(storage_impl)

    # sanity check
    expected_methods = [
        'make_mutable_url', 'get_immutable_handler', 'get_mutable_handler',
        'put_immutable_handler', 'put_mutable_handler', 'delete_immutable_handler',
        'delete_mutable_handler', 'get_classes'
    ]

    for expected_method in expected_methods:
        if not getattr(storage_impl, expected_method, None):
            msg = 'Storage implementation is missing a "{}" method'
            log.warning(msg.format(expected_method))

    return True


def get_storage_driver_classes(driver_name):
    """
    Get the driver classes for a driver.
    Return [] if the driver does not list any.
    """
    global storage_handlers
    if len(storage_handlers) == 0:
        log.warn("No storage drivers registered")
        return []

    for driver in storage_handlers:
        if driver.__name__ == driver_name:
            if not hasattr(driver, 'get_classes'):
                log.warn("Driver {} does not implement 'get_classes()'".format(driver_name))
                return []

            return driver.get_classes()

    log.warn("No such driver {}".format(driver_name))
    return []


def classify_storage_drivers():
    """
    Classify the set of storage drivers.
    Return {'class': ['driver names']}
    """
    global storage_handlers
    classes = {}

    for driver_class in BLOCKSTACK_STORAGE_CLASSES:
        classes[driver_class] = []

    for driver in storage_handlers:
        driver_classes = get_storage_driver_classes(driver.__name__)
        for driver_class in driver_classes:
            if driver_class not in BLOCKSTACK_STORAGE_CLASSES:
                raise ValueError("Driver '{}' reports unrecognized class '{}'".format(driver.__name__, driver_class))

            classes[driver_class].append(driver.__name__)
        
    return classes


def configure_storage_driver(driver_name, index=False, force_index=False, config_path=CONFIG_PATH):
    """
    Instruct a driver to configure itself
    Return {'status': True} on success
    Return {'error': '...', 'status': False} if configuration failed
    Return {'error': ...} if we couldn't call the driver configuration method
    """
    global storage_handlers

    conf = get_config(config_path)
    assert conf

    # find storage handler 
    for driver in storage_handlers:
        if driver.__name__ == driver_name:
            res = driver.storage_init(conf, index=index, force_index=force_index)
            if not res:
                log.error("Failed to configure {}".format(driver_name))
                return {'error': 'Failed to configure driver', 'status': False}

            return {'status': True}

    log.error("No such driver {}".format(driver_name))
    return {'error': 'No such driver'}


def get_immutable_data(data_hash, data_url=None, hash_func=get_data_hash, fqu=None,
                       data_id=None, zonefile=False, drivers=None):
    """
    Given the hash of the data, go through the list of
    immutable data handlers and look it up.

    Optionally pass the fully-qualified name (@fqu), human-readable data ID (data_id),
    and whether or not this is a zonefile request (zonefile) as hints to the driver.

    Return the data (as a dict) on success.
    Return None on failure
    """

    global storage_handlers
    if len(storage_handlers) == 0:
        log.warn('No storage handlers registered')
        return None

    handlers_to_use = []
    if drivers is None:
        handlers_to_use = storage_handlers
    else:
        # whitelist of drivers to try
        for d in drivers:
            handlers_to_use.extend(
                h for h in storage_handlers if h.__name__ == d
            )

    log.debug('get_immutable {}'.format(data_hash))

    for handler in [data_url] + handlers_to_use:
        if handler is None:
            continue

        data, data_dict = None, None

        if handler == data_url:
            # url hint
            try:
                # assume it's something we can urlopen
                urlh = urllib2.urlopen(data_url)
                data = urlh.read()
                urlh.close()
            except Exception as e:
                log.exception(e)
                msg = 'Failed to load profile from "{}"'
                log.error(msg.format(data_url))
                continue
        else:
            # handler
            if not getattr(handler, 'get_immutable_handler', None):
                msg = 'No method: {}.get_immutable_handler({})'
                log.debug(msg.format(handler, data_hash))
                continue

            log.debug('Try {} ({})'.format(handler.__name__, data_hash))
            try:
                data = handler.get_immutable_handler(
                    data_hash, data_id=data_id, zonefile=zonefile, fqu=fqu
                )
            except Exception as e:
                log.exception(e)
                msg = 'Method failed: {}.get_immutable_handler({})'
                log.debug(msg.format(handler, data_hash))
                continue

        if data is None:
            msg = 'No data: {}.get_immutable_handler({})'
            log.debug(msg.format(handler.__name__, data_hash))
            continue

        # validate
        dh = hash_func(data)
        if dh != data_hash:
            # nope
            if handler == data_url:
                msg = 'Invalid data hash from "{}"'
                log.error(msg.format(data_url))
            else:
                msg = 'Invalid data hash from {}.get_immutable_handler'
                log.error(msg.format(handler.__name__))

            continue

        log.debug('loaded {} with {}'.format(data_hash, handler.__name__))
        return data

    return None


def get_drivers_for_url(url):
    """
    Which drivers can handle this url?
    Return the list of loaded driver modules
    """
    global storage_drivers
    ret = []

    for h in storage_handlers:
        if not getattr(h, 'handles_url', None):
            continue

        if h.handles_url(url):
            ret.append(h)

    return ret


def get_driver_urls( fq_data_id, storage_drivers ):
    """
    Get the list of URLs for a particular datum
    """
    ret = []
    for sh in storage_drivers:
        if not getattr(sh, 'make_mutable_url', None):
            continue
        
        ret.append( sh.make_mutable_url(fq_data_id) )

    return ret


def get_mutable_data(fq_data_id, data_pubkey, urls=None, data_address=None, data_hash=None,
                     owner_address=None, blockchain_id=None, drivers=None, decode=True, bsk_version=None, return_public_key=False):
    """
    Low-level call to get mutable data, given a fully-qualified data name.
    
    if decode is False, then data_pubkey, data_address, and owner_address are not needed and raw bytes will be returned.
    if return_public_key is True, and resolution succeeds, then return {'data': ..., 'public_key': ...} instead of the data.

    Return:
    * a dict containing the profile if profile=True and this was a profile
    * a dict {'data': {...profile dict...}, 'public_key': ...} if profile=True and return_public_key=True
    * a dict {'data': "...", 'public_key': ...} if profile=False and return_public_key=True
    * a byte string if profile=False and return_public_key=False

    Return None on error
    """

    global storage_handlers

    # fully-qualified username hint
    fqu = None
    if blockchain_id is not None:
        fqu = blockchain_id

    handlers_to_use = []
    if drivers is None:
        handlers_to_use = storage_handlers
    else:
        # whitelist of drivers to try
        for d in drivers:
            handlers_to_use.extend(
                h for h in storage_handlers if h.__name__ == d
            )

    # ripemd160(sha256(pubkey))
    data_pubkey_hashes = []
    for a in filter(lambda x: x is not None, [data_address, owner_address]):
        try:
            h = keylib.b58check.b58check_decode(str(a)).encode('hex')
            data_pubkey_hashes.append(h)
        except:
            log.debug("Invalid address '{}'".format(a))
            continue

    log.debug('get_mutable_data {} fqu={} bsk_version={}'.format(fq_data_id, fqu, bsk_version))
    for storage_handler in handlers_to_use:
        if not getattr(storage_handler, 'get_mutable_handler', None):
            continue

        # which URLs to attempt?
        try_urls = []
        if urls is None:
            # make one on-the-fly
            if not getattr(storage_handler, 'make_mutable_url', None):
                msg = 'Storage handler {} does not support `{}`'
                log.warning(msg.format(storage_handler.__name__, 'make_mutable_url'))
                continue

            new_url = None

            try:
                new_url = storage_handler.make_mutable_url(fq_data_id)
                log.debug("{} available at {}".format(fq_data_id, new_url))
            except Exception as e:
                log.exception(e)
                continue

            if new_url is None:
                log.debug("Cannot use {} to generate a URL for {}".format(storage_handler.__name__, fq_data_id))
                continue

            try_urls = [new_url]

        else:
            # find the set that this handler can manage
            for url in urls:
                if not getattr(storage_handler, 'handles_url', None):
                    msg = 'Storage handler {} does not support `{}`'
                    log.warning(msg.format(storage_handler.__name__, 'handles_url'))
                    continue

                if storage_handler.handles_url(url):
                    log.debug("{} supports URL {}".format(storage_handler.__name__, url))
                    try_urls.append(url)

        for url in try_urls:
            data_txt, data_res = None, None

            log.debug('Try {} ({})'.format(storage_handler.__name__, url))
            try:
                data_txt = storage_handler.get_mutable_handler(url, fqu=fqu, data_pubkey=data_pubkey, data_pubkey_hashes=data_pubkey_hashes)
            except UnhandledURLException as uue:
                # handler doesn't handle this URL
                msg = 'Storage handler {} does not handle URLs like {}'
                log.debug(msg.format(storage_handler.__name__, url))
                continue
            except Exception as e:
                log.exception(e)
                continue

            if data_txt is None:
                # no data
                msg = 'No data from {} ({})'
                log.debug(msg.format(storage_handler.__name__, url))
                continue

            # parse it, if desired
            if decode:
                data_res = None
                if data_pubkey is not None or data_address is not None or data_hash is not None:
                    data_res = parse_mutable_data(
                        data_txt, data_pubkey, public_key_hash=data_address, data_hash=data_hash, bsk_version=bsk_version, return_public_key=return_public_key
                    )

                if data_res is None and owner_address is not None:
                    data_res = parse_mutable_data(
                        data_txt, None, public_key_hash=owner_address, bsk_version=bsk_version, return_public_key=return_public_key
                    )

                if data_res is None:
                    msg = 'Unparseable data from "{}"'
                    log.error(msg.format(url))
                    continue

                msg = 'Loaded "{}" with {}'
                log.debug(msg.format(url, storage_handler.__name__))

                if BLOCKSTACK_TEST:
                    log.debug("loaded data: {}".format(data_res))

            else:
                if return_public_key:
                    data_res = {'data': data_txt, 'public_key': None}
                else:
                    data_res = data_txt

                msg = 'Fetched (but did not decode or verify) "{}" with "{}"'
                log.debug(msg.format(url, storage_handler.__name__))

            return data_res

    return None


def put_immutable_data(data_text, txid, data_hash=None, required=None, skip=None, required_exclusive=False):
    """
    Given a string of data (which can either be data or a zonefile), store it into our immutable data stores.
    Do so in a best-effort manner--this method only fails if *all* storage providers fail.

    Return the hash of the data on success
    Return None on error
    """

    global storage_handlers

    required = [] if required is None else required
    skip = [] if skip is None else skip

    if data_hash is None:
        assert data_text
        data_hash = get_data_hash(data_text)
    else:
        data_hash = str(data_hash)

    successes = 0
    required_successes = 0

    msg = 'put_immutable_data({}), required={}, skip={}'
    log.debug(msg.format(data_hash, ','.join(required), ','.join(skip)))

    for handler in storage_handlers:
        if required_exclusive and handler.__name__ not in required:
            continue
        if handler.__name__ in skip:
            log.debug("Skipping {}".format(handler.__name__))
            continue

        if not getattr(handler, 'put_immutable_handler', None):
            if handler.__name__ not in required:
                continue

            # this one failed. fatal
            log.debug("Storage provider {} is required but does not allow immutable storage".format(handler.__name__))
            return None

        rc = False

        try:
            log.debug('Try "{}"'.format(handler.__name__))
            rc = handler.put_immutable_handler(data_hash, data_text, txid)
        except Exception as e:
            log.exception(e)
            if handler.__name__ not in required:
                continue

            # fatal
            log.debug("Failed to replicate to required storage provider {}".format(handler.__name__))
            return None

        if not rc:
            log.debug('Failed to replicate with "{}"'.format(handler.__name__))
            if handler.__name__ not in required:
                continue

            # fatal
            return None

        else:
            log.debug('Replication succeeded with "{}"'.format(handler.__name__))
            successes += 1

            if handler.__name__ in required:
                required_successes += 1

    # failed everywhere or succeeded somewhere
    return None if successes == 0 and required_successes == len(set(required) - set(skip)) else data_hash


def put_mutable_data(fq_data_id, data_text_or_json, sign=True, raw=False, data_privkey=None, data_pubkey=None, data_signature=None, profile=False, blockchain_id=None, required=None, skip=None, required_exclusive=False):
    """
    Given the unserialized data, store it into our mutable data stores.
    Do so in a best-effort way.  This method fails if all storage providers fail,
    or if a storage provider in required fails.

    @required: list of required drivers to use.  All of them must succeed for this method to succeed.
    @skip: list of drivers we can skip.  None of them will be tried.
    @required_exclusive: if True, then only the required drivers will be tried (none of the loaded but not-required drivers will be invoked)
    @sign: if True, then a private key is required.  if False, then simply store the data without serializing it or including a public key and signature.
    @raw: If True, then the data will be put as-is without any ancilliary metadata.  Requires sign=False

    Return True on success
    Return False on error
    """

    global storage_handlers
    assert len(storage_handlers) > 0, "No storage handlers initialized"

    # sanity check: only take structured data if this is a profile 
    if not isinstance(data_text_or_json, (str, unicode)):
        assert profile, "Structured data is only supported when profile=True"

    required = [] if required is None else required
    skip = [] if skip is None else skip

    assert len(set(required).intersection(set(skip))) == 0, "Overlap between required and skip driver lists"

    log.debug('put_mutable_data({}), required={}, skip={} required_exclusive={}'.format(fq_data_id, ','.join(required), ','.join(skip), required_exclusive))

    # fully-qualified username hint
    fqu = None
    if blockchain_id is not None:
        fqu = blockchain_id

    # sanity check: only support single-sig private keys
    if data_privkey is not None:
        if not is_singlesig_hex(data_privkey):
            log.error('Only single-signature data private keys are supported')
            return False

        data_pubkey = get_pubkey_hex( data_privkey )

    elif sign:
        assert data_pubkey is not None
        assert data_signature is not None

    serialized_data = None
    if sign or not raw:
        serialized_data = serialize_mutable_data(data_text_or_json, data_privkey=data_privkey, data_pubkey=data_pubkey, data_signature=data_signature, profile=profile)
    else:
        serialized_data = data_text_or_json

    if BLOCKSTACK_TEST:
        log.debug("data ({}): {}".format(type(serialized_data), serialized_data))

    successes = 0
    required_successes = 0

    skipped_optionals = []

    for handler in storage_handlers:
        if handler.__name__ in skip:
            log.debug("Skipping {}: at caller's request".format(handler.__name__))
            continue

        if not getattr(handler, 'put_mutable_handler', None):
            if handler.__name__ not in required:
                log.debug("Skipping {}: it does not implement put_mutable_handler".format(handler.__name__))
                continue

            log.debug("Required storage provider {} does not implement put_mutable_handler".format(handler.__name__))
            return False

        if required_exclusive and handler.__name__ not in required:
            skipped_optionals.append(handler.__name__)
            continue

        rc = False
        log.debug('Try "{}"'.format(handler.__name__))

        try:
            rc = handler.put_mutable_handler(fq_data_id, serialized_data, fqu=fqu, profile=profile)
        except Exception as e:
            log.exception(e)
            if handler.__name__ not in required:
                continue

            log.error("Failed to replicate data with '{}'".format(handler.__name__))
            return None

        if rc:
            log.debug("Replicated {} bytes with {} (rc = {})".format(len(serialized_data), handler.__name__, rc))
            successes += 1

            if handler.__name__ in required:
                required_successes += 1

            continue

        if handler.__name__ not in required:
            log.debug('Failed to replicate with "{}"'.format(handler.__name__))
            continue

        # required driver failed
        log.error("Failed to replicate to required storage provider '{}'".format(handler.__name__))
        return False

    if len(skipped_optionals) > 1:
        log.debug("Skipped optional drivers: [{}]".format(",".join(skipped_optionals)))
    # failed everywhere or succeeded somewhere
    log.debug("put_mutable_data: successes = {}, required_successes = {}, |required - skip| = {}".format(
        successes, required_successes, len(set(required) - set(skip))
    ))

    return (successes > 0) and (required_successes >= len(set(required) - set(skip)))


def delete_immutable_data(data_hash, txid, privkey=None, signed_data_tombstone=None):
    """
    Given the hash of the data, the private key of the user,
    and the txid that deleted the data's hash from the blockchain,
    delete the data from all immutable data stores.
    """

    global storage_handlers

    # sanity check
    if not is_singlesig_hex(privkey):
        log.error('Only single-signature data private keys are supported')
        return False

    if signed_data_tombstone is None:
        assert privkey
        data_hash = str(data_hash)
        txid = str(txid)

        ts = make_data_tombstone('immutable:{}:{}'.format(data_hash, txid))
        signed_data_tombstone = sign_data_tombstone( ts, privkey )
        
    for handler in storage_handlers:
        if not getattr(handler, 'delete_immutable_handler', None):
            continue

        try:
            handler.delete_immutable_handler(data_hash, txid, signed_data_tombstone)
        except Exception as e:
            log.exception(e)
            return False

    return True


def delete_mutable_data(fq_data_id, privatekey=None, signed_data_tombstone=None, required=None, required_exclusive=False, skip=None, blockchain_id=None, profile=False):
    """
    Given the data ID and private key of a user,
    go and delete the associated mutable data.

    The fq_data_id is an opaque identifier that is prefixed with the username.
    """

    global storage_handlers
    
    assert privatekey or signed_data_tombstone

    required = [] if required is None else required
    skip = [] if skip is None else skip

    # fully-qualified username hint
    fqu = None
    if blockchain_id is not None:
        fqu = blockchain_id

    # sanity check
    if privatekey is not None and not is_singlesig_hex(privatekey):
        log.error('Only single-signature data private keys are supported')
        return False

    fq_data_id = str(fq_data_id)
    if signed_data_tombstone is None:
        assert privatekey
        ts = make_data_tombstone(fq_data_id)
        signed_data_tombstone = sign_data_tombstone(ts, privatekey)

    required_successes = 0

    # remove data
    for handler in storage_handlers:
        if handler.__name__ in skip:
            log.debug("Skipping {}".format(handler.__name__))
            continue

        if not getattr(handler, 'delete_mutable_handler', None):
            continue

        if required_exclusive and handler.__name__ not in required:
            log.debug("Skipping non-required driver {}".format(handler.__name__))
            continue

        rc = False
        try:
            rc = handler.delete_mutable_handler(fq_data_id, signed_data_tombstone, fqu=fqu, profile=profile)
        except Exception as e:
            log.exception(e)
            rc = False

        if not rc and handler.__name__ in required:
            log.error("Failed to delete from required storage driver {}".format(handler.__name__))
            return False
        
        elif handler.__name__ in required:
            required_successes += 1

    return required_successes >= len(set(required) - set(skip))


def get_announcement(announcement_hash):
    """
    Go get an announcement's text, given its hash.
    Use the blockstack client library, so we can get at
    the storage drivers for the storage systems the sender used
    to host it.

    Return the data on success
    """

    data = get_immutable_data(
        announcement_hash, hash_func=get_blockchain_compat_hash
    )

    if data is None:
        log.error('Failed to get announcement "{}"'.format(announcement_hash))
        return None

    return data


def put_announcement(announcement_text, txid):
    """
    Go put an announcement into back-end storage.
    Use the blockstack client library, so we can get at
    the storage drivers for the storage systems this host
    is configured to use.

    Return the data's hash
    """

    data_hash = get_blockchain_compat_hash(announcement_text)
    res = put_immutable_data(announcement_text, txid, data_hash=data_hash)
    if res is None:
        log.error('Failed to put announcement "{}"'.format(data_hash))
        return None

    return data_hash


def make_fq_data_id(device_id, data_id):
    """
    Make a fully-qualified data ID, prefixed by the device ID
    """
    return urllib.quote(str('{}:{}'.format(device_id, data_id).replace('/', '\\x2f')))


def parse_fq_data_id(fq_data_id):
    """
    Parse a fully-qualified data ID
    """
    fq_data_id = urllib.unquote(fq_data_id).replace('\\x2f', '/')
    parts = fq_data_id.split(":", 1)
    if len(parts) != 2:
        return None, None

    return parts[0], parts[1]
