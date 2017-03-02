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

# this module contains the high-level methods for talking to ancillary storage.

import pybitcoin
import keylib
import re
import os
import json
import hashlib
import urllib
import urllib2
import base64
import posixpath

import blockstack_zones

from binascii import hexlify

from keylib import ECPrivateKey, ECPublicKey

import blockstack_profiles

from config import get_logger
from constants import CONFIG_PATH, BLOCKSTACK_TEST, BLOCKSTACK_DEBUG
from scripts import is_name_valid
import schemas
from keys import *

log = get_logger()

import string

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
    return pybitcoin.hex_hash160(data_txt)


def get_blockchain_compat_hash(data_txt):
    """
    Generate a hash suitable for embedding into
    the blockchain (e.g. for user zonefiles and
    announcements).
    """
    return pybitcoin.hex_hash160(data_txt)


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


def serialize_mutable_data(data_text_or_json, privatekey_hex, pubkey_hex, profile=False):
    """
    Generate a serialized mutable data record from the given information.
    Sign it with privatekey.

    Return the serialized data (as a string) on success
    """
  
    if profile:
        # profiles must conform to a particular standard format
        tokenized_data = blockstack_profiles.sign_token_records(
            [data_text_or_json], privatekey_hex
        )

        del tokenized_data[0]['decodedToken']

        serialized_data = json.dumps(tokenized_data, sort_keys=True)
        return serialized_data
    
    else:
        # version 2 format for mutable data
        data_text_or_json = str(data_text_or_json)
        data_sig = sign_raw_data(data_text_or_json, privatekey_hex)

        # make sure it's compressed
        pubkey_hex_compressed = keylib.key_formatting.compress(pubkey_hex)
        res = "bsk2.{}.{}.{}".format(pubkey_hex_compressed, base64.b64encode(data_sig), data_text_or_json)

        return res


def parse_mutable_data_v2(mutable_data_json_txt, public_key_hex, public_key_hash=None, data_hash=None):
    """
    Version 2 parser
    Parse a piece of mutable data back into the serialized payload.
    Verify that it was signed by the given public key, or the public key hash.
    If neither are given, then verify that it has the given hash.
    Return the data on success
    Return None on error
    """

    parts = mutable_data_json_txt.split(".", 2)
    if len(parts) != 3:
        log.debug("Malformed data: {}".format(mutable_data_json_txt))
        return None 

    pubk_hex = str(parts[0])
    sig_b64 = str(parts[1])
    data_txt = str(parts[2])

    if not re.match('^[0-9a-fA-F]+$', pubk_hex):
        log.debug("Not a v2 mutable datum: Invalid public key")
        return None 

    if not re.match(schemas.OP_BASE64_PATTERN_SECTION, sig_b64):
        log.debug("Not a v2 mutable datum: Invalid signature data")
        return None

    # shortcut: if hash is given, we're done 
    if data_hash is not None:
        dh = hashlib.sha256(data_txt.encode('utf-8')).hexdigest()
        if dh == data_hash:
            # done!
            log.debug("Verified with hash {}".format(data_hash))
            return data_txt

        else:
            log.debug("Hash mismatch: expected {}, got {}".format(data_hash, dh))

    # validate 
    if keylib.key_formatting.get_pubkey_format(pubk_hex) == 'hex_compressed':
        pubk_hex = keylib.key_formatting.decompress(pubk_hex)

    try:
        sig_bin = base64.b64decode(sig_b64)
    except:
        log.error("Incorrect base64-encoding")
        return None

    if public_key_hex is not None:
        # make sure uncompressed
        given_pubkey_hex = str(public_key_hex)
        if keylib.key_formatting.get_pubkey_format(given_pubkey_hex) == 'hex_compressed':
            given_pubkey_hex = keylib.key_formatting.decompress(given_pubkey_hex)

        log.debug("Try verify with {}".format(pubk_hex))

        if given_pubkey_hex == pubk_hex:
            if verify_raw_data(data_txt, pubk_hex, sig_bin):
                log.debug("Verified with public key {}".format(pubk_hex))
                return data_txt
            else:
                log.debug("Signature failed")

        else:
            log.debug("Public key mismatch: {} != {}".format(given_pubkey_hex, pubk_hex))

    if public_key_hash is not None:
        pubkey_hash = keylib.address_formatting.bin_hash160_to_address(
                keylib.address_formatting.address_to_bin_hash160(
                    str(public_key_hash),
                ),
                version_byte=0
        )

        log.debug("Try verify with {}".format(pubkey_hash))

        if keylib.public_key_to_address(pubk_hex) == pubkey_hash:
            if verify_raw_data(data_txt, pubk_hex, sig_bin):
                log.debug("Verified with public key hash {} ({})".format(pubk_hex, pubkey_hash))
                return data_txt
            else:
                log.debug("Signature failed with pubkey hash")

        else:
            log.debug("Public key hash mismatch")

    log.debug("Failed to verify v2 mutable datum")
    return None


def parse_mutable_data(mutable_data_json_txt, public_key, public_key_hash=None, data_hash=None):
    """
    Given the serialized JSON for a piece of mutable data,
    parse it into a JSON document.  Verify that it was
    signed by public_key's or public_key_hash's private key.

    Try to verify with both keys, if given.

    Return the parsed JSON dict on success
    Return None on error
    """
    
    # newer version?
    if mutable_data_json_txt.startswith("bsk2."):
        mutable_data_json_txt = mutable_data_json_txt[len("bsk2."):]
        return parse_mutable_data_v2(mutable_data_json_txt, public_key, public_key_hash=public_key_hash, data_hash=data_hash)
        
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
        'delete_mutable_handler'
    ]

    for expected_method in expected_methods:
        if not getattr(storage_impl, expected_method, None):
            msg = 'Storage implementation is missing a "{}" method'
            log.warning(msg.format(expected_method))

    return True


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
        log.debug('No storage handlers registered')
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


def get_file_hash( fd, hashfunc, fd_len=None ):
    """
    Get the hex-encoded hash of the fd's data
    """

    h = hashfunc()
    fd.seek(0, os.SEEK_SET)

    count = 0
    while True:
        buf = fd.read(65536)
        if len(buf) == 0:
            break

        if fd_len is not None:
            if count + len(buf) > fd_len:
                buf = buf[:fd_len - count]

        h.update(buf)
        count += len(buf)

    hashed = h.hexdigest()
    return hashed


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
                     owner_address=None, blockchain_id=None, drivers=None, decode=True):
    """
    Low-level call to get mutable data, given a fully-qualified data name.
    
    if decode is False, then data_pubkey, data_address, and owner_address are not needed and raw bytes will be returned.

    Return a mutable data dict on success (or raw bytes if decode=False)
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

    log.debug('get_mutable_data {} fqu={}'.format(fq_data_id, fqu))
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
                    try_urls.append(url)

        for url in try_urls:
            data_txt, data = None, None

            log.debug('Try {} ({})'.format(storage_handler.__name__, url))
            try:
                data_txt = storage_handler.get_mutable_handler(url, fqu=fqu)
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
                data = None
                if data_pubkey is not None or data_address is not None or data_hash is not None:
                    data = parse_mutable_data(
                        data_txt, data_pubkey, public_key_hash=data_address, data_hash=data_hash
                    )

                if data is None and owner_address is not None:
                    data = parse_mutable_data(
                        data_txt, None, public_key_hash=owner_address
                    )

                if data is None:
                    msg = 'Unparseable data from "{}"'
                    log.error(msg.format(url))
                    continue

                msg = 'Loaded "{}" with {}'
                log.debug(msg.format(url, storage_handler.__name__))

                if BLOCKSTACK_TEST:
                    log.debug("loaded data: {}".format(data))

            else:
                data = data_txt
                msg = 'Fetched (but did not decode) "{}" with "{}"'
                log.debug(msg.format(url, storage_handler.__name__))

            return data

    return None


def serialize_immutable_data(data_json):
    """
    Serialize a piece of immutable data
    """
    msg = 'Invalid immutable data: must be a dict or list(got type {})'
    assert isinstance(data_json, (dict, list)), msg.format(type(data_json))
    return json.dumps(data_json, sort_keys=True)


def put_immutable_data(data_json, txid, data_hash=None, data_text=None, required=None, skip=None):
    """
    Given a string of data (which can either be data or a zonefile), store it into our immutable data stores.
    Do so in a best-effort manner--this method only fails if *all* storage providers fail.

    Return the hash of the data on success
    Return None on error
    """

    global storage_handlers

    required = [] if required is None else required
    skip = [] if skip is None else skip

    data_checks = (
        (data_hash is None and data_text is None and data_json is not None) or
        (data_hash is not None and data_text is not None)
    )

    assert data_checks, 'Need data hash and text, or just JSON'

    if data_text is None:
        data_text = serialize_immutable_data(data_json)

    if data_hash is None:
        data_hash = get_data_hash(data_text)
    else:
        data_hash = str(data_hash)

    successes = 0
    msg = 'put_immutable_data({}), required={}, skip={}'
    log.debug(msg.format(data_hash, ','.join(required), ','.join(skip)))

    for handler in storage_handlers:
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

    # failed everywhere or succeeded somewhere
    return None if successes == 0 else data_hash


def put_mutable_data(fq_data_id, data_text_or_json, privatekey_hex, profile=False, blockchain_id=None, required=None, skip=None, required_exclusive=False):
    """
    Given the unserialized data, store it into our mutable data stores.
    Do so in a best-effort way.  This method fails if all storage providers fail,
    or if a storage provider in required fails.

    Return True on success
    Return False on error
    """

    global storage_handlers

    required = [] if required is None else required
    skip = [] if skip is None else skip

    # fully-qualified username hint
    fqu = None
    if blockchain_id is not None:
        fqu = blockchain_id

    # sanity check: only support single-sig private keys
    if not is_singlesig_hex(privatekey_hex):
        log.error('Only single-signature data private keys are supported')
        return False

    assert privatekey_hex is not None
    pubkey_hex = get_pubkey_hex( privatekey_hex )
    serialized_data = serialize_mutable_data(data_text_or_json, privatekey_hex, pubkey_hex, profile=profile)
    
    successes = 0

    log.debug('put_mutable_data({}), required={}, skip={} required_exclusive={}'.format(fq_data_id, ','.join(required), ','.join(skip), required_exclusive))
    if BLOCKSTACK_TEST:
        log.debug("data: {}".format(serialized_data))

    fail_msg = 'Failed to replicate with required storage provider "{}"'

    for handler in storage_handlers:
        if handler.__name__ in skip:
            log.debug("Skipping {}".format(handler.__name__))
            continue

        if not getattr(handler, 'put_mutable_handler', None):
            if handler.__name__ not in required:
                continue

            log.debug("Storage provider {} does not implement mutable storage".format(handler.__name__))
            return None

        if required_exclusive and handler.__name__ not in required:
            log.debug("Skipping non-required driver {}".format(handler.__name__))
            continue

        rc = False

        try:
            log.debug('Try "{}"'.format(handler.__name__))
            rc = handler.put_mutable_handler(fq_data_id, serialized_data, fqu=fqu)
        except Exception as e:
            log.exception(e)
            if handler.__name__ not in required:
                continue

            log.error(fail_msg.format(handler.__name__))
            return None

        if rc:
            log.debug("Replicated {} bytes with {}".format(len(serialized_data), handler.__name__))
            successes += 1
            continue

        if handler.__name__ not in required:
            log.debug('Failed to replicate with "{}"'.format(handler.__name__))
            continue

        log.error(fail_msg.format(handler.__name__))
        return None

    # failed everywhere or succeeded somewhere
    return (successes > 0)


def delete_immutable_data(data_hash, txid, privkey):
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

    data_hash = str(data_hash)
    txid = str(txid)
    sigb64 = sign_raw_data("delete:" + data_hash + txid, privkey)

    for handler in storage_handlers:
        if not getattr(handler, 'delete_immutable_handler', None):
            continue

        try:
            handler.delete_immutable_handler(data_hash, txid, sigb64)
        except Exception as e:
            log.exception(e)
            return False

    return True


def delete_mutable_data(fq_data_id, privatekey, required=None, required_exclusive=False, skip=None, blockchain_id=None, profile=False):
    """
    Given the data ID and private key of a user,
    go and delete the associated mutable data.

    The fq_data_id is an opaque identifier that is prefixed with the username.
    """

    global storage_handlers

    required = [] if required is None else required
    skip = [] if skip is None else skip

    # fully-qualified username hint
    fqu = None
    if blockchain_id is not None:
        fqu = blockchain_id

    # sanity check
    if not is_singlesig_hex(privatekey):
        log.error('Only single-signature data private keys are supported')
        return False

    fq_data_id = str(fq_data_id)
    sigb64 = sign_raw_data("delete:" + fq_data_id, privatekey)

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
            rc = handler.delete_mutable_handler(fq_data_id, sigb64, fqu=fqu, profile=profile)
        except Exception as e:
            log.exception(e)
            rc = False

        if not rc and handler.__name__ in required:
            log.error("Failed to delete from required storage driver {}".format(handler.__name__))
            return False

    return True


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
    res = put_immutable_data(
        None, txid, data_hash=data_hash, data_text=announcement_text
    )

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
