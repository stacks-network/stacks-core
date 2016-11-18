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
import bitcoin
import re
import json
import hashlib
import urllib
import urllib2
import ecdsa
import blockstack_zones

import blockstack_profiles

from config import get_logger
from constants import CONFIG_PATH, BLOCKSTACK_TEST
from scripts import is_name_valid
import keys

log = get_logger()

import string

B40_CHARS = string.digits + string.lowercase + '-_.+'
B40_CLASS = '[a-z0-9\-_.+]'
B40_NO_PERIOD_CLASS = '[a-z0-9\-_+]'
B40_REGEX = '^{}*$'.format(B40_CLASS)
URLENCODED_CLASS = '[a-zA-Z0-9\-_.~%]'

# global list of registered data handlers
storage_handlers = []


class UnhandledURLException(Exception):
    def __init__(self, url):
        super(UnhandledURLException, self).__init__()
        self.unhandled_url = url


def is_valid_hash(value):
    """
    Is this string a valid 32-byte hash?
    """
    if not isinstance(value, (str, unicode)):
        return False

    strvalue = str(value)

    if re.match(r'^[a-fA-F0-9]+$', strvalue) is None:
        return False

    return len(strvalue) == 64


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

    msg = 'Comparing zonefile hashes: expected {}, got {}'
    log.debug(msg.format(value_hash, zonefile_hash))

    return zonefile_hash == value_hash


def get_storage_handlers():
    """
    Get the list of loaded storage handler instances
    """
    global storage_handlers
    return storage_handlers


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


def serialize_mutable_data(data_json, privatekey):
    """
    Generate a serialized mutable data record from the given information.
    Sign it with privatekey.

    Return the serialized data (as a string) on success
    """

    tokenized_data = blockstack_profiles.sign_token_records(
        [data_json], privatekey
    )

    del tokenized_data[0]['decodedToken']

    serialized_data = json.dumps(tokenized_data, sort_keys=True)
    return serialized_data


def parse_mutable_data(mutable_data_json_txt, public_key, public_key_hash=None):
    """
    Given the serialized JSON for a piece of mutable data,
    parse it into a JSON document.  Verify that it was
    signed by public_key's or public_key_hash's private key.

    Try to verify with both keys, if given.

    Return the parsed JSON dict on success
    Return None on error
    """

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
            mutable_data_jwt, public_key
        )

        if len(mutable_data_json) > 0:
            return mutable_data_json

        msg = 'Failed to verify with public key "{}"'
        log.warn(msg.format(public_key))

    # try pubkey address
    if public_key_hash is not None:
        # NOTE: these should always have version byte 0
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
                       data_id=None, zonefile=False, deserialize=True, drivers=None):
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

        if not deserialize:
            data_dict = data
        else:
            # deserialize
            try:
                data_dict = json.loads(data)
            except ValueError:
                log.error('Invalid JSON for {}'.format(data_hash))
                continue

        log.debug('loaded {} with {}'.format(data_hash, handler.__name__))
        return data_dict

    return None


def sign_raw_data(raw_data, privatekey):
    """
    Sign a string of data.
    Returns signature as a base64 string
    """
    data_hash = get_data_hash(raw_data)

    pk = ECPrivateKey(privatekey)
    pk_hex = pk.to_hex()

    # force uncompressed
    if len(pk_hex) > 64:
        pk = ECPrivateKey(privkey[:64])
    
    priv = pk.to_hex()
    pub = pk.public_key().to_hex()

    assert len(pub[2:].decode('hex')) == ecdsa.SECP256k1.verifying_key_len, "BUG: Invalid key decoding"
 
    sk = ecdsa.SigningKey.from_string(priv.decode('hex'), curve=ecdsa.SECP256k1)
    sig_bin = sk.sign_digest(data_hash.decode('hex'), sigencode=ecdsa.util.sigencode_der)
    
    # enforce low-s
    sig_r, sig_s = ecdsa.util.sigdecode_der( sig_bin, ecdsa.SECP256k1.order )
    if sig_s * 2 >= ecdsa.SECP256k1.order:
        log.debug("High-S to low-S")
        sig_s = ecdsa.SECP256k1.order - sig_s

    sig_bin = ecdsa.util.sigencode_der( sig_r, sig_s, ecdsa.SECP256k1.order )

    # sanity check 
    vk = ecdsa.VerifyingKey.from_string(pub[2:].decode('hex'), curve=ecdsa.SECP256k1)
    assert vk.verify_digest(sig_bin, data_hash.decode('hex'), sigdecode=ecdsa.util.sigdecode_der), "Failed to verify signature ({}, {})".format(sig_r, sig_s)

    return base64.b64encode( bitcoin.encode_sig( None, sig_r, sig_s ).decode('hex') )


def secp256k1_compressed_pubkey_to_uncompressed_pubkey( pubkey ):
    """
    convert a secp256k1 compressed public key into an uncompressed public key.
    taken from https://bitcointalk.org/index.php?topic=644919.msg7205689#msg7205689
    """
    pubk = ECPublicKey(pubkey).to_hex()

    assert len(pubk) == 66, "Not a compressed hex public key"

    def pow_mod(x, y, z):
        "Calculate (x ** y) % z efficiently."
        number = 1
        while y:
            if y & 1:
                number = number * x % z
            y >>= 1
            x = x * x % z
        return number
    
    p = ecdsa.SECP256k1.curve.p()
    b = ecdsa.SECP256k1.curve.b()
    y_parity = int(pubk[:2]) - 2
    x = int(pubk[2:], 16)
    a = (pow_mod(x, 3, p) + b) % p
    y = pow_mod(a, (p+1)//4, p)
    if y % 2 != y_parity:
        y = -y % p

    uncompressed_pubk = '04{:x}{:x}'.format(x, y)
    return uncompressed_pubk


def verify_raw_data(raw_data, pubkey, sigb64):
    """
    Verify the signature over a string, given the public key
    and base64-encode signature.
    Return True on success.
    Return False on error.
    """

    data_hash = get_data_hash(raw_data)
    pubk = ECPublicKey(pubkey).to_hex()
    if len(pubk) == 66:
        pubk = secp256k1_compressed_pubkey_to_uncompressed_pubkey( pubkey )

    sig_bin = base64.b64decode(sigb64)
    vk = ecdsa.VerifyingKey.from_string( pubk[2:].decode('hex'), curve=ecdsa.SECP256k1 )
    return vk.verify_digest(sig_bin, data_hash.decode('hex'), sigdecode=ecdsa.util.sigdecode_der)


def get_drivers_for_url(url):
    """
    Which drivers can handle this url?
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


def get_mutable_data(fq_data_id, data_pubkey, urls=None, data_address=None,
                     owner_address=None, drivers=None, decode=True):
    """
    Low-level call to get mutable data, given a fully-qualified data name.

    @fq_data_id is either a username, or username:mutable_data_name

    The mutable_data_name field is an opaque name.

    Return a mutable data dict on success
    Return None on error
    """

    global storage_handlers

    fq_data_id = str(fq_data_id)
    msg = 'Need either a fully-qualified data ID or a blockchain ID: "{}"'
    assert is_fq_data_id(fq_data_id) or is_name_valid(fq_data_id), msg.format(fq_data_id)

    fqu = None
    if is_fq_data_id(fq_data_id):
        fqu = fq_data_id.split(':')[0]
    else:
        fqu = fq_data_id

    handlers_to_use = []
    if drivers is None:
        handlers_to_use = storage_handlers
    else:
        # whitelist of drivers to try
        for d in drivers:
            handlers_to_use.extend(
                h for h in storage_handlers if h.__name__ == d
            )

    log.debug('get_mutable {}'.format(fq_data_id))
    for storage_handler in handlers_to_use:
        if not getattr(storage_handler, 'get_mutable_handler', None):
            continue

        # which URLs to attempt?
        try_urls = []
        msg = 'Storage handler {} does not support `{}`'
        if urls is None:
            # make one on-the-fly
            if not getattr(storage_handler, 'make_mutable_url', None):
                log.warning(msg.format(storage_handler.__name__, 'make_mutable_url'))
                continue

            new_url = None

            try:
                new_url = storage_handler.make_mutable_url(fq_data_id)
            except Exception as e:
                log.exception(e)
                continue

            try_urls = [new_url]
        else:
            # find the set that this handler can manage
            for url in urls:
                if not getattr(storage_handler, 'handles_url', None):
                    log.warning(msg.format(storage_handler.__name__, 'handles_url'))
                    continue

                if storage_handler.handles_url(url):
                    try_urls.append(url)

        for url in try_urls:
            data_json, data = None, None

            log.debug('Try {} ({})'.format(storage_handler.__name__, url))
            try:
                data_json = storage_handler.get_mutable_handler(url, fqu=fqu)
            except UnhandledURLException as uue:
                # handler doesn't handle this URL
                msg = 'Storage handler {} does not handle URLs like {}'
                log.debug(msg.format(storage_handler.__name__, url))
                continue
            except Exception as e:
                log.exception(e)
                continue

            if data_json is None:
                # no data
                msg = 'No data from {} ({})'
                log.debug(msg.format(storage_handler.__name__, url))
                continue

            # parse it, if desired
            if decode:
                data = parse_mutable_data(
                    data_json, data_pubkey, public_key_hash=data_address
                )

                if data is None:
                    # maybe try owner address?
                    if owner_address is not None:
                        data = parse_mutable_data(
                            data_json, data_pubkey, public_key_hash=owner_address
                        )

                    if data is None:
                        msg = 'Unparseable data from "{}"'
                        log.error(msg.format(url))
                        continue

                msg = 'Loaded "{}" with {}'
                log.debug(msg.format(url, storage_handler.__name__))
            else:
                data = data_json
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


def put_immutable_data(data_json, txid, data_hash=None, data_text=None, required=None):
    """
    Given a string of data (which can either be data or a zonefile), store it into our immutable data stores.
    Do so in a best-effort manner--this method only fails if *all* storage providers fail.

    Return the hash of the data on success
    Return None on error
    """

    global storage_handlers

    required = [] if required is None else required

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
    msg = 'put_immutable_data({}), required={}'
    log.debug(msg.format(data_hash, ','.join(required)))

    for handler in storage_handlers:
        if not getattr(handler, 'put_immutable_handler', None):
            if handler.__name__ not in required:
                continue

            # this one failed. fatal
            msg = 'Failed to replicate to required storage provider "{}"'
            log.debug(msg.format(handler.__name__))
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
            msg = 'Failed to replicate to required storage provider "{}"'
            log.debug(msg.format(handler.__name__))
            return None

        if not rc:
            log.debug('Failed to replicate with "{}"'.format(handler.__name__))
        else:
            log.debug('Replication succeeded with "{}"'.format(handler.__name__))
            successes += 1

    # failed everywhere or succeeded somewhere
    return None if not successes else data_hash


def put_mutable_data(fq_data_id, data_json, privatekey, required=None, use_only=None):
    """
    Given the unserialized data, store it into our mutable data stores.
    Do so in a best-effort way.  This method only fails if all storage providers fail.

    @fq_data_id is the fully-qualified data id.  It must be prefixed with the username,
    to avoid collisions in shared mutable storage.
    i.e. the format is either `username` or `username:mutable_data_name`

    The mutable_data_name field is an opaque string.

    Return True on success
    Return False on error
    """

    global storage_handlers

    required = [] if required is None else required
    use_only = [] if use_only is None else use_only

    # sanity check: only support single-sig private keys
    if not keys.is_singlesig(privatekey):
        log.error('Only single-signature data private keys are supported')
        return False

    fq_data_id = str(fq_data_id)
    msg = 'Data ID must be fully qualified or must be a valid blockchain ID (got {})'
    assert is_fq_data_id(fq_data_id) or is_name_valid(fq_data_id), msg.format(fq_data_id)
    assert privatekey is not None

    fqu = fq_data_id.split(':')[0] if is_fq_data_id(fq_data_id) else fq_data_id

    serialized_data = serialize_mutable_data(data_json, privatekey)
    successes = 0

    log.debug('put_mutable_data({}), required={}'.format(fq_data_id, ','.join(required)))

    msg = 'Failed to replicate with required storage provider "{}"'
    for handler in storage_handlers:
        if not getattr(handler, 'put_mutable_handler', None):
            if handler.__name__ not in required:
                continue

            log.debug(msg.format(handler.__name__))
            return None

        if use_only and handler.__name__ not in use_only:
            log.debug('Skipping storage driver "{}"'.format(handler.__name__))
            continue

        rc = False

        try:
            log.debug('Try "{}"'.format(handler.__name__))
            rc = handler.put_mutable_handler(fq_data_id, serialized_data, fqu=fqu)
        except Exception as e:
            log.exception(e)
            if handler.__name__ not in required:
                continue

            log.debug(msg.format(handler.__name__))
            return None

        if rc:
            successes += 1
            continue

        if handler.__name__ not in required:
            log.debug('Failed to replicate with "{}"'.format(handler.__name__))
            continue

        log.debug(msg.format(handler.__name__))
        return None

    # failed everywhere or succeeded somewhere
    return bool(successes)


def delete_immutable_data(data_hash, txid, privkey):
    """
    Given the hash of the data, the private key of the user,
    and the txid that deleted the data's hash from the blockchain,
    delete the data from all immutable data stores.
    """

    global storage_handlers

    # sanity check
    if not keys.is_singlesig(privkey):
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


def delete_mutable_data(fq_data_id, privatekey, only_use=None):
    """
    Given the data ID and private key of a user,
    go and delete the associated mutable data.

    The fq_data_id is an opaque identifier that is prefixed with the username.
    """

    global storage_handlers

    only_use = [] if only_use is None else only_use

    # sanity check
    if not keys.is_singlesig(privatekey):
        log.error('Only single-signature data private keys are supported')
        return False

    fq_data_id = str(fq_data_id)
    msg = 'Data ID must be fully qualified or must be a valid blockchain ID (got {})'
    assert is_fq_data_id(fq_data_id) or is_name_valid(fq_data_id), msg.format(fq_data_id)

    sigb64 = sign_raw_data("delete:" + fq_data_id, privatekey)

    # remove data
    for handler in storage_handlers:
        if not getattr(handler, 'delete_mutable_handler', None):
            continue

        if only_use and handler.__name__ in only_use:
            log.debug('Skip storage driver {}'.format(handler.__name__))
            continue

        try:
            handler.delete_mutable_handler(fq_data_id, sigb64)
        except Exception as e:
            log.exception(e)
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
        announcement_hash, hash_func=get_blockchain_compat_hash, deserialize=False
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


def make_fq_data_id(name, data_id):
    """
    Make a fully-qualified data ID, prefixed by the name.
    """
    return str('{}:{}'.format(name, data_id))


def is_fq_data_id(fq_data_id):
    """
    Is a data ID is fully qualified?
    """
    if len(fq_data_id.split(':')) < 2:
        return False

    # name must be valid
    name = fq_data_id.split(':')[0]

    return is_name_valid(name)


def blockstack_mutable_data_url(blockchain_id, data_id, version):
    """
    Make a blockstack:// URL for mutable data
    """
    if version is None:
        return 'blockstack://{}/{}'.format(
            urllib.quote(blockchain_id), urllib.quote(data_id)
        )

    if not isinstance(version, (int, long)):
        raise ValueError('Verison must be an int or long')

    return 'blockstack://{}/{}#{}'.format(
        urllib.quote(blockchain_id), urllib.quote(data_id), str(version)
    )


def blockstack_immutable_data_url(blockchain_id, data_id, data_hash):
    """
    Make a blockstack:// URL for immutable data
    """
    if data_hash is not None and not is_valid_hash(data_hash):
        raise ValueError('Invalid hash: {}'.format(data_hash))

    if data_hash is not None:
        return 'blockstack://{}.{}/#{}'.format(
            urllib.quote(data_id), urllib.quote(blockchain_id), data_hash
        )

    return 'blockstack://{}.{}'.format(
        urllib.quote(data_id), urllib.quote(blockchain_id)
    )


def blockstack_app_data_url(blockchain_id, service_id, account_id, data_id, version):
    """
    Make a blockstack:// URL for application data
    """
    if version is None:
        return 'blockstack://{}.{}@{}/{}'.format(
            urllib.quote(account_id), urllib.quote(service_id),
            urllib.quote(blockchain_id), urllib.quote(data_id)
        )

    if not isinstance(version, (int, long)):
        raise ValueError('Version must be an int or a long')

    # don't allow periods in the service ID
    service_id = service_id.replace('.', '\\x2e')

    # don't allow '@' in either the service or account IDs
    service_id = service_id.replace('@', '\\x40')
    account_id = account_id.replace('@', '\\x40')

    return 'blockstack://{}.{}@{}/{}#{}'.format(
        urllib.quote(account_id), urllib.quote(service_id),
        urllib.quote(blockchain_id), urllib.quote(data_id), str(version)
    )


def blockstack_mutable_data_url_parse(url):
    """
    Parse a blockstack:// URL for mutable data
    Return (blockchain ID, data ID, data version, account ID, service ID) on success
    * The version may be None if not given (in which case, the latest value is requested).
    * The data ID may be None, in which case, a listing of mutable data is requested.
    * account ID and service ID will be None for mutable data in the profile, but will be defined for app-specific mutable data

    Raise on bad data
    """

    url = str(url)
    mutable_url_data_regex = r'blockstack://({}+)[/]+({}+)(#[0-9]+)?'.format(B40_CLASS, URLENCODED_CLASS)
    app_url_data_regex = r'blockstack://({}+)\.({}+)@({}+)[/]+({}+)(#[0-9]+)?'.format(
        URLENCODED_CLASS, URLENCODED_CLASS, B40_CLASS, URLENCODED_CLASS
    )
    mutable_url_listing_regex = r'blockstack://({}+)[/]+#mutable'.format(B40_CLASS)

    blockchain_id, data_id, version = None, None, None

    # app?
    m = re.match(app_url_data_regex, url)
    if m:
        account_id, service_id, blockchain_id, data_id, version = m.groups()
        if not is_name_valid(blockchain_id):
            raise ValueError('Invalid blockchain ID "{}"'.format(blockchain_id))

        # version?
        if version is not None:
            version = version.strip('#')
            version = int(version)

        return (
            urllib.unquote(blockchain_id), urllib.unquote(data_id),
            version, urllib.unquote(account_id), urllib.unquote(service_id)
        )

    # mutable?
    m = re.match(mutable_url_data_regex, url)
    if m:

        blockchain_id, data_id, version = m.groups()
        if not is_name_valid(blockchain_id):
            raise ValueError('Invalid blockchain ID "{}"'.format(blockchain_id))

        # version?
        if version is not None:
            version = version.strip('#')
            version = int(version)

        return urllib.unquote(blockchain_id), urllib.unquote(data_id), version, None, None
    else:
        # maybe a listing?
        m = re.match(mutable_url_listing_regex, url)
        if not m:
            raise ValueError('Invalid URL: {}'.format(url))

        blockchain_id = m.groups()[0]
        return urllib.unquote(blockchain_id), None, None, None, None

    return [None] * 5


def blockstack_immutable_data_url_parse(url):
    """
    Parse a blockstack:// URL for immutable data
    Return (blockchain ID, data ID, data hash)
    * The hash may be None if not given, in which case, the hash should be looked up from the blockchain ID's profile.
    * The data ID may be None, in which case, the list of immutable data is requested.

    Raise on bad data
    """

    url = str(url)
    immutable_data_regex = r'blockstack://({}+)\.({}+)\.({}+)([/]+#[a-fA-F0-9]+)?'.format(
        URLENCODED_CLASS, B40_NO_PERIOD_CLASS, B40_NO_PERIOD_CLASS
    )
    immutable_listing_regex = r'blockstack://({}+)[/]+#immutable'.format(B40_CLASS)

    m = re.match(immutable_data_regex, url)
    if m:
        data_id, blockchain_name, namespace_id, data_hash = m.groups()
        blockchain_id = '{}.{}'.format(blockchain_name, namespace_id)

        if not is_name_valid(blockchain_id):
            log.debug('Invalid blockstack ID "{}"'.format(blockchain_id))
            raise ValueError('Invalid blockstack ID')

        if data_hash is not None:
            data_hash = data_hash.lower().strip('#/')
            if not is_valid_hash(data_hash):
                log.debug('Invalid data hash "{}"'.format(data_hash))
                raise ValueError('Invalid data hash')

        return urllib.unquote(blockchain_id), urllib.unquote(data_id), data_hash
    else:
        # maybe a listing?
        m = re.match(immutable_listing_regex, url)
        if not m:
            log.debug('Invalid URL "{}"'.format(url))
            raise ValueError('Invalid URL')

        blockchain_id = m.groups()[0]
        return urllib.unquote(blockchain_id), None, None

    return None, None, None


def blockstack_data_url_parse(url):
    """
    Parse a blockstack:// URL
    Return {
        'type': immutable|mutable
        'app': True|False
        'blockchain_id': blockchain ID
        'data_id': data_id
        'fields': { fields }
    } on success
    Fields will be either {'data_hash'} on immutable
    or {'version'} on mutable

    Return None on error
    """

    blockchain_id, data_id, url_type, account_id, service_id = [None] * 5
    fields = {}
    app = False

    try:
        blockchain_id, data_id, data_hash = blockstack_immutable_data_url_parse(url)
        url_type = 'immutable'
        fields.update({'data_hash': data_hash})
    except Exception as e1:
        log.exception(e1)
        try:
            blockchain_id, data_id, version, account_id, service_id = (
                blockstack_mutable_data_url_parse(url)
            )

            url_type = 'mutable'
            fields.update({'version': version})

            app = account_id is not None and service_id is not None

            if account_id is not None:
                fields['account_id'] = account_id

            if service_id is not None:
                fields['service_id'] = service_id
        except Exception as e2:
            log.exception(e2)
            log.debug('Unparseable URL "{}"'.format(url))
            return None

    ret = {
        'type': url_type,
        'app': app,
        'blockchain_id': blockchain_id,
        'data_id': data_id,
        'fields': fields
    }

    return ret


def blockstack_data_url(field_dict):
    """
    Make a blockstack:// URL from constituent fields.
    Takes the output of blockstack_data_url_parse
    Return the URL on success
    Raise on error
    """
    assert 'blockchain_id' in field_dict
    assert 'type' in field_dict
    assert field_dict['type'] in ['mutable', 'immutable']
    assert 'data_id' in field_dict
    assert 'fields' in field_dict
    assert 'data_hash' in field_dict['fields'] or 'version' in field_dict['fields']

    if field_dict['type'] == 'immutable':
        return blockstack_immutable_data_url(
            field_dict['blockchain_id'], field_dict['data_id'], field_dict['fields']['data_hash']
        )

    return blockstack_mutable_data_url(
        field_dict['blockchain_id'], field_dict['data_id'], field_dict['fields']['version']
    )


class BlockstackURLHandle(object):
    """
    A file-like object that handles reads on blockstack URLs
    """

    def __init__(self, url, data=None, full_response=False, config_path=CONFIG_PATH, wallet_keys=None):
        self.name = url
        self.data = data
        self.full_response = full_response
        self.fetched = False
        self.config_path = config_path
        self.wallet_keys = wallet_keys

        self.offset = 0
        self.closed = False
        self.softspace = 0

        if data is None:
            self.newlines = None
        else:
            self.data_len = len(data)
            self.fetched = True
            self.newlines = self.make_newlines(data)

    def make_newlines(self, data):
        """
        Set up newlines
        """

        return tuple(nls for nls in ('\n', '\r', '\r\n') if nls in data)

    def fetch(self):
        """
        Lazily fetch the data on read
        """

        if not self.fetched:
            import data as data_mod
            from .proxy import get_default_proxy

            proxy = get_default_proxy(config_path=self.config_path)
            data = data_mod.blockstack_url_fetch(
                self.name, proxy=proxy, wallet_keys=self.wallet_keys
            )

            if data is None:
                msg = 'Failed to fetch "{}"'
                raise urllib2.URLError(msg.format(self.name))

            if 'error' in data:
                msg = 'Failed to fetch "{}": {}'
                raise urllib2.URLError(msg.format(self.name, data['error']))

            if self.full_response:
                self.data = json.dumps(data)
            else:
                self.data = data['data']
                if not isinstance(self.data, (str, unicode)):
                    self.data = json.dumps(data['data'])

            self.newlines = self.make_newlines(data)
            self.data_len = len(self.data)
            self.fetched = True

    def close(self):
        self.data = None
        self.closed = True

    def flush(self):
        pass

    def __iter__(self):
        return self

    def next(self):
        line = self.readline()
        if len(line) == 0:
            raise StopIteration()
        else:
            return line

    def read(self, numbytes=None):
        self.fetch()
        if self.offset >= self.data_len:
            return ''

        ret = []
        if numbytes is not None:
            ret = self.data[self.offset:min(self.data_len, self.offset + numbytes)]
            self.offset += numbytes
            self.offset = self.data_len if self.offset > self.data_len else self.offset
        else:
            ret = self.data[self.offset:]
            self.offset = self.data_len
            self.data = None

        return ret

    def readline(self, numbytes=None):
        if self.data is None:
            return ''

        next_newline_offset = self.data[self.offset:].find('\n')
        if next_newline_offset < 0:
            # no more newlines
            return self.read()
        else:
            line_data = self.read(next_newline_offset + 1)
            return line_data

    def readlines(self, sizehint=None):
        sizehint = self.data_len if sizehint is None else sizehint

        total_len = 0
        lines = []
        while total_len < sizehint:
            line = self.readline()
            lines.append(line)
            total_len += len(line)

        return lines


class BlockstackHandler(urllib2.BaseHandler):
    """
    URL opener for blockstack:// URLs.
    Usable with urllib2.
    """

    def __init__(self, full_response=False, config_path=CONFIG_PATH):
        self.full_response = full_response
        self.config_path = config_path

    def blockstack_open(self, req):
        """
        Open a blockstack URL
        """
        bh = BlockstackURLHandle(
            req.get_full_url(), full_response=self.full_response,
            config_path=self.config_path
        )

        return bh
