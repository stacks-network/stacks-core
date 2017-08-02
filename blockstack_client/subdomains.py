#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2017 by Blockstack.org

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

import sqlite3

import base64, copy, re, binascii
import ecdsa, hashlib
import keylib
import virtualchain

from itertools import izip
from blockstack_client import data, storage, config, proxy, schemas
from blockstack_client import zonefile as bs_zonefile
from blockstack_client import user as user_db
from blockstack_client.backend import safety
from blockstack_client.logger import get_logger
import blockstack_zones
from blockstack_client.rpc import local_api_connect

from subdomain_registrar import util as subdomain_util
from subdomain_registrar.util import (SUBDOMAIN_ZF_PARTS, SUBDOMAIN_ZF_PIECE, 
                                      SUBDOMAIN_SIG, SUBDOMAIN_PUBKEY, SUBDOMAIN_N)

log = get_logger()


class DomainNotOwned(Exception):
    pass
class SubdomainNotFound(Exception):
    pass
class SubdomainAlreadyExists(Exception):
    def __init__(self, subdomain, domain):
        self.subdomain = subdomain
        self.domain = domain
        super(SubdomainAlreadyExists, self).__init__(
            "Subdomain already exists: {}.{}".format(subdomain, domain))

class Subdomain(object):
    def __init__(self, name, address, n, zonefile_str, sig=None):
        self.name = name
        self.address = address
        self.n = n
        self.zonefile_str = zonefile_str
        self.sig = sig

    def pack_subdomain(self):
        """ Returns subdomain packed into a list of strings
            Also defines the canonical order for signing!
            ADDR, N, ZF_PARTS, IN_ORDER_PIECES, (? SIG)
        """
        output = []
        output.append(txt_encode_key_value(SUBDOMAIN_PUBKEY, 
                                           self.address))
        output.append(txt_encode_key_value(SUBDOMAIN_N, "{}".format(self.n)))
        
        encoded_zf = base64.b64encode(self.zonefile_str)
        # let's pack into 250 byte strings -- the entry "zf99=" eliminates 5 useful bytes,
        # and the max is 255.
        n_pieces = (len(encoded_zf) / 250) + 1
        if len(encoded_zf) % 250 == 0:
            n_pieces -= 1
        output.append(txt_encode_key_value(SUBDOMAIN_ZF_PARTS, "{}".format(n_pieces)))
        for i in range(n_pieces):
            start = i * 250
            piece_len = min(250, len(encoded_zf[start:]))
            assert piece_len != 0
            piece = encoded_zf[start:(start+piece_len)]
            output.append(txt_encode_key_value(SUBDOMAIN_ZF_PIECE % i, piece))

        if self.sig is not None:
            output.append(txt_encode_key_value(SUBDOMAIN_SIG, self.sig))

        return output

    def add_signature(self, privkey):
        plaintext = self.get_plaintext_to_sign()
        self.sig = sign(privkey, plaintext)

    def verify_signature(self, pubkey):
        return verify(pubkey, self.get_plaintext_to_sign(), self.sig)

    def as_zonefile_entry(self):
        d = { "name" : self.name,
              "txt" : self.pack_subdomain() }
        return d

    def get_plaintext_to_sign(self):
        as_strings = self.pack_subdomain()
        if self.sig is not None:
            as_strings = as_strings[:-1]
        return ",".join(as_strings)

    @staticmethod
    def parse_subdomain_record(rec):
        txt_entry = rec['txt']
        if not isinstance(txt_entry, list):
            raise subdomain_util.ParseError("Tried to parse a TXT record with only a single <character-string>")
        entries = {}
        for item in txt_entry:
            if isinstance(item, unicode):
                item = str(item)
            first_equal = item.index("=")
            key = item[:first_equal]
            value = item[first_equal + 1:]
            value = value.replace("\\=", "=") # escape equals
            assert key not in entries
            entries[key] = value

        pubkey = entries[SUBDOMAIN_PUBKEY]
        n = entries[SUBDOMAIN_N]
        if SUBDOMAIN_SIG in entries:
            sig = entries[SUBDOMAIN_SIG]
        else:
            sig = None
        zonefile_parts = int(entries[SUBDOMAIN_ZF_PARTS])
        b64_zonefile = "".join([ entries[SUBDOMAIN_ZF_PIECE % zf_index] for
                                 zf_index in range(zonefile_parts) ])

        return Subdomain(rec['name'], pubkey, int(n),
                         base64.b64decode(b64_zonefile), sig)

class SubdomainDB(object):
    def __init__(self, domain_fqa):
        self.domain = domain_fqa
        self.subdomain_table = "subdomain_{}".format(
            domain_fqa.replace('.', '_'))
        self.status_table = "status_{}".format(
            domain_fqa.replace('.', '_'))
        self.conn = sqlite3.connect(config.get_subdomains_db_path())
        self._create_tables()

    def last_seen(self):
        get_cmd = """SELECT * FROM {} ORDER BY lastBlock DESC LIMIT 1""".format(
            self.status_table)
        cursor = self.conn.cursor()
        cursor.execute(get_cmd)
        try:
            last_hash, last_block = cursor.fetchone()
        except:
            return False, 0
        return str(last_hash), int(last_block)

    def get_subdomain_entry(self, subdomain_name):
        get_cmd = "SELECT * FROM {} WHERE subdomain=?".format(self.subdomain_table)
        cursor = self.conn.cursor()
        cursor.execute(get_cmd, (subdomain_name,))
        try:
            (name, n, encoded_pubkey, zonefile_str, sig) = cursor.fetchone()
        except:
            raise SubdomainNotFound(subdomain_name)
        if sig == '':
            sig = None
        else:
            sig = str(sig)
        # lol, unicode support.
        return Subdomain(str(name), str(encoded_pubkey), int(n), str(zonefile_str), sig)

    def initialize_db(self):
        return self.update(full_refresh=True)

    def update(self, full_refresh=False):
        if full_refresh:
            self._drop_tables()
            self._create_tables()
            last_block = 0
        else:
            last_block = self.last_seen()[1]

        zonefiles, hashes, blockids = data.list_zonefile_history(
            self.domain, return_hashes = True, from_block = last_block, return_blockids = True)
        assert len(hashes) == len(blockids)
        assert len(hashes) == len(zonefiles)
        if len(blockids) > 0 and blockids[0] == last_block:
            zonefiles = list(zonefiles[1:])
            hashes = list(hashes[1:])
            blockids = list(blockids[1:])
        if len(hashes) == 0:
            return

        failed_zonefiles = []
        for ix, zonefile in enumerate(zonefiles):
            if 'error' in zonefile:
                failed_zonefiles.append(ix)
                log.error("Failed to get zonefile for hash ({}), error: {}".format(
                    hashes[ix], zonefile))
        failed_zonefiles.sort(reverse=True)
        for ix in failed_zonefiles:
            del zonefiles[ix]
            del hashes[ix]
            del blockids[ix]
        if len(hashes) == 0:
            return

        _build_subdomain_db(self.domain, zonefiles, self)
        
        last_hash = hashes[-1]
        last_block = blockids[-1]

        self._set_last_seen_zf_hash(hashes[-1], last_block)

    def __setitem__(self, subdomain_name, subdomain_obj):
        assert isinstance(subdomain_obj, Subdomain)
        assert subdomain_name == subdomain_obj.name
        write_cmd = """INSERT OR REPLACE INTO {} VALUES
                       (?, ?, ?, ?, ?) """.format(self.subdomain_table)
        cursor = self.conn.cursor()
        cursor.execute(write_cmd,
                       (subdomain_obj.name,
                        subdomain_obj.n,
                        subdomain_obj.address,
                        subdomain_obj.zonefile_str,
                        subdomain_obj.sig))
        self.conn.commit()

    def __getitem__(self, subdomain_name):
        return self.get_subdomain_entry(subdomain_name)

    def __contains__(self, subdomain_name):
        try:
            _ = self[subdomain_name]
            return True
        except SubdomainNotFound:
            return False

    def _set_last_seen_zf_hash(self, hash, block):
        write_cmd = """INSERT INTO {} VALUES (?,?)""".format(self.status_table)
        cursor = self.conn.cursor()
        cursor.execute(write_cmd, (hash, block))
        self.conn.commit()

    def _drop_tables(self):
        drop_cmd = "DROP TABLE IF EXISTS {};"
        cursor = self.conn.cursor()
        cursor.execute(drop_cmd.format(self.subdomain_table))
        cursor.execute(drop_cmd.format(self.status_table)) 

    def _create_tables(self):
        create_cmd = """CREATE TABLE IF NOT EXISTS {} (
        subdomain TEXT PRIMARY KEY,
        sequence INTEGER,
        pubkey TEXT,
        zonefile TEXT, 
        signature TEXT);
        """.format(self.subdomain_table)
        create_status_cmd = """CREATE TABLE IF NOT EXISTS {} (
        zonefileHash TEXT, lastBlock INTEGER);""".format(
            self.status_table)
        cursor = self.conn.cursor()
        cursor.execute(create_cmd)
        cursor.execute(create_status_cmd)


def parse_zonefile_subdomains(zonefile_json):
    registrar_urls = []

    if "txt" in zonefile_json:
        subdomains = [ Subdomain.parse_subdomain_record(x) for x in zonefile_json["txt"]
                       if subdomain_util.is_subdomain_record(x) ]
    else:
        subdomains = []

    return subdomains

def is_address_subdomain(fqa):
    """
    Tests whether fqa is a subdomain. 
    If it isn't, returns False.
    If it is, returns True and a tuple (subdomain_name, domain)
    """
    if re.match(schemas.OP_NAME_PATTERN, fqa) == None:
        return False
    pieces = fqa.split(".")
    if len(pieces) == 3:
        subd_name = pieces[0]
        domain  = fqa[len(subd_name) + 1:]
        error = safety.check_valid_name(domain)
        if error:
            return False
        return (True, (subd_name, domain))
    return False

def _transition_valid(from_sub_record, to_sub_record):
    if from_sub_record.n + 1 != to_sub_record.n:
        log.warn("Failed subdomain {} transition because of N:{}->{}".format(
            to_sub_record.name, from_sub_record.n, to_sub_record.n))
        return False
    if not to_sub_record.verify_signature(from_sub_record.address):
        log.warn("Failed subdomain {} transition because of signature failure".format(
            to_sub_record.name))
        return False
    return True

def _build_subdomain_db(domain_fqa, zonefiles, subdomain_db = None):
    if subdomain_db is None:
        subdomain_db = {}
    for zf in zonefiles:
        if isinstance(zf, dict):
            assert "zonefile" not in zf
            zf_json = zf
        else:
            assert isinstance(zf, (str, unicode)) 
            zf_json = bs_zonefile.decode_name_zonefile(domain_fqa, zf)
            assert "zonefile" not in zf_json

        subdomains = parse_zonefile_subdomains(zf_json)

        for subdomain in subdomains:
            if subdomain.name in subdomain_db:
                previous = subdomain_db[subdomain.name]
                if _transition_valid(previous, subdomain):
                    subdomain_db[subdomain.name] = subdomain
                else:
                    log.warn("Failed subdomain transition for {}.{} on N:{}->{}".format(
                        subdomain.name, domain_fqa, previous.n, subdomain.n))
            else:
                if subdomain.n != 0:
                    log.warn("First sight of subdomain {}.{} with N={}".format(
                        subdomain.name, domain_fqa, subdomain.n))
                    continue
                subdomain_db[subdomain.name] = subdomain
    return subdomain_db

def issue_zonefile(domain_fqa, user_data_txt):
    rpc = local_api_connect()
    assert rpc
    try:
        resp = rpc.backend_update(domain_fqa, user_data_txt, None, None)
    except Exception as e:
        log.exception(e)
        return {'error': 'Exception submitting zonefile for update'}
    return resp

def add_subdomains(subdomains, domain_fqa):
    """
    subdomains => list Subdomain objects to add
    domain_fqa => fully qualified domain name to add the subdomain to.
                  - must be owned by the Core's wallet
                  - must not already have a subdomain associated with it
    """

    assert isinstance(subdomains, list)

    # get domain's current zonefile
    zf_resp = bs_zonefile.get_name_zonefile(domain_fqa)
    if 'error' in zf_resp:
        log.error(zf_resp)
        raise Exception(zf_resp['error'])
    zonefile_json = zf_resp['zonefile']

    def filter_by(x, y):
        try:
            resolve_subdomain(x, y)
            return False
        except SubdomainNotFound as e:
            return True

    zf_txt, subdomains_failed = subdomain_util.add_subdomains(
        subdomains, domain_fqa, zonefile_json, filter_by)
    if len(subdomains_failed) > 0:
        raise SubdomainAlreadyExists(subdomains[subdomains_failed[0]], domain_fqa)
    return issue_zonefile(domain_fqa, zf_txt)

def is_subdomain_resolution_cached(domain_fqa):
    domains = config.get_subdomains_cached_for()
    return domain_fqa in domains

def resolve_subdomain(subdomain, domain_fqa, use_cache = True):
    if not use_cache:
        zonefiles = data.list_zonefile_history(domain_fqa)
        subdomain_db = _build_subdomain_db(domain_fqa, zonefiles)        
    else:
        blockchain_record = proxy.get_name_blockchain_record(domain_fqa)
        if 'value_hash' not in blockchain_record:
            raise SubdomainNotFound("Failed to get zonefile for domain {}".format(domain_fqa))
        zf_hash = blockchain_record['value_hash']
        subdomain_db = SubdomainDB(domain_fqa)
        if zf_hash != subdomain_db.last_seen()[0]:
            log.debug("SubdomainDB Zonefile {} not up to date with {}".format(
                subdomain_db.last_seen(), zf_hash))
            subdomain_db.update()
        else:
            log.debug("SubdomainDB Zonefile {} up to date with {}".format(
                subdomain_db.last_seen(), zf_hash))
    try:
        subdomain_obj = subdomain_db[subdomain]
    except Exception as e:
        log.exception(e)
        log.error("Raising SubdomainNotFound({}) from exception {}".format(subdomain, e))
        raise SubdomainNotFound(subdomain)

    return subdomain_record_to_profile(subdomain_obj)

def subdomain_record_to_profile(my_rec):
    owner_addr = my_rec.address

    assert isinstance(my_rec.zonefile_str, (str, unicode))

    parsed_zf = bs_zonefile.decode_name_zonefile(my_rec.name, my_rec.zonefile_str)
    urls = user_db.user_zonefile_urls(parsed_zf)

    # try to get pubkey from zonefile, or default to ``owner`` pubkey
    user_data_pubkey = None
    try:
        user_data_pubkey = user_db.user_zonefile_data_pubkey(parsed_zf)
        if user_data_pubkey is not None:
            user_data_pubkey = str(user_data_pubkey)
    except ValueError:
        pass # no pubkey defined in zonefile

    try:
        user_profile = storage.get_mutable_data(
            None, user_data_pubkey, blockchain_id=None,
            data_address=owner_addr, owner_address=None,
            urls=urls, drivers=None, decode=True,
        )
    except:
        user_profile = None

    if user_profile is None:
        user_profile = {'error' :
                        'Error fetching the data for subdomain {}'.format(my_rec.name)}

    data = { 'profile' : user_profile,
             'zonefile' : parsed_zf }
    return data

# aaron: I was hesitant to write these two functions. But I did so because:
#   1> getting the sign + verify functions from virtualchain.ecdsa 
#      was tricky because of the hashfunc getting lost in translating from
#      SK to PK
#   2> didn't want this code to necessarily depend on virtualchain

def verify(address, plaintext, scriptSigb64):
    assert isinstance(address, str)

    scriptSig = base64.b64decode(scriptSigb64)

    vb = keylib.b58check.b58check_version_byte(address)

    if vb != 0:
        raise NotImplementedError("Addresses must be single-sig: version-byte == 0")

    sighex, pubkey_hex = virtualchain.btc_script_deserialize(scriptSig)
    # verify pubkey_hex corresponds to address
    if keylib.ECPublicKey(pubkey_hex).address() != address:
        raise Exception(("Address {} does not match the public key in the" +
                         " provided scriptSig: provided pubkey = {}").format(
                             address, pubkey_hex))
    sig64 = base64.b64encode(binascii.unhexlify(sighex))

    hash_hex = binascii.hexlify(hashlib.sha256(plaintext).digest())
    return virtualchain.ecdsalib.verify_digest(hash_hex, pubkey_hex, sig64)

def sign(sk, plaintext):
    """
    This returns a signature of the given plaintext with the given SK.
    This is in the form of a p2pkh scriptSig
    """
    privkey_hex = sk.to_hex()
    hash_hex = binascii.hexlify(hashlib.sha256(plaintext).digest())
    b64sig = virtualchain.ecdsalib.sign_digest(hash_hex, privkey_hex)
    sighex = binascii.hexlify(base64.b64decode(b64sig))
    pubkey_hex = sk.public_key().to_hex()
    return base64.b64encode(virtualchain.btc_script_serialize([sighex, pubkey_hex]))

def encode_pubkey_entry(key):
    """
    key should be a key object, right now this means 
        keylib.ECPrivateKey or
        keylib.ECPublicKey
    """
    if isinstance(key, keylib.ECPrivateKey):
        pubkey = key.public_key()
    elif isinstance(key, keylib.ECPublicKey):
        pubkey = key
    else:
        raise NotImplementedError("No support for this key type")

    addr = pubkey.address()

    return "{}".format(addr)


def txt_encode_key_value(key, value):
    return "{}={}".format(key,
                          value.replace("=", "\\="))

