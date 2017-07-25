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

import base64, copy, re
import ecdsa, hashlib
import keylib
from itertools import izip
from blockstack_client import data, storage, config, proxy, schemas
from blockstack_client import zonefile as bs_zonefile
from blockstack_client import user as user_db
from blockstack_client.backend import safety
from blockstack_client.logger import get_logger
import blockstack_zones
from blockstack_client.rpc import local_api_connect

log = get_logger()

SUBDOMAIN_ZF_PARTS = "zf-parts"
SUBDOMAIN_ZF_PIECE = "zf%d"
SUBDOMAIN_SIG = "sig"
SUBDOMAIN_PUBKEY = "pub-key"
SUBDOMAIN_N = "sequence-n"

class ParseError(Exception):
    pass
class DomainNotOwned(Exception):
    pass
class SubdomainNotFound(Exception):
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
    def __init__(self, name, pubkey_encoded, n, zonefile_str, sig=None):
        self.name = name
        self.pubkey = decode_pubkey_entry(pubkey_encoded)
        self.n = n
        self.zonefile_str = zonefile_str
        self.sig = sig

    def pack_subdomain(self):
        """ Returns subdomain packed into a list of strings
            Also defines the canonical order for signing!
            PUBKEY, N, ZF_PARTS, IN_ORDER_PIECES, (? SIG)
        """
        output = []
        output.append(txt_encode_key_value(SUBDOMAIN_PUBKEY, 
                                           encode_pubkey_entry(self.pubkey)))
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
            raise ParseError("Tried to parse a TXT record with only a single <character-string>")
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

    def last_seen_zonefile_hash(self):
        get_cmd = """SELECT * FROM {}""".format(self.status_table)
        cursor = self.conn.cursor()
        cursor.execute(get_cmd)
        # aaron: note, if there's no entry, we'll get such a lovely exception.
        zonefile_hash = str(cursor.fetchone()[0])
        return zonefile_hash

    def get_subdomain_entry(self, subdomain_name):
        get_cmd = "SELECT * FROM {} WHERE subdomain=?".format(self.subdomain_table)
        cursor = self.conn.cursor()
        cursor.execute(get_cmd, (subdomain_name,))
        (name, n, encoded_pubkey, zonefile_str, sig) = cursor.fetchone()
        if sig == '':
            sig = None
        else:
            sig = str(sig)
        # lol, unicode support.
        return Subdomain(str(name), str(encoded_pubkey), int(n), str(zonefile_str), sig)

    def update(self):
        self._drop_and_create_table()
        zonefiles, hashes = data.list_zonefile_history(self.domain, return_hashes = True)
        in_mem = _build_subdomain_db(self.domain, zonefiles)

        for record in in_mem.values():
            self._write_record(record)
        self._set_last_seen_zf_hash(hashes[-1])

    def _write_record(self, subdomain_obj):
        write_cmd = """INSERT INTO {} VALUES (?, ?, ?, ?, ?)""".format(self.subdomain_table)
        cursor = self.conn.cursor()
        cursor.execute(write_cmd, 
                       (subdomain_obj.name,
                        subdomain_obj.n,
                        encode_pubkey_entry(subdomain_obj.pubkey),
                        subdomain_obj.zonefile_str,
                        subdomain_obj.sig
                       ))
        self.conn.commit()

    def _set_last_seen_zf_hash(self, hash):
        write_cmd = """INSERT INTO {} VALUES (?)""".format(self.status_table)
        cursor = self.conn.cursor()
        cursor.execute(write_cmd, (hash, ))
        self.conn.commit()

    def _drop_and_create_table(self):
        drop_cmd = "DROP TABLE IF EXISTS {};"
        create_cmd = """CREATE TABLE {} (
        subdomain TEXT PRIMARY KEY,
        sequence INTEGER,
        pubkey TEXT,
        zonefile TEXT, 
        signature TEXT);
        """.format(self.subdomain_table)
        create_status_cmd = """CREATE TABLE {} (zonefileHash TEXT);""".format(
            self.status_table)
        cursor = self.conn.cursor()
        cursor.execute(drop_cmd.format(self.subdomain_table))
        cursor.execute(drop_cmd.format(self.status_table)) 

        cursor.execute(create_cmd)
        cursor.execute(create_status_cmd)

def is_subdomain_record(rec):
    txt_entry = rec['txt']
    if not isinstance(txt_entry, list):
        return False
    for entry in txt_entry:
        if entry.startswith(SUBDOMAIN_ZF_PARTS + "="):
            return True
    return False

def parse_zonefile_subdomains(zonefile_json):
    registrar_urls = []

    if "txt" in zonefile_json:
        subdomains = [ Subdomain.parse_subdomain_record(x) for x in zonefile_json["txt"]
                       if is_subdomain_record(x) ]
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
    if not to_sub_record.verify_signature(from_sub_record.pubkey):
        log.warn("Failed subdomain {} transition because of signature failure".format(
            to_sub_record.name))
        return False
    return True

def _build_subdomain_db(domain_fqa, zonefiles):
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

def _extend_with_subdomain(zf_json, subdomain):
    """
    subdomain := one of (Subdomain Object, packed subdomain = list<string>)
    """
    if isinstance(subdomain, Subdomain):
        txt_data = subdomain.pack_subdomain()
    elif isinsntance(subdomain, list):
        txt_data = subdomain
    else:
        raise ParseError("Tried to extend zonefile with non-valid subdomain object")

    name = subdomain.name

    if "txt" not in zf_json:
        zf_json["txt"] = []

    txt_records = zf_json["txt"]

    for rec in txt_records:
        if name == rec["name"]:
            raise Exception("Name {} already exists in zonefile TXT records.".format(
                name))

    zf_json["txt"].append(subdomain.as_zonefile_entry())

def add_subdomains(subdomains, domain_fqa, broadcast_tx = True):
    """
    subdomains => list Subdomain objects to add
    domain_fqa => fully qualified domain name to add the subdomain to.
                  - must be owned by the Core's wallet
                  - must not already have a subdomain associated with it
    broadcast_tx => either broadcast transaction and return response OR
                    just return the new zonefile
    """

    assert isinstance(subdomains, list)

    # get domain's current zonefile and filter the subdomain entries
    zf_resp = bs_zonefile.get_name_zonefile(domain_fqa)
    if 'error' in zf_resp:
        log.error(zf_resp)
        raise Exception(zf_resp['error'])
    zonefile_json = zf_resp['zonefile']

    zf = copy.deepcopy(zonefile_json)
    if "txt" in zf:
        zf["txt"] = list([ x for x in zf["txt"]
                           if not is_subdomain_record(x)])

    if len(set(subdomains)) != len(subdomains):
        raise Exception("Same subdomain listed multiple times")

    subdomains_failed = []
    for ix, subdomain in enumerate(subdomains):
        # step 1: see if this resolves to an already defined subdomain
        subdomain_already = True
        try:
            resolve_subdomain(subdomain.name, domain_fqa)
        except SubdomainNotFound as e:
            subdomain_already = False
        if subdomain_already:
            if broadcast_tx:
                raise SubdomainAlreadyExists(subdomain, domain)
            subdomains_failed.append(ix)
        else:
            # step 2: create the subdomain record, adding it to zf
            try:
                _extend_with_subdomain(zf, subdomain)
            except Exception as e:
                log.exception(e)
                subdomains_failed.append(ix)

    zf_txt = blockstack_zones.make_zone_file(zf)
    if broadcast_tx:
        return issue_zonefile(domain_fqa, zf_txt)
    else:
        return zf_txt, subdomains_failed

def is_subdomain_resolution_cached(domain_fqa):
    domains = config.get_subdomains_cached_for()
    return domain_fqa in domains

def resolve_subdomain_cached_domain(subdomain, domain_fqa):
    db = SubdomainDB(domain_fqa)
    # check if db is current with zonefile hash
    zf_hash = proxy.get_name_blockchain_record(domain_fqa)['value_hash']
    if zf_hash != db.last_seen_zonefile_hash():
        log.debug("SubdomainDB Zonefile {} not up to date with {}".format(db.last_seen_zonefile_hash(), 
                                                                          zf_hash))
        db.update()
    else:
        log.debug("SubdomainDB Zonefile {} up to date with {}".format(db.last_seen_zonefile_hash(), 
                                                                      zf_hash))
    subdomain_obj = db.get_subdomain_entry(subdomain)

    return subdomain_record_to_profile(subdomain_obj)

def resolve_subdomain(subdomain, domain_fqa):
    # step 1: fetch domain zonefiles.
    zonefiles = data.list_zonefile_history(domain_fqa)

    # step 2: for each zonefile, parse the subdomain
    #         operations.
    subdomain_db = _build_subdomain_db(domain_fqa, zonefiles)

    # step 3: find the subdomain.
    if not subdomain in subdomain_db:
        raise SubdomainNotFound(subdomain)
    my_rec = subdomain_db[subdomain]

    # step 4: resolve!
    return subdomain_record_to_profile(my_rec)

def subdomain_record_to_profile(my_rec):
    owner_pubkey = my_rec.pubkey

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

    if user_data_pubkey is None:
        user_data_pubkey = owner_pubkey.to_hex()

    user_profile = storage.get_mutable_data(
        None, user_data_pubkey, blockchain_id=None,
        data_address=None, owner_address=None,
        urls=urls, drivers=None, decode=True,
    )

    data = { 'profile' : user_profile,
             'zonefile' : parsed_zf }
    return data

# aaron: I was hesitant to write these two functions. But I did so because:
#   1> getting the sign + verify functions from virtualchain.ecdsa 
#      was tricky because of the hashfunc getting lost in translating from
#      SK to PK
#   2> didn't want this code to necessarily depend on virtualchain

def sign(sk, plaintext):
    signer = ecdsa.SigningKey.from_pem(sk.to_pem())
    blob = signer.sign_deterministic(plaintext, hashfunc = hashlib.sha256)
    return base64.b64encode(blob)

def verify(pk, plaintext, sigb64):
    signature = base64.b64decode(sigb64)
    verifier = ecdsa.VerifyingKey.from_pem(pk.to_pem())
    return verifier.verify(signature, plaintext, hashfunc = hashlib.sha256)


def decode_pubkey_entry(pubkey_entry):
    assert pubkey_entry.startswith("pubkey:data:")
    data = pubkey_entry[len("pubkey:data:"):]

    return keylib.ECPublicKey(data)

def encode_pubkey_entry(key):
    """
    key should be a key object, right now this means 
        keylib.ECPrivateKey or
        keylib.ECPublicKey
    """
    if isinstance(key, keylib.ECPrivateKey):
        data = key.public_key().to_hex()
    elif isinstance(key, keylib.ECPublicKey):
        data = key.to_hex()
    else:
        raise NotImplementedError("No support for this key type")

    return "pubkey:data:{}".format(data)

def txt_encode_key_value(key, value):
    return "{}={}".format(key,
                          value.replace("=", "\\="))

