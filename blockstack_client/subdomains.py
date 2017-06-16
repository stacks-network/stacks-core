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

import base64
import ecdsa, hashlib
import keylib
from itertools import izip
from blockstack_client import data, zonefile
from blockstack_client.logger import get_logger


log = get_logger()


class ParseError(Exception):
    pass

class SubdomainNotFound(Exception):
    pass

class SubdomainNotFound(Exception):
    pass

# aaron: I was hesitant to write these two functions. But I did because:
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

def parse_zonefile_subdomains(zonefile_json, with_packed=False):
    if "uri" in zonefile_json:
        registrar_urls = [ x for x in zonefile_json["uri"] if x["name"] == "registrar" ]
    else:
        registrar_urls = []

    if "txt" in zonefile_json:
        subdomains = [ (parse_subdomain_record(x), x["txt"]) for x in zonefile_json["txt"]
                       if x["name"].startswith("_subd.") ]
    else:
        subdomains = []

    if len(subdomains) > 0:
        parsed, packed = zip(*subdomains)
    else:
        parsed, packed = ([], [])

    if with_packed:
        return registrar_urls, parsed, packed
    else:
        return registrar_urls, parsed

def parse_subdomain_record(subdomain_record):
    parsed = {}
    parsed["name"] = subdomain_record["name"][len("_subd."):]
    parsed["urls"] = []

    sig_found = False
    for datum in subdomain_record["txt"].split(","):
        if sig_found:
            raise ParseError("No subdomain data may exist after the signature: {}".format(
                subdomain_record))

        first_colon = datum.index(":")
        datum_label = datum[:first_colon].lower()
        datum_entry = datum[first_colon + 1:]
        if datum_label == "pubkey":
            if "pubkey" in parsed:
                raise ParseError("Multiple pubkeys defined in subdomain record: {}".format(
                    subdomain_record))
            parsed["pubkey"] = datum_entry
        elif datum_label == "n":
            if "n" in parsed:
                raise ParseError("Multiple Ns defined in subdomain record: {}".format(
                    subdomain_record))
            parsed["n"] = int(datum_entry)
        elif datum_label == "sig":
            if "sig" in parsed: # presently unreachable code, but you never know!
                raise ParseError("Multiple sigs defined in subdomain record: {}".format(
                    subdomain_record))
            parsed["sig"] = datum_entry
            sig_found = True
        elif datum_label == "url":
            parsed["urls"].append(datum_entry)
    for must_have in ["n", "pubkey"]:
        if must_have not in parsed:
            raise ParseError("Subdomain entry must have {} setting".format(must_have))
    if parsed["n"] != 0 and "sig" not in parsed:
        raise ParseError("Subdomain entries (with n>0) must have signature".format(must_have))

    return parsed

def make_zonefile_entry(subdomain_name, packed_subdomain, as_dict=False):
    d = { "name" : "_subd." + subdomain_name,
          "txt" : packed_subdomain }
    if as_dict:
        return d
    return '{} TXT "{}"'.format(d["name"], d["txt"])

def pack_and_sign_subdomain_record(subdomain_record, key):
    entries = []
    for k, v in subdomain_record.items():
        if "," in k or (isinstance(v, str) and "," in v):
            raise ParseError("Don't use commas.")
        if k in ["n", "pubkey"]:
            entries.append((k,v))
        if k == "urls":
            entries.extend([("url",value) for value in v])

    plaintext = ",".join([ "{}:{}".format(k, v) for k,v in entries ])

    signature_blob = sign(key, plaintext)

    return plaintext + ",sig:data:" + signature_blob

def verify_subdomain_record(subdomain_record, prior_pubkey_entry):
    sig_separator = ",sig:data:"
    signature_index = subdomain_record.index(sig_separator)
    plaintext = subdomain_record[:signature_index]
    sig = subdomain_record[(signature_index + len(sig_separator)): ]

    pk_header, pk_data = decode_pubkey_entry(prior_pubkey_entry)

    if pk_header == "echex":
        try:
            return verify(keylib.ECPublicKey(pk_data), plaintext, sig)
        except ecdsa.BadSignatureError as e:
            log.error("Signature verification failed with BadSignature {} over {} by {}".format(
                sig, plaintext, pk_data))
            return False
    else:
        raise NotImplementedError("PubKey type ({}) not supported".format(pk_header))

def decode_pubkey_entry(pubkey_entry):
    assert pubkey_entry.startswith("data:")
    pubkey_entry = pubkey_entry[len("data:"):]
    header, data = pubkey_entry.split(":")
    return header, data

def encode_pubkey_entry(key):
    """
    key should be a key object, right now this means 
        keylib.ECPrivateKey or
        keylib.ECPublicKey
    """
    if isinstance(key, keylib.ECPrivateKey):
        data = key.public_key().to_hex()
        head = "echex"
    elif isinstance(key, keylib.ECPublicKey):
        data = key.to_hex()
        head = "echex"
    else:
        raise NotImplementedError("No support for this key type")

    return "data:{}:{}".format(head, data)

def is_a_subdomain(fqa):
    """
    Tests whether fqa is a subdomain. 
    If it isn't, returns False.
    If it is, returns True and a tuple (subdomain_name, domain)
    """
    if re.match(schemas.OP_NAME_PATTERN, fqa) == None:
        return False
    pieces = fqa.split(".")
    if len(pieces) == 3:
        return (True, (pieces[0], ("{}.{}".format(*pieces[1:]))))
    return False

def _transition_valid(from_sub_record, to_sub_record, packed_sub_record):
    if from_sub_record["n"] + 1 != to_sub_record["n"]:
        log.warn("Failed subdomain {} transition because of N:{}->{}".format(
            to_sub_record["name"], from_sub_record["n"], to_sub_record["n"]))
        return False
    if not verify_subdomain_record(packed_sub_record, from_sub_record["pubkey"]):
        log.warn("Failed subdomain {} transition because of signature failure".format(
            to_sub_record["name"], from_sub_record["n"], to_sub_record["n"]))
        return False
    parsed_again = parse_subdomain_record(
        make_zonefile_entry(to_sub_record["name"], packed_sub_record, as_dict = True))
    for (k,v) in parsed_again.items():
        if k not in to_sub_record:
            log.warn("Parsed version does not match packed version")
            raise ParseError()
        if v != to_sub_record[k]:
            log.warn("Parsed version does not match packed version") 
            raise ParseError()
    for (k,v) in to_sub_record.items():
        if k not in parsed_again:
            log.warn("Parsed version does not match packed version")
            raise ParseError()
        if v != parsed_again[k]:
            log.warn("Parsed version does not match packed version") 
            raise ParseError()
    return True

def _build_subdomain_db(domain_fqa, zonefiles):
    subdomain_db = {}
    for zf in zonefiles:
        zf_json = zonefile.decode_name_zonefile(domain_fqa, zf)
        _, subdomain_ops, subdomain_packs = parse_zonefile_subdomains(
            zf_json, with_packed = True)
        if len(subdomain_ops) < 1:
            print zf

        for subdomain_op, packed in izip(subdomain_ops, subdomain_packs):
            if subdomain_op["name"] in subdomain_db:
                previous = subdomain_db[subdomain_op["name"]]
                if _transition_valid(previous, subdomain_op, packed):
                    new_rec = dict(subdomain_op)
                    del new_rec["sig"]
                    del new_rec["name"]
                    subdomain_db[subdomain_op["name"]] = new_rec
                else:
                    log.warn("Failed subdomain transition for {}.{} on N:{}->{}".format(
                        subdomain_op["name"], domain_fqa, previous["n"], subdomain_op["n"]))
            else:
                if subdomain_op["n"] != 0:
                    log.warn("First sight of subdomain {}.{} with N={}".format(
                        subdomain_op["name"], domain_fqa, subdomain_op["n"]))
                    continue
                new_rec = dict(subdomain_op)
                if "sig" in new_rec:
                    del new_rec["sig"]
                del new_rec["name"]
                subdomain_db[subdomain_op["name"]] = new_rec
    return subdomain_db

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
    pubkey_type, user_data_pubkey = decode_pubkey_entry(my_rec["pubkey"])
    if pubkey_type != "echex":
        raise NotImplementedError(
            "Pubkey type {} for subdomain {}.{} not supported by resolver.".format(
                pubkey_type, subdomain, domain_fqa))

    user_profile = storage.get_mutable_data(
        None, user_data_pubkey, blockchain_id=None,
        data_address=None, owner_address=None,
        urls=urls, drivers=None, decode=True,
    )
