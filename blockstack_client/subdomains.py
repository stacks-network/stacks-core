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

class ParseError(Exception):
    pass

def parse_zonefile_subdomains(zonefile_json):    
    registrar_urls = [ x for x in zonefile_json["uri"] if x["name"] == "registrar" ]

    subdomains = [ parse_subdomain_record(x) for x in zonefile_json["txt"]
                   if x["name"].startswith("_subd.") ]

    return registrar_urls, subdomains

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

    return parsed

def pack_and_sign_subdomain_record(subdomain_record, key):
    entries = []
    for k, v in subdomain_record.items():
        if "," in k or (isinstance(v, str) and "," in v):
            raise ParseError("Don't use commas.")
        if k in ["n", "pubkey"]:
            entries.append((k,v))
        if k == "url":
            entries.append((k,v))

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
        return verify(keylib.ECPublicKey(pk_data), plaintext, sig)
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

def sign(sk, plaintext):
    signer = ecdsa.SigningKey.from_pem(sk.to_pem())
    blob = signer.sign_deterministic(plaintext, hashfunc = hashlib.sha256)
    return base64.b64encode(blob)

def verify(pk, plaintext, sigb64):
    signature = base64.b64decode(sigb64)
    verifier = ecdsa.VerifyingKey.from_pem(pk.to_pem())
    return verifier.verify(signature, plaintext, hashfunc = hashlib.sha256)
