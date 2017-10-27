#!/usr/bin/env python2
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

from multiprocessing import Pool

from itertools import izip
from blockstack_client import storage, config, proxy, schemas, constants
from blockstack_client import zonefile as bs_zonefile
from blockstack_client import user as user_db
from blockstack_client.backend import safety
from blockstack_client.logger import get_logger
import blockstack_zones

from subdomain_registrar import util as subdomain_util
from subdomain_registrar.util import (SUBDOMAIN_ZF_PARTS, SUBDOMAIN_ZF_PIECE, 
                                      SUBDOMAIN_SIG, SUBDOMAIN_PUBKEY, SUBDOMAIN_N)

log = get_logger()

SUBDOMAINS_FIRST_BLOCK = 478872

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
    def __init__(self, domain, subdomain_name, address, n, zonefile_str, sig=None, last_txid=None):
        self.subdomain_name = subdomain_name
        self.domain = domain
        self.address = address
        self.n = n
        self.zonefile_str = zonefile_str
        self.sig = sig
        self.last_txid = last_txid

    def get_fqn(self):
        return "{}.{}".format(self.subdomain_name, self.domain)

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
        d = { "name" : self.subdomain_name,
              "txt" : self.pack_subdomain() }
        return d

    def get_plaintext_to_sign(self):
        as_strings = self.pack_subdomain()
        if self.sig is not None:
            as_strings = as_strings[:-1]
        return ",".join(as_strings)

    @staticmethod
    def parse_subdomain_record(domain_name, rec):
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

        return Subdomain(domain_name, rec['name'], pubkey, int(n),
                         base64.b64decode(b64_zonefile), sig)

class SubdomainDB(object):
    def __init__(self):
        self.subdomain_table = "subdomain_records"
        self.status_table = "domains_last_seen"
        self.conn = sqlite3.connect(config.get_subdomains_db_path())
        self._create_tables()

    def get_subdomain_entry(self, fqn):
        """
        Returns a subdomain object corresponding to the fully-qualified name
        """
        get_cmd = "SELECT * FROM {} WHERE fully_qualified_subdomain=?".format(
            self.subdomain_table)
        cursor = self.conn.cursor()
        cursor.execute(get_cmd, (fqn,))
        try:
            (name, n, encoded_pubkey, zonefile_str, sig, txid) = cursor.fetchone()
        except:
            raise SubdomainNotFound(fqn)
        if sig == '':
            sig = None
        else:
            sig = str(sig)

        name = str(name)
        is_subdomain = is_address_subdomain(name)
        if is_subdomain:
            (subdomain_name, domain_name) = is_subdomain[1]
        else:
            raise Exception("Subdomain DB lookup returned bad subdomain result {}".format(name))

        return Subdomain(domain_name, subdomain_name, str(encoded_pubkey), int(n), str(zonefile_str), sig, txid)

    def get_all_subdomains(self, above_seq = None):
        if above_seq:
            get_cmd = "SELECT fully_qualified_subdomain FROM {} WHERE sequence >= ?"
        else:
            get_cmd = "SELECT fully_qualified_subdomain FROM {}"
        get_cmd = get_cmd.format(self.subdomain_table)
        cursor = self.conn.cursor()
        if above_seq:
            cursor.execute(get_cmd, (above_seq,))
        else:
            cursor.execute(get_cmd)
        try:
            return [ x[0] for x in cursor.fetchall() ]
        except:
            return []

    def get_subdomains_owned_by_address(self, owner):
        get_cmd = "SELECT fully_qualified_subdomain FROM {} WHERE owner = ?".format(
            self.subdomain_table)
        cursor = self.conn.cursor()
        cursor.execute(get_cmd, (owner,))
        try:
            return [ x[0] for x in cursor.fetchall() ]
        except:
            return []

    def initialize_db(self):
        return self.update(full_refresh=True)

    def update(self, full_refresh=False):
        if not is_resolving_subdomains():
            log.warn('Configured not to resolve subdomains, but tried to update subdomain cache anyways...')
            return

        if full_refresh:
            self._drop_tables()
            self._create_tables()
            last_block = 0
            if not constants.BLOCKSTACK_TESTNET:
                last_block = SUBDOMAINS_FIRST_BLOCK
        else:
            last_block = self.last_seen()
            if not constants.BLOCKSTACK_TESTNET:
                last_block = max(last_block, SUBDOMAINS_FIRST_BLOCK)

        core_last_block = proxy.getinfo()['last_block_processed']
        log.debug("Fetching zonefiles in range ({}, {})".format(
            last_block + 1, core_last_block))
        if core_last_block < last_block + 1:
            return

        zonefiles_in_blocks = proxy.get_zonefiles_by_block(last_block + 1,
                                                           core_last_block)
        if 'error' in zonefiles_in_blocks:
            log.error("Error fetching zonefile info: {}".format(zonefiles_in_blocks))
            return
        core_last_block = min(zonefiles_in_blocks['last_block'],
                              core_last_block)
        zonefiles_info = zonefiles_in_blocks['zonefile_info']
        if len(zonefiles_info) == 0:
            return
        zonefiles_info.sort( key = lambda a : a['block_height'] )
        domains, hashes, blockids, txids = map( list,
                                                zip(* [ ( x['name'], x['zonefile_hash'],
                                                          x['block_height'],
                                                          x['txid'] )
                                                        for x in zonefiles_info ]))
        zf_dict = {}
        zonefiles_to_fetch_per = 100
        for offset in range(0, len(hashes)/zonefiles_to_fetch_per + 1):
            lower = offset * zonefiles_to_fetch_per
            upper = min(lower + zonefiles_to_fetch_per, len(hashes))
            zf_resp = proxy.get_zonefiles(
                None, hashes[lower:upper], proxy = proxy.get_default_proxy())
            if 'zonefiles' not in zf_resp:
                log.error("Couldn't get zonefiles from proxy {}".format(zf_resp))
                return
            zf_dict.update( zf_resp['zonefiles'] )
        if len(zf_dict) == 0:
            return
        could_not_find = []
        zonefiles = []
        for ix, zf_hash in enumerate(hashes):
            if zf_hash not in zf_dict:
                could_not_find.append(ix)
            else:
                zonefiles.append(zf_dict[zf_hash])
        could_not_find.sort(reverse=True)
        for ix in could_not_find:
            del domains[ix]
            del hashes[ix]
            del blockids[ix]
            del txids[ix]

        _build_subdomain_db(domains, zonefiles, self, txids)

        last_block = core_last_block

        self._set_last_seen(last_block)

    def __setitem__(self, fqn, subdomain_obj):
        assert isinstance(subdomain_obj, Subdomain)
        is_subdomain = is_address_subdomain(fqn)
        if is_subdomain:
            (subdomain_name, domain_name) = is_subdomain[1]
        else:
            raise Exception("Must give fully qualified name: given: {}".format(fqn))

        assert subdomain_name == subdomain_obj.subdomain_name
        assert domain_name == subdomain_obj.domain

        write_cmd = """INSERT OR REPLACE INTO {} VALUES
                       (?, ?, ?, ?, ?, ?) """.format(self.subdomain_table)
        cursor = self.conn.cursor()
        cursor.execute(write_cmd,
                       (fqn,
                        subdomain_obj.n,
                        subdomain_obj.address,
                        subdomain_obj.zonefile_str,
                        subdomain_obj.sig,
                        subdomain_obj.last_txid))
        self.conn.commit()

    def __getitem__(self, fqn):
        return self.get_subdomain_entry(fqn)

    def __contains__(self, fqn):
        try:
            _ = self[fqn]
            return True
        except SubdomainNotFound:
            return False

    def _set_last_seen(self, block):
        write_cmd = """INSERT INTO {} VALUES (?)""".format(self.status_table)
        cursor = self.conn.cursor()
        cursor.execute(write_cmd, (block,))
        self.conn.commit()

    def last_seen(self):
        get_cmd = """SELECT * FROM {} ORDER BY lastBlock DESC LIMIT 1""".format(
            self.status_table)
        cursor = self.conn.cursor()
        cursor.execute(get_cmd)
        try:
            last_block = cursor.fetchone()[0]
        except:
            return 0
        return int(last_block)

    def get_last_index(self):
        """
        Returns the last sequence number for the subdomain DB.
        WARNING: this is specific to *this* instance, and *this* DB,
        if you use this, it should *only* be as an optimization.
        """
        get_cmd = """SELECT sequence FROM {} ORDER BY sequence DESC LIMIT 1""".format(
            self.subdomain_table)
        cursor = self.conn.cursor()
        cursor.execute(get_cmd)
        try:
            last_seq = cursor.fetchone()[0]
        except:
            return 0
        return int(last_seq)

    def _drop_tables(self):
        drop_cmd = "DROP TABLE IF EXISTS {};"
        cursor = self.conn.cursor()
        cursor.execute(drop_cmd.format(self.subdomain_table))
        cursor.execute(drop_cmd.format(self.status_table))

    def _create_tables(self):
        create_cmd = """CREATE TABLE IF NOT EXISTS {} (
        fully_qualified_subdomain TEXT PRIMARY KEY,
        sequence INTEGER,
        owner TEXT,
        zonefile TEXT,
        signature TEXT,
        last_txid TEXT);
        """.format(self.subdomain_table)
        create_status_cmd = """CREATE TABLE IF NOT EXISTS {} (
        lastBlock INTEGER);""".format(
            self.status_table)
        cursor = self.conn.cursor()
        cursor.execute(create_cmd)
        cursor.execute(create_status_cmd)

def is_resolving_subdomains():
    return config.get_is_resolving_subdomains()

def parse_zonefile_subdomains(domain, zonefile_json):
    registrar_urls = []

    if "txt" in zonefile_json:
        subdomains = [ Subdomain.parse_subdomain_record(domain, x) for x in zonefile_json["txt"]
                       if subdomain_util.is_subdomain_record(x) ]
    else:
        subdomains = []

    return subdomains

def is_address_subdomain(fqa):
    """
    Tests whether fqa is a subdomain.
    @fqa must be a string
    If it isn't, returns False.
    If it is, returns True and a tuple (subdomain_name, domain)
    """
    if re.match(schemas.OP_SUBDOMAIN_NAME_PATTERN, fqa) == None:
        return False
    pieces = fqa.split(".")
    if len(pieces) == 3:
        subd_name = pieces[0]
        if len(subd_name) < 1:
            return False
        domain  = fqa[len(subd_name) + 1:]
        error = safety.check_valid_name(domain)
        if error:
            return False
        return (True, (subd_name, domain))
    return False

def _transition_valid(from_sub_record, to_sub_record):
    if from_sub_record.n + 1 != to_sub_record.n:
        log.warn("Failed subdomain {} transition because of N:{}->{}".format(
            to_sub_record.get_fqn() , from_sub_record.n, to_sub_record.n))
        return False
    if not to_sub_record.verify_signature(from_sub_record.address):
        log.warn("Failed subdomain {} transition because of signature failure".format(
            to_sub_record.get_fqn()))
        return False
    return True

def _build_subdomain_db(domain_fqas, zonefiles, subdomain_db = None, txids = None):
    if subdomain_db is None:
        subdomain_db = {}
    if txids is None:
        txids = [None for x in zonefiles]
    for zf, domain_fqa, txid in zip(zonefiles, domain_fqas, txids):
        if isinstance(zf, dict):
            assert "zonefile" not in zf
            zf_json = zf
        else:
            assert isinstance(zf, (str, unicode))
            zf_json = bs_zonefile.decode_name_zonefile(domain_fqa, zf)
            assert "zonefile" not in zf_json

        subdomains = parse_zonefile_subdomains(domain_fqa, zf_json)

        for subdomain in subdomains:
            if txid:
                subdomain.last_txid = txid
            if subdomain.get_fqn() in subdomain_db:
                previous = subdomain_db[subdomain.get_fqn()]
                if _transition_valid(previous, subdomain):
                    subdomain_db[subdomain.get_fqn()] = subdomain
                else:
                    log.warn("Failed subdomain transition for {} on N:{}->{}".format(
                        subdomain.get_fqn(), previous.n, subdomain.n))
            else:
                if subdomain.n != 0:
                    log.warn("First sight of subdomain {} with N={}".format(
                        subdomain.get_fqn(), subdomain.n))
                    continue
                subdomain_db[subdomain.get_fqn()] = subdomain
    return subdomain_db

def issue_zonefile(domain_fqa, user_data_txt):
    from blockstack_client.rpc import local_api_connect
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

def get_subdomain_info(subdomain, domain_fqa, use_cache = True):
    if not is_resolving_subdomains():
        log.error('Tried to resolve subdomain, but subdomain resolution is turned off in this client.')
        raise SubdomainNotFound(subdomain)

    if not use_cache:
        from blockstack_client import data
        zonefiles = data.list_zonefile_history(domain_fqa)
        subdomain_db = _build_subdomain_db([domain_fqa for z in zonefiles], zonefiles)
    else:
        subdomain_db = SubdomainDB()
        subdomain_db.update()
    try:
        subdomain_obj = subdomain_db["{}.{}".format(subdomain, domain_fqa)]
    except Exception as e:
        log.exception(e)
        log.error("Raising SubdomainNotFound({}) from exception {}".format(subdomain, e))
        raise SubdomainNotFound(subdomain)

    return subdomain_obj

def resolve_subdomain(subdomain, domain_fqa, use_cache = True):
    if not is_resolving_subdomains():
        log.error('Tried to resolve subdomain, but subdomain resolution is turned off in this client.')
        raise SubdomainNotFound(subdomain)
    subdomain_obj = get_subdomain_info(subdomain, domain_fqa, use_cache = use_cache)
    return subdomain_record_to_profile(subdomain_obj)

def subdomain_record_to_profile(my_rec):
    owner_addr = my_rec.address

    assert isinstance(my_rec.zonefile_str, (str, unicode))

    parsed_zf = bs_zonefile.decode_name_zonefile(my_rec.subdomain_name, my_rec.zonefile_str)
    urls = user_db.user_zonefile_urls(parsed_zf)

    # try to get pubkey from zonefile, or default to ``owner`` pubkey
    user_data_pubkey = None
    profile_pubkey = None
    try:
        user_data_pubkey = user_db.user_zonefile_data_pubkey(parsed_zf)
        if user_data_pubkey is not None:
            user_data_pubkey = str(user_data_pubkey)
    except ValueError:
        pass # no pubkey defined in zonefile

    try:
        user_profile_res = storage.get_mutable_data(
            None, user_data_pubkey, blockchain_id=None,
            data_address=owner_addr, owner_address=None,
            urls=urls, drivers=None, decode=True, return_public_key=True
        )

        user_profile = user_profile_res['data']
        profile_pubkey = user_profile_res['public_key']
    except:
        user_profile = None

    if user_profile is None:
        user_profile = {'error' :
                        'Error fetching the data for subdomain {}'.format(my_rec.get_fqn())}

    data = { 'profile' : user_profile,
             'zonefile' : parsed_zf,
             'public_key': profile_pubkey }

    return data

def get_subdomains_owned_by_address(address):
    if not is_resolving_subdomains():
        return []

    db = SubdomainDB()
    db.update()
    return db.get_subdomains_owned_by_address(address)

##
# Aaron: what follows is verification and signing code for subdomains.
#   because subdomains are ownable by either a single-sig *address* or
#   a multi-sig *address*, the sign/verify process has to be 'bitcoin-like'
#   the data to be verified is hashed, and then verified using one of two
#   processes:
#
#       multi-sig: parse b64 signature blob as a scriptSig, parse out the
#                  redeem script portion and sigs, verify with OPCHECKMULTISIG
#                  verify redeem script matches owner address.
#       single-sig: parse b64 signature blob as a scriptSig, parse out the
#                   pubkey and sig, verify like OPCHECKSIG.
#                   verify pubkey matches owner address.
##

def verify(address, plaintext, scriptSigb64):
    assert isinstance(address, str)

    scriptSig = base64.b64decode(scriptSigb64)
    hash_hex = binascii.hexlify(hashlib.sha256(plaintext).digest())

    vb = keylib.b58check.b58check_version_byte(address)

    if vb == 0:
        return verify_singlesig(address, hash_hex, scriptSig)
    elif vb == 5:
        return verify_multisig(address, hash_hex, scriptSig)
    else:
        raise NotImplementedError("Addresses must be single-sig (version-byte = 0) or multi-sig (version-byte = 5)")

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

def verify_singlesig(address, hash_hex, scriptSig):
    sighex, pubkey_hex = virtualchain.btc_script_deserialize(scriptSig)
    # verify pubkey_hex corresponds to address
    if keylib.ECPublicKey(pubkey_hex).address() != address:
        log.warn(("Address {} does not match the public key in the" +
                  " provided scriptSig: provided pubkey = {}").format(
                      address, pubkey_hex))
        return False

    sig64 = base64.b64encode(binascii.unhexlify(sighex))

    return virtualchain.ecdsalib.verify_digest(hash_hex, pubkey_hex, sig64)

def sign_multisig(hash_hex, redeem_script, secret_keys):
    assert len(redeem_script) > 0
    m, pk_hexes = virtualchain.parse_multisig_redeemscript(redeem_script)

    privs = {}
    for sk in secret_keys:
        pk = virtualchain.ecdsalib.ecdsa_private_key(sk).public_key().to_hex()

        compressed_pubkey = keylib.key_formatting.compress(pk)
        uncompressed_pubkey = keylib.key_formatting.decompress(pk)

        privs[compressed_pubkey] = sk
        privs[uncompressed_pubkey] = sk

    used_keys, sigs = [],[]
    for pk in pk_hexes:
        if pk not in privs:
            continue
        if len(used_keys) == m:
            break
        assert pk not in used_keys, 'Tried to reuse key {}'.format(pk)

        sk_hex = privs[pk]
        used_keys.append(pk)

        b64sig = virtualchain.ecdsalib.sign_digest(hash_hex, sk_hex)
        sighex = binascii.hexlify(base64.b64decode(b64sig))
        sigs.append(sighex)

    assert len(used_keys) == m, 'Missing private keys (used {}, required {})'.format(len(used_keys), m)
    return base64.b64encode(virtualchain.btc_script_serialize([None] + sigs + [redeem_script]))


def verify_multisig(address, hash_hex, scriptSig):
    script_parts = virtualchain.btc_script_deserialize(scriptSig)
    if len(script_parts) < 2:
        log.warn("Verfiying multisig failed, couldn't grab script parts")
        return False
    redeem_script = script_parts[-1]
    script_sigs = script_parts[1:-1]

    if virtualchain.btc_make_p2sh_address(redeem_script) != address:
        log.warn(("Address {} does not match the public key in the" +
                  " provided scriptSig: provided redeemscript = {}").format(
                      address, redeem_script))
        return False

    m, pk_hexes = virtualchain.parse_multisig_redeemscript(redeem_script)
    if len(script_sigs) != m:
        log.warn("Failed to validate multi-sig, not correct number of signatures: have {}, require {}".format(
            len(script_sigs), m))
        return False

    cur_pk = 0
    for cur_sig in script_sigs:
        sig64 = base64.b64encode(binascii.unhexlify(cur_sig))
        sig_passed = False
        while not sig_passed:
            if cur_pk >= len(pk_hexes):
                log.warn("Failed to validate multi-signature, ran out of pks to check")
                return False
            sig_passed = virtualchain.ecdsalib.verify_digest(hash_hex, pk_hexes[cur_pk], sig64)
            cur_pk += 1

    return True

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



def get_update_nameops(block):
    nameops_at = proxy.get_nameops_affected_at(block)
    return [ str(n['name']) for n in nameops_at if n['opcode'] == "NAME_UPDATE" ]
