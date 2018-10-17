#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2017-2018 by Blockstack.org

    This file is part of Blockstack.

    Blockstack is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
"""

import sqlite3

import base64, copy, re, binascii
from itertools import izip
import hashlib
import keylib
import jsonschema
import virtualchain
import blockstack_zones
import threading

import virtualchain.lib.blockchain.bitcoin_blockchain as bitcoin_blockchain

from .config import BLOCKSTACK_TESTNET, BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, SUBDOMAINS_FIRST_BLOCK, get_blockstack_opts, is_atlas_enabled, is_subdomains_enabled, \
        SUBDOMAIN_ADDRESS_VERSION_BYTE, SUBDOMAIN_ADDRESS_MULTISIG_VERSION_BYTE, SUBDOMAIN_ADDRESS_VERSION_BYTES

from .atlas import atlasdb_open, atlasdb_get_zonefiles_by_block, atlas_node_add_callback, atlasdb_query_execute, atlasdb_get_zonefiles_by_hash, atlasdb_get_zonefiles_missing_count_by_name
from .storage import get_atlas_zonefile_data, get_zonefile_data_hash, store_atlas_zonefile_data 
from .scripts import is_name_valid, is_address_subdomain, is_subdomain
from .schemas import *
from .util import db_query_execute, parse_DID, make_DID
from .queue import *

log = virtualchain.get_logger('blockstack-subdomains')

# special case zone file TXT RR names
SUBDOMAIN_TXT_RR_MISSING = "_missing"
SUBDOMAIN_TXT_RR_RESOLVER = "_resolver"
SUBDOMAIN_TXT_RR_REGISTRAR = "_registrar"

SUBDOMAIN_TXT_RR_RESERVED = [SUBDOMAIN_TXT_RR_MISSING, SUBDOMAIN_TXT_RR_RESOLVER, SUBDOMAIN_TXT_RR_REGISTRAR]

# names of subdomain record fields
SUBDOMAIN_ZF_PARTS = "parts"
SUBDOMAIN_ZF_PIECE = "zf%d"
SUBDOMAIN_SIG = "sig"
SUBDOMAIN_PUBKEY = "owner"
SUBDOMAIN_N = "seqn"

log = virtualchain.get_logger()

class DomainNotOwned(Exception):
    """
    Exception thrown when the stem name is not found
    """
    pass


class SubdomainNotFound(Exception):
    """
    Exception thrown when the subdomain is not found
    """
    pass


class SubdomainAlreadyExists(Exception):
    """
    Exception thrown when a subdomain already exists, but
    we tried to add it again
    """
    def __init__(self, subdomain, domain):
        self.subdomain = subdomain
        self.domain = domain
        super(SubdomainAlreadyExists, self).__init__(
            "Subdomain already exists: {}.{}".format(subdomain, domain))


class ParseError(Exception):
    """
    Subdomain parse error
    """
    pass


class Subdomain(object):
    """
    Subdomain entry
    """
    def __init__(self, fqn, domain, address, n, zonefile_str, sig, block_height, parent_zonefile_hash, parent_zonefile_index, zonefile_offset, txid, domain_zonefiles_missing=[], accepted=False, resolver=None):
        """
        @fqn: fully-qualified subdomain name
        @domain: the stem name at which this subdomain record was found
        @address: the base58check-encoded owner of this subdomain
        @n: the sequence number, which increments each time the subdomain changes
        @zonefile_str: the zone file data for this subdomain
        @sig: signature over the subdomain entry
        """
        is_subdomain, subd, _ = is_address_subdomain(fqn)
        assert is_subdomain, 'Not a fully-qualified subdomain name: {}'.format(fqn)

        self.subdomain = subd       # the leaf name
        self.fqn = fqn              # fully-qualified name
        self.domain = domain        # domain name of the zone file that carried this record (not necessarily the stem of fqn)
        self.address = address      # owner address
        self.n = n                  # update sequence number (0 for creation, 1+ for update)
        self.zonefile_str = zonefile_str    # zonefile payload for this record
        self.sig = sig              # signature (base64-encoded scripsig)

        # pertinent information discovered when querying for subdomains
        self.block_height = block_height
        self.parent_zonefile_index = parent_zonefile_index
        self.zonefile_offset = zonefile_offset
        self.parent_zonefile_hash = parent_zonefile_hash
        self.txid = txid
        self.independent = False        # indicates whether or not this record is independent of its domain (i.e. a.b.id is independent of c.id, but not b.id)
        self.accepted = accepted

        if not fqn.endswith('.' + domain):
            self.independent = True

        self.domain_zonefiles_missing = domain_zonefiles_missing
        self.pending = None     # set at runtime
        self.did_info = None    # set at runtime
        
        self.resolver = resolver


    def get_fqn(self):
        """
        Get fuly-qualified name
        """
        return self.fqn
   

    def get_domain(self):
        """
        Get the domain name that processed this subdomain record
        """
        return self.domain


    def pack_subdomain(self):
        """
        Pack all of the data for this subdomain into a list of strings.
        The list of strings will be given in the order in which they should be signed.
        That is: NAME, ADDR, N, NUM_ZF_PARTS ZF_PARTS, IN_ORDER_PIECES, (? SIG)
        """
        output = []

        # name (only fully-qualified if independent of the domain name)
        if self.independent:
            output.append(self.fqn)
        else:
            _, subdomain_name, _ = is_address_subdomain(self.fqn)
            output.append(subdomain_name)

        # address
        output.append(txt_encode_key_value(SUBDOMAIN_PUBKEY, self.address))

        # sequence number 
        output.append(txt_encode_key_value(SUBDOMAIN_N, "{}".format(self.n)))
        
        # subdomain zone file data, broken into 255-character base64 strings.
        # let's pack into 250 byte strings -- the entry "zf99=" eliminates 5 useful bytes,
        # and the max is 255.
        encoded_zf = base64.b64encode(self.zonefile_str)
        n_pieces = (len(encoded_zf) / 250) + 1
        if len(encoded_zf) % 250 == 0:
            n_pieces -= 1
        
        # number of pieces
        output.append(txt_encode_key_value(SUBDOMAIN_ZF_PARTS, "{}".format(n_pieces)))

        for i in range(n_pieces):
            start = i * 250
            piece_len = min(250, len(encoded_zf[start:]))
            assert piece_len != 0
            piece = encoded_zf[start:(start+piece_len)]

            # next piece
            output.append(txt_encode_key_value(SUBDOMAIN_ZF_PIECE % i, piece))

        # signature (optional)
        if self.sig is not None:
            output.append(txt_encode_key_value(SUBDOMAIN_SIG, self.sig))

        return output


    def verify_signature(self, addr):
        """
        Given an address, verify whether or not it was signed by it
        """
        return verify(virtualchain.address_reencode(addr), self.get_plaintext_to_sign(), self.sig)


    def get_plaintext_to_sign(self):
        """
        Get back the plaintext that will be signed.
        It is derived from the serialized zone file strings,
        but encoded as a single string (omitting the signature field,
        if already given)
        """
        as_strings = self.pack_subdomain()
        if self.sig is not None:
            # don't sign the signature
            as_strings = as_strings[:-1]

        return ",".join(as_strings)
    

    def serialize_to_txt(self):
        """
        Serialize this subdomain record to a TXT record.  The trailing newline will be omitted
        """
        txtrec = {
            'name': self.fqn if self.independent else self.subdomain,
            'txt': self.pack_subdomain()[1:]
        }
        return blockstack_zones.record_processors.process_txt([txtrec], '{txt}').strip()


    def to_json(self):
        """
        Serialize to JSON, which can be returned e.g. via RPC
        """
        ret = {
            'address': self.address,
            'domain': self.domain,
            'block_number': self.block_height,
            'sequence': self.n,
            'txid': self.txid,
            'value_hash': get_zonefile_data_hash(self.zonefile_str),
            'zonefile': base64.b64encode(self.zonefile_str),
            'name': self.get_fqn(),
        }
        
        if self.pending is not None:
            ret['pending'] = self.pending

        if self.resolver is not None:
            ret['resolver'] = self.resolver

        return ret
   

    @classmethod
    def parse_subdomain_missing_zonefiles_record(cls, rec):
        """
        Parse a missing-zonefiles vector given by the domain.
        Returns the list of zone file indexes on success
        Raises ParseError on unparseable records
        """
        txt_entry = rec['txt']
        if isinstance(txt_entry, list):
            raise ParseError("TXT entry too long for a missing zone file list")

        try:
            return [int(i) for i in txt_entry.split(',')] if txt_entry is not None and len(txt_entry) > 0 else []
        except ValueError:
            raise ParseError('Invalid integers')


    @staticmethod
    def parse_subdomain_record(domain_name, rec, block_height, parent_zonefile_hash, parent_zonefile_index, zonefile_offset, txid, domain_zonefiles_missing, resolver=None):
        """
        Parse a subdomain record, and verify its signature.
        @domain_name: the stem name
        @rec: the parsed zone file, with 'txt' records

        Returns a Subdomain object on success
        Raises an exception on parse error
        """
        # sanity check: need 'txt' record list
        txt_entry = rec['txt']
        if not isinstance(txt_entry, list):
            raise ParseError("Tried to parse a TXT record with only a single <character-string>")
       
        entries = {}    # parts of the subdomain record
        for item in txt_entry:
            # coerce string
            if isinstance(item, unicode):
                item = str(item)

            key, value = item.split('=', 1)
            value = value.replace('\\=', '=')  # escape '='
            
            if key in entries:
                raise ParseError("Duplicate TXT entry '{}'".format(key))

            entries[key] = value

        pubkey = entries[SUBDOMAIN_PUBKEY]
        n = entries[SUBDOMAIN_N]
        if SUBDOMAIN_SIG in entries:
            sig = entries[SUBDOMAIN_SIG]
        else:
            sig = None
        
        try:
            zonefile_parts = int(entries[SUBDOMAIN_ZF_PARTS])
        except ValueError:
            raise ParseError("Not an int (SUBDOMAIN_ZF_PARTS)")
        
        try:
            n = int(n)
        except ValueError:
            raise ParseError("Not an int (SUBDOMAIN_N)")

        b64_zonefile = "".join([entries[SUBDOMAIN_ZF_PIECE % zf_index] for zf_index in range(zonefile_parts)])
        
        is_subdomain, _, _ = is_address_subdomain(rec['name'])
        subd_name = None
        if not is_subdomain:
            # not a fully-qualified subdomain, which means it ends with this domain name
            try:
                assert is_name_valid(str(domain_name)), domain_name
                subd_name = str(rec['name'] + '.' + domain_name)
                assert is_address_subdomain(subd_name)[0], subd_name
            except AssertionError as ae:
                if BLOCKSTACK_DEBUG:
                    log.exception(ae)

                raise ParseError("Invalid names: {}".format(ae))

        else:
            # already fully-qualified
            subd_name = rec['name']
            
        return Subdomain(str(subd_name), str(domain_name), str(pubkey), int(n), base64.b64decode(b64_zonefile), str(sig), block_height, parent_zonefile_hash, parent_zonefile_index, zonefile_offset, txid, domain_zonefiles_missing=domain_zonefiles_missing, resolver=resolver)


    def get_public_key(self):
        """
        Parse the scriptSig and extract the public key.
        Raises ValueError if this is a multisig-controlled subdomain.
        """
        res = self.get_public_key_info()
        if 'error' in res:
            raise ValueError(res['error'])

        if res['type'] != 'singlesig':
            raise ValueError(res['error'])

        return res['public_keys'][0]


    def get_public_keys(self):
        """
        Parse the scriptSig and extract the public keys and number of required signatures.
        Raises ValueError if this is a singlesig-controlled subdomain.
        """
        res = self.get_public_key_info()
        if res['type'] != 'multisig':
            raise ValueError(res['error'])

        return res

    
    def get_public_key_info(self):
        """
        Analyze the public key information we have in our scriptSig.
        Returns {'status': true, 'type': 'singlesig' | 'multisig', 'public_keys': [...], 'num_sigs': ...} on success
        Returns {'error': ...} on error
        """
        script_parts = virtualchain.btc_script_deserialize(base64.b64decode(self.sig))
        if len(script_parts) < 2:
            return {'error': 'Signature script does not appear to encode any public keys'}

        if len(script_parts) == 2:
            # possibly p2pkh
            pubkey = script_parts[1].encode('hex')
            try:
                pubkey_object = virtualchain.ecdsalib.ecdsa_public_key(pubkey)
            except:
                return {'error': 'Could not instantiate public key {}'.format(pubkey)}

            if virtualchain.address_reencode(pubkey_object.address()) != virtualchain.address_reencode(self.address):
                return {'error': 'Public key does not match owner address {}'.format(self.address)}

            return {'status': True, 'type': 'singlesig', 'public_keys': [pubkey], 'num_sigs': 1}

        else:
            # possibly p2sh multisig.
            redeem_script = script_parts[-1]

            if virtualchain.address_reencode(virtualchain.btc_make_p2sh_address(redeem_script)) != virtualchain.address_reencode(self.address):
                return {'error': 'Multisig redeem script does not match owner address {}'.format(self.address)}

            m, pubkey_hexes = virtualchain.parse_multisig_redeemscript(redeem_script)
            for pkh in pubkey_hexes:
                try:
                    virtualchain.ecdsalib.ecdsa_public_key(pkh)
                except:
                    return {'error': 'Invalid public key string in multisig script'}

            return {'status': True, 'type': 'multisig', 'public_keys': pubkey_hexes, 'num_sigs': m}


    def __repr__(self):
        return 'Subdomain(fqn={},domain={},seq={},address={},zfhash={},zfindex={})'.format(
                self.get_fqn(), self.domain, self.n, self.address, get_zonefile_data_hash(self.zonefile_str), self.parent_zonefile_index)


class SubdomainIndex(object):
    """
    Process zone files as they arrive for subdomain state, and as instructed by an external caller.
    """
    def __init__(self, subdomain_db_path, blockstack_opts=None):

        if blockstack_opts is None:
            blockstack_opts = get_blockstack_opts()

        assert is_atlas_enabled(blockstack_opts), 'Cannot start subdomain indexer since Atlas is disabled'
        
        self.subdomain_db_path = subdomain_db_path
        self.subdomain_queue_path = self.subdomain_db_path + ".queue"
        self.subdomain_db = SubdomainDB(subdomain_db_path, blockstack_opts['zonefiles'])
        self.subdomain_db_lock = threading.Lock()

        self.serialized_enqueue_zonefile = threading.Lock()

        self.atlasdb_path = blockstack_opts['atlasdb_path']
        self.zonefiles_dir = blockstack_opts['zonefiles']

        log.debug("SubdomainIndex: db={}, atlasdb={}, zonefiles={}".format(subdomain_db_path, self.atlasdb_path, self.zonefiles_dir))


    def close(self):
        """
        Close the index
        """
        with self.subdomain_db_lock:
            self.subdomain_db.close()
            self.subdomain_db = None
            self.subdomain_db_path = None


    def get_db(self):
        """
        Get the DB handle
        """
        return self.subdomain_db


    @classmethod
    def check_subdomain_transition(cls, existing_subrec, new_subrec):
        """
        Given an existing subdomain record and a (newly-discovered) new subdomain record,
        determine if we can use the new subdomain record (i.e. is its signature valid? is it in the right sequence?)
        Return True if so
        Return False if not
        """
        if existing_subrec.get_fqn() != new_subrec.get_fqn():
            return False

        if existing_subrec.n + 1 != new_subrec.n:
            return False

        if not new_subrec.verify_signature(existing_subrec.address):
            log.debug("Invalid signature from {}".format(existing_subrec.address))
            return False

        if virtualchain.address_reencode(existing_subrec.address) != virtualchain.address_reencode(new_subrec.address):
            if new_subrec.independent:
                log.debug("Transfer is independent of domain: {}".format(new_subrec))
                return False

        return True


    @classmethod
    def check_initial_subdomain(cls, subdomain_rec):
        """
        Verify that a first-ever subdomain record is well-formed.
        * n must be 0
        * the subdomain must not be independent of its domain
        """
        if subdomain_rec.n != 0:
            return False
       
        if subdomain_rec.independent:
            return False

        return True


    def find_zonefile_subdomains(self, block_start, block_end, name=None):
        """
        Find the sequence of subdomain operations over a block range (block_end is excluded).
        Does not check for validity or signature matches; only that they are well-formed.

        Optionally only finds zone file updates for a specific name

        Returns {
            'zonefile_info': [{'name':.., 'zonefile_hash':..., 'block_height':..., 'txid':..., 'subdomains': [...] or None}], # in blockchain order
            'subdomains': {'fqn': [indexes into zonefile_info]}
        }

        'subdomains' will map to a list if we had the zone file and were able to parse it.
        'subdomains' will map to None if we did not have the zone file, period (means we can't process anything for the given name beyond this point)
        """
        assert block_start < block_end
        
        subdomain_info = []
        offset = 0
        count = 100
        con = atlasdb_open(self.atlasdb_path)

        while True:
            # NOTE: filtered on name
            range_subdomain_info = atlasdb_get_zonefiles_by_block(block_start, block_end-1, offset, count, name=name, con=con)
            if len(range_subdomain_info) == 0:
                break

            offset += count
            subdomain_info += range_subdomain_info

        con.close()
       
        log.debug("Found {} zonefile hashes between {} and {} for {}".format(len(subdomain_info), block_start, block_end, '"{}"'.format(name) if name is not None else 'all names'))

        # extract sequence of subdomain operations for each zone file discovered
        for i, sdinfo in enumerate(subdomain_info):
            # find and parse zone file data
            sddata = get_atlas_zonefile_data(sdinfo['zonefile_hash'], self.zonefiles_dir)
            if sddata is None:
                # no zone file
                log.debug("Missing zonefile {} (at {})".format(sdinfo['zonefile_hash'], sdinfo['block_height']))
                subdomain_info[i]['subdomains'] = None
                continue

            subdomains = decode_zonefile_subdomains(sdinfo['name'], sddata, sdinfo['block_height'], sdinfo['inv_index'], sdinfo['txid'])
            if subdomains is None:
                # have zone file, but no subdomains
                subdomains = []

            log.debug("Found {} subdomain record(s) for '{}' in zonefile {} at {} (index {})".format(len(subdomains), sdinfo['name'], sdinfo['zonefile_hash'], sdinfo['block_height'], sdinfo['inv_index']))
            subdomain_info[i]['subdomains'] = subdomains

        # group discovered subdomain records by subdomain name
        subdomain_index = {}
        for i, zfinfo in enumerate(subdomain_info):
            if zfinfo['subdomains'] is None:
                # no zone file
                continue

            for sd in zfinfo['subdomains']:
                fqn = sd.get_fqn()
                if fqn not in subdomain_index:
                    subdomain_index[fqn] = []

                subdomain_index[fqn].append(i)

        return {'zonefile_info': subdomain_info, 'subdomains': subdomain_index}
                
    
    def make_new_subdomain_history(self, cursor, subdomain_rec):
        """
        Recalculate the history for this subdomain from genesis up until this record.
        Returns the list of subdomain records we need to save.
        """
        # what's the subdomain's history up until this subdomain record?
        hist = self.subdomain_db.get_subdomain_history(subdomain_rec.get_fqn(), include_unaccepted=True, end_sequence=subdomain_rec.n+1, end_zonefile_index=subdomain_rec.parent_zonefile_index+1, cur=cursor)
        assert len(hist) > 0, 'BUG: not yet stored: {}'.format(subdomain_rec)

        for i in range(0, len(hist)):
            hist[i].accepted = False

        hist.sort(lambda h1, h2: -1 if h1.n < h2.n or (h1.n == h2.n and h1.parent_zonefile_index < h2.parent_zonefile_index) \
                                 else 0 if h1.n == h2.n and h1.parent_zonefile_index == h2.parent_zonefile_index \
                                 else 1)

        if not self.check_initial_subdomain(hist[0]):
            log.debug("Reject initial {}".format(hist[0]))
            return hist
        else:
            log.debug("Accept initial {}".format(hist[0]))
            pass

        hist[0].accepted = True
        last_accepted = 0

        for i in xrange(1, len(hist)):
            if self.check_subdomain_transition(hist[last_accepted], hist[i]):
                log.debug("Accept historic update {}".format(hist[i]))
                hist[i].accepted = True
                last_accepted = i
            else:
                log.debug("Reject historic update {}".format(hist[i]))
                hist[i].accepted = False

        return hist


    def make_new_subdomain_future(self, cursor, subdomain_rec):
        """
        Recalculate the future for this subdomain from the current record
        until the latest known record.
        Returns the list of subdomain records we need to save.
        """
        assert subdomain_rec.accepted, 'BUG: given subdomain record must already be accepted'

        # what's the subdomain's future after this record?
        fut = self.subdomain_db.get_subdomain_history(subdomain_rec.get_fqn(), include_unaccepted=True, start_sequence=subdomain_rec.n, start_zonefile_index=subdomain_rec.parent_zonefile_index, cur=cursor)
        for i in range(0, len(fut)):
            if fut[i].n == subdomain_rec.n and fut[i].parent_zonefile_index == subdomain_rec.parent_zonefile_index:
                fut.pop(i)
                break

        if len(fut) == 0:
            log.debug("At tip: {}".format(subdomain_rec))
            return []
        
        for i in range(0, len(fut)):
            fut[i].accepted = False
            
        fut = [subdomain_rec] + fut
        fut.sort(lambda h1, h2: -1 if h1.n < h2.n or (h1.n == h2.n and h1.parent_zonefile_index < h2.parent_zonefile_index) \
                                 else 0 if h1.n == h2.n and h1.parent_zonefile_index == h2.parent_zonefile_index \
                                 else 1)

        assert fut[0].accepted, 'BUG: initial subdomain record is not accepted: {}'.format(fut[0])
        last_accepted = 0

        for i in range(1, len(fut)):
            if self.check_subdomain_transition(fut[last_accepted], fut[i]):
                log.debug("Accept future update {}".format(fut[i]))
                fut[i].accepted = True
                last_accepted = i
            else:
                log.debug("Reject future update {}".format(fut[i]))
                fut[i].accepted = False

        return fut
        

    def get_subdomain_history_neighbors(self, cursor, subdomain_rec):
        """
        Given a subdomain record, get its neighbors.
        I.e. get all of the subdomain records with the previous sequence number,
        and get all of the subdomain records with the next sequence number
        Returns {'prev': [...blockchain order...], 'cur': [...blockchain order...], 'fut': [...blockchain order...]}
        """
        # what's the subdomain's immediate prior history?
        hist = self.subdomain_db.get_subdomain_history(subdomain_rec.get_fqn(), include_unaccepted=True, start_sequence=subdomain_rec.n-1, end_sequence=subdomain_rec.n, cur=cursor)
        hist.sort(lambda h1, h2: -1 if h1.n < h2.n or (h1.n == h2.n and h1.parent_zonefile_index < h2.parent_zonefile_index) \
                                 else 0 if h1.n == h2.n and h1.parent_zonefile_index == h2.parent_zonefile_index \
                                 else 1)

        # what's the subdomain's current and immediate future?
        fut = self.subdomain_db.get_subdomain_history(subdomain_rec.get_fqn(), include_unaccepted=True, start_sequence=subdomain_rec.n, end_sequence=subdomain_rec.n+2, cur=cursor)
        fut.sort(lambda h1, h2: -1 if h1.n < h2.n or (h1.n == h2.n and h1.parent_zonefile_index < h2.parent_zonefile_index) \
                                 else 0 if h1.n == h2.n and h1.parent_zonefile_index == h2.parent_zonefile_index \
                                 else 1)

        # extract the current (conflicting) records from the future
        cur = []
        tmp_fut = []
        for f in fut:
            if f.n == subdomain_rec.n:
                cur.append(f)
            else:
                tmp_fut.append(f)

        fut = tmp_fut

        ret = {'prev': hist, 'cur': cur, 'fut': fut}
        return ret
    

    def subdomain_try_insert(self, cursor, subdomain_rec, history_neighbors):
        """
        Try to insert a subdomain record into its history neighbors.
        This is an optimization that handles the "usual" case.

        We can do this without having to rewrite this subdomain's past and future
        if (1) we can find a previously-accepted subdomain record, and (2) the transition 
        from this subdomain record to a future subdomain record preserves its
        acceptance as True.  In this case, the "far" past and "far" future are already
        consistent.
        
        Return True if we succeed in doing so.
        Return False if not.
        """
        blockchain_order = history_neighbors['prev'] + history_neighbors['cur'] + history_neighbors['fut']

        last_accepted = -1
        for i in range(0, len(blockchain_order)):
            if blockchain_order[i].accepted:
                last_accepted = i
                break

            if blockchain_order[i].n > subdomain_rec.n or (blockchain_order[i].n == subdomain_rec.n and blockchain_order[i].parent_zonefile_index > subdomain_rec.parent_zonefile_index):
                # can't cheaply insert this subdomain record,
                # since none of its immediate ancestors are accepted.
                log.debug("No immediate ancestors are accepted on {}".format(subdomain_rec))
                return False

        if last_accepted < 0:
            log.debug("No immediate ancestors or successors are accepted on {}".format(subdomain_rec))
            return False

        # one ancestor was accepted.
        # work from there.

        chain_tip_status = blockchain_order[-1].accepted

        dirty = []  # to be written
        for i in range(last_accepted+1, len(blockchain_order)):
            cur_accepted = blockchain_order[i].accepted
            new_accepted = self.check_subdomain_transition(blockchain_order[last_accepted], blockchain_order[i])
            if new_accepted != cur_accepted:
                blockchain_order[i].accepted = new_accepted
                log.debug("Changed from {} to {}: {}".format(cur_accepted, new_accepted, blockchain_order[i]))
                dirty.append(blockchain_order[i])

            if new_accepted:
                last_accepted = i

        if chain_tip_status != blockchain_order[-1].accepted and len(history_neighbors['fut']) > 0:
            # deeper reorg
            log.debug("Immediate history chain tip altered from {} to {}: {}".format(chain_tip_status, blockchain_order[-1].accepted, blockchain_order[-1]))
            return False

        # localized change.  Just commit the dirty entries
        for subrec in dirty:
            log.debug("Update to accepted={}: {}".format(subrec.accepted, subrec))
            self.subdomain_db.update_subdomain_entry(subrec, cur=cursor)

        return True

    
    def process_subdomains(self, zonefile_subdomain_info):
        """
        Takes the output of find_zonefile_subdomains, and processes the sequence of subdomain operations.
        Does state-transitions in a big step:
        * loads the current subdomain state for each subdomain affected in @zonefile_subdomain_info
        * computes and executes all valid subdomain creations and subdomain state-transitions on each
          affected subdomain, in blockchain-given and zonefile-given order.
        * stores the resulting subdomain state for each affected subdomain to the subdomain DB

        WARNING: NOT THREAD SAFE.  DO NOT CALL FROM MULTIPLE THREADS
        """

        cursor = self.subdomain_db.cursor()

        # we can afford to be fast and loose here since if the host crashes while this is going on,
        # the node will do a `restore` anyway and wipe this db out.
        db_query_execute(cursor, 'PRAGMA synchronous = off;', ())
        db_query_execute(cursor, 'PRAGMA journal_mode = off;', ())
        db_query_execute(cursor, 'BEGIN', ())

        # no matter what we do, store everything.
        # but, don't accept it yet.
        for subinfo in zonefile_subdomain_info:
            if subinfo['subdomains'] is None:
                continue

            for subrec in subinfo['subdomains']:
                subrec.accepted = False
                log.debug("Store {}".format(subrec))
                self.subdomain_db.update_subdomain_entry(subrec, cur=cursor)

        # at each zone file, find out if its subdomain creates/updates are valid
        for subinfo in zonefile_subdomain_info:

            zfhash = subinfo['zonefile_hash']
            zfindex = subinfo['inv_index']

            log.debug("Process subdomain records in zonefile {} ({})".format(subinfo['zonefile_hash'], subinfo['inv_index']))

            new_subdomain_recs = {}

            # get the set of subdomain records created by this zonefile
            if subinfo['subdomains']:
                for subrec in subinfo['subdomains']:
                    assert subrec.get_fqn() not in new_subdomain_recs, 'BUG: duplicate subdomain record for "{}" in {}'.format(subrec.get_fqn(), zfhash)
                    new_subdomain_recs[subrec.get_fqn()] = subrec
            
            for fqn in new_subdomain_recs:
                immediate_history = self.get_subdomain_history_neighbors(cursor, new_subdomain_recs[fqn])
                inserted = self.subdomain_try_insert(cursor, new_subdomain_recs[fqn], immediate_history)
                if inserted:
                    log.debug("Inserted {}".format(fqn))
                    continue

                log.debug("Rewrite history of {}".format(fqn))

                new_hist = self.make_new_subdomain_history(cursor, new_subdomain_recs[fqn])
                for subrec in new_hist:
                    self.subdomain_db.update_subdomain_entry(subrec, cur=cursor)

                last_accepted = None
                for h in reversed(new_hist):
                    if h.accepted:
                        last_accepted = h
                        break

                if last_accepted:
                    new_fut = self.make_new_subdomain_future(cursor, last_accepted)
                else:
                    new_fut = []

                for subrec in new_fut:
                    self.subdomain_db.update_subdomain_entry(subrec, cur=cursor)

        db_query_execute(cursor, 'END', ())


    def enqueue_zonefile(self, zonefile_hash, block_height):
        """
        Called when we discover a zone file.  Queues up a request to reprocess this name's zone files' subdomains.
        zonefile_hash is the hash of the zonefile.
        block_height is the minimium block height at which this zone file occurs.

        This gets called by:
        * AtlasZonefileCrawler (as it's "store_zonefile" callback).
        * rpc_put_zonefiles() 
        """
        with self.serialized_enqueue_zonefile:
            log.debug("Append {} from {}".format(zonefile_hash, block_height))
            queuedb_append(self.subdomain_queue_path, "zonefiles", zonefile_hash, json.dumps({'zonefile_hash': zonefile_hash, 'block_height': block_height}))
         

    def index_blockchain(self, block_start, block_end):
        """
        Go through the sequence of zone files discovered in a block range, and reindex the names' subdomains.
        """
        log.debug("Processing subdomain updates for zonefiles in blocks {}-{}".format(block_start, block_end))
        
        res = self.find_zonefile_subdomains(block_start, block_end)
        zonefile_subdomain_info = res['zonefile_info']

        self.process_subdomains(zonefile_subdomain_info)


    def index_discovered_zonefiles(self, lastblock):
        """
        Go through the list of zone files we discovered via Atlas, grouped by name and ordered by block height.
        Find all subsequent zone files for this name, and process all subdomain operations contained within them.
        """
        all_queued_zfinfos = []         # contents of the queue
        subdomain_zonefile_infos = {}   # map subdomain fqn to list of zonefile info bundles, for process_subdomains
        name_blocks = {}                # map domain name to the block at which we should reprocess its subsequent zone files

        offset = 0

        while True:
            queued_zfinfos = queuedb_findall(self.subdomain_queue_path, "zonefiles", limit=100, offset=offset)
            if len(queued_zfinfos) == 0:
                # done!
                break
            
            offset += 100
            all_queued_zfinfos += queued_zfinfos

            if len(all_queued_zfinfos) >= 1000:
                # only do so many zone files per block, so we don't stall the node
                break
        
        log.debug("Discovered {} zonefiles".format(len(all_queued_zfinfos)))

        for queued_zfinfo in all_queued_zfinfos:
            zfinfo = json.loads(queued_zfinfo['data'])

            zonefile_hash = zfinfo['zonefile_hash']
            block_height = zfinfo['block_height']

            # find out the names that sent this zone file at this block
            zfinfos = atlasdb_get_zonefiles_by_hash(zonefile_hash, block_height=block_height, path=self.atlasdb_path)
            if zfinfos is None:
                log.warn("Absent zonefile {}".format(zonefile_hash))
                continue
            
            # find out for each name block height at which its zone file was discovered.
            # this is where we'll begin looking for more subdomain updates.
            for zfi in zfinfos:
                if zfi['name'] not in name_blocks:
                    name_blocks[zfi['name']] = block_height
                else:
                    name_blocks[zfi['name']] = min(block_height, name_blocks[zfi['name']])
      
        for name in name_blocks:
            if name_blocks[name] >= lastblock:
                continue

            log.debug("Finding subdomain updates for {} at block {}".format(name, name_blocks[name]))
            
            # get the subdomains affected at this block by finding the zonefiles created here.
            res = self.find_zonefile_subdomains(name_blocks[name], lastblock, name=name)
            zonefile_subdomain_info = res['zonefile_info']
            subdomain_index = res['subdomains']
            
            # for each subdomain, find the list of zonefiles that contain records for it
            for fqn in subdomain_index:
                if fqn not in subdomain_zonefile_infos:
                    subdomain_zonefile_infos[fqn] = []

                for i in subdomain_index[fqn]:
                    subdomain_zonefile_infos[fqn].append(zonefile_subdomain_info[i])
           
        processed = []
        for fqn in subdomain_zonefile_infos:
            subseq = filter(lambda szi: szi['zonefile_hash'] not in processed, subdomain_zonefile_infos[fqn])
            if len(subseq) == 0:
                continue

            log.debug("Processing {} zone file entries found for {} and others".format(len(subseq), fqn))

            subseq.sort(cmp=lambda z1, z2: -1 if z1['block_height'] < z2['block_height'] else 0 if z1['block_height'] == z2['block_height'] else 1)
            self.process_subdomains(subseq)
            processed += [szi['zonefile_hash'] for szi in subseq]

        # clear queue 
        queuedb_removeall(self.subdomain_queue_path, all_queued_zfinfos)
        return True


    def index(self, block_start, block_end):
        """
        Entry point for indexing:
        * scan the blockchain from start_block to end_block and make sure we're up-to-date
        * process any newly-arrived zone files and re-index the affected subdomains
        """
        log.debug("BEGIN Processing zonefiles discovered since last re-indexing")
        t1 = time.time()
        self.index_discovered_zonefiles(block_end)
        t2 = time.time()
        log.debug("END Processing zonefiles discovered since last re-indexing ({} seconds)".format(t2 - t1))

    
    @classmethod
    def reindex(cls, lastblock, firstblock=None, opts=None):
        """
        Generate a subdomains db from scratch, using the names db and the atlas db and zone file collection.
        Best to do this in a one-off command (i.e. *not* in the blockstackd process)
        """
        if opts is None:
            opts = get_blockstack_opts()

        if not is_atlas_enabled(opts):
            raise Exception("Atlas is not enabled")

        if not is_subdomains_enabled(opts):
            raise Exception("Subdomain support is not enabled")

        subdomaindb_path = opts['subdomaindb_path']
        atlasdb_path = opts['atlasdb_path']
        
        if not os.path.exists(atlasdb_path):
            raise Exception("No Atlas database at {}".format(opts['atlasdb_path']))
        
        subdomain_indexer = SubdomainIndex(subdomaindb_path, blockstack_opts=opts)
        subdomain_indexer.subdomain_db.wipe()

        if firstblock is None:
            start_block = SUBDOMAINS_FIRST_BLOCK
        else:
            start_block = firstblock

        for i in range(start_block, lastblock, 100):
            log.debug("Processing all subdomains in blocks {}-{}...".format(i, i+99))
            subdomain_indexer.index_blockchain(i, i+100)

        log.debug("Finished indexing subdomains in blocks {}-{}".format(start_block, lastblock))


class SubdomainDB(object):
    """
    Subdomain database.
    Builds up a DB of subdomain names to their subdomain states as zone file arrive
    in the Atlas network
    """
    def __init__(self, db_path, zonefiles_dir):
        self.db_path = db_path
        self.queue_path = db_path + '.queue'
        self.subdomain_table = "subdomain_records"
        self.blocked_table = "blocked_table"
        self.zonefiles_dir = zonefiles_dir
        self.conn = sqlite3.connect(db_path, isolation_level=None, timeout=2**30)
        self.conn.row_factory = SubdomainDB.subdomain_row_factory
        self._create_tables()


    @classmethod
    def subdomain_row_factory(cls, cursor, row):
        """
        Dict row factory for subdomains
        """
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]

        return d

    
    def commit(self):
        """
        Commit state
        """
        self.conn.commit()


    def cursor(self):
        """
        Make and return a cursor
        """
        return self.conn.cursor()

    
    def _extract_subdomain(self, rowdata):
        """
        Extract a single subdomain from a DB cursor
        Raise SubdomainNotFound if there are no valid rows
        """
        name = str(rowdata['fully_qualified_subdomain'])
        domain = str(rowdata['domain'])
        n = str(rowdata['sequence'])
        encoded_pubkey = str(rowdata['owner'])
        zonefile_hash = str(rowdata['zonefile_hash'])
        sig = rowdata['signature']
        block_height = int(rowdata['block_height'])
        parent_zonefile_hash = str(rowdata['parent_zonefile_hash'])
        parent_zonefile_index = int(rowdata['parent_zonefile_index'])
        zonefile_offset = int(rowdata['zonefile_offset'])
        txid = str(rowdata['txid'])
        missing = [int(i) for i in rowdata['missing'].split(',')] if rowdata['missing'] is not None and len(rowdata['missing']) > 0 else []
        accepted = int(rowdata['accepted'])
        resolver = str(rowdata['resolver']) if rowdata['resolver'] is not None else None

        if accepted == 0:
            accepted = False
        else:
            accepted = True

        if sig == '' or sig is None:
            sig = None
        else:
            sig = str(sig)

        name = str(name)
        is_subdomain, _, _ = is_address_subdomain(name)
        if not is_subdomain:
            raise Exception("Subdomain DB lookup returned bad subdomain result {}".format(name))

        zonefile_str = get_atlas_zonefile_data(zonefile_hash, self.zonefiles_dir)
        if zonefile_str is None:
            log.error("No zone file for {}".format(name))
            raise SubdomainNotFound('{}: missing zone file {}'.format(name, zonefile_hash))

        return Subdomain(str(name), str(domain), str(encoded_pubkey), int(n), str(zonefile_str), sig, block_height, parent_zonefile_hash, parent_zonefile_index, zonefile_offset, txid, domain_zonefiles_missing=missing, accepted=accepted, resolver=resolver)


    def get_subdomains_count(self, accepted=True, cur=None):
        """
        Fetch subdomain names
        """
        if accepted:
            accepted_filter = 'WHERE accepted=1'
        else:
            accepted_filter = ''

        get_cmd = "SELECT COUNT(DISTINCT fully_qualified_subdomain) as count FROM {} {};".format(
            self.subdomain_table, accepted_filter)

        cursor = cur
        if cursor is None:
            cursor = self.conn.cursor()

        db_query_execute(cursor, get_cmd, ())

        try:
            rowdata = cursor.fetchone()
            return rowdata['count']
        except Exception as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)
            return 0


    def get_all_subdomains(self, offset=None, count=None, min_sequence=None, cur=None):
        """
        Get and all subdomain names, optionally over a range
        """
        get_cmd = 'SELECT DISTINCT fully_qualified_subdomain FROM {}'.format(self.subdomain_table)
        args = ()

        if min_sequence is not None:
            get_cmd += ' WHERE sequence >= ?'
            args += (min_sequence,)

        if count is not None:
            get_cmd += ' LIMIT ?'
            args += (count,)

        if offset is not None:
            get_cmd += ' OFFSET ?'
            args += (offset,)

        get_cmd += ';'

        cursor = None
        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor = cur

        rows = db_query_execute(cursor, get_cmd, args)
        subdomains = []
        for row in rows:
            subdomains.append(row['fully_qualified_subdomain'])

        return subdomains


    def get_subdomain_entry(self, fqn, accepted=True, cur=None):
        """
        Given a fully-qualified subdomain, get its (latest) subdomain record.
        Raises SubdomainNotFound if there is no such subdomain
        """
        get_cmd = "SELECT * FROM {} WHERE fully_qualified_subdomain=? {} ORDER BY sequence DESC, parent_zonefile_index DESC LIMIT 1;".format(self.subdomain_table, 'AND accepted=1' if accepted else '')
        cursor = None
        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor = cur

        db_query_execute(cursor, get_cmd, (fqn,))

        try:
            rowdata = cursor.fetchone()
            assert rowdata
        except Exception as e:
            raise SubdomainNotFound(fqn)

        return self._extract_subdomain(rowdata)

    
    def get_subdomain_entry_at_sequence(self, fqn, sequence, include_unaccepted=False, cur=None):
        """
        Given a fully-qualified subdomain and a sequence number, get its historic subdomain record at that sequence.
        Raises SubdomainNotFound if there is no such subdomain
        """
        get_cmd = "SELECT * FROM {} WHERE fully_qualified_subdomain=? AND sequence = ?".format(self.subdomain_table)
        if not include_unaccepted:
            get_cmd += " AND accepted=1"

        cursor = None
        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor = cur

        db_query_execute(cursor, get_cmd, (fqn,sequence))

        try:
            rowdata = cursor.fetchone()
            assert rowdata
        except Exception as e:
            raise SubdomainNotFound(fqn)

        return self._extract_subdomain(rowdata)

    
    def get_subdomain_entry_at_zonefile_index(self, fqn, zonefile_index, cur=None):
        """
        Given a fully-qualified subdomain and a sequence number, get its historic subdomain record at that sequence.
        Raises SubdomainNotFound if there is no such subdomain
        """
        get_cmd = "SELECT * FROM {} WHERE fully_qualified_subdomain=? AND parent_zonefile_index=?".format(self.subdomain_table)
        cursor = None
        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor = cur

        db_query_execute(cursor, get_cmd, (fqn,zonefile_index))

        try:
            rowdata = cursor.fetchone()
            assert rowdata
        except Exception as e:
            raise SubdomainNotFound(fqn)

        return self._extract_subdomain(rowdata)


    def get_subdomain_ops_at_txid(self, txid, cur=None):
        """
        Given a txid, get all subdomain operations at that txid.
        Include unaccepted operations.
        Order by zone file index
        """
        get_cmd = 'SELECT * FROM {} WHERE txid = ? ORDER BY zonefile_offset'.format(self.subdomain_table)

        cursor = None
        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor = cur

        db_query_execute(cursor, get_cmd, (txid,))

        try:
            return [x for x in cursor.fetchall()]
        except Exception as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            return []


    def get_subdomains_owned_by_address(self, owner, cur=None):
        """
        Get the list of subdomain names that are owned by a given address.
        """
        get_cmd = "SELECT fully_qualified_subdomain, MAX(sequence) FROM {} WHERE owner = ? AND accepted=1 GROUP BY fully_qualified_subdomain".format(self.subdomain_table)

        cursor = None
        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor = cur

        db_query_execute(cursor, get_cmd, (owner,))

        try:
            return [ x['fully_qualified_subdomain'] for x in cursor.fetchall() ]
        except Exception as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            return []


    def get_domain_resolver(self, domain_name, cur=None):
        """
        Get the last-knwon resolver entry for a domain name
        Returns None if not found.
        """
        get_cmd = "SELECT resolver FROM {} WHERE domain=? AND resolver != '' AND accepted=1 ORDER BY sequence DESC, parent_zonefile_index DESC LIMIT 1;".format(self.subdomain_table)

        cursor = None
        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor = cur

        db_query_execute(cursor, get_cmd, (domain_name,))

        rowdata = cursor.fetchone()
        if not rowdata:
            return None

        return rowdata['resolver']


    def get_subdomain_DID_info(self, fqn, cur=None):
        """
        Get the DID information for a subdomain.
        Raise SubdomainNotFound if there is no such subdomain

        Return {'name_type': ..., 'address': ..., 'index': ...}
        """
        subrec = self.get_subdomain_entry_at_sequence(fqn, 0, cur=cur)
        cmd = 'SELECT zonefile_offset FROM {} WHERE fully_qualified_subdomain = ? AND owner = ? AND sequence=0 AND parent_zonefile_index <= ? AND accepted=1 ORDER BY parent_zonefile_index, zonefile_offset LIMIT 1;'.format(self.subdomain_table)
        args = (fqn, subrec.address, subrec.parent_zonefile_index)

        cursor = None
        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor = cur

        rows = db_query_execute(cursor, cmd, args)
        
        zonefile_offset = None
        for r in rows:
            zonefile_offset = r['zonefile_offset']
            break

        if zonefile_offset is None:
            raise SubdomainNotFound('No rows for {}'.format(fqn))

        cmd = 'SELECT COUNT(*) FROM {} WHERE owner = ? AND sequence=0 AND (parent_zonefile_index < ? OR parent_zonefile_index = ? AND zonefile_offset < ?) AND accepted=1 ORDER BY parent_zonefile_index, zonefile_offset LIMIT 1;'.format(self.subdomain_table)
        args = (subrec.address, subrec.parent_zonefile_index, subrec.parent_zonefile_index, zonefile_offset)

        rows = db_query_execute(cursor, cmd, args)
        count = None
        for r in rows:
            count = r['COUNT(*)']
            break

        if count is None:
            raise SubdomainNotFound('No rows for {}'.format(fqn))

        return {'name_type': 'subdomain', 'address': subrec.address, 'index': count}


    def get_DID_subdomain(self, did, cur=None):
        """
        Get a subdomain, given its DID
        Raise ValueError if the DID is invalid
        Raise SubdomainNotFound if the DID does not correspond to a subdomain
        """
        did = str(did)

        try:
            did_info = parse_DID(did)
            assert did_info['name_type'] == 'subdomain', 'Not a subdomain DID'
        except:
            raise ValueError("Invalid DID: {}".format(did))
        
        original_address = did_info['address']
        name_index = did_info['index']

        # find the initial subdomain (the nth subdomain created by this address)
        cmd = 'SELECT fully_qualified_subdomain FROM {} WHERE owner = ? AND sequence = ? ORDER BY parent_zonefile_index, zonefile_offset LIMIT 1 OFFSET ?;'.format(self.subdomain_table)
        args = (original_address, 0, name_index)

        cursor = None
        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor = cur

        subdomain_name = None

        rows = db_query_execute(cursor, cmd, args)
        for r in rows:
            subdomain_name = r['fully_qualified_subdomain']
            break

        if not subdomain_name:
            raise SubdomainNotFound('Does not correspond to a subdomain: {}'.format(did))

        # get the current form
        subrec = self.get_subdomain_entry(subdomain_name, cur=cur)
        subrec.did_info = did_info
        return subrec


    def is_subdomain_zonefile_hash(self, fqn, zonefile_hash, cur=None):
        """
        Does this zone file hash belong to this subdomain?
        """
        sql = 'SELECT COUNT(zonefile_hash) FROM {} WHERE fully_qualified_subdomain = ? and zonefile_hash = ?;'.format(self.subdomain_table)
        args = (fqn,zonefile_hash)

        cursor = None
        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor = cur

        rows = db_query_execute(cursor, sql, args)
        
        count = None
        for row in rows:
            count = row['COUNT(zonefile_hash)']
            break

        return (count > 0)


    def get_subdomain_history(self, fqn, start_sequence=None, end_sequence=None, start_zonefile_index=None, end_zonefile_index=None, include_unaccepted=False, offset=None, count=None, cur=None):
        """
        Get the subdomain's history over a block range.
        By default, only include accepted history items (but set include_unaccepted=True to get them all)
        No zone files will be loaded.

        Returns the list of subdomains in order by sequnce number, and then by parent zonefile index 
        """
        sql = 'SELECT * FROM {} WHERE fully_qualified_subdomain = ? {} {} {} {} {} ORDER BY parent_zonefile_index ASC'.format(
                self.subdomain_table,
                'AND accepted=1' if not include_unaccepted else '',
                'AND parent_zonefile_index >= ?' if start_zonefile_index is not None else '',
                'AND parent_zonefile_index < ?' if end_zonefile_index is not None else '',
                'AND sequence >= ?' if start_sequence is not None else '',
                'AND sequence < ?' if end_sequence is not None else '')

        args = (fqn,)
        if start_zonefile_index is not None:
            args += (start_zonefile_index,)

        if end_zonefile_index is not None:
            args += (end_zonefile_index,)

        if start_sequence is not None:
            args += (start_sequence,)

        if end_sequence is not None:
            args += (end_sequence,)
        
        if count is not None:
            sql += ' LIMIT ?'
            args += (count,)
        
        if offset is not None:
            sql += ' OFFSET ?'
            args += (offset,)    
        
        sql += ';'

        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor = cur

        rowcursor = db_query_execute(cursor, sql, args)

        rows = []
        for rowdata in rowcursor:
            # want subdomain rec
            subrec = self._extract_subdomain(rowdata)
            rows.append(subrec)
        
        return rows


    def update_subdomain_entry(self, subdomain_obj, cur=None):
        """
        Update the subdomain history table for this subdomain entry.
        Creates it if it doesn't exist.

        Return True on success
        Raise exception on error
        """
        # sanity checks
        assert isinstance(subdomain_obj, Subdomain)
       
        # NOTE: there is no need to call fsync() on the zone file fd here---we already have the data from the on-chain name's zone file fsync'ed,
        # so this information is already durable (albeit somewhere else) and can ostensibly be restored later.
        # We get such high subdomain traffic that we cannot call fsync() here each time; otherwise we could stall the node.
        zonefile_hash = get_zonefile_data_hash(subdomain_obj.zonefile_str)
        rc = store_atlas_zonefile_data(subdomain_obj.zonefile_str, self.zonefiles_dir, fsync=False)
        if not rc:
            raise Exception("Failed to store zone file {} from {}".format(zonefile_hash, subdomain_obj.get_fqn()))
        
        write_cmd = 'INSERT OR REPLACE INTO {} VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)'.format(self.subdomain_table)
        args = (subdomain_obj.get_fqn(), subdomain_obj.domain, subdomain_obj.n, subdomain_obj.address, zonefile_hash,
                subdomain_obj.sig, subdomain_obj.block_height, subdomain_obj.parent_zonefile_hash,
                subdomain_obj.parent_zonefile_index, subdomain_obj.zonefile_offset, subdomain_obj.txid, 
                ','.join(str(i) for i in subdomain_obj.domain_zonefiles_missing),
                1 if subdomain_obj.accepted else 0,
                subdomain_obj.resolver)

        cursor = None
        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor = cur

        db_query_execute(cursor, write_cmd, args)
        num_rows_written = cursor.rowcount
        
        if cur is None:
            # not part of a transaction
            self.conn.commit()

        if num_rows_written != 1:
            raise ValueError("No row written: fqn={} seq={}".format(subdomain_obj.get_fqn(), subdomain_obj.n))

        return True


    def subdomain_check_pending(self, subrec, atlasdb_path, cur=None):
        """
        Determine whether or not a subdomain record's domain is missing zone files
        (besides the ones we expect) that could invalidate its history.
        """
        _, _, domain = is_address_subdomain(subrec.get_fqn())
        sql = 'SELECT missing FROM {} WHERE domain = ? ORDER BY parent_zonefile_index DESC LIMIT 1;'.format(self.subdomain_table)
        args = (domain,)

        cursor = None
        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor= cur

        rows = db_query_execute(cursor, sql, args)
        missing_str = ""
        try:
            rowdata = rows.fetchone()
            assert rowdata
            missing_str = rowdata['missing']
        except:
            pass

        known_missing = [int(i) for i in missing_str.split(',')] if missing_str is not None and len(missing_str) > 0 else []
        num_missing = atlasdb_get_zonefiles_missing_count_by_name(domain, indexes_exclude=known_missing, path=atlasdb_path)
        if num_missing > 0:
            log.debug("Subdomain is missing {} zone files: {}".format(num_missing, subrec))

        return num_missing > 0


    def get_last_block(self, cur=None):
        """
        Get the highest block last processed
        """
        sql = 'SELECT MAX(block_height) FROM {};'.format(self.subdomain_table)
        cursor = None
        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor = cur

        rows = db_query_execute(cursor, sql, ())
        height = 0
        try:
            rowdata = rows.fetchone()
            height = rowdata['MAX(block_height)']
        except:
            height = 0

        return height


    def get_last_sequence(self, cur=None):
        """
        Get the highest sequence number in this db
        """
        sql = 'SELECT sequence FROM {} ORDER BY sequence DESC LIMIT 1;'.format(self.subdomain_table)
        cursor = None
        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor = cur

        db_query_execute(cursor, sql, ())
        last_seq = None
        try:
            last_seq = cursor.fetchone()[0]
        except:
            last_seq = 0
        
        return int(last_seq)


    def _drop_tables(self):
        """
        Clear the subdomain db's tables
        """
        drop_cmd = "DROP TABLE IF EXISTS {};"
        for table in [self.subdomain_table, self.blocked_table]:
            cursor = self.conn.cursor()
            db_query_execute(cursor, drop_cmd.format(table), ())


    def _create_tables(self):
        """
        Set up the subdomain db's tables
        """
        cursor = self.conn.cursor()

        create_cmd = """CREATE TABLE IF NOT EXISTS {} (
        fully_qualified_subdomain TEXT NOT NULL,
        domain TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        owner TEXT NOT NULL,
        zonefile_hash TEXT NOT NULL,
        signature TEXT NOT NULL,
        block_height INTEGER NOT NULL,
        parent_zonefile_hash TEXT NOT NULL,
        parent_zonefile_index INTEGER NOT NULL,
        zonefile_offset INTEGER NOT NULL,
        txid TEXT NOT NULL,
        missing TEXT NOT NULL,
        accepted INTEGER NOT NULL,
        resolver TEXT,
        PRIMARY KEY(fully_qualified_subdomain,parent_zonefile_index));
        """.format(self.subdomain_table)
        db_query_execute(cursor, create_cmd, ())

        # set up a queue as well
        queue_con = queuedb_open(self.queue_path)
        queue_con.close()


    def wipe(self):
        """
        Delete all the tables and recreate them
        """
        self._drop_tables()
        self._create_tables()


    def close(self):
        """
        Close our db handle
        """
        self.conn.close()
        self.conn = None



def decode_zonefile_subdomains(domain, zonefile_txt, block_height, zonefile_index, txid):
    """
    Decode a serialized zone file into a zonefile structure that could contain subdomain info.
    Ignore duplicate subdomains.  The subdomain with the lower sequence number will be accepted.
    In the event of a tie, the *first* subdomain will be accepted

    Returns the list of subdomain operations, as Subdomain objects (optionally empty), in the order they appeared in the zone file
    Returns None if this zone file could not be decoded
    """
    zonefile_hash = get_zonefile_data_hash(zonefile_txt)

    try:
        # by default, it's a zonefile-formatted text file
        zonefile_defaultdict = blockstack_zones.parse_zone_file(zonefile_txt)
        zonefile_json = dict(zonefile_defaultdict)
        try:
            # zonefiles with subdomains have TXT records and URI records
            jsonschema.validate(zonefile_json, USER_ZONEFILE_SCHEMA)
        except Exception as e:
            if BLOCKSTACK_TEST:
                log.exception(e)
            
            log.debug("Failed to validate zone file {}".format(zonefile_hash))
            raise ValueError("Not a user zone file")

        assert zonefile_json['$origin'] == domain, 'Zonefile does not contain $ORIGIN == {} (but has {} instead)'.format(domain, zonefile_json['$origin'])
        
        resolver_url = None
        if 'uri' in zonefile_json:
            resolver_urls = [x['target'] for x in zonefile_json['uri'] if x['name'] == SUBDOMAIN_TXT_RR_RESOLVER]
            if len(resolver_urls) > 0:
                resolver_url = resolver_urls[0]

        subdomains = {}     # map fully-qualified name to subdomain record with lowest sequence number
        subdomain_pos = {}  # map fully-qualified name to position in zone file
        domain_zonefiles_missing = None   # list of zone files declared missing by this domain
        zonefile_offset = 0

        if "txt" in zonefile_json:
            for i, txt in enumerate(zonefile_json['txt']):
                if is_subdomain_missing_zonefiles_record(txt):
                    if domain_zonefiles_missing is not None:
                        raise ValueError("Invalid zone file: multiple RRs for {}".format(SUBDOMAIN_TXT_RR_MISSING))

                    try:
                        domain_zonefiles_missing = Subdomain.parse_subdomain_missing_zonefiles_record(txt)
                    except ParseError as pe:
                        if BLOCKSTACK_DEBUG:
                            log.exception(pe)

                        log.warn("Invalid missing-zonefiles vector at position {}".format(i))
                        continue

            if domain_zonefiles_missing is None:
                domain_zonefiles_missing = []

            for i, txt in enumerate(zonefile_json['txt']):
                if is_subdomain_record(txt):
                    try:
                        # force lowercase
                        txt['name'] = txt['name'].lower()
                        if txt['name'] in SUBDOMAIN_TXT_RR_RESERVED:
                            continue

                        subrec = Subdomain.parse_subdomain_record(domain, txt, block_height, zonefile_hash, zonefile_index, zonefile_offset, txid, domain_zonefiles_missing, resolver=resolver_url)
                        zonefile_offset += 1
                    except ParseError as pe:
                        if BLOCKSTACK_DEBUG:
                            log.exception(pe)

                        log.warn("Invalid subdomain record at position {}".format(i))
                        continue

                    if subrec.get_fqn() in subdomains:
                        if subrec.n < subdomains[subrec.get_fqn()].n:
                            # replace
                            subdomains[subrec.get_fqn()] = subrec
                            subdomain_pos[subrec.get_fqn()] = i

                        else:
                            log.warn("Ignoring subdomain record '{}' with higher sequence".format(subrec.get_fqn()))

                    else:
                        # new
                        subdomains[subrec.get_fqn()] = subrec
                        subdomain_pos[subrec.get_fqn()] = i
       
        subdomain_list = [subdomains[fqn] for fqn in subdomains]
        subdomain_list.sort(cmp=lambda subrec1, subrec2: -1 if subdomain_pos[subrec1.get_fqn()] < subdomain_pos[subrec2.get_fqn()] else 0 if subdomain_pos[subrec1.get_fqn()] == subdomain_pos[subrec2.get_fqn()] else 1)
        return subdomain_list

    except Exception as e:
        if BLOCKSTACK_TEST:
            log.exception(e)

        log.debug("Failed to parse zone file {}".format(zonefile_hash))
        return None


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
    """
    Verify that a given plaintext is signed by the given scriptSig, given the address
    """
    assert isinstance(address, str)
    assert isinstance(scriptSigb64, str)

    scriptSig = base64.b64decode(scriptSigb64)
    hash_hex = hashlib.sha256(plaintext).hexdigest()

    vb = keylib.b58check.b58check_version_byte(address)

    if vb == bitcoin_blockchain.version_byte:
        return verify_singlesig(address, hash_hex, scriptSig)
    elif vb == bitcoin_blockchain.multisig_version_byte:
        return verify_multisig(address, hash_hex, scriptSig)
    else:
        log.warning("Unrecognized address version byte {}".format(vb))
        raise NotImplementedError("Addresses must be single-sig (version-byte = 0) or multi-sig (version-byte = 5)")


def verify_singlesig(address, hash_hex, scriptSig):
    """
    Verify that a p2pkh address is signed by the given pay-to-pubkey-hash scriptsig
    """
    try:
        sighex, pubkey_hex = virtualchain.btc_script_deserialize(scriptSig)
    except:
        log.warn("Wrong signature structure for {}".format(address))
        return False

    # verify pubkey_hex corresponds to address
    if virtualchain.address_reencode(keylib.public_key_to_address(pubkey_hex)) != virtualchain.address_reencode(address):
        log.warn(("Address {} does not match signature script {}".format(address, scriptSig.encode('hex'))))
        return False

    sig64 = base64.b64encode(binascii.unhexlify(sighex))
    return virtualchain.ecdsalib.verify_digest(hash_hex, pubkey_hex, sig64)


def verify_multisig(address, hash_hex, scriptSig):
    """
    verify that a p2sh address is signed by the given scriptsig
    """
    script_parts = virtualchain.btc_script_deserialize(scriptSig)
    if len(script_parts) < 2:
        log.warn("Verfiying multisig failed, couldn't grab script parts")
        return False

    redeem_script = script_parts[-1]
    script_sigs = script_parts[1:-1]

    if virtualchain.address_reencode(virtualchain.btc_make_p2sh_address(redeem_script)) != virtualchain.address_reencode(address):
        log.warn(("Address {} does not match redeem script {}".format(address, redeem_script)))
        return False

    m, pubk_hexes = virtualchain.parse_multisig_redeemscript(redeem_script)
    if len(script_sigs) != m:
        log.warn("Failed to validate multi-sig, not correct number of signatures: have {}, require {}".format(
            len(script_sigs), m))
        return False

    cur_pubk = 0
    for cur_sig in script_sigs:
        sig64 = base64.b64encode(binascii.unhexlify(cur_sig))
        sig_passed = False
        while not sig_passed:
            if cur_pubk >= len(pubk_hexes):
                log.warn("Failed to validate multi-signature, ran out of public keys to check")
                return False
            sig_passed = virtualchain.ecdsalib.verify_digest(hash_hex, pubk_hexes[cur_pubk], sig64)
            cur_pubk += 1

    return True


def txt_encode_key_value(key, value):
    """
    Encode a key=value string, where value's '=''s are escaped
    """
    return "{}={}".format(key, value.replace("=", "\\="))


def is_subdomain_missing_zonefiles_record(rec):
    """
    Does a given parsed zone file TXT record encode a missing-zonefile vector?
    Return True if so
    Return False if not
    """
    if rec['name'] != SUBDOMAIN_TXT_RR_MISSING:
        return False

    txt_entry = rec['txt']
    if isinstance(txt_entry, list):
        return False

    missing = txt_entry.split(',')
    try:
        for m in missing:
            m = int(m)
    except ValueError:
        return False

    return True


def is_subdomain_record(rec):
    """
    Does a given parsed zone file TXT record (@rec) encode a subdomain?
    Return True if so
    Return False if not
    """
    txt_entry = rec['txt']
    if not isinstance(txt_entry, list):
        return False

    has_parts_entry = False
    has_pk_entry = False
    has_seqn_entry = False
    for entry in txt_entry:
        if entry.startswith(SUBDOMAIN_ZF_PARTS + "="):
            has_parts_entry = True
        if entry.startswith(SUBDOMAIN_PUBKEY + "="):
            has_pk_entry = True
        if entry.startswith(SUBDOMAIN_N + "="):
            has_seqn_entry = True

    return (has_parts_entry and has_pk_entry and has_seqn_entry)


def get_subdomain_info(fqn, db_path=None, atlasdb_path=None, zonefiles_dir=None, check_pending=False, include_did=False):
    """
    Static method for getting the state of a subdomain, given its fully-qualified name.
    Return the subdomain record on success.
    Return None if not found.
    """
    opts = get_blockstack_opts()
    if not is_subdomains_enabled(opts):
        log.warn("Subdomain support is disabled")
        return None

    if db_path is None:
        db_path = opts['subdomaindb_path']

    if zonefiles_dir is None:
        zonefiles_dir = opts['zonefiles']

    if atlasdb_path is None:
        atlasdb_path = opts['atlasdb_path']

    db = SubdomainDB(db_path, zonefiles_dir)
    try:
        subrec = db.get_subdomain_entry(fqn)
    except SubdomainNotFound:
        log.warn("No such subdomain: {}".format(fqn))
        return None

    if check_pending:
        # make sure that all of the zone files between this subdomain's
        # domain's creation and this subdomain's zone file index are present,
        # minus the ones that are allowed to be missing.
        subrec.pending = db.subdomain_check_pending(subrec, atlasdb_path)

    if include_did:
        # include the DID 
        subrec.did_info = db.get_subdomain_DID_info(fqn)

    return subrec


def get_subdomain_resolver(name, db_path=None, zonefiles_dir=None):
    """
    Static method for determining the last-known resolver for a domain name.
    Returns the resolver URL on success
    Returns None on error
    """
    opts = get_blockstack_opts()
    if not is_subdomains_enabled(opts):
        log.warn("Subdomain support is disabled")
        return None

    if db_path is None:
        db_path = opts['subdomaindb_path']

    if zonefiles_dir is None:
        zonefiles_dir = opts['zonefiles']

    db = SubdomainDB(db_path, zonefiles_dir)
    resolver_url = db.get_domain_resolver(name)

    return resolver_url


def get_subdomains_count(db_path=None, zonefiles_dir=None):
    """
    Static method for getting count of all subdomains
    Return number of subdomains on success
    """
    opts = get_blockstack_opts()
    if not is_subdomains_enabled(opts):
        log.warn("Subdomain support is disabled")
        return None

    if db_path is None:
        db_path = opts['subdomaindb_path']

    if zonefiles_dir is None:
        zonefiles_dir = opts['zonefiles']

    db = SubdomainDB(db_path, zonefiles_dir)
    return db.get_subdomains_count()


def get_subdomain_DID_info(fqn, db_path=None, zonefiles_dir=None):
    """
    Get a subdomain's DID info.
    Return None if not found
    """
    opts = get_blockstack_opts()
    if not is_subdomains_enabled(opts):
        log.warn("Subdomain support is disabled")
        return None

    if db_path is None:
        db_path = opts['subdomaindb_path']

    if zonefiles_dir is None:
        zonefiles_dir = opts['zonefiles']

    db = SubdomainDB(db_path, zonefiles_dir)
    try:
        subrec = db.get_subdomain_entry(fqn)
    except SubdomainNotFound:
        log.warn("No such subdomain: {}".format(fqn))
        return None
    
    try:
        return db.get_subdomain_DID_info(fqn)
    except SubdomainNotFound:
        return None


def get_DID_subdomain(did, db_path=None, zonefiles_dir=None, atlasdb_path=None, check_pending=False):
    """
    Static method for resolving a DID to a subdomain
    Return the subdomain record on success
    Return None on error
    """
    opts = get_blockstack_opts()
    if not is_subdomains_enabled(opts):
        log.warn("Subdomain support is disabled")
        return None

    if db_path is None:
        db_path = opts['subdomaindb_path']

    if zonefiles_dir is None:
        zonefiles_dir = opts['zonefiles']
    
    if atlasdb_path is None:
        atlasdb_path = opts['atlasdb_path']

    db = SubdomainDB(db_path, zonefiles_dir)
    try:
        subrec = db.get_DID_subdomain(did)
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.warn("Failed to load subdomain for {}".format(did))
        return None

    if check_pending:
        # make sure that all of the zone files between this subdomain's
        # domain's creation and this subdomain's zone file index are present,
        # minus the ones that are allowed to be missing.
        subrec.pending = db.subdomain_check_pending(subrec, atlasdb_path)

    return subrec


def is_subdomain_zonefile_hash(fqn, zonefile_hash, db_path=None, zonefiles_dir=None):
    """
    Static method for getting all historic zone file hashes for a subdomain
    """
    opts = get_blockstack_opts()
    if not is_subdomains_enabled(opts):
        return []

    if db_path is None:
        db_path = opts['subdomaindb_path']
    
    if zonefiles_dir is None:
        zonefiles_dir = opts['zonefiles']

    db = SubdomainDB(db_path, zonefiles_dir)
    zonefile_hashes = db.is_subdomain_zonefile_hash(fqn, zonefile_hash)
    return zonefile_hashes


def get_subdomain_history(fqn, offset=None, count=None, reverse=False, db_path=None, zonefiles_dir=None, json=False):
    """
    Static method for getting all historic operations on a subdomain
    """
    opts = get_blockstack_opts()
    if not is_subdomains_enabled(opts):
        return []

    if db_path is None:
        db_path = opts['subdomaindb_path']
    
    if zonefiles_dir is None:
        zonefiles_dir = opts['zonefiles']

    db = SubdomainDB(db_path, zonefiles_dir)
    recs = db.get_subdomain_history(fqn, offset=offset, count=count)

    if json:
        recs = [rec.to_json() for rec in recs]
        ret = {}
        for rec in recs:
            if rec['block_number'] not in ret:
                ret[rec['block_number']] = []

            ret[rec['block_number']].append(rec)

        if reverse:
            for block_height in ret:
                ret[block_height].sort(lambda r1, r2: -1 if r1['parent_zonefile_index'] > r2['parent_zonefile_index'] or 
                                                           (r1['parent_zonefile_index'] == r2['parent_zonefile_index'] and r1['zonefile_offset'] > r2['zonefile_offset']) else
                                                       1 if r1['parent_zonefile_index'] < r2['parent_zonefile_index'] or 
                                                           (r1['parent_zonefile_index'] == r2['parent_zonefile_index'] and r1['zonefile_offset'] < r2['zonefile_offset']) else
                                                       0)
        return ret

    else:
        return recs


def get_all_subdomains(offset=None, count=None, min_sequence=None, db_path=None, zonefiles_dir=None):
    """
    Static method for getting the list of all subdomains
    """
    opts = get_blockstack_opts()
    if not is_subdomains_enabled(opts):
        return []

    if db_path is None:
        db_path = opts['subdomaindb_path']

    if zonefiles_dir is None:
        zonefiles_dir = opts['zonefiles']

    db = SubdomainDB(db_path, zonefiles_dir)
    return db.get_all_subdomains(offset=offset, count=count, min_sequence=None)


def get_subdomain_ops_at_txid(txid, db_path=None, zonefiles_dir=None):
    """
    Static method for getting the list of subdomain operations accepted at a given txid.
    Includes unaccepted subdomain operations
    """
    opts = get_blockstack_opts()
    if not is_subdomains_enabled(opts):
        return []

    if db_path is None:
        db_path = opts['subdomaindb_path']

    if zonefiles_dir is None:
        zonefiles_dir = opts['zonefiles']

    db = SubdomainDB(db_path, zonefiles_dir)
    return db.get_subdomain_ops_at_txid(txid)


def get_subdomains_owned_by_address(address, db_path=None, zonefiles_dir=None):
    """
    Static method for getting the list of subdomains for a given address
    """
    opts = get_blockstack_opts()
    if not is_subdomains_enabled(opts):
        return []

    if db_path is None:
        db_path = opts['subdomaindb_path']

    if zonefiles_dir is None:
        zonefiles_dir = opts['zonefiles']

    db = SubdomainDB(db_path, zonefiles_dir)
    return db.get_subdomains_owned_by_address(address)


def get_subdomain_last_sequence(db_path=None, zonefiles_dir=None):
    """
    Static method for getting the last sequence number in the database
    """
    opts = get_blockstack_opts()
    if not is_subdomains_enabled(opts):
        return []

    if db_path is None:
        db_path = opts['subdomaindb_path']

    if zonefiles_dir is None:
        zonefiles_dir = opts['zonefiles']

    db = SubdomainDB(db_path, zonefiles_dir)
    return db.get_last_sequence()


def make_subdomain_txt(name_or_fqn, domain, address, n, zonefile_str, privkey_bundle):
    """
    Make a signed subdomain TXT record, to be appended to a (domain's) zone file.
    Return the TXT record string
    """
    subrec = Subdomain(str(name_or_fqn), str(domain), str(address), int(n), str(zonefile_str), None, None, None, None, None, None)
    subrec_plaintext = subrec.get_plaintext_to_sign()
    sig = sign(privkey_bundle, subrec_plaintext)
    
    subrec = Subdomain(str(name_or_fqn), str(domain), str(address), int(n), str(zonefile_str), str(sig), None, None, None, None, None)
    return subrec.serialize_to_txt()


def sign(privkey_bundle, plaintext):
    """
    Sign a subdomain plaintext with a private key bundle
    Returns the base64-encoded scriptsig
    """
    if virtualchain.is_singlesig(privkey_bundle):
        return sign_singlesig(privkey_bundle, plaintext)
    elif virtualchain.is_multisig(privkey_bundle):
        return sign_multisig(privkey_bundle, plaintext)
    else:
        raise ValueError("private key bundle is neither a singlesig nor multisig bundle")


def sign_singlesig(privkey_hex, plaintext):
    """
    Sign a subdomain record's plaintext with a private key.
    Return a bitcoin-compatible scriptSig, base64-encoded, that encodes the [signature, public-key] data
    """
    hash_hex = hashlib.sha256(plaintext).hexdigest()
    b64sig = virtualchain.ecdsalib.sign_digest(hash_hex, privkey_hex)
    sighex = binascii.hexlify(base64.b64decode(b64sig))
    pubkey_hex = virtualchain.ecdsalib.ecdsa_private_key(privkey_hex).public_key().to_hex()
    return base64.b64encode(virtualchain.btc_script_serialize([sighex, pubkey_hex]).decode('hex'))


def sign_multisig(privkey_bundle, plaintext):
    """
    Sign a subdomain record's plaintext with a multisig key bundle.
    This returns a bitcoin-compatible multisig scriptSig, base64-encoded, that encodes the [OP_0, m, [signatures], [public_keys], n, OP_CHECKMULTISIG] script
    """
    hash_hex = hashlib.sha256(plaintext).hexdigest()
    redeem_script = privkey_bundle['redeem_script']
    secret_keys = privkey_bundle['private_keys']

    assert len(redeem_script) > 0
    m, pubk_hexes = virtualchain.parse_multisig_redeemscript(redeem_script)

    privs = {}
    for sk in secret_keys:
        pubk = virtualchain.ecdsalib.ecdsa_private_key(sk).public_key().to_hex()

        compressed_pubkey = keylib.key_formatting.compress(pubk)
        uncompressed_pubkey = keylib.key_formatting.decompress(pubk)

        privs[compressed_pubkey] = sk
        privs[uncompressed_pubkey] = sk

    used_keys, sigs = [], []
    for pubk in pubk_hexes:
        if pubk not in privs:
            continue

        if len(used_keys) == m:
            break

        assert pubk not in used_keys, 'Tried to reuse key {}'.format(pubk)

        sk_hex = privs[pubk]
        used_keys.append(pubk)

        b64sig = virtualchain.ecdsalib.sign_digest(hash_hex, sk_hex)
        sighex = base64.b64decode(b64sig).encode('hex')
        sigs.append(sighex)

    assert len(used_keys) == m, 'Missing private keys (used {}, required {})'.format(len(used_keys), m)
    return base64.b64encode(virtualchain.btc_script_serialize([None] + sigs + [redeem_script]).decode('hex'))


def subdomains_init(blockstack_opts, working_dir, atlas_state):
    """
    Set up subdomain state
    Returns a SubdomainIndex object that has been successfully connected to Atlas
    """
    if not is_subdomains_enabled(blockstack_opts):
        return None

    subdomain_state = SubdomainIndex(blockstack_opts['subdomaindb_path'], blockstack_opts=blockstack_opts)
    atlas_node_add_callback(atlas_state, 'store_zonefile', subdomain_state.enqueue_zonefile)

    return subdomain_state


if __name__ == "__main__":

    # basic unit tests on creating and extracting zone files
    singlesig = virtualchain.ecdsalib.ecdsa_private_key().to_hex()
    singlesig_addr = virtualchain.get_privkey_address(singlesig)
    multisig = bitcoin_blockchain.multisig.make_multisig_wallet(2,3)

    zf_template = "$ORIGIN {}\n$TTL 3600\n_missing TXT \"1,2,3\"\n{}"
    zf_default_url = '_https._tcp URI 10 1 "https://raw.githubusercontent.com/nobody/content/profile.md"'

    print "----\nsinglesig\n----"

    subdomain_txt = make_subdomain_txt('bar.foo.test', 'foo.test', singlesig_addr, 0, zf_template.format('bar.foo.test', zf_default_url), singlesig)
    zf = zf_template.format('foo.test', subdomain_txt)

    print zf

    subdomains = decode_zonefile_subdomains('foo.test', zf, 1234, 5678, '185c112401590b11acdfea6bb26d2a8e37cb31f24a0c89dbb8cc14b3d6271fb1')

    assert len(subdomains) == 1, subdomains
    subd = subdomains[0]

    assert subd.subdomain == 'bar', subd.subdomain
    assert subd.domain == 'foo.test', subd.domain
    assert subd.fqn == 'bar.foo.test', subd.fqn
    assert subd.n == 0
    assert subd.block_height == 1234
    assert subd.parent_zonefile_index == 5678
    assert subd.txid == '185c112401590b11acdfea6bb26d2a8e37cb31f24a0c89dbb8cc14b3d6271fb1'
    assert subd.domain_zonefiles_missing == [1,2,3]

    assert subdomain_txt == subd.serialize_to_txt()

    assert subd.verify_signature(singlesig_addr), 'failed to verify'
    assert not subd.verify_signature('16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg'), 'verified with wrong key'

    print "----\nmultisig\n----"

    subdomain_txt = make_subdomain_txt('multisig.foo.test', 'foo.test', multisig['address'], 0, zf_template.format('multisig.foo.test', zf_default_url), multisig)
    zf = zf_template.format('foo.test', subdomain_txt)

    print zf

    subdomains = decode_zonefile_subdomains('foo.test', zf, 1234, 5678, '185c112401590b11acdfea6bb26d2a8e37cb31f24a0c89dbb8cc14b3d6271fb1')

    assert len(subdomains) == 1, subdomains
    subd = subdomains[0]

    assert subd.subdomain == 'multisig', subd.subdomain
    assert subd.domain == 'foo.test', subd.domain
    assert subd.fqn == 'multisig.foo.test', subd.fqn
    assert subd.n == 0
    assert subd.block_height == 1234
    assert subd.parent_zonefile_index == 5678
    assert subd.txid == '185c112401590b11acdfea6bb26d2a8e37cb31f24a0c89dbb8cc14b3d6271fb1'
    assert subd.domain_zonefiles_missing == [1,2,3]

    assert subdomain_txt == subd.serialize_to_txt()

    assert subd.verify_signature(multisig['address']), 'failed to verify multisig'
    assert not subd.verify_signature('16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg'), 'verified multisig with wrong key'

    print "----\nsinglesig independent\n----"

    subdomain_txt = make_subdomain_txt('bar.baz.test', 'foo.test', singlesig_addr, 0, zf_template.format('bar.baz.test', zf_default_url), singlesig)
    zf = zf_template.format('foo.test', subdomain_txt)

    print zf
    
    # simulate zone file update from foo.test with bar.baz.test's info in it
    subdomains = decode_zonefile_subdomains('foo.test', zf, 1234, 5678, '185c112401590b11acdfea6bb26d2a8e37cb31f24a0c89dbb8cc14b3d6271fb1')

    assert len(subdomains) == 1, subdomains
    subd = subdomains[0]

    assert subd.subdomain == 'bar', subd.subdomain
    assert subd.domain == 'foo.test', subd.domain
    assert subd.fqn == 'bar.baz.test', subd.fqn
    assert subd.n == 0
    assert subd.block_height == 1234
    assert subd.parent_zonefile_index == 5678
    assert subd.txid == '185c112401590b11acdfea6bb26d2a8e37cb31f24a0c89dbb8cc14b3d6271fb1'
    assert subd.domain_zonefiles_missing == [1,2,3]

    assert subdomain_txt == subd.serialize_to_txt()

    assert subd.verify_signature(singlesig_addr), 'failed to verify'
    assert not subd.verify_signature('16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg'), 'verified with wrong key'

    print "----\nmultisig independent\n----"

    subdomain_txt = make_subdomain_txt('bar.baz.test', 'foo.test', multisig['address'], 0, zf_template.format('bar.baz.test', zf_default_url), multisig)
    zf = zf_template.format('foo.test', subdomain_txt)

    print zf
    
    # simulate zone file update from foo.test with bar.baz.test's info in it
    subdomains = decode_zonefile_subdomains('foo.test', zf, 1234, 5678, '185c112401590b11acdfea6bb26d2a8e37cb31f24a0c89dbb8cc14b3d6271fb1')

    assert len(subdomains) == 1, subdomains
    subd = subdomains[0]

    assert subd.subdomain == 'bar', subd.subdomain
    assert subd.domain == 'foo.test', subd.domain
    assert subd.fqn == 'bar.baz.test', subd.fqn
    assert subd.n == 0
    assert subd.block_height == 1234
    assert subd.parent_zonefile_index == 5678
    assert subd.txid == '185c112401590b11acdfea6bb26d2a8e37cb31f24a0c89dbb8cc14b3d6271fb1'
    assert subd.domain_zonefiles_missing == [1,2,3]

    assert subdomain_txt == subd.serialize_to_txt()

    assert subd.verify_signature(multisig['address']), 'failed to verify'
    assert not subd.verify_signature('16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg'), 'verified with wrong key'

    print "----\nmultiple subdomains\n----"
    
    txts = []
    for (name, addr, privkey) in zip(['a.foo.test', 'b.foo.test', 'c.baz.test', 'd.baz.test'], [singlesig_addr, multisig['address'], singlesig_addr, multisig['address']], [singlesig, multisig, singlesig, multisig]):
        subdomain_txt = make_subdomain_txt(name, 'foo.test', addr, 0, zf_template.format(name, zf_default_url), privkey)
        txts.append(subdomain_txt)

    zf = zf_template.format('foo.test', '\n'.join(txts))

    print zf

    subdomains = decode_zonefile_subdomains('foo.test', zf, 1234, 5678, '185c112401590b11acdfea6bb26d2a8e37cb31f24a0c89dbb8cc14b3d6271fb1')
    assert len(subdomains) == 4, subdomains

    for (name, addr, privkey, subd, txt) in zip(['a.foo.test', 'b.foo.test', 'c.baz.test', 'd.baz.test'], [singlesig_addr, multisig['address'], singlesig_addr, multisig['address']], [singlesig, multisig, singlesig, multisig], subdomains, txts):
        assert subd.subdomain == name.split('.')[0], subd.subdomain
        assert subd.domain == 'foo.test', subd.domain
        assert subd.fqn == name, subd.name
        assert subd.n == 0
        assert subd.block_height == 1234
        assert subd.parent_zonefile_index == 5678
        assert subd.txid == '185c112401590b11acdfea6bb26d2a8e37cb31f24a0c89dbb8cc14b3d6271fb1'
        assert subd.domain_zonefiles_missing == [1,2,3]

        assert txt == subd.serialize_to_txt(), 'mismatch\n{}\n{}'.format(txt, subd.serialize_to_txt())

        assert subd.verify_signature(addr), 'failed to verify'
        assert not subd.verify_signature('16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg'), 'verified with wrong key'
