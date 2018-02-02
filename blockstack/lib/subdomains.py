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

from virtualchain import bitcoin_blockchain

from .config import BLOCKSTACK_TESTNET, BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, SUBDOMAINS_FIRST_BLOCK, get_blockstack_opts, is_atlas_enabled, is_subdomains_enabled
from .atlas import atlasdb_open, atlasdb_get_zonefiles_by_block, atlasdb_get_zonefiles_by_name, atlas_node_add_callback, atlasdb_query_execute, atlasdb_get_zonefiles_by_hash
from .storage import get_atlas_zonefile_data, get_zonefile_data_hash, store_atlas_zonefile_data 
from .scripts import is_name_valid, is_address_subdomain, is_subdomain
from .schemas import *
from .util import db_query_execute
from .queue import *

log = virtualchain.get_logger('blockstack-subdomains')

# names of subdomain record fields
SUBDOMAIN_ZF_PARTS = "parts"
SUBDOMAIN_ZF_PIECE = "zf%d"
SUBDOMAIN_SIG = "sig"
SUBDOMAIN_PUBKEY = "owner"
SUBDOMAIN_N = "seqn"

log = virtualchain.get_logger()

# for DIDs
SUBDOMAIN_ADDRESS_VERSION_BYTE = 63             # 'S'
SUBDOMAIN_ADDRESS_MULTISIG_VERSION_BYTE = 50    # 'M'

if BLOCKSTACK_TESTNET:
    SUBDOMAIN_ADDRESS_VERSION_BYTE = 127            # 't'
    SUBDOMAIN_ADDRESS_MULTISIG_VERSION_BYTE = 142   # 'z'

SUBDOMAIN_ADDRESS_VERSION_BYTES = [SUBDOMAIN_ADDRESS_VERSION_BYTE, SUBDOMAIN_ADDRESS_MULTISIG_VERSION_BYTE]

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
    def __init__(self, fqn, domain, address, n, zonefile_str, sig, block_height, parent_zonefile_hash, parent_zonefile_index, txid, accepted=False):
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
        self.parent_zonefile_hash = parent_zonefile_hash
        self.txid = txid
        self.independent = False        # indicates whether or not this record is independent of its domain (i.e. a.b.id is independent of c.id, but not b.id)
        self.accepted = accepted

        if not fqn.endswith('.' + domain):
            self.independent = True


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
        
        return ret
    

    @staticmethod
    def parse_subdomain_record(domain_name, rec, block_height, parent_zonefile_hash, parent_zonefile_index, txid):
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
                assert is_address_subdomain(subd_name)[0]
            except AssertionError as ae:
                if BLOCKSTACK_DEBUG:
                    log.exception(ae)

                raise ParserError("Invalid names: {}".format(ae))

        else:
            # already fully-qualified
            subd_name = rec['name']
            
        return Subdomain(str(subd_name), str(domain_name), str(pubkey), int(n), base64.b64decode(b64_zonefile), str(sig), block_height, parent_zonefile_hash, parent_zonefile_index, txid)


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
        self.subdomain_db = SubdomainDB(subdomain_db_path, blockstack_opts['zonefiles'])
        self.subdomain_db_lock = threading.Lock()

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


    @classmethod
    def check_subdomain_transition(cls, existing_subrec, new_subrec):
        """
        Given an existing subdomain record and a (newly-discovered) new subdomain record,
        determine if we can use the new subdomain record (i.e. is its signature valid? is it in the right sequence?)
        Return True if so
        Return False if not
        """
        if existing_subrec.get_fqn() != new_subrec.get_fqn():
            log.warn("Failed subdomain {} transition because fqn changed to {} (at block height {} zonefile index {})".format(
                existing_subrec.get_fqn(), new_subrec.get_fqn(), new_subrec.block_height, new_subrec.parent_zonefile_index))

            return False

        if existing_subrec.n + 1 != new_subrec.n:
            log.warn("Failed subdomain {} transition because of N:{}->{} (at block height {} zonefile index {})".format
                (new_subrec.get_fqn(), existing_subrec.n + 1, new_subrec.n, new_subrec.block_height, new_subrec.parent_zonefile_index))

            return False

        if not new_subrec.verify_signature(existing_subrec.address):
            log.warn("Failed subdomain {} transition because of signature failure (at block height {} zonefile index {})".format(
                new_subrec.get_fqn(), new_subrec.block_height, new_subrec.parent_zonefile_index))

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
            log.warn("Failed initial subdomain {} because N != 0 (got {})".format(subdomain_rec.get_fqn(), subdomain_rec.n))
            return False
       
        if subdomain_rec.independent:
            log.warn('Failed initial subdomain {} because it is independent of its domain name {}'.format(subdomain_rec.get_fqn(), subdomain_rec.get_domain()))
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
      

    @classmethod
    def subdomains_validate_domains(cls, new_subdomains, atlasdb_path):
        """
        Given a dict of {'fqn': subdomain_rec} for subdomain records,
        verify that all of their domain names' zone files are accounted for.
        (i.e. in order to prove the absence of a prior initial subdomain record or transfer record for a given subdomain)

        Returns a subset of new_subdomains that can be created, as a {'fqn': subdomain_rec} dict
        """
        # find the set of names to query
        domains = []
        max_zonefile_indexes = {}       # optimization: map domain name to maximum zone file index to query
        domain_zonefiles = {}           # map domain name to zone file info

        # find the set of domains these subdomains represent.
        # also, find the maximum zone file index for each domain (as a query optimization, so we don't do a full db scan).
        for new_fqn in new_subdomains:
            new_subrec = new_subdomains[new_fqn]

            domain = new_subrec.get_domain()
            domains.append(domain)
            
            if domain not in max_zonefile_indexes:
                max_zonefile_indexes[domain] = new_subrec.parent_zonefile_index
            else:
                max_zonefile_indexes[domain] = max(new_subrec.parent_zonefile_index, max_zonefile_indexes[domain])

        domains = list(set(domains))

        # get the set of zone file hashes (and present/absent status) from atlas for each domain
        atlasdb_con = atlasdb_open(atlasdb_path)
        cur = atlasdb_con.cursor()
        
        # get the zonefile history for each domain. We'll use this to check that the domain has all zone files present.
        # do all the reads in one transaction.
        atlasdb_query_execute(cur, 'BEGIN', ())
        for domain in domains:
            zfinfos = atlasdb_get_zonefiles_by_name(domain, max_index=max_zonefile_indexes[domain], path=atlasdb_path)
            domain_zonefiles[domain] = zfinfos

        atlasdb_query_execute(cur, 'END', ())

        accepted_subdomains = {}
        for new_fqn in new_subdomains:
            assert new_fqn not in accepted_subdomains, 'BUG: multiple entries for {}'.format(new_subrec.get_fqn())

            # do not accept a new subdomain if its stem name is missing any prior zone files
            new_subrec = new_subdomains[new_fqn]
            domain = new_subrec.get_domain()
            zfinfos = domain_zonefiles[domain]
            missing = False
            for zfinfo in zfinfos:
                if not zfinfo['present'] and zfinfo['inv_index'] < new_subrec.parent_zonefile_index:
                    log.warning("Name '{}' is missing zone file {} (from block {}).  Will not create subdomain '{}'".format(domain, zfinfo['zonefile_hash'], zfinfo['block_height'], new_fqn))
                    missing = True

            if missing:
                # cannot create subdomain, since another creation could have happened earlier
                continue

            accepted_subdomains[new_fqn] = new_subrec

        return accepted_subdomains

   
    def get_subdomain_state(self, cursor, subdomain_recs):
        """
        Find out the state of each subdomain in subdomain_recs.
        * find the *current* subdomain state
        * find the state of the subdomain *at* subdomain_recs[fqn]
            (i.e. if it exists, then there's a sequence conflict)
        * find the state of the subdomain *just before* subdomain_recs[fqn]
            (i.e. if it does not exist, then this record is invalid)

        TODO: cache to avoid excess queries
        """
        ret = {}        # map fqn to state of the subdomain we know about.
        for fqn in subdomain_recs:

            ret[fqn] = []
            for subr in subdomain_recs[fqn]:
                state = {}

                # Get current accepted subdomain state (may not exist; this may append to another record)
                try:
                    cur_subrec = self.subdomain_db.get_subdomain_entry(fqn, cur=cursor)
                    state['current'] = cur_subrec
                except SubdomainNotFound:
                    state['current'] = None

                # Get subdomain state at this subr's sequence (if it exists, there's a reorg)
                try:
                    seq_subrec = self.subdomain_db.get_subdomain_entry_at_sequence(fqn, subr.n, cur=cursor)
                    state['sequence'] = seq_subrec
                except SubdomainNotFound:
                    state['sequence'] = None

                if subr.n > 0:
                    # Get subdomain state *just prior* to this subr's sequence (may not exist)
                    try:
                        seq_subrec = self.subdomain_db.get_subdomain_entry_at_sequence(fqn, subr.n-1, cur=cursor)
                        state['prev_sequence'] = seq_subrec
                    except SubdomainNotFound:
                        state['prev_sequence'] = None
                else:
                    state['prev_sequence'] = None
                
                ret[fqn].append(state)

        return ret


    def subdomain_histories_find_reorgs(self, subdomain_recs, subdomain_state):
        """
        Find all reorg points, given the current state of each subdomain and the subdomains we discovered.
        Returns {fqn: [{'current': cur_subrec, 'new': replaced_subrec, 'type': 'owner' or 'sequence'}]}
        """
        reorg_points = {}

        for fqn in subdomain_recs:
            assert len(subdomain_state[fqn]) == len(subdomain_recs[fqn]), 'BUG: len(subdomain state) != len(subdomain recs)'
            
            for subr, subr_state in zip(subdomain_recs[fqn], subdomain_state[fqn]):
                subr.accepted = False
                
                # Reorg?
                if not subr_state['sequence']:
                    continue

                if not subr_state['prev_sequence']:
                    continue

                if subr_state['sequence'].n != subr.n:
                    continue

                # Reorg.
                # Possibility 1: this subdomain entry cannot be reached from the parent of the entry it's trying to reorg
                if not self.check_subdomain_transition(subr_state['prev_sequence'], subr):
                    # (possibility 1)
                    continue

                # Possibility 2: this subdomain entry is reachable from its previous entry, and the owner *stayed the same*
                # Possibility 3: this subdomain entry is reachable from its previous entry, and the owner *changed*
                if virtualchain.address_reencode(subr_state['prev_sequence'].address) == virtualchain.address_reencode(subr.address):
                    # (possibility 2)
                    # Possibility 2a: this new subdomain is *earlier* in the blockchain history than the one it seeks to replace.
                    # Possibility 2b: this new subdomain is *later* in the blockchain history than the one it seeks to replace.
                    # We only care about 2a.
                    if subr.parent_zonefile_index < subr_state['sequence'].parent_zonefile_index:
                        log.debug("Reorg {} with earlier update {}".format(subr_state['sequence'], subr))

                        subr.accepted = True
                        if fqn not in reorg_points:
                            reorg_points[fqn] = []
                            
                        reorg_points[fqn].append({'current': subr_state['sequence'], 'new': subr, 'type': 'sequence'})

                else:
                    # (possibility 3)
                    # For now, we can only accept an address change if either:
                    # Possibility 3a: it came from the domain name that created this name (and the domain name has all zone files up to this point), OR
                    # Possibility 3b: it came from an on-chain transaction from a name that owns this subdomain (i.e. has the same address)
                    
                    subr.accepted = False       # not sure yet
                    if fqn not in reorg_points:
                        reorg_points[fqn] = []

                    reorg_points[fqn].append({'current': subr_state['sequence'], 'new': subr, 'type': 'owner'})
                     
            return reorg_points


    def subdomain_histories_process_reorgs(self, cursor, reorg_points):
        """
        Given {fqn: {'current': subr, 'new': subr, 'type': ...}}, process history reorganizations
        for each subdomain.
        """
        owner_change_checks = {}

        # can only accept an owner change if this subrec is not independent, and the domain name has all of its zone files
        for fqn in reorg_points:
            fqn_reorg_points = reorg_points[fqn]
            for reorg_point in fqn_reorg_points:
                if reorg_point['type'] == 'owner' and not reorg_point['new'].independent:
                    assert fqn not in owner_change_checks, 'BUG: multiple owner reorgs on {} in the same block'.format(fqn)
                    owner_change_checks[fqn] = reorg_point['new']

        # filter owner changes that occur via the domain name issuing an update---we can only accept the address change if we have all zone files for the domain
        owner_change_checks = self.subdomains_validate_domains(owner_change_checks, self.atlasdb_path)

        for fqn in reorg_points:
            fqn_reorg_points = reorg_points[fqn]
            for reorg_point in fqn_reorg_points:
                reorg_point['new'].accepted = False

                if reorg_point['type'] == 'sequence':
                    # we had a conflict, and accepted an earlier undiscovered update.
                    # no further invalidations are necessary
                    reorg_point['new'].accepted = True
                    self.subdomain_db.update_subdomain_entry(reorg_point['new'], cur=cursor)

                elif reorg_point['type'] == 'owner':
                    if fqn not in owner_change_checks:
                        log.debug("Reject owner-change {}: independent of its domain".format(reorg_point['new']))

                    else:
                        reorg_point['new'].accepted = True
                        self.subdomain_db.update_subdomain_entry(reorg_point['new'], cur=cursor)
                        self.subdomain_history_reorg(reorg_point['new'].get_fqn(), reorg_point['new'].n + 1, False, cur=cursor)

                else:
                    raise ValueError("Unknown reorg_point type {}".format(reorg_point['type']))
            

    def subdomain_histories_find_new(self, subdomain_recs, subdomain_state):
        """
        Given subdomain records and current state, find the list of ones we can add to the history.
        Returns a list of new entries we accept
        """
        ret = []
        for fqn in subdomain_recs:
            assert len(subdomain_state[fqn]) == len(subdomain_recs[fqn]), 'BUG: len(subdomain state) != len(subdomain recs)'

            for subr, subr_state in zip(subdomain_recs[fqn], subdomain_state[fqn]):
                if subr_state['current'] and self.check_subdomain_transition(subr_state['current'], subr):
                    # Possibility 1: this is the next subdomain entry in this subdomain's history
                    log.debug("Found transition {}".format(subr))
                    subr.accepted = True
                    ret.append(subr)

                elif self.check_initial_subdomain(subr):
                    # Possibility 2: this is new
                    log.debug("Found new {}".format(subr))
                    subr.accepted = True
                    ret.append(subr)

                else:
                    # neither new nor a valid state transition
                    subr.accepted = False
                    ret.append(subr)

        return ret


    def subdomain_histories_process_new(self, cursor, new_subdomain_records):
        """
        Accept new subdomain state (creations and updates).
        Write all entries, but only include ones for which the domain name has the full state.
        """
        # find valid, new subdomains that we're creating for which we have the full history
        new_subrecs = dict([(subr.fqn, subr) for subr in filter(lambda x: x.n == 0 and not x.independent, new_subdomain_records)])
        new_subrecs = self.subdomains_validate_domains(new_subrecs, self.atlasdb_path)

        # everyone else
        append_subrecs = dict([(subr.fqn, subr) for subr in filter(lambda x: x.get_fqn() not in new_subrecs, new_subdomain_records)])
        
        db_query_execute(cursor, 'BEGIN', ())
        
        for fqn in new_subrecs:
            if new_subrecs[fqn].accepted:
                log.debug("Accept new {}".format(new_subrecs[fqn]))
            else:
                log.debug("Reject new {}".format(new_subrecs[fqn]))

            self.subdomain_db.add_subdomain_entry(new_subrecs[fqn], cur=cursor)

        for fqn in append_subrecs:
            if append_subrecs[fqn].accepted:
                log.debug('Accept update {}'.format(append_subrecs[fqn]))
            else:
                log.debug("Reject update {}".format(append_subrecs[fqn]))

            self.subdomain_db.update_subdomain_entry(append_subrecs[fqn], cur=cursor)

        db_query_execute(cursor, 'END', ())


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
        # The arrival of a zone file can reorganize the history for a subdomain.
        subdomain_recs_list = []    # list of maps from fqn to list of new subdomain records (given in blockchain order).  List items are per-zonefile.
        subdomain_histories = {}    # map fqn to exisitng histories
        merged_histories = {}       # map fqn to its new history
        initial_subdomains = {}     # map fqn to its initial subdomain entry

        new_subdomain_history = {}  # map fqn to new subdomain history to insert
        subdomain_tips = {}         # map fqn to its history tips
        reorg_points = {}           # map fqn to [{'current': what's there now, 'new': what should be there}]

        for subinfo in zonefile_subdomain_info:
            subdomain_recs = {}
            if subinfo['subdomains'] is None:
                # no subdomain info for this zone file
                continue
           
            for subrec in subinfo['subdomains']:
                if subrec.get_fqn() not in subdomain_recs:
                    subdomain_recs[subrec.get_fqn()] = []

                subdomain_recs[subrec.get_fqn()].append(subrec)

            subdomain_recs_list.append(subdomain_recs)

        cursor = self.subdomain_db.cursor()
        for subdomain_recs in subdomain_recs_list:
            # begin transaction 
            db_query_execute(cursor, 'BEGIN', ())
           
            # find out the state of the subdomain at and just before these subdomain records were discovered.
            # search for reorgs, and process them.
            subdomain_state = self.get_subdomain_state(cursor, subdomain_recs)
            reorg_points = self.subdomain_histories_find_reorgs(subdomain_recs, subdomain_state)
            self.subdomain_histories_process_reorgs(cursor, reorg_points)

            # now see which subdomains we can accept
            reorged_subdomain_state = self.get_subdomain_state(cursor, subdomain_recs)
            db_query_execute(cursor, 'END', ())

            # append new state
            new_subrecs = self.subdomain_histories_find_new(subdomain_recs, reorged_subdomain_state)
            self.subdomain_histories_process_new(cursor, new_subrecs)
        
    
    def enqueue_zonefile(self, zonefile_hash, block_height):
        """
        Called when we discover a zone file.  Queues up a request to reprocess this name's zone files' subdomains.
        zonefile_hash is the hash of the zonefile.
        block_height is the minimium block height at which this zone file occurs.

        This gets called by:
        * AtlasZonefileCrawler (as it's "store_zonefile" callback).
        * rpc_put_zonefiles() 
        """
        log.debug("Append {} from {}".format(zonefile_hash, block_height))
        queuedb_append(self.subdomain_db_path, "zonefiles", zonefile_hash, json.dumps({'zonefile_hash': zonefile_hash, 'block_height': block_height}))
         

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
        zonefile_infos = {}             # cached zone file infos
        all_queued_zfinfos = []         # contents of the queue
        subdomain_zonefile_infos = {}   # map subdomain fqn to list of zonefile info bundles, for process_subdomains
        name_blocks = {}                # map domain name to the block at which we should reprocess its subsequent zone files

        offset = 0

        while True:
            queued_zfinfos = queuedb_findall(self.subdomain_db_path, "zonefiles", limit=100, offset=offset)
            if len(queued_zfinfos) == 0:
                # done!
                break
            
            offset += 100
            all_queued_zfinfos += queued_zfinfos
        
        log.debug("Discovered {} zonefiles".format(len(all_queued_zfinfos)))

        for queued_zfinfo in all_queued_zfinfos:
            zfinfo = json.loads(queued_zfinfo['data'])

            zonefile_hash = zfinfo['zonefile_hash']
            block_height = zfinfo['block_height']

            if zonefile_hash not in zonefile_infos:
                # find out the names that sent this zone file at this block
                zfinfos = atlasdb_get_zonefiles_by_hash(zonefile_hash, block_height=block_height, path=self.atlasdb_path)
                if zfinfos is None:
                    log.warn("Absent zonefile {}".format(zonefile_hash))
                    continue
                
                zonefile_infos[zonefile_hash] = zfinfos
            else:
                zfinfos = zonefile_infos[zonefile_hash]
            
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
            
            # get the subdomains affected at this block
            res = self.find_zonefile_subdomains(name_blocks[name], lastblock, name=name)
            zonefile_subdomain_info = res['zonefile_info']
            subdomain_index = res['subdomains']
            
            # for each subdomain, find the list of zonefiles that contain records for it
            for fqn in subdomain_index:
                if fqn not in subdomain_zonefile_infos:
                    subdomain_zonefile_infos[fqn] = []

                for i in subdomain_index[fqn]:
                    subdomain_zonefile_infos[fqn].append(zonefile_subdomain_info[i])
            
        for fqn in subdomain_zonefile_infos:
            log.debug("Processing {} subdomain update(s) found for {}".format(len(subdomain_zonefile_infos[fqn]), fqn))
            self.process_subdomains(subdomain_zonefile_infos[fqn])

        # clear queue 
        queuedb_removeall(self.subdomain_db_path, all_queued_zfinfos)
        return True


    def index(self, block_start, block_end):
        """
        Entry point for indexing:
        * scan the blockchain from start_block to end_block and make sure we're up-to-date
        * process any newly-arrived zone files and re-index the affected subdomains
        """
        log.debug("BEGIN Processing zonefiles discovered since last re-indexing")
        self.index_discovered_zonefiles(block_end)
        log.debug("END Processing zonefiles discovered since last re-indexing")

    
    @classmethod
    def reindex(cls, lastblock, opts=None):
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

        start_block = SUBDOMAINS_FIRST_BLOCK

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
        self.subdomain_table = "subdomain_records"
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


    def cursor(self):
        """
        Make and return a cursor
        """
        return self.conn.cursor()

    
    def _extract_subdomain(self, fqn, rowdata):
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
        txid = str(rowdata['txid'])
        accepted = int(rowdata['accepted'])

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
            log.error("No zone file for {}".format(fqn))
            raise SubdomainNotFound('{}: missing zone file {}'.format(fqn, zonefile_hash))

        return Subdomain(str(fqn), str(domain), str(encoded_pubkey), int(n), str(zonefile_str), sig, block_height, parent_zonefile_hash, parent_zonefile_index, txid, accepted=accepted)


    def get_subdomain_entry(self, fqn, cur=None):
        """
        Given a fully-qualified subdomain, get its (latest) subdomain record.
        Raises SubdomainNotFound if there is no such subdomain
        """
        get_cmd = "SELECT * FROM {} WHERE fully_qualified_subdomain=? AND accepted=1 ORDER BY sequence DESC LIMIT 1;".format(self.subdomain_table)
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

        return self._extract_subdomain(fqn, rowdata)

    
    def get_subdomain_entry_at_sequence(self, fqn, sequence, cur=None):
        """
        Given a fully-qualified subdomain and a sequence number, get its historic subdomain record at that sequence.
        Raises SubdomainNotFound if there is no such subdomain
        """
        get_cmd = "SELECT * FROM {} WHERE fully_qualified_subdomain=? AND sequence = ? AND accepted=1;".format(self.subdomain_table)
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

        return self._extract_subdomain(fqn, rowdata)


    def get_subdomain_entry_before(self, fqn, parent_zonefile_index, cur=None):
        """
        Given a fully-qualified subdoman name and a zonefile index, get the
        subdomain entry that was processed just before the index.
        Raises SubdomainNotFound if there is no such subdomain
        """
        get_cmd = 'SELECT * FROM {} WHERE fully_qualified_subdomain=? AND parent_zonefile_index < ? AND accepted=1 ORDER BY parent_zonefile_index DESC LIMIT 1;'.format(self.subdomain_table)
        cursor = None
        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor = cur

        db_query_execute(cursor, get_cmd, (fqn,zonefile_index,))

        try:
            rowdata = cursor.fetchone()
            assert rowdata
        except Exception as e:
            log.exception(e)
            log.error("Failed to fetch data for {}".format(fqn))
            raise SubdomainNotFound(fqn)

        return self._extract_subdomain(fqn, rowdata)


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
            return [ x[0] for x in cursor.fetchall() ]
        except Exception as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            return []


    def get_subdomain_DID(self, fqn, cur=None):
        """
        Get the DID for a subdomain.
        Raise SubdomainNotFound if there is no such subdomain

        The resulting DID will have the format did:stack:v0:${address}-${name_index},
        where ${address} will be the base58-encoded pubkey hash using version byte SUBDOMAIN_ADDRESS_VERSION_BYTE
        for p2pkh addresses and SUBDOMAIN_ADDRESS_MULTISIG_VERSION_BYTE for p2sh addresses.
        """
        subrec = self.get_subdomain_at_sequence(fqn, 0, cur=cur)
        cmd = 'SELECT COUNT(*) FROM {} WHERE owner = ? AND sequence = ? AND parent_zonefile_index < ? AND accepted=1;'.format(self.subdomain_table)
        args = (subrec.address,0,subrec.parent_zonefile_index)

        cursor = None
        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor = cur

        rows = db_query_execute(cursor, cmd, args)
        
        count = None
        for r in rows:
            count = r['COUNT(*)']
            break

        if not cound:
            raise SubdomainNotFound('No rows for {}'.format(fqn))

        # what's the current version byte?
        vb = keylib.b58check.b58check_version_byte(subrec.address)
        if vb == bitcoin_blockchain.version_byte:
            # singlesig
            vb = SUBDOMAIN_ADDRESS_VERSION_BYTE
        else:
            vb = SUBDOMAIN_ADDRESS_MULTISIG_VERSION_BYTE

        # reencode with our subdomain version byte 
        return 'did:stack:v0:{}-{}'.format(virtualchain.address_reencode(subrec.address, version_byte=vb), count)


    def get_DID_subdomain(self, did, cur=None):
        """
        Get a subdomain, given its DID
        Raise SubdomainNotFound if the DID does not correspond to a subdomain
        """
        did_pattern = '^did:stack:v0:({}{{25,35}})-([0-9]+)$'.format(OP_BASE58CHECK_CLASS)

        m = re.match(did_pattern, did)
        assert m, 'Invalid DID: {}'.format(did)

        original_address = m.groups()[0]
        name_index = int(m.groups()[1])
        vb = keylib.b58check.b58check_version_byte(address)
        
        assert vb in [SUBDOMAIN_ADDRESS_VERSION_BYTE, SUBDOMAIN_MULTISIG_ADDRESS_VERSION_BYTE], 'Invalid address version byte'

        # decode version 
        if vb == SUBDOMAIN_ADDRESS_VERSION_BYTE:
            vb = bitcoin_blockchain.version_byte
        else:
            vb = bitcoin_blockchain.multisig_version_byte

        original_address = virtualchain.address_reencode(original_address, version_byte=vb)

        # find the initial subdomain (the nth subdomain created by this address)
        cmd = 'SELECT fully_qualified_subdomain FROM {} WHERE owner = ? AND sequence = ? AND accepted=1 LIMIT 1 OFFSET ?;'.format(self.subdomain_table)
        args = (original_address,0,name_index)

        cursor = None
        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor = cur

        subdomain_name = None

        rows = db_query_execute(cursor, cmd, args)
        for r in rows:
            subdomain_name = r[0]
            break

        if not subdomain_name:
            raise SubdomainNotFound('Does not correspond to a subdomain: {}'.format(did))

        # get the current form
        return self.get_subdomain_entry(subdomain_name, cur=cur)


    def get_subdomain_history(self, fqn, start_zonefile_index=None, include_unaccepted=False, offset=None, count=None, cur=None):
        """
        Get the subdomain's history over a block range.
        By default, only include accepted history items (but set include_unaccepted=True to get them all)
        No zone files will be loaded.

        Returns the list of subdomains in order by sequnce number, and then by parent zonefile index 
        """
        sql = 'SELECT * FROM {} WHERE fully_qualified_subdomain = ? {} {} ORDER BY parent_zonefile_index ASC'.format(
                self.subdomain_table,
                'AND accepted=1' if not include_unaccepted else '',
                'AND parent_zonefile_index >= ?' if start_zonefile_index else '')

        args = (fqn,)
        if start_zonefile_index:
            args += (start_sequence,)
        
        if offset is not None:
            sql += ' OFFSET ?'
            args += (offset,)
            
        if count is not None:
            sql += ' LIMIT ?'
            args += (count,)
        
        sql += ';'

        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor = cur

        rowcursor = db_query_execute(cursor, sql, args)

        rows = []
        for rowdata in rowcursor:
            # want subdomain rec
            subrec = self._extract_subdomain(fqn, rowdata)
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
        
        zonefile_hash = get_zonefile_data_hash(subdomain_obj.zonefile_str)
        rc = store_atlas_zonefile_data(subdomain_obj.zonefile_str, self.zonefiles_dir)
        if not rc:
            raise Exception("Failed to store zone file {} from {}".format(zonefile_hash, subdomain_obj.get_fqn()))
        
        write_cmd = 'INSERT OR REPLACE INTO {} VALUES (?,?,?,?,?,?,?,?,?,?,?)'.format(self.subdomain_table)
        args = (subdomain_obj.get_fqn(), subdomain_obj.domain, subdomain_obj.n, subdomain_obj.address, zonefile_hash,
                subdomain_obj.sig, subdomain_obj.block_height, subdomain_obj.parent_zonefile_hash,
                subdomain_obj.parent_zonefile_index, subdomain_obj.txid, 1 if subdomain_obj.accepted else 0)

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


    def subdomain_history_reorg(self, fqn, sequence, accept_state, cur=None):
        """
        For all subdomain entries for the given fqn, set the acceptance state 
        for each entry after the given sequence number
        """
        cmd = 'UPDATE {} SET accept = ? WHERE fully_qualified_subdomain = ? AND sequence >= ?;'.format(self.subdomain_table)
        args = (1 if accept_state else 0, fqn, sequence)

        cursor = None
        if cur is None:
            cursor = self.conn.cursor()
        else:
            cursor = cur

        db_query_execute(cursor, cmd, args)
        return True


    def add_subdomain_entry(self, subdomain_obj, cur=None):
        """
        Append new subdomain state for this fully-qualified name.
        Does NOT verify the signature; assumes that it is vald.
        Does not care whether or not this subdomain is yet accepted.

        Return True on success
        Raise an exception on failure
        """
       
        # sanity checks
        assert isinstance(subdomain_obj, Subdomain)
        fqn = subdomain_obj.get_fqn()
        is_subdomain, subdomain_name, domain_name = is_address_subdomain(fqn)
        if not is_subdomain:
            raise ValueError("Must give fully qualified name: given: {}".format(fqn))
        
        zonefile_hash = get_zonefile_data_hash(subdomain_obj.zonefile_str)
        rc = store_atlas_zonefile_data(subdomain_obj.zonefile_str, self.zonefiles_dir)
        if not rc:
            raise Exception("Failed to store zone file {} from {}".format(zonefile_hash, subdomain_obj.get_fqn()))
        
        write_cmd = 'INSERT INTO {} VALUES (?,?,?,?,?,?,?,?,?,?,?)'.format(self.subdomain_table)
        args = (subdomain_obj.get_fqn(), subdomain_obj.domain, subdomain_obj.n, subdomain_obj.address, zonefile_hash,
                subdomain_obj.sig, subdomain_obj.block_height, subdomain_obj.parent_zonefile_hash,
                subdomain_obj.parent_zonefile_index, subdomain_obj.txid, 1 if subdomain_obj.accepted else 0)

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
            raise ValueError("No row written: fqn={} seq={}".format(fqn, subdomain_obj.n))

        return True


    def _drop_tables(self):
        """
        Clear the subdomain db's tables
        """
        drop_cmd = "DROP TABLE IF EXISTS {};"
        for table in [self.subdomain_table, 'queue']:
            cursor = self.conn.cursor()
            db_query_execute(cursor, drop_cmd.format(table), ())


    def _create_tables(self):
        """
        Set up the subdomain db's tables
        """
        create_cmd = """CREATE TABLE IF NOT EXISTS {} (
        fully_qualified_subdomain TEXT,
        domain TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        owner TEXT NOT NULL,
        zonefile_hash TEXT NOT NULL,
        signature TEXT NOT NULL,
        block_height INTEGER NOT NULL,
        parent_zonefile_hash TEXT NOT NULL,
        parent_zonefile_index INTEGER UNIQUE NOT NULL,
        txid TEXT PRIMARY KEY,
        accepted INTEGER NOT NULL);
        """.format(self.subdomain_table)

        cursor = self.conn.cursor()
        db_query_execute(cursor, create_cmd, ())

        # set up a queue as well
        queue_con = queuedb_open(self.db_path)
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
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            raise ValueError("Not a user zone file")

        assert zonefile_json['$origin'] == domain, 'Zonefile does not contain $ORIGIN == {}'.format(domain)

        subdomains = {}     # map fully-qualified name to subdomain record with lowest sequence number
        subdomain_pos = {}  # map fully-qualified name to position in zone file

        if "txt" in zonefile_json:
            for i, txt in enumerate(zonefile_json['txt']):
                if not is_subdomain_record(txt):
                    continue

                try:
                    subrec = Subdomain.parse_subdomain_record(domain, txt, block_height, zonefile_hash, zonefile_index, txid)
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
        if BLOCKSTACK_TEST or BLOCKSTACK_DEBUG:
            log.exception(e)

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


def is_subdomain_record(rec):
    """
    Does a given parsed zone file (@rec) encode a subdomain?
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


def get_subdomain_info(fqn, db_path=None, zonefiles_dir=None):
    """
    Static method for getting the state of a subdomain, given its fully-qualified name
    """
    opts = get_blockstack_opts()
    if not is_subdomains_enabled(opts):
        return []

    if db_path is None:
        db_path = opts['subdomaindb_path']

    if zonefiles_dir is None:
        zonefiles_dir = opts['zonefiles']

    db = SubdomainDB(db_path, zonefiles_dir)
    return db.get_subdomain_entry(fqn)


def get_subdomain_history(fqn, db_path=None, zonefiles_dir=None, json=False):
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
    recs = db.get_subdomain_history(fqn)

    if json:
        recs = [rec.to_json() for rec in recs]
        ret = {}
        for rec in recs:
            if rec['block_number'] not in ret:
                ret[rec['block_number']] = []

            ret[rec['block_number']].append(rec)

        return ret

    else:
        return recs


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


def make_subdomain_txt(name_or_fqn, domain, address, n, zonefile_str, privkey_bundle):
    """
    Make a signed subdomain TXT record, to be appended to a (domain's) zone file.
    Return the TXT record string
    """
    subrec = Subdomain(str(name_or_fqn), str(domain), str(address), int(n), str(zonefile_str), None, None, None, None, None)
    subrec_plaintext = subrec.get_plaintext_to_sign()
    sig = sign(privkey_bundle, subrec_plaintext)
    
    subrec = Subdomain(str(name_or_fqn), str(domain), str(address), int(n), str(zonefile_str), str(sig), None, None, None, None)
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

    zf_template = "$ORIGIN {}\n$TTL 3600\n{}"
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

        assert txt == subd.serialize_to_txt(), 'mismatch\n{}\n{}'.format(txt, subd.serialize_to_txt())

        assert subd.verify_signature(addr), 'failed to verify'
        assert not subd.verify_signature('16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg'), 'verified with wrong key'
