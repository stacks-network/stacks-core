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
import simplejson
import random
import time

from .backend.blockchain import get_bitcoind_client

from proxy import (
    get_default_proxy, get_nameops_hash_at, get_consensus_hashes, get_nameops_at,
    get_block_from_consensus, get_consensus_at)

import virtualchain
from virtualchain import SPVClient

from utilitybelt import is_hex

from .logger import get_logger
from .constants import (
    FIRST_BLOCK_MAINNET, NAME_OPCODES,
    OPFIELDS, BLOCKCHAIN_ID_MAGIC, NAME_PREORDER,
    NAME_TRANSFER, NAMESPACE_PREORDER
)

import json

log = get_logger()


def txid_to_block_data(txid, bitcoind_proxy, proxy=None):
    """
    Given a txid, get its block's data.

    Use SPV to verify the information we receive from the (untrusted)
    bitcoind host.

    @bitcoind_proxy must be a BitcoindConnection (from virtualchain.lib.session)

    Return the (block hash, block data, txdata) on success
    Return (None, None, None) on error
    """

    proxy = get_default_proxy() if proxy is None else proxy

    timeout = 1.0
    while True:
        try:
            untrusted_tx_data = bitcoind_proxy.getrawtransaction(txid, 1)
            untrusted_block_hash = untrusted_tx_data['blockhash']
            untrusted_block_data = bitcoind_proxy.getblock(untrusted_block_hash)
            break
        except (OSError, IOError) as ie:
            log.exception(ie)
            log.error('Network error; retrying...')
            timeout = timeout * 2 + random.randint(0, timeout)
            continue
        except Exception as e:
            log.exception(e)
            return None, None, None

    # first, can we trust this block? is it in the SPV headers?
    untrusted_block_header_hex = virtualchain.block_header_to_hex(
        untrusted_block_data, untrusted_block_data['previousblockhash']
    )

    block_id = SPVClient.block_header_index(
        proxy.spv_headers_path,
        ('{}00'.format(untrusted_block_header_hex)).decode('hex')
    )

    if block_id < 0:
        # bad header
        log.error('Block header "{}" is not in the SPV headers ({})'.format(
            untrusted_block_header_hex, proxy.spv_headers_path
        ))

        return None, None, None

    # block header is trusted.  Is the transaction data consistent with it?
    verified_block_header = virtualchain.block_verify(untrusted_block_data)

    if not verified_block_header:
        msg = (
            'Block transaction IDs are not consistent '
            'with the Merkle root of the trusted header'
        )

        log.error(msg)

        return None, None, None

    # verify block hash
    verified_block_hash = virtualchain.block_header_verify(
        untrusted_block_data, untrusted_block_data['previousblockhash'], untrusted_block_hash
    )

    if not verified_block_hash:
        log.error('Block hash is not consistent with block header')
        return None, None, None

    # we trust the block hash, block data, and txids
    block_hash = untrusted_block_hash
    block_data = untrusted_block_data
    tx_data = untrusted_tx_data

    return block_hash, block_data, tx_data


def serial_number_to_tx(serial_number, bitcoind_proxy, proxy=None):
    """
    Convert a serial number into its transaction in the blockchain.
    Use an untrusted bitcoind connection to get the list of transactions,
    and use trusted SPV headers to ensure that the transaction obtained is on the main chain.
    @bitcoind_proxy must be a BitcoindConnection (from virtualchain.lib.session)

    Return the SPV-verified transaction object (as a dict) on success
    Return None on error
    """

    proxy = get_default_proxy() if proxy is None else proxy

    parts = serial_number.split('-')
    block_id, tx_index = int(parts[0]), int(parts[1])

    timeout = 1.0
    while True:
        try:
            block_hash = bitcoind_proxy.getblockhash(block_id)
            block_data = bitcoind_proxy.getblock(block_hash)
            break
        except Exception as e:
            log.error('Unable to obtain block data; retrying...')
            time.sleep(timeout)
            timeout = timeout * 2 + random.random() * timeout

    rc = SPVClient.sync_header_chain(
        proxy.spv_headers_path, bitcoind_proxy.opts['bitcoind_server'], block_id
    )

    if not rc:
        msg = 'Failed to synchronize SPV header chain up to {}'
        log.error(msg.format(block_id))
        return None

    # verify block header
    rc = SPVClient.block_header_verify(proxy.spv_headers_path, block_id, block_hash, block_data)
    if not rc:
        msg = 'Failed to verify block header for {} against SPV headers'
        log.error(msg.format(block_id))
        return None

    # verify block txs
    rc = SPVClient.block_verify(block_data, block_data['tx'])
    if not rc:
        msg = 'Failed to verify block transaction IDs for {} against SPV headers'
        log.error(msg.format(block_id))
        return None

    # sanity check
    if tx_index >= len(block_data['tx']):
        msg = 'Serial number {} references non-existant transaction {} (out of {} txs)'
        log.error(msg.format(serial_number, tx_index, len(block_data['tx'])))
        return None

    # obtain transaction
    txid = block_data['tx'][tx_index]
    tx = bitcoind_proxy.getrawtransaction(txid, 1)

    # verify tx
    rc = SPVClient.tx_verify(block_data['tx'], tx)
    if not rc:
        msg = 'Failed to verify block transaction {} against SPV headers'
        log.error(msg.format(txid))
        return None

    # verify tx index
    if tx_index != SPVClient.tx_index(block_data['tx'], tx):
        msg = (
            'TX index mismatch: serial number identifies '
            'transaction number {} ({}), but got transaction {}'
        )

        log.error(msg.format(
            tx_index, block_data['tx'][tx_index],
            block_data['tx'][SPVClient.tx_index(block_data['tx'], tx)]
        ))
        return None

    # success!
    return tx


def parse_tx_op_return(tx):
    """
    Given a transaction, locate its OP_RETURN and parse
    out its opcode and payload.
    Return (opcode, payload) on success
    Return (None, None) if there is no OP_RETURN, or if it's not a blockchain ID operation.
    """

    # find OP_RETURN output
    op_return = None
    outputs = tx['vout']
    for out in outputs:
        script_key = out['scriptPubKey']['hex']
        if int(script_key[0:2], 16) == virtualchain.OPCODE_VALUES['OP_RETURN']:
            op_return = script_key.decode('hex')
            break

    if op_return is None:
        msg = 'transaction has no OP_RETURN output'
        log.error(msg)
        log.debug('{}:\n{}'.format(msg, simplejson.dumps(tx)))
        return None, None

    # [0] is OP_RETURN, [1] is the length; [2:4] are 'id', [4] is opcode
    magic = op_return[2:4]

    if magic != BLOCKCHAIN_ID_MAGIC:
        # not a blockchain ID operation
        msg = 'OP_RETURN output does not encode a blockchain ID operation'
        log.error(msg)
        return None, None

    opcode, payload = op_return[4], op_return[5:]

    return (opcode, payload)


def get_consensus_hash_from_tx(tx):
    """
    Given an SPV-verified transaction, extract its consensus hash.
    Only works of the tx encodes a NAME_PREORDER, NAMESPACE_PREORDER,
    or NAME_TRANSFER.

    Return hex-encoded consensus hash on success.
    Return None on error.
    """

    opcode, payload = parse_tx_op_return(tx)
    if opcode is None or payload is None:
        return None

    # only present in NAME_PREORDER, NAMESPACE_PREORDER, NAME_TRANSFER
    if opcode in [NAME_PREORDER, NAMESPACE_PREORDER, NAME_TRANSFER]:
        consensus_hash = payload[-16:].encode('hex')
        return consensus_hash

    msg = (
        'Blockchain ID transaction is not a '
        'NAME_PREORDER, NAMESPACE_PROERDER or NAME_TRANSFER'
    )

    log.error(msg)

    return None


def snv_get_nameops_at(current_block_id, current_consensus_hash, block_id, consensus_hash, proxy=None):
    """
    Simple name verification (snv) lookup:
    Use a known-good "current" consensus hash and block ID to
    look up a set of name operations from the past, given the previous
    point in time's untrusted block ID and consensus hash.
    """

    log.debug('verify {}-{} to {}-{}'.format(
        current_block_id, current_consensus_hash, block_id, consensus_hash
    ))

    proxy = get_default_proxy() if proxy is None else proxy

    # work backwards in time, using a Merkle skip-list constructed
    # by blockstackd over the set of consensus hashes.
    next_block_id = current_block_id

    prev_nameops_hashes = {}
    prev_consensus_hashes = {
        next_block_id: current_consensus_hash
    }

    # print 'next_block_id = {}, block_id = {}'.format(next_block_id, block_id)
    while next_block_id >= block_id:
        # get nameops_at[ next_block_id ], and all consensus_hash[ next_block_id - 2^i ]
        # such that block_id - 2*i > block_id (start at i = 1)
        i = 0
        nameops_hash = None

        if next_block_id in prev_nameops_hashes:
            nameops_hash = prev_nameops_hashes[next_block_id]
        else:
            nameops_resp = get_nameops_hash_at(next_block_id, proxy=proxy)

            if 'error' in nameops_resp:
                log.error('get_nameops_hash_at: {}'.format(nameops_resp['error']))
                return {'error': 'Failed to get nameops: {}'.format(nameops_resp['error'])}

            nameops_hash = str(nameops_resp)
            prev_nameops_hashes[next_block_id] = nameops_hash

        log.debug('nameops hash at {}: {}'.format(next_block_id, nameops_hash))

        # find out which consensus hashes we'll need
        to_fetch = []
        ch_block_ids = []
        while next_block_id - (2 ** (i + 1) - 1) >= FIRST_BLOCK_MAINNET:
            i += 1
            prev_block_id = next_block_id - (2 ** i - 1)
            ch_block_ids.append(prev_block_id)

            if prev_block_id not in prev_consensus_hashes:
                to_fetch.append(prev_block_id)

        # get the consensus hashes
        chs = {}
        if to_fetch:
            chs = get_consensus_hashes(to_fetch, proxy=proxy)
            if 'error' in chs:
                msg = 'Failed to get consensus hashes for {}: {}'
                log.error(msg.format(to_fetch, chs['error']))
                return {'error': 'Failed to get consensus hashes'}

        prev_consensus_block_ids = []
        for b in ch_block_ids:
            # NOTE: we process to_fetch *in decreasing order* so we know when we're missing data
            if b not in chs and b not in prev_consensus_hashes:
                msg = 'Missing consensus hash response for {} (chs={}, prev_chs={})'
                log.error(msg.format(b, chs, prev_consensus_hashes))
                return {'error': 'Server did not reply valid data'}

            prev_consensus_block_ids.append(b)
            if b in prev_consensus_hashes:
                # already got this one
                continue

            ch = chs[b]
            if ch is not None:
                prev_consensus_hashes[b] = str(ch)
            else:
                # no consensus hash for this block and all future blocks
                prev_consensus_block_ids.pop()
                break

        # prev_consensus_hashes_list = [ prev_consensus_hashes[b] for b in ch_block_ids ]
        prev_consensus_hashes_list = [
            prev_consensus_hashes[b] for b in prev_consensus_block_ids
        ]

        # calculate the snapshot, and see if it matches
        ch = virtualchain.StateEngine.make_snapshot_from_ops_hash(
            nameops_hash, prev_consensus_hashes_list
        )

        expected_ch = prev_consensus_hashes[next_block_id]
        if ch != expected_ch:
            msg = 'Consensus hash mismatch at {}: expected {}, got {} (from {}, {})'
            log.error(msg.format(next_block_id, expected_ch, ch, nameops_hash, prev_consensus_hashes))
            return {'error': 'Consensus hash mismatch'}

        # advance!
        # find the smallest known consensus hash whose block is greater than block_id
        current_candidate = next_block_id
        found_any = False
        for candidate_block_id in prev_consensus_hashes:
            if candidate_block_id < block_id:
                continue

            if candidate_block_id < current_candidate:
                current_candidate = candidate_block_id
                found_any = True

        if not found_any:
            break

        next_block_id = current_candidate

    # get the final nameops
    historic_nameops = get_nameops_at(block_id, proxy=proxy)
    if isinstance(historic_nameops, dict) and 'error' in historic_nameops:
        log.error('Failed to get nameops at {}: {}'.format(block_id, historic_nameops['error']))
        return {'error': 'BUG: no nameops found'}

    # sanity check...
    for historic_op in historic_nameops:
        if 'opcode' not in historic_op:
            return {'error': 'Invalid/corrupt name operations detected'}

        # recover binary op string
        if 'op' not in historic_op:
            historic_op['op'] = NAME_OPCODES[str(historic_op['opcode'])]

    # check integrity
    serialized_historic_nameops = [
        virtualchain.StateEngine.serialize_op(
            str(op['op'][0]), op, OPFIELDS, verbose=True
        ) for op in historic_nameops
    ]

    historic_nameops_hash = virtualchain.StateEngine.make_ops_snapshot(serialized_historic_nameops)

    if block_id not in prev_nameops_hashes:
        return {'error': 'Previous block/consensus hash is unreachable from trusted block/consensus hash'}

    if historic_nameops_hash != prev_nameops_hashes[block_id]:
        return {
            'error': 'Hash mismatch: failed to get operations at {}-{} from {}-{} ({} != {})'.format(
                block_id, consensus_hash, current_block_id, current_consensus_hash, historic_nameops_hash, prev_nameops_hashes[block_id]
            )
        }

    log.debug('{} nameops at {}'.format(len(historic_nameops), block_id))

    # strip history
    for hn in historic_nameops:
        if 'history' in hn.keys():
            del hn['history']

    return historic_nameops


def snv_name_verify(name, current_block_id, current_consensus_hash, block_id,
                    consensus_hash, trusted_txid=None, trusted_txindex=None, proxy=None):
    """
    Use SNV to verify that a name existed at a particular block ID in the past,
    given a later known-good block ID and consensus hash (as well as the previous
    untrusted consensus hash)

    Return the name's historic nameop(s) on success.
    If there are multiple matches, multiple nameops will be returned.
    The return value takes the form of {'status': True, 'nameops': [...]}
    Return a dict with {'error'} on error
    """

    proxy = get_default_proxy() if proxy is None else proxy

    historic_nameops = snv_get_nameops_at(
        current_block_id, current_consensus_hash,
        block_id, consensus_hash, proxy=proxy
    )

    if 'error' in historic_nameops:
        return historic_nameops

    matching_nameops = []

    # find the one we asked for
    for nameop in historic_nameops:
        # select on more-accurate filters first
        if trusted_txindex is not None and nameop['vtxindex'] == trusted_txindex:
            matching_nameops = [nameop]
            break

        if trusted_txid is not None and nameop['txid'] == trusted_txid:
            matching_nameops = [nameop]
            break

        if 'name' not in nameop:
            continue

        if str(nameop['name']) == str(name):
            # success!
            matching_nameops.append(nameop)
            continue

    if matching_nameops:
        return {'status': True, 'nameops': matching_nameops}

    # not found
    log.error('Not found at block {}: "{}"'.format(block_id, name))
    return {'error': 'Name not found'}


def snv_lookup(verify_name, verify_block_id,
               trusted_serial_number_or_txid_or_consensus_hash, proxy=None, trusted_txid=None):

    """
    High-level call to simple name verification:
    Given a trusted serial number, txid, or consensus_hash, use it as a trust root to verify that
    a previously-registered but untrusted name (@verify_name) exists and was processed
    at a given block (@verify_block_id)

    Basically, use the trust root to derive a "current" block ID and consensus hash, and
    use the untrusted (name, block_id) pair to derive an earlier untrusted block ID and
    consensus hash.  Then, use the snv_get_nameops_at() method to verify that the name
    existed at the given block ID.

    The Blockstack node is not trusted.  This algorithm prevents a malicious Blockstack node
    from getting the caller to falsely trust @verify_name and @verify_block_id by
    using SNV to confirm that:
    * the consensus hash at the trust root's block is consistent with @verify_name's
    corresponding NAMESPACE_PREORDER or NAME_PREORDER;
    * the consensus hash at @trusted_serial_number's block is consistent with @verify_name's
    consensus hash (from @verify_serial_number)

    The only way a Blockstack node working with a malicious Sybil can trick the caller is if
    both can create a parallel history of name operations such that the final consensus hash
    at @trusted_serial_number's block collides.  This is necessary, since the client uses
    the hash over a block's operations and prior consensus hashes to transitively trust
    prior consensus hashes--if the later consensus hash is assumed out-of-band to be valid,
    then the transitive closure of all prior consensus hashes will be assumed valid as well.
    This means that the only way to drive the valid consensus hash from a prior invalid
    consensus hash is to force a hash collision somewhere in the transitive closure, which is infeasible.

    NOTE: @trusted_txid is needed for isolating multiple operations in the same name within a single block.

    Return the list of nameops in the given verify_block_id that match.
    """

    proxy = get_default_proxy() if proxy is None else proxy

    trusted_serial_number_or_txid_or_consensus_hash = str(trusted_serial_number_or_txid_or_consensus_hash)

    bitcoind_proxy = get_bitcoind_client(config_path=proxy.conf['path'])
    trusted_serial_number = None
    trusted_tx_index = None
    trusted_consensus_hash = None
    trusted_block_id = None

    # what did we get?
    hash_len_64 = len(trusted_serial_number_or_txid_or_consensus_hash) == 64
    hash_len_32 = len(trusted_serial_number_or_txid_or_consensus_hash) == 32
    hash_parts_2 = len(trusted_serial_number_or_txid_or_consensus_hash.split('-')) == 2
    hash_is_hex = is_hex(trusted_serial_number_or_txid_or_consensus_hash)

    if hash_len_64 and hash_is_hex:
        # txid: convert to trusted block ID and consensus hash
        trusted_txid = trusted_serial_number_or_txid_or_consensus_hash
        trusted_block_hash, trusted_block_data, trusted_tx = txid_to_block_data(trusted_txid, bitcoind_proxy)
        if trusted_block_hash is None or trusted_block_data is None or trusted_tx is None:
            return {'error': 'Unable to look up given transaction ID'}

        # must have a consensus hash
        # TOOD: Check why return values are ignored
        op, payload = parse_tx_op_return(trusted_tx)
        trusted_consensus_hash = get_consensus_hash_from_tx(trusted_tx)
        if trusted_consensus_hash is None:
            return {'error': 'Tx does not refer to a consensus-bearing transaction'}

        # find the block for this consensus hash (it's not the same as the serial number's block ID,
        # but that's okay--if the consensus hash in this tx is inauthentic, it will be unreachable
        # from the other consensus hash [short of a SHA256 collision])
        trusted_block_id = get_block_from_consensus(trusted_consensus_hash, proxy=proxy)

    elif hash_len_32 and hash_is_hex:
        # consensus hash
        trusted_consensus_hash = trusted_serial_number_or_txid_or_consensus_hash
        trusted_block_id = get_block_from_consensus(trusted_consensus_hash, proxy=proxy)
        if isinstance(trusted_block_id, dict) and 'error' in trusted_block_id:
            # got error back
            return trusted_block_id
        
    elif hash_parts_2:
        # must be a serial number
        parts = trusted_serial_number_or_txid_or_consensus_hash.split('-')
        try:
            trusted_block_id = int(parts[0])
            # TODO: Check why this variable is unused
            trusted_tx_index = int(parts[1])
        except:
            log.error('Malformed serial number "{}"'.format(trusted_serial_number_or_txid_or_consensus_hash))
            return {'error': 'Did not receive a valid serial number'}

        trusted_tx = serial_number_to_tx(trusted_serial_number_or_txid_or_consensus_hash, bitcoind_proxy)
        if trusted_tx is None:
            return {'error': 'Unable to convert given serial number into transaction'}

        # tx must have a consensus hash
        # TOOD: Check why return values are ignored
        op, payload = parse_tx_op_return(trusted_tx)
        trusted_consensus_hash = get_consensus_hash_from_tx(trusted_tx)
        if trusted_consensus_hash is None:
            return {'error': 'Tx does not refer to a consensus-bearing transaction'}

        # find the block for this consensus hash (it's not the same as the serial number's block ID,
        # but that's okay--if the consensus hash in this tx is inauthentic, it will be unreachable
        # from the other consensus hash [short of a SHA256 collision])
        trusted_block_id = get_block_from_consensus(trusted_consensus_hash, proxy=proxy)
        if isinstance(trusted_block_id, dict) and 'error' in trusted_block_id:
            # got error back
            return trusted_block_id
    else:
        msg = 'Did not receive a valid txid, consensus hash, or serial number ({})'
        return {'error': msg.format(trusted_serial_number_or_txid_or_consensus_hash)}

    if trusted_block_id < verify_block_id:
        msg = 'Trusted block/consensus hash came before the untrusted block/consensus hash'
        return {'error': msg}

    # go verify the name
    verify_consensus_hash = get_consensus_at(verify_block_id, proxy=proxy)
    historic_namerecs = snv_name_verify(
        verify_name, trusted_block_id, trusted_consensus_hash,
        verify_block_id, verify_consensus_hash,
        trusted_txid=trusted_txid, trusted_txindex=trusted_tx_index
    )

    if 'error' in historic_namerecs:
        return historic_namerecs

    return historic_namerecs['nameops']


# backwards compatibility
lookup_snv = snv_lookup
