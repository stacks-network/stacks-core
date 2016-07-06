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
import argparse
import sys
import json
import traceback
import types
import socket
import uuid
import os
import importlib
import pprint
import random
import time
import copy
import blockstack_profiles
import urllib

from .backend.blockchain import get_bitcoind_client

from keys import *
from proxy import *
from profile import *

from spv import SPVClient

import pybitcoin
import bitcoin
import binascii
from utilitybelt import is_hex

from config import get_logger, DEBUG, MAX_RPC_LEN, find_missing, BLOCKSTACKD_SERVER, \
    BLOCKSTACKD_PORT, BLOCKSTACK_METADATA_DIR, BLOCKSTACK_DEFAULT_STORAGE_DRIVERS, \
    FIRST_BLOCK_MAINNET, NAME_OPCODES, OPFIELDS, CONFIG_DIR, SPV_HEADERS_PATH, BLOCKCHAIN_ID_MAGIC, \
    NAME_PREORDER, NAME_REGISTRATION, NAME_UPDATE, NAME_TRANSFER, NAMESPACE_PREORDER, NAME_IMPORT, \
    USER_ZONEFILE_TTL, CONFIG_PATH

log = get_logger()

import virtualchain

def get_create_diff(blockchain_record):
    """
    Given a blockchain record, find its earliest history diff and its creation block number.
    """

    preorder_block_number = blockchain_record['preorder_block_number']
    history = blockchain_record['history']
    create_block_number = None

    if str(preorder_block_number) in history.keys():
        # was preordered
        create_block_number = preorder_block_number
    else:
        # was imported
        create_block_number = int(sorted(history.keys())[0])

    create_diff = history[str(create_block_number)][0]
    return (create_block_number, create_diff)


def get_reveal_txid(blockchain_record):
    """
    Given a blockchain record, find the transaction ID that revealed it
    as well as the associated block number.
    """

    history = blockchain_record['history']
    reveal_block_number = None

    # find the earliest history record with NAME_IMPORT or NAME_REGISTRATION
    for block_number_str in sorted(history.keys()):
        for i in xrange(0, len(history[block_number_str])):
            if history[block_number_str][i].has_key('opcode'):
                if str(history[block_number_str][i]['opcode']) in ['NAME_IMPORT', 'NAME_REGISTRATION']:

                    reveal_block_number = int(block_number_str)
                    return reveal_block_number, str(history[block_number_str][i]['txid'])

    return (None, None)


def get_serial_number(blockchain_record):
    """
    Calculate the serial number from a name's blockchain record.
    * If the name was preordered, then this is first such $preorder_block-$vtxindex
    * If the name was imported, then this is the first such $import_block-$vtxindex
    """

    create_block_number, create_diff = get_create_diff(blockchain_record)
    create_tx_index = create_diff['vtxindex']
    history = blockchain_record['history']

    serial_number = None

    if str(create_diff['opcode']) == "NAME_PREORDER":

        # name was preordered; use preorder block_id/tx_index
        # find the oldest registration
        update_order = sorted(history.keys())
        for block_num in update_order:
            for tx_op in history[block_num]:
                if tx_op['opcode'] == "NAME_PREORDER":
                    serial_number = str(tx_op['block_number']) + '-' + str(tx_op['vtxindex'])
                    break

        if serial_number is None:
            raise Exception("No NAME_REGISTRATION found for '%s'" % blockchain_record.get('name', 'UNKNOWN_NAME'))

    else:
        # name was imported.
        # serial number is the first NAME_IMPORT block + txindex
        serial_number = str(create_block_number) + '-' + str(create_tx_index)

    return serial_number


def get_block_from_consensus(consensus_hash, proxy=None):
    """
    Get a block ID from a consensus hash
    """
    if proxy is None:
        proxy = get_default_proxy()

    resp = proxy.get_block_from_consensus(consensus_hash)
    if resp is None:
        resp = {'error': 'No such consensus hash'}

    elif type(resp) == list:
        # backwards-compatibility
        if len(resp) == 0:
            resp = {'error': 'No data returned'}
        else:
            resp = resp[0]

    return resp


def txid_to_block_data(txid, bitcoind_proxy, proxy=None):
    """
    Given a txid, get its block's data.

    Use SPV to verify the information we receive from the (untrusted)
    bitcoind host.

    @bitcoind_proxy must be a BitcoindConnection (from virtualchain.lib.session)

    Return the (block hash, block data, txdata) on success
    Return (None, None, None) on error
    """

    if proxy is None:
        proxy = get_default_proxy()

    timeout = 1.0
    while True:
        try:
            untrusted_tx_data = bitcoind_proxy.getrawtransaction(txid, 1)
            untrusted_block_hash = untrusted_tx_data['blockhash']
            untrusted_block_data = bitcoind_proxy.getblock(untrusted_block_hash)
            break
        except (OSError, IOError), ie:
            log.exception(ie)
            log.error("Network error; retrying...")
            timeout = timeout * 2 + random.randint(0, timeout)
            continue

        except Exception, e:
            log.exception(e)
            return (None, None, None)

    # first, can we trust this block? is it in the SPV headers?
    untrusted_block_header_hex = virtualchain.block_header_to_hex(untrusted_block_data, untrusted_block_data['previousblockhash'])
    block_id = SPVClient.block_header_index(proxy.spv_headers_path, (untrusted_block_header_hex + "00").decode('hex'))
    if block_id < 0:
        # bad header
        log.error("Block header '%s' is not in the SPV headers" % untrusted_block_header_hex)
        return (None, None, None)

    # block header is trusted.  Is the transaction data consistent with it?
    if not virtualchain.block_verify(untrusted_block_data):
        log.error("Block transaction IDs are not consistent with the trusted header's Merkle root")
        return (None, None, None)

    # verify block hash
    if not virtualchain.block_header_verify(untrusted_block_data, untrusted_block_data['previousblockhash'], untrusted_block_hash):
        log.error("Block hash is not consistent with block header")
        return (None, None, None)

    # we trust the block hash, block data, and txids
    block_hash = untrusted_block_hash
    block_data = untrusted_block_data
    tx_data = untrusted_tx_data

    return (block_hash, block_data, tx_data)



def txid_to_serial_number(txid, bitcoind_proxy, proxy=None):
    """
    Given a transaction ID, convert it into a serial number
    (defined as $block_id-$tx_index).

    Use SPV to verify the information we receive from the (untrusted)
    bitcoind host.

    @bitcoind_proxy must be a BitcoindConnection (from virtualchain.lib.session)

    Return the serial number on success
    Return None on error
    """

    if proxy is None:
        proxy = get_default_proxy()

    block_hash, block_data, _ = txid_to_block_data(txid, bitcoind_proxy, proxy=proxy)
    if block_hash is None or block_data is None:
        return None

    # What's the tx index?
    try:
        tx_index = block_data['tx'].index(txid)
    except:
        # not actually present
        log.error("Transaction %s is not present in block %s (%s)" % (txid, block_id, block_hash))

    return "%s-%s" % (block_id, tx_index)



def serial_number_to_tx(serial_number, bitcoind_proxy, proxy=None):
    """
    Convert a serial number into its transaction in the blockchain.
    Use an untrusted bitcoind connection to get the list of transactions,
    and use trusted SPV headers to ensure that the transaction obtained is on the main chain.
    @bitcoind_proxy must be a BitcoindConnection (from virtualchain.lib.session)

    Return the SPV-verified transaction object (as a dict) on success
    Return None on error
    """

    if proxy is None:
        proxy = get_default_proxy()

    parts = serial_number.split("-")
    block_id = int(parts[0])
    tx_index = int(parts[1])

    timeout = 1.0
    while True:
        try:
            block_hash = bitcoind_proxy.getblockhash(block_id)
            block_data = bitcoind_proxy.getblock(block_hash)
            break
        except Exception, e:
            log.error("Unable to obtain block data; retrying...")
            time.sleep(timeout)
            timeout = timeout * 2 + random.random() * timeout

    rc = SPVClient.sync_header_chain(proxy.spv_headers_path, bitcoind_proxy.opts['bitcoind_server'], block_id)
    if not rc:
        log.error("Failed to synchronize SPV header chain up to %s" % block_id)
        return None

    # verify block header
    rc = SPVClient.block_header_verify(proxy.spv_headers_path, block_id, block_hash, block_data)
    if not rc:
        log.error("Failed to verify block header for %s against SPV headers" % block_id)
        return None

    # verify block txs
    rc = SPVClient.block_verify(block_data, block_data['tx'])
    if not rc:
        log.error("Failed to verify block transaction IDs for %s against SPV headers" % block_id)
        return None

    # sanity check
    if tx_index >= len(block_data['tx']):
        log.error("Serial number %s references non-existant transaction %s (out of %s txs)" % (serial_number, tx_index, len(block_data['tx'])))
        return None

    # obtain transaction
    txid = block_data['tx'][tx_index]
    tx = bitcoind_proxy.getrawtransaction(txid, 1)

    # verify tx
    rc = SPVClient.tx_verify(block_data['tx'], tx)
    if not rc:
        log.error("Failed to verify block transaction %s against SPV headers" % txid)
        return None

    # verify tx index
    if tx_index != SPVClient.tx_index(block_data['tx'], tx):
        log.error("TX index mismatch: serial number identifies transaction number %s (%s), but got transaction %s" % \
                (tx_index, block_data['tx'][tx_index], block_data['tx'][ SPVClient.tx_index(block_data['tx'], tx) ]))
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
        if int(out["scriptPubKey"]['hex'][0:2], 16) == pybitcoin.opcodes.OP_RETURN:
            op_return = out['scriptPubKey']['hex'].decode('hex')
            break

    if op_return is None:
        pp = pprint.PrettyPrinter()
        pp.pprint(tx)
        log.error("transaction has no OP_RETURN output")
        return (None, None)

    # [0] is OP_RETURN, [1] is the length; [2:4] are 'id', [4] is opcode
    magic = op_return[2:4]

    if magic != BLOCKCHAIN_ID_MAGIC:
        # not a blockchain ID operation
        log.error("OP_RETURN output does not encode a blockchain ID operation")
        return (None, None)

    opcode = op_return[4]
    payload = op_return[5:]

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
    if opcode not in [NAME_PREORDER, NAMESPACE_PREORDER, NAME_TRANSFER]:
        log.error("Blockchain ID transaction is not a NAME_PREORDER, NAMESPACE_PROERDER or NAME_TRANSFER")
        return None

    else:
        consensus_hash = payload[-16:].encode('hex')
        return consensus_hash


def verify_consensus_hash_from_tx(tx, fqname, candidate_consensus_hash):
    """
    Given the SPV-verified transaction that encodes a consensus hash-bearing OP_RETURN,
    the fully qualified name, and the list of candidate consensus hashes from Blockstack,
    verify the consensus hash against the transaction.

    Return the consensus hash on success
    Return None if there was no OP_RETURN output in the tx, or the OP_RETURN output
    does not encode one of the valid opcodes, or there is a mismatch.
    """

    opcode, payload = parse_tx_op_return(tx)
    if opcode is None or payload is None:
        return None

    if opcode not in [NAME_PREORDER, NAMESPACE_PREORDER, NAME_UPDATE, NAME_TRANSFER]:
        # no consensus hash will be present
        log.error("Blockchain ID transaction is not a NAME_PREORDER, NAMESPACE_PROERDER, NAME_UPDATE, or NAME_TRANSFER")
        return None

    elif opcode != NAME_UPDATE:
        # in all but NAME_UPDATE, the consensus hash is the last 16 bytes
        consensus_hash = payload[-16:].encode('hex')
        if str(consensus_hash) == str(candidate_consensus_hash):
            return consensus_hash

        else:
            # nope
            log.error("Consensus hash mismatch: expected %s, got %s" % (candidate_consensus_hash, consensus_hash))
            return None

    else:
        # In NAME_UPDATE, the consensus hash *at the time of the operation* is mixed with the name,
        # truncated to 16 bytes, and appended after the opcode.
        name_consensus_hash_mix = pybitcoin.hash.bin_sha256(fqname + candidate_consensus_hash)[0:16]
        tx_name_consensus_hash_mix = payload[0:16]

        if name_consensus_hash_mix == tx_name_consensus_hash_mix:
            return candidate_consensus_hash

        log.error("NAME_UPDATE consensus hash mix mismatch: expected %s from %s, got %s" % (name_consensus_hash_mix.encode('hex'), candidate_consensus_hash, tx_name_consensus_hash_mix.encode('hex')))
        return None


def get_name_creation_consensus_info(name, blockchain_record, bitcoind_proxy, proxy=None, serial_number=None):
    """
    Given the result of a call to get_name_blockchain_record,
    obtain the creation consensus hash, type, and block number.
    Verify them with SPV.

    On success, return a dict with:
    * type: if the name was preordered, then this is NAME_PREORDER.  If the name was instead
        imported, then this is NAME_IMPORT.
    * block_id: the block ID of the NAME_PREORDER or NAME_IMPORT
    * anchor: an object containing:
        * consensus_hash: if the name was preordered, then this is the consensus hash at the time
            the preorder operation was issued.  Otherwise, if the name was imported, then this is
            the consensus hash at the time the namespace preorder of the namespace into which the
            was imported was issued.  Note that in both cases, this is the consensus hash
            from the block *at the time of issue*--this is NOT the block at which the name
            operation was incorporated into the blockchain.
        * block_id: the block id from which the consensus hash was taken.  Note that this
            is *not* the block at which the name operation was incorporated into the blockchain
            (i.e. this block ID may *not* match the serial number).
        * txid: the transaction ID that contains the consensus hash

    'anchor' will not be given on NAMESPACE_PREORDER

    On error, return a dict with 'error' defined as a key, mapped to an error message.
    """
    create_block_number, create_diff = get_create_diff(blockchain_record)
    create_consensus_tx = None

    # consensus info for when the name was created (NAMESPACE_PREORDER or NAME_PREORDER)
    creation_consensus_hash = None
    creation_consensus_type = str(create_diff['opcode'])

    # find preorder consensus hash, if preordered
    if creation_consensus_type == "NAME_PREORDER":
        creation_consensus_hash = create_diff['consensus_hash']

        # transaction with the consensus hash comes from the NAME_PREORDER
        preorder_serial_number = None
        if serial_number is None:
            preorder_serial_number = get_serial_number(blockchain_record)
        else:
            preorder_serial_number = serial_number

        create_consensus_tx = serial_number_to_tx(preorder_serial_number, bitcoind_proxy, proxy=proxy)

        if create_consensus_tx is None:
           return {'error': 'Failed to verify name creation consensus-bearing transaction against SPV headers'}

        # we can trust that the consensus-bearing transaction is on the blockchain.
        # now, what's the creation consensus hash's block number?
        # (NOTE: this trusts Blockstack)
        creation_consensus_block_id = get_block_from_consensus(creation_consensus_hash, proxy=proxy)
        if type(creation_consensus_hash_id) == dict and 'error' in ret:
            return ret

        # verify that the given consensus hash is present in the trusted consensus-bearing transaction
        tx_consensus_hash = verify_consensus_hash_from_tx(create_consensus_tx, name, creation_consensus_hash)
        if tx_consensus_hash is None:
            # !!! Blockstackd lied to us--we got the wrong consensus hash
            return {'error': 'Blockstack consensus hash does not match the SPV block headers'}


    creation_info = {
        'type': creation_consensus_type,
        'block_id': create_block_number,
    }

    if creation_consensus_type == 'NAME_PREORDER':

        # have trust anchor
        creation_info['anchor'] = {
            'consensus_hash': creation_consensus_hash,
            'block_id': creation_consensus_block_id,
            'txid': create_consensus_tx['txid']
        }

    return creation_info


def get_name_reveal_consensus_info(name, blockchain_record, bitcoind_proxy, proxy=None):
    """
    Given a name, its blockchain record, and a bitcoind proxy, get information
    about the name's revelation (i.e. the Blockstack state transition that exposed
    the name's plaintext).  That is, get information about a name's NAME_REGISTRATION,
    or its NAME_IMPORT.

    The transaction that performed the revelation will be fetched
    from the underlying blockchain, and verified with SPV.

    Return a dict with the following:
    * type: either NAME_REGISTRATION or NAME_IMPORT
    * block_id: the block ID of the name op that revealed the name
    * txid: the transaction ID of the revelation
    """

    reveal_block_number, reveal_txid = get_reveal_txid(blockchain_record)

    # consensus info for when the name was revealed to the world (NAME_IMPORT or NAME_REGISTRATION)
    reveal_consensus_tx = None
    reveal_consensus_hash = None
    reveal_consensus_type = None

    # get verified name revelation data
    reveal_block_hash, reveal_block_data, reveal_tx = txid_to_block_data(reveal_txid, bitcoind_proxy, proxy=proxy)
    if reveal_block_hash is None or reveal_block_data is None:
        return {'error': 'Failed to look up name revelation information'}

    reveal_op, reveal_payload = parse_tx_op_return(reveal_tx)
    if reveal_op is None or reveal_payload is None:
        return {'error': 'Transaction is not a valid Blockstack operation'}

    if reveal_op not in [NAME_REGISTRATION, NAME_IMPORT]:
        return {'error': 'Transaction is not a NAME_REGISTRATION or a NAME_IMPORT'}

    if reveal_payload != name:
        log.error("Reveal payload is '%s'; expected '%s'" % (reveal_payload, name))
        return {'error': 'Transaction does not reveal the given name'}

    # NOTE: trusts Blockstack
    if reveal_op == NAME_REGISTRATION:
        reveal_op = "NAME_REGISTRATION"
    elif reveal_op == NAME_IMPORT:
        reveal_op = "NAME_IMPORT"
    else:
        return {'error': 'Unrecognized reveal opcode'}

    ret = {
        'type': reveal_op,
        'block_id': reveal_block_number,
        'txid': reveal_tx['txid']
    }

    return ret


def find_last_historical_op(history, opcode):
    """
    Given the blockchain history of a name, and the desired opcode name,
    find the last history record for the opcode.  This returns a dict of the
    old values for the fields.

    Return (block number, dict of records that changed at that block number) on success.
      block number will be -1 if the dict of records is the oldest historical record, which
      indicates that the caller should use the preorder_block_number field as the block to
      which the history record applies.

    Return (None, None) on error
    """

    prev_blocks = sorted(history.keys())[::-1] + [-1]
    prev_opcode = None
    for i in xrange(0, len(prev_blocks)-1):

        prev_block = prev_blocks[i]
        prev_ops = history[prev_block]
        for prev_op in reversed(prev_ops):

            if prev_op.has_key('opcode'):
                prev_opcode = str(prev_op['opcode'])

            if prev_opcode == opcode:
                return (int(prev_blocks[i + 1]), prev_op)

    return (None, None)


def get_name_update_consensus_info(name, blockchain_record, bitcoind_proxy, proxy=None):
    """
    Given the result of a call to get_name_blockchain_record (an untrusted database record for a name),
    obtain the last-modification consensus hash, type, and block number.  Use SPV to verify that
    (1) the consensus hash is in the blockchain,
    (2)

    On success, and the name was modified since it was registered, return a dict with:
    * type: NAME_UPDATE
    * anchor: an object with:
        * consensus_hash: the consensus hash obtained from the NAME_UPDATE transaction.  Note
            that this is the consensus hash *at the time of issue*--it is *not* guaranteed to
            correspond to the block at which the NAME_UPDATE was incorporated into the blockchain.
        * block_id: the block id at which the operation was issued (*not* the block ID
            at which the NAME_UPDATE was incorporated into the blockchain).

    If the name has never been updated, then return None.

    On error, return a dict with 'error' defined as a key, mapped to an error message.
    """

    update_consensus_hash = None
    update_record = None
    update_block_id = None
    update_consensus_block_id = None

    # find the latest NAME_UPDATE
    if str(blockchain_record['opcode']) == "NAME_UPDATE":
        update_consensus_hash = str(blockchain_record['consensus_hash'])
        update_record = blockchain_record
        update_block_id = int(sorted(blockchain_record['history'].keys())[-1])

    else:
        update_block_id, update_record = find_last_historical_op(blockchain_record['history'], "NAME_UPDATE")
        if update_record is not None:
            update_consensus_hash = str(update_record['consensus_hash'])

    if update_consensus_hash is None:
        # never updated
        return None

    # get update tx data and verify it via SPV
    update_serial = "%s-%s" % (update_block_id, update_record['vtxindex'])
    update_tx = serial_number_to_tx(update_serial, bitcoind_proxy, proxy=proxy)

    # update_tx is now known to be on the main blockchain.
    tx_consensus_hash = None

    # the consensus hash will be between when we accepted the update (update_block_id), and up to BLOCKS_CONSENSUS_HASH_IS_VALID blocks in the past.
    candidate_consensus_hashes = get_consensus_range(update_block_id, update_block_id - virtualchain.lib.BLOCKS_CONSENSUS_HASH_IS_VALID)
    for i in xrange(0, len(candidate_consensus_hashes)):

        ch = candidate_consensus_hashes[i]
        tx_consensus_hash = verify_consensus_hash_from_tx(update_tx, name, ch)
        if tx_consensus_hash is not None:
            # the update_tx contains the untrusted consensus hash.
            # success!
            update_consensus_block_id = update_block_id + i
            break

    if tx_consensus_hash is None:
        # !!! Blockstackd lied to us--we got the wrong consensus hash
        return {'error': 'Blockstack consensus hash does not match the SPV block headers'}

    else:
        update_info = {
            'type': 'NAME_UPDATE',
            'block_id': update_block_id,
            'anchor': {
                'consensus_hash': update_consensus_hash,
                'block_id': update_consensus_block_id,
                'txid': update_tx['txid']
            }
        }

        return update_info


def snv_get_nameops_at(current_block_id, current_consensus_hash, block_id, consensus_hash, proxy=None):
    """
    Simple name verification (snv) lookup:
    Use a known-good "current" consensus hash and block ID to
    look up a set of name operations from the past, given the previous
    point in time's untrusted block ID and consensus hash.
    """

    log.debug("verify %s-%s to %s-%s" % (current_block_id, current_consensus_hash, block_id, consensus_hash))

    if proxy is None:
        proxy = get_default_proxy()

    # work backwards in time, using a Merkle skip-list constructed
    # by blockstackd over the set of consensus hashes.
    next_block_id = current_block_id

    prev_nameops_hashes = {}
    prev_consensus_hashes = {
        next_block_id: current_consensus_hash
    }

    # print "next_block_id = %s, block_id = %s" % (next_block_id, block_id)
    while next_block_id >= block_id:

        # get nameops_at[ next_block_id ], and all consensus_hash[ next_block_id - 2^i ] such that block_id - 2*i > block_id (start at i = 1)
        i = 0
        nameops_hash = None

        if not prev_nameops_hashes.has_key(next_block_id):
            nameops_resp = get_nameops_hash_at(next_block_id, proxy=proxy)

            if 'error' in nameops_resp:
                log.error("get_nameops_hash_at: %s" % nameops_resp['error'])
                return {'error': 'Failed to get nameops: %s' % nameops_resp['error']}

            nameops_hash = str(nameops_resp)
            prev_nameops_hashes[ next_block_id ] = nameops_hash

        else:
            nameops_hash = prev_nameops_hashes[ next_block_id ]

        # print "prev_nameops_hashes[%s] = %s" % (next_block_id, nameops_hash)
        """
        ch_block_ids = []
        while next_block_id - (2**(i+1) - 1) >= FIRST_BLOCK_MAINNET:

            i += 1
            ch_block_ids.append(next_block_id - (2**i - 1))

            if not prev_consensus_hashes.has_key(next_block_id - (2**i - 1)):
                ch = str(get_consensus_at(next_block_id - (2**i - 1), proxy=proxy))

                if ch != "None":
                    prev_consensus_hashes[ next_block_id - (2**i - 1) ] = ch
                    # print "prev_consensus_hashes[%s] = %s" % (next_block_id - (2**i - 1), ch)

                else:
                    # skip this one
                    ch_block_ids.pop()
                    break
        """
        # find out which consensus hashes we'll need
        to_fetch = []
        ch_block_ids = []
        while next_block_id - (2**(i+1) - 1) >= FIRST_BLOCK_MAINNET:

            i += 1
            prev_block_id = next_block_id - (2**i - 1)
            ch_block_ids.append(prev_block_id)

            if not prev_consensus_hashes.has_key(prev_block_id):
                to_fetch.append( prev_block_id )


        # get the consensus hashes
        chs = {}
        if len(to_fetch) > 0:
            chs = get_consensus_hashes( to_fetch, proxy=proxy )

        prev_consensus_block_ids = []
        for b in ch_block_ids:

            # NOTE: we process to_fetch *in decreasing order* so we know when we're missing data
            if not chs.has_key(b) and not prev_consensus_hashes.has_key(b):
                log.error("Missing consensus hash response for %s" % b)
                return {'error': "Server did not reply valid data"}

            prev_consensus_block_ids.append(b)
            if prev_consensus_hashes.has_key(b):
                # already got this one
                continue

            ch = str(chs[b])
            if ch != "None":
                prev_consensus_hashes[b] = ch

            else:
                # no consensus hash for this block and all future blocks
                prev_consensus_block_ids.pop()
                break
                
        # prev_consensus_hashes_list = [ prev_consensus_hashes[b] for b in ch_block_ids ]
        prev_consensus_hashes_list = [ prev_consensus_hashes[b] for b in prev_consensus_block_ids ]

        # calculate the snapshot, and see if it matches
        ch = virtualchain.StateEngine.make_snapshot_from_ops_hash(nameops_hash, prev_consensus_hashes_list)
        expected_ch = prev_consensus_hashes[ next_block_id ]
        if ch != expected_ch:
            log.error("Consensus hash mismatch at %s: expected %s, got %s" % (next_block_id, expected_ch, ch))
            return {'error': 'Consensus hash mismatch'}

        # advance!
        # find the smallest known consensus hash whose block is greater than block_id
        current_candidate = next_block_id
        found_any = False
        for candidate_block_id in prev_consensus_hashes.keys():
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
    if type(historic_nameops) == dict and 'error' in historic_nameops:
        return {'error': 'BUG: no nameops found'}

    # sanity check...
    for historic_op in historic_nameops:
        if not historic_op.has_key('opcode'):
            return {'error': 'Invalid/corrupt name operations detected'}

        # recover binary op string
        if not historic_op.has_key('op'):
            historic_op['op'] = NAME_OPCODES[ str(historic_op['opcode']) ]

    # check integrity
    serialized_historic_nameops = [virtualchain.StateEngine.serialize_op(str(op['op'][0]), op, OPFIELDS, verbose=False) for op in historic_nameops]
    historic_nameops_hash = virtualchain.StateEngine.make_ops_snapshot(serialized_historic_nameops)

    if not prev_nameops_hashes.has_key(block_id):
        return {'error': 'Previous block/consensus hash is unreachable from trusted block/consensus hash'}

    if historic_nameops_hash != prev_nameops_hashes[ block_id ]:
        return {'error': 'Hash mismatch: name is not consistent with consensus hash'}

    return historic_nameops


def snv_name_verify(name, current_block_id, current_consensus_hash, block_id, consensus_hash, proxy=None):
    """
    Use SNV to verify that a name existed at a particular block ID in the past,
    given a later known-good block ID and consensus hash (as well as the previous
    untrusted consensus hash)

    Return the name's historic nameop on success
    Return a dict with {'error'} on error
    """

    if proxy is None:
        proxy = get_default_proxy()

    historic_nameops = snv_get_nameops_at(current_block_id, current_consensus_hash, block_id, consensus_hash, proxy=proxy)
    if 'error' in historic_nameops:
        return historic_nameops

    # find the one we asked for
    for nameop in historic_nameops:
        if 'name' not in nameop:
            continue

        if str(nameop['name']) == str(name):
            # success!
            return nameop

    # not found
    log.error("Not found at block %s: '%s'" % (block_id, name))
    return {'error': 'Name not found'}



def snv_lookup(verify_name, verify_block_id, trusted_serial_number_or_txid_or_consensus_hash, proxy=None):
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
    """

    if proxy is None:
        proxy = get_default_proxy()

    trusted_serial_number_or_txid_or_consensus_hash = str(trusted_serial_number_or_txid_or_consensus_hash)

    bitcoind_proxy = get_bitcoind_client( config_path=proxy.conf['path'] )
    trusted_serial_number = None
    trusted_txid = None
    trusted_consensus_hash = None
    trusted_block_id = None

    # what did we get?
    if len(trusted_serial_number_or_txid_or_consensus_hash) == 64 and is_hex(trusted_serial_number_or_txid_or_consensus_hash):
        # txid: convert to trusted block ID and consensus hash
        trusted_txid = trusted_serial_number_or_txid_or_consensus_hash
        trusted_block_hash, trusted_block_data, trusted_tx = txid_to_block_data(trusted_txid, bitcoind_proxy)
        if trusted_block_hash is None or trusted_block_data is None or trusted_tx is None:
            return {'error': 'Unable to look up given transaction ID'}

        # must have a consensus hash
        op, payload = parse_tx_op_return(trusted_tx)
        trusted_consensus_hash = get_consensus_hash_from_tx(trusted_tx)
        if trusted_consensus_hash is None:
            return {'error': 'Tx does not refer to a consensus-bearing transaction'}

        # find the block for this consensus hash (it's not the same as the serial number's block ID,
        # but that's okay--if the consensus hash in this tx is inauthentic, it will be unreachable
        # from the other consensus hash [short of a SHA256 collision])
        trusted_block_id = get_block_from_consensus(trusted_consensus_hash, proxy=proxy)


    elif len(trusted_serial_number_or_txid_or_consensus_hash) == 32 and is_hex(trusted_serial_number_or_txid_or_consensus_hash):
        # consensus hash
        trusted_consensus_hash = trusted_serial_number_or_txid_or_consensus_hash
        trusted_block_id = get_block_from_consensus(trusted_consensus_hash, proxy=proxy)
        if type(trusted_block_id) == dict and 'error' in trusted_block_id:
            # got error back
            return trusted_block_id


    elif len(trusted_serial_number_or_txid_or_consensus_hash.split("-")) == 2:
        # must be a serial number
        parts = trusted_serial_number_or_txid_or_consensus_hash.split("-")
        try:
            trusted_block_id = int(parts[0])
            trusted_tx_index = int(parts[1])
        except:
            log.error("Malformed serial number '%s'" % trusted_serial_number_or_txid_or_consensus_hash)
            return {'error': 'Did not receive a valid serial number'}

        trusted_tx = serial_number_to_tx(trusted_serial_number_or_txid_or_consensus_hash, bitcoind_proxy)
        if trusted_tx is None:
            return {'error': 'Unable to convert given serial number into transaction'}

        # tx must have a consensus hash
        op, payload = parse_tx_op_return(trusted_tx)
        trusted_consensus_hash = get_consensus_hash_from_tx(trusted_tx)
        if trusted_consensus_hash is None:
            return {'error': 'Tx does not refer to a consensus-bearing transaction'}

        # find the block for this consensus hash (it's not the same as the serial number's block ID,
        # but that's okay--if the consensus hash in this tx is inauthentic, it will be unreachable
        # from the other consensus hash [short of a SHA256 collision])
        trusted_block_id = get_block_from_consensus(trusted_consensus_hash, proxy=proxy)
        if type(trusted_block_id) == dict and 'error' in trusted_block_id:
            # got error back
            return trusted_block_id

    else:
        return {'error': 'Did not receive a valid txid, consensus hash, or serial number (%s)' % trusted_serial_number_or_txid_or_consensus_hash}

    if trusted_block_id < verify_block_id:
        return {'error': 'Trusted block/consensus hash came before the untrusted block/consensus hash'}

    # go verify the name
    verify_consensus_hash = get_consensus_at(verify_block_id, proxy=proxy)
    historic_namerec = snv_name_verify(verify_name, trusted_block_id, trusted_consensus_hash, verify_block_id, verify_consensus_hash)

    return historic_namerec

# backwards compatibility
lookup_snv = snv_lookup

