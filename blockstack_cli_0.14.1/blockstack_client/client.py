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

import parsing, schemas, storage, drivers, config, spv, utils
import user as user_db
from spv import SPVClient

import pybitcoin
import bitcoin
import binascii
from utilitybelt import is_hex

from config import log, DEBUG, MAX_RPC_LEN, find_missing, BLOCKSTACKD_SERVER, \
    BLOCKSTACKD_PORT, BLOCKSTACK_METADATA_DIR, BLOCKSTACK_DEFAULT_STORAGE_DRIVERS, \
    FIRST_BLOCK_MAINNET, NAME_OPCODES, OPFIELDS, CONFIG_DIR, SPV_HEADERS_PATH, BLOCKCHAIN_ID_MAGIC, \
    NAME_PREORDER, NAME_REGISTRATION, NAME_UPDATE, NAME_TRANSFER, NAMESPACE_PREORDER, NAME_IMPORT

import virtualchain

# default API endpoint proxy to blockstackd
default_proxy = None

# ancillary storage providers
STORAGE_IMPL = None


class BlockstackRPCClient(object):
    """
    Not-quite-JSONRPC client for Blockstack.

    Blockstack's not-quite-JSONRPC server expects a raw Netstring that encodes
    a JSON object with a "method" string and an "args" list.  It will ignore
    "id" and "version", and will not accept keyword arguments.  It also does
    not guarantee that the "result" and "error" keywords will be present.
    """

    def __init__(self, server, port,
                 max_rpc_len=MAX_RPC_LEN,
                 timeout=config.DEFAULT_TIMEOUT):
        self.server = server
        self.port = port
        self.sock = None
        self.max_rpc_len = max_rpc_len
        self.timeout = timeout

    def __getattr__(self, key):
        try:
            return object.__getattr__(self, key)
        except AttributeError:
            return self.dispatch(key)

    def socket():
        return self.sock

    def default(self, *args):
        self.params = args
        return self.request()

    def dispatch(self, key):
        self.method = key
        return self.default

    def ensure_connected(self):
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.server, self.port))

        return True

    def request(self):

        self.ensure_connected()
        request_id = str(uuid.uuid4())
        parameters = {
            'id': request_id,
            'method': self.method,
            'params': self.params,
            'version': '2.0'
        }

        data = json.dumps(parameters)
        data_netstring = str(len(data)) + ":" + data + ","

        # send request
        try:
            self.sock.sendall(data_netstring)
        except Exception, e:
            self.sock.close()
            self.sock = None
            raise e

        # get response: expect comma-ending netstring
        # get the length first
        len_buf = ""

        while True:
            c = self.sock.recv(1)
            if len(c) == 0:
                # connection closed
                self.sock.close()
                self.sock = None
                raise Exception("Server closed remote connection")

            c = c[0]

            if c == ':':
                break
            else:
                len_buf += c
                buf_len = 0

                # ensure it's an int
                try:
                    buf_len = int(len_buf)
                except Exception, e:
                    # invalid
                    self.sock.close()
                    self.sock = None
                    raise Exception("Invalid response: invalid netstring length")

                # ensure it's not too big
                if buf_len >= self.max_rpc_len:
                    self.sock.close()
                    self.sock = None
                    raise Exception("Invalid response: message too big")

        # receive message
        num_received = 0
        response = ""

        while num_received < buf_len+1:
            buf = self.sock.recv(4096)
            num_received += len(buf)
            response += buf

        # ensure that the message is terminated with a comma
        if response[-1] != ',':
            self.sock.close()
            self.sock = None
            raise Exception("Invalid response: invalid netstring termination")

        # trim ','
        response = response[:-1]
        result = None

        # parse the response
        try:
            result = json.loads(response)

            # Netstrings responds with [{}] instead of {}
            result = result[0]

            return result
        except Exception, e:

            # try to clean up
            self.sock.close()
            self.sock = None
            raise Exception("Invalid response: not a JSON string")


def session(conf=None, server_host=BLOCKSTACKD_SERVER, server_port=BLOCKSTACKD_PORT,
            storage_drivers=BLOCKSTACK_DEFAULT_STORAGE_DRIVERS,
            metadata_dir=BLOCKSTACK_METADATA_DIR, spv_headers_path=SPV_HEADERS_PATH, set_global=False):

    """
    Create a blockstack session:
    * validate the configuration
    * load all storage drivers
    * initialize all storage drivers
    * load an API proxy to blockstack

    conf's fields override specific keyword arguments.

    Returns the API proxy object.
    """

    global default_proxy
    if conf is not None:

        missing = find_missing(conf)
        if len(missing) > 0:
            log.error("Missing blockstack configuration fields: %s" % (", ".join(missing)))
            sys.exit(1)

        server_host = conf['server']
        server_port = conf['port']
        storage_drivers = conf['storage_drivers']
        metadata_dir = conf['metadata']

    if storage_drivers is None:
        log.error("No storage driver(s) defined in the config file.  Please set 'storage=' to a comma-separated list of %s" % ", ".join(drivers.DRIVERS))
        sys.exit(1)

    # create proxy
    proxy = BlockstackRPCClient(server_host, server_port)


    # load all storage drivers
    for storage_driver in storage_drivers.split(","):
        storage_impl = load_storage(storage_driver)
        if storage_impl is None:
            log.error("Failed to load storage driver '%s'" % (storage_driver))
            sys.exit(1)

        rc = register_storage(storage_impl)
        if not rc:
            log.error("Failed to initialize storage driver '%s'" % (storage_driver))
            sys.exit(1)

    # initialize SPV
    SPVClient.init(spv_headers_path)
    proxy.spv_headers_path = spv_headers_path
    proxy.conf = conf

    if set_global:
        default_proxy = proxy

    return proxy


def get_default_proxy():
    """
    Get the default API proxy to blockstack.
    """
    global default_proxy

    return default_proxy


def set_default_proxy(proxy):
    """
    Set the default API proxy
    """
    global default_proxy
    default_proxy = proxy


def load_storage(module_name):
    """
    Load a storage implementation, given its module name.
    Valid options can be found in blockstack.drivers.DRIVERS
    """

    if module_name not in drivers.DRIVERS:
        raise Exception("Unrecognized storage driver.  Valid options are %s" % (", ".join(drivers.DRIVERS)))

    try:
        storage_impl = importlib.import_module("blockstack_client.drivers.%s" % module_name)
    except ImportError, ie:
        raise Exception("Failed to import blockstack.drivers.%s.  Please verify that it is accessible via your PYTHONPATH" % module_name)

    return storage_impl


def register_storage(storage_impl):
    """
    Register a storage implementation.
    """
    rc = storage.register_storage(storage_impl)
    if rc:
        rc = storage_impl.storage_init()

    return rc


def load_user(record_hash):
    """
    Load a user record from the storage implementation with the given hex string hash,
    The user record hash should have been loaded from the blockchain, and thereby be the
    authentic hash.

    Return the user record on success
    Return None on error
    """

    user_json = storage.get_immutable_data(record_hash)

    if user_json is None:
        log.error("Failed to load user record '%s'" % record_hash)
        return None

    # verify integrity
    user_record_hash = storage.get_data_hash(user_json)
    if user_record_hash != record_hash:
        log.error("Profile hash mismatch: expected '%s', got '%s'" % (record_hash, user_record_hash))
        return None

    #user = user_db.parse_user(user_json)
    #return user
    return user_json


def get_zone_file(name):
    # or whatever else we're going to call this
    return get_name_record(name)


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
    if type(resp) == list:
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
        except Exception, e:
            log.exception(e)
            log.error("Unable to obtain block data; retrying...")
            time.sleep(timeout)
            timeout = timeout * 2 + random.random() * timeout

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
        #print SPVClient.tx_hash(tx)
        #print op_return.encode('hex')
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


def lookup(name, proxy=None):
    """
    Get the name and (some) blockchain data:
    * zone file
    * serial number
    * consensus hash at block of creation (NAME_IMPORT or NAME_PREORDER)
    * consensus hash at block of last modification
    * address

    Use SPV to verify that we're getting the right consensus hash.
    """

    if proxy is None:
        proxy = get_default_proxy()

    bitcoind_proxy = virtualchain.connect_bitcoind(proxy.conf)

    # get zonefile data
    zone_file = get_zone_file(name)
    if 'error' in zone_file:
        return zone_file

    # get blockchain-obtained data
    blockchain_result = get_name_blockchain_record(name, proxy=proxy)

    # get creation consensus data
    creation_info = get_name_creation_consensus_info(name, blockchain_result, bitcoind_proxy, proxy=proxy)
    if 'error' in creation_info:
        return creation_info

    # get revelation consensus data
    reveal_info = get_name_reveal_consensus_info(name, blockchain_result, bitcoind_proxy, proxy=proxy)
    if reveal_info is not None and 'error' in reveal_info:
        return reveal_info

    # get update consensus data
    update_info = get_name_update_consensus_info(name, blockchain_result, bitcoind_proxy, proxy=proxy)
    if update_info is not None and 'error' in update_info:
        return update_info

    # get serial number
    serial_number = get_serial_number(blockchain_result)

    # fill in serial number, address
    result = {
        'blockchain_id': name,
        'zone_file': zone_file,
        'serial_number': serial_number,
        'address': blockchain_result.get('address', None),
        'created': creation_info
    }

    if reveal_info is not None:
        result['revealed'] = reveal_info

    if update_info is not None:
        result['updated'] = update_info

    return result


def get_name_record(name, create_if_absent=False, proxy=None,
                    check_only_blockchain=False):
    """
    Given the name of the user, look up the user's record hash,
    and then get the record itself from storage.

    Returns a dict that contains the record,
    or a dict with "error" defined and a message.
    """

    if proxy is None:
        proxy = get_default_proxy()

    # find name record first
    name_record = get_name_blockchain_record(name, proxy=proxy)
    if len(name_record) == 0:
        return {"error": "No such name"}

    if 'error' in name_record:
        return name_record

    if name_record is None:
        # failed to look up
        return {'error': "No such name"}

    if 'error' in name_record:

        # failed to look up
        return name_record

    # sanity check
    if 'value_hash' not in name_record:

        return {"error": "Name has no user record hash defined"}

    if check_only_blockchain:
        return name_record

    # is there a user record loaded?
    if name_record['value_hash'] in [None, "null", ""]:

        # no user data
        if not create_if_absent:
            return {"error": "No user data"}
        else:
            # make an empty one and return that
            user_resp = user_db.make_empty_user(name, name_record)
            return user_resp

    # get record
    user_record_hash = name_record['value_hash']
    user_resp = load_user(user_record_hash)

    if user_resp is None:

      # no user record data
      return {"error": "User data could not be loaded from storage"}

    return user_resp


def store_name_record(user, txid):
    """
    Store JSON user record data to the immutable storage providers, synchronously.

    Return (True, hash(user)) on success
    Return (False, hash(user)) on failure
    """

    username = user_db.name(user)

    # serialize
    user_json = None
    try:
        user_json = user_db.serialize_user(user)
    except Exception, e:
        log.error("Failed to serialize '%s'" % user)
        return False

    data_hash = storage.get_data_hash(user_json)
    result = storage.put_immutable_data(user_json, txid)

    rc = None
    if result is None:
        rc = False
    else:
        rc = True

    return (rc, data_hash)


def remove_name_record(user, txid):
    """
    Delete JSON user record data from immutable storage providers, synchronously.

    Return (True, hash(user)) on success
    Return (False, hash(user)) on error
    """

    username = user_db.name(user)

    # serialize
    user_json = None
    try:
        user_json = user_db.serialize_user(user)
    except Exception, e:
        log.error("Failed to serialize '%s'" % user)
        return False

    data_hash = storage.get_data_hash(user_json)
    result = storage.delete_immutable_data(data_hash, txid)

    rc = None
    if result is None:
        rc = False
    else:
        rc = True

    return (rc, data_hash)


def json_traceback():
    exception_data = traceback.format_exc().splitlines()
    return {
        "error": exception_data[-1],
        "traceback": exception_data
    }


def getinfo(proxy=None):
    """
    getinfo
    """

    resp = {}

    if proxy is None:
        proxy = get_default_proxy()

    try:
        resp = proxy.getinfo()
        if type(resp) == list:
            if len(resp) == 0:
                resp = {'error': 'No data returned'}
            else:
                resp = resp[0]

    except Exception as e:
        resp = json_traceback()

    return resp


def ping(proxy=None):
    """
    ping
    """

    resp = {}

    if proxy is None:
        proxy = get_default_proxy()

    try:
        resp = proxy.ping()
        if type(resp) == list:
            if len(resp) == 0:
                resp = {'error': 'No data returned'}
            else:
                resp = resp[0]

    except Exception as e:
        resp['error'] = str(e)

    return resp


def get_name_cost(name, proxy=None):
    """
    name_cost
    """
    if proxy is None:
        proxy = get_default_proxy()

    resp = proxy.get_name_cost(name)
    if type(resp) == list:
        if len(resp) == 0:
            resp = {'error': 'No data returned'}
        else:
            resp = resp[0]

    return resp


def get_namespace_cost(namespace_id, proxy=None):
    """
    namespace_cost
    """
    if proxy is None:
        proxy = get_default_proxy()

    resp = proxy.get_namespace_cost(namespace_id)
    if type(resp) == list:
        if len(resp) == 0:
            resp = {'error': 'No data returned'}
        else:
            resp = resp[0]

    return resp


def get_all_names(offset, count, proxy=None):
    """
    get all names
    """
    if proxy is None:
        proxy = get_default_proxy()

    return proxy.get_all_names(offset, count)


def get_names_in_namespace(namespace_id, offset, count, proxy=None):
    """
    Get names in a namespace
    """
    if proxy is None:
        proxy = get_default_proxy()

    return proxy.get_names_in_namespace(namespace_id, offset, count)


def get_names_owned_by_address(address, proxy=None):
    """
    Get the names owned by an address.
    Only works for p2pkh scripts.
    """
    if proxy is None:
        proxy = get_default_proxy()

    return proxy.get_names_owned_by_address(address)


def get_consensus_at(block_height, proxy=None):
    """
    Get consensus at a block
    """
    if proxy is None:
        proxy = get_default_proxy()

    resp = proxy.get_consensus_at(block_height)
    if type(resp) == list:
        if len(resp) == 0:
            resp = {'error': 'No data returned'}
        else:
            resp = resp[0]

    return resp


def get_consensus_range(block_id_start, block_id_end, proxy=None):
    """
    Get a range of consensus hashes.  The range is inclusive.
    """
    if proxy is None:
        proxy = get_default_proxy()

    resp = proxy.get_consensus_range(block_id_start, block_id_end)
    return resp


def get_nameops_at(block_id, proxy=None):
    """
    Get the set of records as they were at a particular block.
    """
    if proxy is None:
        proxy = get_default_proxy()

    resp = proxy.get_nameops_at(block_id)
    return resp


def get_nameops_hash_at(block_id, proxy=None):
    """
    Get the hash of a set of records as they were at a particular block.
    """
    if proxy is None:
        proxy = get_default_proxy()

    resp = proxy.get_nameops_hash_at(block_id)
    if type(resp) == list:
        if len(resp) == 0:
            resp = {'error': 'No data returned'}
        else:
            resp = resp[0]

    return resp


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

    # get current consensus hash and block ID
    current_info = getinfo(proxy=proxy)
    if 'error' in current_info:
        return current_info

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

        prev_consensus_hashes_list = [ prev_consensus_hashes[b] for b in ch_block_ids ]

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
    if 'error' in historic_nameops:
        return {'error': 'BUG: no nameops found'}

    historic_nameops = historic_nameops[0]

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

    bitcoind_proxy = virtualchain.connect_bitcoind(proxy.conf)
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

def get_name_blockchain_record(name, proxy=None):
    """
    get_name_blockchain_record
    """

    if proxy is None:
        proxy = get_default_proxy()

    resp = proxy.get_name_blockchain_record(name)
    if type(resp) == list:
        if len(resp) == 0:
            resp = {'error': 'No data returned'}
        else:
            resp = resp[0]

    return resp


def get_namespace_blockchain_record(namespace_id, proxy=None):
    """
    get_namespace_blockchain_record
    """

    if proxy is None:
        proxy = get_default_proxy()

    ret = proxy.get_namespace_blockchain_record(namespace_id)
    if type(ret) == list:
        if len(ret) == 0:
            ret = {'error': 'No data returned'}
            return ret
        else:
            ret = ret[0]

    if ret is not None:
        # this isn't needed
        if 'opcode' in ret:
            del ret['opcode']

    return ret


def get_namespace_reveal_blockchain_record(namespace_id, proxy=None):
    """
    Get a revealed (but not readied) namespace's information
    """
    if proxy is None:
        proxy = get_default_proxy()

    ret = proxy.get_namespace_reveal_blockchain_record(namespace_id)
    if type(ret) == list:
        if len(ret) == 0:
            ret = {'error': 'No data returned'}
            return ret
        else:
            ret = ret[0]

    if ret is not None:
        # this isn't needed
        if 'opcode' in ret:
            del ret['opcode']

    return ret


def preorder(name, privatekey, register_addr=None, proxy=None, tx_only=False):
    """
    preorder.
    Generate a private key to derive a change address for the register,
    if one is not given already.
    """

    register_privkey_wif = None

    if register_addr is None:
        privkey = pybitcoin.BitcoinPrivateKey()
        pubkey = privkey.public_key()

        register_addr = pubkey.address()

        register_privkey_wif = privkey.to_wif()
        print register_privkey_wif
        print register_addr

    # make sure the reveal address is *not* the address of this private key
    privkey = pybitcoin.BitcoinPrivateKey(privatekey)
    if register_addr == privkey.public_key().address():
        return {"error": "Register address derived from private key"}

    resp = {}

    if proxy is None:
        proxy = get_default_proxy()

    try:
        if tx_only:

            # get unsigned preorder
            resp = proxy.preorder_tx(name, privatekey, register_addr)

        else:
            # send preorder
            resp = proxy.preorder(name, privatekey, register_addr)

    except Exception as e:
        resp['error'] = str(e)

    if 'error' in resp:
        return resp

    # give the client back the key to the addr we used
    if register_privkey_wif is not None:
        resp['register_privatekey'] = register_privkey_wif

    return resp


def preorder_subsidized(name, public_key, register_addr, subsidy_key, proxy=None):
    """
    preorder a name, but subsidize it with the given subsidy_key.
    Return a SIGHASH_ANYONECANPAY transaction, where the client must sign each
    input originating from register_addr
    """
    resp = {}

    if proxy is None:
        proxy = get_default_proxy()

    try:
        # get preorder tx
        resp = proxy.preorder_tx_subsidized(name, public_key, register_addr, subsidy_key)

    except Exception as e:
        resp['error'] = str(e)

    return resp


def register(name, privatekey, register_addr, proxy=None, tx_only=False):
    """
    register
    """

    resp = {}

    if proxy is None:
        proxy = get_default_proxy()

    try:
        if tx_only:

            # get unsigned preorder
            resp = proxy.register_tx(name, privatekey, register_addr)

        else:
            # send preorder
            resp = proxy.register(name, privatekey, register_addr)

    except Exception as e:
        resp['error'] = str(e)

    return resp



def register_subsidized(name, public_key, register_addr, subsidy_key, proxy=None):
    """
    make a transaction that will register a name, but subsidize it with the given subsidy_key.
    Return a SIGHASH_ANYONECANPAY transaction, where the client must sign each
    input originating from register_addr
    """
    resp = {}

    if proxy is None:
        proxy = get_default_proxy()

    try:
        # get register tx
        resp = proxy.register_tx_subsidized(name, public_key, register_addr, subsidy_key)

    except Exception as e:
        resp['error'] = str(e)

    return resp


def update(name, user_json_or_hash, privatekey, txid=None, proxy=None, tx_only=False, public_key=None, subsidy_key=None):
    """
    update

    Optionally supply a txid.  The reason for doing so is to try to replicate user
    data to new storage systems, or to recover from a transient error encountered
    earlier.
    """

    # sanity check
    if privatekey is None and public_key is None:
        return {'error': 'Missing public and private key'}

    if proxy is None:
        proxy = get_default_proxy()

    user_record_hash = None
    user_data = None

    # 160-bit hex string?
    if len(user_json_or_hash) == 40 and len(user_json_or_hash.translate(None, "0123456789ABCDEFabcdef")) == 0:

        user_record_hash = user_json_or_hash.lower()
    else:

        # user record json.  hash it
        user_data = user_db.parse_user(user_json_or_hash)
        if user_data is None:
            return {'error': 'Invalid user record JSON'}

        user_record_hash = pybitcoin.hash.hex_hash160(user_db.serialize_user(user_data))

    # go get the current user record (blockchain only)
    current_user_record = get_name_record(name, check_only_blockchain=True)
    if current_user_record is None:
        return {'error': 'No such user'}

    if current_user_record.has_key('error'):
        # some other error
        return current_user_record

    result = {}

    old_hash = pybitcoin.hash.hex_hash160(user_db.serialize_user(user_data))

    # only want transaction?
    if tx_only:

        if privatekey is None and public_key is not None and subsidy_key is not None:
            return proxy.update_tx_subsidized(name, user_record_hash, public_key, subsidy_key)

        else:
            return proxy.update_tx(name, user_record_hash, privatekey)


    # no transaction: go put one
    if txid is None:

        if tx_only:
            result = proxy.update_tx(name, user_record_hash, privatekey)
            return result

        else:
            result = proxy.update(name, user_record_hash, privatekey)

        if 'error' in result:
            # failed
            return result

        if 'transaction_hash' not in result:
            # failed
            result['error'] = "No transaction hash given"
            return result

        txid = result['transaction_hash']

    else:

        # embed the txid into the result nevertheless
        result['transaction_hash'] = txid

    # store new user data
    rc = True
    new_data_hash = None
    if user_data is not None:
        rc, new_data_hash = store_name_record(user_data, txid)

    else:
        # was already a hash
        new_data_hash = user_json_or_hash

    if not rc:
        result['error'] = "Failed to store updated user record."
        return result

    result['status'] = True
    result['value_hash'] = new_data_hash
    result['transaction_hash'] = txid

    return result


def update_subsidized(name, user_json_or_hash, public_key, subsidy_key, txid=None):
    """
    update_subsidized
    """
    return update(name, user_json_or_hash, None, txid=txid, public_key=public_key, subsidy_key=subsidy_key, tx_only=True)


def transfer(name, address, keep_data, privatekey, proxy=None, tx_only=False):
    """
    transfer
    """

    if proxy is None:
        proxy = get_default_proxy()

    if tx_only:
        return proxy.transfer_tx(name, address, keep_data, privatekey)

    else:
        return proxy.transfer(name, address, keep_data, privatekey)


def transfer_subsidized(name, address, keep_data, public_key, subsidy_key, proxy=None):
    """
    transfer_subsidized
    """
    if proxy is None:
        proxy = get_default_proxy()

    return proxy.transfer_tx_subsidized(name, address, keep_data, public_key, subsidy_key)


def renew(name, privatekey, proxy=None, tx_only=False):
    """
    renew
    """

    if proxy is None:
        proxy = get_default_proxy()

    if tx_only:
        return proxy.renew_tx(name, privatekey)

    else:
        return proxy.renew(name, privatekey)


def renew_subsidized(name, public_key, subsidy_key, proxy=None):
    """
    renew_subsidized
    """

    if proxy is None:
        proxy = get_default_proxy()

    return proxy.renew_tx_subsidized(name, public_key, subsidy_key)


def revoke(name, privatekey, proxy=None, tx_only=False):
    """
    revoke
    """

    if proxy is None:
        proxy = get_default_proxy()

    if tx_only:
        return proxy.revoke_tx(name, privatekey)

    else:
        return proxy.revoke(name, privatekey)


def revoke_subsidized(name, public_key, subsidy_key, proxy=None):
    """
    revoke_subsidized
    """
    if proxy is None:
        proxy = get_default_proxy()

    return proxy.revoke_tx_subsidized(name, public_key, subsidy_key)


def send_subsidized(privatekey, subsidized_tx, proxy=None):
    """
    send_subsidized
    """
    if proxy is None:
        proxy = get_default_proxy()

    return proxy.send_subsidized(privatekey, subsidized_tx)


def name_import(name, address, update_hash, privatekey, proxy=None):
    """
    name import
    """

    if proxy is None:
        proxy = get_default_proxy()

    return proxy.name_import(name, address, update_hash, privatekey)


def namespace_preorder(namespace_id, privatekey, reveal_addr=None, proxy=None):
    """
    namespace preorder
    Generate a register change address private key, if not given
    """

    if proxy is None:
        proxy = get_default_proxy()

    reveal_privkey_wif = None

    if reveal_addr is None:
        privkey = pybitcoin.BitcoinPrivateKey()
        pubkey = privkey.public_key()
        reveal_addr = pubkey.address()

        reveal_privkey_wif = privkey.to_wif()
        print reveal_privkey_wif
        print reveal_addr

    # make sure the reveal address is *not* the address of this private key
    privkey = pybitcoin.BitcoinPrivateKey(privatekey)
    if reveal_addr == privkey.public_key().address():
        return {"error": "Reveal address derived from private key"}

    result = proxy.namespace_preorder(namespace_id, reveal_addr, privatekey)

    if 'error' in result:
        return result

    if reveal_privkey_wif is not None:
        result['reveal_privatekey'] = reveal_privkey_wif

    return result


def namespace_reveal(namespace_id, reveal_addr, lifetime, coeff, base_cost,
                     bucket_exponents, nonalpha_discount, no_vowel_discount,
                     privatekey, proxy=None):
    """
    namesapce_reveal
    """

    if proxy is None:
        proxy = get_default_proxy()

    return proxy.namespace_reveal(namespace_id, reveal_addr, lifetime, coeff,
                                  base_cost, bucket_exponents, nonalpha_discount,
                                  no_vowel_discount, privatekey)


def namespace_ready(namespace_id, privatekey, proxy=None):
    """
    namespace_ready
    """

    if proxy is None:
        proxy = get_default_proxy()

    return proxy.namespace_ready(namespace_id, privatekey)


def load_mutable_data_version(conf, name, data_id, try_remote=True):
    """
    Get the version field of a piece of mutable data.
    Check the local cache first, and if we need to,
    fetch the data itself from mutable storage
    """

    # try to get the current, locally-cached version
    if conf is None:
        conf = config.get_config()

    metadata_dir = None
    if conf is not None:

        metadata_dir = conf.get('metadata', None)
        if metadata_dir is not None and os.path.isdir(metadata_dir):

            # find the version file for this data
            serialized_data_id = data_id.replace("/", "\x2f").replace('\0', "\\0")
            version_file_path = os.path.join(metadata_dir, serialized_data_id + ".ver")

            if os.path.exists(version_file_path):

                ver = None
                try:
                    with open(version_file_path, "r") as f:
                        ver_txt = f.read()
                        ver = int(ver_txt.strip())

                    # success!
                    return ver

                except ValueError, ve:
                    # not an int
                    log.warn("Not an integer: '%s'" % version_file_path)

                except Exception, e:
                    # can't read
                    log.warn("Failed to read '%s': %s" % (version_file_path))

    if not try_remote:
        if conf is None:
            log.warning("No config found; cannot load version for '%s'" % data_id)

        elif metadata_dir is None:
            log.warning("No metadata directory found; cannot load version for '%s'" % data_id)

        return None

    # if we got here, then we need to fetch remotely
    existing_data = get_mutable(name, data_id)
    if existing_data is None:

        # nope
        return None

    if existing_data.has_key('error'):

        # nope
        return None

    ver = existing_data['ver']
    return ver


def store_mutable_data_version(conf, data_id, ver):
    """
    Locally store the version of a piece of mutable data,
    so we can ensure that its version is incremented on
    subsequent puts.

    Return True if stored
    Return False if not
    """

    if conf is None:
        conf = config.get_config()

    if conf is None:
        log.warning("No config found; cannot store version for '%s'" % data_id)
        return False

    metadata_dir = conf['metadata']
    if not os.path.isdir(metadata_dir):
        log.warning("No metadata directory found; cannot store version of '%s'" % data_id)
        return False

    serialized_data_id = data_id.replace("/", "\x2f").replace('\0', "\\0")
    version_file_path = os.path.join(metadata_dir, serialized_data_id + ".ver")

    try:
        with open(version_file_path, "w+") as f:
            f.write("%s" % ver)

        return True

    except Exception, e:
        # failed for whatever reason
        log.warn("Failed to store version of '%s' to '%s'" % (data_id, version_file_path))
        return False


def delete_mutable_data_version(conf, data_id):
    """
    Locally delete the version of a piece of mutable data.

    Return True if deleted.
    Return False if not
    """

    if conf is None:
        conf = config.get_config()

    if conf is None:
        log.warning("No config found; cannot store version for '%s'" % data_id)
        return False

    metadata_dir = conf['metadata']
    if not os.path.isdir(metadata_dir):
        log.warning("No metadata directory found; cannot store version of '%s'" % data_id)
        return False

    serialized_data_id = data_id.replace("/", "\x2f").replace('\0', "\\0")
    version_file_path = os.path.join(metadata_dir, serialized_data_id + ".ver")

    try:
        os.unlink(version_file_path)
        return True

    except Exception, e:
        # failed for whatever reason
        log.warn("Failed to remove version file '%s'" % (version_file_path))
        return False


def get_immutable(name, data_key):
    """
    get_immutable
    """

    user = get_name_record(name)
    if 'error' in user:

        # no user data
        return {'error': "Unable to load user record: %s" % user['error']}

    #if not user_db.has_immutable_data(user, data_key):

        # no data
    #    return {'error': 'Profile has no such immutable data'}

    data = storage.get_immutable_data(data_key)
    if data is None:

        # no data
        return {'error': 'No immutable data found'}

    return {'data': data}


def get_mutable(name, data_id, ver_min=None, ver_max=None, ver_check=None, conf=None):
    """
    get_mutable
    """

    if conf is None:
        conf = config.get_config()

    user = get_name_record(name)
    if 'error' in user:

        # no user data
        return {'error': "Unable to load user record: %s" % user['error']}

    # find the mutable data ID
    data_route = user_db.get_mutable_data_route(user, data_id)
    if data_route is None:

        # no data
        return {'error': 'No such route'}

    # go and fetch the data
    data = storage.get_mutable_data(data_route, ver_min=ver_min,
                                    ver_max=ver_max,
                                    ver_check=ver_check)
    if data is None:

        # no data
        return {'error': 'No mutable data found'}

    # what's the expected version of this data?
    expected_version = load_mutable_data_version(conf, name, data_id, try_remote=False)
    if expected_version is not None:
        if expected_version > data['ver']:
            return {'error': 'Stale data', 'ver_minimum': expected_version, 'ver_received': data['ver']}

    elif ver_check is None:
        # we don't have a local version, and the caller didn't check it.
        log.warning("Unconfirmed version for data '%s'" % data_id)
        data['warning'] = "Unconfirmed version"

    # remember latest version
    if data['ver'] > expected_version:
        store_mutable_data_version(conf, data_id, data['ver'])

    # include the route
    data['route'] = data_route
    return data


def put_immutable(name, data, privatekey, txid=None, proxy=None):
    """
    put_immutable

    Optionally include a txid from the user record update, in order to retry a failed
    data replication (in which case, this txid corresponds to the succeeded name
    update operation).  This is to avoid needing to pay for each replication retry.
    """

    if proxy is None:
        global default_proxy
        proxy = default_proxy

    # need to put the transaction ID into the data record we put
    user = get_name_record(name, create_if_absent=True)
    if 'error' in user:

        # no user data
        return {'error': "Unable to load user record: %s" % user['error']}

    data_hash = storage.get_data_hash(data)
    rc = user_db.add_immutable_data(user, data_hash)
    if not rc:
        return {'error': 'Invalid hash'}

    user_json = user_db.serialize_user(user)
    if user_json is None:
        raise Exception("BUG: failed to serialize user record")

    value_hash = None

    if txid is None:

        # haven't updated the user record yet.  Do so now.
        # put the new user record hash
        update_result = update(name, user_json, privatekey, proxy=proxy)
        if 'error' in update_result:

            # failed to replicate user record
            # NOTE: result will have the txid in it; pass it as txid to try again!
            return update_result

        txid = update_result['transaction_hash']
        value_hash = update_result['value_hash']

    result = {
        'data_hash': data_hash,
        'transaction_hash': txid
    }

    # propagate update() data
    if value_hash is not None:
        result['value_hash'] = value_hash

    # replicate the data
    rc = storage.put_immutable_data(data, txid)
    if not rc:
        result['error'] = 'Failed to store immutable data'
        return result

    else:
        result['status'] = True
        return result


def put_mutable(name, data_id, data_text, privatekey, proxy=None, create=True,
                txid=None, ver=None, make_ver=None, conf=None):
    """
    put_mutable

    ** Consistency **

    ver, if given, is the version to include in the data.
    make_ver, if given, is a callback that takes the data_id, data_text, and current version as arguments, and generates the version to be included in the data record uploaded.
    If ver is not given, but make_ver is, then make_ver will be used to generate the version.
    If neither ver nor make_ver are given, the mutable data (if it already exists) is fetched, and the version is calculated as the larget known version + 1.

    ** Durability **

    Replication is best-effort.  If one storage provider driver succeeds, the put_mutable succeeds.  If they all fail, then put_mutable fails.
    More complex behavior can be had by creating a "meta-driver" that calls existing drivers' methods in the desired manner.
    """

    if proxy is None:
        proxy = get_default_proxy()

    result = {}
    user = get_name_record(name, create_if_absent=create)
    if 'error' in user:

        return {'error': "Unable to load user record: %s" % user['error']}

    route = None
    exists = user_db.has_mutable_data_route(user, data_id)
    old_hash = None
    cur_hash = None
    new_ver = ver

    if ver is None:

        if exists:
            # mutable record already exists.
            # generate one automatically.
            # use the existing locally-stored version,
            # and fall back to using the last-known version
            # from the existing mutable data record.
            new_ver = load_mutable_data_version(config.get_config(), name, data_id, try_remote=True)
            if new_ver is None:
                # data exists, but we couldn't figure out the version
                return {'error': "Unable to determine version"}

        if make_ver is not None:
            # generate version
            new_ver = make_ver(data_id, data_text, new_ver)

        else:
            # no version known, and no way to generate it.
            # by default, start at 1.  we'll manage it ourselves.
            if new_ver is None:
                new_ver = 1
            else:
                new_ver += 1


    # do we have a route for this data yet?
    if not exists:

        if not create:
            # won't create; expect it to exist
            return {'error': 'No such route'}

        # need to put one
        urls = storage.make_mutable_urls(data_id)
        if len(urls) == 0:
            return {"error": "No routes constructed"}

        writer_pubkey = bitcoin.privkey_to_pubkey(privatekey)

        route = storage.mutable_data_route(data_id, urls,
                                           writer_pubkey=writer_pubkey)

        user_db.add_mutable_data_route(user, route)

        user_json = user_db.serialize_user(user)

        # update the user record with the new route
        update_result = update(name, user_json, privatekey, txid=txid, proxy=proxy)
        if 'error' in update_result:

            # update failed; caller should try again
            return update_result

        txid = update_result['transaction_hash']
        cur_hash = update_result['value_hash']

    else:

        route = user_db.get_mutable_data_route(user, data_id)
        if route is None:

            return {"error": "No such route"}

    # generate the data
    data = storage.mutable_data(data_id, data_text, new_ver, privkey=privatekey)
    if data is None:
        return {"error": "Failed to generate data record"}

    # serialize...
    data_json = parsing.json_stable_serialize(data)

    # replicate...
    store_rc = storage.put_mutable_data(data, privatekey)
    if not store_rc:
        result['error'] = "Failed to store mutable data"

    else:
        result['status'] = True

    result['transaction_hash'] = txid

    if cur_hash:
        # propagate
        result['value_hash'] = cur_hash

    # cache new version
    store_mutable_data_version(conf, data_id, new_ver)

    return result


def delete_immutable(name, data_key, privatekey, proxy=None, txid=None):
    """
    delete_immutable
    """

    if proxy is None:
        proxy = get_default_proxy()

    result = {}
    user = get_name_record(name)
    if 'error' in user:

        # no user data
        return {'error': "Unable to load user record: %s" % user['error']}

    # does the user record have this data?
    if not user_db.has_immutable_data(user, data_key):

        # already deleted
        return {'status': True}

    # remove hash from the user record and update it
    user_db.remove_immutable_data(user, data_key)

    user_json = user_db.serialize_user(user)

    update_result = update(name, user_json, privatekey, txid=txid, proxy=proxy)
    if 'error' in update_result:

        # update failed; caller should try again
        return update_result

    txid = update_result['transaction_hash']

    # remove the data itself data
    delete_result = storage.delete_immutable_data(data_key, txid)
    if delete_result:

        result['status'] = True

    else:

        # be sure to give back the update transaction hash, so this call can be retried
        result['error'] = 'Failed to delete immutable data'

    result['transaction_hash'] = txid
    result['value_hash'] = update_result['value_hash']

    return result


def delete_mutable(name, data_id, privatekey, proxy=default_proxy, txid=None,
                   route=None):
    """
    delete_mutable
    """

    if proxy is None:
        proxy = get_default_proxy()

    result = {}
    user = get_name_record(name)
    if 'error' in user:

        # no user data
        return {'error': "Unable to load user record: %s" % user['error']}

    # does the user have a route to this data?
    if not user_db.has_mutable_data_route(user, data_id) and txid is None:

        # nope--we're good
        return {'status': True}

    # blow away the data
    storage_rc = storage.delete_mutable_data(data_id, privatekey)
    if not storage_rc:
        result['error'] = "Failed to delete mutable data"
        return result

    # remove the route from the user record
    user_db.remove_mutable_data_route(user, data_id)
    user_json = user_db.serialize_user(user)

    # update the user record
    update_status = update(name, user_json, privatekey, txid=txid,
                           proxy=proxy)

    if 'error' in update_status:

        # failed; caller should try again
        return update_status

    if txid is None:
        txid = update_status['transaction_hash']

    # blow away the route
    if route is None:
        route = user_db.get_mutable_data_route(user, data_id)

    route_hash = storage.get_mutable_data_route_hash(route)
    storage_rc = storage.delete_immutable_data(route_hash, txid)
    if not storage_rc:

        result['error'] = "Failed to delete immutable data route"
        result['route'] = route

    else:
        result['status'] = True
        result['transaction_hash'] = txid
        result['value_hash'] = update_status['value_hash']

    # uncache local version
    delete_mutable_data_version(config.get_config(), data_id)

    return result
