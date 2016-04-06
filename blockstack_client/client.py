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
import zone_file
import urllib

import storage, drivers, config, spv, utils
import user as user_db
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

from wallet import * 

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

    """
    def update( self, name, user_zonefile_hash, privatekey ):
        print "fake update"
        return {'transaction_hash': "00" * 32, 'fake_update': True} 
    """

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


def get_default_proxy(config_path=config.CONFIG_PATH):
    """
    Get the default API proxy to blockstack.
    """
    global default_proxy
    if default_proxy is None:
        # load     
        conf = config.get_config()
        blockstack_server = conf['server']
        blockstack_port = conf['port']

        proxy = session(conf=conf, server_host=blockstack_server,
                        server_port=blockstack_port)

        return proxy

    else:
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


def load_name_zonefile(expected_zonefile_hash):
    """
    Fetch and load a user zonefile from the storage implementation with the given hex string hash,
    The user zonefile hash should have been loaded from the blockchain, and thereby be the
    authentic hash.

    Return the user zonefile on success
    Return None on error
    """

    zonefile_txt = storage.get_immutable_data(expected_zonefile_hash, hash_func=storage.get_user_zonefile_hash, deserialize=False)
    if zonefile_txt is None:
        log.error("Failed to load user zonefile '%s'" % expected_zonefile_hash)
        return None

    try:
        # by default, it's a zonefile-formatted text file
        user_zonefile = zone_file.parse_zone_file( zonefile_txt )
        assert user_db.is_user_zonefile( user_zonefile ), "Not a user zonefile: %s" % user_zonefile
    except (IndexError, ValueError, zone_file.InvalidLineException):
        # might be legacy profile
        log.debug("WARN: failed to parse user zonefile; trying to import as legacy")
        try:
            user_zonefile = json.loads(zonefile_txt)
        except Exception, e:
            log.exception(e)
            log.error("Failed to parse:\n%s" % zonefile_txt)
            return None
        
    except Exception, e:
        log.exception(e)
        log.error("Failed to parse:\n%s" % zonefile_txt)
        return None 

    return user_zonefile


def load_legacy_user_profile( name, expected_hash ):
    """
    Load a legacy user profile, and convert it into
    the new zonefile-esque profile format that can 
    be serialized into a JWT.

    Verify that the profile hashses to the above expected hash
    """

    # fetch... 
    storage_host = "onename.com"
    assert name.endswith(".id")

    name_without_namespace = ".".join( name.split(".")[:-1] )
    storage_path = "/%s.json" % name_without_namespace 

    try:
        req = httplib.HTTPConnection( storage_host )
        resp = req.request( "GET", storage_path )
        data = resp.read()
    except Exception, e:
        log.error("Failed to fetch http://%s/%s: %s" % (storage_host, storage_path, e))
        return None 

    try:
        data_json = json.loads(data)
    except Exception, e:
        log.error("Unparseable profile data")
        return None

    data_hash = registrar.utils.get_hash( data_json )
    if expected_hash != data_hash:
        log.error("Hash mismatch: expected %s, got %s" % (expected_hash, data_hash))
        return None

    assert blockstack_profiles.is_profile_in_legacy_format( data_json )
    new_profile = blockstack_profiles.get_person_from_legacy_format( data_json )
    return new_profile
    

def load_name_profile(name, user_zonefile, public_key):
    """
    Fetch and load a user profile, given the user zonefile.

    Return the user profile on success
    Return None on error
    """
    
    urls = user_db.user_zonefile_urls( user_zonefile )
    user_profile = storage.get_mutable_data( name, public_key, urls=urls )
    return user_profile
    

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


'''
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

    # get blockchain-obtained data
    blockchain_result = get_name_blockchain_record(name, proxy=proxy)
    if blockchain_result is None:
        return {'error': 'No profile zonefile'}

    if 'error' in blockchain_result:
        return blockchain_result

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

    # get zonefile data
    zone_file = get_name_zonefile(name, proxy=proxy, value_hash=blockchain_result['value_hash'])
    if zone_file is None:
        return {'error': 'No zonefile found'}

    if 'error' in zone_file:
        return zone_file

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
'''

def make_wallet_keys( data_privkey=None, owner_privkey=None ):
    """
    For testing.  DO NOT USE
    """

    pk_data = pybitcoin.BitcoinPrivateKey( data_privkey ).to_hex()
    pk_owner = pybitcoin.BitcoinPrivateKey( owner_privkey ).to_hex()

    return {
        'data_privkey': pk_data,
        'owner_privkey': pk_owner
    }


def get_data_keypair( wallet_keys=None ):
    """
    Get the user's data keypair
    """
    wallet = None
    if wallet_keys is not None:
        assert wallet_keys.has_key('data_privkey') and wallet_keys['data_privkey'] is not None, "No data private key set"
        wallet = wallet_keys

    else:
        wallet = get_wallet()
        assert wallet is not None

    data_privkey = wallet['data_privkey']
    public_key = pybitcoin.BitcoinPrivateKey(data_privkey).public_key().to_hex()
    return public_key, data_privkey


def get_owner_keypair( wallet_keys=None ):
    """
    Get the user's owner keypair
    """
    wallet = None
    if wallet_keys is not None:
        assert wallet_keys.has_key('owner_privkey') and wallet_keys['owner_privkey'] is not None, "No owner private key set"
        wallet = wallet_keys

    else:
        wallet = get_wallet()
        assert wallet is not None 

    owner_privkey = wallet['owner_privkey']
    public_key = pybitcoin.BitcoinPrivateKey(owner_privkey).public_key().to_hex()
    return public_key, owner_privkey


def get_name_zonefile( name, create_if_absent=False, proxy=None, value_hash=None, wallet_keys=None ):
    """
    Given the name of the user, go fetch its zonefile.

    Returns a dict with the zonefile, or 
    a dict with "error" defined and a message.
    Return None if there is no zonefile (i.e. the hash is null)
    """
    if proxy is None:
        proxy = get_default_proxy()

    if value_hash is None:
        # find name record first
        name_record = get_name_blockchain_record(name, proxy=proxy)

        if name_record is None:
            # failed to look up
            return {'error': "No such name"}

        if len(name_record) == 0:
            return {"error": "No such name"}

        # sanity check
        if 'value_hash' not in name_record:
            return {"error": "Name has no user record hash defined"}

        value_hash = name_record['value_hash']

    # is there a user record loaded?
    if value_hash in [None, "null", ""]:

        # no user data
        if not create_if_absent:
            return None

        else:
            # make an empty zonefile and return that
            # get user's data public key 
            public_key, _ = get_data_keypair(wallet_keys=wallet_keys)
            user_resp = user_db.make_empty_user_zonefile(name, public_key)
            return user_resp

    user_zonefile_hash = value_hash
    user_zonefile = load_name_zonefile(user_zonefile_hash)
    if user_zonefile is None:
        return {"error": "Failed to load zonefile"}

    return user_zonefile
    

def get_name_profile(name, create_if_absent=False, proxy=None, wallet_keys=None, user_zonefile=None):
    """
    Given the name of the user, look up the user's record hash,
    and then get the record itself from storage.

    If the user's zonefile is really a legacy profile, then 
    the profile will be the converted legacy profile.  The
    returned zonefile will still be a legacy profile, however.
    The caller can check this and perform the conversion automatically.

    Returns (profile, zonefile) on success.
    Returns (None, {'error': ...}) on failure
    """

    if proxy is None:
        proxy = get_default_proxy()
 
    if user_zonefile is None:
        user_zonefile = get_name_zonefile( name, create_if_absent=create_if_absent, proxy=proxy, wallet_keys=wallet_keys )
        if user_zonefile is None:
            return (None, {'error': 'No user zonefile'})

        if 'error' in user_zonefile:
            return (None, user_zonefile)

    # is this really a legacy profile?
    if blockstack_profiles.is_profile_in_legacy_format( user_zonefile ):
        # convert it 
        user_profile = blockstack_profiles.get_person_from_legacy_format( user_zonefile )
       
    else:
        # get user's data public key 
        user_data_pubkey = user_db.user_zonefile_data_pubkey( user_zonefile )
        if user_data_pubkey is None:
            return (None, {'error': 'No data public key found in user profile.'})

        user_profile = load_name_profile( name, user_zonefile, user_data_pubkey )
        if user_profile is None or 'error' in user_profile:
            if create_if_absent:
                user_profile = user_db.make_empty_user_profile()
            else:
                return (None, {'error': 'Failed to load user profile'})

    return (user_profile, user_zonefile)


def store_name_zonefile( name, user_zonefile, txid ):
    """
    Store JSON user zonefile data to the immutable storage providers, synchronously.
    This is only necessary if we've added/changed/removed immutable data.

    Return (True, hash(user)) on success
    Return (False, None) on failure
    """

    assert not blockstack_profiles.is_profile_in_legacy_format(user_zonefile), "User zonefile is a legacy profile"

    # make sure our data pubkey is there 
    user_data_pubkey = user_db.user_zonefile_data_pubkey( user_zonefile )
    assert user_data_pubkey is not None, "BUG: user zonefile is missing data public key"

    # serialize and send off
    user_zonefile_txt = zone_file.make_zone_file( user_zonefile, origin=name, ttl=USER_ZONEFILE_TTL )
    data_hash = storage.get_user_zonefile_hash( user_zonefile_txt )
    result = storage.put_immutable_data(None, txid, data_hash=data_hash, data_text=user_zonefile_txt )

    rc = None
    if result is None:
        rc = False
    else:
        rc = True

    return (rc, data_hash)


def store_name_profile(username, user_profile, wallet_keys=None):
    """
    Store JSON user profile data to the mutable storage providers, synchronously.

    The wallet must be initialized before calling this.

    Return True on success
    Return False on error
    """

    _, data_privkey = get_data_keypair(wallet_keys=wallet_keys)
    rc = storage.put_mutable_data( username, user_profile, data_privkey )
    return rc


def remove_name_zonefile(user, txid):
    """
    Delete JSON user zonefile data from immutable storage providers, synchronously.

    Return (True, hash(user)) on success
    Return (False, hash(user)) on error
    """

    # serialize
    user_json = json.dumps(user, sort_keys=True)
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


def update(name, user_zonefile_json_or_hash, privatekey, txid=None, proxy=None, tx_only=False, public_key=None, subsidy_key=None):
    """
    Low-level update.

    Update a name record.  Send a new transaction that attaches the given zonefile JSON (or a hash of it) to the name.

    Optionally supply a txid.  The reason for doing so is to try to replicate user
    data to new storage systems, or to recover from a transient error encountered
    earlier.
    """

    # sanity check
    if privatekey is None and public_key is None:
        return {'error': 'Missing public and private key'}

    if proxy is None:
        proxy = get_default_proxy()

    user_zonefile_hash = None
    user_zonefile = None

    # 160-bit hex string?
    if len(user_zonefile_json_or_hash) == 40 and len(user_zonefile_json_or_hash.translate(None, "0123456789ABCDEFabcdef")) == 0:

        user_zonefile_hash = user_zonefile_json_or_hash.lower()
    else:
        
        # user zonefile. verify that it's wellformed
        try:
            if type(user_zonefile_json_or_hash) in [str, unicode]:
                user_zonefile = json.loads(user_zonefile_json_or_hash)
            else:
                user_zonefile = copy.deepcopy(user_zonefile_json_or_hash)

            assert user_db.is_user_zonefile( user_zonefile )
        except Exception, e:
            log.exception(e)
            return {'error': 'User profile is unparseable JSON or unparseable hash'}

        user_zonefile_txt = zone_file.make_zone_file( user_zonefile, origin=name, ttl=USER_ZONEFILE_TTL )
        user_zonefile_hash = storage.get_user_zonefile_hash( user_zonefile_txt )

    # must be blockchain data for this user
    blockchain_result = get_name_blockchain_record( name, proxy=proxy )
    if blockchain_result is None:
        return {'error': 'No such user'}
    
    if 'error' in blockchain_result:
        return blockchain_result

    if tx_only:

        result = None

        # only want a transaction 
        if privatekey is None and public_key is not None and subsidy_key is not None:
            result = proxy.update_tx_subsidized( name, user_profile_hash, public_key, subsidy_key )

        if privatekey is not None:
            result = proxy.update_tx( name, user_zonefile_hash, privatekey )

        if result is not None:
            return result[0]

    if txid is None:

        # send a new transaction 
        result = proxy.update( name, user_zonefile_hash, privatekey )
        if result is not None:
            result = result[0]
        else:
            return {'error': 'No response from server'}
        
        if 'error' in result:
            return result

        if 'transaction_hash' not in result:
            # failed
            result['error'] = 'No transaction hash returned'
            return result

        txid = result['transaction_hash']

    else:
        # embed the txid into the result nevertheless
        result['transaction_hash'] = txid 

    # store the zonefile, if given
    if user_zonefile is not None:
        rc, new_hash = store_name_zonefile( name, user_zonefile, txid )
        if not rc:
            result['error'] = 'Failed to store user zonefile'
            return result

    # success!
    result['status'] = True
    result['value_hash'] = user_zonefile_hash
    return result


def update_subsidized(name, user_zonefile_json_or_hash, public_key, subsidy_key, txid=None):
    """
    update_subsidized
    """
    return update(name, user_zonefile_json_or_hash, None, txid=txid, public_key=public_key, subsidy_key=subsidy_key, tx_only=True)


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


def serialize_mutable_data_id( data_id ):
    """
    Turn a data ID into a suitable filesystem name
    """
    return urllib.quote(data_id.replace("\0", "\\0")).replace("/", r"\x2f")


def load_mutable_data_version(conf, name, data_id):
    """
    Get the version field of a piece of mutable data from local cache.
    """

    # try to get the current, locally-cached version
    if conf is None:
        conf = config.get_config()

    metadata_dir = None
    if conf is not None:

        metadata_dir = conf.get('metadata', None)
        if metadata_dir is not None and os.path.isdir(metadata_dir):

            # find the version file for this data
            serialized_data_id = serialize_mutable_data_id( data_id )
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
                    return None

                except Exception, e:
                    # can't read
                    log.warn("Failed to read '%s': %s" % (version_file_path))
                    return None

            else:
                log.debug("No version path found")
                return None

    else:
        log.debug("No config found; cannot load version for '%s'" % data_id)
        return None



def store_mutable_data_version(conf, fq_data_id, ver):
    """
    Locally store the version of a piece of mutable data,
    so we can ensure that its version is incremented on
    subsequent puts.

    Return True if stored
    Return False if not
    """

    assert storage.is_fq_data_id( fq_data_id ) or storage.is_valid_name( fq_data_id ), "data ID must be a Blockstack DNS name or a fully-qualified data ID"

    if conf is None:
        conf = config.get_config()

    if conf is None:
        log.warning("No config found; cannot store version for '%s'" % fq_data_id)
        return False

    assert 'metadata' in conf, "Missing metadata directory"
    metadata_dir = conf['metadata']
    if not os.path.isdir(metadata_dir):
        log.warning("No metadata directory found; cannot store version of '%s'" % fq_data_id)
        return False

    serialized_data_id = serialize_mutable_data_id( fq_data_id )
    version_file_path = os.path.join(metadata_dir, serialized_data_id + ".ver")

    try:
        with open(version_file_path, "w+") as f:
            f.write("%s" % ver)

        return True

    except Exception, e:
        # failed for whatever reason
        log.exception(e)
        log.warn("Failed to store version of '%s' to '%s'" % (fq_data_id, version_file_path))
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


def get_and_migrate_profile( name, proxy=None, create_if_absent=False, wallet_keys=None ):
    """
    Get a name's profile and zonefile, optionally creating a new one along the way.  Migrate the profile to a new zonefile,
    if the profile is in legacy format.

    Return (user_profile, user_zonefile, migrated:bool) on success
    Return ({'error': ...}, None, False) on error
    """

    created_new_zonefile = False
    user_zonefile = get_name_zonefile( name, proxy=proxy, wallet_keys=wallet_keys )
    if user_zonefile is None: 
        if not create_if_absent:
            return ({'error': 'No such zonefile'}, None, False)

        log.debug("Creating new profile and zonefile for name '%s'" % name)
        data_pubkey, _ = get_data_keypair( wallet_keys=wallet_keys )
        user_profile = user_db.make_empty_user_profile()
        user_zonefile = user_db.make_empty_user_zonefile( name, data_pubkey )

        created_new_zonefile = True
    
    elif blockstack_profiles.is_profile_in_legacy_format( user_zonefile ):
        log.debug("Migrating legacy profile to modern zonefile for name '%s'" % name)
        data_pubkey, _ = get_data_keypair( wallet_keys=wallet_keys )
        user_profile = blockstack_profiles.get_person_from_legacy_format( user_zonefile )
        user_zonefile = user_db.make_empty_user_zonefile( name, data_pubkey )

        created_new_zonefile = True

    else:
        user_profile, error_msg = get_name_profile( name, proxy=proxy, wallet_keys=wallet_keys, user_zonefile=user_zonefile )
        if user_profile is None:
            return (error_msg, None, False)

    return (user_profile, user_zonefile, created_new_zonefile)


def get_immutable(name, data_key, data_id=None, proxy=None):
    """
    get_immutable

    Fetch a piece of immutable data.  Use @data_key to look it up
    in the user's zonefile, and then fetch and verify the data itself
    from the configured storage providers.

    Return {'data': the data, 'hash': hash} on success
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy()

    user_zonefile = get_name_zonefile(name, proxy=proxy)
    if user_zonefile is None:
        return {'error': 'No user zonefile defined'}

    if 'error' in user_zonefile:
        return user_zonefile 

    if blockstack_profiles.is_profile_in_legacy_format( user_zonefile ):
        # zonefile is really a legacy profile 
        return {'error': 'Profile is in a legacy format that does not support immutable data.'}

    if data_id is not None:
        # look up hash by name 
        h = user_db.get_immutable_data_hash( user_zonefile, data_id )
        if h is None:
            return {'error': 'No such immutable datum'}
         
        if type(h) == list:
            # this tool doesn't allow this to happen (one ID matches one hash),
            # but that doesn't preclude the user from doing this with other tools.
            if data_key is not None and data_key not in h:
                return {'error': 'Data ID/hash mismatch'}

            else:
                return {'error': "Multiple matches for '%s': %s" % (data_id, ",".join(h))}

        if data_key is not None:
            if h != data_key:
                return {'error': 'Data ID/hash mismatch'}

        else:
            data_key = h

    elif not user_db.has_immutable_data( user_zonefile, data_key ):
        return {'error': 'No such immutable datum'}

    data = storage.get_immutable_data( data_key )
    if data is None:
        return {'error': 'No immutable data returned'}

    return {'data': data, 'hash': data_key}


def get_immutable_by_name( name, data_id, proxy=None ):
    """
    get_immutable_by_name

    Fetch a piece of immutable data, using a human-meaningful name.
    Look up the hash in the user's zonefile, and use it to fetch
    and verify the immutable data from the configured storage providers.

    Return {'data': the data, 'hash': hash} on success
    Return {'error': ...} on failure
    """
    return get_immutable( name, None, data_id=data_id, proxy=proxy )


def list_update_history( name, current_block=None, proxy=None ):
    """
    list_update_history

    List all prior zonefile hashes of a name, in historic order.
    Return a list of hashes on success.
    Return None on error
    """

    if proxy is None:
        proxy = get_default_proxy()

    if current_block is None:
        info = proxy.getinfo()
        info = info[0]
        current_block = info['last_block']+1

    name_history = proxy.get_name_blockchain_history( name, 0, current_block )
    name_history = name_history[0]
    all_update_hashes = []

    for state in name_history:
        if state.has_key('value_hash') and state['value_hash'] is not None:
            if len(all_update_hashes) == 0 or all_update_hashes[-1] != state['value_hash']:
                # changed
                all_update_hashes.append( state['value_hash'] )

    return all_update_hashes


def list_zonefile_history( name, current_block=None, proxy=None ):
    """
    list_zonefile_history

    List all prior zonefiles of a name, in historic order.
    Return the list of zonefiles.  Each zonefile will be a dict with either the zonefile data,
    or a dict with only the key 'error' defined.  This method can successfully return
    some but not all zonefiles.
    """
    zonefile_hashes = list_update_history( name, current_block=current_block, proxy=proxy )
    zonefiles = []
    for zh in zonefile_hashes:
        zonefile = load_name_zonefile( zh )
        if zonefile is None:
            zonefile = {'error': 'Failed to load zonefile %s' % zh}

        zonefiles.append( zonefile )

    return zonefiles
       

def list_immutable_data_history( name, data_id, current_block=None, proxy=None ):
    """
    list_immutable_data_history

    List all prior hashes of an immutable datum, given its unchanging ID.
    If the zonefile at a particular update is missing, the string "missing zonefile" will be
    appended in its place.  If the zonefile did not define data_id at that time,
    the string "data not defined" will be placed in the hash's place.

    Returns the list of hashes.
    If there are multiple matches for the data ID in a zonefile, then return the list of hashes for that zonefile.
    """
    zonefiles = list_zonefile_history( name, current_block=current_block, proxy=proxy )
    hashes = []
    for zf in zonefiles:
        if 'error' in zf and len(zf.keys()) == 1:
            # invalid
            hashes.append("missing zonefile")
            continue
       
        if not user_db.is_user_zonefile(zf):
            # legacy profile 
            hashes.append("missing zonefile")
            continue 

        data_hash_or_hashes = user_db.get_immutable_data_hash( zf, data_id )
        if data_hash_or_hashes is None:
            hashes.append("data not defined")
            continue
       
        else:
            hashes.append(data_hash_or_hashes)

    return hashes


def get_mutable(name, data_id, proxy=None, ver_min=None, ver_max=None, ver_check=None, conf=None, wallet_keys=None):
    """
    get_mutable

    Fetch a piece of mutable data.  Use @data_id to look it up in the user's
    pofile, and then fetch and erify the data itself from the configured 
    storage providers.

    If @ver_min is given, ensure the data's version is greater or equal to it.
    If @ver_max is given, ensure the data's version is less than it.
    If @ver_check is given, it must be a callable that takes the name, data and version and returns True/False

    Return {'data': the data, 'version': the version} on success
    Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy()

    if conf is None:
        conf = proxy.conf

    fq_data_id = storage.make_fq_data_id( name, data_id )
    user_profile, user_zonefile = get_name_profile( name, proxy=proxy, wallet_keys=wallet_keys )
    if user_profile is None:
        return user_zonefile    # will be an error message
   
    if blockstack_profiles.is_profile_in_legacy_format( user_zonefile ):
        # profile has not been converted to the new zonefile format yet.
        return {'error': 'Profile is in a legacy format that does not support mutable data.'}

    # get the mutable data zonefile
    if not user_db.has_mutable_data( user_profile, data_id ):
        return {'error': "No such mutable datum"}

    mutable_data_zonefile = user_db.get_mutable_data_zonefile( user_profile, data_id )
    assert mutable_data_zonefile is not None, "BUG: could not look up mutable datum '%s'.'%s'" % (name, data_id)

    # get user's data public key 
    data_pubkey = user_db.user_zonefile_data_pubkey( user_zonefile )
    if data_pubkey is None:
        return {'error': "No data public key defined in this user's zonefile"}

    # get the mutable data itself
    urls = user_db.mutable_data_zonefile_urls( mutable_data_zonefile )
    mutable_data = storage.get_mutable_data(fq_data_id, data_pubkey, urls=urls )
    if mutable_data is None:
        return {'error': "Failed to look up mutable datum"}

    expected_version = load_mutable_data_version( conf, name, data_id )
    if expected_version is None:
        expected_version = 0

    # check consistency
    version = user_db.mutable_data_version( user_profile, data_id )
    if ver_min is not None and ver_min > version:
        return {'error': 'Mutable data is stale'}

    if ver_max is not None and ver_max <= version:
        return {'error': 'Mutable data is in the future'}

    if ver_check is not None:
        rc = ver_check( name, mutable_data, version )
        if not rc:
            return {'error': 'Mutable data consistency check failed'}

    elif expected_version > version:
        return {'error': 'Mutable data is stale; a later version was previously fetched'}

    rc = store_mutable_data_version( conf, fq_data_id, version )
    if not rc:
        return {'error': 'Failed to store consistency information'}

    return {'data': mutable_data, 'version': version}
 

def migrate_profile( name, txid=None, proxy=None, wallet_keys=None ):
    """
    Migrate a user's profile from the legacy format to the profile/zonefile format.
    Return {'status': True, 'transaction_hash': txid, 'zonefile_hash': ...} on success, if the profile was migrated
    Return {'status': True} on success, if the profile is already migrated
    Return {'error': ...} on error
    """
    legacy = False
    txid = None 
    value_hash = None
    if proxy is None:
        proxy = get_default_proxy()

    user_profile, user_zonefile, legacy = get_and_migrate_profile( name, create_if_absent=True, proxy=proxy, wallet_keys=wallet_keys )
    if 'error' in user_profile:
        log.debug("Unable to load user zonefile for '%s'" % name)
        return user_profile

    if not legacy:
        return {'status': True}

    # store profile...
    _, data_privkey = get_data_keypair( wallet_keys=wallet_keys )
    rc = storage.put_mutable_data( name, user_profile, data_privkey )
    if not rc:
        return {'error': 'Failed to move legacy profile to profile zonefile'}

    # store zonefile, if we haven't already
    if txid is None:
        _, owner_privkey = get_owner_keypair(wallet_keys=wallet_keys)
        update_result = update( name, user_zonefile, owner_privkey, proxy=proxy )
        if 'error' in update_result:
            # failed to replicate user zonefile hash 
            # the caller should simply try again, with the 'transaction_hash' given in the result.
            return update_result

        txid = update_result['transaction_hash']
        value_hash = update_result['value_hash']

    result = {
        'status': True
    }
    if txid is not None:
        result['transaction_hash'] = txid
    if value_hash is not None:
        result['zonefile_hash'] = value_hash

    return result


def put_immutable(name, data_id, data_json, txid=None, proxy=None, wallet_keys=None ):
    """
    put_immutable

    Given a user's name, the data ID, and a JSON-ified chunk of data,
    put it into the user's zonefile.

    If the user's zonefile corresponds to a legacy profile, then automatically
    convert it into a mutable profile and a modern zonefile, and then proceed
    to add the data record.

    If @txid is given, then don't re-send the NAME_UPDATE.  Just try to store
    the data to the immutable storage providers (again).  This is to allow
    for retries in the case where the NAME_UPDATE went through but the
    storage providers did not receive data.
    
    Return {'status': True, 'transaction_hash': txid, 'immutable_data_hash': data_hash, ...} on success
    Return {'error': ...} on error
    """

    if type(data_json) not in [dict]:
        raise ValueError("Immutable data must be a dict")

    legacy = False
    if proxy is None:
        proxy = get_default_proxy()

    user_profile, user_zonefile, legacy = get_and_migrate_profile( name, create_if_absent=True, proxy=proxy, wallet_keys=wallet_keys )
    if 'error' in user_profile:
        log.debug("Unable to load user zonefile for '%s'" % name)
        return user_profile
   
    if legacy:
        log.debug("User profile is legacy")
        return {'error': "User profile is in legacy format, which does not support this operation.  You must first migrate it with the 'migrate' command."}

    data_text = storage.serialize_immutable_data( data_json )
    data_hash = storage.get_data_hash( data_text )
    value_hash = None

    # insert into user zonefile, overwriting if need be
    if user_db.has_immutable_data_id( user_zonefile, data_id ):
        log.debug("WARN: overwriting old '%s'" % data_id)
        old_hash = user_db.get_immutable_data_hash( user_zonefile, data_id )

        # NOTE: can be a list, if the name matches multiple hashes.
        # this tool doesn't do this, but it's still possible for the user to use other tools to do this.
        if type(old_hash) != list:
            old_hash = [old_hash]

        for oh in old_hash:
            rc = user_db.remove_immutable_data_zonefile( user_zonefile, oh )
            if not rc:
                return {'error': 'Failed to overwrite old immutable data'}

    rc = user_db.put_immutable_data_zonefile( user_zonefile, data_id, data_hash )
    if not rc:
        return {'error': 'Failed to insert immutable data into user zonefile'}

    # update zonefile, if we haven't already
    if txid is None:
        _, owner_privkey = get_owner_keypair(wallet_keys=wallet_keys)
        update_result = update( name, user_zonefile, owner_privkey, proxy=proxy )
        if 'error' in update_result:
            # failed to replicate user zonefile hash 
            # the caller should simply try again, with the 'transaction_hash' given in the result.
            return update_result

        txid = update_result['transaction_hash']
        value_hash = update_result['value_hash']

    result = {
        'immutable_data_hash': data_hash,
        'transaction_hash': txid
    }

    if value_hash is not None:
       result['zonefile_hash'] = value_hash 

    # replicate immutable data 
    rc = storage.put_immutable_data( data_json, txid )
    if not rc:
        result['error'] = 'Failed to store immutable data'
        return result

    # success!
    result['status'] = True
    return result


def put_mutable_get_version( user_profile, data_id, data_json, make_version=None ):
    """
    Given the user profile, data_id, desired version, and callback to create a version,
    find out what the next version of the mutable datum should be.
    """
    version = None
    mutable_version = user_db.mutable_data_version( user_profile, data_id )
    if make_version is not None:
        version = make_version( data_id, data_json, mutable_version )

    else:
        if mutable_version is not None:
            version = mutable_version + 1
        else:
            version = 1

    return version


def put_mutable(name, data_id, data_json, proxy=None, create_only=False, update_only=False, 
                txid=None, version=None, make_version=None, wallet_keys=None):
    """
    put_mutable

    Given a name, an ID for the data, and the data itself, sign and upload the data to the
    configured storage providers.  Add an entry for it into the user's profile as well.

    ** Consistency **

    @version, if given, is the version to include in the data.
    @make_version, if given, is a callback that takes the data_id, data_json, and current version as arguments, and generates the version to be included in the data record uploaded.
    If ver is not given, but make_ver is, then make_ver will be used to generate the version.
    If neither ver nor make_ver are given, the mutable data (if it already exists) is fetched, and the version is calculated as the larget known version + 1.

    ** Durability **

    Replication is best-effort.  If one storage provider driver succeeds, the put_mutable succeeds.  If they all fail, then put_mutable fails.
    More complex behavior can be had by creating a "meta-driver" that calls existing drivers' methods in the desired manner.

    Returns a dict with {'status': True, 'version': version, ...} on success
    Returns a dict with 'error' set on failure
    """

    if type(data_json) not in [dict]:
        raise ValueError("Mutable data must be a dict")

    if proxy is None:
        proxy = get_default_proxy()

    fq_data_id = storage.make_fq_data_id( name, data_id )

    user_profile, user_zonefile, created_new_zonefile = get_and_migrate_profile( name, create_if_absent=True, proxy=proxy, wallet_keys=wallet_keys )
    if 'error' in user_profile:
        return user_profile 

    if created_new_zonefile:
        log.debug("User profile is legacy")
        return {'error': "User profile is in legacy format, which does not support this operation.  You must first migrate it with the 'migrate' command."}

    exists = user_db.has_mutable_data( user_profile, data_id )
    if not exists and update_only:
        return {'error': 'Mutable datum does not exist'}

    if exists and create_only:
        return {'error': 'Mutable datum already exists'}
    
    # get the version to use
    if version is None:
        version = put_mutable_get_version( user_profile, data_id, data_json, make_version=make_version )

    # generate the mutable zonefile
    _, data_privkey = get_data_keypair( wallet_keys=wallet_keys )
    urls = storage.make_mutable_data_urls( fq_data_id )
    mutable_zonefile = user_db.make_mutable_data_zonefile( data_id, version, urls )

    # add the mutable zonefile to the profile
    rc = user_db.put_mutable_data_zonefile( user_profile, data_id, version, mutable_zonefile )
    assert rc, "Failed to put mutable data zonefile"

    # for legacy migration...
    txid = None 
    zonefile_hash = None
    result = {}
 
    # update the profile with the new zonefile
    rc = storage.put_mutable_data( name, user_profile, data_privkey )
    if not rc:
        result['error'] = 'Failed to store mutable data zonefile to profile'
        return result

    # put the mutable data record itself
    rc = storage.put_mutable_data( fq_data_id, data_json, data_privkey )
    if not rc:
        result['error'] = "Failed to store mutable data"
        return result

    # remember which version this was 
    rc = store_mutable_data_version(proxy.conf, fq_data_id, version)
    if not rc:
        result['error'] = "Failed to store mutable data version"
        return result

    result['status'] = True
    result['version'] = version
    return result


def delete_immutable(name, data_key, data_id=None, proxy=None, txid=None, wallet_keys=None):
    """
    delete_immutable

    Remove an immutable datum from a name's profile, given by @data_key.
    Return a dict with {'status': True} on success
    Return a dict with {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy()

    legacy = False
    user_zonefile = get_name_zonefile( name, proxy=proxy )
    if user_zonefile is None or 'error' in user_zonefile:
        if user_zonefile is None:
            return {'error': 'No user zonefile'}
        else:
            return user_zonefile

    if blockstack_profiles.is_profile_in_legacy_format( user_zonefile ):
        # zonefile is a legacy profile.  There is no immutable data 
        log.info("Profile is in legacy format.  No immutable data.")
        return {'status': True}

    if data_key is None:
        if data_id is not None:
            # look up the key (or list of keys)
            # shouldn't be a list--this tool prevents that--but deal with it nevertheless
            data_key = user_db.get_immutable_data_hash( user_zonefile, data_id )
            if type(data_key) == list:
                return {'error': "Multiple hashes for '%s': %s" % (data_id, ",".join(data_key)) }

            if data_key is None:
                return {'error': "No hash for '%s'" % data_id}

        else:
            return {'error': 'No data hash or data ID given'}

    # already deleted?
    if not user_db.has_immutable_data( user_zonefile, data_key ):
        return {'status': True}

    # remove 
    user_db.remove_immutable_data_zonefile( user_zonefile, data_key )
    value_hash = None
    
    if txid is None:
        # actually send the transaction
        _, owner_privkey = get_owner_keypair(wallet_keys=wallet_keys)
        update_result = update( name, user_zonefile, owner_privkey, proxy=proxy )
        if 'error' in update_result:
            # failed to remove from zonefile 
            return update_result 

        txid = update_result['transaction_hash']
        value_hash = update_result['value_hash']

    result = {
        'zonefile_hash': value_hash,
        'transaction_hash': txid
    }

    # delete immutable data 
    _, data_privkey = get_data_keypair( wallet_keys=wallet_keys )
    rc = storage.delete_immutable_data( data_key, txid, data_privkey )
    if not rc:
        result['error'] = 'Failed to delete immutable data'
        return result

    else:
        result['status'] = True
        return result


def delete_mutable(name, data_id, proxy=None, wallet_keys=None):
    """
    delete_mutable

    Remove a piece of mutable data from the user's profile. Delete it from
    the storage providers as well.

    Returns a dict with {'status': True} on success
    Returns a dict with {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy()
 
    fq_data_id = storage.make_fq_data_id( name, data_id )
    legacy = False
    user_profile, user_zonefile = get_name_profile( name, proxy=proxy, wallet_keys=wallet_keys )
    if user_profile is None:
        return user_zonefile    # will be an error message 

    if blockstack_profiles.is_profile_in_legacy_format( user_zonefile ):
        # zonefile is a legacy profile.  There is no immutable data 
        log.info("Profile is in legacy format.  No immutable data.")
        return {'status': True}

    # already deleted?
    if not user_db.has_mutable_data( user_profile, data_id ):
        return {'status': True}

    # unlink
    user_db.remove_mutable_data_zonefile( user_profile, data_id )

    # put new profile 
    _, data_privkey = get_data_keypair( wallet_keys=wallet_keys )
    rc = storage.put_mutable_data( name, user_profile, data_privkey )
    if not rc:
        return {'error': 'Failed to unlink mutable data from profile'}

    # remove the data itself 
    rc = storage.delete_mutable_data( fq_data_id, data_privkey )
    if not rc:
        return {'error': 'Failed to delete mutable data from storage providers'}

    return {'status': True}


def list_immutable_data( name, proxy=None ):
    """
    List the names and hashes of all immutable data in a user's zonefile.
    Returns {"data": [{"data_id": data_id, "hash": hash}]} on success
    """
    if proxy is None:
        proxy = get_default_proxy()

    user_zonefile = get_name_zonefile(name, proxy=proxy)
    if user_zonefile is None:
        return {'error': 'No user zonefile defined'}

    if 'error' in user_zonefile:
        return user_zonefile 

    if blockstack_profiles.is_profile_in_legacy_format( user_zonefile ):
        # zonefile is really a legacy profile
        return {"data": []}

    names_and_hashes = user_db.list_immutable_data( user_zonefile )
    listing = [ {"data_id": nh[0], "hash": nh[1]} for nh in names_and_hashes ]
    return {"data": listing}


def list_mutable_data( name, proxy=None, wallet_keys=None ):
    """
    List the names and versions of all mutable data in a user's zonefile
    Returns {"data": [{"data_id": data ID, "version": version}]}
    """
    if proxy is None:
        proxy = get_default_proxy()

    user_profile, user_zonefile = get_name_profile( name, proxy=proxy, wallet_keys=wallet_keys )
    if user_zonefile is None:
        # user_profile will contain an error message
        return user_profile 

    if blockstack_profiles.is_profile_in_legacy_format( user_zonefile ):
        # zonefile is really a legacy profile
        return {"data": []}

    names_and_versions = user_db.list_mutable_data( user_profile )
    listing = [ {"data_id": nv[0], "version": nv[1]} for nv in names_and_versions ]
    return {"data": listing}


def blockstack_url_fetch( url, proxy=None, wallet_keys=None ):
    """
    Given a blockstack:// url, fetch its data.
    If the data is an immutable data url, and the hash is not given, then look up the hash first.
    If the data is a mutable data url, and the version is not given, then look up the version as well.

    Return {"data": data} on success
    Return {"error": error message} on error
    """
    mutable = False
    immutable = False
    blockchain_id = None
    data_id = None
    version = None
    data_hash = None

    try:
        blockchain_id, data_id, version = storage.blockstack_mutable_data_url_parse( url )
        mutable = True
    except ValueError:
        blockchain_id, data_id, data_hash = storage.blockstack_immutable_data_url_parse( url )
        immutable = True

    if mutable:
        if data_id is not None:
            # get single data
            if version is not None:
                return get_mutable( blockchain_id, data_id, proxy=proxy, wallet_keys=wallet_keys, ver_min=version, ver_max=version+1 )
            else:
                return get_mutable( blockchain_id, data_id, proxy=proxy, wallet_keys=wallet_keys )

        else:
            # list data 
            return list_mutable_data( blockchain_id, proxy=proxy, wallet_keys=wallet_keys )

    else:
        if data_id is not None:
            # get single data
            if data_hash is not None:
                return get_immutable( blockchain_id, data_hash, data_id=data_id, proxy=proxy )

            else:
                return get_immutable_by_name( blockchain_id, data_id, proxy=proxy )

        else:
            # list data
            return list_immutable_data( blockchain_id, proxy=proxy )


def data_get( blockstack_url, proxy=None, wallet_keys=None, **kw ):
    """
    Resolve a blockstack URL to data (be it mutable or immutable).
    """
    return blockstack_url_fetch( blockstack_url, proxy=proxy, wallet_keys=wallet_keys )


def data_put( blockstack_url, data, proxy=None, wallet_keys=None, **kw ):
    """
    Put data to a blockstack URL (be it mutable or immutable).
    """
    parts = storage.blockstack_data_url_parse( blockstack_url )
    if parts['type'] == 'immutable':
        return put_immutable( parts['blockchain_id'], parts['data_id'], data, proxy=proxy, wallet_keys=wallet_keys, **kw ) 
    else:
        return put_mutable( parts['blockchain_id'], parts['data_id'], data, proxy=proxy, wallet_keys=wallet_keys, **kw ) 


def data_delete( blockstack_url, proxy=None, wallet_keys=None, **kw ):
    """
    Delete data from a blockstack URL (be it mutable or immutable).
    """
    parts = storage.blockstack_data_url_parse( blockstack_url )
    if parts['type'] == 'immutable':
        return delete_immutable( parts['blockchain_id'], parts['fields']['data_hash'], data_id=parts['data_id'], proxy=proxy, wallet_keys=wallet_keys, **kw )
    else:
        return delete_mutable( parts['blockchain_id'], parts['data_id'], proxy=proxy, wallet_keys=wallet_keys )


def profile_update( name, new_profile, proxy=None, wallet_keys=None ):
    """
    Set the new profile data.  CLIENTS SHOULD NOT CALL THIS METHOD DIRECTLY.
    Return {'status: True} on success, as well as {'transaction_hash': hash} if we updated on the blockchain.
    Return {'error': ...} on failure.
    """
    
    ret = {}
    if proxy is None:
        proxy = get_default_proxy()

    # update the profile with the new zonefile
    _, data_privkey = get_data_keypair( wallet_keys=wallet_keys )
    rc = storage.put_mutable_data( name, new_profile, data_privkey )
    if not rc:
        ret['error'] = 'Failed to update profile'
        return ret

    else:
        ret['status'] = True

    return ret


def list_accounts( name, proxy=None, wallet_keys=None ):
    """
    List all of the accounts in a user's profile
    Each account will have at least the following:
        service:  the type of service
        identifier:  a type-specific ID
        role:  a type-specific role

    Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy()

    user_profile, user_zonefile = get_name_profile( name, proxy=proxy, wallet_keys=wallet_keys )
    if user_zonefile is None:
        # user_profile will contain an error message
        return user_profile

    # user_profile will be in the new zonefile format 
    if not user_profile.has_key("accounts"):
        return []

    else:
        return user_profile['accounts']


def get_account( name, identifier, proxy=None, wallet_keys=None ):
    """
    Get an account by identifier.  Return duplicates
    Return {'accounts': account information} on success
    Return {'error': ...} on error
    """
    if proxy is None:
        proxy = get_default_proxy()

    accounts = list_accounts( name, proxy=proxy, wallet_keys=wallet_keys )
    if 'error' in accounts:
        return accounts

    ret = []
    for acc in accounts:
        if acc['identifier'] == identifier:
            ret.append(acc)

    return {'accounts': ret}


def put_account( name, service, identifier, content_url, proxy=None, wallet_keys=None, txid=None, **extra_fields ):
    """
    Put an account's information into a profile.
    NOTE: the account must already be in the latest form.

    Return a dict with {'status': True} on success (optionally also with 'transaction_hash' set if we updated the zonefile)
    Return a dict with {'error': ...} set on failure.
    """

    if proxy is None:
        proxy = get_default_proxy()

    need_update = False

    user_profile, user_zonefile, need_update = get_and_migrate_profile( name, proxy=proxy, create_if_absent=True, wallet_keys=wallet_keys )
    if 'error' in user_profile:
        return user_profile

    if need_update:
        return {'error': 'Profile is in legacy format.  Please migrate it with the `migrate` command.'}

    # user_profile will be in the new zonefile format 
    if not user_profile.has_key("accounts"):
        user_profile['accounts'] = []

    new_profile = {}
    new_profile.update( extra_fields )
    new_profile.update( {
        "service": service,
        "identifier": identifier,
        "contentUrl": content_url
    })

    user_profile['accounts'].append(new_profile)

    return profile_update( name, user_profile, proxy=proxy, wallet_keys=wallet_keys )


def delete_account( name, service, identifier, proxy=None, wallet_keys=None ):
    """
    Remove an account's information.
    Return {'status': True, 'removed': [list of removed accounts], ...} on success
    Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy()

    need_update = False 
    removed = False

    user_profile, user_zonefile, need_update = get_and_migrate_profile( name, proxy=proxy, create_if_absent=True, wallet_keys=wallet_keys )
    if 'error' in user_profile:
        return user_profile 

    if need_update:
        return {'error': 'Profile is in legacy format.  Please migrate it with the `migrate` command.'}

    # user_profile will be in the new zonefile format
    removed = []
    for account in user_profile.get('accounts', []):
        if account['service'] == service and account['identifier'] == identifier:
            user_profile['accounts'].remove( account )
            removed.append( account )

    if len(removed) == 0:
        return {'status': True, 'removed': []}

    else:
        res = profile_update( name, user_profile, proxy=proxy, wallet_keys=wallet_keys )
        if 'error' in res:
            return res 

        else:
            res['removed'] = removed
            return res

