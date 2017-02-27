#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

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
    along with Blockstack-client.  If not, see <http://www.gnu.org/licenses/>.
"""

import os
import sys
import virtualchain
from .version import __version__, __version_major__, __version_minor__, __version_patch__

BLOCKSTACK_TEST = os.environ.get('BLOCKSTACK_TEST', None)
BLOCKSTACK_TEST_NODEBUG = os.environ.get('BLOCKSTACK_TEST_NODEBUG', None)
BLOCKSTACK_DEBUG = os.environ.get('BLOCKSTACK_DEBUG', None)
BLOCKSTACK_TEST_FIRST_BLOCK = os.environ.get('BLOCKSTACK_TEST_FIRST_BLOCK', None)
BLOCKSTACK_DRY_RUN = os.environ.get('BLOCKSTACK_DRY_RUN', None)

DEBUG = False
if BLOCKSTACK_TEST is not None and BLOCKSTACK_TEST_NODEBUG is None:
    DEBUG = True

if BLOCKSTACK_DEBUG is not None:
    DEBUG = True

if os.environ.get("DISABLE_CLIENT_DEBUG") == "1":
    DEBUG = False

TX_MIN_CONFIRMATIONS = 6
if os.environ.get("BLOCKSTACK_TEST", None) is not None:
    # test environment
    TX_MIN_CONFIRMATIONS = 0

VERSION = __version__
SERIES_VERSION = "{}.{}.{}".format(__version_major__, __version_minor__, __version_patch__)

DEFAULT_BLOCKSTACKD_PORT = 6264  # blockstackd port
DEFAULT_BLOCKSTACKD_SERVER = 'node.blockstack.org'

DEFAULT_API_PORT = 6270  # RPC endpoint port

# initialize to default settings
BLOCKSTACKD_SERVER = DEFAULT_BLOCKSTACKD_SERVER
BLOCKSTACKD_PORT = DEFAULT_BLOCKSTACKD_PORT
WALLET_PASSWORD_LENGTH = 8
WALLET_DECRYPT_MAX_TRIES = 5
WALLET_DECRYPT_BACKOFF_RESET = 3600

BLOCKSTACK_DEFAULT_STORAGE_DRIVERS = 'disk,blockstack_resolver,blockstack_server,http,dht'

# storage drivers that must successfully acknowledge each write
BLOCKSTACK_REQUIRED_STORAGE_DRIVERS_WRITE = 'disk,blockstack_server,dht'

DEFAULT_TIMEOUT = 30  # in secs

""" transaction fee configs
"""

DEFAULT_OP_RETURN_FEE = 10000
DEFAULT_DUST_FEE = 5500
DEFAULT_OP_RETURN_VALUE = 0
DEFAULT_FEE_PER_KB = 10000


""" magic bytes configs
"""

MAGIC_BYTES = 'id'

# borrowed from Blockstack
FIRST_BLOCK_MAINNET = 373601

if BLOCKSTACK_TEST and BLOCKSTACK_TEST_FIRST_BLOCK:
    FIRST_BLOCK_MAINNET = int(BLOCKSTACK_TEST_FIRST_BLOCK)
    print('TEST ACTIVE: FIRST_BLOCK_MAINNET = {}'.format(FIRST_BLOCK_MAINNET))

FIRST_BLOCK_TIME_UTC = 1441737751

TX_MIN_CONFIRMATIONS = 6
if BLOCKSTACK_TEST:
    # test environment
    TX_MIN_CONFIRMATIONS = 0
    print('TEST ACTIVE: TX_MIN_CONFIRMATIONS = {}'.format(TX_MIN_CONFIRMATIONS))

# borrowed from Blockstack
# Opcodes
ANNOUNCE = '#'
NAME_PREORDER = '?'
NAME_REGISTRATION = ':'
NAME_UPDATE = '+'
NAME_TRANSFER = '>'
NAME_RENEWAL = NAME_REGISTRATION
NAME_REVOKE = '~'
NAME_IMPORT = ';'
NAMESPACE_PREORDER = '*'
NAMESPACE_REVEAL = '&'
NAMESPACE_READY = '!'

# extra bytes affecting a transfer
TRANSFER_KEEP_DATA = '>'
TRANSFER_REMOVE_DATA = '~'

# borrowed from Blockstack Core
# these never change, so it's fine to duplicate them here
NAME_OPCODES = {
    'NAME_PREORDER': NAME_PREORDER,
    'NAME_REGISTRATION': NAME_REGISTRATION,
    'NAME_UPDATE': NAME_UPDATE,
    'NAME_TRANSFER': NAME_TRANSFER,
    'NAME_RENEWAL': NAME_REGISTRATION,
    'NAME_IMPORT': NAME_IMPORT,
    'NAME_REVOKE': NAME_REVOKE,
    'NAMESPACE_PREORDER': NAMESPACE_PREORDER,
    'NAMESPACE_REVEAL': NAMESPACE_REVEAL,
    'NAMESPACE_READY': NAMESPACE_READY,
    'ANNOUNCE': ANNOUNCE
}

# borrowed from Blockstack Core
# these never change, so it's fine to duplicate them here
OPCODE_NAMES = {
    NAME_PREORDER: 'NAME_PREORDER',
    NAME_REGISTRATION: 'NAME_REGISTRATION',
    NAME_UPDATE: 'NAME_UPDATE',
    NAME_TRANSFER: 'NAME_TRANSFER',
    NAME_RENEWAL: 'NAME_REGISTRATION',
    NAME_REVOKE: 'NAME_REVOKE',
    NAME_IMPORT: 'NAME_IMPORT',
    NAMESPACE_PREORDER: 'NAMESPACE_PREORDER',
    NAMESPACE_REVEAL: 'NAMESPACE_REVEAL',
    NAMESPACE_READY: 'NAMESPACE_READY',
    ANNOUNCE: 'ANNOUNCE'
}

# borrowed from Blockstack Core; needed by SNV
# these never change, so it's fine to duplicate them here
NAMEREC_FIELDS = [
    'name',                    # the name itself
    'value_hash',              # the hash of the name's associated profile
    'sender',                  # the scriptPubKey hex that owns this name (identifies ownership)
    'sender_pubkey',           # (OPTIONAL) the public key
    'address',                 # the address of the sender
    'block_number',            # the block number when this name record was created (preordered for the first time)
    'preorder_block_number',   # the block number when this name was last preordered
    'first_registered',        # the block number when this name was registered by the current owner
    'last_renewed',            # the block number when this name was renewed by the current owner
    'revoked',                 # whether or not the name is revoked

    'op',                      # byte sequence describing the last operation to affect this name
    'txid',                    # the ID of the last transaction to affect this name
    'vtxindex',                # the index in the block of the transaction.
    'op_fee',                  # the value of the last Blockstack-specific burn fee paid for this name (i.e. from preorder or renew)

    'importer',                # (OPTIONAL) if this name was imported, this is the importer's scriptPubKey hex
    'importer_address',        # (OPTIONAL) if this name was imported, this is the importer's address
]

# borrowed from Blockstack Core; needed by SNV
# these never change, so it's fine to duplicate them here
NAMESPACE_FIELDS = [
    'namespace_id',            # human-readable namespace ID
    'namespace_id_hash',       # hash(namespace_id,sender,reveal_addr) from the preorder (binds this namespace to its preorder)
    'version',                 # namespace rules version
    'sender',                  # the scriptPubKey hex script that identifies the preorderer
    'sender_pubkey',           # if sender is a p2pkh script, this is the public key
    'address',                 # address of the sender, from the scriptPubKey
    'recipient',               # the scriptPubKey hex script that identifies the revealer.
    'recipient_address',       # the address of the revealer
    'block_number',            # block number at which this namespace was preordered
    'reveal_block',            # block number at which this namespace was revealed
    'op',                      # byte code identifying this operation to Blockstack
    'txid',                    # transaction ID at which this namespace was revealed
    'vtxindex',                # the index in the block where the tx occurs
    'lifetime',                # how long names last in this namespace (in number of blocks)
    'coeff',                   # constant multiplicative coefficient on a name's price
    'base',                    # exponential base of a name's price
    'buckets',                 # array that maps name length to the exponent to which to raise 'base' to
    'nonalpha_discount',       # multiplicative coefficient that drops a name's price if it has non-alpha characters
    'no_vowel_discount',       # multiplicative coefficient that drops a name's price if it has no vowels
]

# borrowed from Blockstack Core; needed by SNV
# these never change, so it's fine to duplicate them here
OPFIELDS = {
    NAME_IMPORT: NAMEREC_FIELDS + [
        'recipient',           # scriptPubKey hex that identifies the name recipient
        'recipient_address'    # address of the recipient
    ],
    NAMESPACE_PREORDER: [
        'namespace_id_hash',   # hash(namespace_id,sender,reveal_addr)
        'consensus_hash',      # consensus hash at the time issued
        'op',                  # bytecode describing the operation (not necessarily 1 byte)
        'op_fee',              # fee paid for the namespace to the burn address
        'txid',                # transaction ID
        'vtxindex',            # the index in the block where the tx occurs
        'block_number',        # block number at which this transaction occurred
        'sender',              # scriptPubKey hex from the principal that issued this preorder (identifies the preorderer)
        'sender_pubkey',       # if sender is a p2pkh script, this is the public key
        'address',             # address from the scriptPubKey
    ],
    NAMESPACE_REVEAL: NAMESPACE_FIELDS,
    NAMESPACE_READY: NAMESPACE_FIELDS + [
        'ready_block',         # block number at which the namespace was readied
    ],
    NAME_PREORDER: [
        'preorder_hash',       # hash(name,sender,register_addr)
        'consensus_hash',      # consensus hash at time of send
        'sender',              # scriptPubKey hex that identifies the principal that issued the preorder
        'sender_pubkey',       # if sender is a pubkeyhash script, then this is the public key.  Otherwise, this is empty.
        'address',             # address from the sender's scriptPubKey
        'block_number',        # block number at which this name was preordered for the first time

        'op',                  # blockstack bytestring describing the operation
        'txid',                # transaction ID
        'vtxindex',            # the index in the block where the tx occurs
        'op_fee',              # blockstack fee (sent to burn address)
    ],
    NAME_REGISTRATION: NAMEREC_FIELDS + [
        'recipient',           # scriptPubKey hex script that identifies the principal to own this name
        'recipient_address'    # principal's address from the scriptPubKey in the transaction
    ],
    NAME_REVOKE: NAMEREC_FIELDS,
    NAME_TRANSFER: NAMEREC_FIELDS + [
        'name_hash128',        # hash(name)
        'consensus_hash',      # consensus hash when this operation was sent
        'keep_data'            # whether or not to keep the profile data associated with the name when transferred
    ],
    NAME_UPDATE: NAMEREC_FIELDS + [
        'name_consensus_hash', # hash(name,consensus_hash)
        'consensus_hash'       # consensus hash when this update was sent
    ]
}


# a few contants borrowed from Blockstack Core
LENGTH_VALUE_HASH = 20
LENGTH_CONSENSUS_HASH = 16
LENGTH_MAX_NAME = 37  # maximum name length
LENGTH_MAX_NAMESPACE_ID = 19  # maximum namespace length

# namespace version
BLOCKSTACK_VERSION = 1
NAME_SCHEME = MAGIC_BYTES + NAME_REGISTRATION

# burn address for fees (the address of public key
# 0x0000000000000000000000000000000000000000)
BLOCKSTACK_BURN_PUBKEY_HASH = '0000000000000000000000000000000000000000'
BLOCKSTACK_BURN_ADDRESS = virtualchain.hex_hash160_to_address(BLOCKSTACK_BURN_PUBKEY_HASH)   # '1111111111111111111114oLvT2'

# borrowed from Blockstack Core
# never changes, so safe to duplicate to avoid gratuitous imports
MAXIMUM_NAMES_PER_ADDRESS = 25

MAX_RPC_LEN = 1024 * 1024 * 1024

RPC_MAX_ZONEFILE_LEN = 4096     # 4KB
RPC_MAX_PROFILE_LEN = 1024000   # 1MB

CONFIG_FILENAME = 'client.ini'
WALLET_FILENAME = 'wallet.json'

CONFIG_PATH = os.environ.get('BLOCKSTACK_CLIENT_CONFIG')

if not BLOCKSTACK_TEST:
    # production
    if CONFIG_PATH is None:
        # default
        CONFIG_DIR = os.path.expanduser("~/.blockstack")
        CONFIG_PATH = os.path.join(CONFIG_DIR, CONFIG_FILENAME)

    else:
        # env value
        CONFIG_DIR = os.path.dirname(CONFIG_PATH)

else:
    # testing
    assert CONFIG_PATH, 'BLOCKSTACK_CLIENT_CONFIG not set'

    CONFIG_DIR = os.path.dirname(CONFIG_PATH)
    print('TEST ACTIVE: CONFIG_PATH = {}'.format(CONFIG_PATH))

WALLET_PATH = os.path.join(CONFIG_DIR, 'wallet.json')
DEFAULT_QUEUE_PATH = os.path.join(CONFIG_DIR, 'queues.db')

METADATA_DIRNAME = 'metadata'
APP_ACCOUNT_DIRNAME = 'accounts'
USER_DIRNAME = 'accounts'
DATASTORE_DIRNAME = 'datastores'
LOCAL_PRIVKEY_INDEX_NAME = 'local_privkey.idx'

BLOCKCHAIN_ID_MAGIC = 'id'

USER_ZONEFILE_TTL = 3600    # cache lifetime for a user's zonefile

SLEEP_INTERVAL = 20  # in seconds
TX_EXPIRED_INTERVAL = 10  # if a tx is not picked up by x blocks
PREORDER_CONFIRMATIONS = 6
PREORDER_MAX_CONFIRMATIONS = 130  # no. of blocks after which preorder should be removed
TX_CONFIRMATIONS_NEEDED = 10
MAX_TX_CONFIRMATIONS = 130
QUEUE_LENGTH_TO_MONITOR = 50
MINIMUM_BALANCE = 0.002
DEFAULT_POLL_INTERVAL = 300

# approximate transaction sizes, for when the user has no balance.
# over-estimations, to avoid stalled registrations.
APPROX_PREORDER_TX_LEN = 620
APPROX_REGISTER_TX_LEN = 620
APPROX_UPDATE_TX_LEN = 1240
APPROX_TRANSFER_TX_LEN = 1240
APPROX_RENEWAL_TX_LEN = 1240
APPROX_REVOKE_TX_LEN = 1240

# for estimating tx lengths, when we can't generate a transaction.
APPROX_TX_OVERHEAD_LEN = 12
APPROX_TX_IN_P2PKH_LEN = 150
APPROX_TX_OUT_P2PKH_LEN = 40
APPROX_TX_IN_P2SH_LEN = 300
APPROX_TX_OUT_P2SH_LEN = 40

# hardened children indexes
ACCOUNT_SIGNING_KEY_INDEX = 0
DATASTORE_SIGNING_KEY_INDEX = 0

# session lifetime
DEFAULT_SESSION_LIFETIME = 3600 * 24 * 7    # 1 week

# epoch dates
EPOCH_1_END_BLOCK = 436650

# epoch dates for the test environment
NUM_EPOCHS = 2
for i in range(1, NUM_EPOCHS + 1):
    # epoch lengths can be altered by the test framework, for ease of tests
    blockstack_epoch_end_block = os.environ.get('BLOCKSTACK_EPOCH_{}_END_BLOCK'.format(i), None)
    if blockstack_epoch_end_block is not None and BLOCKSTACK_TEST is not None:
        exec('EPOCH_{}_END_BLOCK = int({})'.format(i, blockstack_epoch_end_block))
        if DEBUG:
            print('Envar: EPOCH_{}_END_BLOCK = {}'.format(i, eval('EPOCH_{}_END_BLOCK'.format(i))))

del i

EPOCH_HEIGHT_MINIMUM = EPOCH_1_END_BLOCK + 1

DEFAULT_BLOCKCHAIN_READER = 'blockcypher'
DEFAULT_BLOCKCHAIN_WRITER = 'blockcypher'

SUPPORTED_UTXO_PROMPT_MESSAGES = {
    'blockcypher': 'Please enter your Blockcypher API token.',
    'blockchain_info': 'Please enter your blockchain.info API token.',
    'bitcoind_utxo': 'Please enter your fully-indexed bitcoind node information.',
    'blockstack_utxo': 'Please enter your Blockstack server info.',
}


