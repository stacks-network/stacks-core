#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack

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

import os
import sys
import copy
import socket
import stun
from ConfigParser import SafeConfigParser

from ..version import __version__

import virtualchain
log = virtualchain.get_logger("blockstack-server")

DEBUG = True
VERSION = __version__

ATLAS_SEEDS_ENV_VAR = 'BLOCKSTACK_ATLAS_SEEDS'
ATLAS_HOSTNAME_ENV_VAR = 'BLOCKSTACK_ATLAS_HOSTNAME'

# namespace version bits
NAMESPACE_VERSION_PAY_TO_BURN = 0x1
NAMESPACE_VERSION_PAY_TO_CREATOR = 0x2

NAMESPACE_VERSIONS_SUPPORTED = [
    NAMESPACE_VERSION_PAY_TO_BURN, 
    NAMESPACE_VERSION_PAY_TO_CREATOR,
]

""" constants
"""

AVERAGE_MINUTES_PER_BLOCK = 10
AVERAGE_SECONDS_PER_BLOCK = AVERAGE_MINUTES_PER_BLOCK * 60
DAYS_PER_YEAR = 365.2424
HOURS_PER_DAY = 24
MINUTES_PER_HOUR = 60
SECONDS_PER_MINUTE = 60
MINUTES_PER_YEAR = DAYS_PER_YEAR*HOURS_PER_DAY*MINUTES_PER_HOUR
SECONDS_PER_YEAR = int(round(MINUTES_PER_YEAR*SECONDS_PER_MINUTE))
BLOCKS_PER_YEAR = int(round(MINUTES_PER_YEAR/AVERAGE_MINUTES_PER_BLOCK))
BLOCKS_PER_DAY = int(round(float(MINUTES_PER_HOUR * HOURS_PER_DAY)/AVERAGE_MINUTES_PER_BLOCK))
EXPIRATION_PERIOD = BLOCKS_PER_YEAR*1
NAME_PREORDER_EXPIRE = BLOCKS_PER_DAY
AVERAGE_BLOCKS_PER_HOUR = MINUTES_PER_HOUR/AVERAGE_MINUTES_PER_BLOCK

FAST_SYNC_PUBLIC_KEYS = [
    '022052f827a2a3cb130c9abdbbfb133adc237f3ffc305ca891f49701a9e4794d2a',
]

FAST_SYNC_DEFAULT_URL = 'http://fast-sync-19.blockstack.org/snapshot.bsk'

""" name price configs
"""

NAME_COST_UNIT = 100            # minimum name cost in BTC is 100 satoshis, or about USD $0.00026 in September 2015 BTC

# BTC namespace costs (assumes ~USD $260/BTC)
# units in satoshis
SATOSHIS_PER_BTC = 10**8
NAMESPACE_1_CHAR_COST = 400.0 * SATOSHIS_PER_BTC        # ~$96,000
NAMESPACE_23_CHAR_COST = 40.0 * SATOSHIS_PER_BTC        # ~$9,600
NAMESPACE_4567_CHAR_COST = 4.0 * SATOSHIS_PER_BTC       # ~$960
NAMESPACE_8UP_CHAR_COST = 0.4 * SATOSHIS_PER_BTC        # ~$96

NAMESPACE_PREORDER_EXPIRE = BLOCKS_PER_DAY      # namespace preorders expire after 1 day, if not revealed
NAMESPACE_REVEAL_EXPIRE = BLOCKS_PER_YEAR       # namespace reveals expire after 1 year, if not readied.

""" blockstack configs
"""
BLOCKSTACK_TEST = os.environ.get('BLOCKSTACK_TEST', None)
BLOCKSTACK_TEST_NODEBUG = os.environ.get('BLOCKSTACK_TEST_NODEBUG', None)
BLOCKSTACK_DEBUG = os.environ.get('BLOCKSTACK_DEBUG', None)
BLOCKSTACK_TEST_FIRST_BLOCK = os.environ.get('BLOCKSTACK_TEST_FIRST_BLOCK', None)
BLOCKSTACK_TESTNET = os.environ.get("BLOCKSTACK_TESTNET", None)
BLOCKSTACK_TESTNET3 = os.environ.get("BLOCKSTACK_TESTNET3", None)
BLOCKSTACK_TESTNET_FIRST_BLOCK = os.environ.get("BLOCKSTACK_TESTNET_FIRST_BLOCK", None)
BLOCKSTACK_DRY_RUN = os.environ.get('BLOCKSTACK_DRY_RUN', None)
BLOCKSTACK_TEST_SUBDOMAINS_FIRST_BLOCK = os.environ.get('BLOCKSTACK_TEST_SUBDOMAINS_FIRST_BLOCK', None)

if BLOCKSTACK_TEST:
    # test environment can override these deadlines
    if os.environ.get('BLOCKSTACK_TEST_NAMESPACE_PREORDER_EXPIRE'):
        NAMESPACE_PREORDER_EXPIRE = int(os.environ['BLOCKSTACK_TEST_NAMESPACE_PREORDER_EXPIRE'])

    if os.environ.get('BLOCKSTACK_TEST_NAMESPACE_REVEAL_EXPIRE'):
        NAMESPACE_REVEAL_EXPIRE = int(os.environ['BLOCKSTACK_TEST_NAMESPACE_REVEAL_EXPIRE'])

    if os.environ.get("BLOCKSTACK_TEST_NAME_PREORDER_EXPIRE"):
        NAME_PREORDER_EXPIRE = int(os.environ['BLOCKSTACK_TEST_NAME_PREORDER_EXPIRE'])


MAX_NAMES_PER_SENDER = 25                # a single sender script can own up to this many names

if BLOCKSTACK_TEST is not None:
    # testing 
    log.warning("(%s): in test environment" % os.getpid())

    NAME_IMPORT_KEYRING_SIZE = 5                  # number of keys to derive from the import key

    if os.environ.get("BLOCKSTACK_NAMESPACE_REVEAL_EXPIRE", None) is not None:
        NAMESPACE_REVEAL_EXPIRE = int(os.environ.get("BLOCKSTACK_NAMESPACE_REVEAL_EXPIRE"))
        log.warning("NAMESPACE_REVEAL_EXPIRE = %s" % NAMESPACE_REVEAL_EXPIRE)

    else:
        NAMESPACE_REVEAL_EXPIRE = BLOCKS_PER_DAY      # small enough so we can actually test this...

    # make this low enough that we can actually test it with regtest
    NAMESPACE_1_CHAR_COST = 41 * SATOSHIS_PER_BTC

else:
    NAME_IMPORT_KEYRING_SIZE = 300                  # number of keys to derive from the import key


NUM_CONFIRMATIONS = 6                         # number of blocks to wait for before accepting names
if BLOCKSTACK_TEST is not None:
    NUM_CONFIRMATIONS = 0
    log.warning("NUM_CONFIRMATIONS = %s" % NUM_CONFIRMATIONS)

if os.environ.get("BLOCKSTACK_CORE_NUM_CONFS", None) is not None:
    NUM_CONFIRMATIONS = int(os.environ["BLOCKSTACK_CORE_NUM_CONFS"])
    log.warning("NUM_CONFIRMATIONS = %s" % NUM_CONFIRMATIONS)


""" RPC server configs
"""
RPC_SERVER_TEST_PORT = 16264
RPC_SERVER_PORT = None      # non-HTTPS port
RPC_SERVER_IP = None        # looked up via STUN, config file, or getaddrinfo
if BLOCKSTACK_TEST is not None:
    RPC_SERVER_PORT = RPC_SERVER_TEST_PORT
else:
    RPC_SERVER_PORT = 6264

DEFAULT_API_HOST = 'localhost'
DEFAULT_API_PORT = 6270  # API endpoint port
if BLOCKSTACK_TEST:
    DEFAULT_API_PORT = 16268

RPC_DEFAULT_TIMEOUT = 30  # in secs
RPC_MAX_ZONEFILE_LEN = 40960     # 40KB
RPC_MAX_INDEXING_DELAY = 2 * 3600   # 2 hours; maximum amount of time before the absence of new blocks causes the node to stop responding

MAX_RPC_LEN = RPC_MAX_ZONEFILE_LEN * 150    # maximum blockstackd RPC length == 10 zone files, base64-encoded (assume 1.33x overhead for encoding, plus extra XML)
if os.environ.get("BLOCKSTACK_TEST_MAX_RPC_LEN"):
    MAX_RPC_LEN = int(os.environ.get("BLOCKSTACK_TEST_MAX_RPC_LEN"))
    print("Overriding MAX_RPC_LEN to {}".format(MAX_RPC_LEN))

MAX_RPC_THREADS = 1000
if os.environ.get('BLOCKSTACK_RPC_MAX_THREADS'):
    MAX_RPC_THREADS = int(os.environ.get('BLOCKSTACK_RPC_MAX_THREADS'))
    print('Overriding MAX_RPC_THREADS to {}'.format(MAX_RPC_THREADS))

if BLOCKSTACK_TEST:
    RPC_MAX_INDEXING_DELAY = 5

# threshold for garbage-collection
GC_EVENT_THRESHOLD = 15


""" block indexing configs
"""
REINDEX_FREQUENCY = 300 # seconds
if BLOCKSTACK_TEST is not None:
    REINDEX_FREQUENCY = 1

FIRST_BLOCK_MAINNET = 373601

if BLOCKSTACK_TEST and BLOCKSTACK_TEST_FIRST_BLOCK:
    FIRST_BLOCK_MAINNET = int(BLOCKSTACK_TEST_FIRST_BLOCK)

elif BLOCKSTACK_TEST and BLOCKSTACK_TESTNET_FIRST_BLOCK:
    FIRST_BLOCK_MAINNET = int(BLOCKSTACK_TESTNET_FIRST_BLOCK)

SUBDOMAINS_FIRST_BLOCK = 478872

if BLOCKSTACK_TEST:
    if BLOCKSTACK_TEST_SUBDOMAINS_FIRST_BLOCK:
        SUBDOMAINS_FIRST_BLOCK = int(BLOCKSTACK_TEST_SUBDOMAINS_FIRST_BLOCK)
    else:
        SUBDOMAINS_FIRST_BLOCK = 256

GENESIS_SNAPSHOT = {
    str(FIRST_BLOCK_MAINNET-4): "17ac43c1d8549c3181b200f1bf97eb7d",
    str(FIRST_BLOCK_MAINNET-3): "17ac43c1d8549c3181b200f1bf97eb7d",
    str(FIRST_BLOCK_MAINNET-2): "17ac43c1d8549c3181b200f1bf97eb7d",
    str(FIRST_BLOCK_MAINNET-1): "17ac43c1d8549c3181b200f1bf97eb7d",
}

"""
Epoch constants govern externally-adjusted behaviors over different time intervals.
Specifically:
    * NAMESPACE_LIFETIME_MULTIPLIER:    constant to multiply name lifetimes by
    * NAMESPACE_LIFETIME_GRACE_PERIOD:  constant to add to the name's lifetime when it's about to expire
    * PRICE_MULTIPLIER:                 constant to multiply name and namespace prices by
"""
EPOCH_FIELDS = [
    "end_block",
    "namespaces",
    "features"
]

EPOCH_NAMESPACE_FIELDS = [
    "NAMESPACE_LIFETIME_MULTIPLIER",
    "NAMESPACE_LIFETIME_GRACE_PERIOD",
    "PRICE_MULTIPLIER"
]

# epoch features
EPOCH_FEATURE_MULTISIG = "BLOCKSTACK_MULTISIG"
EPOCH_FEATURE_SEGWIT = "BLOCKSTACK_SEGWIT"
EPOCH_FEATURE_OP_REGISTER_UPDATE = "BLOCKSTACK_OP_REGISTER_UPDATE"
EPOCH_FEATURE_OP_RENEW_TRANSFER_UPDATE = "BLOCKSTACK_OP_RENEW_TRANSFER_UPDATE"
EPOCH_FEATURE_NAMESPACE_BURN_TO_CREATOR = "BLOCKSTACK_NAMESPACE_BURN_TO_CREATOR"

# when epochs end (-1 means "never")
EPOCH_NOW = -1
EPOCH_1_END_BLOCK = 436650      # F-Day 2016
EPOCH_2_END_BLOCK = 488500      # F-day 2017
EPOCH_3_END_BLOCK = 999999      # TODO
EPOCH_4_END_BLOCK = EPOCH_NOW

EPOCH_1_NAMESPACE_LIFETIME_MULTIPLIER_id = 1
EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER_id = 2
EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER_id = 2

EPOCH_1_NAMESPACE_LIFETIME_GRACE_PERIOD_id = 0
EPOCH_2_NAMESPACE_LIFETIME_GRACE_PERIOD_id = 0
EPOCH_3_NAMESPACE_LIFETIME_GRACE_PERIOD_id = 5000   # about 30 days

EPOCH_1_PRICE_MULTIPLIER_id = 1.0
EPOCH_2_PRICE_MULTIPLIER_id = 1.0
EPOCH_3_PRICE_MULTIPLIER_id = 0.1

EPOCH_1_NAMESPACE_RECEIVE_FEES_PERIOD_id = 0
EPOCH_2_NAMESPACE_RECEIVE_FEES_PERIOD_id = 0
EPOCH_3_NAMESPACE_RECEIVE_FEES_PERIOD_id = BLOCKS_PER_YEAR

EPOCH_1_FEATURES = []
EPOCH_2_FEATURES = [EPOCH_FEATURE_MULTISIG]
EPOCH_3_FEATURES = [EPOCH_FEATURE_MULTISIG, EPOCH_FEATURE_SEGWIT, EPOCH_FEATURE_OP_REGISTER_UPDATE, EPOCH_FEATURE_OP_RENEW_TRANSFER_UPDATE, EPOCH_FEATURE_NAMESPACE_BURN_TO_CREATOR]

NUM_EPOCHS = 3
for i in xrange(1, NUM_EPOCHS+1):
    # epoch lengths can be altered by the test framework, for ease of tests
    if os.environ.get("BLOCKSTACK_EPOCH_%s_END_BLOCK" % i, None) is not None and BLOCKSTACK_TEST:
        exec("EPOCH_%s_END_BLOCK = int(%s)" % (i, os.environ.get("BLOCKSTACK_EPOCH_%s_END_BLOCK" % i)))
        log.warn("EPOCH_%s_END_BLOCK = %s" % (i, eval("EPOCH_%s_END_BLOCK" % i)))

    if os.environ.get("BLOCKSTACK_EPOCH_%s_PRICE_MULTIPLIER" % i, None) is not None and BLOCKSTACK_TEST:
        exec("EPOCH_%s_PRICE_MULTIPLIER_id = float(%s)" % (i, os.environ.get("BLOCKSTACK_EPOCH_%s_PRICE_MULTIPLIER" % i)))
        log.warn("EPOCH_%s_PRICE_MULTIPLIER_id = %s" % (i, eval("EPOCH_%s_PRICE_MULTIPLIER_id" % i)))

    if os.environ.get("BLOCKSTACK_EPOCH_%s_NAMESPACE_LIFETIME_MULTIPLIER" % i, None) is not None and BLOCKSTACK_TEST:
        exec("EPOCH_%s_NAMESPACE_LIFETIME_MULTIPLIER_id = int(%s)" % (i, os.environ.get("BLOCKSTACK_EPOCH_%s_NAMESPACE_LIFETIME_MULTIPLIER" % i)))
        log.warn("EPOCH_%s_NAMESPACE_LIFETIME_MULTIPLIER_id = %s" % (i, eval("EPOCH_%s_NAMESPACE_LIFETIME_MULTIPLIER_id" % i)))

    if os.environ.get("BLOCKSTACK_EPOCH_%s_NAMESPACE_LIFETIME_GRACE_PERIOD" % i, None) is not None and BLOCKSTACK_TEST:
        exec("EPOCH_%s_NAMESPACE_LIFETIME_GRACE_PERIOD_id = int(%s)" % (i, os.environ.get("BLOCKSTACK_EPOCH_%s_NAMESPACE_LIFETIME_GRACE_PERIOD" % i)))
        log.warn("EPOCH_%s_NAMESPACE_LIFETIME_GRACE_PERIOD_id = %s" % (i, eval("EPOCH_%s_NAMESPACE_LIFETIME_GRACE_PERIOD_id" % i)))

    if os.environ.get("BLOCKSTACK_EPOCH_%s_NAMESPACE_RECEIVE_FEES_PERIOD" % i, None) is not None and BLOCKSTACK_TEST:
        exec("EPOCH_%s_NAMESPACE_RECEIVE_FEES_PERIOD_id = int(%s)" % (i, os.environ.get("BLOCKSTACK_EPOCH_%s_NAMESPACE_RECEIVE_FEES_PERIOD" % i)))
        log.warn("EPOCH_%s_NAMESPACE_RECEIVE_FEES_PERIOD_id = %s" % (i, eval("EPOCH_%s_NAMESPACE_RECEIVE_FEES_PERIOD_id" % i)))

del i

# epoch definitions
# each epoch begins at the block after 'end_block'.
# the first epoch begins at FIRST_BLOCK_MAINNET
EPOCHS = [
    {
        # epoch 1
        "end_block": EPOCH_1_END_BLOCK,
        "namespaces": {
            "NAMESPACE_LIFETIME_MULTIPLIER": EPOCH_1_NAMESPACE_LIFETIME_MULTIPLIER_id,
            "NAMESPACE_LIFETIME_GRACE_PERIOD": EPOCH_1_NAMESPACE_LIFETIME_GRACE_PERIOD_id,
            "PRICE_MULTIPLIER": EPOCH_1_PRICE_MULTIPLIER_id,
            "NAMESPACE_RECEIVE_FEES_PERIOD": EPOCH_1_NAMESPACE_RECEIVE_FEES_PERIOD_id,
        },
        "namespace_prices": [
            21 * 10**8,                 # 0-character cost
            NAMESPACE_1_CHAR_COST,      # 1-character cost
            NAMESPACE_23_CHAR_COST,     # 2-character cost
            NAMESPACE_23_CHAR_COST,     # 3-character cost
            NAMESPACE_4567_CHAR_COST,   # 4-character cost
            NAMESPACE_4567_CHAR_COST,   # 5-character cost
            NAMESPACE_4567_CHAR_COST,   # 6-character cost
            NAMESPACE_4567_CHAR_COST,   # 7-character cost
            NAMESPACE_8UP_CHAR_COST,    # 8-character cost
            NAMESPACE_8UP_CHAR_COST,    # 9-character cost
            NAMESPACE_8UP_CHAR_COST,    # 10-character cost
            NAMESPACE_8UP_CHAR_COST,    # 11-character cost
            NAMESPACE_8UP_CHAR_COST,    # 12-character cost
            NAMESPACE_8UP_CHAR_COST,    # 13-character cost
            NAMESPACE_8UP_CHAR_COST,    # 14-character cost
            NAMESPACE_8UP_CHAR_COST,    # 15-character cost
            NAMESPACE_8UP_CHAR_COST,    # 16-character cost
            NAMESPACE_8UP_CHAR_COST,    # 17-character cost
            NAMESPACE_8UP_CHAR_COST,    # 18-character cost
            NAMESPACE_8UP_CHAR_COST,    # 19-character cost 
        ],
        "features": EPOCH_1_FEATURES
    },
    {
        # epoch 2
        "end_block": EPOCH_2_END_BLOCK,
        "namespaces": {
            "NAMESPACE_LIFETIME_MULTIPLIER": EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER_id,
            "NAMESPACE_LIFETIME_GRACE_PERIOD": EPOCH_2_NAMESPACE_LIFETIME_GRACE_PERIOD_id,
            "PRICE_MULTIPLIER": EPOCH_2_PRICE_MULTIPLIER_id,
            "NAMESPACE_RECEIVE_FEES_PERIOD": EPOCH_2_NAMESPACE_RECEIVE_FEES_PERIOD_id,
        },
        "namespace_prices": [
            21 * 10**8,                 # 0-character cost
            NAMESPACE_1_CHAR_COST,      # 1-character cost
            NAMESPACE_23_CHAR_COST,     # 2-character cost
            NAMESPACE_23_CHAR_COST,     # 3-character cost
            NAMESPACE_4567_CHAR_COST,   # 4-character cost
            NAMESPACE_4567_CHAR_COST,   # 5-character cost
            NAMESPACE_4567_CHAR_COST,   # 6-character cost
            NAMESPACE_4567_CHAR_COST,   # 7-character cost
            NAMESPACE_8UP_CHAR_COST,    # 8-character cost
            NAMESPACE_8UP_CHAR_COST,    # 9-character cost
            NAMESPACE_8UP_CHAR_COST,    # 10-character cost
            NAMESPACE_8UP_CHAR_COST,    # 11-character cost
            NAMESPACE_8UP_CHAR_COST,    # 12-character cost
            NAMESPACE_8UP_CHAR_COST,    # 13-character cost
            NAMESPACE_8UP_CHAR_COST,    # 14-character cost
            NAMESPACE_8UP_CHAR_COST,    # 15-character cost
            NAMESPACE_8UP_CHAR_COST,    # 16-character cost
            NAMESPACE_8UP_CHAR_COST,    # 17-character cost
            NAMESPACE_8UP_CHAR_COST,    # 18-character cost
            NAMESPACE_8UP_CHAR_COST,    # 19-character cost 
        ],
        "features": EPOCH_2_FEATURES,
    },
    {
        # epoch 3
        "end_block": EPOCH_3_END_BLOCK,
        "namespaces": {
            "NAMESPACE_LIFETIME_MULTIPLIER": EPOCH_3_NAMESPACE_LIFETIME_MULTIPLIER_id,
            "NAMESPACE_LIFETIME_GRACE_PERIOD": EPOCH_3_NAMESPACE_LIFETIME_GRACE_PERIOD_id,
            "PRICE_MULTIPLIER": EPOCH_3_PRICE_MULTIPLIER_id,
            "NAMESPACE_RECEIVE_FEES_PERIOD": EPOCH_3_NAMESPACE_RECEIVE_FEES_PERIOD_id,
        },
        "namespace_prices": [
            21 * 10**8,                 # 0-character cost
            NAMESPACE_1_CHAR_COST / 10,      # 1-character cost
            NAMESPACE_23_CHAR_COST / 10,     # 2-character cost
            NAMESPACE_23_CHAR_COST / 10,     # 3-character cost
            NAMESPACE_4567_CHAR_COST / 10,   # 4-character cost
            NAMESPACE_4567_CHAR_COST / 10,   # 5-character cost
            NAMESPACE_4567_CHAR_COST / 10,   # 6-character cost
            NAMESPACE_4567_CHAR_COST / 10,   # 7-character cost
            NAMESPACE_8UP_CHAR_COST / 10,    # 8-character cost
            NAMESPACE_8UP_CHAR_COST / 10,    # 9-character cost
            NAMESPACE_8UP_CHAR_COST / 10,    # 10-character cost
            NAMESPACE_8UP_CHAR_COST / 10,    # 11-character cost
            NAMESPACE_8UP_CHAR_COST / 10,    # 12-character cost
            NAMESPACE_8UP_CHAR_COST / 10,    # 13-character cost
            NAMESPACE_8UP_CHAR_COST / 10,    # 14-character cost
            NAMESPACE_8UP_CHAR_COST / 10,    # 15-character cost
            NAMESPACE_8UP_CHAR_COST / 10,    # 16-character cost
            NAMESPACE_8UP_CHAR_COST / 10,    # 17-character cost
            NAMESPACE_8UP_CHAR_COST / 10,    # 18-character cost
            NAMESPACE_8UP_CHAR_COST / 10,    # 19-character cost 
        ],
        "features": EPOCH_3_FEATURES,
    },
]

# epoch self-consistency check 
for epoch_field in EPOCH_FIELDS:
    for i in xrange(0, len(EPOCHS)):
        if not EPOCHS[i].has_key(epoch_field):
            raise Exception("Missing field '%s' at epoch %s" % (epoch_field, i))

for i in xrange(0, len(EPOCHS)):
    for epoch_field in EPOCHS[i]['namespaces']:
        if not EPOCHS[i]['namespaces'].has_key(epoch_field):
            raise Exception("Missing field '%s' at epoch %s" % (epoch_field, i))

# if EPOCHS[len(EPOCHS)-1]['end_block'] != EPOCH_NOW:
#    raise Exception("Last epoch ends at %s" % EPOCHS[len(EPOCHS)-1]['end_block'])

for i in xrange(0, len(EPOCHS)-1):
    if EPOCHS[i]['end_block'] < 0:
        raise Exception("Invalid end block for epoch %s" % (i+1))

    if EPOCHS[i]['end_block'] >= EPOCHS[i+1]['end_block'] and EPOCHS[i+1]['end_block'] > 0:
        raise Exception("Invalid epoch block range at epoch %s" % (i+1))


del epoch_field
del i 

""" magic bytes configs
"""

MAGIC_BYTES = 'id'

""" name operation data configs
"""

# Opcodes
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
ANNOUNCE = '#'

# extra bytes affecting a transfer
TRANSFER_KEEP_DATA = '>'
TRANSFER_REMOVE_DATA = '~'

# list of opcodes we support
# ORDER MATTERS--it determines processing order, and determines collision priority
# (i.e. earlier operations in this list are preferred over later operations)
OPCODES = [
   NAME_PREORDER,
   NAME_REVOKE,
   NAME_REGISTRATION,
   NAME_UPDATE,
   NAME_TRANSFER,
   NAME_IMPORT,
   NAMESPACE_PREORDER,
   NAMESPACE_REVEAL,
   NAMESPACE_READY,
   ANNOUNCE
]

OPCODE_NAMES = {
    NAME_PREORDER: "NAME_PREORDER",
    NAME_REGISTRATION: "NAME_REGISTRATION",
    NAME_UPDATE: "NAME_UPDATE",
    NAME_TRANSFER: "NAME_TRANSFER",
    NAME_RENEWAL: "NAME_REGISTRATION",
    NAME_REVOKE: "NAME_REVOKE",
    NAME_IMPORT: "NAME_IMPORT",
    NAMESPACE_PREORDER: "NAMESPACE_PREORDER",
    NAMESPACE_REVEAL: "NAMESPACE_REVEAL",
    NAMESPACE_READY: "NAMESPACE_READY",
    ANNOUNCE: "ANNOUNCE"
}

NAME_OPCODES = {
    "NAME_PREORDER": NAME_PREORDER,
    "NAME_REGISTRATION": NAME_REGISTRATION,
    "NAME_UPDATE": NAME_UPDATE,
    "NAME_TRANSFER": NAME_TRANSFER,
    "NAME_RENEWAL": NAME_REGISTRATION,
    "NAME_IMPORT": NAME_IMPORT,
    "NAME_REVOKE": NAME_REVOKE,
    "NAMESPACE_PREORDER": NAMESPACE_PREORDER,
    "NAMESPACE_REVEAL": NAMESPACE_REVEAL,
    "NAMESPACE_READY": NAMESPACE_READY,
    "ANNOUNCE": ANNOUNCE
}


# op-return formats
LENGTHS = {
    'magic_bytes': 2,
    'opcode': 1,
    'preorder_name_hash': 20,
    'consensus_hash': 16,
    'namelen': 1,
    'name_min': 1,
    'name_max': 34,
    'fqn_min': 3,
    'fqn_max': 37,
    'name_hash': 16,
    'name_consensus_hash': 16,
    'value_hash': 20,
    'blockchain_id_name': 37,
    'blockchain_id_namespace_life': 4,
    'blockchain_id_namespace_coeff': 1,
    'blockchain_id_namespace_base': 1,
    'blockchain_id_namespace_buckets': 8,
    'blockchain_id_namespace_discounts': 1,
    'blockchain_id_namespace_version': 2,
    'blockchain_id_namespace_id': 19,
    'namespace_id': 19,     # same as above
    'announce': 20,
    'max_op_length': 80
}

MIN_OP_LENGTHS = {
    'preorder': LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash'],
    'preorder_multi': 1 + LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash'],
    'registration': LENGTHS['fqn_min'],
    'registration_multi': 2*LENGTHS['fqn_min'] + 2*LENGTHS['value_hash'],
    'update': LENGTHS['name_consensus_hash'] + LENGTHS['value_hash'],
    'transfer': LENGTHS['name_hash'] + LENGTHS['consensus_hash'],
    'revoke': LENGTHS['fqn_min'],
    'name_import': LENGTHS['fqn_min'],
    'namespace_preorder': LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash'],
    'namespace_reveal': LENGTHS['blockchain_id_namespace_life'] + LENGTHS['blockchain_id_namespace_coeff'] + \
                        LENGTHS['blockchain_id_namespace_base'] + LENGTHS['blockchain_id_namespace_buckets'] + \
                        LENGTHS['blockchain_id_namespace_discounts'] + LENGTHS['blockchain_id_namespace_version'] + \
                        LENGTHS['name_min'],
    'namespace_ready': 1 + LENGTHS['name_min'],
    'announce': LENGTHS['announce']
}

# graph of allowed operation sequences
OPCODE_SEQUENCE_GRAPH = {
    "NAME_PREORDER":      [ "NAME_REGISTRATION" ],
    "NAME_REGISTRATION":  [ "NAME_UPDATE", "NAME_TRANSFER", "NAME_RENEWAL", "NAME_REVOKE" ],
    "NAME_UPDATE":        [ "NAME_UPDATE", "NAME_TRANSFER", "NAME_RENEWAL", "NAME_REVOKE" ],
    "NAME_TRANSFER":      [ "NAME_UPDATE", "NAME_TRANSFER", "NAME_RENEWAL", "NAME_REVOKE" ],
    "NAME_RENEWAL":       [ "NAME_UPDATE", "NAME_TRANSFER", "NAME_RENEWAL", "NAME_REVOKE" ],
    "NAME_REVOKE":        [ "NAME_REGISTRATION" ],      # i.e. following a re-preorder 
    "NAME_IMPORT":        [ "NAME_IMPORT", "NAME_UPDATE", "NAME_TRANSFER", "NAME_RENEWAL", "NAME_REVOKE" ],   # i.e. only after the namespace is ready'ed
    "NAMESPACE_PREORDER": [ "NAMESPACE_REVEAL" ],
    "NAMESPACE_REVEAL":   [ "NAMESPACE_READY" ],
    "NAMESPACE_READY":    [],
}

# set of operations that preorder names
OPCODE_NAME_STATE_PREORDER = [
    "NAME_PREORDER",
]

# set of operations that preorder namespaces 
OPCODE_NAMESPACE_STATE_PREORDER = [
    "NAMESPACE_PREORDER"
]

OPCODE_PREORDER_OPS = OPCODE_NAME_STATE_PREORDER + OPCODE_NAMESPACE_STATE_PREORDER

# set of operations that create names
OPCODE_NAME_STATE_CREATIONS = [
    "NAME_REGISTRATION",
    "NAME_IMPORT"
]

# set of operations that import names 
OPCODE_NAME_STATE_IMPORTS = [
    "NAME_IMPORT"
]

# set of operations that create namespaces
OPCODE_NAMESPACE_STATE_CREATIONS = [
    "NAMESPACE_REVEAL"
]

OPCODE_CREATION_OPS = OPCODE_NAME_STATE_CREATIONS + OPCODE_NAMESPACE_STATE_CREATIONS

# set of operations that affect existing names 
OPCODE_NAME_STATE_TRANSITIONS = [
    "NAME_IMPORT",
    "NAME_UPDATE",
    "NAME_TRANSFER",
    "NAME_RENEWAL",
    "NAME_REVOKE"
]

# set of operations that affect existing namespaces 
OPCODE_NAMESPACE_STATE_TRANSITIONS = [
    "NAMESPACE_READY"
]

OPCODE_TRANSITION_OPS = OPCODE_NAME_STATE_TRANSITIONS + OPCODE_NAMESPACE_STATE_TRANSITIONS 

# set of ops that have no state to record 
OPCODE_STATELESS_OPS = [
    "ANNOUNCE"
]

# set of operations that affect only names
OPCODE_NAME_NAMEOPS = [
    'NAME_PREORDER',
    'NAME_IMPORT',
    'NAME_REGISTRATION',
    'NAME_UPDATE',
    'NAME_TRANSFER',
    'NAME_RENEWAL',
    'NAME_REVOKE'
]

NAMESPACE_LIFE_INFINITE = 0xffffffff

# default burn address for fees (the address of public key hash 0x0000000000000000000000000000000000000000)
BLOCKSTACK_BURN_PUBKEY_HASH = "0000000000000000000000000000000000000000"
BLOCKSTACK_BURN_ADDRESS = virtualchain.hex_hash160_to_address( BLOCKSTACK_BURN_PUBKEY_HASH )   # "1111111111111111111114oLvT2"

# default namespace record (i.e. for names with no namespace ID)
NAMESPACE_DEFAULT = {
   'opcode': 'NAMESPACE_REVEAL',
   'lifetime': EXPIRATION_PERIOD,
   'coeff': 15,
   'base': 15,
   'buckets': [15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15],
   'version': NAMESPACE_VERSION_PAY_TO_BURN,
   'nonalpha_discount': 1.0,
   'no_vowel_discount': 1.0,
   'namespace_id': None,
   'namespace_id_hash': None,
   'sender': "",
   'recipient': "",
   'address': "",
   'recipient_address': "",
   'sender_pubkey': None,
   'history': {},
   'block_number': 0
}

# for subdomain DIDs
SUBDOMAIN_ADDRESS_VERSION_BYTE = 63             # 'S'
SUBDOMAIN_ADDRESS_MULTISIG_VERSION_BYTE = 50    # 'M'

if BLOCKSTACK_TESTNET:
    SUBDOMAIN_ADDRESS_VERSION_BYTE = 127            # 't'
    SUBDOMAIN_ADDRESS_MULTISIG_VERSION_BYTE = 142   # 'z'

SUBDOMAIN_ADDRESS_VERSION_BYTES = [SUBDOMAIN_ADDRESS_VERSION_BYTE, SUBDOMAIN_ADDRESS_MULTISIG_VERSION_BYTE]

# global mutable state 
blockstack_opts = None
blockstack_api_opts = None
bitcoin_opts = None
running = False

def get_epoch_number( block_height ):
    """
    Which epoch are we in?
    Return integer (>=0) on success
    """
    global EPOCHS

    if block_height <= EPOCHS[0]['end_block']:
        return 0

    for i in xrange(1, len(EPOCHS)):
        if EPOCHS[i-1]['end_block'] < block_height and (block_height <= EPOCHS[i]['end_block'] or EPOCHS[i]['end_block'] == EPOCH_NOW):
            return i

    # should never happen 
    log.error("FATAL: No epoch for %s" % block_height)
    os.abort()


def get_epoch_config( block_height ):
    """
    Get the epoch constants for the given block height
    """
    global EPOCHS
    epoch_number = get_epoch_number( block_height )

    if epoch_number < 0 or epoch_number >= len(EPOCHS):
        log.error("FATAL: invalid epoch %s" % epoch_number)
        os.abort()

    return EPOCHS[epoch_number]


def get_epoch_namespace_lifetime_multiplier( block_height, namespace_id ):
    """
    what's the namespace lifetime multipler for this epoch?
    """
    epoch_config = get_epoch_config( block_height )
    return epoch_config['namespaces']['NAMESPACE_LIFETIME_MULTIPLIER']


def get_epoch_namespace_lifetime_grace_period( block_height, namespace_id ):
    """
    what's the namespace lifetime grace period for this epoch?
    """
    epoch_config = get_epoch_config( block_height )
    return epoch_config['namespaces']['NAMESPACE_LIFETIME_GRACE_PERIOD']


def get_epoch_price_multiplier( block_height, namespace_id ):
    """
    what's the name price multiplier for this epoch?
    """
    epoch_config = get_epoch_config( block_height )
    return epoch_config['namespaces']['PRICE_MULTIPLIER']


def get_epoch_namespace_receive_fees_period( block_height, namespace_id ):
    """
    how long can a namespace receive register/renewal fees?
    """
    epoch_config = get_epoch_config( block_height )
    return epoch_config['namespaces']['NAMESPACE_RECEIVE_FEES_PERIOD']


def get_epoch_namespace_prices( block_height ):
    """
    get the list of namespace prices by block height
    """
    epoch_config = get_epoch_config( block_height )
    return epoch_config['namespace_prices']


def get_epoch_features( block_height ):
    """
    Get the features of an epoch
    """
    epoch_config = get_epoch_config( block_height )
    return epoch_config['features']


def epoch_has_multisig( block_height ):
    """
    Is multisig available in this epoch?
    """
    epoch_config = get_epoch_config( block_height )
    if EPOCH_FEATURE_MULTISIG in epoch_config['features']:
        return True
    else:
        return False


def epoch_has_segwit( block_height ):
    """
    Is segwit available in this epoch?
    """
    epoch_config = get_epoch_config( block_height )
    if EPOCH_FEATURE_SEGWIT in epoch_config['features']:
        return True
    else:
        return False


"""
Which announcements has this blockstack node seen so far?
Announcements encode CVEs, bugs, and new features.  This list will be
updated in Blockstack releases to describe which of them have been
incorporated into the codebase.
"""
ANNOUNCEMENTS = []

def op_get_opcode_name(op_string):
    """
    Get the name of an opcode, given the 'op' byte sequence of the operation.
    """
    global OPCODE_NAMES

    # special case...
    if op_string == '{}:'.format(NAME_REGISTRATION):
        return 'NAME_RENEWAL'

    op = op_string[0]
    if op not in OPCODE_NAMES:
        raise Exception('No such operation "{}"'.format(op))

    return OPCODE_NAMES[op]


def get_default_virtualchain_impl():
   """
   Get the set of virtualchain hooks--to serve as
   the virtualchain's implementation.  Uses the
   one set in the virtualchain runtime config, but
   falls back to Blockstack's by default (i.e. if
   blockstack is getting imported as part of a 
   library).
   """
   import nameset.virtualchain_hooks as virtualchain_hooks
   return virtualchain_hooks


def get_announce_filename( working_dir ):
   """
   Get the path to the file that stores all of the announcements.
   """
   announce_filepath = os.path.join( working_dir, get_default_virtualchain_impl().get_virtual_chain_name() ) + '.announce'
   return announce_filepath


def get_bitcoin_opts():
   """
   Get the bitcoind connection arguments.
   """
   global bitcoin_opts
   return bitcoin_opts


def get_blockstack_opts():
   """
   Get blockstack configuration options.
   """
   global blockstack_opts
   return blockstack_opts


def get_blockstack_api_opts():
    """
    Get the blockstack RESTful API configuration options
    """
    global blockstack_api_opts
    return blockstack_api_opts


def set_bitcoin_opts( new_bitcoin_opts ):
   """
   Set new global bitcoind operations
   """
   global bitcoin_opts
   bitcoin_opts = new_bitcoin_opts


def set_blockstack_opts( new_opts ):
    """
    Set new global blockstack opts
    """
    global blockstack_opts
    blockstack_opts = new_opts


def set_blockstack_api_opts( new_opts ):
    """
    Set new RESTful API opts
    """
    global blockstack_api_opts
    blockstack_api_opts = new_opts


def get_indexing_lockfile(working_dir):
    """
    Return path to the indexing lockfile
    """
    return os.path.join(working_dir, "blockstack-server.indexing" )


def is_indexing(working_dir):
    """
    Is the blockstack daemon synchronizing with the blockchain?
    """
    indexing_path = get_indexing_lockfile(working_dir)
    if os.path.exists( indexing_path ):
        return True
    else:
        return False


def set_indexing(working_dir, flag):
    """
    Set a flag in the filesystem as to whether or not we're indexing.
    """
    indexing_path = get_indexing_lockfile(working_dir)
    if flag:
        try:
            fd = open( indexing_path, "w+" )
            fd.close()
            return True
        except:
            return False

    else:
        try:
            os.unlink( indexing_path )
            return True
        except:
            return False


def set_running(status):
    """
    Set running flag
    """
    global running
    running = status


def is_running():
    """
    Check running flag
    """
    global running 
    return running


def is_atlas_enabled(blockstack_opts):
    """
    Can we do atlas operations?
    """
    if not blockstack_opts['atlas']:
        log.debug("Atlas is disabled")
        return False

    if 'zonefiles' not in blockstack_opts:
        log.debug("Atlas is disabled: no 'zonefiles' path set")
        return False

    if 'atlasdb_path' not in blockstack_opts:
        log.debug("Atlas is disabled: no 'atlasdb_path' path set")
        return False

    return True


def is_subdomains_enabled(blockstack_opts):
    """
    Can we do subdomain operations?
    """
    if not is_atlas_enabled(blockstack_opts):
        log.debug("Subdomains are disabled")
        return False

    if 'subdomaindb_path' not in blockstack_opts:
        log.debug("Subdomains are disabled: no 'subdomaindb_path' path set")
        return False

    return True


def store_announcement( working_dir, announcement_hash, announcement_text, force=False ):
   """
   Store a new announcement locally, atomically.
   """

   if not force:
       # don't store unless we haven't seen it before
       if announcement_hash in ANNOUNCEMENTS:
           return

   announce_filename = get_announce_filename( working_dir )
   announce_filename_tmp = announce_filename + ".tmp"
   announce_text = ""
   announce_cleanup_list = []

   # did we try (and fail) to store a previous announcement?  If so, merge them all
   if os.path.exists( announce_filename_tmp ):

       log.debug("Merge announcement list %s" % announce_filename_tmp )

       with open(announce_filename, "r") as f:
           announce_text += f.read()

       i = 1
       failed_path = announce_filename_tmp + (".%s" % i)
       while os.path.exists( failed_path ):

           log.debug("Merge announcement list %s" % failed_path )
           with open(failed_path, "r") as f:
               announce_text += f.read()

           announce_cleanup_list.append( failed_path )

           i += 1
           failed_path = announce_filename_tmp + (".%s" % i)

       announce_filename_tmp = failed_path

   if os.path.exists( announce_filename ):
       with open(announce_filename, "r" ) as f:
           announce_text += f.read()

   announce_text += ("\n%s\n" % announcement_hash)

   # filter
   if not force:
       announcement_list = announce_text.split("\n")
       unseen_announcements = filter( lambda a: a not in ANNOUNCEMENTS, announcement_list )
       announce_text = "\n".join( unseen_announcements ).strip() + "\n"

   log.debug("Store announcement hash to %s" % announce_filename )

   with open(announce_filename_tmp, "w" ) as f:
       f.write( announce_text )
       f.flush()

   # NOTE: rename doesn't remove the old file on Windows
   if sys.platform == 'win32' and os.path.exists( announce_filename_tmp ):
       try:
           os.unlink( announce_filename_tmp )
       except:
           pass

   try:
       os.rename( announce_filename_tmp, announce_filename )
   except:
       log.error("Failed to save announcement %s to %s" % (announcement_hash, announce_filename ))
       raise

   # clean up
   for tmp_path in announce_cleanup_list:
       try:
           os.unlink( tmp_path )
       except:
           pass

   # put the announcement text
   announcement_text_dir = os.path.join( working_dir, "announcements" )
   if not os.path.exists( announcement_text_dir ):
       try:
           os.makedirs( announcement_text_dir )
       except:
           log.error("Failed to make directory %s" % announcement_text_dir )
           raise

   announcement_text_path = os.path.join( announcement_text_dir, "%s.txt" % announcement_hash )

   try:
       with open( announcement_text_path, "w" ) as f:
           f.write( announcement_text )

   except:
       log.error("Failed to save announcement text to %s" % announcement_text_path )
       raise

   log.debug("Stored announcement to %s" % (announcement_text_path))


def get_atlas_hostname_stun():
    log.debug("Using STUN servers to discover my public IP (set 'atlas_hostname' to a valid DNS name or IP address in the config file to override)")
    _, real_atlas_hostname, _ = stun.get_ip_info()
    log.debug("Atlas host IP is {}".format(real_atlas_hostname))
    return real_atlas_hostname


def get_atlas_hostname_addrinfo(rpc_port):
    log.debug("Using getnameinfo and getaddrinfo to get my assigned IP address (set 'atlas_hostname' to a valid DNS name or IP address in the config to override)")
    hostn = socket.gethostname()

    try:
        addr_infos = socket.getaddrinfo(hostn, rpc_port)
    except socket.gaierror as gaie:
        # hostname doesn't match /etc/hosts, or similar (can happen in chroots)
        log.warning('Unable to get addr info for {}: {}.  Defaulting to 127.0.0.1'.format(hostn, gaie))
        return '127.0.0.1'
        
    real_atlas_hostname = None
    for addr_info in addr_infos:
        # addr_info[0] == ai_family
        # addr_info[1] == ai_socktype
        # addr_info[2] == ai_protocol
        # addr_info[3] == ai_cannonname
        # addr_info[4] == (hostname, port) (ai_sockaddr)
        if addr_info[0] in (socket.AF_INET, socket.AF_INET6) and addr_info[1] == socket.SOCK_STREAM and addr_info[2] == socket.IPPROTO_TCP:
            # tcp/ip, either IPv4 or IPv6
            real_atlas_hostname = addr_info[4][0]

    log.debug("Atlas host IP is {}".format(real_atlas_hostname))
    return real_atlas_hostname


def default_blockstack_opts( working_dir, config_file=None ):
   """
   Get our default blockstack opts from a config file
   or from sane defaults.
   """

   global RPC_SERVER_IP, RPC_SERVER_PORT

   from .util import url_to_host_port
   from .scripts import is_name_valid

   if config_file is None:
      config_file = virtualchain.get_config_filename(get_default_virtualchain_impl(), working_dir)

   announce_path = get_announce_filename(working_dir)

   parser = SafeConfigParser()
   parser.read( config_file )

   blockstack_opts = {}
   announcers = "judecn.id,muneeb.id,shea256.id"
   announcements = None
   backup_frequency = 144   # once a day; 10 minute block time
   backup_max_age = 1008    # one week
   rpc_port = RPC_SERVER_PORT 
   zonefile_dir = os.path.join( os.path.dirname(config_file), "zonefiles")
   server_version = VERSION
   atlas_enabled = True
   atlas_seed_peers = "node.blockstack.org:%s" % RPC_SERVER_PORT
   atlasdb_path = os.path.join( os.path.dirname(config_file), "atlas.db" )
   atlas_blacklist = ""
   atlas_hostname = RPC_SERVER_IP
   real_atlas_hostname = None       # if we need to look it up on-the-fly
   atlas_port = RPC_SERVER_PORT
   subdomaindb_path = os.path.join( os.path.dirname(config_file), "subdomains.db" )
   run_indexer = True

   if parser.has_section('blockstack'):
      if parser.has_option('blockstack', 'enabled'):
         run_indexer = parser.get('blockstack', 'enabled').lower() in ['1', 'true', 'on']

      if parser.has_option('blockstack', 'backup_frequency'):
         backup_frequency = int( parser.get('blockstack', 'backup_frequency'))

      if parser.has_option('blockstack', 'backup_max_age'):
         backup_max_age = int( parser.get('blockstack', 'backup_max_age') )

      if parser.has_option('blockstack', 'rpc_port'):
         rpc_port = int(parser.get('blockstack', 'rpc_port'))

      if parser.has_option("blockstack", "zonefiles"):
          zonefile_dir = parser.get("blockstack", "zonefiles")
    
      if parser.has_option('blockstack', 'announcers'):
         # must be a CSV of blockchain IDs
         announcer_list_str = parser.get('blockstack', 'announcers')
         announcer_list = filter( lambda x: len(x) > 0, announcer_list_str.split(",") )

         # validate each one
         valid = True
         for bid in announcer_list:
             if not is_name_valid( bid ):
                 log.error("Invalid blockchain ID '%s'" % bid)
                 valid = False

         if valid:
             announcers = ",".join(announcer_list)

      if parser.has_option('blockstack', 'server_version'):
         server_version = parser.get('blockstack', 'server_version')

      if parser.has_option('blockstack', 'atlas'):
         atlas_enabled = parser.get('blockstack', 'atlas')
         if atlas_enabled.lower() in ['true', '1', 'enabled', 'enabled', 'on']:
            atlas_enabled = True
         else:
            atlas_enabled = False

      if parser.has_option('blockstack', 'atlas_seeds'):
         atlas_seed_peers = parser.get('blockstack', 'atlas_seeds')

         # must be a CSV of host:port
         check_hostport_list(atlas_seed_peers)

      if parser.has_option('blockstack', 'atlasdb_path'):
         atlasdb_path = parser.get('blockstack', 'atlasdb_path')

      if parser.has_option('blockstack', 'atlas_blacklist'):
         atlas_blacklist = parser.get('blockstack', 'atlas_blacklist')

         # must be a CSV of host:port
         hostports = filter( lambda x: len(x) > 0, atlas_blacklist.split(",") )
         for hp in hostports:
             host, port = url_to_host_port( hp )
             assert host is not None and port is not None

      if parser.has_option('blockstack', 'atlas_hostname'):
         atlas_hostname = parser.get('blockstack', 'atlas_hostname')
    
      if parser.has_option('blockstack', 'atlas_port'):
         atlas_port = int(parser.get('blockstack', 'atlas_port'))

      if parser.has_option('blockstack', 'subdomaindb_path'):
         subdomaindb_path = parser.get('blockstack', 'subdomaindb_path')

   if os.environ.get(ATLAS_SEEDS_ENV_VAR, False):
       atlas_seed_peers = os.environ[ATLAS_SEEDS_ENV_VAR]
       check_hostport_list(atlas_seed_peers)

   if os.environ.get(ATLAS_HOSTNAME_ENV_VAR, False):
       atlas_hostname = os.environ[ATLAS_HOSTNAME_ENV_VAR]

   if os.path.exists( announce_path ):
       # load announcement list
       with open( announce_path, "r" ) as f:
           announce_text = f.readlines()

       all_announcements = [ a.strip() for a in announce_text ]
       unseen_announcements = []

       # find announcements we haven't seen yet
       for a in all_announcements:
           if a not in ANNOUNCEMENTS:
               unseen_announcements.append( a )

       announcements = ",".join( unseen_announcements )

   if zonefile_dir is not None and not os.path.exists( zonefile_dir ):
       try:
           os.makedirs( zonefile_dir, 0700 )
       except:
           pass

   if RPC_SERVER_IP is None:
       if atlas_hostname is None or atlas_hostname.lower() == '<stun>':
           real_atlas_hostname = get_atlas_hostname_stun()
           RPC_SERVER_IP = real_atlas_hostname

       elif atlas_hostname.lower() == '<host>':
           real_atlas_hostname = get_atlas_hostname_addrinfo(rpc_port)
           RPC_SERVER_IP = real_atlas_hostname
       
       else:
           log.debug('Using configuration-given Atlas hostname')
           real_atlas_hostname = atlas_hostname
           RPC_SERVER_IP = atlas_hostname

       if atlas_hostname is None and real_atlas_hostname is None:
           log.warning('No Atlas hostname could be determined, assuming 127.0.0.1')
           real_atlas_hostname = '127.0.0.1'
           RPC_SERVER_IP = real_atlas_hostname
   
       log.info('Atlas IP address is ({}, {})'.format(RPC_SERVER_IP, rpc_port))

   else:
       # already set
       real_atlas_hostname = RPC_SERVER_IP

   atlas_hostname = real_atlas_hostname
   RPC_SERVER_PORT = rpc_port

   blockstack_opts = {
       'rpc_port': rpc_port,
       'announcers': announcers,
       'announcements': announcements,
       'backup_frequency': backup_frequency,
       'backup_max_age': backup_max_age,
       'server_version': server_version,
       'atlas': atlas_enabled,
       'atlas_seeds': atlas_seed_peers,
       'atlasdb_path': atlasdb_path,
       'atlas_blacklist': atlas_blacklist,
       'atlas_hostname': atlas_hostname,
       'atlas_port': atlas_port,
       'zonefiles': zonefile_dir,
       'subdomaindb_path': subdomaindb_path,
       'enabled': run_indexer
   }

   # strip Nones
   for (k, v) in blockstack_opts.items():
      if v is None:
         del blockstack_opts[k]

   return blockstack_opts


def default_blockstack_api_opts(working_dir, config_file=None):
   """
   Get our default blockstack RESTful API opts from a config file,
   or from sane defaults.
   """

   from .util import url_to_host_port, url_protocol

   if config_file is None:
      config_file = virtualchain.get_config_filename(get_default_virtualchain_impl(), working_dir)

   parser = SafeConfigParser()
   parser.read(config_file)

   blockstack_api_opts = {}
   indexer_url = None
   api_port = DEFAULT_API_PORT
   api_host = DEFAULT_API_HOST
   run_api = True

   if parser.has_section('blockstack-api'):
      if parser.has_option('blockstack-api', 'enabled'):
          run_api = parser.get('blockstack-api', 'enabled').lower() in ['true', '1', 'on']

      if parser.has_option('blockstack-api', 'api_port'):
          api_port = int(parser.get('blockstack-api', 'api_port'))

      if parser.has_option('blockstack-api', 'api_host'):
          api_host = parser.get('blockstack-api', 'api_host')

      if parser.has_option('blockstack-api', 'indexer_url'):
          indexer_host, indexer_port = url_to_host_port(parser.get('blockstack-api', 'indexer_url'))
          indexer_protocol = url_protocol(parser.get('blockstack-api', 'indexer_url'))
          if indexer_protocol is None:
              indexer_protocol = 'http'

          indexer_url = parser.get('blockstack-api', 'indexer_url')

   if indexer_url is None:
       # try defaults
       indexer_url = 'http://localhost:{}'.format(RPC_SERVER_PORT)

   blockstack_api_opts = {
        'indexer_url': indexer_url,
        'api_host': api_host,
        'api_port': api_port,
        'enabled': run_api
   }

   # strip Nones
   for (k, v) in blockstack_api_opts.items():
      if v is None:
         del blockstack_api_opts[k]

   return blockstack_api_opts


def interactive_prompt(message, parameters, default_opts):
    """
    Prompt the user for a series of parameters
    Return a dict mapping the parameter name to the
    user-given value.
    """

    # pretty-print the message
    lines = message.split('\n')
    max_line_len = max([len(l) for l in lines])

    print('-' * max_line_len)
    print(message)
    print('-' * max_line_len)

    ret = {}
    for param in parameters:
        formatted_param = param
        prompt_str = '{}: '.format(formatted_param)
        if param in default_opts:
            prompt_str = '{} (default: "{}"): '.format(formatted_param, default_opts[param])

        try:
            value = raw_input(prompt_str)
        except KeyboardInterrupt:
            log.debug('Exiting on keyboard interrupt')
            sys.exit(0)

        if len(value) > 0:
            ret[param] = value
        elif param in default_opts:
            ret[param] = default_opts[param]
        else:
            ret[param] = None

    return ret


def find_missing(message, all_params, given_opts, default_opts, header=None, prompt_missing=True):
    """
    Find and interactively prompt the user for missing parameters,
    given the list of all valid parameters and a dict of known options.

    Return the (updated dict of known options, missing, num_prompted), with the user's input.
    """

    # are we missing anything?
    missing_params = list(set(all_params) - set(given_opts))

    num_prompted = 0

    if not missing_params:
        return given_opts, missing_params, num_prompted

    if not prompt_missing:
        # count the number missing, and go with defaults
        missing_values = set(default_opts) - set(given_opts)
        num_prompted = len(missing_values)
        given_opts.update(default_opts)

    else:
        if header is not None:
            print('-' * len(header))
            print(header)

        missing_values = interactive_prompt(message, missing_params, default_opts)
        num_prompted = len(missing_values)
        given_opts.update(missing_values)

    return given_opts, missing_params, num_prompted


def opt_strip(prefix, opts):
    """
    Given a dict of opts that start with prefix,
    remove the prefix from each of them.
    """

    ret = {}
    for opt_name, opt_value in opts.items():
        # remove prefix
        if opt_name.startswith(prefix):
            opt_name = opt_name[len(prefix):]

        ret[opt_name] = opt_value

    return ret

def check_hostport_list(hp_list):
    from .util import url_to_host_port
    hostports = filter( lambda x: len(x) > 0, hp_list.split(",") )
    for hp in hostports:
        host, port = url_to_host_port( hp )
        assert host is not None and port is not None

def opt_restore(prefix, opts):
    """
    Given a dict of opts, add the given prefix to each key
    """

    return {prefix + name: value for name, value in opts.items()}


def default_bitcoind_opts(config_file=None, prefix=False):
    """
    Get our default bitcoind options, such as from a config file,
    or from sane defaults
    """

    default_bitcoin_opts = virtualchain.get_bitcoind_config(config_file=config_file)

    # drop dict values that are None
    default_bitcoin_opts = {k: v for k, v in default_bitcoin_opts.items() if v is not None}

    # strip 'bitcoind_'
    if not prefix:
        default_bitcoin_opts = opt_strip('bitcoind_', default_bitcoin_opts)

    return default_bitcoin_opts


def default_working_dir():
    """
    Get the default configuration directory for blockstackd
    """
    import nameset.virtualchain_hooks as virtualchain_hooks
    return os.path.expanduser('~/.{}'.format(virtualchain_hooks.get_virtual_chain_name()))


def configure(working_dir, config_file=None, force=False, interactive=False):
   """
   Configure blockstack:  find and store configuration parameters to the config file.

   Optionally prompt for missing data interactively (with interactive=True).  Or, raise an exception
   if there are any fields missing.

   Optionally force a re-prompting for all configuration details (with force=True)

   Return {'blockstack': {...}, 'bitcoind': {...}, 'blockstack-api': {...}}
   """

   if config_file is None:
      # get input for everything
      config_file = virtualchain.get_config_filename(get_default_virtualchain_impl(), working_dir)

   if not os.path.exists( config_file ):
       # definitely ask for everything
       force = True

   log.debug("Load config from '%s'" % config_file)

   # get blockstack opts
   blockstack_opts = {}
   blockstack_opts_defaults = default_blockstack_opts(working_dir, config_file=config_file)
   blockstack_params = blockstack_opts_defaults.keys()

   if not force or not interactive:
       # default blockstack options
       blockstack_opts = default_blockstack_opts(working_dir, config_file=config_file )

   blockstack_msg = "Please enter blockstack configuration hints."

   blockstack_opts, missing_blockstack_opts, num_blockstack_opts_prompted = find_missing( blockstack_msg, \
                                                                                          blockstack_params, \
                                                                                          blockstack_opts, \
                                                                                          blockstack_opts_defaults, \
                                                                                          prompt_missing=interactive )

   blockstack_api_opts = {}
   blockstack_api_defaults = default_blockstack_api_opts(working_dir, config_file=config_file)
   blockstack_api_params = blockstack_api_defaults.keys()
   
   if not force or not interactive:
       # default blockstack API options
       blockstack_api_opts = default_blockstack_api_opts(working_dir, config_file=config_file)

   blockstack_api_msg = "Please enter blockstack RESTful API configuration hints."

   blockstack_api_opts, missing_blockstack_api_opts, num_blockstack_api_opts_prompted = find_missing( blockstack_api_msg, \
                                                                                                      blockstack_api_params, \
                                                                                                      blockstack_api_opts, \
                                                                                                      blockstack_api_defaults, \
                                                                                                      prompt_missing=interactive )

   bitcoind_message  = "Blockstack does not have enough information to connect\n"
   bitcoind_message += "to bitcoind.  Please supply the following parameters, or\n"
   bitcoind_message += "press [ENTER] to select the default value."

   bitcoind_opts = {}
   bitcoind_opts_defaults = default_bitcoind_opts( config_file=config_file )
   bitcoind_params = bitcoind_opts_defaults.keys()

   if not force or not interactive:
      # get default set of bitcoind opts
      bitcoind_opts = default_bitcoind_opts( config_file=config_file )


   # get any missing bitcoind fields
   bitcoind_opts, missing_bitcoin_opts, num_bitcoind_prompted = find_missing( bitcoind_message, \
                                                                              bitcoind_params, \
                                                                              bitcoind_opts, \
                                                                              bitcoind_opts_defaults, \
                                                                              prompt_missing=interactive )

   if not interactive and (len(missing_bitcoin_opts) > 0 or len(missing_blockstack_opts) > 0 or len(missing_blockstack_api_opts) > 0):
       # cannot continue
       raise Exception("Missing configuration fields: %s" % (",".join( missing_blockstack_opts + missing_bitcoin_opts + missing_blockstack_api_opts )) )

   ret = {
      'blockstack': blockstack_opts,
      'bitcoind': bitcoind_opts,
      'blockstack-api': blockstack_api_opts
   }

   # if we prompted, then save
   if num_bitcoind_prompted > 0 or num_blockstack_opts_prompted > 0 or num_blockstack_api_opts_prompted > 0 or \
      (not os.path.exists(config_file) and not interactive):
       print >> sys.stderr, "Saving configuration to %s" % config_file
   
       # always set version when writing
       config_opts = copy.deepcopy(ret)
       if not config_opts['blockstack'].has_key('server_version'):
           config_opts['blockstack']['server_version'] = VERSION

       if not config_opts['blockstack-api'].has_key('server_version'):
           config_opts['blockstack']['server_version'] = VERSION

       # if the config file doesn't exist, then set the version 
       # in ret as well, since it's what's written
       if not os.path.exists(config_file):
           ret['blockstack']['server_version'] = VERSION
           ret['blockstack-api']['server_version'] = VERSION

       write_config_file( config_opts, config_file )

   # prefix our bitcoind options, so they work with virtualchain
   ret['bitcoind'] = opt_restore("bitcoind_", ret['bitcoind'])
   return ret 


def write_config_file(opts, config_file):
    """
    Write our config file with the given options dict.
    Each key is a section name, and each value is the list of options.

    If the file exists, do not remove unaffected sections.  Instead,
    merge the sections in opts into the file.

    Return True on success
    Raise on error
    """
    parser = SafeConfigParser()

    if os.path.exists(config_file):
        parser.read(config_file)

    for sec_name in opts:
        sec_opts = opts[sec_name]

        if parser.has_section(sec_name):
            parser.remove_section(sec_name)

        parser.add_section(sec_name)
        for opt_name, opt_value in sec_opts.items():
            if opt_value is None:
                opt_value = ''

            parser.set(sec_name, opt_name, '{}'.format(opt_value))

    with open(config_file, 'w') as fout:
        os.fchmod(fout.fileno(), 0600)
        parser.write(fout)

    return True


def get_version_parts(whole, func):
    return [func(_.strip()) for _ in whole[0:3]]


def semver_newer(v1, v2):
    """
    Verify (as semantic versions) if v1 < v2
    Patch versions can be different
    """
    v1_parts = v1.split('.')
    v2_parts = v2.split('.')
    if len(v1_parts) < 3 or len(v2_parts) < 3:
        # one isn't a semantic version
        return False

    v1_major, v1_minor, v1_patch = get_version_parts(v1_parts, int)
    v2_major, v2_minor, v2_patch = get_version_parts(v2_parts, int)

    if v1_major > v2_major:
        return False

    if v1_major == v2_major and v1_minor >= v2_minor:
        return False

    return True


def versions_need_upgrade(v_from, v_to):
    version_upgrades = [
        # all semver mismatches before "0.17" require upgrade
        (lambda v : v[:2] < (0,17))
    ]

    v1 = tuple( int(x) for x in str(v_from).split('.') )
    v2 = tuple( int(x) for x in str(v_to).split('.') )
    if len(v1) < 3 or len(v2) < 3:
        return True # one isn't semver
    if v1[:2] == v2[:2]:
        return False # same semver, no upgrade
    # mismatch, see if this version requires a migration
    for version_needs_upgrade_check in version_upgrades:
        if version_needs_upgrade_check(v1):
            return True
    return False


def load_configuration(working_dir):
    """
    Load the system configuration and set global variables
    Return the configuration of the node on success.
    Return None on failure
    """

    import nameset.virtualchain_hooks as virtualchain_hooks

    # acquire configuration, and store it globally
    opts = configure(working_dir)
    blockstack_opts = opts.get('blockstack', None)
    blockstack_api_opts = opts.get('blockstack-api', None)
    bitcoin_opts = opts['bitcoind']

    # config file version check
    config_server_version = blockstack_opts.get('server_version', None)
    if (config_server_version is None or versions_need_upgrade(config_server_version, VERSION)):
       print >> sys.stderr, "Obsolete or unrecognizable config file ({}): '{}' != '{}'".format(virtualchain.get_config_filename(virtualchain_hooks, working_dir), config_server_version, VERSION)
       print >> sys.stderr, 'Please see the release notes for version {} for instructions to upgrade (in the release-notes/ folder).'.format(VERSION)
       return None

    # store options
    set_bitcoin_opts( bitcoin_opts )
    set_blockstack_opts( blockstack_opts )
    set_blockstack_api_opts( blockstack_api_opts )

    return {
        'bitcoind': bitcoin_opts,
        'blockstack': blockstack_opts,
        'blockstack-api': blockstack_api_opts
    }

