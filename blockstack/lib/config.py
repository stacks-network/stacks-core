#!/usr/bin/env python
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
from ConfigParser import SafeConfigParser
import pybitcoin
import json

try:
    from ..version import __version__
except:
    if os.environ.get("BLOCKSTACK_TEST") != "1":
        print "Try setting BLOCKSTACK_TEST=1"
        raise
    else:
        __version__ = "0.14.0"

import blockstack_client
from blockstack_client.config import DEFAULT_OP_RETURN_FEE, DEFAULT_DUST_FEE, DEFAULT_OP_RETURN_VALUE, DEFAULT_FEE_PER_KB, url_to_host_port
import virtualchain
log = virtualchain.get_logger("blockstack-server")

DEBUG = True
VERSION = __version__

# namespace version
BLOCKSTACK_VERSION = 1

""" constants
"""

AVERAGE_MINUTES_PER_BLOCK = 10
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
    '02edbaa730f241960bcd1a50c718fac7f9d4874f460c1f6db0a3941094e7685ef9'
]


""" blockstack configs
"""
MAX_NAMES_PER_SENDER = 25                # a single sender script can own up to this many names

""" RPC server configs
"""
if os.getenv("BLOCKSTACK_TEST") is not None:
    RPC_SERVER_PORT = 16264
else:
    RPC_SERVER_PORT = 6264

RPC_MAX_ZONEFILE_LEN = 4096     # 4KB
RPC_MAX_PROFILE_LEN = 1024000   # 1MB
RPC_MAX_DATA_LEN = 10240000     # 10MB

""" block indexing configs
"""
REINDEX_FREQUENCY = 300 # seconds
if os.environ.get("BLOCKSTACK_TEST") == "1":
    REINDEX_FREQUENCY = 1

FIRST_BLOCK_MAINNET = 373601

if os.environ.get("BLOCKSTACK_TEST", None) == "1" and os.environ.get("BLOCKSTACK_TEST_FIRST_BLOCK", None) is not None:
    FIRST_BLOCK_MAINNET = int(os.environ.get("BLOCKSTACK_TEST_FIRST_BLOCK"))

elif os.environ.get("BLOCKSTACK_TESTNET", None) == "1" and os.environ.get("BLOCKSTACK_TESTNET_FIRST_BLOCK", None) is not None:
    FIRST_BLOCK_MAINNET = int(os.environ.get("BLOCKSTACK_TESTNET_FIRST_BLOCK"))

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
    * PRICE_MULTIPLIER:                 constant to multiply name and namespace prices by
"""
EPOCH_FIELDS = [
    "end_block",
    "namespaces",
    "features"
]

EPOCH_NAMESPACE_FIELDS = [
    "NAMESPACE_LIFETIME_MULTIPLIER",
    "PRICE_MULTIPLIER"
]

# epoch features
EPOCH_FEATURE_MULTISIG = "BLOCKSTACK_MULTISIG"

# when epochs end (-1 means "never")
EPOCH_NOW = -1
EPOCH_1_END_BLOCK = 436650      # F-Day 2016
EPOCH_2_END_BLOCK = EPOCH_NOW

EPOCH_1_NAMESPACE_LIFETIME_MULTIPLIER_id = 1
EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER_id = 2

EPOCH_1_PRICE_MULTIPLIER_id = 1.0
EPOCH_2_PRICE_MULTIPLIER_id = 1.0

EPOCH_1_FEATURES = []
EPOCH_2_FEATURES = [EPOCH_FEATURE_MULTISIG]

# minimum block height at which this server can run
EPOCH_MINIMUM = EPOCH_1_END_BLOCK + 1

NUM_EPOCHS = 2
for i in xrange(1, NUM_EPOCHS+1):
    # epoch lengths can be altered by the test framework, for ease of tests
    if os.environ.get("BLOCKSTACK_EPOCH_%s_END_BLOCK" % i, None) is not None and os.environ.get("BLOCKSTACK_TEST", None) == "1":
        exec("EPOCH_%s_END_BLOCK = int(%s)" % (i, os.environ.get("BLOCKSTACK_EPOCH_%s_END_BLOCK" % i)))
        log.warn("EPOCH_%s_END_BLOCK = %s" % (i, eval("EPOCH_%s_END_BLOCK" % i)))

    if os.environ.get("BLOCKSTACK_EPOCH_%s_PRICE_MULTIPLIER" % i, None) is not None and os.environ.get("BLOCKSTACK_TEST", None) == "1":
        exec("EPOCH_%s_PRICE_MULTIPLIER_id = float(%s)" % (i, os.environ.get("BLOCKSTACK_EPOCH_%s_PRICE_MULTIPLIER" % i)))
        log.warn("EPOCH_%s_PRICE_MULTIPLIER_id = %s" % (i, eval("EPOCH_%s_PRICE_MULTIPLIER_id" % i)))

    if os.environ.get("BLOCKSTACK_EPOCH_%s_NAMESPACE_LIFETIME_MULTIPLIER" % i, None) is not None and os.environ.get("BLOCKSTACK_TEST", None) == "1":
        exec("EPOCH_%s_NAMESPACE_LIFETIME_MULTIPLIER_id = int(%s)" % (i, os.environ.get("BLOCKSTACK_EPOCH_%s_NAMESPACE_LIFETIME_MULTIPLIER" % i)))
        log.warn("EPOCH_%s_NAMESPACE_LIFETIME_MULTIPLIER_id = %s" % (i, eval("EPOCH_%s_NAMESPACE_LIFETIME_MULTIPLIER_id" % i)))

del i

# epoch definitions
# each epoch begins at the block after 'end_block'.
# the first epoch begins at FIRST_BLOCK_MAINNET
EPOCHS = [
    {
        # epoch 1
        "end_block": EPOCH_1_END_BLOCK,
        "namespaces": {
            "id": {
                "NAMESPACE_LIFETIME_MULTIPLIER": EPOCH_1_NAMESPACE_LIFETIME_MULTIPLIER_id,
                "PRICE_MULTIPLIER": EPOCH_1_PRICE_MULTIPLIER_id
            }
        },
        "features": EPOCH_1_FEATURES
    },
    {
        # epoch 2
        "end_block": EPOCH_2_END_BLOCK,
        "namespaces": {
            "id": {
                "NAMESPACE_LIFETIME_MULTIPLIER": EPOCH_2_NAMESPACE_LIFETIME_MULTIPLIER_id,
                "PRICE_MULTIPLIER": EPOCH_2_PRICE_MULTIPLIER_id
            }
        },
        "features": EPOCH_2_FEATURES
    }
]

# if we're testing, then add the same rules for the 'test' namespace
if os.environ.get("BLOCKSTACK_TEST", None) == "1":
    for i in xrange(0, len(EPOCHS)):
        EPOCHS[i]['namespaces']['test'] = EPOCHS[i]['namespaces']['id']

# epoch self-consistency check 
for epoch_field in EPOCH_FIELDS:
    for i in xrange(0, len(EPOCHS)):
        if not EPOCHS[i].has_key(epoch_field):
            raise Exception("Missing field '%s' at epoch %s" % (epoch_field, i))

for i in xrange(0, len(EPOCHS)):
    for nsid in EPOCHS[i]['namespaces']:
        for epoch_field in EPOCH_NAMESPACE_FIELDS:
            if not EPOCHS[i]['namespaces'][nsid].has_key(epoch_field):
                raise Exception("Missing field '%s' at epoch %s in namespace '%s'" % (epoch_field, i, nsid))

if EPOCHS[len(EPOCHS)-1]['end_block'] != EPOCH_NOW:
    raise Exception("Last epoch ends at %s" % EPOCHS[len(EPOCHS)-1]['end_block'])

for i in xrange(0, len(EPOCHS)-1):
    if EPOCHS[i]['end_block'] < 0:
        raise Exception("Invalid end block for epoch %s" % (i+1))

    if EPOCHS[i]['end_block'] >= EPOCHS[i+1]['end_block'] and EPOCHS[i+1]['end_block'] > 0:
        raise Exception("Invalid epoch block range at epoch %s" % (i+1))


del epoch_field
del i 
del nsid

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

NAME_SCHEME = MAGIC_BYTES + NAME_REGISTRATION

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

# set of operations that have fees 
OPCODE_HAVE_FEES = [
    "NAMESPACE_PREORDER",
    "NAME_PREORDER",
    "NAME_RENEWAL"
]

# set of ops that have no state to record 
OPCODE_STATELESS_OPS = [
    "ANNOUNCE"
]


NAMESPACE_LIFE_INFINITE = 0xffffffff

OP_RETURN_MAX_SIZE = 40

""" name price configs
"""

SATOSHIS_PER_BTC = 10**8
PRICE_FOR_1LETTER_NAMES = 10*SATOSHIS_PER_BTC
PRICE_DROP_PER_LETTER = 10
PRICE_DROP_FOR_NON_ALPHABETIC = 10
ALPHABETIC_PRICE_FLOOR = 10**4

NAME_COST_UNIT = 100    # 100 satoshis

NAMESPACE_1_CHAR_COST = 400 * SATOSHIS_PER_BTC        # ~$96,000
NAMESPACE_23_CHAR_COST = 40 * SATOSHIS_PER_BTC        # ~$9,600
NAMESPACE_4567_CHAR_COST = 4 * SATOSHIS_PER_BTC       # ~$960
NAMESPACE_8UP_CHAR_COST = 0.4 * SATOSHIS_PER_BTC      # ~$96

NAMESPACE_PREORDER_EXPIRE = BLOCKS_PER_DAY      # namespace preorders expire after 1 day, if not revealed
NAMESPACE_REVEAL_EXPIRE = BLOCKS_PER_YEAR       # namespace reveals expire after 1 year, if not readied.

if os.environ.get("BLOCKSTACK_TEST", None) is not None:
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
if os.environ.get("BLOCKSTACK_TEST", None) == "1":
    NUM_CONFIRMATIONS = 0
    log.warning("NUM_CONFIRMATIONS = %s" % NUM_CONFIRMATIONS)

# burn address for fees (the address of public key 0x0000000000000000000000000000000000000000)
BLOCKSTACK_BURN_PUBKEY_HASH = "0000000000000000000000000000000000000000"
BLOCKSTACK_BURN_ADDRESS = virtualchain.hex_hash160_to_address( BLOCKSTACK_BURN_PUBKEY_HASH )   # "1111111111111111111114oLvT2"

# default namespace record (i.e. for names with no namespace ID)
NAMESPACE_DEFAULT = {
   'opcode': 'NAMESPACE_REVEAL',
   'lifetime': EXPIRATION_PERIOD,
   'coeff': 15,
   'base': 15,
   'buckets': [15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15],
   'version': BLOCKSTACK_VERSION,
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

# global mutable state 
blockstack_opts = None
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
    if epoch_config['namespaces'].has_key(namespace_id):
        return epoch_config['namespaces'][namespace_id]['NAMESPACE_LIFETIME_MULTIPLIER']
    else:
        return 1


def get_epoch_price_multiplier( block_height, namespace_id ):
    """
    what's the price multiplier for this epoch?
    """
    epoch_config = get_epoch_config( block_height )
    if epoch_config['namespaces'].has_key(namespace_id):
        return epoch_config['namespaces'][namespace_id]['PRICE_MULTIPLIER']
    else:
        return 1


def epoch_has_multisig( block_height ):
    """
    Is multisig available in this epoch?
    """
    epoch_config = get_epoch_config( block_height )
    if EPOCH_FEATURE_MULTISIG in epoch_config['features']:
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


blockstack_client_session = None
blockstack_client_session_opts = None

def op_get_opcode_name( op_string ):
    """
    Get the name of an opcode, given the operation's 'op' byte sequence.
    """
    return blockstack_client.config.op_get_opcode_name( op_string )


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
   blockstack_impl = virtualchain.get_implementation()
   if blockstack_impl is None:
       blockstack_impl = virtualchain_hooks 

   return blockstack_impl


def get_announce_filename( working_dir=None ):
   """
   Get the path to the file that stores all of the announcements.
   """

   if working_dir is None:
       working_dir = virtualchain.get_working_dir()

   announce_filepath = os.path.join( working_dir, virtualchain.get_implementation().get_virtual_chain_name() ) + ".announce"
   return announce_filepath


def get_zonefile_dir( working_dir=None ):
    """
    Get the path to the directory to hold any zonefiles we download.
    """

    if working_dir is None:
       working_dir = virtualchain.get_working_dir()

    zonefile_dir = os.path.join( working_dir, "zonefiles" )
    return zonefile_dir


def get_blockstack_client_session( new_blockstack_client_session_opts=None ):
    """
    Get or instantiate our storage API session.
    """
    global blockstack_client_session
    global blockstack_client_session_opts

    # do we have storage?
    if blockstack_client is None:
        return None

    opts = None
    if new_blockstack_client_session_opts is not None:
        opts = new_blockstack_client_session_opts
    else:
        opts = blockstack_client.get_config()

    if opts is None:
        return None

    blockstack_client_session = blockstack_client.session( conf=opts )
    if blockstack_client_session is not None:

        if new_blockstack_client_session_opts is not None:
            blockstack_client_session_opts = new_blockstack_client_session_opts

    return blockstack_client_session


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


def get_indexing_lockfile(impl=None):
    """
    Return path to the indexing lockfile
    """
    return os.path.join( virtualchain.get_working_dir(impl=impl), "blockstack-server.indexing" )


def is_indexing(impl=None):
    """
    Is the blockstack daemon synchronizing with the blockchain?
    """
    indexing_path = get_indexing_lockfile(impl=impl)
    if os.path.exists( indexing_path ):
        return True
    else:
        return False


def set_indexing( flag, impl=None ):
    """
    Set a flag in the filesystem as to whether or not we're indexing.
    """
    indexing_path = get_indexing_lockfile(impl=impl)
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


def set_running( status ):
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


def fast_getlastblock( impl=None ):
    """
    Fast way to get the last block processed,
    without loading the db.
    """
    lastblock_path = virtualchain.get_lastblock_filename( impl=impl )
    try:
        with open(lastblock_path, "r") as f:
            data = f.read().strip()
            return int(data)

    except:
        log.exception("Failed to read: %s" % lastblock_path)
        return None


def store_announcement( announcement_hash, announcement_text, working_dir=None, force=False ):
   """
   Store a new announcement locally, atomically.
   """

   if working_dir is None:
       working_dir = virtualchain.get_working_dir()

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

           log.debug("Merge announcement list %s" % failed_paht )
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
   if sys.platform == 'win32' and os.path.exists( announcement_filename_tmp ):
       try:
           os.unlink( announcement_filename_tmp )
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


def default_blockstack_opts( config_file=None, virtualchain_impl=None ):
   """
   Get our default blockstack opts from a config file
   or from sane defaults.
   """

   if config_file is None:
      config_file = virtualchain.get_config_filename()

   announce_path = get_announce_filename( virtualchain.get_working_dir(impl=virtualchain_impl) )

   parser = SafeConfigParser()
   parser.read( config_file )

   blockstack_opts = {}
   contact_email = None
   announcers = "judecn.id,muneeb.id,shea256.id"
   announcements = None
   backup_frequency = 144   # once a day; 10 minute block time
   backup_max_age = 1008    # one week
   rpc_port = RPC_SERVER_PORT 
   serve_zonefiles = True
   serve_profiles = False
   serve_data = False
   zonefile_dir = os.path.join( os.path.dirname(config_file), "zonefiles")
   analytics_key = None
   zonefile_storage_drivers = "disk,dht"
   profile_storage_drivers = "disk"
   data_storage_drivers = "disk"
   redirect_data = False
   data_servers = None
   server_version = None
   atlas_enabled = True
   atlas_seed_peers = "node.blockstack.org:%s" % RPC_SERVER_PORT
   atlasdb_path = os.path.join( os.path.dirname(config_file), "atlas.db" )
   atlas_blacklist = ""
   atlas_hostname = socket.gethostname()

   if parser.has_section('blockstack'):

      if parser.has_option('blockstack', 'backup_frequency'):
         backup_frequency = int( parser.get('blockstack', 'backup_frequency'))

      if parser.has_option('blockstack', 'backup_max_age'):
         backup_max_age = int( parser.get('blockstack', 'backup_max_age') )

      if parser.has_option('blockstack', 'email'):
         contact_email = parser.get('blockstack', 'email')

      if parser.has_option('blockstack', 'rpc_port'):
         rpc_port = int(parser.get('blockstack', 'rpc_port'))

      if parser.has_option('blockstack', 'serve_zonefiles'):
          serve_zonefiles = parser.get('blockstack', 'serve_zonefiles')
          if serve_zonefiles.lower() in ['1', 'yes', 'true', 'on']:
              serve_zonefiles = True
          else:
              serve_zonefiles = False

      if parser.has_option('blockstack', 'serve_profiles'):
          serve_profiles = parser.get('blockstack', 'serve_profiles')
          if serve_profiles.lower() in ['1', 'yes', 'true', 'on']:
              serve_profiles = True
          else:
              serve_profiles = False

      if parser.has_option('blockstack', 'serve_data'):
          serve_data = parser.get('blockstack', 'serve_data')
          if serve_data.lower() in ['1', 'yes', 'true', 'on']:
              serve_data = True
          else:
              serve_data = False

      if parser.has_option("blockstack", "zonefile_storage_drivers"):
          zonefile_storage_drivers = parser.get("blockstack", "zonefile_storage_drivers")

      if parser.has_option("blockstack", "profile_storage_drivers"):
          profile_storage_drivers = parser.get("blockstack", "profile_storage_drivers")

      if parser.has_option("blockstack", "zonefiles"):
          zonefile_dir = parser.get("blockstack", "zonefiles")
    
      if parser.has_option('blockstack', 'redirect_data'):
          redirect_data = parser.get('blockstack', 'redirect_data')
          if redirect_data.lower() in ['1', 'yes', 'true', 'on']:
              redirect_data = True
          else:
              redirect_data = False

      if parser.has_option('blockstack', 'data_servers'):
          data_servers = parser.get('blockstack', 'data_servers')

          # must be a CSV of host:port
          hostports = filter( lambda x: len(x) > 0, data_servers.split(",") )
          for hp in hostports:
              host, port = url_to_host_port( hp )
              assert host is not None and port is not None


      if parser.has_option('blockstack', 'announcers'):
         # must be a CSV of blockchain IDs
         announcer_list_str = parser.get('blockstack', 'announcers')
         announcer_list = filter( lambda x: len(x) > 0, announcer_list_str.split(",") )

         import scripts

         # validate each one
         valid = True
         for bid in announcer_list:
             if not scripts.is_name_valid( bid ):
                 log.error("Invalid blockchain ID '%s'" % bid)
                 valid = False

         if valid:
             announcers = ",".join(announcer_list)

      if parser.has_option('blockstack', 'analytics_key'):
         analytics_key = parser.get('blockstack', 'analytics_key')

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
         hostports = filter( lambda x: len(x) > 0, atlas_seed_peers.split(",") )
         for hp in hostports:
             host, port = url_to_host_port( hp )
             assert host is not None and port is not None

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

   blockstack_opts = {
       'rpc_port': rpc_port,
       'email': contact_email,
       'announcers': announcers,
       'announcements': announcements,
       'backup_frequency': backup_frequency,
       'backup_max_age': backup_max_age,
       'serve_zonefiles': serve_zonefiles,
       'zonefile_storage_drivers': zonefile_storage_drivers,
       'serve_profiles': serve_profiles,
       'profile_storage_drivers': profile_storage_drivers,
       'serve_data': serve_data,
       'data_storage_drivers': data_storage_drivers,
       'redirect_data': redirect_data,
       'data_servers': data_servers,
       'analytics_key': analytics_key,
       'server_version': server_version,
       'atlas': atlas_enabled,
       'atlas_seeds': atlas_seed_peers,
       'atlasdb_path': atlasdb_path,
       'atlas_blacklist': atlas_blacklist,
       'atlas_hostname': atlas_hostname,
       'zonefiles': zonefile_dir,
   }

   # strip Nones
   for (k, v) in blockstack_opts.items():
      if v is None:
         del blockstack_opts[k]

   return blockstack_opts


def configure( config_file=None, force=False, interactive=True ):
   """
   Configure blockstack:  find and store configuration parameters to the config file.

   Optionally prompt for missing data interactively (with interactive=True).  Or, raise an exception
   if there are any fields missing.

   Optionally force a re-prompting for all configuration details (with force=True)

   Return {'blockstack': {...}, 'bitcoind': {...}}
   """

   if config_file is None:
      try:
         # get input for everything
         config_file = virtualchain.get_config_filename()
      except:
         raise

   if not os.path.exists( config_file ):
       # definitely ask for everything
       force = True

   log.debug("Load config from '%s'" % config_file)

   # get blockstack opts
   blockstack_opts = {}
   blockstack_opts_defaults = default_blockstack_opts( config_file=config_file )
   blockstack_params = blockstack_opts_defaults.keys()

   if not force:

       # default blockstack options
       blockstack_opts = default_blockstack_opts( config_file=config_file )

   blockstack_msg = "ADVANCED USERS ONLY.\nPlease enter blockstack configuration hints."

   # NOTE: disabled
   blockstack_opts, missing_blockstack_opts, num_blockstack_opts_prompted = blockstack_client.config.find_missing( blockstack_msg, \
                                                                                                                   blockstack_params, \
                                                                                                                   blockstack_opts, \
                                                                                                                   blockstack_opts_defaults, \
                                                                                                                   prompt_missing=False )

   bitcoind_message  = "Blockstack does not have enough information to connect\n"
   bitcoind_message += "to bitcoind.  Please supply the following parameters, or\n"
   bitcoind_message += "press [ENTER] to select the default value."

   bitcoind_opts = {}
   bitcoind_opts_defaults = blockstack_client.config.default_bitcoind_opts( config_file=config_file )
   bitcoind_params = bitcoind_opts_defaults.keys()

   if not force:

      # get default set of bitcoind opts
      bitcoind_opts = blockstack_client.config.default_bitcoind_opts( config_file=config_file )


   # get any missing bitcoind fields
   bitcoind_opts, missing_bitcoin_opts, num_bitcoind_prompted = blockstack_client.config.find_missing( bitcoind_message, \
                                                                                                       bitcoind_params, \
                                                                                                       bitcoind_opts, \
                                                                                                       bitcoind_opts_defaults, \
                                                                                                       prompt_missing=interactive )

   if not interactive and (len(missing_bitcoin_opts) > 0 or len(missing_blockstack_opts) > 0):
       # cannot continue
       raise Exception("Missing configuration fields: %s" % (",".join( missing_blockstack_opts + missing_bitcoin_opts )) )

   # ask for contact info, so we can send out notifications for bugfixes and upgrades
   if blockstack_opts.get('email', None) is None:
       email_msg = "Would you like to receive notifications\n"
       email_msg+= "from the developers when there are critical\n"
       email_msg+= "updates available to install?\n\n"
       email_msg+= "If so, please enter your email address here.\n"
       email_msg+= "If not, leave this field blank.\n\n"
       email_msg+= "Your email address will be used solely\n"
       email_msg+= "for this purpose.\n"
       email_opts, _, email_prompted = blockstack_client.config.find_missing( email_msg, ['email'], {}, {'email': ''}, prompt_missing=interactive )

       # merge with blockstack section
       num_blockstack_opts_prompted += 1
       blockstack_opts['email'] = email_opts['email']

   ret = {
      'blockstack': blockstack_opts,
      'bitcoind': bitcoind_opts
   }

   # if we prompted, then save
   if num_bitcoind_prompted > 0 or num_blockstack_opts_prompted > 0:
       print >> sys.stderr, "Saving configuration to %s" % config_file
   
       # always set version when writing
       config_opts = copy.deepcopy(ret)
       if not config_opts['blockstack'].has_key('server_version'):
           config_opts['blockstack']['server_version'] = VERSION

       # if the config file doesn't exist, then set the version 
       # in ret as well, since it's what's written
       if not os.path.exists(config_file):
           ret['blockstack']['server_version'] = VERSION

       blockstack_client.config.write_config_file( config_opts, config_file )

   # prefix our bitcoind options, so they work with virtualchain
   ret['bitcoind'] = blockstack_client.config.opt_restore("bitcoind_", ret['bitcoind'])
   return ret 


