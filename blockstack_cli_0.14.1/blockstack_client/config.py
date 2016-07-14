#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
import logging
import copy
import traceback
import uuid

import virtualchain
from blockstack_utxo import *

from binascii import hexlify

from ConfigParser import SafeConfigParser

from version import __version__

DEBUG = False
if os.environ.get("BLOCKSTACK_TEST") is not None and os.environ.get("BLOCKSTACK_TEST_NODEBUG") is None:
    DEBUG = True

if os.environ.get("BLOCKSTACK_DEBUG") is not None:
    DEBUG = True

VERSION = __version__

DEFAULT_BLOCKSTACKD_PORT = 6264     # blockstackd port
DEFAULT_BLOCKSTACKD_SERVER = "node.blockstack.org"

DEFAULT_API_PORT = 6270     # RPC endpoint port

# initialize to default settings
BLOCKSTACKD_SERVER = DEFAULT_BLOCKSTACKD_SERVER
BLOCKSTACKD_PORT = DEFAULT_BLOCKSTACKD_PORT
WALLET_PASSWORD_LENGTH = 8

BLOCKSTACK_METADATA_DIR = os.path.expanduser("~/.blockstack/metadata")
BLOCKSTACK_DEFAULT_STORAGE_DRIVERS = "disk,blockstack_resolver,blockstack_server,http,dht"

# storage drivers that must successfully acknowledge each write
BLOCKSTACK_REQUIRED_STORAGE_DRIVERS_WRITE = "disk,blockstack_server"

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
FIRST_BLOCK_TIME_UTC = 1441737751 

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

# borrowed from Blockstack
# these never change, so it's fine to duplicate them here
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

# borrowed from Blockstack
# these never change, so it's fine to duplicate them here
NAMEREC_FIELDS = [
    'name',                 # the name itself
    'value_hash',           # the hash of the name's associated profile
    'sender',               # the scriptPubKey hex that owns this name (identifies ownership)
    'sender_pubkey',        # (OPTIONAL) the public key
    'address',              # the address of the sender

    'block_number',         # the block number when this name record was created (preordered for the first time)
    'preorder_block_number', # the block number when this name was last preordered
    'first_registered',     # the block number when this name was registered by the current owner
    'last_renewed',         # the block number when this name was renewed by the current owner
    'revoked',              # whether or not the name is revoked

    'op',                   # byte sequence describing the last operation to affect this name
    'txid',                 # the ID of the last transaction to affect this name
    'vtxindex',             # the index in the block of the transaction.
    'op_fee',               # the value of the last Blockstack-specific burn fee paid for this name (i.e. from preorder or renew)

    'importer',             # (OPTIONAL) if this name was imported, this is the importer's scriptPubKey hex
    'importer_address',     # (OPTIONAL) if this name was imported, this is the importer's address
]

# borrowed from Blockstack
# these never change, so it's fine to duplicate them here
NAMESPACE_FIELDS = [
    'namespace_id',         # human-readable namespace ID
    'namespace_id_hash',    # hash(namespace_id,sender,reveal_addr) from the preorder (binds this namespace to its preorder)
    'version',              # namespace rules version

    'sender',               # the scriptPubKey hex script that identifies the preorderer
    'sender_pubkey',        # if sender is a p2pkh script, this is the public key
    'address',              # address of the sender, from the scriptPubKey
    'recipient',            # the scriptPubKey hex script that identifies the revealer.
    'recipient_address',    # the address of the revealer
    'block_number',         # block number at which this namespace was preordered
    'reveal_block',         # block number at which this namespace was revealed

    'op',                   # byte code identifying this operation to Blockstack
    'txid',                 # transaction ID at which this namespace was revealed
    'vtxindex',             # the index in the block where the tx occurs

    'lifetime',             # how long names last in this namespace (in number of blocks)
    'coeff',                # constant multiplicative coefficient on a name's price
    'base',                 # exponential base of a name's price
    'buckets',              # array that maps name length to the exponent to which to raise 'base' to
    'nonalpha_discount',    # multiplicative coefficient that drops a name's price if it has non-alpha characters
    'no_vowel_discount',    # multiplicative coefficient that drops a name's price if it has no vowels
]

# borrowed from Blockstack
# these never change, so it's fine to duplicate them here
OPFIELDS = {
    NAME_IMPORT: NAMEREC_FIELDS + [
        'recipient',            # scriptPubKey hex that identifies the name recipient
        'recipient_address'     # address of the recipient
    ],
    NAMESPACE_PREORDER: [
        'namespace_id_hash',    # hash(namespace_id,sender,reveal_addr)
        'consensus_hash',       # consensus hash at the time issued
        'op',                   # bytecode describing the operation (not necessarily 1 byte)
        'op_fee',               # fee paid for the namespace to the burn address
        'txid',                 # transaction ID
        'vtxindex',             # the index in the block where the tx occurs
        'block_number',         # block number at which this transaction occurred
        'sender',               # scriptPubKey hex from the principal that issued this preorder (identifies the preorderer)
        'sender_pubkey',        # if sender is a p2pkh script, this is the public key
        'address'               # address from the scriptPubKey
    ],
    NAMESPACE_REVEAL: NAMESPACE_FIELDS,
    NAMESPACE_READY: NAMESPACE_FIELDS + [
        'ready_block',      # block number at which the namespace was readied
    ],
    NAME_PREORDER: [
         'preorder_name_hash',  # hash(name,sender,register_addr)
         'consensus_hash',      # consensus hash at time of send
         'sender',              # scriptPubKey hex that identifies the principal that issued the preorder
         'sender_pubkey',       # if sender is a pubkeyhash script, then this is the public key
         'address',             # address from the sender's scriptPubKey
         'block_number',        # block number at which this name was preordered for the first time

         'op',                  # blockstack bytestring describing the operation
         'txid',                # transaction ID
         'vtxindex',            # the index in the block where the tx occurs
         'op_fee',              # blockstack fee (sent to burn address)
    ],
    NAME_REGISTRATION: NAMEREC_FIELDS + [
        'recipient',            # scriptPubKey hex script that identifies the principal to own this name
        'recipient_address'     # principal's address from the scriptPubKey in the transaction
    ],
    NAME_REVOKE: NAMEREC_FIELDS,
    NAME_TRANSFER: NAMEREC_FIELDS +  [
        'name_hash128',         # hash(name)
        'consensus_hash',       # consensus hash when this operation was sent
        'keep_data'             # whether or not to keep the profile data associated with the name when transferred
    ],
    NAME_UPDATE: NAMEREC_FIELDS + [
        'name_hash128',         # hash(name,consensus_hash)
        'consensus_hash'        # consensus hash when this update was sent
    ]
}

# borrowed from Blockstack
# never changes so safe to duplicate to avoid gratuitous imports
# op-return formats
# Byte-lengths of fields
LENGTHS = {
    'magic_bytes': 2,
    'opcode': 1,
    'preorder_name_hash': 20,
    'consensus_hash': 16,
    'namelen': 1,
    'name_min': 1,
    'name_max': 34,
    'name_hash': 16,
    'update_hash': 20,
    'data_hash': 20,
    'blockchain_id_name': 37,
    'blockchain_id_namespace_life': 4,
    'blockchain_id_namespace_coeff': 1,
    'blockchain_id_namespace_base': 1,
    'blockchain_id_namespace_buckets': 8,
    'blockchain_id_namespace_discounts': 1,
    'blockchain_id_namespace_version': 2,
    'blockchain_id_namespace_id': 19,
    'announce': 20,
    'max_op_length': 40
}


# namespace version
BLOCKSTACK_VERSION = 1
NAME_SCHEME = MAGIC_BYTES + NAME_REGISTRATION
 
# burn address for fees (the address of public key 0x0000000000000000000000000000000000000000)
BLOCKSTACK_BURN_PUBKEY_HASH = "0000000000000000000000000000000000000000"
BLOCKSTACK_BURN_ADDRESS = "1111111111111111111114oLvT2"

# borrowed from Blockstack
# never changes, so safe to duplicate to avoid gratuitous imports
MAXIMUM_NAMES_PER_ADDRESS = 25

MAX_RPC_LEN = 1024 * 1024 * 1024

MAX_NAME_LENGTH = 37        # taken from blockstack-server

CONFIG_FILENAME = "client.ini"
WALLET_FILENAME = "wallet.json"

if os.environ.get("BLOCKSTACK_TEST", None) == "1":
    # testing 
    CONFIG_PATH = os.environ.get("BLOCKSTACK_CLIENT_CONFIG", None)
    assert CONFIG_PATH is not None, "BLOCKSTACK_CLIENT_CONFIG not set"

    CONFIG_DIR = os.path.dirname(CONFIG_PATH)

else:
    CONFIG_DIR = os.path.expanduser("~/.blockstack")
    CONFIG_PATH = os.path.join(CONFIG_DIR, CONFIG_FILENAME)

WALLET_PATH = os.path.join(CONFIG_DIR, "wallet.json")
SPV_HEADERS_PATH = os.path.join(CONFIG_DIR, "blockchain-headers.dat")
DEFAULT_QUEUE_PATH = os.path.join(CONFIG_DIR, "queues.db")

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

# approximate transaction sizes, for when the user has no balance
# over-estimations, to be safe
APPROX_PREORDER_TX_LEN = 620
APPROX_REGISTER_TX_LEN = 620
APPROX_UPDATE_TX_LEN = 1240
APPROX_TRANSFER_TX_LEN = 1240
APPROX_RENEWAL_TX_LEN = 1240
APPROX_REVOKE_TX_LEN = 1240

DEFAULT_BLOCKCHAIN_READER = "blockcypher"
DEFAULT_BLOCKCHAIN_WRITER = "blockcypher"

SUPPORTED_UTXO_PROMPT_MESSAGES = {
    "blockcypher": "Please enter your Blockcypher API token.",
    "blockchain_info": "Please enter your blockchain.info API token.",
    "bitcoind_utxo": "Please enter your fully-indexed bitcoind node information.",
    "blockstack_utxo": "Please enter your Blockstack server info.",
    "mock_utxo": "Mock UTXO provider.  Do not use in production."
}

def get_logger( debug=DEBUG ):
    logger = virtualchain.get_logger("blockstack-client")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    return logger

log = get_logger()


def interactive_prompt( message, parameters, default_opts ):
   """
   Prompt the user for a series of parameters
   Return a dict mapping the parameter name to the
   user-given value.
   """

   # pretty-print the message
   lines = message.split("\n")
   max_line_len = max( [len(l) for l in lines] )

   print '-' * max_line_len
   print message
   print '-' * max_line_len

   ret = {}

   for param in parameters:

      formatted_param = param
      prompt_str = "%s: "  % formatted_param
      if param in default_opts.keys():
          prompt_str = "%s (default: '%s'): " % (formatted_param, default_opts[param])

      try:
          value = raw_input(prompt_str)
      except KeyboardInterrupt:
          log.debug("Exiting on keyboard interrupt")
          sys.exit(0)

      if len(value) > 0:
         ret[param] = value
      elif param in default_opts.keys():
         ret[param] = default_opts[param]
      else:
         ret[param] = None


   return ret


def find_missing( message, all_params, given_opts, default_opts, header=None, prompt_missing=True ):
   """
   Find and interactively prompt the user for missing parameters,
   given the list of all valid parameters and a dict of known options.

   Return the (updated dict of known options, missing, num_prompted), with the user's input.
   """

   # are we missing anything?
   missing_params = []
   for missing_param in all_params:
      if missing_param not in given_opts.keys():
         missing_params.append( missing_param )

   num_prompted = 0
   if len(missing_params) > 0:

      if prompt_missing:
         if header is not None:
             print '-' * len(header)
             print header

         missing_values = interactive_prompt( message, missing_params, default_opts )
         given_opts.update( missing_values )
         num_prompted = len(missing_values)

      else:
         # count the number missing, and go with defaults
         for default_key in default_opts.keys():
            if default_key not in given_opts:
                num_prompted += 1

         given_opts.update( default_opts )


   return given_opts, missing_params, num_prompted



def opt_strip( prefix, opts ):
   """
   Given a dict of opts that start with prefix,
   remove the prefix from each of them.
   """

   ret = {}
   for (opt_name, opt_value) in opts.items():

      # remove prefix
      if opt_name.startswith(prefix):
         opt_name = opt_name[len(prefix):]

      ret[ opt_name ] = opt_value

   return ret


def opt_restore( prefix, opts ):
   """
   Given a dict of opts, add the given prefix to each key
   """

   ret = {}

   for (opt_name, opt_value) in opts.items():

      ret[ prefix + opt_name ] = opt_value

   return ret


def default_bitcoind_opts( config_file=None, prefix=False ):
   """
   Get our default bitcoind options, such as from a config file,
   or from sane defaults
   """

   default_bitcoin_opts = virtualchain.get_bitcoind_config( config_file=config_file )
   
   # strip None's
   for (k, v) in default_bitcoin_opts.items():
      if v is None:
         del default_bitcoin_opts[k]

   # strip 'bitcoind_'
   if not prefix:
       default_bitcoin_opts = opt_strip("bitcoind_", default_bitcoin_opts)

   return default_bitcoin_opts


def client_uuid_path( config_dir=CONFIG_DIR ):
    """
    where is the client UUID stored
    """
    uuid_path = os.path.join(config_dir, "client.uuid")
    return uuid_path


def get_or_set_uuid( config_dir=CONFIG_DIR ):
    """
    Get or set the UUID for this installation.
    Return the UUID either way
    Return None on failure
    """
    uuid_path = client_uuid_path(config_dir=config_dir)
    u = None
    if not os.path.exists(uuid_path):
       try:
           u = str(uuid.uuid4())
           with open(uuid_path, "w") as f:
               f.write(u)
               f.flush()
               os.fsync(f.fileno())

       except Exception, e:
            log.exception(e)
            return None

    else:
       try:
           with open(uuid_path, "r") as f:
               u = f.read()
               u = u.strip()

       except Exception, e:
           log.exception(e)
           return None

    return u 


def configure( config_file=CONFIG_PATH, force=False, interactive=True ):
   """
   Configure blockstack-client:  find and store configuration parameters to the config file.

   Optionally prompt for missing data interactively (with interactive=True).  Or, raise an exception
   if there are any fields missing.

   Optionally force a re-prompting for all configuration details (with force=True)

   Return {
      'blockstack-client': { ... },
      'bitcoind': { ... },
      'blockchain-reader': { ... },
      'blockchain-writer': { ... },
      'uuid': ...
   }
   """

   global SUPPORTED_UTXO_PROVIDERS, SUPPORTED_UTXO_PARAMS, SUPPORTED_UTXO_PROMPT_MESSAGES

   if not os.path.exists( config_file ) and interactive:
       # definitely ask for everything
       force = True

   config_dir = os.path.dirname(config_file)

   # get blockstack client opts
   blockstack_message  = "Your client does not have enough information to connect\n"
   blockstack_message += "to a Blockstack server.  Please supply the following\n"
   blockstack_message += "parameters, or press [ENTER] to select the default value."

   blockstack_opts = {}
   blockstack_opts_defaults = read_config_file( path=config_file )['blockstack-client']
   blockstack_params = blockstack_opts_defaults.keys()

   if not force:
       # defaults 
       blockstack_opts = read_config_file( path=config_file )['blockstack-client']
       blockstack_opts['path'] = config_file
       if config_file is not None:
           blockstack_opts['dir'] = os.path.dirname(config_file)
       else:
           blockstack_opts['dir'] = None

   blockstack_opts, missing_blockstack_opts, num_blockstack_opts_prompted = find_missing( blockstack_message, blockstack_params, blockstack_opts, blockstack_opts_defaults, prompt_missing=interactive )
   blockstack_opts['path'] = config_file
   if config_file is not None:
       blockstack_opts['dir'] = os.path.dirname(config_file)
   else:
       blockstack_opts['dir'] = None
   
   # get bitcoind options
   bitcoind_message  = "Blockstack does not have enough information to connect\n"
   bitcoind_message += "to bitcoind.  Please supply the following parameters, or\n"
   bitcoind_message += "press [ENTER] to select the default value."

   bitcoind_opts = {}
   bitcoind_opts_defaults = default_bitcoind_opts( config_file=config_file )
   bitcoind_params = bitcoind_opts_defaults.keys()

   if not force:
      # get default set of bitcoind opts
      bitcoind_opts = default_bitcoind_opts( config_file=config_file )

   # get any missing bitcoind fields
   bitcoind_opts, missing_bitcoin_opts, num_bitcoind_prompted = find_missing( bitcoind_message, bitcoind_params, bitcoind_opts, bitcoind_opts_defaults, prompt_missing=interactive )

   # find the blockchain reader 
   blockchain_reader = blockstack_opts.get('blockchain_reader', None)
   while blockchain_reader is None or blockchain_reader not in SUPPORTED_UTXO_PROVIDERS:

       # prompt for it?
       if interactive or force:

           blockchain_message  = 'NOTE: Blockstack currently requires an external API\n'
           blockchain_message += 'for querying the blockchain.  The set of supported\n'
           blockchain_message += 'service providers are:\n'
           blockchain_message += "\t\n".join( SUPPORTED_UTXO_PROVIDERS ) + "\n"
           blockchain_message += "Please enter the requisite information here."

           blockchain_reader_dict = interactive_prompt( blockchain_message, ['blockchain_reader'], {} )
           blockchain_reader = blockchain_reader_dict['blockchain_reader']

       else:
           raise Exception("No blockchain reader given")

   blockchain_reader_opts = {}
   blockchain_reader_defaults = default_utxo_provider_opts( blockchain_reader, config_file=config_file )
   blockchain_reader_params = SUPPORTED_UTXO_PARAMS[ blockchain_reader ]

   if not force:
       # get current set of reader opts 
       blockchain_reader_opts = default_utxo_provider_opts( blockchain_reader, config_file=config_file )

   blockchain_reader_opts, missing_reader_opts, num_reader_opts_prompted = find_missing( SUPPORTED_UTXO_PROMPT_MESSAGES[blockchain_reader], \
                                                                                         blockchain_reader_params, \
                                                                                         blockchain_reader_opts, \
                                                                                         blockchain_reader_defaults, \
                                                                                         header="Blockchain reader configuration",
                                                                                         prompt_missing=interactive )
  
   blockchain_reader_opts['utxo_provider'] = blockchain_reader_defaults['utxo_provider']

   # find the blockchain writer
   blockchain_writer = blockstack_opts.get('blockchain_writer', None)
   while blockchain_writer is None or blockchain_writer not in SUPPORTED_UTXO_PROVIDERS:

       # prompt for it?
       if interactive or force:

           blockchain_message  = 'NOTE: Blockstack currently requires an external API\n'
           blockchain_message += 'for sending transactions to the blockchain.  The set\n'
           blockchain_message += 'of supported service providers are:\n'
           blockchain_message += "\t\n".join( SUPPORTED_UTXO_PROVIDERS ) + "\n"
           blockchain_message += "Please enter the requisite information here."

           blockchain_writer_dict = interactive_prompt( blockchain_message, ['blockchain_writer'], {} )
           blockchain_writer = blockchain_writer_dict['blockchain_writer']

       else:
           raise Exception("No blockchain reader given")

   blockchain_writer_opts = {}
   blockchain_writer_defaults = default_utxo_provider_opts( blockchain_writer, config_file=config_file )
   blockchain_writer_params = SUPPORTED_UTXO_PARAMS[ blockchain_writer ]

   if not force:
       # get current set of writer opts 
       blockchain_writer_opts = default_utxo_provider_opts( blockchain_writer, config_file=config_file )

   blockchain_writer_opts, missing_writer_opts, num_writer_opts_prompted = find_missing( SUPPORTED_UTXO_PROMPT_MESSAGES[blockchain_writer], \
                                                                                         blockchain_writer_params, \
                                                                                         blockchain_writer_opts, \
                                                                                         blockchain_writer_defaults, \
                                                                                         header="Blockchain writer configuration",
                                                                                         prompt_missing=interactive )
 
   blockchain_writer_opts['utxo_provider'] = blockchain_writer_defaults['utxo_provider']
   if not interactive and (len(missing_bitcoin_opts) > 0 or len(missing_writer_opts) > 0 or len(missing_reader_opts) > 0 or len(missing_blockstack_opts) > 0):

       # cannot continue
       raise Exception("Missing configuration fields: %s" % (",".join( missing_bitcoin_opts + missing_writer_opts + missing_reader_opts + missing_blockstack_opts )) )

   # ask for contact info, so we can send out notifications for bugfixes and upgrades
   if blockstack_opts.get('email', None) is None:
       email_msg = "Would you like to receive notifications\n"
       email_msg+= "from the developers when there are critical\n"
       email_msg+= "updates available to install?\n\n"
       email_msg+= "If so, please enter your email address here.\n"
       email_msg+= "If not, leave this field blank.\n\n"
       email_msg+= "Your email address will be used solely\n"
       email_msg+= "for this purpose.\n"
       email_opts, _, email_prompted = find_missing( email_msg, ['email'], {}, {'email': ''}, prompt_missing=interactive )

       # merge with blockstack section
       num_blockstack_opts_prompted += 1
       blockstack_opts['email'] = email_opts['email']

   # get client UUID for analytics
   u = get_or_set_uuid( config_dir=config_dir )
   if u is None:
       raise Exception("Failed to get/set UUID")

   ret = {
      'blockstack-client': blockstack_opts,
      'bitcoind': bitcoind_opts,
      'blockchain-reader': blockchain_reader_opts,
      'blockchain-writer': blockchain_writer_opts
   }

   # if we prompted, then save
   if num_bitcoind_prompted > 0 or num_reader_opts_prompted > 0 or num_writer_opts_prompted or num_blockstack_opts_prompted > 0:
       print >> sys.stderr, "Saving configuration to %s" % config_file

       # rename appropriately, so other packages can find them
       write_config_file( ret, config_file )

   # set this here, so we don't save it
   ret['uuid'] = u
   return ret


def write_config_file( opts, config_file ):
    """
    Write our config file with the given options dict.
    Each key is a section name, and each value is the list of options.

    Return True on success
    Raise on error
    """

    parser = SafeConfigParser()

    if os.path.exists(config_file):
        parser.read(config_file)

    for sec_name in opts.keys():
        sec_opts = opts[sec_name]

        if parser.has_section(sec_name):
            parser.remove_section(sec_name)

        parser.add_section(sec_name)
        for opt_name, opt_value in sec_opts.items():
            if opt_value is None:
                opt_value = ""

            parser.set(sec_name, opt_name, "%s" % opt_value)

    with open(config_file, "w") as fout:
       os.fchmod( fout.fileno(), 0600 )
       parser.write( fout )

    return True


def write_config_field( config_path, section_name, field_name, field_value ):
   """
   Set a particular config file field
   Return True on success
   Return False on error
   """
   if not os.path.exists(config_path):
       return False

   parser = SafeConfigParser()
   parser.read(config_path)

   parser.set(section_name, field_name, "%s" % field_value)
   with open(config_path, "w") as fout:
       os.fchmod(fout.fileno(), 0600 )
       parser.write(fout)

   return True


def set_advanced_mode( status, config_path=CONFIG_PATH ):
   """ 
   Enable or disable advanced mode
   @status must be a bool
   """
   return write_config_field( config_path, "blockstack-client", "advanced_mode", str(status) )
   

def get_utxo_provider_client(config_path=CONFIG_PATH):
   """
   Get or instantiate our blockchain UTXO provider's client.
   Return None if we were unable to connect
   """

   # acquire configuration (which we should already have)
   opts = configure( interactive=False, config_file=config_path )
   reader_opts = opts['blockchain-reader']

   try:
       utxo_provider = connect_utxo_provider( reader_opts )
       return utxo_provider
   except Exception, e:
       log.exception(e)
       return None


def get_tx_broadcaster(config_path=CONFIG_PATH):
   """
   Get or instantiate our blockchain UTXO provider's transaction broadcaster.
   fall back to the utxo provider client, if one is not designated
   """

   # acquire configuration (which we should already have)
   opts = configure( interactive=False, config_file=config_path )
   writer_opts = opts['blockchain-writer']

   try:
       blockchain_broadcaster = connect_utxo_provider( writer_opts )
       return blockchain_broadcaster
   except:
       log.exception(e)
       return None


def str_to_bool( s ):
    """
    Convert "true" to True; "false" to False
    """
    if type(s) not in [str, unicode]:
        raise ValueError("'%s' is not a string" % s)

    if s.lower() == "false":
        return False 

    elif s.lower() == "true":
        return True 

    else:
        raise ValueError("Indeterminate boolean '%s'" % s)


def read_config_file(path=CONFIG_PATH):
    """
    Read or make a new empty config file with sane defaults.
    Return the config dict on success
    Raise on error
    """
    global CONFIG_PATH, BLOCKSTACKD_SERVER, BLOCKSTACKD_PORT

    # try to create
    if path is not None:
        dirname = os.path.dirname(CONFIG_PATH)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        if not os.path.isdir(dirname):
            raise Exception("Not a directory: %s" % path)

    if path is None or not os.path.exists(path):

        parser = SafeConfigParser()
        parser.add_section('blockstack-client')
        parser.set('blockstack-client', 'server', str(BLOCKSTACKD_SERVER))
        parser.set('blockstack-client', 'port', str(BLOCKSTACKD_PORT))
        parser.set('blockstack-client', 'metadata', BLOCKSTACK_METADATA_DIR)
        parser.set('blockstack-client', 'storage_drivers', BLOCKSTACK_DEFAULT_STORAGE_DRIVERS)
        parser.set('blockstack-client', 'storage_drivers_required_write', BLOCKSTACK_REQUIRED_STORAGE_DRIVERS_WRITE)
        parser.set('blockstack-client', 'blockchain_headers', SPV_HEADERS_PATH)
        parser.set('blockstack-client', 'advanced_mode', 'false')
        parser.set('blockstack-client', 'api_endpoint_port', str(DEFAULT_API_PORT))
        parser.set('blockstack-client', 'queue_path', str(DEFAULT_QUEUE_PATH))
        parser.set('blockstack-client', 'poll_interval', str(DEFAULT_POLL_INTERVAL))
        parser.set('blockstack-client', 'rpc_detach', "True")
        parser.set('blockstack-client', 'blockchain_reader', DEFAULT_BLOCKCHAIN_READER)
        parser.set('blockstack-client', 'blockchain_writer', DEFAULT_BLOCKCHAIN_WRITER)
        parser.set('blockstack-client', 'anonymous_statistics', "True")
        parser.set('blockstack-client', 'client_version', VERSION)

        rpc_token = os.urandom(32)
        parser.set('blockstack-client', 'rpc_token', hexlify(rpc_token))

        if path is not None:
            try:
                with open(path, "w") as f:
                    parser.write(f)
                    f.flush()
                    os.fsync(f.fileno())

            except:
                traceback.print_exc()
                log.error("Failed to write default configuration file to '%s'." % path)
                return False
        
        parser.add_section('blockchain-reader')
        parser.set('blockchain-reader', 'utxo_provider', DEFAULT_BLOCKCHAIN_READER)

        parser.add_section('blockchain-writer')
        parser.set('blockchain-writer', 'utxo_provider', DEFAULT_BLOCKCHAIN_WRITER)

        parser.add_section('bitcoind')

        bitcoind_config = default_bitcoind_opts()
        for k, v in bitcoind_config.items():
            if v is not None:
                parser.set('bitcoind', k, '%s' % v)

        # save 
        if path is not None:
            with open(path, "w") as f:
                parser.write( f )
                f.flush()
                os.fsync(f.fileno())

    # now read it back
    parser = SafeConfigParser()
    parser.read(path)

    # these are booleans--convert them 
    bool_values = {
        'blockstack-client': [
            'advanced_mode',
            'rpc_detach',
            'anonymous_statistics'
        ]
    }

    ret = {}
    for sec in parser.sections():
        ret[sec] = {}
        for opt in parser.options(sec):
            if bool_values.has_key(sec) and opt in bool_values[sec]:
                # decode to bool
                ret[sec][opt] = str_to_bool( parser.get(sec, opt) )

            else:
                # literal
                ret[sec][opt] = parser.get(sec, opt)

    if not ret['blockstack-client'].has_key('advanced_mode'):
        ret['blockstack-client']['advanced_mode'] = False

    ret['path'] = path
    ret['dir'] = os.path.dirname(path)
    return ret


def get_config(path=CONFIG_PATH):
    """
    Read our config file.
    Flatten the resulting config:
    * make all bitcoin-specific fields start with 'bitcoind_'
    * keep only the blockstack-client and bitcoin fields

    Return our flattened configuration (as a dict) on success.
    Return None on error
    """

    try:
        opts = configure( config_file=path )
    except Exception, e:
        log.exception(e)
        return None

    # flatten 
    blockstack_opts = opts['blockstack-client']
    bitcoin_opts = opts['bitcoind']

    bitcoin_opts = opt_restore("bitcoind_", bitcoin_opts)
    blockstack_opts.update(bitcoin_opts)
    
    # pass along the config path and dir, and statistics info
    blockstack_opts['path'] = path
    blockstack_opts['dir'] = os.path.dirname(path)
    blockstack_opts['uuid'] = opts['uuid']
    blockstack_opts['client_version'] = blockstack_opts.get('client_version', '')
    if not blockstack_opts.has_key('anonymous_statistics'):
        # not disabled 
        blockstack_opts['anonymous_statistics'] = True

    return blockstack_opts


def update_config(section, option, value, config_path=CONFIG_PATH):

    parser = SafeConfigParser()

    try:
        parser.read(config_path)
    except Exception, e:
        log.exception(e)
        return None

    if parser.has_option(section, option):
        parser.set(section, option, value)

        with open(config_path, 'wb') as configfile:
            parser.write(configfile)
