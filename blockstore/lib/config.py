#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstore

    Blockstore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore. If not, see <http://www.gnu.org/licenses/>.
"""

import os
import sys
from ConfigParser import SafeConfigParser
import pybitcoin

import virtualchain

if not globals().has_key('log'):
    log = virtualchain.session.log

try:
    import blockstore_client
except:
    blockstore_client = None

DEBUG = True
TESTNET = False

VERSION = "0.0.10.6"

# namespace version
BLOCKSTORE_VERSION = 1

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
# EXPIRATION_PERIOD = 10
AVERAGE_BLOCKS_PER_HOUR = MINUTES_PER_HOUR/AVERAGE_MINUTES_PER_BLOCK

""" blockstore configs
"""
MAX_NAMES_PER_SENDER = 25                # a sender can own exactly one name

""" RPC server configs
"""
RPC_SERVER_PORT = 6264

""" DHT configs
"""
# 3 years
STORAGE_TTL = 3 * 60 * 60 * 24 * 365

DHT_SERVER_PORT = 6265  # blockstored default to port 6264

DEFAULT_DHT_SERVERS = [('dht.blockstack.org', DHT_SERVER_PORT),
                       ('dht.onename.com', DHT_SERVER_PORT),
                       ('dht.halfmoonlabs.com', DHT_SERVER_PORT),
                       ('127.0.0.1', DHT_SERVER_PORT)]


""" Bitcoin configs
"""
DEFAULT_BITCOIND_SERVER = 'btcd.onename.com'
DEFAULT_BITCOIND_PORT = 8332
DEFAULT_BITCOIND_PORT_TESTNET = 18332
DEFAULT_BITCOIND_USERNAME = 'openname'
DEFAULT_BITCOIND_PASSWD = 'opennamesystem'

""" block indexing configs
"""
REINDEX_FREQUENCY = 300 # seconds

FIRST_BLOCK_MAINNET = 373601
FIRST_BLOCK_MAINNET_TESTSET = 380960
# FIRST_BLOCK_TESTNET = 343883
FIRST_BLOCK_TESTNET = 529008
FIRST_BLOCK_TESTNET_TESTSET = FIRST_BLOCK_TESTNET

GENESIS_SNAPSHOT = {
    str(FIRST_BLOCK_MAINNET-4): "17ac43c1d8549c3181b200f1bf97eb7d",
    str(FIRST_BLOCK_MAINNET-3): "17ac43c1d8549c3181b200f1bf97eb7d",
    str(FIRST_BLOCK_MAINNET-2): "17ac43c1d8549c3181b200f1bf97eb7d",
    str(FIRST_BLOCK_MAINNET-1): "17ac43c1d8549c3181b200f1bf97eb7d",
}

GENESIS_SNAPSHOT_TESTSET = {
    str(FIRST_BLOCK_MAINNET_TESTSET-2): "9e938749294b8019f9857cda93e7e73f",
    str(FIRST_BLOCK_MAINNET_TESTSET-1): "9e938749294b8019f9857cda93e7e73f",
}

""" magic bytes configs
"""

MAGIC_BYTES_TESTSET = 'eg'
MAGIC_BYTES_MAINSET = 'id'

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

NAME_OPCODES = [
    NAME_PREORDER,
    NAME_REGISTRATION,
    NAME_UPDATE,
    NAME_TRANSFER,
    NAME_RENEWAL,
    NAME_REVOKE,
    NAME_IMPORT
]

NAME_SCHEME = MAGIC_BYTES_MAINSET + NAME_REGISTRATION

NAMESPACE_PREORDER = '*'
NAMESPACE_REVEAL = '&'
NAMESPACE_READY = '!'

NAMESPACE_OPCODES = [
    NAMESPACE_PREORDER,
    NAMESPACE_REVEAL,
    NAMESPACE_READY
]

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

NAMESPACE_LIFE_INFINITE = 0xffffffff

# op-return formats
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

MIN_OP_LENGTHS = {
    'preorder': LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash'],
    'registration': LENGTHS['name_min'],
    'update': LENGTHS['name_hash'] + LENGTHS['update_hash'],
    'transfer': LENGTHS['name_hash'] + LENGTHS['consensus_hash'],
    'revoke': LENGTHS['name_min'],
    'name_import': LENGTHS['name_min'],
    'namespace_preorder': LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash'],
    'namespace_reveal': LENGTHS['blockchain_id_namespace_life'] + LENGTHS['blockchain_id_namespace_coeff'] + \
                        LENGTHS['blockchain_id_namespace_base'] + LENGTHS['blockchain_id_namespace_buckets'] + \
                        LENGTHS['blockchain_id_namespace_discounts'] + LENGTHS['blockchain_id_namespace_version'] + \
                        LENGTHS['name_min'],
    'namespace_ready': 1 + LENGTHS['name_min'],
    'announce': LENGTHS['announce']
}

OP_RETURN_MAX_SIZE = 40

""" transaction fee configs
"""

DEFAULT_OP_RETURN_FEE = 10000
DEFAULT_DUST_FEE = 5500
DEFAULT_OP_RETURN_VALUE = 0
DEFAULT_FEE_PER_KB = 10000

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

TESTSET_NAMESPACE_1_CHAR_COST = 10000
TESTSET_NAMESPACE_23_CHAR_COST = 10000
TESTSET_NAMESPACE_4567_CHAR_COST = 10000
TESTSET_NAMESPACE_8UP_CHAR_COST = 10000

NAMESPACE_PREORDER_EXPIRE = BLOCKS_PER_DAY      # namespace preorders expire after 1 day, if not revealed
NAMESPACE_REVEAL_EXPIRE = BLOCKS_PER_YEAR       # namespace reveals expire after 1 year, if not readied.

NAME_IMPORT_KEYRING_SIZE = 300                  # number of keys to derive from the import key

NUM_CONFIRMATIONS = 6                         # number of blocks to wait for before accepting names

# burn address for fees (the address of public key 0x0000000000000000000000000000000000000000)
BLOCKSTORE_BURN_PUBKEY_HASH = "0000000000000000000000000000000000000000"
BLOCKSTORE_BURN_ADDRESS = "1111111111111111111114oLvT2"

# default namespace record (i.e. for names with no namespace ID)
NAMESPACE_DEFAULT = {
   'opcode': 'NAMESPACE_REVEAL',
   'lifetime': EXPIRATION_PERIOD,
   'coeff': 15,
   'base': 15,
   'buckets': [15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15],
   'version': BLOCKSTORE_VERSION,
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


""" UTXOs
"""
SUPPORTED_UTXO_PROVIDERS = [ "chain_com", "blockcypher", "blockchain_info", "bitcoind_utxo", "mock_utxo" ]
SUPPORTED_UTXO_PARAMS = {
    "chain_com": ["api_key_id", "api_key_secret"],
    "blockcypher": ["api_token"],
    "blockchain_info": ["api_token"],
    "bitcoind_utxo": ["rpc_username", "rpc_password", "server", "port", "use_https", "version_byte"],
    "mock_utxo": []
}

SUPPORTED_UTXO_PROMPT_MESSAGES = {
    "chain_com": "Please enter your chain.com API key and secret.",
    "blockcypher": "Please enter your Blockcypher API token.",
    "blockchain_info": "Please enter your blockchain.info API token.",
    "bitcoind_utxo": "Please enter your fully-indexed bitcoind node information.",
    "mock_utxo": "Mock UTXO provider.  Do not use in production."
}


"""
Which announcements has this blockstore node seen so far?
Announcements encode CVEs, bugs, and new features.  This list will be
updated in Blockstore releases to describe which of them have been
incorporated into the codebase.
"""
ANNOUNCEMENTS = []


blockstore_client_session = None
blockstore_client_session_opts = None

def get_testset_filename( working_dir=None ):
   """
   Get the path to the file to determine whether or not we're in testset.
   """

   if working_dir is None:
       working_dir = virtualchain.get_working_dir()

   testset_filepath = os.path.join( working_dir, virtualchain.get_implementation().get_virtual_chain_name() ) + ".testset"
   return testset_filepath


def get_announce_filename( working_dir=None ):
   """
   Get the path to the file that stores all of the announcements.
   """

   if working_dir is None:
       working_dir = virtualchain.get_working_dir()

   announce_filepath = os.path.join( working_dir, virtualchain.get_implementation().get_virtual_chain_name() ) + ".announce"
   return announce_filepath


def get_blockstore_client_session( new_blockstore_client_session_opts=None ):
    """
    Get or instantiate our storage API session.
    """
    global blockstore_client_session
    global blockstore_client_session_opts

    # do we have storage?
    if blockstore_client is None:
        return None

    opts = None
    if new_blockstore_client_session_opts is not None:
        opts = new_blockstore_client_session_opts
    else:
        opts = blockstore_client.config.get_config()

    if opts is None:
        return None

    blockstore_client_session = blockstore_client.session( conf=opts )
    if blockstore_client_session is not None:

        if new_blockstore_client_session_opts is not None:
            blockstore_client_session_opts = new_blockstore_client_session_opts

    return blockstore_client_session


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


def get_announcement( announcement_hash ):
    """
    Go get an announcement's text, given its hash.
    Use the blockstore client library, so we can get at
    the storage drivers for the storage systems the sender used
    to host it.

    Return the data on success
    """

    session = get_blockstore_client_session()   # has the side-effect of initializing all storage drivers, if they're not already.
    data = blockstore_client.storage.get_immutable_data( announcement_hash )
    if data is None:
        log.error("Failed to get announcement '%s'" % (announcement_hash))
        return None

    return data


def put_announcement( announcement_text, txid ):
    """
    Go put an announcement into back-end storage.
    Use the blockstore client library, so we can get at
    the storage drivers for the storage systems this host
    is configured to use.

    Return the data's hash
    """

    session = get_blockstore_client_session()   # has the side-effect of initializing all storage drivers, if they're not already
    data_hash = blockstore_client.storage.put_immutable_data( announcement_text, txid )
    if data_hash is None:
        log.error("Failed to put announcement '%s'" % (pybitcoin.hex_hash160(announcement_text)))
        return None

    return data_hash


def default_blockstore_opts( config_file=None, testset=False ):
   """
   Get our default blockstore opts from a config file
   or from sane defaults.
   """

   if config_file is None:
      config_file = virtualchain.get_config_filename()

   testset_path = get_testset_filename( virtualchain.get_working_dir() )
   announce_path = get_announce_filename( virtualchain.get_working_dir() )

   parser = SafeConfigParser()
   parser.read( config_file )

   blockstore_opts = {}
   tx_broadcaster = None
   utxo_provider = None
   testset_first_block = None
   max_subsidy = 0
   contact_email = None
   announcers = "judecn.id,muneeb.id,shea256.id"
   announcements = None

   if parser.has_section('blockstore'):

      if parser.has_option('blockstore', 'tx_broadcaster'):
         tx_broadcaster = parser.get('blockstore', 'tx_broadcaster')

      if parser.has_option('blockstore', 'utxo_provider'):
         utxo_provider = parser.get('blockstore', 'utxo_provider')

      if parser.has_option('blockstore', 'testset_first_block'):
         testset_first_block = int( parser.get('blockstore', 'testset_first_block') )

      if parser.has_option('blockstore', 'max_subsidy'):
         max_subsidy = int( parser.get('blockstore', 'max_subsidy'))

      if parser.has_option('blockstore', 'email'):
         contact_email = parser.get('blockstore', 'email')

      if parser.has_option('blockstore', 'announcers'):
         # must be a CSV of blockchain IDs
         announcer_list_str = parser.get('blockstore', 'announcers')
         announcer_list = announcer_list_str.split(",")

         import scripts

         # validate each one
         valid = True
         for bid in announcer_list:
             if not scripts.is_name_valid( bid ):
                 log.error("Invalid blockchain ID '%s'" % bid)
                 valid = False

         if valid:
             announcers = ",".join(announcer_list)

   if os.path.exists( testset_path ):
       # testset file flag set
       testset = True

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

   blockstore_opts = {
       'tx_broadcaster': tx_broadcaster,
       'utxo_provider': utxo_provider,
       'testset': testset,
       'testset_first_block': testset_first_block,
       'max_subsidy': max_subsidy,
       'email': contact_email,
       'announcers': announcers,
       'announcements': announcements
   }

   # strip Nones
   for (k, v) in blockstore_opts.items():
      if v is None:
         del blockstore_opts[k]

   return blockstore_opts


def default_bitcoind_opts( config_file=None ):
   """
   Get our default bitcoind options, such as from a config file,
   or from sane defaults
   """

   bitcoind_server = None
   bitcoind_port = None
   bitcoind_user = None
   bitcoind_passwd = None
   bitcoind_use_https = None
   bitcoind_mock = False

   loaded = False

   if config_file is not None:

      parser = SafeConfigParser()
      parser.read(config_file)

      if parser.has_section('bitcoind'):

         if parser.has_option('bitcoind', 'server'):
            bitcoind_server = parser.get('bitcoind', 'server')

         if parser.has_option('bitcoind', 'port'):
            bitcoind_port = parser.get('bitcoind', 'port')

         if parser.has_option('bitcoind', 'user'):
            bitcoind_user = parser.get('bitcoind', 'user')

         if parser.has_option('bitcoind', 'passwd'):
            bitcoind_passwd = parser.get('bitcoind', 'passwd')

         if parser.has_option('bitcoind', 'use_https'):
            use_https = parser.get('bitcoind', 'use_https')
         else:
            use_https = 'no'

         if parser.has_option('bitcoind', 'mock'):
            mock = parser.get('bitcoind', 'mock')
         else:
            mock = 'no'

         if use_https.lower() in ["yes", "y", "true"]:
            bitcoind_use_https = True
         else:
            bitcoind_use_https = False

         if mock.lower() in ['yes', 'y', 'true']:
            bitcoind_mock = True
         else:
            bitcoind_mock = False

         loaded = True

   if not loaded:

      if TESTNET:
         bitcoind_server = "localhost"
         bitcoind_port = DEFAULT_BITCOIND_PORT_TESTNET
         bitcoind_user = DEFAULT_BITCOIND_USERNAME
         bitcoind_passwd = DEFAULT_BITCOIND_PASSWD
         bitcoind_use_https = False

      else:
         bitcoind_server = DEFAULT_BITCOIND_SERVER
         bitcoind_port = DEFAULT_BITCOIND_PORT
         bitcoind_user = DEFAULT_BITCOIND_USERNAME
         bitcoind_passwd = DEFAULT_BITCOIND_PASSWD
         bitcoind_use_https = True

   default_bitcoin_opts = {
      "bitcoind_user": bitcoind_user,
      "bitcoind_passwd": bitcoind_passwd,
      "bitcoind_server": bitcoind_server,
      "bitcoind_port": bitcoind_port,
      "bitcoind_use_https": bitcoind_use_https,
      "bitcoind_mock": bitcoind_mock
   }

   # strip None's
   for (k, v) in default_bitcoin_opts.items():
      if v is None:
         del default_bitcoin_opts[k]

   return default_bitcoin_opts


def default_utxo_provider( config_file=None ):
   """
   Get our defualt UTXO provider options from a config file.
   """

   global SUPPORTED_UTXO_PROVIDERS

   if config_file is None:
      config_file = virtualchain.get_config_filename()

   parser = SafeConfigParser()
   parser.read( config_file )

   for provider_name in SUPPORTED_UTXO_PROVIDERS:
       if parser.has_section( provider_name ):
           return provider_name

   return None


def all_utxo_providers( config_file=None ):
   """
   Get our defualt UTXO provider options from a config file.
   """

   global SUPPORTED_UTXO_PROVIDERS

   if config_file is None:
      config_file = virtualchain.get_config_filename()

   parser = SafeConfigParser()
   parser.read( config_file )

   provider_names = []

   for provider_name in SUPPORTED_UTXO_PROVIDERS:
       if parser.has_section( provider_name ):
           provider_names.append( provider_name )

   return provider_names


def default_utxo_provider_opts( utxo_provider, config_file=None ):
   """
   Get the default options for a utxo provider.
   """

   if utxo_provider == "chain_com":
       return default_chaincom_opts( config_file=config_file )

   elif utxo_provider == "blockcypher":
       return default_blockcypher_opts( config_file=config_file )

   elif utxo_provider == "blockchain_info":
       return default_blockchain_info_opts( config_file=config_file )

   elif utxo_provider == "bitcoind_utxo":
       return default_bitcoind_utxo_opts( config_file=config_file )

   elif utxo_provider == "mock_utxo":
       return default_mock_utxo_opts( config_file=config_file )

   else:
       raise Exception("Unsupported UTXO provider '%s'" % utxo_provider)


def default_chaincom_opts( config_file=None ):
   """
   Get our default chain.com options from a config file.
   """

   if config_file is None:
      config_file = virtualchain.get_config_filename()

   parser = SafeConfigParser()
   parser.read( config_file )

   chaincom_opts = {}

   api_key_id = None
   api_key_secret = None

   if parser.has_section('chain_com'):

      if parser.has_option('chain_com', 'api_key_id'):
         api_key_id = parser.get('chain_com', 'api_key_id')

      if parser.has_option('chain_com', 'api_key_secret'):
         api_key_secret = parser.get('chain_com', 'api_key_secret')

   chaincom_opts = {
       'utxo_provider': "chain_com",
       'api_key_id': api_key_id,
       'api_key_secret': api_key_secret
   }


   # strip Nones
   for (k, v) in chaincom_opts.items():
      if v is None:
         del chaincom_opts[k]

   return chaincom_opts


def default_blockcypher_opts( config_file=None ):
   """
   Get our default blockcypher.com options from a config file.
   """

   if config_file is None:
      config_file = virtualchain.get_config_filename()

   parser = SafeConfigParser()
   parser.read( config_file )

   blockcypher_opts = {}

   api_token = None

   if parser.has_section('blockcypher'):

      if parser.has_option('blockcypher', 'api_token'):
         api_token = parser.get('blockcypher', 'api_token')

   blockcypher_opts = {
       'utxo_provider': "blockcypher",
       'api_token': api_token
   }


   # strip Nones
   for (k, v) in blockcypher_opts.items():
      if v is None:
         del blockcypher_opts[k]

   return blockcypher_opts


def default_blockchain_info_opts( config_file=None ):
   """
   Get our default blockchain.info options from a config file.
   """

   if config_file is None:
       config_file = virtualchain.get_config_filename()

   parser = SafeConfigParser()
   parser.read( config_file )

   blockchain_info_opts = {}

   api_token = None

   if parser.has_section("blockchain_info"):

       if parser.has_option("blockchain_info", "api_token"):
           api_token = parser.get("blockchain_info", "api_token")

   blockchain_info_opts = {
       "utxo_provider": "blockchain_info",
       "api_token": api_token
   }

   # strip Nones
   for (k, v) in blockchain_info_opts.items():
      if v is None:
         del blockchain_info_opts[k]

   return blockchain_info_opts


def default_bitcoind_utxo_opts( config_file=None ):
   """
   Get our default bitcoind UTXO options from a config file.
   """

   if config_file is None:
       config_file = virtualchain.get_config_filename()

   parser = SafeConfigParser()
   parser.read( config_file )

   bitcoind_utxo_opts = {}

   server = None
   port = None
   rpc_username = None
   rpc_password = None
   use_https = None
   version_byte = None

   if parser.has_section("bitcoind_utxo"):

       if parser.has_option("bitcoind_utxo", "server"):
           server = parser.get("bitcoind_utxo", "server")

       if parser.has_option("bitcoind_utxo", "port"):
           port = int( parser.get("bitcoind_utxo", "port") )

       if parser.has_option("bitcoind_utxo", "rpc_username"):
           rpc_username = parser.get("bitcoind_utxo", "rpc_username")

       if parser.has_option("bitcoind_utxo", "rpc_password"):
           rpc_password = parser.get("bitcoind_utxo", "rpc_password")

       if parser.has_option("bitcoind_utxo", "use_https"):

            if parser.get("bitcoind_utxo", "use_https").lower() in ["y", "yes", "true"]:
                use_https = True
            else:
                use_https = False

       if parser.has_option("bitcoind_utxo", "version_byte"):
           version_byte = int(parser.get("bitcoind_utxo", "version_byte"))


   if use_https is None:
       use_https = True

   if version_byte is None:
       version_byte = 0

   if server is None:
       server = '127.0.0.1'

   if port is None:
       port = 8332

   bitcoind_utxo_opts = {
       "utxo_provider": "bitcoind_utxo",
       "rpc_username": rpc_username,
       "rpc_password": rpc_password,
       "server": server,
       "port": port,
       "use_https": use_https,
       "version_byte": version_byte
   }

   # strip Nones
   for (k, v) in bitcoind_utxo_opts.items():
      if v is None:
         del bitcoind_utxo_opts[k]

   return bitcoind_utxo_opts


def default_mock_utxo_opts( config_file=None ):
   """
   Get default options for the mock UTXO provider.
   """

   mock_tx_list = None
   mock_tx_file = None
   mock_start_block = FIRST_BLOCK_MAINNET
   mock_start_time = None
   mock_difficulty = None
   mock_initial_utxos = None

   if config_file is not None:

      parser = SafeConfigParser()
      parser.read(config_file)

      if parser.has_section("mock_utxo"):

         if parser.has_option('mock_utxo', 'tx_list'):
            # should be a csv of raw transactions
            mock_tx_list = parser.get('mock_utxo', 'tx_list').split(',')

         if parser.has_option('mock_utxo', 'tx_file'):
            # should be a path
            mock_tx_file = parser.get('mock_utxo', 'tx_file')

         if parser.has_option('mock_utxo', 'start_block'):
            # should be an int
            try:
                mock_start_block = int( parser.get('mock_utxo', 'start_block') )
            except:
                print >> sys.stderr, "Invalid 'start_block' value: expected int"
                return None

         if parser.has_option('mock_utxo', 'difficulty'):
            # should be a float
            try:
                mock_difficulty = float( parser.get('mock_utxo', 'difficulty') )
            except:
                print >> sys.stderr, "Invalid 'difficulty' value: expected float"
                return None

         if parser.has_option('mock_utxo', 'start_block'):
            # should be an int
            try:
                mock_start_block = int( parser.get('mock_utxo', 'start_block'))
            except:
                print >> sys.stderr, "Invalid 'start_block' value: expected int"
                return None

         if parser.has_option('mock_utxo', 'initial_utxos'):
            # should be a csv of privatekey:int
            try:
                # verify that we can parse this
                wallet_info = parser.get('mock_utxo', 'initial_utxos').split(',')
                wallets = {}
                for wi in wallet_info:
                    privkey, value = wi.split(':')
                    wallets[ privkey ] = int(value)

                #mock_initial_utxos = wallets
                mock_initial_utxos = parser.get('mock_utxo', 'initial_utxos')

            except:
                print >> sys.stderr, "Invalid 'mock_initial_utxos' value: expected CSV of wif_private_key:int"
                return None


   default_mock_utxo_opts = {
      "utxo_provider": "mock_utxo",
      "tx_list": mock_tx_list,
      "tx_file": mock_tx_file,
      "start_block": mock_start_block,
      "difficulty": mock_difficulty,
      "initial_utxos": mock_initial_utxos,
      "start_block": mock_start_block
   }

   # strip Nones
   for (k, v) in default_mock_utxo_opts.items():
      if v is None:
         del default_mock_utxo_opts[k]

   return default_mock_utxo_opts


def default_dht_opts( config_file=None ):
   """
   Get our default DHT options from the config file.
   """

   global DHT_SERVER_PORT, DEFAULT_DHT_SERVERS

   if config_file is None:
      config_file = virtualchain.get_config_filename()


   defaults = {
      'disable': str(True),
      'port': str(DHT_SERVER_PORT),
      'servers': ",".join( ["%s:%s" % (host, port) for (host, port) in DEFAULT_DHT_SERVERS] )
   }

   parser = SafeConfigParser( defaults )
   parser.read( config_file )

   if parser.has_section('dht'):

      disable = parser.get('dht', 'disable')
      port = parser.get('dht', 'port')
      servers = parser.get('dht', 'servers')     # expect comma-separated list of host:port

      if disable is None:
         disable = True

      if port is None:
         port = DHT_SERVER_PORT

      if servers is None:
         servers = DEFAULT_DHT_SERVERS

      if disable.lower() in ['no', 'n', '0', 'false']:
          disable = False
      else:
          disable = True

      try:
         port = int(port)
      except:
         raise Exception("Invalid field value for dht.port: expected int")

      parsed_servers = []
      try:
         server_list = servers.split(",")
         for server in server_list:
            server_host, server_port = server.split(":")
            server_port = int(server_port)

            parsed_servers.append( (server_host, server_port) )

      except:
         raise Exception("Invalid field value for dht.servers: expected 'HOST:PORT[,HOST:PORT...]'")

      dht_opts = {
         'disable': disable,
         'port': port,
         'servers': parsed_servers
      }

      return dht_opts

   else:

      # use defaults
      dht_opts = {
         'disable': True,
         'port': DHT_SERVER_PORT,
         'servers': ",".join( ["%s:%s" % (host, port) for (host, port) in DEFAULT_DHT_SERVERS] )
      }

      return dht_opts



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


def interactive_prompt( message, parameters, default_opts, strip_prefix="" ):
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
      if param.startswith( strip_prefix ):
          formatted_param = param[len(strip_prefix):]

      prompt_str = "%s: "  % formatted_param
      if param in default_opts.keys():
          prompt_str = "%s (default: '%s'): " % (formatted_param, default_opts[param])

      value = raw_input(prompt_str)

      if len(value) > 0:
         ret[param] = value
      elif param in default_opts.keys():
         ret[param] = default_opts[param]
      else:
         ret[param] = None


   return ret


def find_missing( message, all_params, given_opts, default_opts, prompt_missing=True, strip_prefix="" ):
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
         missing_values = interactive_prompt( message, missing_params, default_opts, strip_prefix=strip_prefix )
         given_opts.update( missing_values )
         num_prompted = len(missing_values)

      else:
         # count the number missing, and go with defaults
         for default_key in default_opts.keys():
            if default_key not in given_opts:
                num_prompted += 1

         given_opts.update( default_opts )


   return given_opts, missing_params, num_prompted


def configure( config_file=None, force=False, interactive=True, testset=False ):
   """
   Configure blockstore:  find and store configuration parameters to the config file.

   Optionally prompt for missing data interactively (with interactive=True).  Or, raise an exception
   if there are any fields missing.

   Optionally force a re-prompting for all configuration details (with force=True)

   Return (bitcoind_opts, utxo_opts)
   """

   global SUPPORTED_UTXO_PROVIDERS, SUPPORTED_UTXO_PARAMS, SUPPORTED_UTXO_PROMPT_MESSAGES

   if config_file is None:
      try:
         # get input for everything
         config_file = virtualchain.get_config_filename()
      except:
         raise

   if not os.path.exists( config_file ):
       # definitely ask for everything
       force = True

   # get blockstore opts
   blockstore_opts = {}
   blockstore_opts_defaults = default_blockstore_opts( config_file=config_file, testset=testset )
   blockstore_params = blockstore_opts_defaults.keys()

   if not force:

       # default blockstore options
       blockstore_opts = default_blockstore_opts( config_file=config_file, testset=testset )

   blockstore_msg = "ADVANCED USERS ONLY.\nPlease enter blockstore configuration hints."

   # NOTE: disabled
   blockstore_opts, missing_blockstore_opts, num_blockstore_opts_prompted = find_missing( blockstore_msg, blockstore_params, blockstore_opts, blockstore_opts_defaults, prompt_missing=False )

   utxo_provider = None
   if 'utxo_provider' in blockstore_opts:
       utxo_provider = blockstore_opts['utxo_provider']
   else:
       utxo_provider = default_utxo_provider( config_file=config_file )

   bitcoind_message  = "Blockstore does not have enough information to connect\n"
   bitcoind_message += "to bitcoind.  Please supply the following parameters, or\n"
   bitcoind_message += "press [ENTER] to select the default value."

   bitcoind_opts = {}
   bitcoind_opts_defaults = default_bitcoind_opts( config_file=config_file )
   bitcoind_params = bitcoind_opts_defaults.keys()

   if not force:

      # get default set of bitcoind opts
      bitcoind_opts = default_bitcoind_opts( config_file=config_file )


   # get any missing bitcoind fields
   bitcoind_opts, missing_bitcoin_opts, num_bitcoind_prompted = find_missing( bitcoind_message, bitcoind_params, bitcoind_opts, bitcoind_opts_defaults, prompt_missing=interactive, strip_prefix="bitcoind_" )

   # find the current utxo provider
   while utxo_provider is None or utxo_provider not in SUPPORTED_UTXO_PROVIDERS:

       # prompt for it?
       if interactive or force:

           utxo_message  = 'NOTE: Blockstore currently requires an external API\n'
           utxo_message += 'for querying unspent transaction outputs.  The set of\n'
           utxo_message += 'supported providers are:\n'
           utxo_message += "\t\n".join( SUPPORTED_UTXO_PROVIDERS ) + "\n"
           utxo_message += "Please get the requisite API tokens and enter them here."

           utxo_provider_dict = interactive_prompt( utxo_message, ['utxo_provider'], {} )
           utxo_provider = utxo_provider_dict['utxo_provider']

       else:
           raise Exception("No UTXO provider given")

   utxo_opts = {}
   utxo_opts_defaults = default_utxo_provider_opts( utxo_provider, config_file=config_file )
   utxo_params = SUPPORTED_UTXO_PARAMS[ utxo_provider ]

   if not force:

      # get current set of utxo opts
      utxo_opts = default_utxo_provider_opts( utxo_provider, config_file=config_file )

   utxo_opts, missing_utxo_opts, num_utxo_opts_prompted = find_missing( SUPPORTED_UTXO_PROMPT_MESSAGES[utxo_provider], utxo_params, utxo_opts, utxo_opts_defaults, prompt_missing=interactive )
   utxo_opts['utxo_provider'] = utxo_provider

   dht_opts = {}
   dht_opts_defaults = default_dht_opts( config_file=config_file )
   dht_params = dht_opts_defaults.keys()

   if not force:

       # default DHT options
       dht_opts = default_dht_opts( config_file=config_file )

   dht_msg = "Please enter your DHT node configuration.\nUnless you plan on leaving Blockstore\nrunning, you should disable the DHT feature."

   # NOTE: disabled
   dht_opts, missing_dht_opts, num_dht_opts_prompted = find_missing( dht_msg, dht_params, dht_opts, dht_opts_defaults, prompt_missing=False )

   if not interactive and (len(missing_bitcoin_opts) > 0 or len(missing_utxo_opts) > 0 or len(missing_dht_opts) > 0 or len(missing_blockstore_opts) > 0):

       # cannot continue
       raise Exception("Missing configuration fields: %s" % (",".join( missing_bitcoin_opts + missing_utxo_opts )) )

   # ask for contact info, so we can send out notifications for bugfixes and upgrades
   if blockstore_opts.get('email', None) is None:
       email_msg = "Would you like to receive notifications\n"
       email_msg+= "from the developers when there are critical\n"
       email_msg+= "updates available to install?\n\n"
       email_msg+= "If so, please enter your email address here.\n"
       email_msg+= "If not, leave this field blank.\n\n"
       email_msg+= "Your email address will be used solely\n"
       email_msg+= "for this purpose.\n"
       email_opts, _, email_prompted = find_missing( email_msg, ['email'], {}, {'email': ''}, prompt_missing=interactive )

       # merge with blockstore section
       num_blockstore_opts_prompted += 1
       blockstore_opts['email'] = email_opts['email']

   # if we prompted, then save
   if num_bitcoind_prompted > 0 or num_utxo_opts_prompted > 0 or num_dht_opts_prompted > 0 or num_blockstore_opts_prompted > 0:
       print >> sys.stderr, "Saving configuration to %s" % config_file
       write_config_file( bitcoind_opts=bitcoind_opts, utxo_opts=utxo_opts, dht_opts=dht_opts, blockstore_opts=blockstore_opts, config_file=config_file )

   return (blockstore_opts, bitcoind_opts, utxo_opts, dht_opts)


def write_config_file( blockstore_opts=None, bitcoind_opts=None, utxo_opts=None, dht_opts=None, config_file=None ):
   """
   Update a configuration file, given the bitcoind options and chain.com options.
   Return True on success
   Return False on failure
   """

   print dht_opts
   if config_file is None:
      try:
         config_file = virtualchain.get_config_filename()
      except:
         return False

   if config_file is None:
      return False

   parser = SafeConfigParser()
   parser.read(config_file)

   if bitcoind_opts is not None and len(bitcoind_opts) > 0:

      tmp_bitcoind_opts = opt_strip( "bitcoind_", bitcoind_opts )

      if parser.has_section('bitcoind'):
          parser.remove_section('bitcoind')

      parser.add_section( 'bitcoind' )
      for opt_name, opt_value in tmp_bitcoind_opts.items():
         if opt_value is None:
             raise Exception("%s is not defined" % opt_name)
         parser.set( 'bitcoind', opt_name, "%s" % opt_value )

   if utxo_opts is not None and len(utxo_opts) > 0:

      if parser.has_section( utxo_opts['utxo_provider'] ):
          parser.remove_section( utxo_opts['utxo_provider'] )

      parser.add_section( utxo_opts['utxo_provider'] )
      for opt_name, opt_value in utxo_opts.items():

         # don't log this meta-field
         if opt_name == 'utxo_provider':
             continue

         if opt_value is None:
             raise Exception("%s is not defined" % opt_name)

         parser.set( utxo_opts['utxo_provider'], opt_name, "%s" % opt_value )

   if dht_opts is not None and len(dht_opts) > 0:

      if parser.has_section("dht"):
          parser.remove_section("dht")

      parser.add_section( "dht" )
      for opt_name, opt_value in dht_opts.items():

          if opt_value is None:
              raise Exception("%s is not defined" % opt_name )

          parser.set( "dht", opt_name, "%s" % opt_value )


   if blockstore_opts is not None and len(blockstore_opts) > 0:

      if parser.has_section("blockstore"):
          parser.remove_section("blockstore")

      parser.add_section( "blockstore" )
      for opt_name, opt_value in blockstore_opts.items():

          if opt_value is None:
              raise Exception("%s is not defined" % opt_name )

          parser.set( "blockstore", opt_name, "%s" % opt_value )


   with open(config_file, "w") as fout:
      os.fchmod( fout.fileno(), 0600 )
      parser.write( fout )

   return True


def connect_utxo_provider( utxo_opts ):
   """
   Set up and return a UTXO provider client.
   """

   global SUPPORTED_UTXO_PROVIDERS

   if not utxo_opts.has_key("utxo_provider"):
       raise Exception("No UTXO provider given")

   utxo_provider = utxo_opts['utxo_provider']
   if not utxo_provider in SUPPORTED_UTXO_PROVIDERS:
       raise Exception("Unsupported UTXO provider '%s'" % utxo_provider)

   if utxo_provider == "chain_com":
       return pybitcoin.ChainComClient( utxo_opts['api_key_id'], utxo_opts['api_key_secret'] )

   elif utxo_provider == "blockcypher":
       return pybitcoin.BlockcypherClient( utxo_opts['api_token'] )

   elif utxo_provider == "blockchain_info":
       return pybitcoin.BlockchainInfoClient( utxo_opts['api_token'] )

   elif utxo_provider == "bitcoind_utxo":
       return pybitcoin.BitcoindClient( utxo_opts['rpc_username'], utxo_opts['rpc_password'], use_https=utxo_opts['use_https'], server=utxo_opts['server'], port=utxo_opts['port'], version_byte=utxo_opts['version_byte'] )

   elif utxo_provider == "mock_utxo":
       # requires blockstore tests to be installed
       from ..tests import connect_mock_utxo_provider
       return connect_mock_utxo_provider( utxo_opts )

   else:
       raise Exception("Unrecognized UTXO provider '%s'" % utxo_provider )

