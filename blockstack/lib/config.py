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
from ConfigParser import SafeConfigParser
import pybitcoin
import blockstack_utxo
from blockstack_utxo import *
from ..version import __version__

import blockstack_client
from blockstack_client.config import LENGTHS, DEFAULT_OP_RETURN_FEE, DEFAULT_DUST_FEE, DEFAULT_OP_RETURN_VALUE, DEFAULT_FEE_PER_KB 
import virtualchain
log = virtualchain.get_logger("blockstack-server")

try:
    import blockstack_client
except:
    blockstack_client = None

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
# EXPIRATION_PERIOD = 10
AVERAGE_BLOCKS_PER_HOUR = MINUTES_PER_HOUR/AVERAGE_MINUTES_PER_BLOCK

""" blockstack configs
"""
MAX_NAMES_PER_SENDER = 25                # a sender can own exactly one name

""" RPC server configs
"""
if os.getenv("BLOCKSTACK_TEST") is not None:
    RPC_SERVER_PORT = 16264
else:
    RPC_SERVER_PORT = 6264

RPC_MAX_ZONEFILE_LEN = 4096     # 4KB
RPC_MAX_PROFILE_LEN = 1024000   # 1MB


""" Bitcoin configs
"""
DEFAULT_BITCOIND_SERVER = 'btcd.onename.com'
DEFAULT_BITCOIND_PORT = 8332
DEFAULT_BITCOIND_USERNAME = 'openname'
DEFAULT_BITCOIND_PASSWD = 'opennamesystem'

""" block indexing configs
"""
REINDEX_FREQUENCY = 300 # seconds

FIRST_BLOCK_MAINNET = 373601

GENESIS_SNAPSHOT = {
    str(FIRST_BLOCK_MAINNET-4): "17ac43c1d8549c3181b200f1bf97eb7d",
    str(FIRST_BLOCK_MAINNET-3): "17ac43c1d8549c3181b200f1bf97eb7d",
    str(FIRST_BLOCK_MAINNET-2): "17ac43c1d8549c3181b200f1bf97eb7d",
    str(FIRST_BLOCK_MAINNET-1): "17ac43c1d8549c3181b200f1bf97eb7d",
}

""" magic bytes configs
"""

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

if os.getenv("BLOCKSTACK_TEST") is not None:
    # testing 
    NAME_IMPORT_KEYRING_SIZE = 5                  # number of keys to derive from the import key
    NAMESPACE_REVEAL_EXPIRE = BLOCKS_PER_DAY      # small enough so we can actually test this...
    print >> sys.stderr, "WARN (%s): in test environment" % os.getpid()

else:
    NAME_IMPORT_KEYRING_SIZE = 300                  # number of keys to derive from the import key

NUM_CONFIRMATIONS = 6                         # number of blocks to wait for before accepting names

# burn address for fees (the address of public key 0x0000000000000000000000000000000000000000)
BLOCKSTACK_BURN_PUBKEY_HASH = "0000000000000000000000000000000000000000"
BLOCKSTACK_BURN_ADDRESS = "1111111111111111111114oLvT2"

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



"""
Which announcements has this blockstack node seen so far?
Announcements encode CVEs, bugs, and new features.  This list will be
updated in Blockstack releases to describe which of them have been
incorporated into the codebase.
"""
ANNOUNCEMENTS = []


blockstack_client_session = None
blockstack_client_session_opts = None

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
    Use the blockstack client library, so we can get at
    the storage drivers for the storage systems the sender used
    to host it.

    Return the data on success
    """

    session = get_blockstack_client_session()   # has the side-effect of initializing all storage drivers, if they're not already.
    data = blockstack_client.storage.get_immutable_data( announcement_hash, hash_func=blockstack_client.get_blockchain_compat_hash, deserialize=False )
    if data is None:
        log.error("Failed to get announcement '%s'" % (announcement_hash))
        return None

    return data


def put_announcement( announcement_text, txid ):
    """
    Go put an announcement into back-end storage.
    Use the blockstack client library, so we can get at
    the storage drivers for the storage systems this host
    is configured to use.

    Return the data's hash
    """

    session = get_blockstack_client_session()   # has the side-effect of initializing all storage drivers, if they're not already
    data_hash = blockstack_client.get_blockchain_compat_hash(announcement_text)
    res = blockstack_client.storage.put_immutable_data( None, txid, data_hash=data_hash, data_text=announcement_text )
    if res is None:
        log.error("Failed to put announcement '%s'" % (pybitcoin.hex_hash160(announcement_text)))
        return None

    return data_hash


def default_blockstack_opts( config_file=None ):
   """
   Get our default blockstack opts from a config file
   or from sane defaults.
   """

   if config_file is None:
      config_file = virtualchain.get_config_filename()

   announce_path = get_announce_filename( virtualchain.get_working_dir() )

   parser = SafeConfigParser()
   parser.read( config_file )

   blockstack_opts = {}
   contact_email = None
   announcers = "judecn.id,muneeb.id,shea256.id"
   announcements = None
   backup_frequency = 1008  # once a week; 10 minute block time
   backup_max_age = 12096   # 12 weeks
   rpc_port = RPC_SERVER_PORT 
   blockchain_proxy = False
   serve_zonefiles = True
   serve_profiles = False
   zonefile_dir = None
   analytics_key = None
   zonefile_storage_drivers = ""
   profile_storage_drivers = ""

   if parser.has_section('blockstack'):

      if parser.has_option('blockstack', 'backup_frequency'):
         backup_frequency = int( parser.get('blockstack', 'backup_frequency'))

      if parser.has_option('blockstack', 'backup_max_age'):
         backup_max_age = int( parser.get('blockstack', 'backup_max_age') )

      if parser.has_option('blockstack', 'email'):
         contact_email = parser.get('blockstack', 'email')

      if parser.has_option('blockstack', 'rpc_port'):
         rpc_port = int(parser.get('blockstack', 'rpc_port'))

      if parser.has_option('blockstack', 'blockchain_proxy'):
         blockchain_proxy = parser.get('blockstack', 'blockchain_proxy')
         if blockchain_proxy.lower() in ['1', 'yes', 'true', 'on']:
             blockchain_proxy = True
         else:
             blockchain_proxy = False

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

      if parser.has_option("blockstack", "zonefile_storage_drivers"):
          zonefile_storage_drivers = parser.get("blockstack", "zonefile_storage_drivers")

      if parser.has_option("blockstack", "profile_storage_drivers"):
          profile_storage_drivers = parser.get("blockstack", "profile_storage_drivers")

      if parser.has_option("blockstack", "zonefiles"):
          zonefile_dir = parser.get("blockstack", "zonefiles")

      if parser.has_option('blockstack', 'announcers'):
         # must be a CSV of blockchain IDs
         announcer_list_str = parser.get('blockstack', 'announcers')
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

      if parser.has_option('blockstack', 'analytics_key'):
         analytics_key = parser.get('blockstack', 'analytics_key')

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
       'blockchain_proxy': blockchain_proxy,
       'serve_zonefiles': serve_zonefiles,
       'serve_profiles': serve_profiles,
       'zonefile_storage_drivers': zonefile_storage_drivers,
       'profile_storage_drivers': profile_storage_drivers,
       'zonefiles': zonefile_dir,
       'analytics_key': analytics_key
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
       raise Exception("Missing configuration fields: %s" % (",".join( missing_bitcoin_opts + missing_utxo_opts )) )

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
       blockstack_client.config.write_config_file( ret, config_file )

   # prefix our bitcoind options, so they work with virtualchain
   ret['bitcoind'] = blockstack_client.config.opt_restore("bitcoind_", ret['bitcoind'])
   return ret 


