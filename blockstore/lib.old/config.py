"""
    Blockstore
    ~~~~~
    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

import os
from ConfigParser import SafeConfigParser

import schemas
import virtualchain

DEBUG = True
TESTNET = False
TESTSET = True

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
EXPIRATION_PERIOD = BLOCKS_PER_YEAR*1
# EXPIRATION_PERIOD = 10
AVERAGE_BLOCKS_PER_HOUR = MINUTES_PER_HOUR/AVERAGE_MINUTES_PER_BLOCK

""" blockstore configs
"""

LISTEN_IP = '0.0.0.0'
VERSION = 'v0.1-beta'
RPC_TIMEOUT = 5  # seconds

DEFAULT_BLOCKSTORED_PORT = 6264  # port 6263 is 'NAME' on a phone keypad
BLOCKSTORED_PID_FILE = 'blockstored.pid'
BLOCKSTORED_LOG_FILE = 'blockstored.log'
BLOCKSTORED_TAC_FILE = 'blockstored.tac'
BLOCKSTORED_WORKING_DIR = '.blockstore'
BLOCKSTORED_NAMESPACE_FILE = 'namespace.txt'
BLOCKSTORED_SNAPSHOTS_FILE = 'snapshots.txt'
BLOCKSTORED_STORAGEDB_FILE = 'storagedb.txt'
BLOCKSTORED_LASTBLOCK_FILE = 'lastblock.txt'
BLOCKSTORED_CONFIG_FILE = 'blockstore.ini'

DEFAULT_BLOCKMIRRORD_PORT = 6266  # port 6263 is 'NAME' on a phone keypad
BLOCKMIRRORD_PID_FILE = 'blockmirrord.pid'
BLOCKMIRRORD_LOG_FILE = 'blockmirrord.log'
BLOCKMIRRORD_WORKING_DIR = '.blockmirror'
BLOCKMIRRORD_CONFIG_FILE = 'blockmirror.ini'

try:
    BLOCKSTORED_SERVER = os.environ['BLOCKSTORED_SERVER']
    BLOCKSTORED_PORT = os.environ['BLOCKSTORED_PORT']
    
    BLOCKMIRRORD_SERVER = os.environ['BLOCKMIRRORD_SERVER']
    BLOCKMIRRORD_PORT = os.environ['BLOCKMIRRORD_PORT']
    
except KeyError:
    BLOCKSTORED_SERVER = 'localhost'
    BLOCKSTORED_PORT = DEFAULT_BLOCKSTORED_PORT
    
    BLOCKMIRRORD_SERVER = 'localhost'
    BLOCKMIRRORD_PORT = DEFAULT_BLOCKMIRRORD_PORT

""" DHT configs
"""

DEFAULT_BITCOIND_SERVER = 'btcd.onename.com'

BITCOIND_SERVER = None 
BITCOIND_PORT = None
BITCOIND_USER = None
BITCOIND_PASSWD = None
BITCOIND_USE_HTTPS = None

""" Multiprocessing
"""
MULTIPROCESS_NUM_WORKERS = 8
MULTIPROCESS_WORKER_BATCH = 8
MULTIPROCESS_RPC_RETRY = 3

""" block indexing configs
"""

REINDEX_FREQUENCY = 10  # in seconds

FIRST_BLOCK_MAINNET = 367090 # 343883
FIRST_BLOCK_MAINNET_TESTSET = FIRST_BLOCK_MAINNET
# FIRST_BLOCK_TESTNET = 343883
FIRST_BLOCK_TESTNET = 508800
FIRST_BLOCK_TESTNET_TESTSET = FIRST_BLOCK_TESTNET

if TESTNET:
    if TESTSET:
        START_BLOCK = FIRST_BLOCK_TESTNET_TESTSET
    else:
        START_BLOCK = FIRST_BLOCK_TESTNET
else:
    if TESTSET:
        START_BLOCK = FIRST_BLOCK_MAINNET_TESTSET
    else:
        START_BLOCK = FIRST_BLOCK_MAINNET

""" magic bytes configs
"""

MAGIC_BYTES_TESTSET = 'eg'
MAGIC_BYTES_MAINSET = 'id'

if TESTSET:
    MAGIC_BYTES = MAGIC_BYTES_TESTSET
else:
    MAGIC_BYTES = MAGIC_BYTES_MAINSET

""" name operation data configs
"""

# Opcodes
NAME_PREORDER = '?'
NAME_REGISTRATION = ':'
NAME_UPDATE = '+'
NAME_TRANSFER = '>'
NAME_RENEWAL = ':'
NAME_REVOKE = '~'

# NOTE: to appear as the first three bytes in the OP_RETURN for a NAME_REGISTER
NAME_SCHEME = MAGIC_BYTES_MAINSET + NAME_REGISTRATION

NAMESPACE_DEFINE = '*'
NAMESPACE_BEGIN = '!'

NAMESPACE_LIFE_INFINITE = 0xffffffff

# Other
LENGTHS = {
    'magic_bytes': 2,
    'opcode': 1,
    'preorder_name_hash': 20,
    'consensus_hash': 16,
    'namelen': 1,
    'name_min': 1,
    'name_max': 34,
    'unencoded_name': 34,
    'name_hash': 16,
    'namespace_hash': 20,
    'update_hash': 20,
    'data_hash': 20,
    'blockchain_id_name': 34,
    'blockchain_id_scheme': len(NAME_SCHEME),
    'blockchain_id_namespace_life': 4,
    'blockchain_id_namespace_cost': 8,
    'blockchain_id_namespace_price_decay': 4,
    'blockchain_id_namespace_id': 19
}

MIN_OP_LENGTHS = {
    'preorder': LENGTHS['preorder_name_hash'],
    'registration': LENGTHS['namelen'] + LENGTHS['name_min'],
    'update': LENGTHS['name_hash'] + LENGTHS['update_hash'],
    'transfer': LENGTHS['namelen'] + LENGTHS['name_min'],
    'namespace_begin': 1 + LENGTHS['blockchain_id_namespace_id'],
    'namespace_define': LENGTHS['blockchain_id_namespace_life'] + LENGTHS['blockchain_id_namespace_cost'] + \
                        LENGTHS['blockchain_id_namespace_price_decay'] + LENGTHS['namespace_hash'] 
}

OP_RETURN_MAX_SIZE = 40

""" transaction fee configs
"""

DEFAULT_OP_RETURN_FEE = 10000
DEFAULT_DUST_SIZE = 5500
DEFAULT_OP_RETURN_VALUE = 0
DEFAULT_FEE_PER_KB = 10000

""" name price configs
"""

SATOSHIS_PER_BTC = 10**8
PRICE_FOR_1LETTER_NAMES = 10*SATOSHIS_PER_BTC
PRICE_DROP_PER_LETTER = 10
PRICE_DROP_FOR_NON_ALPHABETIC = 10
ALPHABETIC_PRICE_FLOOR = 10**4

# default namespace record (i.e. for names with no namespace ID)
NAMESPACE_DEFAULT = {
   'opcode': 'NAMESPACE_DEFINE',
   'lifetime': EXPIRATION_PERIOD,
   'cost': PRICE_FOR_1LETTER_NAMES,
   'price_decay': float(PRICE_DROP_PER_LETTER),
   'namespace_id': None 
}

""" consensus hash configs
"""

BLOCKS_CONSENSUS_HASH_IS_VALID = 4*AVERAGE_BLOCKS_PER_HOUR

""" Validation 
"""

def get_first_block():
   """
   Get the first block to start processing requests.
   """ 
   return START_BLOCK


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
   
   loaded = False 
   
   if config_file is not None:
         
      parser = SafeConfigParser()
      parser.read(config_file)

      if parser.has_section('bitcoind'):

         bitcoind_server = parser.get('bitcoind', 'server')
         bitcoind_port = parser.get('bitcoind', 'port')
         bitcoind_user = parser.get('bitcoind', 'user')
         bitcoind_passwd = parser.get('bitcoind', 'passwd')
         
         if parser.has_option('bitcoind', 'use_https'):
            use_https = parser.get('bitcoind', 'use_https')
         else:
            use_https = 'no'

         if use_https.lower() == "yes" or use_https.lower() == "y":
            bitcoind_use_https = True
         else:
            bitcoind_use_https = False
            
         loaded = True

   if not loaded:

      if TESTNET:
         bitcoind_server = "localhost"
         bitcoind_port = 18332
         bitcoind_user = 'openname'
         bitcoind_passwd = 'opennamesystem'
         bitcoind_use_https = False
         
      else:
         bitcoind_server = DEFAULT_BITCOIND_SERVER
         bicoind_port = 8332
         bitcoind_user = 'openname'
         bitcoind_passwd = 'opennamesystem'
         bitcoind_use_https = True
        
   default_bitcoin_opts = {
      "bitcoind_user": bitcoind_user,
      "bitcoind_passwd": bitcoind_passwd,
      "bitcoind_server": bitcoind_server,
      "bitcoind_port": bitcoind_port,
      "bitcoind_use_https": bitcoind_use_https
   }
   
   # strip None's
   for (k, v) in default_bitcoin_opts:
      if v is None:
         del default_bitcoin_opts[k]
      
   return default_bitcoin_opts


def default_chaincom_opts( config_file=None ):
   """
   Get our default chain.com options from a config file.
   """
   
   if config_file is None:
      config_file = virtualchain.get_config_filename()
   
   parser = SafeConfigParser()
   parser.read( config_file )
   
   chaincom_opts = {}
   
   if parser.has_section('chain_com'):
      
      api_key_id = parser.get('api_key_id')
      api_key_secret = parser.get('api_key_secret')
      
      chaincom_opts = {
         'api_key_id': api_key_id,
         'api_key_secret': api_key_secret
      }
      
   
   # strip nones 
   for (k, v) in chaincom_opts:
      if v is None:
         del chaincom_opts[k]
   
   return chaincom_opts


def opt_strip( prefix, opts ):
   """
   Given a dict of opts that start with prefix,
   remove the prefix from each of them.
   """
   
   for (opt_name, opt_value) in opts.items():
      
      # remove prefix
      if opt_name.startswith(prefix):
         opt_name = opt_name[prefix]
      
      opts[ opt_name ] = opt_value
      
   return opts 


def interactive_prompt( message, parameters ):
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
      value = raw_input("%s: ")
      ret[param] = value 
   
   return ret


def interactive_prompt_missing( message, all_params, given_opts ):
   """
   Find and interactively prompt the user for missing parameters,
   given the list of all valid parameters and a dict of known options.
   
   Return the updated dict of known options, with the user's input.
   """
   
   # are we missing anything for bitcoin?
   missing_params = []
   for missing_param in given_opts:
      if missing_param not in given_opts.keys():
         missing_params.append( missing_param )
      
   if len(missing_params) > 0:
      
      missing_values = interactive_prompt( message, missing_params )
      given_opts.update( missing_values )
   
   return given_opts


def interactive_configure( config_file=None, force=False ):
   """
   Prompt the user for all the details of the config file
   that are still missing.  If there are no missing options, 
   then this method does nothing.
   
   Optionally force a re-prompting for all configuration details (with force=True)
   
   Return (bitcoind_opts, chaincom_opts)
   """
   
   if config_file is None:
      try:
         config_file = virtualchain.get_config_filename()
      except:
         pass 
   
   bitcoind_message  = "Blockstore does not have enough information to connect\n"
   bitcoind_message += "to bitcoind.  Please supply the following parameters:"
   
   bitcoind_opts = {}
   bitcoind_params = ["server", "port", "user", "passwd", "use_https"]
   
   chaincom_message  = 'NOTE: Blockstore currently requires API access to chain.com\n'
   chaincom_message += 'for getting unspent outputs. We will add support for using\n'
   chaincom_message += 'bitcoind and/or other API providers in the next release.\n'
   chaincom_message += "\n"
   chaincom_message += "If you have not done so already, please go to https://chain.com\n"
   chaincom_message += "and register for an API key and secret.  Once you have them,"
   chaincom_message += "please enter them here."
   
   chaincom_opts = {}
   chaincom_params = ["api_key_id", "api_key_secret"]
   
   if not force:
      
      # get current set of bitcoind opts
      tmp_bitcoind_opts = default_bitcoin_opts( config_file=config_file )
      bitcoind_opts = opt_strip( "bitcoind_", tmp_bitcoind_opts )
         
      # get current set of chaincom opts 
      chaincom_opts = default_chaincom_opts( config_file=config_file )
      
   # get any missing fields 
   bitcoind_opts = interactive_prompt_missing( bitcoind_message, bitcoind_params, bitcoind_opts )
   chaincom_opts = interactive_prompt_missing( chaincom_message, chaincom_params, chaincom_opts )
   
   return (bitcoind_opts, chaincom_opts)
      

def write_config_file( bitcoind_opts=None, chaincom_opts=None, config_file=None ):
   """
   Update a configuration file, given the bitcoind options and chain.com options.
   Return True on success 
   Return False on failure
   """
   
   if config_file is None:
      try:
         config_file = virtualchain.get_config_filename()
      except:
         return False
      
   if config_file is None:
      return False 
   
   parser = SafeConfigParser()
   parser.read(config_file)
   
   if bitcoind_opts is not None:
      
      bitcoind_opts = opt_strip( "bitcoind_", bitcoind_opts )
      
      for opt_name, opt_value in bitcoind_opts.items():
         parser.set( 'bitcoind', opt_name, opt_value )
      
   if chaincom_opts is not None:
      
      for opt_name, opt_value in chaincom_opts.items():
         parser.set( 'chain_com', opt_name, opt_value )
      
   with open(config_file, "w") as fout:
      parser.write( fout )
   
   return True

   